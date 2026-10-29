"""Context observation must preserve the original C API call contract."""

import copy
import ctypes
import gc
import json
import unittest

from auth_factory_roots import PROFILE, ObservedLibrary, ObservedTimeSetter, validate_profile


class Owner:
    ptr = 71
    capture_now = 100


class Function:
    def __init__(self, result=True):
        self.result = result
        self.calls = []
        self.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        self.restype = ctypes.c_bool

    def __call__(self, *args):
        self.calls.append(args)
        return self.result


class TimeObservation(unittest.TestCase):
    def test_success_records_actual_time_and_returns_original_result(self):
        owner, fn = Owner(), Function(result=17)
        observed = ObservedTimeSetter(fn, owner)
        self.assertEqual(observed(owner.ptr, 601), 17)
        self.assertEqual(owner.capture_now, 601)
        self.assertEqual(fn.calls, [(71, 601)])

    def test_refusal_keeps_previous_time(self):
        owner, fn = Owner(), Function(result=False)
        observed = ObservedTimeSetter(fn, owner)
        self.assertIs(observed(owner.ptr, 601), False)
        self.assertEqual(owner.capture_now, 100)
        self.assertEqual(fn.calls, [(71, 601)])

    def test_ctypes_metadata_reads_and_writes_are_forwarded(self):
        owner, fn = Owner(), Function()
        observed = ObservedTimeSetter(fn, owner)
        self.assertIs(observed.restype, ctypes.c_bool)
        observed.restype = ctypes.c_int
        self.assertIs(fn.restype, ctypes.c_int)
        value = [ctypes.c_void_p, ctypes.c_uint32]
        observed.argtypes = value
        self.assertIs(fn.argtypes, value)
        self.assertIs(observed.argtypes, value)

    def test_foreign_pointer_fails_before_native_side_effect(self):
        owner, fn = Owner(), Function()
        observed = ObservedTimeSetter(fn, owner)
        with self.assertRaisesRegex(AssertionError, "another emulator pointer"):
            observed(72, 601)
        self.assertEqual(fn.calls, [])
        self.assertEqual(owner.capture_now, 100)

    def test_observer_does_not_keep_an_emulator_alive(self):
        owner, fn = Owner(), Function()
        observed = ObservedTimeSetter(fn, owner)
        del owner
        gc.collect()
        with self.assertRaisesRegex(AssertionError, "outlived its emulator"):
            observed(71, 601)
        self.assertEqual(fn.calls, [])

    def test_original_native_error_is_not_swallowed(self):
        owner = Owner()

        def fail(*args):
            raise RuntimeError("native call refused")

        observed = ObservedTimeSetter(fail, owner)
        with self.assertRaisesRegex(RuntimeError, "native call refused"):
            observed(71, 601)
        self.assertEqual(owner.capture_now, 100)


class LibraryObservation(unittest.TestCase):
    def setUp(self):
        self.owner = Owner()
        self.library = type("Library", (), {})()
        self.library.transaction_emulator_set_unixtime = Function()
        self.library.transaction_emulator_set_lt = object()
        self.library.transaction_emulator_destroy = object()
        for name in (
            "set_rand_seed",
            "set_ignore_chksig",
            "set_libraries",
            "set_prev_blocks_info",
            "set_config",
        ):
            setattr(self.library, "transaction_emulator_" + name, Function())
        self.observed = ObservedLibrary(self.library, self.owner)

    def test_library_time_setter_is_intercepted(self):
        self.observed.transaction_emulator_set_unixtime(71, 602)
        self.assertEqual(self.owner.capture_now, 602)

    def test_lt_and_other_original_functions_are_unchanged(self):
        self.assertIs(
            self.observed.transaction_emulator_set_lt, self.library.transaction_emulator_set_lt
        )
        self.assertIs(
            self.observed.transaction_emulator_destroy, self.library.transaction_emulator_destroy
        )

    def test_unobserved_context_changes_fail_loudly(self):
        for name in (
            "set_rand_seed",
            "set_ignore_chksig",
            "set_libraries",
            "set_prev_blocks_info",
            "set_config",
        ):
            with self.subTest(name=name):
                with self.assertRaisesRegex(AssertionError, "unobserved context setter"):
                    getattr(self.observed, "transaction_emulator_" + name)


class FrozenProfiles(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.profiles = json.loads(PROFILE.read_bytes())

    def test_both_actual_profiles_pass(self):
        for family, profile in self.profiles.items():
            validate_profile(family, profile)

    def rejected(self, mutate):
        for family, profile in self.profiles.items():
            with self.subTest(family=family):
                value = copy.deepcopy(profile)
                mutate(value)
                with self.assertRaisesRegex(AssertionError, "population changed"):
                    validate_profile(family, value)

    def test_missing_case(self):
        self.rejected(lambda p: p["cases"].pop())

    def test_missing_call(self):
        self.rejected(lambda p: p["calls"].pop())

    def test_extra_call(self):
        self.rejected(lambda p: p["calls"].append(p["calls"][0]))

    def test_duplicate_call(self):
        self.rejected(lambda p: p["calls"].__setitem__(1, p["calls"][0]))

    def test_reordered_calls(self):
        self.rejected(lambda p: p["calls"].reverse())

    def test_changed_original_context(self):
        self.rejected(lambda p: p["calls"][0].__setitem__("input_sha256", "0" * 64))

    def test_changed_config(self):
        self.rejected(lambda p: p["calls"][0].__setitem__("configuration", "0" * 64))

    def test_changed_version_or_omitted_historical_route(self):
        self.rejected(lambda p: p["calls"][0].__setitem__("version", 15))
        self.rejected(
            lambda p: p.__setitem__("calls", [c for c in p["calls"] if c["version"] == 16])
        )

    def test_changed_native_expected_root(self):
        self.rejected(
            lambda p: p["calls"][0].__setitem__(
                "expected", ["accepted", "0" * 64, "0" * 64, "0" * 64]
            )
        )

    def test_changed_original_assertion_source(self):
        self.rejected(
            lambda p: p["producer_sources"].__setitem__("test/auth-extensions/native.py", "0" * 64)
        )

    def test_unknown_family(self):
        with self.assertRaisesRegex(AssertionError, "unknown auth factory"):
            validate_profile("missing", self.profiles["auth"])

    def test_coherently_changed_frozen_reference_is_rejected(self):
        frozen = copy.deepcopy(self.profiles)
        frozen["auth"]["cases"].pop()
        raw = json.dumps(frozen).encode()
        with self.assertRaisesRegex(AssertionError, "profile source digest"):
            validate_profile("auth", frozen["auth"], raw)

    def test_profile_resource_bound(self):
        with self.assertRaisesRegex(AssertionError, "profile byte limit"):
            validate_profile("auth", self.profiles["auth"], b" " * (1024 * 1024 + 1))


if __name__ == "__main__":
    unittest.main()
