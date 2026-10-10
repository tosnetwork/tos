#!/usr/bin/env python3
"""Self-test for scripts/static-analysis.py against stand-in tools.

The real gate needs CodeChecker, LLVM 21 and a configured build; this suite needs
none of them. It drives each fail-closed path with a stand-in that misbehaves in
one way and checks that the gate refuses, and it checks the comparison and the
suppression audit on fixed inputs.
"""

from __future__ import annotations

import collections
import importlib.util
import json
import os
import re
import signal
import stat
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("static_analysis", HERE / "static-analysis.py")
assert SPEC is not None and SPEC.loader is not None
sa = importlib.util.module_from_spec(SPEC)
sys.modules["static_analysis"] = sa
SPEC.loader.exec_module(sa)


def write_tool(path: Path, body: str) -> Path:
    """A stand-in executable running the given Python body."""
    path.write_text(f"#!{sys.executable}\n" + textwrap.dedent(body))
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def report(checker: str, path: str, digest: str, line: int = 1, column: int = 1) -> object:
    return sa.Report(checker, "clang-tidy", path, line, column, digest, "message")


class Workdir(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name).resolve()

    def tearDown(self) -> None:
        self._tmp.cleanup()


class Termination(Workdir):
    def test_sigterm_kills_the_analyzer_process_group(self) -> None:
        pid_file = self.tmp / "child.pid"
        sleeper = write_tool(
            self.tmp / "slow-analyzer",
            f"import os, time\nopen({str(pid_file)!r}, 'w').write(str(os.getpid()))\ntime.sleep(120)\n",
        )
        driver = (
            "import importlib.util, sys\n"
            f"spec = importlib.util.spec_from_file_location('sa', {str(HERE / 'static-analysis.py')!r})\n"
            "sa = importlib.util.module_from_spec(spec); sys.modules['sa'] = sa\n"
            "spec.loader.exec_module(sa)\n"
            "sa.install_signal_handlers()\n"
            f"sa.run([{str(sleeper)!r}])\n"
        )
        gate = subprocess.Popen([sys.executable, "-c", driver])
        try:
            for _ in range(200):
                if pid_file.exists() and pid_file.read_text():
                    break
                time.sleep(0.05)
            child = int(pid_file.read_text())
            gate.send_signal(signal.SIGTERM)
            self.assertEqual(gate.wait(timeout=30), 128 + signal.SIGTERM)
        finally:
            if gate.poll() is None:
                gate.kill()
        for _ in range(100):
            try:
                os.kill(child, 0)
            except ProcessLookupError:
                return
            time.sleep(0.05)
        os.kill(child, signal.SIGKILL)
        self.fail("the analyzer survived the gate's termination")


class Comparison(unittest.TestCase):
    def judge(self, head: list[object], base: list[object]) -> int:
        return sa.judge(head, base, [])

    def test_new_blocking_fails(self) -> None:
        self.assertEqual(self.judge([report("bugprone-use-after-move", "a.cpp", "h1")], []), 1)

    def test_advisory_only_passes(self) -> None:
        self.assertEqual(self.judge([report("core.NullDereference", "a.cpp", "h1")], []), 0)

    def test_finding_already_at_base_passes(self) -> None:
        head = [report("bugprone-use-after-move", "a.cpp", "h1", line=9)]
        base = [report("bugprone-use-after-move", "a.cpp", "h1", line=7)]
        self.assertEqual(self.judge(head, base), 0)

    def test_second_occurrence_of_a_base_finding_is_new(self) -> None:
        head = [
            report("bugprone-use-after-move", "a.cpp", "h1", line=5),
            report("bugprone-use-after-move", "a.cpp", "h1", line=6),
        ]
        base = [report("bugprone-use-after-move", "a.cpp", "h1", line=5)]
        self.assertEqual(self.judge(head, base), 1)

    def test_fixed_then_reintroduced_is_new(self) -> None:
        # The merge base no longer has the finding an older state of main had.
        self.assertEqual(self.judge([report("cplusplus.Move", "a.cpp", "h1")], []), 1)

    def test_one_report_through_several_compilations_counts_once(self) -> None:
        same = report("bugprone-use-after-move", "a.h", "h1", line=3, column=4)
        twice = report("bugprone-use-after-move", "a.h", "h1", line=3, column=4)
        self.assertEqual(sa.count([same, twice]), collections.Counter({same.key: 1}))
        self.assertEqual(self.judge([same, twice], [same]), 0)

    def test_report_like_a_control_is_still_counted(self) -> None:
        # Controls run in their own invocation; nothing filters gate reports by
        # checker or message.
        control_like = sa.Report(
            "bugprone-unused-return-value", "clang-tidy", "src/x.cpp", 30, 3, "hx", "message"
        )
        self.assertEqual(self.judge([control_like], []), 1)


class Accounting(Workdir):
    def make(self, names: list[str], *, failed: list[str] = (), stats: dict | None = None) -> Path:
        out = self.tmp / "out"
        out.mkdir()
        for name in names:
            (out / f"{name}.plist").write_text("")
        if failed:
            (out / "failed").mkdir()
            for name in failed:
                (out / "failed" / f"{name}.plist_compile_error.zip").write_text("")
        analyzers = {}
        for analyzer in sa.ANALYZERS:
            analyzers[analyzer] = {
                "checkers": {check: True for check in sa.EXPECTED_CHECKERS[analyzer]},
                "analyzer_statistics": {
                    "failed": 0,
                    "successful": 1,
                    "version": sa.LLVM_VERSION,
                    **(stats or {}),
                },
            }
        (out / "metadata.json").write_text(json.dumps({"tools": [{"analyzers": analyzers}]}))
        return out

    def expected(self) -> dict[str, object]:
        entry = sa.Entry("/b", "/r/a.cpp", ("c++", "-c", "/r/a.cpp", "-o", "a.o"))
        return {f"a.cpp_{analyzer}_h": entry for analyzer in sa.ANALYZERS}

    def test_complete_records_pass(self) -> None:
        out = self.make(["a.cpp_clangsa_h", "a.cpp_clang-tidy_h"])
        sa.account(out, self.expected(), 1, "t")

    def test_failed_record_refuses(self) -> None:
        out = self.make(["a.cpp_clangsa_h", "a.cpp_clang-tidy_h"], failed=["a.cpp_clangsa_x"])
        with self.assertRaisesRegex(sa.Refusal, "failed analyses"):
            sa.account(out, self.expected(), 1, "t")

    def test_missing_record_refuses(self) -> None:
        out = self.make(["a.cpp_clangsa_h"])
        with self.assertRaisesRegex(sa.Refusal, "missing"):
            sa.account(out, self.expected(), 1, "t")

    def test_unexpected_record_refuses(self) -> None:
        out = self.make(["a.cpp_clangsa_h", "a.cpp_clang-tidy_h", "b.cpp_clangsa_h"])
        with self.assertRaisesRegex(sa.Refusal, "unexpected"):
            sa.account(out, self.expected(), 1, "t")

    def test_short_count_refuses(self) -> None:
        out = self.make(["a.cpp_clangsa_h", "a.cpp_clang-tidy_h"], stats={"successful": 0})
        with self.assertRaisesRegex(sa.Refusal, "analysed 0/1"):
            sa.account(out, self.expected(), 1, "t")

    def test_wrong_version_refuses(self) -> None:
        out = self.make(["a.cpp_clangsa_h", "a.cpp_clang-tidy_h"], stats={"version": "20.1.0"})
        with self.assertRaisesRegex(sa.Refusal, "version"):
            sa.account(out, self.expected(), 1, "t")

    def test_enabled_set_mismatch_refuses(self) -> None:
        out = self.make(["a.cpp_clangsa_h", "a.cpp_clang-tidy_h"])
        meta = json.loads((out / "metadata.json").read_text())
        meta["tools"][0]["analyzers"]["clang-tidy"]["checkers"]["bugprone-use-after-move"] = False
        (out / "metadata.json").write_text(json.dumps(meta))
        with self.assertRaisesRegex(sa.Refusal, "enabled checkers differ"):
            sa.account(out, self.expected(), 1, "t")

    def test_missing_metadata_refuses(self) -> None:
        out = self.make(["a.cpp_clangsa_h", "a.cpp_clang-tidy_h"])
        (out / "metadata.json").unlink()
        with self.assertRaisesRegex(sa.Refusal, "metadata"):
            sa.account(out, self.expected(), 1, "t")


class StandInCodeChecker(Workdir):
    """parse/analyze through a stand-in CodeChecker that misbehaves on request."""

    def setUp(self) -> None:
        super().setUp()
        self.behaviour = self.tmp / "behaviour.json"
        self.codechecker = write_tool(
            self.tmp / "CodeChecker",
            f"""
            import json, sys, os
            spec = json.load(open({str(self.behaviour)!r}))
            command = sys.argv[1]
            if command == "parse":
                target = sys.argv[sys.argv.index("-o") + 1]
                if spec.get("parse_output") is not None:
                    open(target, "w").write(spec["parse_output"])
                sys.exit(spec.get("parse_status", 2))
            if command == "analyze":
                out = sys.argv[sys.argv.index("-o") + 1]
                os.makedirs(out)
                for name in spec.get("records", []):
                    open(os.path.join(out, name + ".plist"), "w").close()
                json.dump(spec.get("metadata", {{}}), open(os.path.join(out, "metadata.json"), "w"))
                print("[INFO] analysis finished")
                sys.exit(spec.get("analyze_status", 0))
            sys.exit(9)
            """,
        )
        hashing = self.tmp / "pkg" / "codechecker_analyzer"
        hashing.mkdir(parents=True)
        (hashing / "__init__.py").write_text("")
        (hashing / "util.py").write_text(
            "import hashlib\n"
            "def analyzer_action_hash(file, directory, command):\n"
            "    return hashlib.md5((file + directory + command).encode()).hexdigest()\n"
        )
        os.environ["PYTHONPATH"] = str(self.tmp / "pkg")
        self.tools = sa.Tools(
            "clang", "clang++", "clang-tidy", "scan", str(self.codechecker), sys.executable
        )

    def tearDown(self) -> None:
        os.environ.pop("PYTHONPATH", None)
        super().tearDown()

    def configure(self, **spec: object) -> None:
        self.behaviour.write_text(json.dumps(spec))

    def parse(self) -> list[object]:
        out = self.tmp / "out"
        out.mkdir(exist_ok=True)
        return sa.parse_reports(out, self.tools, self.tmp, self.tmp / "build", "t")

    def row(self, **overrides: object) -> dict[str, object]:
        row = {
            "checker_name": "bugprone-use-after-move",
            "analyzer_name": "clang-tidy",
            "file": {"original_path": str(self.tmp / "a.cpp")},
            "line": 3,
            "column": 5,
            "report_hash": "abc",
            "message": "used after move",
        }
        row.update(overrides)
        return row

    def test_reports_are_read_with_relative_paths(self) -> None:
        self.configure(parse_output=json.dumps({"version": 1, "reports": [self.row()]}))
        [found] = self.parse()
        self.assertEqual((found.path, found.line, found.report_hash), ("a.cpp", 3, "abc"))

    def test_unexpected_parse_status_refuses(self) -> None:
        self.configure(
            parse_output=json.dumps({"version": 1, "reports": [self.row()]}), parse_status=3
        )
        with self.assertRaisesRegex(sa.Refusal, "parse exited 3"):
            self.parse()

    def test_malformed_parse_output_refuses(self) -> None:
        self.configure(parse_output="{not json")
        with self.assertRaisesRegex(sa.Refusal, "malformed"):
            self.parse()

    def test_missing_parse_output_refuses(self) -> None:
        self.configure(parse_output=None)
        with self.assertRaisesRegex(sa.Refusal, "missing or malformed"):
            self.parse()

    def test_report_without_hash_refuses(self) -> None:
        row = self.row()
        del row["report_hash"]
        self.configure(parse_output=json.dumps({"version": 1, "reports": [row]}))
        with self.assertRaisesRegex(sa.Refusal, "report_hash is not a hex string"):
            self.parse()

    def test_status_and_content_must_agree(self) -> None:
        self.configure(
            parse_output=json.dumps({"version": 1, "reports": [self.row()]}), parse_status=0
        )
        with self.assertRaisesRegex(sa.Refusal, "exited 0 but"):
            self.parse()
        self.configure(parse_output=json.dumps({"version": 1, "reports": []}), parse_status=2)
        with self.assertRaisesRegex(sa.Refusal, "list is empty"):
            self.parse()

    def test_unsupported_schema_version_refuses(self) -> None:
        self.configure(parse_output=json.dumps({"version": 2, "reports": [self.row()]}))
        with self.assertRaisesRegex(sa.Refusal, "version 2 is not supported"):
            self.parse()

    def test_report_fields_are_validated(self) -> None:
        cases = {
            "unknown analyzer": {"analyzer_name": "cppcheck"},
            "is not enabled for clang-tidy": {"checker_name": "misc-unused-using-decls"},
            "is not enabled for clangsa": {"analyzer_name": "clangsa"},
            "not a positive integer": {"line": 0},
            "not a hex string": {"report_hash": "not-hex"},
            "not an absolute path": {"file": {"original_path": "a.cpp"}},
            "message is not a string": {"message": 3},
        }
        for why, overrides in cases.items():
            with self.subTest(why=why):
                self.configure(
                    parse_output=json.dumps({"version": 1, "reports": [self.row(**overrides)]})
                )
                with self.assertRaisesRegex(sa.Refusal, why):
                    self.parse()

    def analyze_spec(self, entry: object, status: int) -> None:
        names = sa.action_names([entry], self.tools)
        analyzers = {
            analyzer: {
                "checkers": {check: True for check in sa.EXPECTED_CHECKERS[analyzer]},
                "analyzer_statistics": {"failed": 0, "successful": 1, "version": sa.LLVM_VERSION},
            }
            for analyzer in sa.ANALYZERS
        }
        self.configure(
            records=sorted(names),
            metadata={"tools": [{"analyzers": analyzers}]},
            analyze_status=status,
        )

    def test_clean_analysis_with_complete_records_passes(self) -> None:
        entry = sa.Entry(
            str(self.tmp), str(self.tmp / "a.cpp"), ("c++", "-c", "a.cpp", "-o", "a.o")
        )
        self.analyze_spec(entry, 0)
        sa.analyze([entry], self.tools, self.tmp / "side", 1, 10, "t")

    def test_failed_analysis_refuses_even_with_complete_records(self) -> None:
        entry = sa.Entry(
            str(self.tmp), str(self.tmp / "a.cpp"), ("c++", "-c", "a.cpp", "-o", "a.o")
        )
        self.analyze_spec(entry, 3)
        with self.assertRaisesRegex(sa.Refusal, "analyze exited 3"):
            sa.analyze([entry], self.tools, self.tmp / "side", 1, 10, "t")

    def test_reused_report_directory_refuses(self) -> None:
        entry = sa.Entry(
            str(self.tmp), str(self.tmp / "a.cpp"), ("c++", "-c", "a.cpp", "-o", "a.o")
        )
        (self.tmp / "side").mkdir()
        with self.assertRaisesRegex(sa.Refusal, "already exists"):
            sa.analyze([entry], self.tools, self.tmp / "side", 1, 10, "t")

    def test_two_compilations_codechecker_cannot_tell_apart_refuse(self) -> None:
        one = sa.Entry(str(self.tmp), str(self.tmp / "a.cpp"), ("c++", "-c", "a.cpp", "-o", "a.o"))
        with self.assertRaisesRegex(sa.Refusal, "indistinguishable"):
            sa.action_names([one, one], self.tools)

    def test_control_must_report_exactly_its_marks(self) -> None:
        root = self.tmp / "root"
        control = root / sa.CONTROL_DIR
        control.mkdir(parents=True)
        lines = ["int main() {"]
        for check in sorted(sa.BLOCKING):
            lines.append(f"  f();  // expect: {check}")
        lines.append("}")
        (control / "c.cpp").write_text("\n".join(lines) + "\n")
        marks = [
            self.row(
                checker_name=check,
                analyzer_name="clangsa" if check in sa.CLANGSA_BLOCKING else "clang-tidy",
                file={"original_path": str(control / "c.cpp")},
                line=number,
            )
            for number, check in enumerate(sorted(sa.BLOCKING), start=2)
        ]
        work = self.tmp / "work"
        work.mkdir()
        for case, rows in (
            ("exact", marks),
            ("missing", marks[1:]),
            ("extra", marks + [self.row(file={"original_path": str(control / "c.cpp")}, line=1)]),
        ):
            with self.subTest(case=case):
                for stale in work.glob("controls*"):
                    if stale.is_dir():
                        for item in stale.iterdir():
                            item.unlink()
                        stale.rmdir()
                    else:
                        stale.unlink()
                entry = sa.Entry(
                    str(work),
                    str(control / "c.cpp"),
                    (
                        "clang++",
                        "-std=c++20",
                        "-c",
                        str(control / "c.cpp"),
                        "-o",
                        str(work / "controls-obj" / "c.cpp.o"),
                    ),
                )
                self.analyze_spec(entry, 0)
                spec = json.loads(self.behaviour.read_text())
                spec["parse_output"] = json.dumps({"version": 1, "reports": rows})
                self.behaviour.write_text(json.dumps(spec))
                if case == "exact":
                    self.assertEqual(
                        sa.run_controls(root, self.tools, work, 1, 10), len(sa.BLOCKING)
                    )
                else:
                    with self.assertRaisesRegex(sa.Refusal, "positive controls"):
                        sa.run_controls(root, self.tools, work, 1, 10)

    def test_blocking_check_without_control_refuses(self) -> None:
        root = self.tmp / "root"
        control = root / sa.CONTROL_DIR
        control.mkdir(parents=True)
        (control / "c.cpp").write_text("int main() {}  // expect: cplusplus.Move\n")
        with self.assertRaisesRegex(sa.Refusal, "without a positive control"):
            sa.run_controls(root, self.tools, self.tmp, 1, 10)


class Suppressions(Workdir):
    def find(self, *lines: str) -> tuple[list[object], list[str]]:
        found, problems, file_problems = sa.find_suppressions("a.cpp", list(lines))
        return found, problems + file_problems

    def test_exact_check_with_reason_is_accepted(self) -> None:
        found, problems = self.find(
            "x = f();  // NOLINT(bugprone-unused-return-value): result logged by f"
        )
        self.assertEqual(problems, [])
        self.assertEqual(found[0].covers, frozenset({1}))

    def test_bare_nolint_refuses(self) -> None:
        _, problems = self.find("x = f();  // NOLINT")
        self.assertIn("without an exact check name", problems[0])

    def test_reasonless_suppression_refuses(self) -> None:
        _, problems = self.find("// NOLINTNEXTLINE(bugprone-use-after-move)", "use(x);")
        self.assertIn("without a reason", problems[0])

    def test_all_and_wildcards_refuse(self) -> None:
        for text in (
            "// codechecker_suppress [all] noisy",
            "// NOLINT(bugprone-*): noisy",
            "// NOLINT(readability-magic-numbers): not an enabled check",
        ):
            with self.subTest(text=text):
                _, problems = self.find(text)
                self.assertIn("not exact enabled checks", problems[0])

    def test_codechecker_comment_covers_the_next_line(self) -> None:
        found, problems = self.find(
            "// codechecker_false_positive [cplusplus.Move] the value is reassigned first",
            "use(s);",
        )
        self.assertEqual(problems, [])
        self.assertEqual(found[0].covers, frozenset({2}))

    def test_a_reasoned_exact_range_is_still_refused(self) -> None:
        _, problems = self.find(
            "// NOLINTBEGIN(bugprone-use-after-move): generated parser keeps moved tokens",
            "a();",
            "// NOLINTEND(bugprone-use-after-move)",
        )
        self.assertTrue(problems)
        self.assertTrue(all("ranges are not allowed" in p for p in problems))

    def test_a_whole_file_range_refuses_even_away_from_the_changed_lines(self) -> None:
        source = self.tmp / "a.cpp"
        source.write_text(
            "// NOLINTBEGIN(bugprone-use-after-move): the whole file, with a reason\n"
            "void f();\nvoid g();\nvoid h();\n"
            "// NOLINTEND(bugprone-use-after-move)\n"
        )
        change = sa.Change(changed_lines={"a.cpp": {3}})
        with self.assertRaisesRegex(sa.Refusal, "ranges are not allowed"):
            sa.audit_suppressions(self.tmp, change)

    def test_a_suppression_above_a_changed_line_is_audited(self) -> None:
        source = self.tmp / "a.cpp"
        source.write_text("// NOLINTNEXTLINE(bugprone-use-after-move)\nuse(x);\n")
        with self.assertRaisesRegex(sa.Refusal, "without a reason"):
            sa.audit_suppressions(self.tmp, sa.Change(changed_lines={"a.cpp": {2}}))
        source.write_text("// NOLINTNEXTLINE(bugprone-use-after-move): reassigned first\nuse(x);\n")
        [accepted] = sa.audit_suppressions(self.tmp, sa.Change(changed_lines={"a.cpp": {2}}))
        self.assertEqual(accepted.line, 1)

    def test_a_read_fragment_of_any_suffix_is_audited(self) -> None:
        fragment = self.tmp / "opcodes.tbl"
        change = sa.Change(changed_lines={"opcodes.tbl": {1}})
        fragment.write_text("X(drop, f());  // NOLINT(bugprone-unused-return-value)\n")
        # Not read by any compilation: not C/C++ input, not audited.
        self.assertEqual(sa.audit_suppressions(self.tmp, change), [])
        with self.assertRaisesRegex(sa.Refusal, "without a reason"):
            sa.audit_suppressions(self.tmp, change, {"opcodes.tbl"})
        fragment.write_text(
            "X(drop, f());  // NOLINT(bugprone-unused-return-value): table rows ignore it\n"
        )
        [accepted] = sa.audit_suppressions(self.tmp, change, {"opcodes.tbl"})
        self.assertEqual(accepted.path, "opcodes.tbl")

    def test_a_reasonless_suppression_in_an_inc_fragment_is_refused(self) -> None:
        (self.tmp / "bindings.inc").write_text("f();  // NOLINT(bugprone-unused-return-value)\n")
        with self.assertRaisesRegex(sa.Refusal, "without a reason"):
            sa.audit_suppressions(self.tmp, sa.Change(changed_lines={"bindings.inc": {1}}))

    def test_every_nolint_on_a_line_is_audited(self) -> None:
        for suffix in ("NOLINT", "NOLINT(*)", "NOLINT(bugprone-use-after-move)"):
            with self.subTest(suffix=suffix):
                _, problems = self.find(
                    "f(); // NOLINT(bugprone-unused-return-value): already logged " + suffix
                )
                self.assertTrue(problems, "a later suppression was swallowed as the reason")

    def test_two_reasoned_suppressions_are_both_reported(self) -> None:
        found, problems = self.find(
            "f(); // NOLINT(bugprone-unused-return-value): already logged "
            "NOLINT(bugprone-use-after-move): reassigned first"
        )
        self.assertEqual(problems, [])
        self.assertEqual(len(found), 2)

    def test_later_directive_is_not_a_reason_for_the_first(self) -> None:
        _, problems = self.find(
            "f(); // NOLINT(bugprone-unused-return-value) "
            "NOLINT(bugprone-use-after-move): reassigned first"
        )
        self.assertTrue(any("without a reason" in p for p in problems))

    def test_a_range_cannot_hide_after_a_line_suppression(self) -> None:
        source = self.tmp / "a.cpp"
        source.write_text(
            "// NOLINT(bugprone-use-after-move): reviewed "
            "NOLINTBEGIN(bugprone-unused-return-value)\n"
            "void f();\nvoid g();\n"
            "// NOLINT(bugprone-use-after-move): reviewed "
            "NOLINTEND(bugprone-unused-return-value)\n"
        )
        with self.assertRaisesRegex(sa.Refusal, "ranges are not allowed"):
            sa.audit_suppressions(self.tmp, sa.Change(changed_lines={"a.cpp": {3}}))

    def test_a_later_codechecker_suppression_is_audited(self) -> None:
        _, problems = self.find(
            "// codechecker_suppress [cplusplus.Move] reassigned codechecker_suppress [all] hidden"
        )
        self.assertTrue(any("not exact enabled checks" in p for p in problems))

    def test_mixed_directives_cannot_supply_each_others_reason(self) -> None:
        for text in (
            "// NOLINT(bugprone-use-after-move) codechecker_suppress [cplusplus.Move] reassigned",
            "// codechecker_suppress [cplusplus.Move] NOLINT(bugprone-use-after-move): reassigned",
        ):
            with self.subTest(text=text):
                _, problems = self.find(text)
                self.assertTrue(any("without a reason" in p for p in problems))


class Repository(Workdir):
    def git(self, *args: str) -> str:
        return subprocess.run(
            ["git", "-C", str(self.repo), *args], check=True, capture_output=True, text=True
        ).stdout

    def setUp(self) -> None:
        super().setUp()
        self.repo = self.tmp / "repo"
        self.repo.mkdir()
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "user.name", "test")
        for name, text in {
            "a.cpp": "one\ntwo\nthree\nfour\n",
            "gone.h": "x\n",
            "old.h": "a\nb\nc\nd\ne\nf\n",
            "keep.cpp": "1\n2\n3\n",
        }.items():
            (self.repo / name).write_text(text)
        self.git("add", ".")
        self.git("commit", "-q", "-m", "base")
        self.base = self.git("rev-parse", "HEAD").strip()

    def test_merge_base_checkout_must_be_clean_and_at_the_commit(self) -> None:
        sa.check_clean_at(self.repo, self.base)
        (self.repo / "a.cpp").write_text("edited\n")
        with self.assertRaisesRegex(sa.Refusal, "local changes"):
            sa.check_clean_at(self.repo, self.base)
        self.git("commit", "-q", "-am", "next")
        with self.assertRaisesRegex(sa.Refusal, "not at the merge base"):
            sa.check_clean_at(self.repo, self.base)

    def test_changed_lines_of_a_read_fragment_are_collected_on_demand(self) -> None:
        (self.repo / "rows.tbl").write_text("a\nb\nc\n")
        self.git("add", "rows.tbl")
        self.git("commit", "-q", "-m", "fragment")
        base = self.git("rev-parse", "HEAD").strip()
        (self.repo / "rows.tbl").write_text("a\nB\nc\n")
        (self.repo / "new.tbl").write_text("x\ny\n")
        change = sa.collect_change(self.repo, base)
        self.assertNotIn("rows.tbl", change.changed_lines)  # not C/C++ by suffix
        sa.add_changed_lines(self.repo, base, change, {"rows.tbl", "new.tbl"})
        self.assertEqual(change.changed_lines["rows.tbl"], {2})
        self.assertTrue({1, 2} <= change.changed_lines["new.tbl"])

    def test_change_set_covers_every_kind(self) -> None:
        (self.repo / "a.cpp").write_text("one\nTWO\nthree\nfour\n")
        (self.repo / "gone.h").unlink()
        self.git("mv", "old.h", "new.h")
        (self.repo / "keep.cpp").write_text("1\n3\n")  # deletion-only hunk
        (self.repo / "untracked.cpp").write_text("int x;\n")
        change = sa.collect_change(self.repo, self.base)
        self.assertEqual(change.head_paths, {"a.cpp", "new.h", "keep.cpp", "untracked.cpp"})
        self.assertEqual(change.base_paths, {"a.cpp", "gone.h", "old.h", "keep.cpp"})
        self.assertEqual(change.changed_lines["a.cpp"], {2})
        self.assertTrue({1, 2} <= change.changed_lines["keep.cpp"])
        self.assertIn(1, change.changed_lines["untracked.cpp"])

    def assert_bare_suppression_refused(self, path: str, line: int = 2) -> None:
        change = sa.collect_change(self.repo, self.base)
        self.assertIn(line, change.changed_lines.get(path, set()))
        with self.assertRaisesRegex(sa.Refusal, "without an exact check name"):
            sa.audit_suppressions(self.repo, change)

    def test_diff_prefix_preferences_cannot_skip_the_audit(self) -> None:
        (self.repo / "a.cpp").write_text("one\nf(); // NOLINT\nthree\nfour\n")
        self.git("config", "diff.noprefix", "true")
        self.assert_bare_suppression_refused("a.cpp")
        self.git("config", "diff.noprefix", "false")
        self.git("config", "diff.mnemonicprefix", "true")
        self.assert_bare_suppression_refused("a.cpp")

    def test_quoted_and_literal_paths_cannot_skip_the_audit(self) -> None:
        names = (
            "unicode-東京.cpp",
            'quote"name.cpp',
            "back\\slash.cpp",
            "colon:name.cpp",
            "tab\tname.cpp",
            "line\nname.cpp",
            "glob[1].cpp",
            "-option.cpp",
        )
        for name in names:
            (self.repo / name).write_text("one\ntwo\n")
        self.git("add", ".")
        self.git("commit", "-q", "-m", "paths")
        self.base = self.git("rev-parse", "HEAD").strip()
        for name in names:
            with self.subTest(name=name):
                (self.repo / name).write_text("one\nf(); // NOLINT\n")
                self.assert_bare_suppression_refused(name)
                (self.repo / name).write_text("one\ntwo\n")

    def test_binary_diff_attributes_cannot_skip_the_audit(self) -> None:
        (self.repo / ".gitattributes").write_text("*.cpp -diff\n")
        (self.repo / "a.cpp").write_text("one\nf(); // NOLINT\nthree\nfour\n")
        self.assert_bare_suppression_refused("a.cpp")

    def test_textconv_cannot_hide_suppressions_or_run_code(self) -> None:
        marker = self.tmp / "textconv-ran"
        converter = write_tool(
            self.tmp / "textconv",
            f"from pathlib import Path\nPath({str(marker)!r}).touch()\nprint('constant')\n",
        )
        (self.repo / ".gitattributes").write_text("*.cpp diff=hidden\n")
        self.git("config", "diff.hidden.textconv", str(converter))
        (self.repo / "a.cpp").write_text("one\nf(); // NOLINT\nthree\nfour\n")
        self.assert_bare_suppression_refused("a.cpp")
        self.assertFalse(marker.exists())

    def test_pure_renames_audit_the_destination(self) -> None:
        (self.repo / "a.cpp").write_text("one\nf(); // NOLINT\nthree\nfour\n")
        self.git("commit", "-q", "-am", "inherited suppression")
        self.base = self.git("rev-parse", "HEAD").strip()
        self.git("mv", "a.cpp", "renamed.cpp")
        self.assert_bare_suppression_refused("renamed.cpp")


class Database(Workdir):
    def build(self, entries: list[dict[str, object]], home: Path | None = None) -> Path:
        build = self.tmp / "build"
        build.mkdir(exist_ok=True)
        (build / "CMakeCache.txt").write_text(f"CMAKE_HOME_DIRECTORY:INTERNAL={home or self.tmp}\n")
        (build / "compile_commands.json").write_text(json.dumps(entries))
        return build

    def entry(self, *extra: str, output: str = "a.o") -> dict[str, object]:
        return {
            "directory": str(self.tmp / "build"),
            "file": str(self.tmp / "a.cpp"),
            "arguments": ["c++", *extra, "-c", str(self.tmp / "a.cpp"), "-o", output],
        }

    def test_valid_database_loads(self) -> None:
        [entry] = sa.load_database(self.build([self.entry()]), self.tmp)
        self.assertEqual(entry.output, str(self.tmp / "build" / "a.o"))

    def test_database_of_another_checkout_refuses(self) -> None:
        with self.assertRaisesRegex(sa.Refusal, "configured for"):
            sa.load_database(self.build([self.entry()], home=Path("/elsewhere")), self.tmp)

    def test_unsupported_arguments_refuse(self) -> None:
        for extra in (["@flags.rsp"], ["-include", "pre.h"], ["-include-pch", "x.pch"]):
            with self.subTest(extra=extra):
                with self.assertRaises(sa.Refusal):
                    sa.load_database(self.build([self.entry(*extra)]), self.tmp)

    def test_duplicate_outputs_refuse(self) -> None:
        with self.assertRaisesRegex(sa.Refusal, "same output"):
            sa.load_database(self.build([self.entry(), self.entry("-DX")]), self.tmp)

    def test_missing_output_refuses(self) -> None:
        bad = self.entry()
        bad["arguments"] = ["c++", "-c", str(self.tmp / "a.cpp")]
        with self.assertRaisesRegex(sa.Refusal, "no -o output"):
            sa.load_database(self.build([bad]), self.tmp)

    def test_identity_ignores_checkout_build_and_output(self) -> None:
        one = sa.Entry(
            "/h/b", "/h/a.cpp", ("c++", "-I/h/x", "-I/h/b/g", "-c", "/h/a.cpp", "-o", "1.o")
        )
        two = sa.Entry(
            "/o/b", "/s/a.cpp", ("c++", "-I/s/x", "-I/o/b/g", "-c", "/s/a.cpp", "-o", "2.o")
        )
        self.assertEqual(
            sa.identity(one, Path("/h"), Path("/h/b")), sa.identity(two, Path("/s"), Path("/o/b"))
        )

    def test_identical_compilations_collapse_to_one(self) -> None:
        one = sa.Entry("/h/b", "/h/m.cpp", ("c++", "-c", "/h/m.cpp", "-o", "t2/m.o"))
        two = sa.Entry("/h/b", "/h/m.cpp", ("c++", "-c", "/h/m.cpp", "-o", "t1/m.o"))
        other = sa.Entry("/h/b", "/h/m.cpp", ("c++", "-DX", "-c", "/h/m.cpp", "-o", "t3/m.o"))
        chosen = sa.representatives([one, two, other], Path("/h"), Path("/h/b"))
        self.assertEqual(sorted(e.output for e in chosen.values()), ["/h/b/t1/m.o", "/h/b/t3/m.o"])

    def test_identity_keeps_the_working_directory(self) -> None:
        # The same relative -Iinc names different trees from different directories.
        for name, text in (("one/inc/x.h", "int a;"), ("two/inc/x.h", "int b;")):
            (self.tmp / name).parent.mkdir(parents=True, exist_ok=True)
            (self.tmp / name).write_text(text)
        args = ("c++", "-Iinc", "-c", f"{self.tmp}/a.cpp")
        one = sa.Entry(str(self.tmp / "one"), f"{self.tmp}/a.cpp", (*args, "-o", "1.o"))
        two = sa.Entry(str(self.tmp / "two"), f"{self.tmp}/a.cpp", (*args, "-o", "2.o"))
        self.assertNotEqual(
            sa.identity(one, self.tmp, self.tmp / "build"),
            sa.identity(two, self.tmp, self.tmp / "build"),
        )
        self.assertEqual(len(sa.representatives([one, two], self.tmp, self.tmp / "build")), 2)

    def layout(self) -> tuple[Path, Path, Path, Path]:
        """BASE is a main checkout; HEAD is a worktree nested inside it."""
        base = self.tmp / "main"
        head = base / ".claude" / "worktrees" / "w"
        base_build = self.tmp / "base-build"
        head_build = self.tmp / "head-build"
        for directory in (head / "src", base / "src", base_build, head_build):
            directory.mkdir(parents=True, exist_ok=True)
        for path in (head / "src" / "a.h", base / "src" / "a.h"):
            path.write_text("")
        return head, head_build, base, base_build

    def contained(self, side: str, paths: set[str]) -> None:
        head, head_build, base, base_build = self.layout()
        entry = sa.Entry("/b", "/x.cpp", ("c++",))
        own, other = ((head, head_build), (base, base_build))
        if side == "BASE":
            own, other = other, own
        sa.check_contained({entry: paths}, own, other, ["/usr/include"], side)

    def test_each_side_reads_its_own_tree_build_and_system_dirs(self) -> None:
        head, head_build, base, base_build = self.layout()
        self.contained(
            "HEAD", {str(head / "src" / "a.h"), str(head_build / "g.h"), "/usr/include/stdio.h"}
        )
        self.contained("BASE", {str(base / "src" / "a.h"), str(base_build / "g.h")})

    def test_base_reading_the_nested_head_worktree_refuses(self) -> None:
        head, _, _, _ = self.layout()
        with self.assertRaisesRegex(sa.Refusal, "outside its checkout"):
            self.contained("BASE", {str(head / "src" / "a.h")})

    def test_a_symlink_into_the_other_side_refuses(self) -> None:
        head, _, base, _ = self.layout()
        link = base / "src" / "link.h"
        link.symlink_to(head / "src" / "a.h")
        with self.assertRaisesRegex(sa.Refusal, "outside its checkout"):
            self.contained("BASE", {str(link)})

    def test_a_dependency_outside_every_allowed_directory_refuses(self) -> None:
        stray = self.tmp / "elsewhere" / "x.h"
        stray.parent.mkdir()
        stray.write_text("")
        with self.assertRaisesRegex(sa.Refusal, "outside its checkout"):
            self.contained("HEAD", {str(stray)})

    def test_sides_sharing_a_build_refuse(self) -> None:
        head, head_build, base, _ = self.layout()
        entry = sa.Entry("/b", "/x.cpp", ("c++",))
        with self.assertRaisesRegex(sa.Refusal, "share"):
            sa.check_contained({entry: set()}, (head, head_build), (base, head_build), [], "HEAD")

    def side(self, label: str, entries: list[object], deps: dict) -> object:
        return sa.Side(label, self.tmp, self.tmp / "build", entries, deps, set())

    def test_generated_files_that_differ_between_the_sides_are_changes(self) -> None:
        sides = []
        for name, schema, header in (("head", "new", "same"), ("base", "old", "same")):
            root, build = self.tmp / name, self.tmp / f"{name}-build"
            (root / "gen").mkdir(parents=True)
            (build / "inc").mkdir(parents=True)
            (root / "gen" / "api.cpp").write_text(schema)
            (build / "inc" / "config.h").write_text(header)
            generated = {str(root / "gen" / "api.cpp"), str(build / "inc" / "config.h")}
            if name == "head":
                (build / "inc" / "only-head.h").write_text("x")
                generated.add(str(build / "inc" / "only-head.h"))
            sides.append(sa.Side(name, root, build, [], {}, generated))
        head, base = sides
        changed_head, changed_base = sa.generated_changes(head, base)
        self.assertEqual(
            changed_head,
            {str(head.root / "gen" / "api.cpp"), str(head.build / "inc" / "only-head.h")},
        )
        self.assertEqual(changed_base, {str(base.root / "gen" / "api.cpp")})

    def test_a_changed_generated_file_selects_its_compilations_and_readers(self) -> None:
        generated_source = str(self.tmp / "gen" / "api.cpp")
        generated_header = str(self.tmp / "build" / "config.h")
        own = sa.Entry("/b", generated_source, ("c++", "-o", "api.o"))
        reader = sa.Entry("/b", str(self.tmp / "r.cpp"), ("c++", "-o", "r.o"))
        bystander = sa.Entry("/b", str(self.tmp / "z.cpp"), ("c++", "-o", "z.o"))
        deps = {own: {generated_source}, reader: {generated_header}, bystander: set()}
        side = self.side("HEAD", [own, reader, bystander], deps)
        chosen, _ = sa.select_side(side, set(), set(), {generated_source, generated_header})
        self.assertEqual(chosen, {own, reader})

    def test_a_deleted_source_must_be_in_the_base_database(self) -> None:
        a = sa.Entry("/b", str(self.tmp / "a.cpp"), ("c++", "-o", "a.o"))
        side = self.side("BASE", [a], {a: {str(self.tmp / "a.cpp")}})
        chosen, _ = sa.select_side(side, {"a.cpp"}, set())
        self.assertEqual(chosen, {a})
        with self.assertRaisesRegex(sa.Refusal, "BASE: changed sources missing"):
            sa.select_side(side, {"gone.cpp"}, set())

    def fragment_side(self, fragment: str) -> tuple[object, object, object]:
        """One compilation reading a fragment, one reading nothing else."""
        reader = sa.Entry("/b", str(self.tmp / "a.cpp"), ("c++", "-o", "a.o"))
        bystander = sa.Entry("/b", str(self.tmp / "b.cpp"), ("c++", "-o", "b.o"))
        deps = {
            reader: {str(self.tmp / "a.cpp"), str(self.tmp / fragment)},
            bystander: {str(self.tmp / "b.cpp")},
        }
        return self.side("HEAD", [reader, bystander], deps), reader, bystander

    def test_a_changed_inc_fragment_selects_its_readers(self) -> None:
        side, reader, _ = self.fragment_side("metrics/bindings.inc")
        chosen, orphans = sa.select_side(side, {"metrics/bindings.inc"}, set())
        self.assertEqual((chosen, orphans), ({reader}, set()))

    def test_a_read_fragment_of_any_suffix_selects_its_readers(self) -> None:
        side, reader, _ = self.fragment_side("tables/opcodes.tbl")
        read = sa.read_by_compilations(side, {"tables/opcodes.tbl", "docs/notes.txt"})
        self.assertEqual(read, {"tables/opcodes.tbl"})
        chosen, _ = sa.select_side(side, set(), set(), {str(self.tmp / p) for p in read})
        self.assertEqual(chosen, {reader})

    def test_an_unread_file_of_unknown_suffix_selects_nothing(self) -> None:
        side, _, _ = self.fragment_side("tables/opcodes.tbl")
        self.assertEqual(sa.read_by_compilations(side, {"docs/notes.txt"}), set())
        self.assertEqual(sa.select_side(side, set(), set(), set()), (set(), set()))

    def test_a_base_header_no_compilation_includes_refuses_unless_listed(self) -> None:
        a = sa.Entry("/b", str(self.tmp / "a.cpp"), ("c++", "-o", "a.o"))
        side = self.side("BASE", [a], {a: {str(self.tmp / "a.cpp")}})
        with self.assertRaisesRegex(sa.Refusal, "BASE: changed headers no compilation includes"):
            sa.select_side(side, {"old.h"}, set())
        _, orphans = sa.select_side(side, {"old.h"}, {"old.h"})
        self.assertEqual(orphans, {"old.h"})

    def test_select_finds_includers_and_orphans(self) -> None:
        root = self.tmp
        a = sa.Entry("/b", str(root / "a.cpp"), ("c++", "-o", "a.o"))
        b = sa.Entry("/b", str(root / "b.cpp"), ("c++", "-o", "b.o"))
        deps = {a: {str(root / "a.cpp"), str(root / "x.h")}, b: {str(root / "b.cpp")}}
        chosen, orphans = sa.select([a, b], deps, root, {"b.cpp"}, {"x.h", "lonely.h"})
        self.assertEqual(chosen, {a, b})
        self.assertEqual(orphans, {"lonely.h"})


class Choosing(Workdir):
    """choose(), prepare_side() and report keys across two real-looking sides."""

    def setUp(self) -> None:
        super().setUp()
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        self.path = os.environ["PATH"]
        os.environ["PATH"] = f"{self.bin}{os.pathsep}{self.path}"
        write_tool(self.bin / "ninja", "import sys\nsys.exit(0)\n")
        self.scan = write_tool(
            self.tmp / "scan",
            """
            import json, shlex, sys
            rows = json.load(open(sys.argv[sys.argv.index("-compilation-database") + 1]))
            for row in rows:
                args = shlex.split(row["command"])
                print(args[args.index("-o") + 1] + ": " + row["file"])
            """,
        )
        self.tools = sa.Tools(
            "clang", "clang++", "clang-tidy", str(self.scan), "cc", sys.executable
        )

    def tearDown(self) -> None:
        os.environ["PATH"] = self.path
        super().tearDown()

    def side(self, name: str, files: dict[str, str], flags: dict[str, str]) -> object:
        """A git checkout with an in-checkout build; files are relative to the checkout."""
        root = self.tmp / name
        build = root / f"build-{name}"
        build.mkdir(parents=True)
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        (build / "CMakeCache.txt").write_text(f"CMAKE_HOME_DIRECTORY:INTERNAL={root}\n")
        rows = []
        for rel, text in files.items():
            path = root / rel.replace("<build>", build.name)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
            extra = flags.get(rel, "")
            rows.append(
                {
                    "directory": str(build),
                    "file": str(path),
                    "command": f"c++ {extra} -c {path} -o {path.name}.o".replace("  ", " "),
                }
            )
        (build / "compile_commands.json").write_text(json.dumps(rows))
        return sa.prepare_side(name.upper(), root, build, self.tools, self.tmp)

    def test_a_generated_source_in_the_build_is_analysed_when_it_differs(self) -> None:
        head = self.side("head", {"a.cpp": "x", "<build>/auto/code.cpp": "new"}, {})
        base = self.side("base", {"a.cpp": "x", "<build>/auto/code.cpp": "old"}, {})
        self.assertEqual(len(head.entries), 2)
        generated = sa.generated_changes(head, base)
        self.assertEqual(generated[0], {str(head.build / "auto" / "code.cpp")})
        head_run, base_run, _ = sa.choose(head, base, (set(), set()), generated, set(), False)
        self.assertEqual([e.file for e in head_run], [str(head.build / "auto" / "code.cpp")])
        self.assertEqual([e.file for e in base_run], [str(base.build / "auto" / "code.cpp")])

    def test_third_party_build_products_are_not_analysed(self) -> None:
        head = self.side("head", {"a.cpp": "x", "<build>/third-party/lib.cpp": "x"}, {})
        self.assertEqual([Path(e.file).name for e in head.entries], ["a.cpp"])

    def test_a_changed_compile_definition_alone_selects_the_compilation(self) -> None:
        head = self.side("head", {"a.cpp": "x", "b.cpp": "y"}, {"a.cpp": "-DNEW=1"})
        base = self.side("base", {"a.cpp": "x", "b.cpp": "y"}, {})
        head_run, base_run, _ = sa.choose(head, base, (set(), set()), (set(), set()), set(), False)
        self.assertEqual([Path(e.file).name for e in head_run], ["a.cpp"])
        self.assertEqual([Path(e.file).name for e in base_run], ["a.cpp"])

    def test_identical_configurations_select_nothing(self) -> None:
        head = self.side("head", {"a.cpp": "x"}, {})
        base = self.side("base", {"a.cpp": "x"}, {})
        self.assertEqual(
            sa.choose(head, base, (set(), set()), (set(), set()), set(), False), ([], [], set())
        )

    def test_full_mode_still_refuses_a_missing_source_or_an_orphan(self) -> None:
        head = self.side("head", {"a.cpp": "x"}, {})
        base = self.side("base", {"a.cpp": "x"}, {})
        with self.assertRaisesRegex(sa.Refusal, "changed sources missing"):
            sa.choose(head, base, ({"new.cpp"}, set()), (set(), set()), set(), True)
        with self.assertRaisesRegex(sa.Refusal, "changed headers no compilation includes"):
            sa.choose(head, base, ({"lonely.h"}, set()), (set(), set()), set(), True)
        head_run, base_run, _ = sa.choose(head, base, (set(), set()), (set(), set()), set(), True)
        self.assertEqual((len(head_run), len(base_run)), (1, 1))

    def test_reports_in_differently_named_in_checkout_builds_share_a_key(self) -> None:
        def row(root: Path, build: str) -> dict[str, object]:
            return {
                "checker_name": "bugprone-use-after-move",
                "analyzer_name": "clang-tidy",
                "file": {"original_path": str(root / build / "gen" / "api.h")},
                "line": 3,
                "column": 1,
                "report_hash": "abc",
            }

        head_root, base_root = self.tmp / "h", self.tmp / "b"
        head = sa.read_report(
            row(head_root, "build-head"), head_root, head_root / "build-head", "H"
        )
        base = sa.read_report(
            row(base_root, "build-base"), base_root, base_root / "build-base", "B"
        )
        self.assertEqual(head.key, base.key)
        self.assertEqual(sa.judge([head], [base], []), 0)


class StandInTools(Workdir):
    """clang-scan-deps, ninja and clang-tidy stand-ins."""

    def setUp(self) -> None:
        super().setUp()
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        self.path = os.environ["PATH"]
        os.environ["PATH"] = f"{self.bin}{os.pathsep}{self.path}"

    def tearDown(self) -> None:
        os.environ["PATH"] = self.path
        super().tearDown()

    def scan(self, output: str, status: int = 0) -> object:
        tool = write_tool(
            self.tmp / "scan",
            f"import sys\nsys.stdout.write({output!r})\nsys.exit({status})\n",
        )
        return sa.Tools("clang", "clang++", "clang-tidy", str(tool), "cc", sys.executable)

    def entries(self) -> list[object]:
        return [
            sa.Entry(str(self.tmp), str(self.tmp / "a.cpp"), ("c++", "-c", "a.cpp", "-o", "a.o")),
            sa.Entry(str(self.tmp), str(self.tmp / "b.cpp"), ("c++", "-c", "b.cpp", "-o", "b.o")),
        ]

    def test_scan_maps_targets_to_compilations(self) -> None:
        tools = self.scan(f"a.o: {self.tmp}/a.cpp \\\n  {self.tmp}/x.h\nb.o: {self.tmp}/b.cpp\n")
        deps = sa.scan_dependencies(self.entries(), tools, self.tmp, "HEAD")
        self.assertEqual(deps[self.entries()[0]], {f"{self.tmp}/a.cpp", f"{self.tmp}/x.h"})

    def test_scan_failures_refuse(self) -> None:
        for output, status, message in (
            ("a.o: a.cpp\n", 1, "clang-scan-deps failed"),
            ("a.o: a.cpp\n", 0, "covered 1 of 2"),
            ("a.o: a.cpp\nz.o: z.cpp\n", 0, "unknown or repeated"),
            ("a.o: a\\ b.cpp\nb.o: b.cpp\n", 0, "contains a space"),
        ):
            with self.subTest(message=message):
                with self.assertRaisesRegex(sa.Refusal, message):
                    sa.scan_dependencies(
                        self.entries(), self.scan(output, status), self.tmp, "HEAD"
                    )

    def ninja(self, targets: str, status: int = 0, reconfigure: bool = False) -> Path:
        """A stand-in ninja: '-t targets all' lists outputs, anything else is a build."""
        log = self.tmp / "ninja-calls.json"
        database = self.tmp / "build" / "compile_commands.json"
        database.parent.mkdir(parents=True, exist_ok=True)
        database.write_text("[]")
        write_tool(
            self.bin / "ninja",
            f"""
            import json, os, sys
            calls = json.load(open({str(log)!r})) if os.path.exists({str(log)!r}) else []
            calls.append(sys.argv[1:])
            json.dump(calls, open({str(log)!r}, "w"))
            if "-t" in sys.argv:
                sys.stdout.write({targets!r})
                sys.exit(0)
            if {reconfigure!r}:
                open({str(database)!r}, "w").write('[{{"changed": true}}]')
            sys.exit({status})
            """,
        )
        return log

    def test_builds_exactly_the_generated_outputs_it_knows(self) -> None:
        build = self.tmp / "build"
        log = self.ninja(f"gen/api.h: CUSTOM_COMMAND\n{self.tmp}/root/auto.cpp: CUSTOM_COMMAND\n")
        sa.bring_up_to_date(
            build,
            {str(build / "gen" / "api.h"), f"{self.tmp}/root/auto.cpp", str(build / "config.h")},
            "HEAD",
        )
        self.assertEqual(
            json.loads(log.read_text())[-1],
            ["-C", str(build), f"{self.tmp}/root/auto.cpp", "gen/api.h"],
        )

    def test_a_failed_build_refuses(self) -> None:
        build = self.tmp / "build"
        self.ninja("gen/api.h: CUSTOM_COMMAND\n", status=1)
        with self.assertRaisesRegex(sa.Refusal, "building the generated files failed"):
            sa.bring_up_to_date(build, {str(build / "gen" / "api.h")}, "HEAD")

    def test_a_build_that_reconfigures_refuses(self) -> None:
        build = self.tmp / "build"
        self.ninja("gen/api.h: CUSTOM_COMMAND\n", reconfigure=True)
        with self.assertRaisesRegex(sa.Refusal, "reconfigured itself"):
            sa.bring_up_to_date(build, {str(build / "gen" / "api.h")}, "HEAD")

    def test_without_generated_outputs_the_manifest_is_still_brought_up_to_date(self) -> None:
        # Configure-time files are not outputs; building build.ninja refreshes them.
        build = self.tmp / "build"
        log = self.ninja("gen/api.h: CUSTOM_COMMAND\n")
        sa.bring_up_to_date(build, {str(build / "config.h")}, "HEAD")
        self.assertEqual(json.loads(log.read_text())[-1][-1], "build.ninja")

    def test_a_build_that_changes_the_generated_set_refuses(self) -> None:
        # The second scan, after the build, reaches a generated header the first did not.
        root = self.tmp / "root"
        build = self.tmp / "build"
        root.mkdir()
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        self.ninja("gen/a.h: CUSTOM_COMMAND\ngen/b.h: CUSTOM_COMMAND\n")
        (build / "CMakeCache.txt").write_text(f"CMAKE_HOME_DIRECTORY:INTERNAL={root}\n")
        source = root / "a.cpp"
        source.write_text("")
        (build / "compile_commands.json").write_text(
            json.dumps(
                [
                    {
                        "directory": str(build),
                        "file": str(source),
                        "command": f"c++ -c {source} -o a.o",
                    }
                ]
            )
        )
        counter = self.tmp / "scans"
        scan = write_tool(
            self.tmp / "scan",
            f"""
            import os, sys
            n = int(open({str(counter)!r}).read()) + 1 if os.path.exists({str(counter)!r}) else 1
            open({str(counter)!r}, "w").write(str(n))
            extra = " {build}/gen/b.h" if n > 1 else ""
            sys.stdout.write("a.o: {source} {build}/gen/a.h" + extra + "\\n")
            """,
        )
        tools = sa.Tools("clang", "clang++", "clang-tidy", str(scan), "cc", sys.executable)
        with self.assertRaisesRegex(sa.Refusal, "changed which generated files are read"):
            sa.prepare_side("HEAD", root, build, tools, self.tmp)

    def compiler(self, stderr: str, status: int = 0) -> object:
        tool = write_tool(
            self.tmp / "clang++",
            f"import sys\nsys.stderr.write({stderr!r})\nsys.exit({status})\n",
        )
        return sa.Tools("clang", str(tool), "clang-tidy", "scan", "cc", sys.executable)

    def test_system_directories_are_read_from_the_compiler(self) -> None:
        listing = (
            'clang version x\n#include "..." search starts here:\n'
            "#include <...> search starts here:\n /usr/include/c++/15\n /usr/include\n"
            "End of search list.\n"
        )
        self.assertEqual(
            sa.system_directories(self.compiler(listing)),
            [os.path.realpath("/usr/include/c++/15"), "/usr/include"],
        )
        with self.assertRaisesRegex(sa.Refusal, "unexpected output"):
            sa.system_directories(self.compiler("no listing here\n"))
        with self.assertRaisesRegex(sa.Refusal, "cannot list"):
            sa.system_directories(self.compiler("", 1))

    def tidy(self, checks: list[str], options: dict[str, str]) -> object:
        option_lines = "".join(f"  {key}: '{value}'\\n" for key, value in options.items())
        listing = "Enabled checks:\\n" + "".join(f"    {check}\\n" for check in checks)
        tool = write_tool(
            self.tmp / "clang-tidy",
            f"""
            import sys
            if "--list-checks" in sys.argv:
                sys.stdout.write("{listing}")
            else:
                sys.stdout.write("---\\nCheckOptions:\\n{option_lines}")
            """,
        )
        return sa.Tools("clang", "clang++", str(tool), "scan", "cc", sys.executable)

    def test_rule_set_agreement(self) -> None:
        good = sorted(sa.EXPECTED_CHECKERS["clang-tidy"])
        sa.check_rule_set(self.tmp, self.tidy(good, sa.CLANG_TIDY_OPTIONS))
        with self.assertRaisesRegex(sa.Refusal, "disagrees"):
            sa.check_rule_set(self.tmp, self.tidy(good[1:], sa.CLANG_TIDY_OPTIONS))
        with self.assertRaisesRegex(sa.Refusal, "disagrees"):
            sa.check_rule_set(
                self.tmp, self.tidy(good + ["misc-unused-using-decls"], sa.CLANG_TIDY_OPTIONS)
            )
        broken = dict(sa.CLANG_TIDY_OPTIONS)
        broken["bugprone-unused-return-value.CheckedReturnTypes"] = "^::td::Status$"
        with self.assertRaisesRegex(sa.Refusal, "CheckedReturnTypes"):
            sa.check_rule_set(self.tmp, self.tidy(good, broken))

    def test_wrong_tool_version_refuses(self) -> None:
        llvm = self.tmp / "llvm"
        llvm.mkdir()
        for name in ("clang", "clang++", "clang-tidy", "clang-scan-deps"):
            write_tool(llvm / name, "print('Ubuntu clang version 20.1.8')\n")
        with self.assertRaisesRegex(sa.Refusal, "is not LLVM"):
            sa.resolve_tools(llvm, None)

    def test_codechecker_using_other_analyzer_binaries_refuses(self) -> None:
        llvm = self.tmp / "llvm"
        llvm.mkdir()
        for name in ("clang", "clang++", "clang-tidy", "clang-scan-deps"):
            write_tool(llvm / name, f"print('clang version {sa.LLVM_VERSION}')\n")
        version = {"analyzer": {"base_package_version": sa.CODECHECKER_VERSION}}
        rows = [
            {"name": "clangsa", "path": "/usr/bin/other-clang", "version": sa.LLVM_VERSION},
            {"name": "clang-tidy", "path": str(llvm / "clang-tidy"), "version": sa.LLVM_VERSION},
        ]
        codechecker = write_tool(
            self.tmp / "CodeChecker",
            f"""
            import json, sys
            print("[INFO] log line before the JSON")
            print(json.dumps({version!r} if sys.argv[1] == "version" else {rows!r}))
            """,
        )
        with self.assertRaisesRegex(sa.Refusal, "uses /usr/bin/other-clang"):
            sa.resolve_tools(llvm, str(codechecker))

    def test_discovery_commands_must_succeed_before_their_json_is_read(self) -> None:
        llvm = self.tmp / "llvm"
        llvm.mkdir()
        for name in ("clang", "clang++", "clang-tidy", "clang-scan-deps"):
            write_tool(llvm / name, f"print('clang version {sa.LLVM_VERSION}')\n")
        version = {"analyzer": {"base_package_version": sa.CODECHECKER_VERSION}}
        rows = [
            {"name": "clangsa", "path": str(llvm / "clang"), "version": sa.LLVM_VERSION},
            {"name": "clang-tidy", "path": str(llvm / "clang-tidy"), "version": sa.LLVM_VERSION},
        ]
        for failing in ("", "version", "analyzers"):
            with self.subTest(failing=failing):
                codechecker = write_tool(
                    self.tmp / "CodeChecker",
                    f"""
                    import json, sys
                    print(json.dumps({version!r} if sys.argv[1] == "version" else {rows!r}))
                    sys.exit(1 if sys.argv[1] == {failing!r} else 0)
                    """,
                )
                if not failing:
                    sa.resolve_tools(llvm, str(codechecker))
                    continue
                with self.assertRaisesRegex(sa.Refusal, f"CodeChecker {failing} exited 1"):
                    sa.resolve_tools(llvm, str(codechecker))


class DiscardPolicy(unittest.TestCase):
    def test_explicit_discard_requires_auditable_suppression(self) -> None:
        key = "bugprone-unused-return-value.AllowCastToVoid"
        self.assertEqual(sa.CLANG_TIDY_OPTIONS[key], "false")
        self.assertIn(
            "clang-tidy:bugprone-unused-return-value:AllowCastToVoid=false",
            sa.analyzer_arguments(),
        )
        self.assertIn(key + ": false", (HERE.parent / ".clang-tidy").read_text())

    def test_controls_cover_c_style_and_static_cast_discards(self) -> None:
        source = (HERE.parent / sa.CONTROL_DIR / "unused-status.cpp").read_text()
        for statement in (
            "(void)write_record(4);",
            "(void)read_record(5);",
            "static_cast<void>(write_record(6));",
            "static_cast<void>(read_record(7));",
        ):
            with self.subTest(statement=statement):
                self.assertRegex(
                    source, re.escape(statement) + r"[ \t]+// expect: bugprone-unused-return-value"
                )


if __name__ == "__main__":
    unittest.main()
