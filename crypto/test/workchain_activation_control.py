"""Fail-closed checks shared by isolated activation-pair acceptance drivers.

Records must come from the same actual host path. This checker does not produce
host observations or grant provenance to caller-supplied fields. The caller must
use the shared activation helper; this module defines no rejection classifier.
"""
class ControlFailure(RuntimeError):
    def __init__(self, identity):
        self.identity = identity
        super().__init__(str(identity))


def require(condition, identity):
    if not condition:
        raise ControlFailure(identity)


def check_closed_observations(record):
    # Unexpected release is a hard stop, never a skip or accepted fallback.
    require(record['status_code'] != 0, 303)
    require(record['status_code'] == -7201, 304)
    require(record['transactions'] == 0, 305)
    require(record['candidate_exports'] == [], 306)


def check_pair_context(enabled, closed):
    check_closed_observations(closed)
    require(enabled['run_id'] == closed['run_id'] and bool(enabled['run_id']), 307)
    require(enabled['host_path'] == closed['host_path'] and bool(enabled['host_path']), 308)
    require(enabled['input_sha256'] == closed['input_sha256'], 309)
    require(enabled['common_config_sha256'] == closed['common_config_sha256'], 310)
    require(enabled['config_origin'] == closed['config_origin'] == 'test-internal', 311)
    require(enabled['capability_enabled'] is True and closed['capability_enabled'] is False, 312)
    require(enabled['config_sha256'] != closed['config_sha256'], 313)
    require(enabled['reached_required_frontier'] is True, 314)


def check_pair(enabled, closed, *, boundary="collator"):
    # One implementation shared with all other reverse controls. Missing helper
    # and unknown statuses propagate as failures; there is no local substitute.
    from workchain_activation_rejection import is_activation_rejection
    check_pair_context(enabled, closed)
    require(is_activation_rejection(closed['status_code'], closed['status_message'], boundary=boundary), 315)
