"""Small controls for the observer-churn route's verdict, without a node network."""

import ast
import inspect
import textwrap

from test_simplex2_release import (
    _observer_churn,
    _observer_integrity_failures,
    _observer_lifecycle,
)


def test_observer_lifecycle_pairs_exact_shard_session_and_adnl_in_log_order():
    log = (
        "\x1b[1;36mCreated observer group (0,8000).2 at adnl-A\x1b[0m\n"
        "Started observer group (0,8000).2 at adnl-A\n"
        "Destroying observer group (0,8000).2 at adnl-A\n"
        "Created observer group (0,8000).3 at adnl-A\n"
        "Started observer group (0,8000).3 at adnl-A\n"
    )
    errors, cc_seqnos = _observer_lifecycle(log)
    assert errors == []
    assert cc_seqnos == {2, 3}


def test_observer_lifecycle_rejects_equal_counts_with_mismatched_identity():
    log = (
        "Created observer group (0,8000).2 at adnl-A\n"
        "Started observer group (0,8000).2 at adnl-B\n"
        "Destroying observer group (0,8000).2 at adnl-C\n"
    )
    errors, cc_seqnos = _observer_lifecycle(log)
    assert cc_seqnos == {2}
    assert any("started without matching create" in error for error in errors)
    assert any("destroyed without matching start" in error for error in errors)


def test_observer_lifecycle_rejects_a_create_that_never_starts():
    errors, cc_seqnos = _observer_lifecycle(
        "Created observer group (0,8000).2 at adnl-A\n"
    )
    assert cc_seqnos == {2}
    assert any("created without matching start" in error for error in errors)


def test_observer_integrity_checks_each_node_and_distinct_session_numbers():
    failures = _observer_integrity_failures(
        start_heights=[2, 2],
        end_heights=[3, 2],
        lifecycle_errors=[[], []],
        cc_seqnos=[{2}, {2}],
    )
    assert any("node 2" in failure and "did not progress" in failure for failure in failures)
    assert any("distinct cc_seqno" in failure for failure in failures)


def test_observer_integrity_accepts_two_real_sessions_and_all_node_progress():
    assert _observer_integrity_failures(
        start_heights=[2, 2],
        end_heights=[3, 4],
        lifecycle_errors=[[], []],
        cc_seqnos=[{2}, {3}],
    ) == []


def test_route_verdict_consumes_observer_integrity_failures():
    """A pure helper test alone must not go green if the route stops calling it."""
    tree = ast.parse(textwrap.dedent(inspect.getsource(_observer_churn)))
    assert any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "failures"
        and node.func.attr == "extend"
        and len(node.args) == 1
        and isinstance(node.args[0], ast.Call)
        and isinstance(node.args[0].func, ast.Name)
        and node.args[0].func.id == "_observer_integrity_failures"
        for node in ast.walk(tree)
    ), "observer-churn verdict no longer consumes per-node, lifecycle and cc_seqno checks"
