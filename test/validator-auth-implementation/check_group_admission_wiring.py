"""Pin validator-group liveness to the current authenticated-session owner path.

The production rule is now stronger than the old sidecar identity confirmation:
an active P0 validator group may materialize only after session birth/committee
admission and the durable CommittedNativeSession fence.  This checker pins the
manager events that can release a remembered refusal, including the catchain
transition case where an applied state is ahead of the independently finalized
head.
"""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MANAGER = ROOT / "validator/manager.cpp"


def section(text: str, begin: str, end: str) -> str:
    i = text.index(begin)
    j = text.index(end, i)
    return text[i:j]


def verify(text: str) -> None:
    gate = section(
        text,
        "// P0 is genesis-activated.",
        "if (destroyed_validator_sessions_.contains(val_group_id))",
    )
    for token in (
        "validator_auth_groups_ready()",
        "validator_auth_admission_.defer_groups();",
        "ensure_validator_auth_session_store();",
        "ensure_validator_auth_session(",
        "active_validator_groups_master_ : active_validator_groups_shard_",
    ):
        if token not in gate:
            raise ValueError("active-group-gate-" + token)

    admission = section(
        text,
        "void ValidatorManagerImpl::fail_validator_auth_session_admission",
        "void ValidatorManagerImpl::establish_validator_auth_chain",
    )
    for token in (
        "validator_auth_session_refused_at_[session_id]",
        "validator_auth_admission_.defer_groups();",
        "refused->second >= validator_auth_finalized_anchor_->seqno_",
        "NativeSessionCommitteeAdmission",
        "CommittedNativeSession::restart",
        "CommittedNativeSession::commit_new",
    ):
        if token not in admission:
            raise ValueError("session-admission-" + token)

    publish = section(
        text,
        "void ValidatorManagerImpl::publish_validator_auth_finalized_head",
        "void ValidatorManagerImpl::validator_auth_finality_journal_written",
    )
    same = "if (anchor.seqno_ == validator_auth_finalized_anchor_->seqno_)"
    if same not in publish:
        raise ValueError("same-finalized-head-is-not-deduplicated")
    same_body = publish[publish.index(same):]
    if "return;" not in same_body[:700]:
        raise ValueError("duplicate-finalized-head-can-redrive")
    for token in (
        "release_terminated_validator_auth_sessions();",
        "validator_auth_admission_.create_deferred_groups(",
        "validator_auth_groups_ready()",
        "update_shards();",
    ):
        if token not in publish:
            raise ValueError("finalized-head-redrive-" + token)
    if publish.index("release_terminated_validator_auth_sessions();") > publish.index("update_shards();"):
        raise ValueError("terminated-owner-released-after-redrive")

    cleanup = section(
        text,
        "void ValidatorManagerImpl::got_pending_validator_consensus_db_cleanup",
        "void ValidatorManagerImpl::sweep_destroyed_consensus_dbs",
    )
    if "validator_auth_admission_.cleanup_records_loaded();" not in cleanup:
        raise ValueError("cleanup-startup-barrier-missing")

    # Store provisioning is the other asynchronous startup condition. Both the
    # reopen and marker-commit paths must be able to release a remembered pass.
    store = section(
        text,
        "void ValidatorManagerImpl::validator_auth_session_store_marker_written",
        "tos::BlockIdExt ValidatorManagerImpl::validator_auth_session_block_id",
    )
    if store.count("validator_auth_admission_.create_deferred_groups(") < 2:
        raise ValueError("session-store-arrivals-do-not-redrive")


def main() -> None:
    text = MANAGER.read_text()
    verify(text)

    # A silent source checker is not evidence. Each removal below must make the
    # same verifier reject the edited text.
    probes = (
        "validator_auth_session_refused_at_[session_id]",
        "refused->second >= validator_auth_finalized_anchor_->seqno_",
        "release_terminated_validator_auth_sessions();",
        "validator_auth finalized head advanced; retrying deferred validator groups",
        "validator_auth_admission_.cleanup_records_loaded();",
    )
    for token in probes:
        changed = text.replace(token, "/* removed */", 1)
        if changed == text:
            raise RuntimeError("negative control changed nothing: " + token)
        try:
            verify(changed)
        except ValueError:
            pass
        else:
            raise RuntimeError("negative control survived: " + token)

    # Removing only the finalized-head retry, while leaving startup/store
    # retries intact, is the exact first-block regression.
    publish = section(
        text,
        "void ValidatorManagerImpl::publish_validator_auth_finalized_head",
        "void ValidatorManagerImpl::validator_auth_finality_journal_written",
    )
    redrive = """  if (validator_auth_admission_.create_deferred_groups(
          validator_auth_groups_ready())) {
    LOG(INFO) << "validator-auth finalized head advanced; retrying deferred validator groups";
    update_shards();
  }
"""
    if redrive not in publish:
        raise RuntimeError("finalized-head redrive anchor missing")
    changed = text.replace(redrive, "", 1)
    try:
        verify(changed)
    except ValueError:
        pass
    else:
        raise RuntimeError("first-block liveness negative control survived")

    print("PASS: deferred validator sessions are retried when their transition block becomes durably finalized")


if __name__ == "__main__":
    main()
