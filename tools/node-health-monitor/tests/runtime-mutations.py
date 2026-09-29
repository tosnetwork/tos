#!/usr/bin/env python3
"""Compiled behavior mutations for the independent monitoring runtime."""
import os
import json
import pathlib
import subprocess
ROOT = pathlib.Path(__file__).resolve().parents[1]
CASES = [
    ('queue-residence-age', 'health-services', 'manager', 'manager.rs', '.checked_add(elapsed)', '.checked_add(0)', 'queued_observation_cannot_be_rejuvenated'),
    ('database-network', 'health-services', 'manager', 'durable.rs', 'if stored != network {', 'if false {', 'database_aliases_cannot_defeat_isolation'),
    ('multiple-quarantines', 'health-services', 'manager', 'manager.rs', 'entry.epochs.insert(epoch);', 'entry.epochs.clear(); entry.epochs.insert(epoch);', 'conflict_quarantines_live_rule_and_receipt_controls_outbox'),
    ('complete-facts', 'health-core', 'rules', 'rules.rs', 'frame.complete && frame.facts.len() != source.facts.len()', 'false', 'facts_cannot_escape_catalog_or_network'),
    ('probe-node-binding', 'health-services', 'ingress', 'manager_poll.rs', '&& v["node_id"].as_str() == Some(&config.node_id)', '&& true', 'scheduled_probe_uses_mtls_and_never_claims_consensus_health'),
    ('receiver-https', 'health-services', 'ingress', 'manager.rs', 'url.scheme() != "https"', 'false', 'scheduled_probe_uses_mtls_and_never_claims_consensus_health'),
    ('rule-conflict', 'health-core', 'rules', 'freshness.rs', '&& !self.conflicted', '&& true', 'missing_and_conflicting_sources_are_unknown'),
    ('rule-cache-age', 'health-core', 'rules', 'freshness.rs', 'return Ok(false);', 'self.accepted_ms = now; return Ok(false);', 'cache_duplicates_do_not_renew_rule_quality'),
    ('counter-baseline', 'health-core', 'rules', 'rules.rs', 'h.counter.filter(|old| value >= *old).map(|old| value > old)', 'Some(false)', 'counter_rule_needs_baseline_and_does_not_recount'),
    ('pending-generations', 'health-core', 'rules', 'rules.rs', 'h.bad_samples >= r.minimum_bad_samples', 'true', 'bad_hold_and_distinct_samples_are_both_required'),
    ('expected-inventory', 'health-core', 'rules', 'rules.rs', 'Some(!usable)', 'Some(false)', 'telemetry_inventory_detects_never_seen_source'),
    ('network-binding', 'health-core', 'rules', 'rules.rs', 'if frame.network_id != self.inventory.network_id {', 'if false {', 'facts_cannot_escape_catalog_or_network'),
    ('retired-epoch', 'health-core', 'rules', 'observer.rs', 'self.retired.contains(epoch) || self.retired.len() >= 32', 'self.retired.len() >= 32', 'retired_heartbeat_and_repeats_cannot_extend_deadlines'),
    ('scalar-threshold', 'health-core', 'rules', 'rules.rs', 'Some(value > r.threshold.0)', 'Some(value < r.threshold.0)', 'scalar_rules_use_only_their_frozen_facts'),
    ('round-rollback', 'health-services', 'durable', 'durable.rs', 'if n >= self.max_outbox {', 'if false {', 'whole_round_rolls_back_when_any_outbox_change_fails'),
    ('inventory-revision', 'health-services', 'durable', 'durable.rs', 'if old != body {', 'if false {', 'immutable_inventory_revision_is_enforced'),
    ('mtls-fingerprint', 'health-services', 'ingress', 'ingress.rs', 'peers.get(&digest).cloned()', 'peers.values().next().cloned()', 'mtls_acl_rejects_missing_expired_and_unapproved_before_upstream'),
    ('mtls-role', 'health-services', 'ingress', 'ingress.rs', '(Role::ManagerIngest, "/v1/manager/facts")', '(Role::ManagerIngest | Role::EdgeReader, "/v1/manager/facts")', 'mtls_acl_rejects_missing_expired_and_unapproved_before_upstream'),
    ('receipt-matching', 'health-services', 'manager', 'manager.rs', '!receipt.accepted || receipt.idempotency_key != key || receipt.payload_hash != hash', 'false', 'conflict_quarantines_live_rule_and_receipt_controls_outbox'),
    ('live-conflict', 'health-services', 'manager', 'manager.rs', 'engine.quarantine(node, scope, source, process, source_epoch);', '', 'conflict_quarantines_live_rule_and_receipt_controls_outbox'),
    ('process-persistence', 'health-services', 'manager', 'durable.rs', 'db.restore_unknown()?;', 'db.conn.execute("DELETE FROM incidents", []).map_err(err)?;', 'killed_process_reopens_active_incident_as_unknown'),
    ('database-isolation', 'health-services', 'manager', 'manager.rs', 'if same_database(&config.control_db, &config.evidence_db)? {', 'if false {', 'database_aliases_cannot_defeat_isolation'),
    ('pipeline-monitor', 'health-services', 'watchdog', 'watchdog.rs', '|| alert.labels.monitor_id != self.monitor_id', '|| false', 'pipeline_requires_own_firing_new_evaluation'),
    ('pipeline-firing', 'health-services', 'watchdog', 'watchdog.rs', 'alert.status != "firing"', 'false', 'pipeline_requires_own_firing_new_evaluation'),
]
def run(package, test, name):
    return subprocess.run(['cargo', 'test', '--locked', '--manifest-path', str(ROOT/'Cargo.toml'), '-p', 'tos-'+package, '--test', test, name, '--', '--exact'], text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,env={**os.environ,"CARGO_INCREMENTAL":"0"})
def main():
    results=[]
    for label, package, test, file, old, new, name in CASES:
        baseline=run(package,test,name)
        assert baseline.returncode == 0 and '1 passed; 0 failed' in baseline.stdout, baseline.stdout
        path=ROOT/'crates'/package/'src'/file
        original=path.read_text()
        expected=2 if label=='rule-cache-age' else 1
        assert original.count(old)==expected, (label,original.count(old))
        try:
            path.write_text(original.replace(old,new,1))
            mutant=run(package,test,name)
        finally:
            path.write_text(original)
        assert mutant.returncode != 0 and '0 passed; 1 failed' in mutant.stdout and f'test {name} ... FAILED' in mutant.stdout, (label,mutant.stdout)
        results.append({'mutation':label,'test':name,'baseline':'passed','mutant':'compiled_and_failed'})
        print(label+': compiled and failed',flush=True)
    print(json.dumps(results,indent=2))
if __name__=='__main__': main()
