from jsonschema import Draft202012Validator

RUN = {"type": "string", "format": "uuid"}
NODE = {"type": "string", "pattern": "^[a-z][a-z0-9_-]{0,63}$"}
TIME = {"type": "string", "format": "date-time"}

def enum(*values):
    return {"type": "string", "enum": list(values)}

def array(items, minimum=1, maximum=4):
    return {"type": "array", "items": items, "minItems": minimum,
            "maxItems": maximum, "uniqueItems": True}

def schema(properties):
    fields = {"run_id": RUN, **properties}
    return {"type": "object", "additionalProperties": False,
            "properties": fields, "required": list(fields)}

INPUT_SCHEMAS = {
    "tos_get_capabilities": schema({}),
    "tos_get_node_snapshot": schema({
        "node_id": NODE, "as_of": TIME,
        "max_age_seconds": {"type": "integer", "minimum": 1, "maximum": 180},
        "components": array(enum("process", "host", "chain", "consensus", "network",
                                 "storage", "index", "gpu", "telemetry", "deployment"), 1, 10)
    }),
    "tos_get_metric_window": schema({
        "node_ids": array(NODE),
        "metric_ids": array({"type": "string", "minLength": 1, "maxLength": 96}, 1, 6),
        "scope_id": NODE, "start": TIME, "end": TIME,
        "step_seconds": {"type": "integer", "enum": [15, 30, 60, 300]},
        "mode": enum("summary", "series"),
        "max_points_per_series": {"type": "integer", "minimum": 1, "maximum": 240}
    }),
    "tos_get_event_window": schema({
        "node_ids": array(NODE), "scope_id": NODE, "start": TIME, "end": TIME,
        "sources": array(enum("journal", "consensus_trace", "rocksdb", "rpc_probe",
                              "collector", "operator_change"), 1, 6),
        "kinds": array(enum("error", "warning", "consensus_stage", "storage_sample",
                            "lifecycle", "data_gap"), 1, 6),
        "correlation_id": {"type": "string", "maxLength": 160},
        "contains": {"type": "string", "maxLength": 128},
        "limit": {"type": "integer", "minimum": 1, "maximum": 100},
        "cursor": {"type": "string", "maxLength": 2048}
    }),
    "tos_get_change_history": schema({
        "node_ids": array(NODE), "start": TIME, "end": TIME,
        "kinds": array(enum("deploy", "restart", "config", "maintenance", "load_test",
                            "resource_limit"), 1, 6),
        "limit": {"type": "integer", "minimum": 1, "maximum": 100},
        "cursor": {"type": "string", "maxLength": 2048}
    }),
    "tos_get_block_evidence": schema({
        "node_ids": array(NODE),
        "reference_id": {"type": "string", "pattern": "^(blk|cand)_[A-Za-z0-9_-]{16,128}$"},
        "ancestor_depth": {"type": "integer", "minimum": 0, "maximum": 4},
        "max_events": {"type": "integer", "minimum": 1, "maximum": 100}
    })
}
for value in INPUT_SCHEMAS.values():
    Draft202012Validator.check_schema(value)

if __name__ == '__main__':
    import json
    from pathlib import Path
    target = Path(__file__).resolve().parents[1] / 'contracts' / 'tool-input-schemas.json'
    target.write_text(json.dumps(INPUT_SCHEMAS, indent=2) + '\n')
