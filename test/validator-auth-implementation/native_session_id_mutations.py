"""Compile native session identity producer mutations."""
import argparse
import json
import subprocess
from pathlib import Path

from context_mutations import checked, mutate

CPP = [
    ("shard-binding", "native-session-shard-binding",
     "if (selected_shard.workchain != input.workchain || selected_shard.shard != input.shard)",
     "if (false && (selected_shard.workchain != input.workchain || selected_shard.shard != input.shard))"),
    ("catchain", "native-session-catchain",
     "input, validator_set->get_catchain_seqno(), members, encoder",
     "input, 0, members, encoder"),
    ("group-catchain", "native-session-group",
     "workchain, shard, catchain, bits(options),",
     "workchain, shard, 0, bits(options),"),
    ("group-ex-vertical", "native-session-group-ex",
     "workchain, shard, vertical, catchain, bits(options),",
     "workchain, shard, 0, catchain, bits(options),"),
    ("group-new-key", "native-session-group-new",
     "workchain, shard, vertical, key_block, catchain,",
     "workchain, shard, vertical, 0, catchain,"),
    ("member-address", "native-session-group",
     "bits(member.short_id), bits(member.adnl_id), member.weight",
     "bits(member.short_id), td::Bits256::zero(), member.weight"),
    ("member-weight", "native-session-group",
     "bits(member.short_id), bits(member.adnl_id), member.weight",
     "bits(member.short_id), bits(member.adnl_id), std::uint64_t{1}"),
    ("member-order", "native-session-group",
     "auto validators = validator_set->export_vector();",
     "auto validators = validator_set->export_vector(); std::reverse(validators.begin(), validators.end());"),
]


def main(args):
    folder = args.build.resolve() / "validator/auth"
    path = folder / "mutated-native-session-id.cpp"

    def run():
        checked(["cmake", "--build", str(args.build.resolve()),
                 "--target", "test-p0-native-session-id-mutant", "-j2"])
        return subprocess.run(
            [str(folder / "test-p0-native-session-id-mutant")],
            capture_output=True, text=True)

    report = mutate(path, CPP, run)
    args.out.write_text(json.dumps({
        "native_session_id_mutations": report,
        "restored_baselines": True,
    }, indent=2) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    main(parser.parse_args())
