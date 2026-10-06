"""Require file Vault instance and migration ownership guards to reject overlap."""

import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    path = ROOT / "tosctl/src/secrets-vault/src/storage/file_json.rs"
    original = path.read_text()
    lock = """        lock.try_lock()
            .map_err(|_| anyhow::anyhow!("Vault is already open or cannot be locked"))?;"""
    assert original.count(lock) == 1
    start = original.index("    pub async fn migrate(")
    end = original.index("    async fn migrate_locked(", start)
    migrate = """    pub async fn migrate(
        file_path: &Path,
        master_key: &KeyMaterial,
        crypto: &dyn Crypto,
    ) -> anyhow::Result<()> {
        Self::migrate_locked(file_path, master_key, crypto).await
    }

"""
    cases = [
        ("lock", original.replace(lock, ""), "second Vault instance acquired held lock"),
        (
            "migration",
            original[:start] + migrate + original[end:],
            "migration acquired held Vault lock",
        ),
    ]

    def run(label):
        result = subprocess.run(
            [
                "cargo",
                "test",
                "--manifest-path",
                str(ROOT / "tosctl/src/Cargo.toml"),
                "--locked",
                "-p",
                "secrets-vault",
                "--lib",
                "writer_lock_",
            ],
            capture_output=True,
            text=True,
            timeout=1200,
        )
        log = result.stdout + result.stderr
        (args.output / f"{label}.log").write_text(log)
        return result.returncode, log

    def positive(label):
        code, log = run(label)
        assert code == 0 and "2 passed; 0 failed" in log, log[-5000:]

    results = {}
    try:
        positive("baseline")
        for name, source, witness in cases:
            path.write_text(source)
            code, log = run(name)
            assert code != 0 and "test result: FAILED" in log and witness in log, log[-5000:]
            if name == "lock":
                assert "child Vault ownership mismatch" in log, log[-5000:]
            results[name] = {"exit": code, "semantic_witness": witness}
            path.write_text(original)
    finally:
        path.write_text(original)
        positive("restored")
    (args.output / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(f"{len(results)} Vault ownership controls detected; restored tests pass")


if __name__ == "__main__":
    main()
