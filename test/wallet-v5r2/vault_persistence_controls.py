"""Reproduce predictable Vault temporary-file clobbering and require its repair."""

import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TEST = "save_does_not_follow_predictable_temporary_symlink"
OLD_SAVE = """    async fn safe_save(data: &str, file_path: &Path) -> anyhow::Result<()> {
        use tokio::io::AsyncWriteExt;
        let temp_path = file_path.with_extension("tmp");
        let mut file = tokio::fs::File::create(&temp_path).await?;
        file.write_all(data.as_bytes()).await?;
        file.sync_all().await?;
        drop(file);
        tokio::fs::rename(&temp_path, file_path).await?;
        Ok(())
    }

"""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    path = ROOT / "tosctl/src/secrets-vault/src/storage/file_json.rs"
    original = path.read_text()
    start = original.index("    async fn safe_save(")
    end = original.index("    async fn migrate_to(", start)

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
                TEST,
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
        assert code == 0 and "1 passed; 0 failed" in log, log[-4000:]

    try:
        positive("baseline")
        path.write_text(original[:start] + OLD_SAVE + original[end:])
        code, log = run("predictable-temp")
        witness = "predictable temporary symlink clobbered unrelated file"
        assert code != 0 and "test result: FAILED" in log and witness in log, log[-4000:]
    finally:
        path.write_text(original)
        positive("restored")
    (args.output / "results.json").write_text(
        json.dumps({"exit": code, "semantic_witness": witness}, indent=2) + "\n"
    )
    print("Predictable temporary-file control detected; restored test passes")


if __name__ == "__main__":
    main()
