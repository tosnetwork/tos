from pathlib import Path

import tl

if __name__ == "__main__":
    repo_root = Path(__file__).resolve().parents[2]
    schemas_root = repo_root / "tl/generate/scheme"

    schemas = [
        schemas_root / "lite_api.tl",
        schemas_root / "tos_api.tl",
        schemas_root / "toslib_api.tl",
    ]
    out_directory = repo_root / "test/tostester/src/tosapi"

    for schema in schemas:
        tl.generate(schema, out_directory)

    tl.generate(
        repo_root / "test/tostester/tests/tl/test_schema.tl",
        repo_root / "test/tostester/tests/tl/generated",
    )
