"""Require real cache reuse and warning sensitivity on a tiny C/C++ build."""

import os
import shutil
import subprocess
import tarfile
import tempfile
import time
from pathlib import Path


def run(command: list[str], env: dict[str, str], *, success: bool = True) -> str:
    result = subprocess.run(command, env=env, capture_output=True, text=True)
    output = result.stdout + result.stderr
    if (result.returncode == 0) != success:
        raise RuntimeError(f"Unexpected status {result.returncode}: {command}\n{output}")
    return output


def stats(env: dict[str, str]) -> dict[str, int]:
    lines = run(["ccache", "--print-stats"], env).splitlines()
    return {key: int(value) for key, value in (line.split() for line in lines)}


def main() -> None:
    if not shutil.which("ccache"):
        raise SystemExit("A real ccache is required; refusing to skip this check")
    with tempfile.TemporaryDirectory(prefix="native-cache-test-") as directory:
        root = Path(directory)
        (root / "early").mkdir()
        (root / "CMakeLists.txt").write_text(
            "cmake_minimum_required(VERSION 3.17)\nproject(probe C CXX)\n"
            "add_compile_options(-Wall -Wextra -Werror)\nadd_subdirectory(early)\n"
            "add_executable(probe main.cpp)\ntarget_link_libraries(probe early)\n"
        )
        (root / "early/CMakeLists.txt").write_text("add_library(early STATIC early.c)\n")
        (root / "early/early.c").write_text("int answer(void) { return 42; }\n")
        header = root / "value.h"
        header.write_text("static inline int expected(void) { return 42; }\n")
        (root / "main.cpp").write_text(
            '#include "value.h"\nextern "C" int answer(void);\n'
            "int main() { return answer() != expected(); }\n"
        )
        env = dict(os.environ, CCACHE_DIR=str(root / "objects"), CCACHE_BASEDIR=str(root))
        for language in ("C", "CXX"):
            if env.get(f"CMAKE_{language}_COMPILER_LAUNCHER") != "ccache":
                raise RuntimeError(f"The shared action did not install the {language} launcher")
        build = root / "build"

        def rebuild(*, success: bool = True) -> str:
            shutil.rmtree(build, ignore_errors=True)
            run(["cmake", "-S", str(root), "-B", str(build), "-G", "Ninja"], env)
            run(["ccache", "--zero-stats"], env)
            return run(["cmake", "--build", str(build), "--parallel", "2"], env, success=success)

        # Let input timestamps settle without enabling sloppy cache handling.
        time.sleep(1.1)
        rebuild()
        cold = stats(env)
        if cold.get("cache_miss", 0) < 2:
            raise RuntimeError(f"Cold C and C++ compilations did not pass through ccache: {cold}")
        run([str(build / "probe")], env)
        archive = root / "objects.tar"
        with tarfile.open(archive, "w") as stream:
            stream.add(root / "objects", arcname="objects")
        shutil.rmtree(root / "objects")
        with tarfile.open(archive) as stream:
            stream.extractall(root, filter="data")
        rebuild()
        warm = stats(env)
        hits = warm.get("cache_hit_direct", 0) + warm.get("cache_hit_preprocessed", 0)
        if hits < 2 or warm.get("cache_miss", 0):
            raise RuntimeError(f"Restored-cache build did not reuse both compilations: {warm}")
        run([str(build / "probe")], env)
        header.write_text("static inline int expected(void) { int must_be_rejected; return 42; }\n")
        failure = rebuild(success=False)
        if "must_be_rejected" not in failure or "error:" not in failure:
            raise RuntimeError("The red control failed without the intended header warning")
        header.write_text("static inline int expected(void) { return 42; }\n")
        rebuild()
        run([str(build / "probe")], env)
        print(
            f"PASS: cold misses={cold['cache_miss']}; restored hits={hits}; "
            "header warning rejected; restored source passes"
        )


if __name__ == "__main__":
    main()
