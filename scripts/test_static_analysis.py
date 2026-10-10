#!/usr/bin/env python3
"""Self-test for scripts/static-analysis.py against stand-in tools.

The real gate needs CodeChecker, LLVM 21 and a configured build; this suite needs
none of them. It drives each fail-closed path with a stand-in that misbehaves in
one way and checks that the gate refuses, and it checks the comparison and the
suppression audit on fixed inputs.
"""

from __future__ import annotations

import collections
import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("static_analysis", HERE / "static-analysis.py")
assert SPEC is not None and SPEC.loader is not None
sa = importlib.util.module_from_spec(SPEC)
sys.modules["static_analysis"] = sa
SPEC.loader.exec_module(sa)


def write_tool(path: Path, body: str) -> Path:
    """A stand-in executable running the given Python body."""
    path.write_text(f"#!{sys.executable}\n" + textwrap.dedent(body))
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def report(checker: str, path: str, digest: str, line: int = 1, column: int = 1) -> object:
    return sa.Report(checker, "clang-tidy", path, line, column, digest, "message")


class Workdir(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name).resolve()

    def tearDown(self) -> None:
        self._tmp.cleanup()


class Comparison(unittest.TestCase):
    def judge(self, head: list[object], base: list[object]) -> int:
        return sa.judge(head, base, [])

    def test_new_blocking_fails(self) -> None:
        self.assertEqual(self.judge([report("bugprone-use-after-move", "a.cpp", "h1")], []), 1)

    def test_advisory_only_passes(self) -> None:
        self.assertEqual(self.judge([report("core.NullDereference", "a.cpp", "h1")], []), 0)

    def test_finding_already_at_base_passes(self) -> None:
        head = [report("bugprone-use-after-move", "a.cpp", "h1", line=9)]
        base = [report("bugprone-use-after-move", "a.cpp", "h1", line=7)]
        self.assertEqual(self.judge(head, base), 0)

    def test_second_occurrence_of_a_base_finding_is_new(self) -> None:
        head = [
            report("bugprone-use-after-move", "a.cpp", "h1", line=5),
            report("bugprone-use-after-move", "a.cpp", "h1", line=6),
        ]
        base = [report("bugprone-use-after-move", "a.cpp", "h1", line=5)]
        self.assertEqual(self.judge(head, base), 1)

    def test_fixed_then_reintroduced_is_new(self) -> None:
        # The merge base no longer has the finding an older state of main had.
        self.assertEqual(self.judge([report("cplusplus.Move", "a.cpp", "h1")], []), 1)

    def test_one_report_through_several_compilations_counts_once(self) -> None:
        same = report("bugprone-use-after-move", "a.h", "h1", line=3, column=4)
        twice = report("bugprone-use-after-move", "a.h", "h1", line=3, column=4)
        self.assertEqual(sa.count([same, twice]), collections.Counter({same.key: 1}))
        self.assertEqual(self.judge([same, twice], [same]), 0)

    def test_report_like_a_control_is_still_counted(self) -> None:
        # Controls run in their own invocation; nothing filters gate reports by
        # checker or message.
        control_like = sa.Report(
            "bugprone-unused-return-value", "clang-tidy", "src/x.cpp", 30, 3, "hx", "message"
        )
        self.assertEqual(self.judge([control_like], []), 1)


class Accounting(Workdir):
    def make(self, names: list[str], *, failed: list[str] = (), stats: dict | None = None) -> Path:
        out = self.tmp / "out"
        out.mkdir()
        for name in names:
            (out / f"{name}.plist").write_text("")
        if failed:
            (out / "failed").mkdir()
            for name in failed:
                (out / "failed" / f"{name}.plist_compile_error.zip").write_text("")
        analyzers = {}
        for analyzer in sa.ANALYZERS:
            analyzers[analyzer] = {
                "checkers": {check: True for check in sa.EXPECTED_CHECKERS[analyzer]},
                "analyzer_statistics": {
                    "failed": 0,
                    "successful": 1,
                    "version": sa.LLVM_VERSION,
                    **(stats or {}),
                },
            }
        (out / "metadata.json").write_text(json.dumps({"tools": [{"analyzers": analyzers}]}))
        return out

    def expected(self) -> dict[str, object]:
        entry = sa.Entry("/b", "/r/a.cpp", ("c++", "-c", "/r/a.cpp", "-o", "a.o"))
        return {f"a.cpp_{analyzer}_h": entry for analyzer in sa.ANALYZERS}

    def test_complete_records_pass(self) -> None:
        out = self.make(["a.cpp_clangsa_h", "a.cpp_clang-tidy_h"])
        sa.account(out, self.expected(), 1, "t")

    def test_failed_record_refuses(self) -> None:
        out = self.make(["a.cpp_clangsa_h", "a.cpp_clang-tidy_h"], failed=["a.cpp_clangsa_x"])
        with self.assertRaisesRegex(sa.Refusal, "failed analyses"):
            sa.account(out, self.expected(), 1, "t")

    def test_missing_record_refuses(self) -> None:
        out = self.make(["a.cpp_clangsa_h"])
        with self.assertRaisesRegex(sa.Refusal, "missing"):
            sa.account(out, self.expected(), 1, "t")

    def test_unexpected_record_refuses(self) -> None:
        out = self.make(["a.cpp_clangsa_h", "a.cpp_clang-tidy_h", "b.cpp_clangsa_h"])
        with self.assertRaisesRegex(sa.Refusal, "unexpected"):
            sa.account(out, self.expected(), 1, "t")

    def test_short_count_refuses(self) -> None:
        out = self.make(["a.cpp_clangsa_h", "a.cpp_clang-tidy_h"], stats={"successful": 0})
        with self.assertRaisesRegex(sa.Refusal, "analysed 0/1"):
            sa.account(out, self.expected(), 1, "t")

    def test_wrong_version_refuses(self) -> None:
        out = self.make(["a.cpp_clangsa_h", "a.cpp_clang-tidy_h"], stats={"version": "20.1.0"})
        with self.assertRaisesRegex(sa.Refusal, "version"):
            sa.account(out, self.expected(), 1, "t")

    def test_enabled_set_mismatch_refuses(self) -> None:
        out = self.make(["a.cpp_clangsa_h", "a.cpp_clang-tidy_h"])
        meta = json.loads((out / "metadata.json").read_text())
        meta["tools"][0]["analyzers"]["clang-tidy"]["checkers"]["bugprone-use-after-move"] = False
        (out / "metadata.json").write_text(json.dumps(meta))
        with self.assertRaisesRegex(sa.Refusal, "enabled checkers differ"):
            sa.account(out, self.expected(), 1, "t")

    def test_missing_metadata_refuses(self) -> None:
        out = self.make(["a.cpp_clangsa_h", "a.cpp_clang-tidy_h"])
        (out / "metadata.json").unlink()
        with self.assertRaisesRegex(sa.Refusal, "metadata"):
            sa.account(out, self.expected(), 1, "t")


class StandInCodeChecker(Workdir):
    """parse/analyze through a stand-in CodeChecker that misbehaves on request."""

    def setUp(self) -> None:
        super().setUp()
        self.behaviour = self.tmp / "behaviour.json"
        self.codechecker = write_tool(
            self.tmp / "CodeChecker",
            f"""
            import json, sys, os
            spec = json.load(open({str(self.behaviour)!r}))
            command = sys.argv[1]
            if command == "parse":
                target = sys.argv[sys.argv.index("-o") + 1]
                if spec.get("parse_output") is not None:
                    open(target, "w").write(spec["parse_output"])
                sys.exit(spec.get("parse_status", 2))
            if command == "analyze":
                out = sys.argv[sys.argv.index("-o") + 1]
                os.makedirs(out)
                for name in spec.get("records", []):
                    open(os.path.join(out, name + ".plist"), "w").close()
                json.dump(spec.get("metadata", {{}}), open(os.path.join(out, "metadata.json"), "w"))
                print("[INFO] analysis finished")
                sys.exit(spec.get("analyze_status", 0))
            sys.exit(9)
            """,
        )
        hashing = self.tmp / "pkg" / "codechecker_analyzer"
        hashing.mkdir(parents=True)
        (hashing / "__init__.py").write_text("")
        (hashing / "util.py").write_text(
            "import hashlib\n"
            "def analyzer_action_hash(file, directory, command):\n"
            "    return hashlib.md5((file + directory + command).encode()).hexdigest()\n"
        )
        os.environ["PYTHONPATH"] = str(self.tmp / "pkg")
        self.tools = sa.Tools(
            "clang", "clang++", "clang-tidy", "scan", str(self.codechecker), sys.executable
        )

    def tearDown(self) -> None:
        os.environ.pop("PYTHONPATH", None)
        super().tearDown()

    def configure(self, **spec: object) -> None:
        self.behaviour.write_text(json.dumps(spec))

    def parse(self) -> list[object]:
        out = self.tmp / "out"
        out.mkdir(exist_ok=True)
        return sa.parse_reports(out, self.tools, self.tmp, self.tmp / "build", "t")

    def row(self, **overrides: object) -> dict[str, object]:
        row = {
            "checker_name": "bugprone-use-after-move",
            "analyzer_name": "clang-tidy",
            "file": {"original_path": str(self.tmp / "a.cpp")},
            "line": 3,
            "column": 5,
            "report_hash": "abc",
            "message": "used after move",
        }
        row.update(overrides)
        return row

    def test_reports_are_read_with_relative_paths(self) -> None:
        self.configure(parse_output=json.dumps({"version": 1, "reports": [self.row()]}))
        [found] = self.parse()
        self.assertEqual((found.path, found.line, found.report_hash), ("a.cpp", 3, "abc"))

    def test_unexpected_parse_status_refuses(self) -> None:
        self.configure(
            parse_output=json.dumps({"version": 1, "reports": [self.row()]}), parse_status=3
        )
        with self.assertRaisesRegex(sa.Refusal, "parse exited 3"):
            self.parse()

    def test_malformed_parse_output_refuses(self) -> None:
        self.configure(parse_output="{not json")
        with self.assertRaisesRegex(sa.Refusal, "malformed"):
            self.parse()

    def test_missing_parse_output_refuses(self) -> None:
        self.configure(parse_output=None)
        with self.assertRaisesRegex(sa.Refusal, "missing or malformed"):
            self.parse()

    def test_report_without_hash_refuses(self) -> None:
        row = self.row()
        del row["report_hash"]
        self.configure(parse_output=json.dumps({"version": 1, "reports": [row]}))
        with self.assertRaisesRegex(sa.Refusal, "malformed report"):
            self.parse()

    def test_status_and_content_must_agree(self) -> None:
        self.configure(
            parse_output=json.dumps({"version": 1, "reports": [self.row()]}), parse_status=0
        )
        with self.assertRaisesRegex(sa.Refusal, "exited 0 but"):
            self.parse()
        self.configure(parse_output=json.dumps({"version": 1, "reports": []}), parse_status=2)
        with self.assertRaisesRegex(sa.Refusal, "list is empty"):
            self.parse()

    def analyze_spec(self, entry: object, status: int) -> None:
        names = sa.action_names([entry], self.tools)
        analyzers = {
            analyzer: {
                "checkers": {check: True for check in sa.EXPECTED_CHECKERS[analyzer]},
                "analyzer_statistics": {"failed": 0, "successful": 1, "version": sa.LLVM_VERSION},
            }
            for analyzer in sa.ANALYZERS
        }
        self.configure(
            records=sorted(names),
            metadata={"tools": [{"analyzers": analyzers}]},
            analyze_status=status,
        )

    def test_clean_analysis_with_complete_records_passes(self) -> None:
        entry = sa.Entry(
            str(self.tmp), str(self.tmp / "a.cpp"), ("c++", "-c", "a.cpp", "-o", "a.o")
        )
        self.analyze_spec(entry, 0)
        sa.analyze([entry], self.tools, self.tmp / "side", 1, 10, "t")

    def test_failed_analysis_refuses_even_with_complete_records(self) -> None:
        entry = sa.Entry(
            str(self.tmp), str(self.tmp / "a.cpp"), ("c++", "-c", "a.cpp", "-o", "a.o")
        )
        self.analyze_spec(entry, 3)
        with self.assertRaisesRegex(sa.Refusal, "analyze exited 3"):
            sa.analyze([entry], self.tools, self.tmp / "side", 1, 10, "t")

    def test_reused_report_directory_refuses(self) -> None:
        entry = sa.Entry(
            str(self.tmp), str(self.tmp / "a.cpp"), ("c++", "-c", "a.cpp", "-o", "a.o")
        )
        (self.tmp / "side").mkdir()
        with self.assertRaisesRegex(sa.Refusal, "already exists"):
            sa.analyze([entry], self.tools, self.tmp / "side", 1, 10, "t")

    def test_two_compilations_codechecker_cannot_tell_apart_refuse(self) -> None:
        one = sa.Entry(str(self.tmp), str(self.tmp / "a.cpp"), ("c++", "-c", "a.cpp", "-o", "a.o"))
        with self.assertRaisesRegex(sa.Refusal, "indistinguishable"):
            sa.action_names([one, one], self.tools)

    def test_control_must_report_exactly_its_marks(self) -> None:
        root = self.tmp / "root"
        control = root / sa.CONTROL_DIR
        control.mkdir(parents=True)
        lines = ["int main() {"]
        for check in sorted(sa.BLOCKING):
            lines.append(f"  f();  // expect: {check}")
        lines.append("}")
        (control / "c.cpp").write_text("\n".join(lines) + "\n")
        marks = [
            self.row(
                checker_name=check,
                file={"original_path": str(control / "c.cpp")},
                line=number,
            )
            for number, check in enumerate(sorted(sa.BLOCKING), start=2)
        ]
        work = self.tmp / "work"
        work.mkdir()
        for case, rows in (
            ("exact", marks),
            ("missing", marks[1:]),
            ("extra", marks + [self.row(file={"original_path": str(control / "c.cpp")}, line=1)]),
        ):
            with self.subTest(case=case):
                for stale in work.glob("controls*"):
                    if stale.is_dir():
                        for item in stale.iterdir():
                            item.unlink()
                        stale.rmdir()
                    else:
                        stale.unlink()
                entry = sa.Entry(
                    str(work),
                    str(control / "c.cpp"),
                    (
                        "clang++",
                        "-std=c++20",
                        "-c",
                        str(control / "c.cpp"),
                        "-o",
                        str(work / "controls-obj" / "c.cpp.o"),
                    ),
                )
                self.analyze_spec(entry, 0)
                spec = json.loads(self.behaviour.read_text())
                spec["parse_output"] = json.dumps({"version": 1, "reports": rows})
                self.behaviour.write_text(json.dumps(spec))
                if case == "exact":
                    self.assertEqual(
                        sa.run_controls(root, self.tools, work, 1, 10), len(sa.BLOCKING)
                    )
                else:
                    with self.assertRaisesRegex(sa.Refusal, "positive controls"):
                        sa.run_controls(root, self.tools, work, 1, 10)

    def test_blocking_check_without_control_refuses(self) -> None:
        root = self.tmp / "root"
        control = root / sa.CONTROL_DIR
        control.mkdir(parents=True)
        (control / "c.cpp").write_text("int main() {}  // expect: cplusplus.Move\n")
        with self.assertRaisesRegex(sa.Refusal, "without a positive control"):
            sa.run_controls(root, self.tools, self.tmp, 1, 10)


class Suppressions(unittest.TestCase):
    def find(self, *lines: str) -> tuple[list[object], list[str]]:
        return sa.find_suppressions("a.cpp", list(lines))

    def test_exact_check_with_reason_is_accepted(self) -> None:
        found, problems = self.find(
            "x = f();  // NOLINT(bugprone-unused-return-value): result logged by f"
        )
        self.assertEqual(problems, [])
        self.assertEqual(found[0].covers, frozenset({1}))

    def test_bare_nolint_refuses(self) -> None:
        _, problems = self.find("x = f();  // NOLINT")
        self.assertIn("without an exact check name", problems[0])

    def test_reasonless_suppression_refuses(self) -> None:
        _, problems = self.find("// NOLINTNEXTLINE(bugprone-use-after-move)", "use(x);")
        self.assertIn("without a reason", problems[0])

    def test_all_and_wildcards_refuse(self) -> None:
        for text in (
            "// codechecker_suppress [all] noisy",
            "// NOLINT(bugprone-*): noisy",
            "// NOLINT(readability-magic-numbers): not an enabled check",
        ):
            with self.subTest(text=text):
                _, problems = self.find(text)
                self.assertIn("not exact enabled checks", problems[0])

    def test_codechecker_comment_covers_the_next_line(self) -> None:
        found, problems = self.find(
            "// codechecker_false_positive [cplusplus.Move] the value is reassigned first",
            "use(s);",
        )
        self.assertEqual(problems, [])
        self.assertEqual(found[0].covers, frozenset({2}))

    def test_begin_end_range(self) -> None:
        found, problems = self.find(
            "// NOLINTBEGIN(bugprone-use-after-move): generated parser keeps moved tokens",
            "a();",
            "b();",
            "// NOLINTEND(bugprone-use-after-move)",
        )
        self.assertEqual(problems, [])
        self.assertEqual(found[0].covers, frozenset({1, 2, 3, 4}))

    def test_unterminated_range_refuses(self) -> None:
        _, problems = self.find("// NOLINTBEGIN(bugprone-use-after-move): reason", "a();")
        self.assertTrue(any("without NOLINTEND" in p for p in problems))


class Repository(Workdir):
    def git(self, *args: str) -> str:
        return subprocess.run(
            ["git", "-C", str(self.repo), *args], check=True, capture_output=True, text=True
        ).stdout

    def setUp(self) -> None:
        super().setUp()
        self.repo = self.tmp / "repo"
        self.repo.mkdir()
        self.git("init", "-q", "-b", "main")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "user.name", "test")
        for name, text in {
            "a.cpp": "one\ntwo\nthree\nfour\n",
            "gone.h": "x\n",
            "old.h": "a\nb\nc\nd\ne\nf\n",
            "keep.cpp": "1\n2\n3\n",
        }.items():
            (self.repo / name).write_text(text)
        self.git("add", ".")
        self.git("commit", "-q", "-m", "base")
        self.base = self.git("rev-parse", "HEAD").strip()

    def test_merge_base_checkout_must_be_clean_and_at_the_commit(self) -> None:
        sa.check_clean_at(self.repo, self.base)
        (self.repo / "a.cpp").write_text("edited\n")
        with self.assertRaisesRegex(sa.Refusal, "local changes"):
            sa.check_clean_at(self.repo, self.base)
        self.git("commit", "-q", "-am", "next")
        with self.assertRaisesRegex(sa.Refusal, "not at the merge base"):
            sa.check_clean_at(self.repo, self.base)

    def test_change_set_covers_every_kind(self) -> None:
        (self.repo / "a.cpp").write_text("one\nTWO\nthree\nfour\n")
        (self.repo / "gone.h").unlink()
        self.git("mv", "old.h", "new.h")
        (self.repo / "keep.cpp").write_text("1\n3\n")  # deletion-only hunk
        (self.repo / "untracked.cpp").write_text("int x;\n")
        change = sa.collect_change(self.repo, self.base)
        self.assertEqual(change.head_paths, {"a.cpp", "new.h", "keep.cpp", "untracked.cpp"})
        self.assertEqual(change.base_paths, {"a.cpp", "gone.h", "old.h", "keep.cpp"})
        self.assertEqual(change.changed_lines["a.cpp"], {2})
        self.assertTrue({1, 2} <= change.changed_lines["keep.cpp"])
        self.assertIn(1, change.changed_lines["untracked.cpp"])


class Database(Workdir):
    def build(self, entries: list[dict[str, object]], home: Path | None = None) -> Path:
        build = self.tmp / "build"
        build.mkdir(exist_ok=True)
        (build / "CMakeCache.txt").write_text(f"CMAKE_HOME_DIRECTORY:INTERNAL={home or self.tmp}\n")
        (build / "compile_commands.json").write_text(json.dumps(entries))
        return build

    def entry(self, *extra: str, output: str = "a.o") -> dict[str, object]:
        return {
            "directory": str(self.tmp / "build"),
            "file": str(self.tmp / "a.cpp"),
            "arguments": ["c++", *extra, "-c", str(self.tmp / "a.cpp"), "-o", output],
        }

    def test_valid_database_loads(self) -> None:
        [entry] = sa.load_database(self.build([self.entry()]), self.tmp)
        self.assertEqual(entry.output, str(self.tmp / "build" / "a.o"))

    def test_database_of_another_checkout_refuses(self) -> None:
        with self.assertRaisesRegex(sa.Refusal, "configured for"):
            sa.load_database(self.build([self.entry()], home=Path("/elsewhere")), self.tmp)

    def test_unsupported_arguments_refuse(self) -> None:
        for extra in (["@flags.rsp"], ["-include", "pre.h"], ["-include-pch", "x.pch"]):
            with self.subTest(extra=extra):
                with self.assertRaises(sa.Refusal):
                    sa.load_database(self.build([self.entry(*extra)]), self.tmp)

    def test_duplicate_outputs_refuse(self) -> None:
        with self.assertRaisesRegex(sa.Refusal, "same output"):
            sa.load_database(self.build([self.entry(), self.entry("-DX")]), self.tmp)

    def test_missing_output_refuses(self) -> None:
        bad = self.entry()
        bad["arguments"] = ["c++", "-c", str(self.tmp / "a.cpp")]
        with self.assertRaisesRegex(sa.Refusal, "no -o output"):
            sa.load_database(self.build([bad]), self.tmp)

    def test_rewrite_moves_sources_and_keeps_the_build_directory(self) -> None:
        head = self.tmp / "head"
        build = head / "build"
        entry = sa.Entry(
            str(build),
            str(head / "src" / "a.cpp"),
            (
                "c++",
                f"-I{head}/include",
                f"-I{build}/gen",
                "-c",
                str(head / "src" / "a.cpp"),
                "-o",
                "a.o",
            ),
        )
        moved = sa.rewrite_entry(entry, head, self.tmp / "base", build)
        self.assertEqual(moved.file, str(self.tmp / "base" / "src" / "a.cpp"))
        self.assertIn(f"-I{self.tmp / 'base'}/include", moved.arguments)
        self.assertIn(f"-I{build}/gen", moved.arguments)
        self.assertEqual(moved.directory, str(build))

    def test_identity_ignores_checkout_build_and_output(self) -> None:
        one = sa.Entry(
            "/h/b", "/h/a.cpp", ("c++", "-I/h/x", "-I/h/b/g", "-c", "/h/a.cpp", "-o", "1.o")
        )
        two = sa.Entry(
            "/o/b", "/s/a.cpp", ("c++", "-I/s/x", "-I/o/b/g", "-c", "/s/a.cpp", "-o", "2.o")
        )
        self.assertEqual(
            sa.identity(one, Path("/h"), Path("/h/b")), sa.identity(two, Path("/s"), Path("/o/b"))
        )

    def test_base_reading_a_head_source_refuses(self) -> None:
        head = self.tmp / "head"
        entry = sa.Entry("/b", "/base/a.cpp", ("c++",))
        sa.check_contained(
            {entry: {"/base/a.h", str(head / "build" / "gen.h")}}, head, head / "build"
        )
        with self.assertRaisesRegex(sa.Refusal, "reads HEAD file"):
            sa.check_contained({entry: {str(head / "src" / "a.h")}}, head, head / "build")

    def test_select_finds_includers_and_orphans(self) -> None:
        root = self.tmp
        a = sa.Entry("/b", str(root / "a.cpp"), ("c++", "-o", "a.o"))
        b = sa.Entry("/b", str(root / "b.cpp"), ("c++", "-o", "b.o"))
        deps = {a: {str(root / "a.cpp"), str(root / "x.h")}, b: {str(root / "b.cpp")}}
        chosen, orphans = sa.select([a, b], deps, root, {"b.cpp"}, {"x.h", "lonely.h"})
        self.assertEqual(chosen, {a, b})
        self.assertEqual(orphans, {"lonely.h"})


class StandInTools(Workdir):
    """clang-scan-deps, ninja and clang-tidy stand-ins."""

    def setUp(self) -> None:
        super().setUp()
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        self.path = os.environ["PATH"]
        os.environ["PATH"] = f"{self.bin}{os.pathsep}{self.path}"

    def tearDown(self) -> None:
        os.environ["PATH"] = self.path
        super().tearDown()

    def scan(self, output: str, status: int = 0) -> object:
        tool = write_tool(
            self.tmp / "scan",
            f"import sys\nsys.stdout.write({output!r})\nsys.exit({status})\n",
        )
        return sa.Tools("clang", "clang++", "clang-tidy", str(tool), "cc", sys.executable)

    def entries(self) -> list[object]:
        return [
            sa.Entry(str(self.tmp), str(self.tmp / "a.cpp"), ("c++", "-c", "a.cpp", "-o", "a.o")),
            sa.Entry(str(self.tmp), str(self.tmp / "b.cpp"), ("c++", "-c", "b.cpp", "-o", "b.o")),
        ]

    def test_scan_maps_targets_to_compilations(self) -> None:
        tools = self.scan(f"a.o: {self.tmp}/a.cpp \\\n  {self.tmp}/x.h\nb.o: {self.tmp}/b.cpp\n")
        deps = sa.scan_dependencies(self.entries(), tools, self.tmp, "HEAD")
        self.assertEqual(deps[self.entries()[0]], {f"{self.tmp}/a.cpp", f"{self.tmp}/x.h"})

    def test_scan_failures_refuse(self) -> None:
        for output, status, message in (
            ("a.o: a.cpp\n", 1, "clang-scan-deps failed"),
            ("a.o: a.cpp\n", 0, "covered 1 of 2"),
            ("a.o: a.cpp\nz.o: z.cpp\n", 0, "unknown or repeated"),
            ("a.o: a\\ b.cpp\nb.o: b.cpp\n", 0, "contains a space"),
        ):
            with self.subTest(message=message):
                with self.assertRaisesRegex(sa.Refusal, message):
                    sa.scan_dependencies(
                        self.entries(), self.scan(output, status), self.tmp, "HEAD"
                    )

    def ninja(
        self, graph: dict[str, tuple[str, list[str]]], dry_run: str = "ninja: no work to do.\n"
    ) -> None:
        write_tool(
            self.bin / "ninja",
            f"""
            import sys
            graph = {graph!r}
            args = sys.argv[1:]
            if "-n" in args:
                sys.stdout.write({dry_run!r})
                sys.exit(0)
            target = args[-1]
            if target not in graph:
                sys.stderr.write(f"ninja: error: unknown target '{{target}}'\\n")
                sys.exit(1)
            rule, inputs = graph[target]
            print(target + ":")
            print("  input: " + rule)
            for item in inputs:
                print("    " + item)
            print("  outputs:")
            """,
        )

    def test_trace_finds_changed_generator_inputs(self) -> None:
        root = self.tmp / "root"
        build = self.tmp / "build"
        graph = {
            str(root / "gen" / "api.h"): (
                "CUSTOM_COMMAND",
                ["tool", str(root / "schema.tlo"), "|| lib.a"],
            ),
            str(root / "schema.tlo"): ("CUSTOM_COMMAND", [str(root / "schema.tl")]),
            "tool": ("CXX_EXECUTABLE_LINKER__tool", ["tool.o", "| lib.a"]),
            "tool.o": ("CXX_COMPILER__tool", [str(root / "tool.cpp")]),
        }
        self.ninja(graph)
        generated = {str(root / "gen" / "api.h")}
        self.assertEqual(sa.trace_generated(build, root, generated, {"other.cpp"}), [])
        self.assertIn(
            "generator input schema.tl is changed",
            sa.trace_generated(build, root, generated, {"schema.tl"}),
        )
        self.assertIn(
            "generator source tool.cpp is changed",
            sa.trace_generated(build, root, generated, {"tool.cpp"}),
        )
        # A library the generator links is opaque, and order-only inputs are ignored.
        self.assertEqual(sa.trace_generated(build, root, generated, {"lib.cpp"}), [])

    def test_stale_generated_files_refuse(self) -> None:
        self.ninja({}, dry_run="[1/1] generate api.h\n")
        with self.assertRaisesRegex(sa.Refusal, "build the tree first"):
            sa.check_generated_fresh(self.tmp, {"gen.h"})
        self.ninja({})
        sa.check_generated_fresh(self.tmp, {"gen.h"})

    def tidy(self, checks: list[str], options: dict[str, str]) -> object:
        option_lines = "".join(f"  {key}: '{value}'\\n" for key, value in options.items())
        listing = "Enabled checks:\\n" + "".join(f"    {check}\\n" for check in checks)
        tool = write_tool(
            self.tmp / "clang-tidy",
            f"""
            import sys
            if "--list-checks" in sys.argv:
                sys.stdout.write("{listing}")
            else:
                sys.stdout.write("---\\nCheckOptions:\\n{option_lines}")
            """,
        )
        return sa.Tools("clang", "clang++", str(tool), "scan", "cc", sys.executable)

    def test_rule_set_agreement(self) -> None:
        good = sorted(sa.EXPECTED_CHECKERS["clang-tidy"])
        sa.check_rule_set(self.tmp, self.tidy(good, sa.CLANG_TIDY_OPTIONS))
        with self.assertRaisesRegex(sa.Refusal, "disagrees"):
            sa.check_rule_set(self.tmp, self.tidy(good[1:], sa.CLANG_TIDY_OPTIONS))
        with self.assertRaisesRegex(sa.Refusal, "disagrees"):
            sa.check_rule_set(
                self.tmp, self.tidy(good + ["misc-unused-using-decls"], sa.CLANG_TIDY_OPTIONS)
            )
        broken = dict(sa.CLANG_TIDY_OPTIONS)
        broken["bugprone-unused-return-value.CheckedReturnTypes"] = "^::td::Status$"
        with self.assertRaisesRegex(sa.Refusal, "CheckedReturnTypes"):
            sa.check_rule_set(self.tmp, self.tidy(good, broken))

    def test_wrong_tool_version_refuses(self) -> None:
        llvm = self.tmp / "llvm"
        llvm.mkdir()
        for name in ("clang", "clang++", "clang-tidy", "clang-scan-deps"):
            write_tool(llvm / name, "print('Ubuntu clang version 20.1.8')\n")
        with self.assertRaisesRegex(sa.Refusal, "is not LLVM"):
            sa.resolve_tools(llvm, None)

    def test_codechecker_using_other_analyzer_binaries_refuses(self) -> None:
        llvm = self.tmp / "llvm"
        llvm.mkdir()
        for name in ("clang", "clang++", "clang-tidy", "clang-scan-deps"):
            write_tool(llvm / name, f"print('clang version {sa.LLVM_VERSION}')\n")
        version = {"analyzer": {"base_package_version": sa.CODECHECKER_VERSION}}
        rows = [
            {"name": "clangsa", "path": "/usr/bin/other-clang", "version": sa.LLVM_VERSION},
            {"name": "clang-tidy", "path": str(llvm / "clang-tidy"), "version": sa.LLVM_VERSION},
        ]
        codechecker = write_tool(
            self.tmp / "CodeChecker",
            f"""
            import json, sys
            print("[INFO] log line before the JSON")
            print(json.dumps({version!r} if sys.argv[1] == "version" else {rows!r}))
            """,
        )
        with self.assertRaisesRegex(sa.Refusal, "uses /usr/bin/other-clang"):
            sa.resolve_tools(llvm, str(codechecker))


if __name__ == "__main__":
    unittest.main()
