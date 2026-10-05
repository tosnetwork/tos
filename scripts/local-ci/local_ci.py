#!/usr/bin/env python3
"""Replay this repository's GitHub Actions pull-request jobs locally in Docker.

The replay reads the workflow YAML of the commit under test and runs each job's
own `run:` blocks, in order, inside the image built from that commit's
`Dockerfile.builder` (target `builder-24`). Jobs that declare `container:` run
in that image as root, as on GitHub; jobs on the hosted runner run as uid 1001
in a thin layer (`Dockerfile.runner`) that adds what the hosted image provides.

Every job gets a fresh copy of a shallow clone of the exact commit, owned by
uid 1001 and copied onto the container overlay, so a root process meets the
same "dubious ownership" refusal it meets on GitHub, and timing-sensitive
tests run on the local SSD rather than a bind mount.

A step is reported `pass` only if its command ran and exited 0. Steps that
cannot run here are reported `skip` with the reason. See README.md.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import datetime as _dt
import glob
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import threading
import time
import traceback
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover - exercised only on a bare interpreter
    sys.exit("PyYAML is required; run through scripts/local-ci/run.sh")

HERE = Path(__file__).resolve().parent
RUNNER_UID = 1001
RUNNER_HOME = "/home/runner"
RUNNER_WS = "/home/runner/work/tos/tos"
RUNNER_TEMP = "/home/runner/work/_temp"
CONTAINER_WS = "/__w/tos/tos"
CONTAINER_TEMP = "/__w/_temp"
CONTAINER_HOME = "/github/home"
CACHE_VOLUME = "tos-local-ci-cache"
REPOSITORY = "tosnetwork/tos"
SUPPORTED_RUNNERS = {"ubuntu-24.04", "ubuntu-latest", "ubuntu-22.04"}

PRINT_LOCK = threading.Lock()


def log(msg: str) -> None:
    stamp = _dt.datetime.now().strftime("%H:%M:%S")
    with PRINT_LOCK:
        print(f"[{stamp}] {msg}", flush=True)


def sh(cmd: list[str], **kw: Any) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=True, text=True, **kw)


def sh_out(cmd: list[str], **kw: Any) -> str:
    return subprocess.run(cmd, check=True, text=True, capture_output=True, **kw).stdout.strip()


# --------------------------------------------------------------------------
# GitHub expression language (the subset the workflows use, plus operators)
# --------------------------------------------------------------------------

TOKEN_RE = re.compile(
    r"\s*(?:(?P<num>-?\d+(?:\.\d+)?)|(?P<str>'(?:[^']|'')*')|"
    r"(?P<op>==|!=|<=|>=|&&|\|\||[()\[\],.!<>*])|(?P<id>[A-Za-z_][A-Za-z0-9_-]*))"
)


class ExprError(Exception):
    pass


def tokenize(src: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    pos = 0
    src = src.strip()
    while pos < len(src):
        m = TOKEN_RE.match(src, pos)
        if not m or m.end() == pos:
            raise ExprError(f"cannot tokenize {src[pos:]!r} in {src!r}")
        pos = m.end()
        for kind in ("num", "str", "op", "id"):
            if m.group(kind) is not None:
                out.append((kind, m.group(kind)))
                break
    return out


def truthy(v: Any) -> bool:
    if v is None or v is False:
        return False
    if isinstance(v, (int, float)) and not isinstance(v, bool):
        return v != 0
    if isinstance(v, str):
        return v != ""
    return True


def to_number(v: Any) -> float:
    if v is None:
        return 0.0
    if isinstance(v, bool):
        return 1.0 if v else 0.0
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str):
        s = v.strip()
        if s == "":
            return 0.0
        try:
            return float(int(s, 0)) if s.lower().startswith("0x") else float(s)
        except ValueError:
            return float("nan")
    return float("nan")


def loose_eq(a: Any, b: Any) -> bool:
    if isinstance(a, str) and isinstance(b, str):
        return a.lower() == b.lower()
    if type(a) is type(b) or (a is None and b is None):
        return a == b
    if isinstance(a, (dict, list)) or isinstance(b, (dict, list)):
        return a is b
    return to_number(a) == to_number(b)


def to_str(v: Any) -> str:
    if v is None:
        return ""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, float) and v.is_integer():
        return str(int(v))
    if isinstance(v, (dict, list)):
        return json.dumps(v, indent=2)
    return str(v)


def ci_get(obj: Any, key: Any) -> Any:
    if isinstance(obj, dict):
        if key in obj:
            return obj[key]
        if isinstance(key, str):
            for k, v in obj.items():
                if isinstance(k, str) and k.lower() == key.lower():
                    return v
        return None
    if isinstance(obj, list):
        if key == "*":
            return obj
        try:
            return obj[int(to_number(key))]
        except (IndexError, ValueError):
            return None
    return None


class Evaluator:
    def __init__(self, contexts: dict[str, Any], status: dict[str, bool], hash_files) -> None:
        self.ctx = contexts
        self.status = status
        self.hash_files = hash_files

    def evaluate(self, src: str) -> Any:
        self.toks = tokenize(src)
        self.i = 0
        v = self.parse_or()
        if self.i != len(self.toks):
            raise ExprError(f"trailing tokens in {src!r}")
        return v

    def peek(self) -> tuple[str, str] | None:
        return self.toks[self.i] if self.i < len(self.toks) else None

    def take(self, value: str | None = None) -> tuple[str, str]:
        t = self.peek()
        if t is None or (value is not None and t[1] != value):
            raise ExprError(f"expected {value!r}, got {t!r}")
        self.i += 1
        return t

    def parse_or(self) -> Any:
        v = self.parse_and()
        while self.peek() == ("op", "||"):
            self.take()
            rhs = self.parse_and()
            v = v if truthy(v) else rhs
        return v

    def parse_and(self) -> Any:
        v = self.parse_cmp()
        while self.peek() == ("op", "&&"):
            self.take()
            rhs = self.parse_cmp()
            v = rhs if truthy(v) else v
        return v

    def parse_cmp(self) -> Any:
        v = self.parse_unary()
        t = self.peek()
        while t and t[0] == "op" and t[1] in ("==", "!=", "<", ">", "<=", ">="):
            self.take()
            rhs = self.parse_unary()
            op = t[1]
            if op == "==":
                v = loose_eq(v, rhs)
            elif op == "!=":
                v = not loose_eq(v, rhs)
            else:
                a, b = to_number(v), to_number(rhs)
                v = {"<": a < b, ">": a > b, "<=": a <= b, ">=": a >= b}[op]
            t = self.peek()
        return v

    def parse_unary(self) -> Any:
        if self.peek() == ("op", "!"):
            self.take()
            return not truthy(self.parse_unary())
        return self.parse_postfix()

    def parse_postfix(self) -> Any:
        v = self.parse_primary()
        while True:
            t = self.peek()
            if t == ("op", "."):
                self.take()
                name = self.take()
                v = ci_get(v, name[1])
            elif t == ("op", "["):
                self.take()
                key = self.parse_or()
                self.take("]")
                v = ci_get(v, key)
            else:
                return v

    def parse_primary(self) -> Any:
        t = self.take()
        kind, val = t
        if kind == "num":
            return float(val) if "." in val else int(val)
        if kind == "str":
            return val[1:-1].replace("''", "'")
        if kind == "op" and val == "(":
            v = self.parse_or()
            self.take(")")
            return v
        if kind == "id":
            low = val.lower()
            if low == "true":
                return True
            if low == "false":
                return False
            if low == "null":
                return None
            if self.peek() == ("op", "("):
                self.take()
                args = []
                if self.peek() != ("op", ")"):
                    args.append(self.parse_or())
                    while self.peek() == ("op", ","):
                        self.take()
                        args.append(self.parse_or())
                self.take(")")
                return self.call(low, args)
            return ci_get(self.ctx, val)
        raise ExprError(f"unexpected token {t!r}")

    def call(self, name: str, args: list[Any]) -> Any:
        if name == "success":
            return not self.status.get("failed", False)
        if name == "failure":
            return self.status.get("failed", False)
        if name == "always":
            return True
        if name == "cancelled":
            return False
        if name == "contains":
            hay, needle = args
            if isinstance(hay, list):
                return any(loose_eq(x, needle) for x in hay)
            return to_str(needle).lower() in to_str(hay).lower()
        if name == "startswith":
            return to_str(args[0]).lower().startswith(to_str(args[1]).lower())
        if name == "endswith":
            return to_str(args[0]).lower().endswith(to_str(args[1]).lower())
        if name == "format":
            fmt = to_str(args[0])
            for n, a in enumerate(args[1:]):
                fmt = fmt.replace("{" + str(n) + "}", to_str(a))
            return fmt.replace("{{", "{").replace("}}", "}")
        if name == "join":
            sep = to_str(args[1]) if len(args) > 1 else ","
            return (
                sep.join(to_str(x) for x in args[0])
                if isinstance(args[0], list)
                else to_str(args[0])
            )
        if name == "tojson":
            return json.dumps(args[0], indent=2)
        if name == "fromjson":
            return json.loads(to_str(args[0]))
        if name == "hashfiles":
            return self.hash_files([to_str(a) for a in args])
        raise ExprError(f"unsupported function {name}()")


INTERP_RE = re.compile(r"\$\{\{(.*?)\}\}", re.S)


def interpolate(value: Any, ev: Evaluator) -> Any:
    if isinstance(value, str):
        m = INTERP_RE.fullmatch(value)
        if m and len(INTERP_RE.findall(value)) == 1:
            return ev.evaluate(m.group(1))
        return INTERP_RE.sub(lambda mm: to_str(ev.evaluate(mm.group(1))), value)
    if isinstance(value, list):
        return [interpolate(v, ev) for v in value]
    if isinstance(value, dict):
        return {k: interpolate(v, ev) for k, v in value.items()}
    return value


def interpolate_str(value: Any, ev: Evaluator) -> str:
    if isinstance(value, str):
        return INTERP_RE.sub(lambda mm: to_str(ev.evaluate(mm.group(1))), value)
    return to_str(value)


STATUS_FN_RE = re.compile(r"\b(success|failure|always|cancelled)\s*\(", re.I)


def evaluate_if(cond: Any, ev: Evaluator) -> bool:
    if cond is None:
        return truthy(ev.evaluate("success()"))
    if isinstance(cond, bool):
        return cond and truthy(ev.evaluate("success()"))
    text = str(cond).strip()
    m = INTERP_RE.fullmatch(text)
    if m and len(INTERP_RE.findall(text)) == 1:
        text = m.group(1).strip()
    if not STATUS_FN_RE.search(text):
        text = f"success() && ({text})"
    return truthy(ev.evaluate(text))


# --------------------------------------------------------------------------
# Trigger evaluation
# --------------------------------------------------------------------------


def glob_to_regex(pattern: str) -> re.Pattern:
    out = []
    i = 0
    while i < len(pattern):
        c = pattern[i]
        if pattern.startswith("**", i):
            out.append(".*")
            i += 2
            if i < len(pattern) and pattern[i] == "/":
                out[-1] = "(?:.*/)?"
                i += 1
            continue
        if c == "*":
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        elif c == "[":
            j = pattern.find("]", i)
            if j == -1:
                out.append(re.escape(c))
            else:
                out.append(pattern[i : j + 1])
                i = j
        else:
            out.append(re.escape(c))
        i += 1
    return re.compile("^" + "".join(out) + "$")


def filter_matches(patterns: list[str], value: str) -> bool:
    """GitHub filter semantics: later patterns win, `!` negates."""
    result = False
    for p in patterns:
        neg = p.startswith("!")
        if glob_to_regex(p[1:] if neg else p).match(value):
            result = not neg
    return result


def workflow_on(wf: dict) -> Any:
    return wf.get("on", wf.get(True))


def pr_trigger(wf: dict, base_branch: str, changed: list[str]) -> tuple[bool, str]:
    on = workflow_on(wf)
    if isinstance(on, str):
        on = {on: None}
    elif isinstance(on, list):
        on = {k: None for k in on}
    if not isinstance(on, dict) or "pull_request" not in on:
        return False, "no pull_request trigger"
    cfg = on.get("pull_request") or {}
    types = cfg.get("types")
    if types and "synchronize" not in types and "opened" not in types:
        return False, f"pull_request types {types}"
    if "branches" in cfg and not filter_matches(cfg["branches"], base_branch):
        return False, f"base {base_branch} not in branches filter"
    if "branches-ignore" in cfg and filter_matches(cfg["branches-ignore"], base_branch):
        return False, f"base {base_branch} in branches-ignore"
    if "paths" in cfg:
        hits = [f for f in changed if filter_matches(cfg["paths"], f)]
        if not hits:
            return False, "no changed file matches its paths filter"
        return True, f"paths filter matched {len(hits)} file(s), e.g. {hits[0]}"
    if "paths-ignore" in cfg:
        if all(filter_matches(cfg["paths-ignore"], f) for f in changed):
            return False, "every changed file is in paths-ignore"
    return True, "pull_request (no path filter)"


# --------------------------------------------------------------------------
# Results
# --------------------------------------------------------------------------


@dataclass
class StepResult:
    workflow: str
    job: str
    step: str
    status: str  # pass | fail | skip
    seconds: float = 0.0
    note: str = ""
    log: str = ""
    exit_code: int | None = None
    continue_on_error: bool = False
    script: str = ""


@dataclass
class JobResult:
    workflow: str
    job: str
    status: str = "pending"  # pass | fail | skip
    note: str = ""
    seconds: float = 0.0
    outputs: dict[str, str] = field(default_factory=dict)
    steps: list[StepResult] = field(default_factory=list)


# --------------------------------------------------------------------------
# The run
# --------------------------------------------------------------------------


def slug(text: str, limit: int = 60) -> str:
    s = re.sub(r"[^A-Za-z0-9._-]+", "-", text).strip("-")
    return s[:limit] or "x"


def parse_kv_file(path: Path) -> dict[str, str]:
    """GITHUB_OUTPUT / GITHUB_ENV format, including the heredoc form."""
    out: dict[str, str] = {}
    if not path.exists():
        return out
    lines = path.read_text(errors="replace").splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        if "<<" in line and ("=" not in line or line.index("<<") < line.index("=")):
            key, delim = line.split("<<", 1)
            buf = []
            i += 1
            while i < len(lines) and lines[i] != delim:
                buf.append(lines[i])
                i += 1
            out[key] = "\n".join(buf)
        elif "=" in line:
            key, val = line.split("=", 1)
            out[key] = val
        i += 1
    return out


class Run:
    def __init__(self, args: argparse.Namespace) -> None:
        self.args = args
        self.source = args.source
        self.commit = ""
        self.results: list[JobResult] = []
        self.results_lock = threading.Lock()
        self.job_results: dict[tuple[str, str], JobResult] = {}
        self.run_id = str(int(time.time()))

    # ---- preparation -------------------------------------------------------

    def resolve_source(self) -> None:
        src = self.source
        if re.match(r"^[a-z]+://", src) or src.startswith("git@"):
            self.source_is_url = True
            self.mirror = None
            return
        self.source_is_url = False
        common = sh_out(
            ["git", "-C", src, "rev-parse", "--path-format=absolute", "--git-common-dir"]
        )
        self.mirror = common

    def prepare_clone(self) -> None:
        a = self.args
        self.out = Path(a.out).resolve()
        self.src = self.out / "src"
        if self.src.exists():
            sys.exit(f"{self.src} already exists; choose a fresh --out")
        self.out.mkdir(parents=True, exist_ok=True)
        self.src.mkdir()
        fetch_from = self.source if self.source_is_url else self.mirror
        sh(["git", "init", "-q", str(self.src)])
        sh(["git", "-C", str(self.src), "remote", "add", "origin", fetch_from])
        want = a.commit
        if not self.source_is_url:
            want = sh_out(
                [
                    "git",
                    f"--git-dir={self.mirror}",
                    "rev-parse",
                    "--verify",
                    f"{a.commit}^{{commit}}",
                ]
            )
        elif not re.fullmatch(r"[0-9a-f]{40}", want):
            sys.exit("with a URL --source, give the full 40-hex commit id")
        sh(["git", "-C", str(self.src), "fetch", "-q", "--depth", "1", "origin", want])
        self.commit = sh_out(["git", "-C", str(self.src), "rev-parse", "FETCH_HEAD"])
        sh(["git", "-C", str(self.src), "checkout", "-q", "--detach", self.commit])
        # The PR's base: where this commit leaves the base branch. GitHub tests
        # the merge commit; for an exact-commit replay the merge base is the
        # base whose diff equals the PR diff as of this head. It is computed
        # in a separate history-only repository so the replay clone stays
        # exactly as shallow as actions/checkout leaves it.
        if self.source_is_url:
            meta = self.out / "history.git"
            sh(["git", "init", "-q", "--bare", str(meta)])
            sh(
                [
                    "git",
                    f"--git-dir={meta}",
                    "fetch",
                    "-q",
                    "--filter=blob:none",
                    self.source,
                    self.commit,
                    f"+refs/heads/{a.base_branch}:refs/remotes/origin/{a.base_branch}",
                ]
            )
            git_dir = str(meta)
        else:
            git_dir = self.mirror
        self.base_sha = sh_out(
            [
                "git",
                f"--git-dir={git_dir}",
                "merge-base",
                f"refs/remotes/origin/{a.base_branch}",
                self.commit,
            ]
        )
        names = sh_out(
            ["git", f"--git-dir={git_dir}", "diff", "--name-only", self.base_sha, self.commit]
        )
        self.changed = [n for n in names.splitlines() if n]
        log(f"commit {self.commit}, base {self.base_sha} ({len(self.changed)} changed files)")

    def dockerfile_hash(self) -> str:
        return sh_out(
            [
                "git",
                "-C",
                str(self.src),
                "rev-parse",
                "--short=12",
                f"{self.commit}:Dockerfile.builder",
            ]
        )

    def image_exists(self, tag: str) -> bool:
        return (
            subprocess.run(["docker", "image", "inspect", tag], capture_output=True).returncode == 0
        )

    def ensure_images(self) -> None:
        h = self.dockerfile_hash()
        self.base_image = f"tos-builder-local:24-{h}"
        runner_hash = hashlib.sha256((HERE / "Dockerfile.runner").read_bytes()).hexdigest()[:12]
        toml = (
            (self.src / "rust-toolchain.toml").read_text()
            if (self.src / "rust-toolchain.toml").exists()
            else ""
        )
        m = re.search(r'^channel\s*=\s*"([^"]+)"', toml, re.M)
        self.rust_pinned = m.group(1) if m else ""
        self.runner_image = (
            f"tos-local-ci-runner:24-{h}-{runner_hash}-rust{self.rust_pinned or 'none'}"
        )
        ctx = self.out / "image-context"
        ctx.mkdir(exist_ok=True)
        if not self.image_exists(self.base_image):
            log(f"building {self.base_image} from Dockerfile.builder target builder-24")
            shutil.copy(self.src / "Dockerfile.builder", ctx / "Dockerfile.builder")
            with open(self.out / "image-build.log", "a") as fh:
                sh(
                    [
                        "docker",
                        "build",
                        "-f",
                        str(ctx / "Dockerfile.builder"),
                        "--target",
                        "builder-24",
                        "-t",
                        self.base_image,
                        str(ctx),
                    ],
                    stdout=fh,
                    stderr=subprocess.STDOUT,
                )
        else:
            log(f"reusing {self.base_image}")
        if not self.image_exists(self.runner_image):
            log(f"building {self.runner_image}")
            shutil.copy(HERE / "Dockerfile.runner", ctx / "Dockerfile.runner")
            with open(self.out / "image-build.log", "a") as fh:
                sh(
                    [
                        "docker",
                        "build",
                        "-f",
                        str(ctx / "Dockerfile.runner"),
                        "--build-arg",
                        f"BASE_IMAGE={self.base_image}",
                        "--build-arg",
                        f"RUST_PINNED={self.rust_pinned}",
                        "-t",
                        self.runner_image,
                        str(ctx),
                    ],
                    stdout=fh,
                    stderr=subprocess.STDOUT,
                )
        else:
            log(f"reusing {self.runner_image}")
        subprocess.run(
            ["docker", "volume", "create", CACHE_VOLUME], capture_output=True, check=True
        )

    # ---- planning ------------------------------------------------------------

    def load_workflows(self) -> dict[str, dict]:
        wfs = {}
        for p in sorted((self.src / ".github/workflows").glob("*.yml")):
            wfs[p.stem] = yaml.safe_load(p.read_text())
        return wfs

    def plan(self) -> list[tuple[str, str, dict, dict, str]]:
        """Return (workflow, job_id, wf, job, note) for every job to run."""
        a = self.args
        wfs = self.load_workflows()
        self.not_triggered: list[tuple[str, str]] = []
        selected: list[tuple[str, str | None]] = []
        if a.workflow:
            for item in a.workflow:
                wf, _, job = item.partition(":")
                if wf not in wfs:
                    sys.exit(f"unknown workflow {wf}")
                selected.append((wf, job or None))
        else:
            for name, wf in wfs.items():
                ok, why = pr_trigger(wf, a.base_branch, self.changed)
                if ok:
                    selected.append((name, None))
                else:
                    self.not_triggered.append((name, why))
        excluded = set(a.exclude or [])
        plan = []
        for name, only_job in selected:
            wf = wfs[name]
            for job_id, job in (wf.get("jobs") or {}).items():
                if only_job and job_id != only_job:
                    continue
                if name in excluded or f"{name}:{job_id}" in excluded:
                    plan.append((name, job_id, wf, job, "excluded by --exclude"))
                    continue
                plan.append((name, job_id, wf, job, ""))
        return plan

    def expand_matrix(self, job: dict, ev_base: Evaluator) -> list[dict]:
        strat = job.get("strategy") or {}
        matrix = strat.get("matrix")
        if not matrix:
            return [{}]
        if isinstance(matrix, str):
            matrix = interpolate(matrix, ev_base)
        base = {k: v for k, v in matrix.items() if k not in ("include", "exclude")}
        combos: list[dict] = [{}]
        for k, vals in base.items():
            if isinstance(vals, str):
                vals = interpolate(vals, ev_base)
            combos = [dict(c, **{k: v}) for c in combos for v in (vals or [])]
        if not base:
            combos = []
        for ex in matrix.get("exclude") or []:
            combos = [c for c in combos if not all(loose_eq(c.get(k), v) for k, v in ex.items())]
        for inc in matrix.get("include") or []:
            merged = False
            for c in combos:
                if all(loose_eq(c.get(k), v) for k, v in inc.items() if k in base):
                    if all(k in base for k in inc if k in c) and any(k in base for k in inc):
                        c.update({k: v for k, v in inc.items() if k not in base})
                        merged = True
            if not merged:
                combos.append(dict(inc))
        return combos or [{}]

    # ---- execution -----------------------------------------------------------

    def github_context(self, wf_name: str, workspace: str) -> dict:
        a = self.args
        return {
            "event_name": "pull_request",
            "event": {
                "pull_request": {
                    "number": a.pr,
                    "base": {"sha": self.base_sha, "ref": a.base_branch},
                    "head": {"sha": self.commit, "ref": a.head_branch},
                },
                "number": a.pr,
            },
            "sha": self.commit,
            "ref": f"refs/pull/{a.pr}/merge",
            "ref_name": f"{a.pr}/merge",
            "base_ref": a.base_branch,
            "head_ref": a.head_branch,
            "repository": REPOSITORY,
            "repository_owner": REPOSITORY.split("/")[0],
            "workflow": wf_name,
            "workspace": workspace,
            "run_id": self.run_id,
            "run_number": "1",
            "run_attempt": "1",
            "actor": "local-ci",
            "server_url": "https://github.com",
            "token": "",
        }

    def hash_files(self, patterns: list[str]) -> str:
        files: set[str] = set()
        for p in patterns:
            for f in glob.glob(str(self.src / p), recursive=True):
                if os.path.isfile(f):
                    files.add(f)
        if not files:
            return ""
        h = hashlib.sha256()
        for f in sorted(files):
            h.update(hashlib.sha256(Path(f).read_bytes()).digest())
        return h.hexdigest()

    def run_all(self) -> int:
        plan = self.plan()
        if self.args.list:
            for wf, job_id, _, job, note in plan:
                print(f"{wf}:{job_id}  {job.get('name', '')}  {note}")
            for wf, why in self.not_triggered:
                print(f"(not triggered) {wf}: {why}")
            return 0
        # Topological scheduling within each workflow.
        pending = {(wf, jid): (wfd, job, note) for wf, jid, wfd, job, note in plan}
        planned = set(pending)
        done: set[tuple[str, str]] = set()
        running: dict[concurrent.futures.Future, tuple[str, str]] = {}
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.args.parallel) as pool:
            while pending or running:
                for key in list(pending):
                    wfd, job, note = pending[key]
                    needs = job.get("needs") or []
                    if isinstance(needs, str):
                        needs = [needs]
                    if any((key[0], n) in planned and (key[0], n) not in done for n in needs):
                        continue
                    if len(running) >= self.args.parallel or not self.disk_ok():
                        break
                    del pending[key]
                    fut = pool.submit(self.run_job, key[0], key[1], wfd, job, note)
                    running[fut] = key
                if not running:
                    if pending:
                        time.sleep(30)
                    continue
                finished, _ = concurrent.futures.wait(
                    list(running), timeout=30, return_when=concurrent.futures.FIRST_COMPLETED
                )
                for fut in finished:
                    key = running.pop(fut)
                    try:
                        fut.result()
                    except Exception as exc:  # harness defect: report, never pass
                        log(f"HARNESS ERROR in {key[0]}:{key[1]}:\n{traceback.format_exc()}")
                        jr = JobResult(key[0], key[1], "fail", f"harness error: {exc!r}")
                        self.add_result(jr)
                    done.add(key)
        return self.report()

    def disk_ok(self) -> bool:
        free = shutil.disk_usage(
            "/var/lib/docker" if os.path.exists("/var/lib/docker") else "/"
        ).free
        if free < self.args.min_free_gb * 2**30:
            log(f"waiting: {free / 2**30:.0f} GiB free < {self.args.min_free_gb} GiB")
            return False
        return True

    def add_result(self, jr: JobResult) -> None:
        with self.results_lock:
            self.results.append(jr)
            self.job_results[(jr.workflow, jr.job.split(" (")[0])] = jr

    def unreplayable_needs(self, wf: str, needs: list[str]) -> list[str]:
        """Needed jobs with a matrix leg that cannot run here (another runner)."""
        out = []
        for n in needs:
            for r in self.results:
                if (
                    r.workflow == wf
                    and r.job.split(" (")[0] == n
                    and r.status == "skip"
                    and "runner" in r.note
                ):
                    out.append(r.job)
        return out

    def needs_context(self, wf: str, needs: list[str]) -> tuple[dict, bool]:
        ctx = {}
        all_ok = True
        for n in needs:
            matches = [r for r in self.results if r.workflow == wf and r.job.split(" (")[0] == n]
            if not matches:
                ctx[n] = {"result": "skipped", "outputs": {}}
                all_ok = False
                continue
            result = "success"
            outputs: dict[str, str] = {}
            for r in matches:
                outputs.update(r.outputs)
                if r.status == "fail":
                    result = "failure"
                elif r.status == "skip" and result == "success":
                    result = "skipped"
            ctx[n] = {"result": result, "outputs": outputs}
            if result != "success":
                all_ok = False
        return ctx, all_ok

    def run_job(self, wf_name: str, job_id: str, wf: dict, job: dict, note: str) -> None:
        needs = job.get("needs") or []
        if isinstance(needs, str):
            needs = [needs]
        needs_ctx, needs_ok = self.needs_context(wf_name, needs)
        base_ctx = {
            "github": self.github_context(wf_name, RUNNER_WS),
            "env": {},
            "vars": {},
            "secrets": {},
            "inputs": {},
            "needs": needs_ctx,
            "runner": {"os": "Linux", "arch": "X64", "temp": RUNNER_TEMP},
            "matrix": {},
            "strategy": {},
        }
        ev_base = Evaluator(base_ctx, {"failed": not needs_ok}, self.hash_files)
        if note:
            self.add_result(JobResult(wf_name, job_id, "skip", note))
            return
        missing = self.unreplayable_needs(wf_name, needs)
        if missing:
            self.add_result(
                JobResult(
                    wf_name,
                    job_id,
                    "skip",
                    f"needs results of {', '.join(missing)}, which cannot run here",
                )
            )
            return
        if "uses" in job:
            self.add_result(
                JobResult(
                    wf_name, job_id, "skip", f"reusable workflow call {job['uses']} is not replayed"
                )
            )
            return
        # A job-level `if:` cannot see the matrix, and GitHub evaluates it
        # before expanding one built from a needed job's outputs.
        try:
            job_cond = evaluate_if(job.get("if"), ev_base)
        except ExprError as exc:
            self.add_result(
                JobResult(wf_name, job_id, "fail", f"harness could not evaluate job if: {exc}")
            )
            return
        if not job_cond:
            why = (
                "job `if:` is false for a pull_request event"
                if needs_ok
                else "a needed job did not succeed"
            )
            self.add_result(JobResult(wf_name, job_id, "skip", why))
            return
        try:
            combos = self.expand_matrix(job, ev_base)
        except (ExprError, ValueError, TypeError) as exc:
            self.add_result(
                JobResult(wf_name, job_id, "fail", f"harness could not expand matrix: {exc}")
            )
            return
        for combo in combos:
            label = job_id + (
                " (" + ", ".join(to_str(v) for v in combo.values()) + ")" if combo else ""
            )
            ctx = dict(base_ctx, matrix=combo)
            ev = Evaluator(ctx, {"failed": not needs_ok}, self.hash_files)
            runs_on = interpolate(job.get("runs-on", ""), ev)
            runs_on_list = runs_on if isinstance(runs_on, list) else [runs_on]
            if not any(str(r) in SUPPORTED_RUNNERS for r in runs_on_list):
                self.add_result(
                    JobResult(
                        wf_name, label, "skip", f"needs a {runs_on} runner (x86-64 Linux only here)"
                    )
                )
                continue
            jr = self.execute(wf_name, label, wf, job, ctx, runs_on_list)
            self.add_result(jr)

    def execute(
        self, wf_name: str, label: str, wf: dict, job: dict, ctx: dict, runs_on: list
    ) -> JobResult:
        a = self.args
        jr = JobResult(wf_name, label)
        start = time.time()
        container_spec = job.get("container")
        in_container = container_spec is not None
        ws = CONTAINER_WS if in_container else RUNNER_WS
        temp = CONTAINER_TEMP if in_container else RUNNER_TEMP
        home = CONTAINER_HOME if in_container else RUNNER_HOME
        uid = 0 if in_container else RUNNER_UID
        image = self.base_image if in_container else self.runner_image
        ctx["github"] = self.github_context(wf_name, ws)
        ctx["runner"] = {
            "os": "Linux",
            "arch": "X64",
            "temp": temp,
            "tool_cache": "/opt/hostedtoolcache",
            "name": "local-ci",
        }
        ev = Evaluator(ctx, {"failed": False}, self.hash_files)
        notes = []
        if "ubuntu-22.04" in [str(r) for r in runs_on]:
            notes.append("job requests ubuntu-22.04; replayed on the 24.04 image")
        if in_container:
            img = interpolate_str(
                container_spec
                if isinstance(container_spec, str)
                else container_spec.get("image", ""),
                ev,
            )
            notes.append(f"container {img} -> {self.base_image}")
        logdir = self.out / "logs" / slug(wf_name) / slug(label)
        rundir = self.out / "run" / slug(wf_name) / slug(label)
        logdir.mkdir(parents=True, exist_ok=True)
        rundir.mkdir(parents=True, exist_ok=True)
        os.chmod(rundir, 0o777)
        cname = f"tos-local-ci-{self.run_id}-{slug(wf_name, 25)}-{slug(label, 30)}".lower()
        cenv = {}
        if isinstance(container_spec, dict):
            cenv = {k: interpolate_str(v, ev) for k, v in (container_spec.get("env") or {}).items()}
        docker_run = [
            "docker",
            "run",
            "-d",
            "--name",
            cname,
            "--init",
            "--cpuset-cpus",
            a.cpuset,
            "--shm-size",
            "8g",
            "--security-opt",
            "seccomp=unconfined",
            "--security-opt",
            "apparmor=unconfined",
            "--cap-add",
            "SYS_PTRACE",
            "--ulimit",
            "nofile=65536:65536",
            "-v",
            f"{self.src}:/__src:ro",
            "-v",
            f"{self.out}:/__h",
            "-v",
            f"{CACHE_VOLUME}:/__cache",
        ]
        if self.mirror:
            docker_run += ["-v", f"{self.mirror}:/__mirror:ro"]
        docker_run += ["-v", f"{HERE / 'shim'}:/__local-ci-shim:ro"]
        docker_run += [image, "sleep", "infinity"]
        prepared = False
        try:
            sh(docker_run, capture_output=True)
            prep = f"""
set -e
mkdir -p {shlex.quote(ws)} {shlex.quote(temp)} {shlex.quote(home)} /__cache/actions /__cache/cargo-registry /__cache/cargo-git
chmod 0777 /__cache /__cache/actions /__cache/cargo-registry /__cache/cargo-git
cp -a /__src/. {shlex.quote(ws)}
chown -R {RUNNER_UID}:{RUNNER_UID} {shlex.quote(os.path.dirname(ws))} {shlex.quote(temp)}
chown {uid}:{uid} {shlex.quote(home)}
# Download caches only (uv, pip, pnpm, ccache defaults); never build trees.
mkdir -p /__cache/home-cache-{uid} && chmod 0777 /__cache/home-cache-{uid}
rm -rf {shlex.quote(home)}/.cache && ln -s /__cache/home-cache-{uid} {shlex.quote(home)}/.cache
chown -h {uid}:{uid} {shlex.quote(home)}/.cache
if [ -d {RUNNER_HOME}/.cargo ]; then
  rm -rf {RUNNER_HOME}/.cargo/registry {RUNNER_HOME}/.cargo/git
  ln -s /__cache/cargo-registry {RUNNER_HOME}/.cargo/registry
  ln -s /__cache/cargo-git {RUNNER_HOME}/.cargo/git
  chown -h {RUNNER_UID}:{RUNNER_UID} {RUNNER_HOME}/.cargo/registry {RUNNER_HOME}/.cargo/git
fi
"""
            sh(["docker", "exec", "-u", "0", cname, "bash", "-c", prep], capture_output=True)
            image_path = sh_out(["docker", "exec", cname, "printenv", "PATH"])
            prepared = True
        except subprocess.CalledProcessError as exc:
            jr.status = "fail"
            jr.note = f"harness could not prepare the container: {(exc.stderr or '')[-500:]}"
            self.cleanup_container(cname)
            jr.seconds = time.time() - start
            return jr
        log(f"start {wf_name}:{label} in {image}" + (f" ({'; '.join(notes)})" if notes else ""))
        state = JobState(
            ws=ws,
            temp=temp,
            home=home,
            uid=uid,
            cname=cname,
            rundir=rundir,
            logdir=logdir,
            in_container=in_container,
            # Hosted-runner jobs see the docker stand-in (shim/docker).
            path_prepend=[] if in_container else ["/__local-ci-shim"],
            env={},
            steps_ctx={},
            failed=False,
            ran_after_failure=False,
            image_path=image_path,
        )
        wf_env = wf.get("env") or {}
        job_env = job.get("env") or {}
        defaults = dict(((wf.get("defaults") or {}).get("run") or {}))
        defaults.update(((job.get("defaults") or {}).get("run") or {}))
        try:
            for k, v in wf_env.items():
                state.env[k] = interpolate_str(v, ev)
            ctx["env"] = dict(state.env)
            ev = Evaluator(ctx, {"failed": False}, self.hash_files)
            for k, v in job_env.items():
                state.env[k] = interpolate_str(v, ev)
            state.env.update(cenv)
            self.run_steps(
                jr, wf_name, label, job.get("steps") or [], ctx, state, defaults, prefix=""
            )
            outputs = {}
            ctx2 = dict(ctx, steps=state.steps_ctx, env=dict(state.env))
            ev2 = Evaluator(ctx2, {"failed": state.failed}, self.hash_files)
            for k, v in (job.get("outputs") or {}).items():
                outputs[k] = interpolate_str(v, ev2)
            jr.outputs = outputs
        finally:
            if prepared:
                self.cleanup_container(cname)
        jr.status = "fail" if state.failed else "pass"
        jr.note = "; ".join(notes)
        jr.seconds = time.time() - start
        log(f"{jr.status.upper():4} {wf_name}:{label} ({jr.seconds / 60:.1f} min)")
        return jr

    def cleanup_container(self, cname: str) -> None:
        if self.args.keep:
            log(f"keeping container {cname}")
            return
        # Files written into the host-mounted results tree by root or uid 1001
        # are handed back to the invoking user before the container goes away.
        subprocess.run(
            [
                "docker",
                "exec",
                "-u",
                "0",
                cname,
                "chown",
                "-R",
                f"{os.getuid()}:{os.getgid()}",
                "/__h/logs",
                "/__h/run",
                "/__h/artifacts",
            ],
            capture_output=True,
        )
        subprocess.run(["docker", "rm", "-f", cname], capture_output=True)

    def run_steps(
        self,
        jr: JobResult,
        wf_name: str,
        label: str,
        steps: list,
        ctx: dict,
        state: "JobState",
        defaults: dict,
        prefix: str,
        action_inputs: dict | None = None,
        action_dir: str | None = None,
    ) -> None:
        a = self.args
        for idx, step in enumerate(steps, 1):
            name_raw = step.get("name") or (
                f"Run {step['uses']}"
                if "uses" in step
                else "Run " + str(step.get("run", "")).strip().splitlines()[0][:60]
            )
            ctx_now = dict(ctx, steps=state.steps_ctx, env=dict(state.env))
            if action_inputs is not None:
                ctx_now["inputs"] = action_inputs
            status_now = {"failed": state.failed and not a.keep_going}
            ev = Evaluator(ctx_now, status_now, self.hash_files)
            try:
                name = interpolate_str(name_raw, ev)
            except ExprError:
                name = str(name_raw)
            display = f"{prefix}{name}"
            num = f"{prefix.replace(' > ', '-')}{idx:02d}"
            sr = StepResult(wf_name, label, display, "skip")
            try:
                run_it = evaluate_if(step.get("if"), ev)
            except ExprError as exc:
                sr.status, sr.note = "fail", f"harness could not evaluate if: {exc}"
                state.failed = True
                jr.steps.append(sr)
                continue
            if not run_it:
                if state.failed and not STATUS_FN_RE.search(str(step.get("if") or "")):
                    sr.note = "not run: an earlier step failed"
                else:
                    sr.note = "step `if:` is false"
                jr.steps.append(sr)
                continue
            if a.keep_going and state.failed:
                sr.note = "ran after an earlier failure (--keep-going)"
            skip_re = [re.compile(p) for p in (a.skip_step or [])]
            if any(r.search(f"{wf_name}:{label}:{display}") for r in skip_re):
                sr.note = "excluded by --skip-step"
                jr.steps.append(sr)
                continue
            step_env = dict(state.env)
            try:
                for k, v in (step.get("env") or {}).items():
                    step_env[k] = interpolate_str(v, ev)
            except ExprError as exc:
                sr.status, sr.note = "fail", f"harness could not evaluate env: {exc}"
                state.failed = True
                jr.steps.append(sr)
                continue
            t0 = time.time()
            logfile = state.logdir / f"{slug(num)}-{slug(display, 70)}.log"
            sr.log = str(logfile.relative_to(self.out))
            try:
                if "uses" in step:
                    with_ = {k: interpolate(v, ev) for k, v in (step.get("with") or {}).items()}
                    rc, note, outputs = self.run_action(
                        jr,
                        wf_name,
                        label,
                        step["uses"],
                        with_,
                        step_env,
                        ctx,
                        state,
                        defaults,
                        display,
                        logfile,
                        action_dir,
                    )
                else:
                    script = interpolate_str(step.get("run", ""), ev)
                    shell = step.get("shell") or defaults.get("shell")
                    wd = step.get("working-directory") or defaults.get("working-directory")
                    wd = interpolate_str(wd, ev) if wd else None
                    sr.script = script
                    rounds = self.repeat_count(f"{wf_name}:{label}:{display}")
                    round_notes = []
                    for rnd in range(1, rounds + 1):
                        rlog = (
                            logfile
                            if rounds == 1
                            else logfile.with_name(f"{logfile.stem}.round{rnd}.log")
                        )
                        rc, note, outputs = self.exec_script(
                            state, num, script, shell, wd, step_env, rlog, display
                        )
                        round_notes.append(f"round {rnd}: exit {rc}")
                        if rc != 0:
                            break
                    if rounds > 1:
                        note = (
                            (note + "; " if note else "")
                            + f"repeated {rounds}x ("
                            + ", ".join(round_notes)
                            + ")"
                        )
                        sr.log = str(
                            logfile.with_name(f"{logfile.stem}.round1.log").relative_to(self.out)
                        )
            except (ExprError, ValueError, TypeError, KeyError) as exc:
                # A harness defect is a failure, never a pass.
                rc, note, outputs = 1, f"harness could not evaluate the step: {exc}", {}
                logfile.write_text(f"# harness error: {exc!r}\n")
            sr.seconds = time.time() - t0
            if rc is None:
                sr.status = "skip"
                sr.note = note
            else:
                sr.exit_code = rc
                coe = step.get("continue-on-error")
                coe = truthy(interpolate(coe, ev)) if coe is not None else False
                sr.continue_on_error = bool(coe)
                if rc == 0:
                    sr.status = "pass"
                    if note:
                        sr.note = (sr.note + "; " if sr.note else "") + note
                else:
                    sr.status = "fail"
                    sr.note = (sr.note + "; " if sr.note else "") + (note or f"exit {rc}")
                    if coe:
                        sr.note += " (continue-on-error)"
                    else:
                        state.failed = True
            if step.get("id"):
                state.steps_ctx[step["id"]] = {
                    "outputs": outputs,
                    "outcome": "success" if rc == 0 else ("skipped" if rc is None else "failure"),
                    "conclusion": "success"
                    if rc == 0 or sr.continue_on_error
                    else ("skipped" if rc is None else "failure"),
                }
            jr.steps.append(sr)
            log(f"  {sr.status:4} {wf_name}:{label}: {display} ({sr.seconds:.0f}s)")

    def repeat_count(self, key: str) -> int:
        for item in self.args.repeat_step or []:
            pattern, _, count = item.rpartition(":")
            if pattern and re.search(pattern, key):
                return max(1, int(count))
        return 1

    def rewrite_parallelism(self, script: str) -> tuple[str, list[str]]:
        n = self.args.jobs
        if not n:
            return script, []
        changes = []
        out_lines = []
        for line in script.splitlines():
            new = line
            if re.search(r"\b(cmake|ninja|make)\b", line):
                new = re.sub(r"(?<![\w-])-j\s?(?:\d+|\"\$\(nproc\)\"|\$\(nproc\))", f"-j{n}", new)
                new = re.sub(r"--parallel\s+\d+", f"--parallel {n}", new)
            if new != line:
                changes.append(f"{line.strip()}  =>  {new.strip()}")
            out_lines.append(new)
        return "\n".join(out_lines) + ("\n" if script.endswith("\n") else ""), changes

    def exec_script(
        self,
        state: "JobState",
        num: str,
        script: str,
        shell: str | None,
        wd: str | None,
        env: dict,
        logfile: Path,
        display: str,
        rewrite: bool = True,
    ) -> tuple[int | None, str, dict]:
        script, changes = self.rewrite_parallelism(script) if rewrite else (script, [])
        ext = ".py" if shell == "python" else ".sh"
        script_path = state.rundir / f"{slug(num)}{ext}"
        script_path.write_text(script)
        out_file = state.rundir / f"{slug(num)}.output"
        env_file = state.rundir / f"{slug(num)}.env"
        path_file = state.rundir / f"{slug(num)}.path"
        summary_file = state.rundir / f"{slug(num)}.summary"
        for f in (out_file, env_file, path_file, summary_file):
            f.write_text("")
            os.chmod(f, 0o666)
        c_rundir = "/__h/" + str(state.rundir.relative_to(self.out))
        c_script = f"{c_rundir}/{script_path.name}"
        full_env = {
            "CI": "true",
            "GITHUB_ACTIONS": "true",
            "HOME": state.home,
            "GITHUB_WORKSPACE": state.ws,
            "RUNNER_TEMP": state.temp,
            "RUNNER_OS": "Linux",
            "RUNNER_ARCH": "X64",
            "RUNNER_TOOL_CACHE": "/opt/hostedtoolcache",
            "GITHUB_SHA": self.commit,
            "GITHUB_REF": f"refs/pull/{self.args.pr}/merge",
            "GITHUB_EVENT_NAME": "pull_request",
            "GITHUB_BASE_REF": self.args.base_branch,
            "GITHUB_HEAD_REF": self.args.head_branch,
            "GITHUB_REPOSITORY": REPOSITORY,
            "GITHUB_REPOSITORY_OWNER": REPOSITORY.split("/")[0],
            "GITHUB_RUN_ID": self.run_id,
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_SERVER_URL": "https://github.com",
            "GITHUB_OUTPUT": f"{c_rundir}/{out_file.name}",
            "GITHUB_ENV": f"{c_rundir}/{env_file.name}",
            "GITHUB_PATH": f"{c_rundir}/{path_file.name}",
            "GITHUB_STEP_SUMMARY": f"{c_rundir}/{summary_file.name}",
            "ImageOS": "ubuntu24",
            "ImageVersion": "local-ci",
        }
        full_env.update(env)
        path = ":".join(list(reversed(state.path_prepend)) + [state.image_path])
        if shell in (None, ""):
            argv = ["bash", "-e", c_script]
        elif shell == "bash":
            argv = ["bash", "--noprofile", "--norc", "-eo", "pipefail", c_script]
        elif shell == "sh":
            argv = ["sh", "-e", c_script]
        elif shell == "python":
            argv = ["python", c_script]
        else:
            argv = [x.replace("{0}", c_script) for x in shlex.split(shell)]
        workdir = state.ws if not wd else (wd if wd.startswith("/") else f"{state.ws}/{wd}")
        launch = ["#!/bin/bash"]
        for k, v in full_env.items():
            if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", k):
                launch.append(f"export {k}={shlex.quote(str(v))}")
        launch.append(f"export PATH={shlex.quote(path)}")
        launch.append(f"cd {shlex.quote(workdir)} || exit 1")
        launch.append("exec " + " ".join(shlex.quote(x) for x in argv))
        launch_path = state.rundir / f"{slug(num)}.launch"
        launch_path.write_text("\n".join(launch) + "\n")
        with open(logfile, "w") as fh:
            fh.write(
                f"# step: {display}\n# shell: {' '.join(argv)}\n# working-directory: {workdir}\n"
                f"# user: {state.uid}\n"
            )
            for c in changes:
                fh.write(f"# parallelism rewritten: {c}\n")
            fh.write(
                "# ---- script ----\n"
                + script
                + ("\n" if not script.endswith("\n") else "")
                + "# ---- output ----\n"
            )
            fh.flush()
            rc = subprocess.run(
                [
                    "docker",
                    "exec",
                    "-u",
                    str(state.uid),
                    state.cname,
                    "bash",
                    f"/__h/{launch_path.relative_to(self.out)}",
                ],
                stdout=fh,
                stderr=subprocess.STDOUT,
            ).returncode
            fh.write(f"\n# exit status: {rc}\n")
        if rc == 78 and "local-ci docker shim: refusing" in logfile.read_text(errors="replace"):
            return None, "needs real Docker inside the job, which this replay does not provide", {}
        outputs = parse_kv_file(out_file)
        for k, v in parse_kv_file(env_file).items():
            state.env[k] = v
        for line in path_file.read_text().splitlines():
            if line.strip():
                state.path_prepend.append(line.strip())
        return rc, "", outputs

    # ---- actions -------------------------------------------------------------

    def run_action(
        self,
        jr: JobResult,
        wf_name: str,
        label: str,
        uses: str,
        with_: dict,
        env: dict,
        ctx: dict,
        state: "JobState",
        defaults: dict,
        display: str,
        logfile: Path,
        action_dir: str | None,
    ) -> tuple[int | None, str, dict]:
        name = uses.split("@")[0]
        num = slug(display, 40) + "-action"

        def script(body: str, note: str) -> tuple[int | None, str, dict]:
            rc, _, outputs = self.exec_script(
                state, num, body, "bash", None, env, logfile, display, rewrite=False
            )
            return rc, note, outputs

        if name.startswith("./"):
            action_path = self.src / name[2:]
            yml = action_path / "action.yml"
            if not yml.exists():
                yml = action_path / "action.yaml"
            spec = yaml.safe_load(yml.read_text())
            runs = spec.get("runs") or {}
            if runs.get("using") != "composite":
                return None, f"local action {name} is not composite", {}
            inputs = {}
            for k, v in (spec.get("inputs") or {}).items():
                inputs[k] = with_.get(k, (v or {}).get("default", ""))
            sub_ctx = dict(ctx)
            sub_ctx["github"] = dict(ctx["github"], action_path=f"{state.ws}/{name[2:]}")
            before = len(jr.steps)
            failed_before = state.failed
            saved_steps = state.steps_ctx
            state.steps_ctx = {}
            self.run_steps(
                jr,
                wf_name,
                label,
                runs.get("steps") or [],
                sub_ctx,
                state,
                {},
                prefix=f"{display} > ",
                action_inputs=inputs,
                action_dir=name,
            )
            inner = state.steps_ctx
            state.steps_ctx = saved_steps
            ev = Evaluator(
                dict(sub_ctx, steps=inner, inputs=inputs, env=dict(state.env)), {}, self.hash_files
            )
            outputs = {
                k: interpolate_str((v or {}).get("value", ""), ev)
                for k, v in (spec.get("outputs") or {}).items()
            }
            failed = state.failed and not failed_before
            logfile.write_text(
                f"# composite action {name}: {len(jr.steps) - before} inner step(s), see siblings\n"
            )
            return (1 if failed else 0), "composite action", outputs

        if name == "actions/checkout":
            ref = to_str(with_.get("ref") or "")
            if ref and ref not in (self.commit, self.commit[: len(ref)]) and len(ref) >= 7:
                return (
                    None,
                    f"checkout of ref {ref} (not the commit under test) is not replayed",
                    {},
                )
            if ref and len(ref) < 7:
                return None, f"checkout of ref {ref} is not replayed", {}
            if with_.get("repository") or with_.get("path"):
                return (
                    None,
                    f"checkout with {sorted(k for k in with_ if k in ('repository', 'path'))} is not replayed",
                    {},
                )
            depth = str(with_.get("fetch-depth", "1"))
            if depth == "1":
                body = (
                    'cfg="$(mktemp)"; printf \'[safe]\\n\\tdirectory = *\\n\' > "$cfg"\n'
                    'GIT_CONFIG_GLOBAL="$cfg" git -C "$GITHUB_WORKSPACE" rev-parse HEAD; rm -f "$cfg"\n'
                )
                return script(body, "workspace pre-cloned at depth 1")
            refspec = (
                "'+refs/remotes/origin/*:refs/remotes/origin/*'"
                if self.mirror
                else "'+refs/heads/*:refs/remotes/origin/*'"
            )
            remote = "/__mirror" if self.mirror else self.source
            deepen = "--unshallow" if depth == "0" else f"--depth={depth}"
            # Like actions/checkout, trust the directories only for these git
            # calls (a temporary global config); later steps see the real
            # ownership.
            body = (
                'cd "$GITHUB_WORKSPACE"\n'
                'cfg="$(mktemp)"; printf \'[safe]\\n\\tdirectory = *\\n\' > "$cfg"\n'
                f'GIT_CONFIG_GLOBAL="$cfg" git fetch -q --no-write-fetch-head {deepen} --tags {shlex.quote(remote)} {refspec}\n'
                'GIT_CONFIG_GLOBAL="$cfg" git rev-parse HEAD\n'
                'GIT_CONFIG_GLOBAL="$cfg" git rev-list --count HEAD\n'
                'rm -f "$cfg"\n'
            )
            return script(body, f"workspace deepened (fetch-depth {depth})")

        if name == "actions/setup-python":
            ver = to_str(with_.get("python-version", "3.14"))
            body = f"""
ver={shlex.quote(ver)}
dir=/opt/hostedtoolcache/Python/$ver/x64/bin
if [ ! -x "$dir/python" ]; then
  uvbin="$(command -v uv || echo /opt/uv/uv)"
  [ -x "$uvbin" ] || {{ echo "no uv to provide Python $ver" >&2; exit 1; }}
  export UV_PYTHON_INSTALL_DIR=/opt/hostedtoolcache/uv-python
  "$uvbin" python install "$ver"
  py="$("$uvbin" python find "$ver")"
  mkdir -p "$dir"
  ln -sf "$py" "$dir/python"; ln -sf "$py" "$dir/python3"
  find /opt/hostedtoolcache/uv-python -name EXTERNALLY-MANAGED -delete
  "$py" -m ensurepip --upgrade >/dev/null
  printf '#!/bin/sh\\nexec "%s" -m pip "$@"\\n' "$py" > "$dir/pip"; chmod +x "$dir/pip"; cp "$dir/pip" "$dir/pip3"
fi
echo "$dir" >> "$GITHUB_PATH"
"$dir/python" --version
echo "python-version=$("$dir/python" -c 'import platform;print(platform.python_version())')" >> "$GITHUB_OUTPUT"
"""
            return script(body, f"emulated: Python {ver} from the local tool cache")

        if name == "astral-sh/setup-uv":
            body = """
if command -v uv >/dev/null 2>&1; then dir="$(dirname "$(command -v uv)")"; else dir=/opt/uv; fi
echo "$dir" >> "$GITHUB_PATH"
"$dir/uv" --version
"""
            return script(body, "emulated: uv from the image")

        if name == "dtolnay/rust-toolchain":
            tc = to_str(with_.get("toolchain") or uses.split("@")[1])
            comps = to_str(with_.get("components", ""))
            comp_args = " ".join(
                f"--component {shlex.quote(c.strip())}" for c in comps.split(",") if c.strip()
            )
            body = f"rustup toolchain install {shlex.quote(tc)} --profile minimal {comp_args}\nrustup default {shlex.quote(tc)}\nrustc --version\n"
            return script(body, f"emulated: rustup toolchain {tc}")

        if name in ("actions/cache", "actions/cache/restore", "actions/cache/save"):
            if self.args.no_cache:
                return None, "cache disabled by --no-cache (cold build)", {}
            paths = [p for p in to_str(with_.get("path", "")).splitlines() if p.strip()]
            lines = ["set -e", "hit=false"]
            for p in paths:
                p = p.strip()
                key = slug(p.replace("~", "home"), 80)
                lines += [
                    f"p={shlex.quote(p)}",
                    'case "$p" in "~"*) p="$HOME${p#\\~}";; /*) ;; *) p="$GITHUB_WORKSPACE/$p";; esac',
                    f"store=/__cache/actions/{key}",
                ]
                if name == "actions/cache/save":
                    lines += [
                        'if [ -L "$p" ]; then echo "persisted in place: $p -> $(readlink "$p")"; '
                        'else mkdir -p "$store"; cp -a "$p/." "$store/" 2>/dev/null || true; fi'
                    ]
                else:
                    lines += [
                        'mkdir -p "$store"',
                        'chmod 0777 "$store" 2>/dev/null || true',
                        '[ -n "$(ls -A "$store" 2>/dev/null)" ] && hit=true',
                        'mkdir -p "$(dirname "$p")"',
                        'rm -rf "$p"',
                        'ln -s "$store" "$p"',
                        'echo "local cache: $p -> $store ($(du -sh "$store" | cut -f1))"',
                    ]
            lines.append('echo "cache-hit=$hit" >> "$GITHUB_OUTPUT"')
            return script("\n".join(lines) + "\n", "emulated: persistent local cache directory")

        if name == "Swatinem/rust-cache":
            return (
                None,
                "GitHub cache service; cargo registry shared through a local volume, target dirs cold",
                {},
            )

        if name == "actions/upload-artifact":
            art = slug(to_str(with_.get("name", "artifact")))
            paths = [p.strip() for p in to_str(with_.get("path", "")).splitlines() if p.strip()]
            lines = [
                "set +e",
                f"dest=/__h/artifacts/{slug(label)}/{art}",
                'mkdir -p "$dest"',
                'cd "$GITHUB_WORKSPACE"',
            ]
            for p in paths:
                lines.append(
                    f'for f in {p}; do [ -e "$f" ] && cp -a --parents "$f" "$dest/" 2>/dev/null '
                    f'|| cp -a "$f" "$dest/" 2>/dev/null || echo "not found: $f"; done'
                )
            lines.append('du -sh "$dest"; exit 0')
            return script("\n".join(lines) + "\n", "emulated: copied into the results directory")

        if name == "actions/download-artifact":
            return None, "artifact download between jobs is not replayed", {}

        if name == "actions/setup-node":
            return script(
                "node --version\n", "emulated: Node.js from the image (version may differ)"
            )

        return None, f"remote action {name} is not replayed", {}

    # ---- report --------------------------------------------------------------

    def report(self) -> int:
        rows = []
        failed = False
        for jr in sorted(self.results, key=lambda r: (r.workflow, r.job)):
            if not jr.steps:
                rows.append((jr.workflow, jr.job, "(job)", jr.status, jr.seconds, jr.note))
                if jr.status == "fail":
                    failed = True
                continue
            for s in jr.steps:
                rows.append((jr.workflow, jr.job, s.step, s.status, s.seconds, s.note))
            if jr.status == "fail":
                failed = True
        w = [
            max(len(str(r[i])) for r in rows + [("workflow", "job", "step", "status", 0, "note")])
            for i in range(3)
        ]
        w = [min(x, 60) for x in w]
        lines = [f"{'workflow':<{w[0]}}  {'job':<{w[1]}}  {'step':<{w[2]}}  status  duration  note"]
        md = ["| workflow | job | step | status | duration | note |", "|---|---|---|---|---|---|"]
        for wf, job, step, status, secs, note in rows:
            dur = f"{secs / 60:.1f}m" if secs >= 60 else f"{secs:.0f}s"
            lines.append(
                f"{wf[: w[0]]:<{w[0]}}  {job[: w[1]]:<{w[1]}}  {step[: w[2]]:<{w[2]}}  {status:<6}  {dur:>8}  {note}"
            )
            md.append(f"| {wf} | {job} | {step} | {status} | {dur} | {note.replace('|', '/')} |")
        if getattr(self, "not_triggered", None):
            md += ["", "Workflows the pull request does not trigger:", ""]
            md += [f"- {wf}: {why}" for wf, why in self.not_triggered]
        # Every repository guard script any workflow calls, and whether a
        # replayed step that actually ran called it.
        guard_re = re.compile(r"scripts/check-[A-Za-z0-9_.-]+")
        referenced: dict[str, set[str]] = {}
        for p in sorted((self.src / ".github/workflows").glob("*.yml")):
            for g in guard_re.findall(p.read_text()):
                referenced.setdefault(g, set()).add(p.stem)
        ran: dict[str, list[str]] = {}
        for jr in self.results:
            for st in jr.steps:
                if st.status in ("pass", "fail"):
                    for g in set(guard_re.findall(st.script)):
                        ran.setdefault(g, []).append(f"{st.status}")
        cov: list[tuple[str, str, str]] = []
        for g, wfs_ in sorted(referenced.items()):
            r = ran.get(g)
            verdict = ("fail" if "fail" in r else "pass") if r else "not run"
            cov.append((g, verdict, ", ".join(sorted(wfs_))))
        lines += ["", "Repository guards called by any workflow:"]
        lines += [f"{g:<55} {v:<8} ({w})" for g, v, w in cov]
        md += [
            "",
            "Repository guards called by any workflow:",
            "",
            "| guard | result | workflows |",
            "|---|---|---|",
        ]
        md += [f"| {g} | {v} | {w} |" for g, v, w in cov]
        summary = "\n".join(lines)
        (self.out / "summary.txt").write_text(summary + "\n")
        (self.out / "summary.md").write_text(
            f"Local CI replay of {self.commit} (base {self.base_sha})\n\n" + "\n".join(md) + "\n"
        )
        (self.out / "summary.json").write_text(
            json.dumps(
                {
                    "commit": self.commit,
                    "base": self.base_sha,
                    "jobs": [
                        {
                            "workflow": j.workflow,
                            "job": j.job,
                            "status": j.status,
                            "seconds": round(j.seconds, 1),
                            "note": j.note,
                            "steps": [
                                {k: v for k, v in s.__dict__.items() if k != "script"}
                                for s in j.steps
                            ],
                        }
                        for j in self.results
                    ],
                },
                indent=2,
            )
        )
        print(summary)
        counts = {k: sum(1 for r in rows if r[3] == k) for k in ("pass", "fail", "skip")}
        print(
            f"\n{counts['pass']} passed, {counts['fail']} failed, {counts['skip']} skipped; results in {self.out}"
        )
        return 1 if failed else 0


@dataclass
class JobState:
    ws: str
    temp: str
    home: str
    uid: int
    cname: str
    rundir: Path
    logdir: Path
    in_container: bool
    path_prepend: list[str]
    env: dict[str, str]
    steps_ctx: dict[str, Any]
    failed: bool
    ran_after_failure: bool
    image_path: str = ""


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("commit", help="commit to replay (any rev the source resolves)")
    ap.add_argument(
        "--source",
        default=None,
        help="repository to clone from: a local checkout (default: this one) or a URL",
    )
    ap.add_argument(
        "--out",
        default=None,
        help="results directory (default ~/.cache/tos-local-ci/<commit>-<time>)",
    )
    ap.add_argument(
        "--workflow",
        action="append",
        help="workflow file stem, optionally :job; repeatable. Default: every workflow the PR triggers",
    )
    ap.add_argument(
        "--exclude", action="append", help="workflow or workflow:job to report as skipped"
    )
    ap.add_argument("--skip-step", action="append", help="regex over 'workflow:job:step' to skip")
    ap.add_argument("--base-branch", default="main")
    ap.add_argument("--head-branch", default="")
    ap.add_argument("--pr", default="0", help="pull request number for github.event context")
    ap.add_argument(
        "--jobs",
        type=int,
        default=0,
        help="rewrite build parallelism (-jN, --parallel N) in cmake/ninja/make lines to this value",
    )
    ap.add_argument("--cpuset", default="0-95", help="docker --cpuset-cpus for every job container")
    ap.add_argument("--parallel", type=int, default=2, help="jobs to run at once")
    ap.add_argument(
        "--min-free-gb", type=int, default=30, help="do not start a job below this free disk"
    )
    ap.add_argument(
        "--repeat-step",
        action="append",
        help="REGEX:N - run steps whose 'workflow:job:step' matches N times; any failing round fails the step "
        "(for suites with randomized inputs)",
    )
    ap.add_argument(
        "--keep-going",
        action="store_true",
        help="run later steps of a job after a failure (GitHub stops; such steps are annotated)",
    )
    ap.add_argument(
        "--no-cache", action="store_true", help="do not emulate actions/cache (cold builds)"
    )
    ap.add_argument("--keep", action="store_true", help="keep job containers")
    ap.add_argument("--list", action="store_true", help="print the plan and exit")
    args = ap.parse_args()
    if args.source is None:
        args.source = str(HERE.parent.parent)
    run = Run(args)
    run.resolve_source()
    if args.out is None:
        stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        args.out = str(Path.home() / ".cache" / "tos-local-ci" / f"{args.commit[:12]}-{stamp}")
    started = time.time()
    run.prepare_clone()
    if not args.list:
        run.ensure_images()
    rc = run.run_all()
    if not args.list:
        print(f"total wall time {(time.time() - started) / 60:.1f} min")
    return rc


if __name__ == "__main__":
    sys.exit(main())
