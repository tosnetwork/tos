# rt.jar Reproducibility + stdlib_hash Pinning

> **Audience**: launch coordinators and validator operators
> establishing or verifying the canonical `rt.jar` bytes for a
> wc=3 chain.

## 1. Why this matters

Every wc=3 contract's JVAC carries a `stdlib_hash` field — the
sha256 of the rt.jar the contract was deployed against.  Validators
reject every inbound call whose JVAC's `stdlib_hash` doesn't match
ConfigParam 85's `stdlib_hash`.  This is the gate that pins the
runtime library every wc=3 contract relies on.

For the gate to admit any contract at all, the launch coordinator
must:

1. Build rt.jar from the pinned source tree.
2. Compute its sha256.
3. Commit that value to ConfigParam 85 (via
   `jvm-config-param-cell-with-stdlib`).
4. Distribute the exact same rt.jar bytes to every validator.
5. Distribute the same hash to every contract developer (so their
   `tosctl jw deploy-contract --stdlib-hash <value>` matches).

If two operators build rt.jar from the same source and get
different sha256, step 4 falls apart — validators disagree on what
the canonical bytes are, no contract activates.  Phase V locks
this property at the build-system level.

## 2. Determinism guarantees

The `make rt.jar` pipeline in `jvm/avata/makefile` now produces a
byte-identical jar across **same-machine same-JDK** builds.  Three
mechanisms combine to achieve this:

1. **Stable file mtimes** — every `.class` file gets touched to
   `1980-01-01 00:00:00` (the ZIP epoch) before jarring.  Without
   this, jar's central-directory entries pick up the file's
   compilation wallclock.

2. **Stable entry order** — the file list is sorted with
   `LC_ALL=C sort` before being passed to `jar`.  Without this,
   filesystem-dependent traversal order (ext4 vs apfs vs tmpfs)
   would produce different entry orderings.

3. **Post-process timestamp canonicalization** — Python tool
   `jvm/avata/tools/normalize-jar-timestamps.py` zeros every ZIP
   entry's `date_time` to (1980, 1, 1, 0, 0, 0) and strips the
   `extra` field.  Necessary because OpenJDK 8's `jar` stamps
   wallclock-derived timestamps into the central directory even
   when file mtimes are pinned (4-byte drift verified empirically).

### 2.1 Canonical stdlib_hash algorithm

Phase DD aligned the off-chain `stdlib_hash` computation with the
production Avata runtime's `hash_boot_classpath`.  The canonical
algorithm is NOT plain `sha256(rt.jar)` — that produces a value
the runtime cannot recognize, and every wc=3 contract deployed
with such a hash rejects every call with `sk_bad_state`.

The canonical wire format (locked by
`jvm/core/config-param.cpp::compute_canonical_stdlib_hash` and
the `Test_JvmWorkchainCore_StdlibHashAlgorithmAlignment` test):

```
sha256(
    "TOS-JVM-AVATA-BOOTCLASSPATH-v1"
    || u64_be(rt_jar.size())
    || rt_jar
    || u64_be(1)                         # single-entry classpath
)
```

Three implementations MUST agree byte-for-byte:

  1. **`compute_canonical_stdlib_hash`** (C++,
     `jvm/core/config-param.cpp`) — what
     `default_activation_with_stdlib` and the Fift word
     `jvm-config-param-cell-with-stdlib` write into ConfigParam 85.
  2. **`hash_boot_classpath`** (C++,
     `jvm/core/avata-runtime.cpp`) — what the production runtime
     returns from `rt_jar_hash()` at startup, consumed by the
     dispatch engine on every wc=3 call.
  3. **`compute-stdlib-hash.py`**
     (`jvm/avata/tools/compute-stdlib-hash.py`) — what
     `make print-rt-jar-stdlib-hash`,
     `scripts/jvm-testnet-genesis-rehearsal.sh`, and operators
     running `tosctl jw deploy-contract --stdlib-hash <hex>`
     consume off-chain.

### 2.2 Canonical hashes (post-Phase-DD)

Under the canonical toolchain (Ubuntu 22.04 + openjdk-8-jdk-headless,
pinned by `.github/workflows/check-jvm-rt-determinism.yml` and the
`jvm/avata/Dockerfile.canonical-build`), the canonical hashes
post-Phase-DD are:

| Artifact | hash | Algorithm |
|---|---|---|
| `rt.jar` (= `stdlib_hash`, ConfigParam 85) | `ae4ff3b7e557a8acffe31e9b41959e811c67dea87b6c6c3e38129466e5ade765` | canonical (§2.1) |
| `api.jar` | `87b1a190733f422f46d908487f43e63d5a792ae328fe0b63fa39ecf06365d3d4` | plain sha256 |

Note the rt.jar value uses the canonical algorithm (§2.1).  The
api.jar value uses plain sha256 because api.jar isn't part of the
consensus surface — it's consumed by `tools/javac -bootclasspath`
during contract compilation, not by the runtime, so its hash is
only used for build-system integrity checks.

> **The `rt.jar` hash above is the value that must be committed
> to ConfigParam 85 as `stdlib_hash` for any wc=3 chain built
> from the post-Phase-DD tree.**  Operators verify their toolchain
> produces the same hash by running
> `make -C jvm/avata java-version=8 print-rt-jar-stdlib-hash`
> or `scripts/jvm-testnet-genesis-rehearsal.sh`.

A previous version of this document (Phase CC) listed
`8c0f7bfc0ceec73dba513537b94bc05f09409b3bbf648f9918ae021f5ebc0e72`
as the canonical value — that was plain `sha256(rt.jar)` and is
NOT consensus-compatible.  Phase DD obsoleted it.

### 2.2 What is NOT guaranteed

* **Cross-JDK determinism** — the .class files javac produces
  depend on JDK vendor + version (e.g. AdoptOpenJDK 8u392 vs
  Zulu 8u412 may emit slightly different bytecode for the same
  source).  The canonical hash above is for the Ubuntu 22.04
  distro openjdk-8 build.  Operators on other JDK builds may
  see different hashes; switch to the canonical toolchain
  (Dockerfile or CI workflow) for the reference value.

* **`build-rt-jar` from a dirty tree** — if local edits / stash /
  uncommitted .java files exist, the resulting rt.jar will not
  match the published canonical hash.  Always build from a clean
  tag checkout.

* **rt.jar surface changes** — any commit that adds, removes, or
  modifies a `.java` file under `jvm/avata/rt/` changes the
  canonical hash.  Track the latest value via the CI workflow log
  on each merged change to `jvm/avata/`.

## 3. Build flow

### 3.1 Single canonical build

```bash
cd jvm/avata
make -B java-version=8 build/<platform>/rt.jar
sha256sum build/<platform>/rt.jar
```

Replace `<platform>` with `linux-x86_64`, `linux-arm64`, etc.  The
java-version flag pins JDK 8 (the current Avata stdlib target;
JDK 11/17 builds are out of scope until the toolchain bump lands).

### 3.2 Self-verify determinism

```bash
make java-version=8 check-rt-jar-determinism
```

This target:
1. Runs the rt.jar build.
2. Captures its sha256.
3. Cleans + rebuilds.
4. Captures the second sha256.
5. Fails loudly if the two differ.

Add this to CI for every PR that touches `jvm/avata/`.

### 3.3 Print the stdlib_hash

```bash
make java-version=8 print-rt-jar-stdlib-hash
```

Prints the sha256 only (no path / no envelope) so it can be piped
directly into the genesis Fift script:

```bash
STDLIB_HASH=$(cd jvm/avata && make -s java-version=8 print-rt-jar-stdlib-hash)
echo "use this in jvm-config-param-cell-with-stdlib: $STDLIB_HASH"
```

## 4. Multi-operator verification flow

Before committing a stdlib_hash to a public ConfigParam 85, the
launch coordinator should verify cross-operator reproducibility:

1. **Coordinator** builds rt.jar at the chosen tag, publishes both
   the bytes (rt.jar artifact) and its sha256 (the stdlib_hash).

2. **Each operator** builds rt.jar locally from the same tag,
   computes sha256, and compares against the coordinator's value.

3. **Operators that mismatch**: investigate the local JDK
   vendor/version + platform; report findings to the coordinator.
   The coordinator may need to pin a specific JDK build for the
   v1 chain.

4. **Coordinator** commits the agreed-upon stdlib_hash to
   ConfigParam 85 in the genesis ceremony.

## 5. Pinned-JDK approach (recommended for v1)

For the simplest reproducibility story, pin a single JDK build
across all operators.  Suggested setup:

* **Operating system**: Debian 12 (bullseye) or Ubuntu 22.04 LTS.
* **JDK**: `openjdk-8-jdk-headless` from the distro repos.

A coordinator-published `Dockerfile` snapshotting this toolchain
makes the cross-operator verification trivial: every operator
runs the same container, the .class outputs are necessarily
identical, and the only remaining variable is the rt.jar
post-processing — which this commit fully canonicalizes.

The canonical build host pattern is already exercised in CI:
`.github/workflows/check-jvm-rt-determinism.yml` runs on every PR
touching `jvm/avata/**` and verifies both rt.jar AND api.jar
produce byte-identical sha256 across two clean back-to-back
builds under `ubuntu-22.04` + `openjdk-8-jdk-headless`.  This is
the same toolchain pair the runbook recommends operators
standardize on, so the CI-printed hash is the canonical hash for
that toolchain combination.

A standalone Dockerfile derived from the same base would let
operators reproduce the canonical hash without going through
GitHub Actions; that's a follow-up worth doing once the canonical
hash is published in a release note.

## 6. Troubleshooting

### `check-rt-jar-determinism` fails on a fresh checkout

* Confirm `python3` is in `PATH` (the normalize-jar-timestamps.py
  post-process needs it).
* Confirm `LC_ALL=C` and `LANG=C` aren't overridden by your shell
  rc files (the entry-sort depends on byte-ordering, not
  locale-ordering).
* Run `make -B build/<platform>/rt.jar` once first to populate
  the build tree; some intermediate files may not be tracked by
  the dep graph.

### Coordinator and operator disagree on sha256

In order of likelihood:

1. **JDK version mismatch** — check `javac -version` on both
   sides.  Even minor version differences (8u392 vs 8u412) can
   change the .class output.

2. **Different source tree** — confirm both sides are at the same
   git SHA via `git rev-parse HEAD`.  A single uncommitted line
   in any `.java` file under `rt/` is enough.

3. **Different build platform** — javac is mostly portable but
   some host-toolchain quirks leak through.  If pinning to one
   architecture is acceptable (e.g. linux-x86_64), use that as
   the canonical build host.

4. **Local makefile edits** — `git diff jvm/avata/makefile` and
   confirm no local overrides.

If all four check out and the hashes still differ, escalate with
the full output of both `sha256sum build/<platform>/rt.jar` plus
`javac -version` plus `git rev-parse HEAD` from both sides — the
coordinator can diff the jars byte-for-byte to find the source.

## 7. References

| File / Target                                       | Role                                  |
|-----------------------------------------------------|---------------------------------------|
| `jvm/avata/makefile` (rt.jar / api.jar rules)       | Deterministic build pipeline          |
| `jvm/avata/tools/normalize-jar-timestamps.py`       | ZIP timestamp canonicalizer           |
| `make check-rt-jar-determinism`                     | Self-verify same-machine reproducibility |
| `make print-rt-jar-stdlib-hash`                     | Emit the sha256 for ConfigParam 85    |
| `doc/jvm/jvm-mainnet-activation.md` §5                  | Where stdlib_hash gets committed      |
| `doc/jvm/jvm-validator-ops.md` §3.1                     | Operator-side rt.jar setup            |
| `doc/jvm/jvm-dos-hardening.md`                          | Why stdlib_hash matters (consensus gate) |
