# X02 frozen binding with the anchored verifier

The X02 Config34 check accepts a block only through `tos-proof-verify`, which
the previous native snapshot (`f1f912…`) did not contain. The binding was
re-frozen on 2026-10-05. The X02 coordinator loads
`scripts/x02_four_node_inputs.json` and checks it with
`scripts/x02_four_node_binding.py`, which now pins the new snapshot.

## What is frozen

| Item | Value |
|---|---|
| Native source | `a075bc51c4e5f949e3c79f36a2cbce8eccb34fce` |
| Native build | Ubuntu 24.04 builder image from `Dockerfile.builder` (`builder-24`, Clang 21), CI flags (Release, `x86-64`, jemalloc, production build); build root `/datax/n6-unit-agents/X02/build-a075bc51c` |
| `validator-engine` SHA-256 | `8e370be745db7ee406746ffed6e1bd1cfe57bb104ff1827abde6e2992e838236` |
| `tos-proof-verify` SHA-256 | `7a914fc405834a184e27bd90741b67a58ba4867bfbf2209cb6ffa055f5f88778` |
| U24 rootfs | `/datax/n6-unit-agents/Z02/u24-rootfs`: `ubuntu:24.04` (`sha256:534baea6…eb55`) plus `libssl3t64 libjemalloc2 libstdc++6 libgcc-s1`, exported with `docker export`; image `sha256:abfb6f76…3b60` |
| Interpreter | CPython 3.14.4 standalone build, `/datax/n6-unit-agents/Z02/u24-runtime-a075bc51c/python/bin/python3.14`, SHA-256 `3033d7dd…c9db` |
| Dependencies | `uv export --frozen --no-dev --package tostester` installed into `…/u24-runtime-a075bc51c/site-packages` |
| Source root | clean checkout `/datax/n6-unit-agents/X02/source` (`git status` clean; generated TL API present) |
| Scenario | D (directed isolation); pinned host files `/usr/bin/bwrap`, `/usr/sbin/tc` |
| Binding | 5835 files; `scripts/x02_four_node_inputs.json` SHA-256 `b51d277472af63d38e2d21b36fba13bc29e364a1a7bf486c807a9fefd532fe5d` |

The binding was produced by `scripts/x02_freeze_binding.py` from the clean
checkout at `d854c2309`. The tool ends by running `verify_binding(…, host=True)`,
and the binding passed. It passed again at `0229eb17d`, after the control runs.

### Deviations from the earlier preparation

- The rootfs is a `docker export` of `ubuntu:24.04`, not a debootstrap of noble.
- The interpreter is a standalone CPython build, not one compiled for the rootfs.
- The binding contract requires the Python TOS library `toslib/libtoslibjson.so`
  to be a regular file. The build produces a symbolic link to
  `libtoslibjson.so.0.5`, so the link was replaced by a copy of that file
  (same bytes).
- `pq_pool_stake_order` was built on the Ubuntu 22.04 host
  (`cargo build --release --locked -p contracts --example pq_pool_stake_order`),
  not in the U24 builder. It needs only libc.
- The rootfs gained an empty `/datax` directory, so that bwrap can mount its
  tmpfs there.
- Build, runtime and rootfs are read-only after freezing.

This is a development re-freeze. It has not been independently accepted the way
the earlier runtime was.

## Controls through the frozen launcher

`test/pq-native/x02_frozen_config34_controls.py` was run from the frozen
checkout at `0229eb17d`. It uses the coordinator's `config34_proof_check` with
its default launcher, `verifier_sandbox_argv`: bwrap, the frozen U24 rootfs,
the pinned interpreter, and the verifier bound read-only from the closure.

| Control | Result | Sandbox terminal |
|---|---|---|
| genuine (zerostate anchor) | `X02_CONFIG34_SAME_BLOCK_PROOF_OK`, 5 links, election 1790945281 | natural exit 0 |
| foreign-anchor (zerostate of `c04-pq-genesis.boc`) | refused: "anchored verifier refused (exit 1): proof chain does not start at the authenticated block" | natural exit 1 |

The result JSON is `/datax/n6-unit-agents/X02/config34-controls-0229eb17d.json`,
SHA-256 `22b4ebd8bbca45eac53e3dcc58f0256d6c19c980a3cacb4f323d50537e7362a4`. It
lives outside Git and is not durable. Neither sandbox setup failed, timed out
or was signalled.

`test/pq-native/test_x02_verifier_sandbox.py` reads its inputs from the frozen
binding. Run from the frozen checkout it passes 9/9: bound paths read-only and
no network, the U24 loader (glibc 2.39), dependency imports, output and time
bounds, and refusal of a setup failure. These tests were skipped before,
because the earlier rootfs was gone.

## Verifier sensitivity at `a075bc51c`

`test/pq-native/proof-verify-mutations.py --build-dir build`: 42 controls, all
red, then restored green (49/0, and the live-commit test passes). The output
SHA-256 is `842d4b74d069b620970e752f296e277691e540262d9326758b09d89a42c9b24b`;
it is kept outside Git.
