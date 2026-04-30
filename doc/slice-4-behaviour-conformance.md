# Slice 4 Behaviour Conformance

Status: release-package surrogate, 2026-04-30.

Behaviour manifests are check-only metadata. They do not generate trait
objects, vtables, dynamic dispatch, or bytecode-visible wrappers.

Built-in manifests live under `doc/slice4-behaviours/`:

| Behaviour | Scope |
|---|---|
| `request_server` | Generic request/reply shape, warning mode for raw code |
| `state_machine` | Explicit state progression shape |
| `postponing_state_machine` | Bounded postponement plus drain shape |
| `jetton_wallet` | Slice 3 Jetton wallet helper surface |
| `nft_item` | Slice 3 NFT item helper surface |
| `multisig` | Slice 3 multisig helper surface |

Validate manifests and conformance with:

```sh
python3 scripts/check-slice-4-behaviour-manifests.py
```

Generated project manifests now include `behaviour_conformance` entries:

```json
{
  "behaviour": "nft_item",
  "manifest": "doc/slice4-behaviours/nft_item.json",
  "mode": "generated"
}
```

`raw` mode emits warnings and exits successfully. `generated` mode uses
the manifest's declared mode and fails on missing required helpers,
messages, queue fields, or postponement paths.
