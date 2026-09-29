# C09 binary handoff correction

The original `REVIEW-RECEIPT.md` named the mutable
`/home/tomi/nhm-c07c08-build/debug/health-edge` build output with SHA-256
`50d71ace513a24562001a57bc3f91faed081553476cd2e6884409bc7c7d53c51`.
The C09 supervisor's pre-deployment hash check found that this target file had
subsequently changed; no file was installed and no Edge or validator was
restarted. That path and hash are **withdrawn as a deployment artifact**. The
original receipt remains intact as historical test/build evidence.

Corrected controlled handoff:

- Source: clean detached worktree
  `/home/tomi/nhm-c09-epoch-candidate-c8bc0e10`, exact HEAD
  `c8bc0e10c6ff82ea7d765f5b350ab8bcd8f99a00`.
- Build: `CARGO_TARGET_DIR=/home/tomi/nhm-c09-epoch-build cargo build --locked -j2 -p tos-health-services --bin health-edge`, natural exit 0.
- Frozen copy: `/home/tomi/nhm-c09-epoch-frozen-c8bc0e10/health-edge`, mode
  `0555`, 120,441,792 bytes, SHA-256
  `1fab27ae7920e7ca2dddb8e7d4456bd4555c3486f4202eccc7bbfb3ae8762ddb`.
- Build output and frozen copy hashes matched after copying. The dedicated
  frozen path is not a Cargo output directory and must not be overwritten by
  subsequent builds.

Only the C09 supervisor may approve or perform the controlled Edge-only
replacement and six-node actual-source rerun. This correction does not claim
the six-node snapshot gate passed.
