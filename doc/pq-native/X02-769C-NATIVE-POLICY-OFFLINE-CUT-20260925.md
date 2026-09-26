# X02 native-file policy and post-RPC offline cut (2026-09-25)

Fixed implementation commit: `769c3c04fe000cfaa07951ca5d47ca5e0431845b`.
Earlier native-byte foundation: `747f515881e624d08b6d0ce53dc9a1e39ec859a0`.

Stage A experiment readiness now records the particular LogStreamer object's
input pipe FD and output log FD, with the child stderr pipe and output file
device/inode checked while alive. `x02_prepare_policy.py` freezes the four
readiness entries, source files, validator executable, distinct DB/log
inodes, exact UDP peer ports, and ten directed bidirectional `tc flower` rules
into an exclusive-create policy file. It refuses a dirty tracked tree or a
readiness/source-commit mismatch. The X02 verifier requires that native-file
policy and rechecks the recorded FD pair; merely finding any pipe and any log
FD in the same harness is insufficient.

Each native snapshot now retains separate pre-RPC and post-RPC raw byte
segments. Verification joins prior post → current pre → current post with
exact offsets and prefix SHA, requires the two segment reads on the correct
sides of the RPC calls, and checks native marker UTC time against the paired
host wall/monotonic clocks. A pre-cut marker read after the cut remains a
pre-cut event. This first directed-isolation slice rejects validator restart
or same-inode log truncation rather than inventing a new file generation.

On the committed tree, X02 unittest discovery passed 53/53 (exit 0), retained
raw `test/integration/.x02-offline-858a03471-20260925/769c-x02-unittest.typescript`
SHA-256 `1ae7fc410d686886d69d5bc5e9dfb6a92ab729aa9f1c7fc73070a627c875c431`.
Stage A experiment pytest passed 39/39 (exit 0), retained raw
`test/integration/.x02-offline-858a03471-20260925/769c-stage-a-pytest.typescript`
SHA-256 `40161c15bc686138fefdaf55366491c2c0cc7eee98e346bdecd136c330c3a46b`.
`py_compile`, branch Python source guard, and `git diff --check` passed.
The local controls include missing/replayed/early post-RPC segment, a real
subprocess pipe→writer FD pair, swapped input/output FD, swapped readiness
mapping, duplicate DB inode, and pre-cut marker read after the cut.

Source SHA-256: recorder `a21f102ea330d64637ea1b18902274dad1caa726c288be9f11b7c54d31416964`;
policy producer `a10fb2eb595ab0e32d69ed075a0ef8c4966df949335b43e65000d8f95d62e257`;
Stage A `8ac9bb67627d2fb5f798fd7c74665bf408b98e838d27da07c2235f074a058666`;
LogStreamer `ad1a6d628336fb5efa3b26642cb6596a854decd48f690637bdea2c3b2289675a`;
network wrapper `157f82028a9cf226825e8b8534419730b04d5ea3e5c7e95254928b7d044b46`.

This is **offline integration only**. No four-validator Stage A readiness was
created on this commit, no policy was frozen from four real validator PIDs,
and no `tc` command or network fault was run. An independent source/raw review
and a serial exact-tree four-validator policy freeze and 100% directed cut
with both-direction hit/drop counters, OS socket/PID evidence, full per-height
IDs and finality timing are still required. Partial packet loss is separate.
X02 remains OPEN.
