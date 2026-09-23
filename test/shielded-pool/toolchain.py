"""Where the mutation batteries find a built FunC/Fift toolchain.

`TOS_ROOT` locates only the *built* compiler, the Fift assembler and its
standard library. The sources under mutation come from this tree, through the
crate manifest, and the two are usually the same directory.

They are not the same directory when a battery runs from a git worktree: a
worktree has every source and no build of its own, and a Fift assembler
without this branch's Poseidon2 opcodes fails every suite at baseline with
`POSEIDON2_HASH7:-?` -- which looks like a broken contract and is not one.

The batteries used to answer this two different ways, neither right. Some
pointed at the checkout they were run from, which has no build in a worktree;
the rest hardcoded a path under the current user's home, which is wrong for
anyone whose checkout is elsewhere. This finds the build.
"""

from pathlib import Path
import subprocess


def toolchain_root(root: Path) -> Path:
    """The checkout whose `build/` holds func, fift and the Fift stdlib.

    `root` is the tree the caller is mutating. Its own build is preferred; a
    worktree falls back to the main checkout it was created from.
    """
    if (root / 'build/crypto/func').exists():
        return root
    common = subprocess.run(
        ['git', 'rev-parse', '--path-format=absolute', '--git-common-dir'],
        cwd=root, capture_output=True, text=True, check=False)
    if common.returncode == 0:
        main = Path(common.stdout.strip()).parent
        if (main / 'build/crypto/func').exists():
            return main
    raise SystemExit(
        f'no built toolchain: neither {root}/build/crypto/func nor the main '
        "checkout's exists. Build it, or set TOS_ROOT to a checkout that has one.")
