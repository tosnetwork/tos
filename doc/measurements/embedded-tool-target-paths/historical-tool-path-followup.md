# Frozen-contract tool-path discovery: coordinator finding

The build report already records the failed unqualified attempt and subsequent
completion with explicit tool and standard-library environment paths. This note
records the coordinator's attribution without replacing those observations.

The build scripts default FUNC_BIN to `$REPO_ROOT/build/crypto/func` and FIFT_BIN
to `$REPO_ROOT/build/crypto/fift`. That default is valid only when the build tools
are available at `<repo>/build`; a symlink there can make a different physical
build directory appear to satisfy the assumption. B's pre-existing build symlink
had concealed this dependency. The fresh independent source and build directories
exposed it. This was not introduced by the merged source changes or the earlier
coordinator CMake invocation.

The existing FUNC_BIN/FIFT_BIN overrides were used to finish the default-all
build. No source change, substitute symlink or merge commit was introduced.
The initial failure remains a distinct result; successful completion with explicit
paths does not establish that the default discovery is correct.

The coordinator-designated repair is for CMake to pass `$<TARGET_FILE:func>`
and the corresponding fift target path to the scripts, rather than relying on
source-directory-relative defaults. That is a separate build-system change,
outside M1 and outside this merge measurement. It is recorded here, not implemented.
