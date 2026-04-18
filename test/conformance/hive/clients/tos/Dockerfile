# Hive expects each client to live under clients/<name>/Dockerfile. We re-use
# the canonical Dockerfile two levels up; the build context that hive passes
# is this directory, so we COPY the parent tree in.
#
# In practice, hive's docker-build invocation is:
#   docker build clients/tos/
# which does NOT include the workchain source tree. There are two ways to
# resolve this:
#
#   (a) Run hive with `--docker.buildargs CONTEXT=../../..` and use a wrapper
#       Dockerfile (TODO).
#   (b) Pre-build a runtime image locally with the canonical Dockerfile and
#       reference it here via FROM, skipping hive's build entirely.
#
# We use approach (b) for the Phase G.3 scaffold because it keeps hive's
# wiring small and the canonical Dockerfile single-source-of-truth.
FROM tos/validator-hive:latest

# Hive will COPY a genesis.json into /genesis.json at runtime; tos.cmd reads it.
# Nothing else to do here — the parent image already wires ENTRYPOINT.
