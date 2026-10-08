FROM busybox:1.36
# Build time: proves whether the image is built, and when.
RUN ["/bin/touch", "/tos-ci-probe-docker-build"]
# Run time: proves whether the action's container is started, and when.
ENTRYPOINT ["/bin/echo", "TOS_CI_PROBE_DOCKER_RUN"]
