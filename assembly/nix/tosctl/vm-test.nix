{ pkgs, lib, tosctl, expectedCommit, expectedEpoch }:
let
  # A defective install for the sensitivity control: it runs the real binary and keeps its
  # exit status, then widens any file it was asked to --output to 0644.
  widening = pkgs.writeShellScript "tosctl" ''
    ${tosctl}/bin/tosctl "$@"
    status=$?
    previous=
    for argument in "$@"; do
      if [ "$previous" = --output ] && [ -f "$argument" ]; then chmod 0644 "$argument"; fi
      previous=$argument
    done
    exit "$status"
  '';
in
pkgs.testers.runNixOSTest {
  name = "tosctl-installation";
  nodes.machine = { ... }: {
    users.users.operator = { isNormalUser = true; };
    environment.systemPackages = [ pkgs.python3 ];
    # Make the built closure available offline, without installing it in PATH.
    virtualisation.additionalPaths = [ tosctl ];
    virtualisation.memorySize = 2048;
    virtualisation.cores = 2;
    nix.settings.substituters = lib.mkForce [ ];
    system.stateVersion = "26.05";
  };
  testScript = ''
    import ast
    import shlex

    # smoke.py must not depend on `assert`, which `python3 -O` removes.
    with open("${./smoke.py}") as source:
        tree = ast.parse(source.read())
    if any(isinstance(node, ast.Assert) for node in ast.walk(tree)):
        raise Exception("smoke.py contains an assert statement")

    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("grep '^ID=nixos$' /etc/os-release")
    machine.succeed("systemd-detect-virt --vm")

    def operator(command):
        return "su - operator -c " + shlex.quote(command)

    expected = "TOSCTL_EXPECTED_COMMIT=${expectedCommit} TOSCTL_EXPECTED_EPOCH=${toString expectedEpoch}"
    smoke = expected + " python3 ${./smoke.py}"
    optimized = expected + " python3 -O ${./smoke.py}"
    machine.fail(operator("command -v tosctl"))
    machine.succeed(operator("nix-env --install ${tosctl}"))
    machine.succeed(operator("test $(readlink -f $(command -v tosctl)) = ${tosctl}/bin/tosctl"))
    print(machine.succeed(operator(smoke)))
    print(machine.succeed(operator(optimized)))

    # The acceptance assertions must detect a defective install, not only an absent one.
    machine.succeed(operator("mkdir -p ~/widening && ln -sf ${widening} ~/widening/tosctl"))
    status, output = machine.execute(operator("PATH=~/widening:$PATH " + smoke + " 2>&1"))
    if status == 0 or "configuration mode is not 0600" not in output:
        raise Exception("defective install was not detected: " + output)
    print("PASS: defective-install sensitivity control")

    # The same acceptance runner must fail if the package is not installed.
    machine.succeed(operator("nix-env --uninstall tosctl"))
    # The driver returns stdout; Python reports the expected refusal on stderr.
    status, output = machine.execute(operator(smoke + " 2>&1"))
    if status == 0 or "tosctl is not installed" not in output:
        raise Exception("absent package was not detected: " + output)
    print("PASS: package-removal sensitivity control")
    machine.succeed(operator("nix-env --install ${tosctl}"))
    print(machine.succeed(operator(smoke)))
    machine.shutdown()
  '';
}
