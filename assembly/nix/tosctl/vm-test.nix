{ pkgs, lib, tosctl }:
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
    import shlex

    machine.start()
    machine.wait_for_unit("multi-user.target")
    machine.succeed("grep '^ID=nixos$' /etc/os-release")
    machine.succeed("systemd-detect-virt --vm")

    def operator(command):
        return "su - operator -c " + shlex.quote(command)

    smoke = "python3 ${./smoke.py}"
    machine.fail(operator("command -v tosctl"))
    machine.succeed(operator("nix-env --install ${tosctl}"))
    machine.succeed(operator("test $(readlink -f $(command -v tosctl)) = ${tosctl}/bin/tosctl"))
    machine.succeed(operator(smoke))

    # The same acceptance runner must fail if the package is not installed.
    machine.succeed(operator("nix-env --uninstall tosctl"))
    status, output = machine.execute(operator(smoke))
    assert status != 0 and "tosctl is not installed" in output, output
    print("PASS: package-removal sensitivity control")
    machine.succeed(operator("nix-env --install ${tosctl}"))
    machine.succeed(operator(smoke))
    machine.shutdown()
  '';
}
