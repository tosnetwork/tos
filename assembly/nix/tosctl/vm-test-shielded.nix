{ pkgs, lib, tosctl-shielded, material, expectedCommit, expectedEpoch }:
let
  torClient = import ./tor-client.nix { };
  # A defective install for the sensitivity control: the real program whose shipped material
  # is a tampered copy the operator's home holds. It defaults the variable the way the real
  # wrapper does, so an operator's own value (set or empty) still wins and every check up to
  # the positive audit behaves as on a sound install; the audit under the default alone is
  # what must refuse the copy, on the proving-key check.
  tampering = pkgs.writeShellScript "tosctl" ''
    export TOSCTL_SHIELD_CEREMONY_DIR="''${TOSCTL_SHIELD_CEREMONY_DIR-$HOME/tampered/ceremony}"
    exec ${tosctl-shielded}/bin/tosctl "$@"
  '';
  socks = torClient.services.tor.client.socksListenAddress;
in
# The Tor client module is the one an installation imports; what the VM boots is held to
# the properties the relayed spend relies on before the VM exists.
assert socks.addr == "127.0.0.1" && socks.port == 9050;
assert socks.OnionTrafficOnly && socks.IsolateSOCKSAuth;
assert torClient.services.tor.settings.ClientOnly && torClient.services.tor.settings.SafeSocks;
assert torClient.services.tor.settings.ControlPort == [ ];
pkgs.testers.runNixOSTest {
  name = "tosctl-shielded-installation";
  nodes.machine = { config, ... }: {
    imports = [ ./tor-client.nix ];
    users.users.operator = { isNormalUser = true; };
    environment.systemPackages = [ pkgs.python3 pkgs.iproute2 ];
    # Make the built closure and its material available offline, without installing it.
    virtualisation.additionalPaths = [ tosctl-shielded material ];
    # The ceremony audit peaks near 150 MiB of resident memory and the runner holds it under
    # 2 GiB; the guest has room for a regression to show as a measured figure, not an OOM
    # panic (the test kernel panics on OOM).
    virtualisation.memorySize = 4096;
    virtualisation.cores = 2;
    # No egress by configuration: no test VLAN, and the harness link restricted from the
    # host's network. Nothing in the test needs a network; Tor never bootstraps.
    virtualisation.vlans = [ ];
    virtualisation.restrictNetwork = true;
    nix.settings.substituters = lib.mkForce [ ];
    system.stateVersion = "26.05";
  };
  testScript = { nodes, ... }:
    assert nodes.machine.virtualisation.vlans == [ ];
    assert nodes.machine.virtualisation.restrictNetwork;
    assert nodes.machine.services.tor.enable && nodes.machine.services.tor.client.enable;
    ''
      import ast
      import shlex

      # Neither runner may depend on `assert`, which `python3 -O` removes.
      for script in ["${./smoke.py}", "${./smoke-shielded.py}"]:
          with open(script) as source:
              tree = ast.parse(source.read())
          if any(isinstance(node, ast.Assert) for node in ast.walk(tree)):
              raise Exception(script + " contains an assert statement")

      machine.start()
      machine.wait_for_unit("multi-user.target")
      machine.succeed("grep '^ID=nixos$' /etc/os-release")
      machine.succeed("systemd-detect-virt --vm")
      machine.wait_for_unit("tor.service")
      machine.wait_for_open_port(9050)

      def operator(command):
          return "su - operator -c " + shlex.quote(command)

      expected = "TOSCTL_EXPECTED_COMMIT=${expectedCommit} TOSCTL_EXPECTED_EPOCH=${toString expectedEpoch}"
      standard = expected + " python3 ${./smoke.py}"
      shielded = "TOSCTL_SHIELD_MATERIAL=${material} python3 ${./smoke-shielded.py}"
      optimized = "TOSCTL_SHIELD_MATERIAL=${material} TOSCTL_SHIELD_SMOKE_FAST=1 python3 -O ${./smoke-shielded.py}"
      machine.fail(operator("command -v tosctl"))
      machine.succeed(operator("nix-env --install ${tosctl-shielded}"))
      machine.succeed(operator("test $(readlink -f $(command -v tosctl)) = ${tosctl-shielded}/bin/tosctl"))
      # The standard acceptance holds for the shielded program too.
      print(machine.succeed(operator(standard)))
      print(machine.succeed(operator(shielded)))
      print(machine.succeed(operator(optimized)))

      # The acceptance assertions must detect an installation whose material is wrong, not
      # only an absent one: the tampered copy is the one the shielded runner itself makes.
      machine.succeed(operator(
          "mkdir -p ~/tampered && cp -r ${material}/ceremony ~/tampered/ && chmod -R u+w ~/tampered"
          " && printf '\\001' | dd of=~/tampered/ceremony/key.bin bs=1 seek=100 count=1 conv=notrunc status=none"
      ))
      machine.succeed(operator("mkdir -p ~/tampering && ln -sf ${tampering} ~/tampering/tosctl"))
      status, output = machine.execute(operator("PATH=~/tampering:$PATH " + shielded + " 2>&1"))
      if status == 0 or "the proving key" not in output:
          raise Exception("tampered material was not detected: " + output)
      print("PASS: tampered-material sensitivity control")

      # The same runner must fail if the package is not installed.
      machine.succeed(operator("nix-env --uninstall tosctl-shielded"))
      status, output = machine.execute(operator(shielded + " 2>&1"))
      if status == 0 or "tosctl is not installed" not in output:
          raise Exception("absent package was not detected: " + output)
      print("PASS: package-removal sensitivity control")
      machine.succeed(operator("nix-env --install ${tosctl-shielded}"))
      print(machine.succeed(operator("TOSCTL_SHIELD_SMOKE_FAST=1 " + shielded)))
      machine.shutdown()
    '';
}
