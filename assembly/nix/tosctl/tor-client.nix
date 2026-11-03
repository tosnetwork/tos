# The Tor client a `tosctl shield` relayed spend speaks to: a dedicated daemon,
# client only, SOCKS on loopback with per-session isolation and onion traffic
# only, no control port. Import this file into a NixOS configuration as it is;
# the installation acceptance test boots exactly this file. The flags are the
# ones `tools/bonded-relayer/tor/client.torrc.example` documents.
{ ... }:
{
  services.tor = {
    enable = true;
    client = {
      enable = true;
      socksListenAddress = {
        addr = "127.0.0.1";
        port = 9050;
        IsolateSOCKSAuth = true;
        OnionTrafficOnly = true;
      };
    };
    settings = {
      ClientOnly = true;
      SafeSocks = true;
      SafeLogging = true;
      ControlPort = [ ];
      SocksPolicy = [
        "accept 127.0.0.1"
        "reject *"
      ];
    };
  };
}
