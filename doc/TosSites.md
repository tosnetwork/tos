# TOS Sites and RLDP HTTP Proxy

TOS Sites expose HTTP content through RLDP and ADNL rather than a traditional public TCP web origin.

In the AI Actor Model, TOS Sites can host service metadata, agent manifests, tool endpoints, model-service documentation, and verifier evidence bundles. Contracts should reference hashes or authenticated metadata rather than treating site content as trusted chain state.

## Main Tool

The operator and client entrypoint is:

- [rldp-http-proxy](../rldp-http-proxy)

## Two Modes

- HTTP to RLDP: access a TOS site from a browser through a local proxy
- RLDP to HTTP: expose a local or remote HTTP service through TOS networking

## Client-Side Proxy

Example pattern:

```bash
cd build
./rldp-http-proxy/rldp-http-proxy \
  -p 8080 \
  -c 3333 \
  -C /data/tos-global.json \
  -D ./proxy-db
```

This runs a local HTTP proxy endpoint and resolves site addresses through the TOS network.

## Service-Side Proxy

Example pattern:

```bash
./rldp-http-proxy/rldp-http-proxy \
  -a <public-ip>:3333 \
  -L <site-domain> \
  -C /data/tos-global.json \
  -D ./proxy-db
```

## Important Flags

- `-C`: global config
- `-D`: local DB root
- `-p`: HTTP listen address: `<port>` listens on `127.0.0.1` only;
  `<ipv4>:<port>` or `[<ipv6>]:<port>` listens on that address
- `-a`: ADNL address to advertise; its UDP port is bound on all interfaces
- `-A`: explicit server ADNL address
- `-L`: local hostname mapping
- `-R`: remote hostname mapping
- `-P`: whether to proxy all HTTP traffic
- `--forward-timeout`: total seconds a request forwarded to a local HTTP
  server may take, response included (default 60). It is a total, not an idle
  limit: a response still streaming when it passes is cut off. Concurrent
  forwards are capped (1000 per remote); more are answered 503. Values above
  3600 are refused.
- `--max-tunnels`, `--max-tunnels-per-peer`: how many CONNECT tunnels a
  service-side proxy keeps open at once, from all peers together (default 512)
  and from one ADNL peer (default 16). Each tunnel holds a TCP connection to
  the backend; a CONNECT beyond either limit is answered 503 and opens nothing.
  The per-peer limit bounds one client, not a peer that creates many ADNL
  identities; the global limit bounds that.
- `--tunnel-idle-timeout`: seconds a tunnel may pass without moving a byte in
  either direction before it is closed (default 600, at most 604800).
- `--tunnel-max-lifetime`: seconds after which a tunnel is closed however busy
  it is (default 86400, at most 2592000), so every tunnel's connection is
  eventually reclaimed.

`-p 8080` used to listen on every interface; it now listens on `127.0.0.1`
only. A proxy that other hosts should reach must name the address, for
example `-p 0.0.0.0:8080`, which opens the proxy to every host that can
reach that port. This does not change ADNL: the UDP ports given by `-a` and
`-c` are still bound on all interfaces.

The generic forwarding proxy `http-proxy` reads `-p` the same way: a bare
port listens on `127.0.0.1` only. It forwards to any host a client names, so
listening on another address (for example `-p 0.0.0.0:8080`) makes it an open
proxy for every host that can reach that port; do that only behind a firewall
that admits the intended clients.

## DNS Integration

TOS Sites depend on working DNS resolution when using named sites. Validate DNS first with:

- [lite-client](../lite-client)
- [toslib-cli](../toslib)

## Operational Notes

- Keep proxy DB and logs on persistent storage.
- Use explicit global config files per environment.
- Do not expose a site publicly until DNS, ADNL address, and backend mapping are all validated.

## Related Docs

- [DNS.md](DNS.md)
- [LiteClient.md](LiteClient.md)
- [ai-actors.md](https://github.com/tosnetwork/doc/blob/main/tos-blockchain/ai-actors.md)
