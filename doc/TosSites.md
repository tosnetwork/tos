# TOS Sites and RLDP HTTP Proxy

TOS Sites expose HTTP content through RLDP and ADNL rather than a traditional public TCP web origin.

## Main Tool

The operator and client entrypoint is:

- [rldp-http-proxy](/home/tomi/tos/build-clang21/rldp-http-proxy/rldp-http-proxy)

## Two Modes

- HTTP to RLDP: access a TOS site from a browser through a local proxy
- RLDP to HTTP: expose a local or remote HTTP service through TOS networking

## Client-Side Proxy

Example pattern:

```bash
cd /path/to/tos/build-clang21
./rldp-http-proxy/rldp-http-proxy \
  -p 8080 \
  -c 3333 \
  -C /path/to/tos-global.config.json \
  -D /path/to/proxy-db
```

This runs a local HTTP proxy endpoint and resolves site addresses through the TOS network.

## Service-Side Proxy

Example pattern:

```bash
./rldp-http-proxy/rldp-http-proxy \
  -a <public-ip>:3333 \
  -L <site-domain> \
  -C /path/to/tos-global.config.json \
  -D /path/to/proxy-db
```

## Important Flags

- `-C`: global config
- `-D`: local DB root
- `-p`: local HTTP listen port
- `-a`: ADNL listen address
- `-A`: explicit server ADNL address
- `-L`: local hostname mapping
- `-R`: remote hostname mapping
- `-P`: whether to proxy all HTTP traffic

## DNS Integration

TOS Sites depend on working DNS resolution when using named sites. Validate DNS first with:

- [lite-client](/home/tomi/tos/build-clang21/lite-client/lite-client)
- [toslib-cli](/home/tomi/tos/build-clang21/toslib/toslib-cli)

## Operational Notes

- Keep proxy DB and logs on persistent storage.
- Use explicit global config files per environment.
- Do not expose a site publicly until DNS, ADNL address, and backend mapping are all validated.

## Related Docs

- [DNS.md](/home/tomi/tos/doc/DNS.md)
- [LiteClient.md](/home/tomi/tos/doc/LiteClient.md)
