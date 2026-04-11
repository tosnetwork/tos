# TOS DNS

TOS DNS maps human-readable names to on-chain or network-level targets such as smart contracts, service endpoints, and resolver chains.

## Core Concepts

- Names are resolved through DNS smart contracts.
- Resolution starts from the root resolver address published in chain config.
- A lookup can return either a final record or a redirect to another resolver.

The root resolver address is typically published in `ConfigParam 4`.

## Useful Tools

- [lite-client](../build/lite-client/lite-client)
- [toslib-cli](../build/toslib/toslib-cli)
- [rldp-http-proxy](../build/rldp-http-proxy/rldp-http-proxy)

## Inspecting DNS Data with Lite Client

Start the lite client:

```bash
cd build
./lite-client/lite-client -C /data/tos-global.json
```

Example commands:

```text
getconfig 4
dnsresolve <domain> 1
dnsresolve <domain> -1
```

Use category-specific lookups when you know the record type you need. Use category `-1` when you want resolver chaining information.

## Inspecting DNS Data with Toslib CLI

`toslib-cli` is useful when you want a higher-level operator workflow:

```bash
cd build
./toslib/toslib-cli
```

Typical flow:

```text
dns resolve root <domain> 1
```

## Resolver Chaining

A resolution path may be partial:

- the current resolver knows a prefix
- it returns a "next resolver" record
- the client continues against that resolver

This is normal. Do not assume every name resolves in one step.

## Operational Guidance

- Always verify DNS data against a recent global config.
- Treat DNS records as on-chain state, not local configuration.
- If a name fails to resolve, check:
  - root config
  - category
  - resolver chaining
  - network reachability

## Related Docs

- [LiteClient.md](LiteClient.md)
- [TosSites.md](TosSites.md)
- [ConfigParam.md](ConfigParam.md)
