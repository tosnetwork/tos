# Local PQ deployment preparation

Topology: one DHT, four PQ validators, two non-validator full nodes and one
standalone lite-client process. Only the four validators belong to Config34.

| Role | Data directory | ADNL/QUIC | LiteServer | Console | JSON-RPC |
| --- | --- | --- | --- | --- | --- |
| DHT | `/data/testnet/node0` | 2001 | — | — | — |
| Validator 1–4 | `/data/testnet/node1` … `node4` | 2002/2005/2008/2011 | 2003/2006/2009/2012 | 2004/2007/2010/2013 | 8011–8014 |
| Observer 5 | `/data/testnet/node5` | 2014 | 2015 | 2016 | 8015 |
| Observer 6 | `/data/testnet/node6` | 2017 | 2018 | 2019 | 8016 |
| Lite-client | `/data/lite-client` | No listener | Queries 2015/2018 | — | — |

`local_pq_testnet.py plan` only writes a topology and service templates into
`/data/preparation`. `prepare-observers` creates independent observer identities
and configs against the retained Genesis without invoking native tools,
starting services, changing validator membership or sending transactions.
Observers have no PQ consensus seed or validator configuration. The installed
services must remain stopped during protocol review.

Runtime chain databases, archives, consensus journals and logs have been
removed. Existing keys, configs and Genesis are retained. The old pool deployment
and health receipts are removed: the reset chain has no deployed pool yet.

After protocol review, use the reviewed binaries for all nodes together. The
new service templates and lite-client wrapper still need installation; this
preparation does not install or start them. Check resources and free ports,
start the DHT/validators/observers, then verify a common full block ID and the
four-member PQ Config34. Re-deploy and verify the pool before starting the
standalone lite-client service.

For a completely new Genesis, `setup-testnet.sh --clean` creates all six full
nodes and the pool through the normal installation path. It is a deployment
command, not a preparation command. `setup-testnet.sh --plan-only` cannot build,
clean data or start a service.
