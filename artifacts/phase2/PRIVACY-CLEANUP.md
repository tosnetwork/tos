# Publication privacy cleanup

This cleanup changes packaging and publication metadata, not the ceremony.

- Local checkout paths were removed from the two published review documents,
  including their versions in the 16 commits after the review baseline.
- Those commits now use the publishing account's GitHub noreply email.
- Both ceremony tags point to the corresponding sanitized commits.
- The contribution download was repacked with UID/GID and timestamps set to
  zero, generic owner names, and no extended attributes. All 16 file payloads
  are byte-for-byte identical to the previous download.
- The original announcement, contribution parameters, register, attestation
  and attestation signature remain unchanged.

[PRIVACY-PROVENANCE.json](PRIVACY-PROVENANCE.json) maps original commit IDs to
the sanitized commits. Its [SSH signature](PRIVACY-PROVENANCE.json.sig) is made
with tosman's registered signing key, in namespace `file`. This supplements
the original signed attestation without changing its bytes or pretending that
the contribution was generated from a different source revision.

Clean archive SHA-256:
`1af43216e0231c36c94eb8bc037a68ec1218a7ab7568b49ea54dd491f51d981b`.
The original release publication timestamp is retained. Replacing an archive
changes its asset upload timestamp and digest; the latest publication receipt
records those values. Historical receipts describe the asset then available.

This is scoped to the review and ceremony publication in this session. It does
not rewrite earlier repository history or unrelated branches. Hosting caches,
unreachable Git objects, forks and previously downloaded copies are not erased
by a force-push or asset replacement. Removing server-retained historical
objects may require GitHub support; no such purge is claimed here.

After this cleanup, an authenticated GitHub API check still retrieved an old
commit by its original ID. The live branch and ceremony tags point to the
sanitized history, but old server objects are not yet purged. GitHub decides
whether a support removal request qualifies; this cleanup does not promise
that it will remove already-public metadata.
