# tosdev3 signing identity

- Contributor name: `tosdev3`
- Affiliation: `community`
- Public signing key: [tosdev3.pub](tosdev3.pub)
- Ed25519 fingerprint: `SHA256:HQAHTRAKttx1Q9pCGsVpAOC6GX3Nxmrpivn0pxpc0gg`
- Key generated on 2026-09-22 on the contribution host, with no passphrase,
  because the contribution was driven non-interactively.
- Independence declaration: `false`. The contribution host is administered by
  the operator, execution was driven by an automated agent over an SSH
  session, and the key was generated on that host. No party outside the
  operator holds it.

This contribution ran on a different machine, from a different provider, than
contributions 1 and 2. That is the whole of what it adds: if one host's
generator or memory were compromised, another host's scalar may still be good,
and a phase-2 ceremony is sound if any single scalar was. It does not add an
independent participant, because independence is about who can compel or
observe the contributor, and that is unchanged.

As with [tosdev2](tosdev2.md), no public identity evidence is registered for
this key, so a reader cannot trace it to a person who can be asked.
`verify-attestations.py` now reports that absence on the contribution's line
and in a summary; it did not when this contribution was made, and the
attestation was signed saying so. See the correction in
[CONTRIBUTION-3.md](../CONTRIBUTION-3.md).

Only the public key is published. This record is not a contribution, an
attestation, or a claim that the ceremony's independent-participation
condition has been met. That condition remains unsatisfied.
