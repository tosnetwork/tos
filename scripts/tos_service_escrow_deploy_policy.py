"""Which stablecoin escrow code the repository's tooling is willing to deploy.

Kept free of third-party imports so the policy can be checked without a node,
a wallet, or the test framework installed.

Only code whose hash is listed in a supported release manifest below is
deployed; any other code, including every earlier escrow version, is refused
as unknown.

Escrow v2 is deployable for non-production use only. A payout the
recipient's jetton wallet refuses is returned to the escrow's own wallet
without telling the escrow, which then stays release_pending or
refund_pending with the funds stranded; with the issuer's unchanged jetton
wallet the escrow cannot tell a refused payout from a delivered one whose
acknowledgment was lost. This is an accepted risk for this version, not a
fixed one. Production support needs a new integration in which the token's
wallet delivers authenticated, request-specific, replay-safe outcomes of
each payout to the escrow. See crypto/smartcont/STABLECOIN-ESCROW.md.
"""

import json
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

NON_PRODUCTION_FLAG = "--non-production-test-deployment"

# Release manifests of escrow versions the tooling can deploy, each with the
# deployment restriction that applies to it. The code hash is read from the
# manifest rather than copied here, so a rebuilt release is followed.
SUPPORTED_ESCROW_RELEASES = {
    "crypto/smartcont/tos-service-stablecoin-escrow-v2.release.json": {
        "production": False,
        "reason": (
            "escrow v2 with the issuer's unchanged jetton wallet is an accepted risk for this "
            "version: a payout the recipient's wallet refuses leaves the funds stranded in "
            "the escrow's own wallet with the escrow pending, and no operation recovers them. "
            "Production use needs a wallet integration that reports authenticated, "
            "request-specific, replay-safe payout outcomes to the escrow"
        ),
    },
}


class DeploymentRefused(RuntimeError):
    """The escrow code may not be deployed by supported tooling."""


def normalize_code_hash(code_hash: str) -> str:
    value = code_hash.strip().lower()
    if not value.startswith("tvm-cell-sha256:"):
        value = "tvm-cell-sha256:" + value
    digest = value.split(":", 1)[1]
    if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
        raise DeploymentRefused(f"malformed escrow code hash {code_hash!r}")
    return value


def supported_release(code_hash: str, repo: Path = REPO):
    """The manifest and policy entry of the supported release with this code hash."""
    for manifest_path, policy in SUPPORTED_ESCROW_RELEASES.items():
        manifest = json.loads((repo / manifest_path).read_text())
        if normalize_code_hash(manifest["code_hash"]) == code_hash:
            return manifest, policy
    return None, None


def check_escrow_deployment(code_hash: str, *, non_production: bool, repo: Path = REPO) -> dict:
    """Refuses the deployment unless the code is a supported release and the
    caller has acknowledged any restriction on it. Returns the release
    manifest of the code being deployed."""
    code_hash = normalize_code_hash(code_hash)
    manifest, policy = supported_release(code_hash, repo)
    if manifest is None:
        raise DeploymentRefused(
            f"refusing to deploy {code_hash}: it is not the code of a supported escrow release"
        )
    if manifest.get("status") in {"deprecated", "retired"}:
        raise DeploymentRefused(
            f"refusing to deploy {code_hash}: release {manifest['protocol']} is "
            f"{manifest['status']}"
        )
    if not policy["production"] and not non_production:
        raise DeploymentRefused(
            f"refusing a production deployment of {manifest['protocol']}: {policy['reason']}. "
            f"Pass {NON_PRODUCTION_FLAG} to deploy it on a local or test network with test "
            "assets only"
        )
    return manifest
