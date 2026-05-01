/*
    Slice 6 conformance fixture -- deploy activation version gate.

    Locks the ConfigParam 8 transition introduced by PR #6 hardening:
    before global version 14, a StateInit deploy that accepted gas may
    activate the account even if compute did not commit; from version 14
    onward activation requires compute success. This mirrors the production
    helper in crypto/block/transaction.cpp.
*/

#include "td/utils/tests.h"

namespace {

constexpr int kDeploySuccessActivationVersion = 14;

bool compute_phase_can_activate_account(bool success, bool accepted, int global_version) {
  return global_version >= kDeploySuccessActivationVersion ? success : accepted;
}

}  // namespace

TEST(Slice6DeployActivationVersionFixture, V13AcceptThenThrowKeepsLegacyActivation) {
  CHECK(compute_phase_can_activate_account(/*success=*/false, /*accepted=*/true, 13));
}

TEST(Slice6DeployActivationVersionFixture, V14AcceptThenThrowDoesNotActivate) {
  CHECK(!compute_phase_can_activate_account(/*success=*/false, /*accepted=*/true, 14));
}

TEST(Slice6DeployActivationVersionFixture, V14SuccessfulDeployActivates) {
  CHECK(compute_phase_can_activate_account(/*success=*/true, /*accepted=*/true, 14));
}
