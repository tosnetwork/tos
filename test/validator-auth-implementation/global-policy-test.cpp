// A zero-identity policy operation, and what it must leave behind.
//
// Operation 4 names no identity, so no identity's keys authorize it and no
// identity record is replaced. Three things move together instead: the policy
// enters the schedule, the activation that binds it is written, and the
// zero-identity record that holds the global admin nonce advances. A run that
// produced any two of them would leave the registry describing a policy nothing
// activates, or an activation for a policy that is not there.
//
// The activation's checkpoint is the case that matters most. Four nonzero
// hashes in the right fields prove nothing on their own: what has to hold is
// that they are the anchor of the governing snapshot that admitted this
// operation. So the authority hands the anchor back, and the mutation that
// stamps a different but perfectly legal anchor has to be caught.
#include <iostream>
#include <stdexcept>
#include <string>

#include "validator/auth/state.h"

#include "native-fixture.h"

using namespace tos::auth;
using namespace p0_fixture;

namespace {
unsigned passed = 0, failed = 0;

void report(bool condition, const std::string& name) {
  if (condition) {
    ++passed;
    std::cout << "CASE_PASS " << name << '\n';
  } else {
    ++failed;
    std::cout << "CASE_FAIL " << name << '\n';
  }
}

// The anchor the governing snapshot was derived from, as this fixture's
// authority reports it. A case that wants a different one changes this, which
// is the only way to change it: the application reads it from the authority.
constexpr std::uint32_t governing_seqno = 3;

Anchor governing_anchor(unsigned variant = 0) {
  return Anchor{variant == 1 ? governing_seqno + 1 : governing_seqno, h(7001 + variant), h(7101 + variant),
                h(7201 + variant)};
}

class GlobalAuthority final : public LifecycleAuthority {
  unsigned variant_;

 public:
  explicit GlobalAuthority(unsigned variant = 0) : variant_(variant) {
  }
  Result<bool> owner(const OwnerAuth&, const Update&, const Identity&) const override {
    return true;
  }
  Result<bool> possession(const PossessionAuth&, const Update&, const Key&) const override {
    return true;
  }
  Result<bool> administration(const IdentityAuth&, const Update&, const Identity&, std::uint32_t) const override {
    return true;
  }
  // The quorum itself is proven by the governance suite against a real
  // certificate. What this fixture controls is the one thing the application
  // decides: which anchor the activation is stamped with.
  Result<Anchor> governance(const Update&, const Authorizations&, const CurrentRegistry&,
                            std::uint32_t) const override {
    if (variant_ == 2)
      return Error{"fixture-governance-refused"};
    return governing_anchor(variant_);
  }
};

Policy successor(const RegistryState& before, std::uint32_t effective_from, unsigned variant = 0) {
  auto policy = value(before.policy_at(0), "fixture-current-policy");
  policy.revision_ = variant == 3 ? policy.revision_ : policy.revision_ + 1;
  policy.previous_ = variant == 4 ? Hash{} : before.current_policy();
  policy.effective_from_ = effective_from;
  return policy;
}

Update policy_update(const RegistryState& before, const Policy& next, std::uint64_t nonce = 0, unsigned variant = 0) {
  Update u;
  u.operation_ = 4;
  u.identity_ = Hash{};
  u.nonce_ = nonce;
  u.previous_ = variant == 5 ? h(999) : before.current_policy();
  u.effective_from_ = variant == 6 ? next.effective_from_ + 1 : next.effective_from_;
  u.new_policy_ = value(encode(next), "fixture-policy-bytes");
  return u;
}
}  // namespace

int main() {
  try {
    static const char* const manifest[] = {
        "global-policy-installs-policy-and-activation-atomically",
        "global-policy-checkpoint-is-governing-anchor",
        "global-policy-zero-nonce-advances",
        "global-policy-old-policy-cas-refused",
        "global-policy-wrong-effective-height-refused",
        "global-policy-activation-chain-revision-refused",
        "global-policy-refusal-changes-no-registry-byte",
        "global-policy-configuration-operation-refused",
    };
    for (const auto* name : manifest)
      std::cout << "MANIFEST " << name << '\n';

    const auto before = p0_fixture::state(3);
    const std::uint32_t inclusion = 1, effective = 64;
    const auto next_policy = successor(before, effective);
    const auto policy_id = value(object_id("policy", next_policy), "fixture-policy-id");
    const auto accepted = [&](const Update& u, unsigned variant = 0) {
      GlobalAuthority authority(variant);
      return before.apply_block(inclusion, {{u, {}}}, authority);
    };

    // The three effects, taken together, read out of the successor state rather
    // than out of what the apply returned: what is being tested is what the
    // registry now holds.
    auto installed = accepted(policy_update(before, next_policy));
    {
      bool complete = installed.ok();
      const Activation* activation = nullptr;
      if (complete) {
        const auto& after = installed.value();
        auto policy = after.policies().find(policy_id);
        auto found = after.activations().find(effective);
        auto global = after.identities().find(Hash{});
        activation = found == after.activations().end() ? nullptr : &found->second;
        complete = policy != after.policies().end() && policy->second == next_policy && activation != nullptr &&
                   activation->next_policy_ == policy_id && activation->effective_from_ == effective &&
                   activation->revision_ == 1 && activation->previous_ == Hash{} &&
                   global != after.identities().end() && global->second.active_.empty() &&
                   global->second.pending_.empty() && after.revision() == before.revision() + 1;
      }
      report(complete, "global-policy-installs-policy-and-activation-atomically");

      // Four nonzero hashes in the right fields are not the property. The
      // property is that they are the anchor of the snapshot that authorized
      // this operation, which is why the authority returns it and nothing here
      // is free to choose another.
      const auto expected = governing_anchor();
      report(activation != nullptr && activation->checkpoint_seqno_ == expected.seqno_ &&
                 activation->checkpoint_root_ == expected.root_ && activation->checkpoint_file_ == expected.file_ &&
                 activation->checkpoint_state_ == expected.state_,
             "global-policy-checkpoint-is-governing-anchor");

      auto global = installed.ok() ? installed.value().identities().find(Hash{}) : before.identities().end();
      report(installed.ok() && global != installed.value().identities().end() && global->second.next_nonce_ == 1,
             "global-policy-zero-nonce-advances");
    }

    // The compare-and-swap for a global operation is the current policy. A
    // request naming another one was authorized against a registry this is not.
    {
      auto refused = accepted(policy_update(before, next_policy, 0, 5));
      report(!refused.ok() && refused.error().code == "global-predecessor",
             "global-policy-old-policy-cas-refused");
    }

    // The operation's height and the policy's are one fact. Two would let an
    // activation be written for a coordinate the policy does not claim.
    {
      auto refused = accepted(policy_update(before, next_policy, 0, 6));
      report(!refused.ok() && refused.error().code == "global-effective-coordinate",
             "global-policy-wrong-effective-height-refused");
    }

    // Policies form a linked chain with consecutive revisions. A successor that
    // repeats its predecessor's revision is not a successor.
    {
      auto stale = successor(before, effective, 3);
      auto refused = accepted(policy_update(before, stale));
      report(!refused.ok() && refused.error().code == "global-policy-revision",
             "global-policy-activation-chain-revision-refused");
    }

    // A refused global operation leaves every byte where it was. The registry
    // is rebuilt from the parent for each attempt, so this is about the whole
    // encoding rather than about the three maps the operation touches.
    {
      const auto original = value(before.encode_cell(), "fixture-original-root");
      auto refused = accepted(policy_update(before, next_policy), 2);
      const auto again = value(before.encode_cell(), "fixture-original-root-again");
      report(!refused.ok() && refused.error().code == "fixture-governance-refused" &&
                 original->get_hash() == again->get_hash(),
             "global-policy-refusal-changes-no-registry-byte");
    }

    // Operation 6 has the same authority and is not applied. Installing a
    // configuration parameter additionally requires the normal configuration
    // vote, and nothing carries this authorization to the block where that vote
    // completes; accepting it on the quorum alone would decide that rule here.
    {
      auto u = policy_update(before, next_policy);
      u.operation_ = 6;
      auto refused = accepted(u);
      report(!refused.ok() && refused.error().code == "global-configuration-unimplemented",
             "global-policy-configuration-operation-refused");
    }

    std::cout << "SUMMARY cases=" << passed + failed << " passed=" << passed << '\n';
    return failed ? 1 : 0;
  } catch (const std::exception& error) {
    std::cerr << "HARNESS_FAILURE " << error.what() << '\n';
    return 2;
  }
}
