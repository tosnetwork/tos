#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <utility>

#include "native-history.h"

namespace tos::auth {

struct NativeHeadCandidate {
  Bytes block;
  td::Ref<vm::Cell> resulting_state;
};

// The configured zero state is the one finalized head that needs no signature
// set: its root/file coordinates are operator configuration already bound into
// ChainContext. It is a separate type so a caller cannot accidentally label an
// ordinary applied block as this exception.
struct NativeGenesisHeadCandidate {
  tos::BlockIdExt block;
  td::Ref<vm::Cell> resulting_state;
};

struct NativeHeadObservation {
  // The configured zero state, and only the configured zero state. Used before
  // a first signed masterchain block exists.
  std::optional<NativeGenesisHeadCandidate> configured_genesis;
  // Candidate backed by this node's finality-verification pipeline.
  std::optional<NativeHeadCandidate> finality_candidate;
  // Diagnostic/local tip only. The establisher must never substitute it when
  // finality_candidate is absent.
  std::optional<NativeHeadCandidate> latest_candidate;
  // Untrusted peer claim. Presence is an explicit refusal, not an ignored hint.
  std::optional<Anchor> peer_claim;
};

enum class NativeSignatureSetKind : std::uint8_t {
  final = 1,
  approval = 2,
};

struct NativeFinalityVerification {
  tos::BlockIdExt block;
  NativeSignatureSetKind kind{NativeSignatureSetKind::approval};
  tos::CatchainSeqno catchain{};
  std::uint32_t validator_set_hash{};
  tos::ValidatorWeight signed_weight{};
  tos::ValidatorWeight total_weight{};
};

// Actor adapters implement this seam using the node's own archive/finality
// pipeline. verify_signatures() must select the validator set for the exact
// block's catchain and run the node's native signature-set verifier. Returning
// approval means the signature set is valid only as approval evidence.
class NativeFinalizedHeadSource {
 public:
  virtual ~NativeFinalizedHeadSource() = default;
  virtual Result<NativeHeadObservation> observe() const = 0;
  virtual Result<NativeFinalityVerification> verify_signatures(
      const tos::BlockIdExt&) const = 0;
};

// Read-only established head token. It states only what this node established
// from its own verified local history. It is not peer consensus and does not
// confer any additional chain authority.
class EstablishedNativeHead {
 public:
  const Anchor& anchor() const {
    return anchor_;
  }
  const td::Ref<vm::Cell>& state() const {
    return state_;
  }
  const ChainContext& chain() const {
    return chain_;
  }

 private:
  friend class NativeFinalizedHeadEstablisher;
  EstablishedNativeHead(
      Anchor anchor, td::Ref<vm::Cell> state, ChainContext chain)
      : anchor_(std::move(anchor)),
        state_(std::move(state)),
        chain_(std::move(chain)) {
  }

  Anchor anchor_;
  td::Ref<vm::Cell> state_;
  ChainContext chain_;
};

// Establishes and monotonically advances one node-local finalized head. It
// mutates only this local remembered observation; it never applies chain state.
class NativeFinalizedHeadEstablisher {
 public:
  static Result<std::unique_ptr<NativeFinalizedHeadEstablisher>> create(
      ChainContext, NativeFinalizedHeadSource&);

  Result<EstablishedNativeHead> establish();

  const std::optional<Anchor>& current() const {
    return current_;
  }

 private:
  NativeFinalizedHeadEstablisher(
      ChainContext chain, NativeFinalizedHeadSource& source)
      : chain_(std::move(chain)), source_(source) {
  }

  ChainContext chain_;
  NativeFinalizedHeadSource& source_;
  std::optional<Anchor> current_;
};

}  // namespace tos::auth
