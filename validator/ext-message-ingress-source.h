#pragma once

#include <variant>

#include "keys/keys.hpp"

namespace tos {

namespace validator {

// Where an external message came from, as a question every caller answers.
//
// This used to be an optional peer. Absence was therefore representable, and
// absence reached the per-source limiter as the case that is not limited at
// all -- a meaning nobody chose, inherited from transports that had no
// identity to hand over. Nothing made a new call site decide, so the way to
// get the unlimited answer was to say nothing.
//
// There is no absent case here. A caller either names the peer it received the
// message from, or says the message did not arrive over a network.
struct RemotePeer {
  PublicKeyHash peer;
};

// Which in-process entry submitted this.
//
// It records provenance, not trust. Being local is not by itself a reason to
// be exempt from anything, and whether a local origin is rate limited is a
// transport policy decision this type deliberately does not make. Merging the
// two is how an in-process convenience becomes an unlimited external path
// later.
enum class LocalIngressKind {
  // Submitted by code running in this process rather than received from any
  // transport. A tool importing blocks and a test driving the pool are both
  // this; neither reached a socket.
  SameProcess,
};

struct LocalOrigin {
  LocalIngressKind kind{LocalIngressKind::SameProcess};
};

using ExtMessageIngressSource = std::variant<RemotePeer, LocalOrigin>;

}  // namespace validator

}  // namespace tos
