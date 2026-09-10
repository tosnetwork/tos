# Shared basic workchain descriptors

Workchain.fif owns the two encoders: add-basic-workchain (a6) and
add-basic-workchain-v2 (a7). Both require explicit routing flags and engine
selector and return the exact descriptor inserted in workchain-dict. The
native convenience word only supplies native arguments; it has no wire body.
Production genesis, local UNO, both Counter paths and the Python network
template call these library encoders. No caller retains its own wire encoder.

The equivalence measurement extracts the five predecessor constructors from
commit a27ff2c77 and compares their complete serialized cells with library
outputs. It is an explicit historical calibration tool, not a claim of
independent implementation verification. Historical bodies live only in that
measurement's generated artifacts, not in any active generator. A production
zerostate oracle additionally checks the real native split-depth arguments.

Versions have different admitted scopes: the generic local template defaults
to 14 without UNO; isolated Counter remains 15 (singleton ingress); the
production and independent local UNO profile require 16 (dual ingress).
validate_native_ingress_presence enforces the block-transition minimum for
all ingress and the multi-account minimum for custody-bearing ingress. The
new UNO setup switch explicitly selects 16; it never inherits generic 14.
Descriptor consolidation does not silently activate unrelated local profiles.
