// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
// Conformance reference entry points. Each harness takes one context as a JSON document and returns one
// effects JSON document, or {"harness_error": "..."} when the context is refused before execution.
// Returned strings are owned by the caller and released with conformance_free. Not thread-safe.
#pragma once

#define CONFORMANCE_EXPORT __attribute__((visibility("default")))

#ifdef __cplusplus
extern "C" {
#endif

// Run the named harness ("vm", "txn", ...). Every harness is also exported as conformance_<name>_v1.
CONFORMANCE_EXPORT const char *conformance_run_v1(const char *harness, const char *context_json);

// 1 when the library provides the named harness.
CONFORMANCE_EXPORT int conformance_has_harness(const char *harness);

// {"reference_commit": "<sha1>", "dirty": <bool>, "harnesses": [...]} of the build this library comes from.
CONFORMANCE_EXPORT const char *conformance_reference_info(void);

CONFORMANCE_EXPORT void conformance_free(const char *str);

#ifdef __cplusplus
}
#endif
