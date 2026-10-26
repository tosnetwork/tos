// Copyright 2026 TOS Blockchain Teams. SPDX-License-Identifier: LGPL-2.0-or-later
// Per-step VM trace for conformance tests. Compiled in only when the build sets
// TOS_VM_STEP_TRACE; release builds carry none of it.
#pragma once

#ifdef TOS_VM_STEP_TRACE

#include "vm/cells/CellHash.h"

namespace vm {
class VmState;

// Receives every step and every cell load of the VMs running on the thread
// that installed it, child VMs included.
class StepTraceSink {
 public:
  virtual ~StepTraceSink() = default;
  // Called after the step counter is incremented, before the instruction runs.
  virtual void on_step(const VmState& vm) = 0;
  // Called after the load was charged; `first` tells a load from a reload.
  virtual void on_cell_load(const VmState& vm, const CellHash& hash, bool first) = 0;
};

// The sink of the current thread; nullptr, the default, records nothing.
StepTraceSink*& step_trace_sink();
}  // namespace vm

#endif
