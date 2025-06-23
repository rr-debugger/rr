/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_CPUS_H_
#define RR_CPUS_H_

#include <sched.h>

#include <string>
#include <vector>

namespace rr {

struct BindCPU {
  enum Mode {
    // Bind to any core.
    ANY,
    // Perfer high-performance core if CPU affinity settings allow.
    PREFER_PERF_CORE,
    // Bind to a specified core unconditionally.
    SPECIFIED_CORE,
    // Don't bind.
    UNBOUND,
  };

  explicit BindCPU(Mode mode) : mode(mode) {}
  explicit BindCPU(int specified_core)
    : mode(SPECIFIED_CORE), specified_core(specified_core) {}

  Mode mode;
  int specified_core;
};

struct CPUGroup {
  enum Kind { P_CORE, E_CORE, UNKNOWN };

  int start_cpu;
  // Exclusive
  int end_cpu;
  std::string name;
  // PERF_TYPE_RAW or something else usable in the perf-attr
  // event_type field.
  int type;
  Kind kind;
};

class CPUs {
public:
  static const CPUs& get();

  // Returns the CPU indices in the initial affinity mask, in increasing order.
  std::vector<int> initial_affinity() const;
  static bool set_affinity_to_cpu(int cpu);
  // Restore the initial affinity mask to the given tid.
  // If unspecified, defaults to this thread.
  void restore_initial_affinity(pid_t tid = 0) const;

  // Returns the CPU group list. May be empty on systems where that
  // information is not available or relevant.
  const std::vector<CPUGroup>& cpu_groups() const { return cpu_groups_; }

private:
  CPUs();

  cpu_set_t initial_affinity_;
  std::vector<CPUGroup> cpu_groups_;
};

}

#endif
