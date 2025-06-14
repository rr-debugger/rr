/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_CPUS_H_
#define RR_CPUS_H_

#include <sched.h>

#include <vector>

namespace rr {

class CPUs {
public:
  static const CPUs& get();

  std::vector<int> initial_affinity() const;
  static bool set_affinity_to_cpu(int cpu);
  void restore_initial_affinity() const;

  struct Group {
    int start_cpu;
    int end_cpu;
  };
  // Returns a list of CPU groups that all have the same microarchitecture.
  // This list covers all available CPUs.
  std::vector<Group> cpu_arch_groups() const;

private:
  CPUs();

  cpu_set_t initial_affinity_;
};

}

#endif
