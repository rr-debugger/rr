/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_CPUS_H_
#define RR_CPUS_H_

#include <sched.h>

#include <vector>

namespace rr {

class CPUs {
public:
  static const CPUs& get();

  // Returns the CPU indices in the initial affinity mask, in increasing order.
  std::vector<int> initial_affinity() const;
  static bool set_affinity_to_cpu(int cpu);
  // Restore the initial affinity mask to the given tid.
  // If unspecified, defaults to this thread.
  void restore_initial_affinity(pid_t tid = 0) const;

private:
  CPUs();

  cpu_set_t initial_affinity_;
};

}

#endif
