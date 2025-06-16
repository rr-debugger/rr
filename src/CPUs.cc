/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "CPUs.h"

#include <sched.h>
#include <unistd.h>

#include "log.h"

using namespace std;

namespace rr {

const CPUs& CPUs::get() {
  static CPUs singleton;
  return singleton;
}

std::vector<int> CPUs::initial_affinity() const {
  std::vector<int> result;
  for (int i = 0; i < CPU_SETSIZE; ++i) {
    if (CPU_ISSET(i, &initial_affinity_)) {
      result.push_back(i);
    }
  }
  return result;
}

bool CPUs::set_affinity_to_cpu(int cpu) {
  DEBUG_ASSERT(cpu >= 0);

  cpu_set_t mask;
  CPU_ZERO(&mask);
  CPU_SET(cpu, &mask);
  if (0 > sched_setaffinity(0, sizeof(mask), &mask)) {
    if (errno == EINVAL) {
      return false;
    }
    FATAL() << "Couldn't bind to CPU " << cpu;
  }
  return true;
}

void CPUs::restore_initial_affinity(pid_t tid) const {
  int ret = sched_setaffinity(tid, sizeof(initial_affinity_), &initial_affinity_);
  if (ret < 0) {
    FATAL() << "restore_initial_affinity failed";
  }
}

CPUs::CPUs() {
  // sched_getaffinity intersects the task's `cpu_mask`
  // (/proc/.../status Cpus_allowed_list) with `cpu_active_mask`
  // which is almost the same as /sys/devices/system/cpu/online
  int ret = sched_getaffinity(0, sizeof(initial_affinity_), &initial_affinity_);
  if (ret < 0) {
    FATAL() << "failed to get initial affinity";
  }
}

}

