/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_CPUID_BUG_DETECTOR_H_
#define RR_CPUID_BUG_DETECTOR_H_

#include <stdint.h>

class Task;

/**
 * Helper to detect when the "CPUID can cause rbcs to be lost" bug is present.
 * See http://robert.ocallahan.org/2014/09/vmware-cpuid-conditional-branch.html
 */
class CPUIDBugDetector {
public:
  CPUIDBugDetector()
      : trace_rbc_count_at_last_geteuid32(0),
        actual_rbc_count_at_last_geteuid32(0),
        detected_cpuid_bug(false) {}
  /**
   * Call this in the context of the first spawned process to run the
   * code that triggers the bug.
   */
  static void run_detection_code();
  /**
   * Call this when task t enters a traced syscall during replay.
   */
  void notify_reached_syscall_during_replay(Task* t);
  /**
   * Returns true when the "CPUID can cause rbcs to be lost" bug has
   * been detected.
   */
  bool is_cpuid_bug_detected() { return detected_cpuid_bug; }

private:
  uint64_t trace_rbc_count_at_last_geteuid32;
  uint64_t actual_rbc_count_at_last_geteuid32;
  bool detected_cpuid_bug;
};

#endif /* RR_CPUID_BUG_DETECTOR_H_ */
