/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_CPUID_BUG_DETECTOR_H_
#define RR_CPUID_BUG_DETECTOR_H_

#include <stdint.h>

namespace rr {

class ReplayTask;

/**
 * Helper to detect when the "CPUID can cause rcbs to be lost" bug is present.
 * See http://robert.ocallahan.org/2014/09/vmware-cpuid-conditional-branch.html
 *
 * This bug is caused by VMM optimizations described in
 * https://www.usenix.org/system/files/conference/atc12/atc12-final158.pdf
 * that cause instruction sequences related to CPUID to be optimized,
 * eliminating the user-space execution of a conditional branch between two
 * CPUID instructions (in some circumstances).
 */
class CPUIDBugDetector {
public:
  CPUIDBugDetector()
      : trace_rcb_count_at_last_geteuid32(0),
        actual_rcb_count_at_last_geteuid32(0),
        detected_cpuid_bug(false) {}
  /**
   * Call this in the context of the first spawned process to run the
   * code that triggers the bug.
   */
  static void run_detection_code();
  /**
   * Call this when task t enters a traced syscall during replay.
   */
  void notify_reached_syscall_during_replay(ReplayTask* t);

private:
  uint64_t trace_rcb_count_at_last_geteuid32;
  uint64_t actual_rcb_count_at_last_geteuid32;
  bool detected_cpuid_bug;
};

} // namespace rr

#endif /* RR_CPUID_BUG_DETECTOR_H_ */
