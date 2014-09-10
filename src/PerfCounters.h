/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_HPC_H_
#define RR_HPC_H_

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <signal.h>
#include <stdint.h>
#include <sys/types.h>

/**
 * A class encapsulating the performance counters we use to monitor
 * each task during recording and replay.
 *
 * Normally we monitor a single kind of event that we use as a proxy
 * for progress, which we call "ticks". Currently this is the count of retired
 * conditional branches. We support dispatching a signal when the counter
 * reaches a particular value.
 *
 * When extra_perf_counters_enabled() returns true, we monitor additional
 * counters of interest.
 */
class PerfCounters {
public:
  /**
   * Create performance counters monitoring the given task.
   */
  PerfCounters(pid_t tid);
  ~PerfCounters() { stop(); }

  // Change this to 'true' to enable perf counters that may be interesting
  // for experimentation, but aren't necessary for core functionality.
  static bool extra_perf_counters_enabled() { return false; }

  /**
   * Reset all counter values to 0 and program the counters to send
   * TIME_SLICE_SIGNAL when 'ticks_period' tick events have elapsed. (In reality
   * the hardware triggers its interrupt some time after that.)
   * This must be called while the task is stopped, and it must be called
   * before the task is allowed to run again.
   */
  void reset(int64_t ticks_period);

  /**
   * Read the current value of the ticks counter.
   */
  int64_t read_ticks();

  /**
   * Return the fd we are using to monitor the ticks counter.
   */
  int ticks_fd() const { return fd_ticks; }

  /* This choice is fairly arbitrary; linux doesn't use SIGSTKFLT so we
   * hope that tracees don't either. */
  enum {
    TIME_SLICE_SIGNAL = SIGSTKFLT
  };

  struct Extra {
    int64_t page_faults;
    int64_t hw_interrupts;
    int64_t instructions_retired;
  };
  Extra read_extra();

private:
  void stop();

  pid_t tid;
  int fd_ticks;
  int fd_page_faults;
  int fd_hw_interrupts;
  int fd_instructions_retired;
  bool started;
};

#endif /* HPC_H_ */
