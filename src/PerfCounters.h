/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_PERF_COUNTERS_H_
#define RR_PERF_COUNTERS_H_

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <signal.h>
#include <stdint.h>
#include <sys/types.h>

#include "ScopedFd.h"
#include "Ticks.h"

struct perf_event_attr;

namespace rr {

class Task;

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

  void set_tid(pid_t tid);

  /**
   * Reset all counter values to 0 and program the counters to send
   * TIME_SLICE_SIGNAL when 'ticks_period' tick events have elapsed. (In reality
   * the hardware triggers its interrupt some time after that. We also allow
   * the interrupt to fire early.)
   * This must be called while the task is stopped, and it must be called
   * before the task is allowed to run again.
   * `ticks_period` of zero means don't interrupt at all.
   */
  void reset(Ticks ticks_period);

  /**
   * Close the perfcounter fds. They will be automatically reopened if/when
   * reset is called again.
   */
  void stop();

  /**
   * Suspend counting until the next reset. This may or may not actually stop
   * the performance counters, depending on whether or not this is required
   * for correctness on this kernel version.
   */
  void stop_counting();

  /**
   * Read the current value of the ticks counter.
   * `t` is used for debugging purposes.
   */
  Ticks read_ticks(Task* t);

  /**
   * Return the fd we last used to generate the ticks-counter signal.
   */
  int ticks_interrupt_fd() const { return fd_ticks_interrupt.get(); }

  /* This choice is fairly arbitrary; linux doesn't use SIGSTKFLT so we
   * hope that tracees don't either. */
  enum { TIME_SLICE_SIGNAL = SIGSTKFLT };

  static bool is_ticks_attr(const perf_event_attr& attr);

  /**
   * When an interrupt is requested, at most this many ticks may elapse before
   * the interrupt is delivered.
   */
  static uint32_t skid_size();

  /**
   * Use a separate skid_size for recording since we seem to see more skid
   * in practice during recording, in particular during the
   * async_signal_syscalls tests
   */
  static uint32_t recording_skid_size() { return skid_size() * 5; }

private:
  // Only valid while 'counting' is true
  Ticks counting_period;
  pid_t tid;
  // We use separate fds for counting ticks and for generating interrupts. The
  // former ignores ticks in aborted transactions, and does not support
  // sample_period; the latter does not ignore ticks in aborted transactions,
  // but does support sample_period.
  ScopedFd fd_ticks_measure;
  ScopedFd fd_ticks_interrupt;
  ScopedFd fd_ticks_in_transaction;
  ScopedFd fd_useless_counter;
  bool started;
  bool counting;
};

} // namespace rr

#endif /* RR_PERF_COUNTERS_H_ */
