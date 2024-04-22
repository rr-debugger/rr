/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_PERF_COUNTERS_H_
#define RR_PERF_COUNTERS_H_

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <signal.h>
#include <stdint.h>
#include <linux/perf_event.h>
#include <sys/types.h>

#include <memory>
#include <utility>
#include <vector>

#include "ScopedFd.h"
#include "Ticks.h"

namespace rr {

class Registers;
class Task;
class BpfAccelerator;

enum TicksSemantics {
  TICKS_RETIRED_CONDITIONAL_BRANCHES,
  TICKS_TAKEN_BRANCHES,
};

/**
 * A buffer of Intel PT control-flow data.
 */
struct PTData {
  PTData() {}
  explicit PTData(std::vector<std::vector<uint8_t>> data)
    : data(std::move(data)) {}
  std::vector<std::vector<uint8_t>> data;
};

/**
 * A class encapsulating the performance counters we use to monitor
 * each task during recording and replay.
 *
 * Normally we monitor a single kind of event that we use as a proxy
 * for progress, which we call "ticks". Currently this is the count of retired
 * conditional branches. We support dispatching a signal when the counter
 * reaches a particular value.
 */
class PerfCounters {
public:
  /**
   * Create performance counters monitoring the given task.
   * When enable is false, we always report 0 and don't do any interrupts.
   */
  enum Enabled {
    ENABLE,
    DISABLE
  };
  enum IntelPTEnabled {
    PT_DISABLE,
    PT_ENABLE
  };
  PerfCounters(pid_t tid, int cpu_binding, TicksSemantics ticks_semantics,
               Enabled enabled, IntelPTEnabled enable_pt);
  ~PerfCounters() { close(); }

  struct PTState {
    PTData pt_data;
    ScopedFd pt_perf_event_fd;
    volatile perf_event_mmap_page* mmap_header;
    char* mmap_aux_buffer;

    PTState() : mmap_header(nullptr), mmap_aux_buffer(nullptr) {}
    ~PTState() { close(); }

    void open(pid_t tid);
    // Returns number of bytes flushed
    size_t flush();
    void close();
  };

  void set_tid(pid_t tid);

  /**
   * Reset all counter values to 0 and program the counters to send
   * TIME_SLICE_SIGNAL when 'ticks_period' tick events have elapsed. (In reality
   * the hardware triggers its interrupt some time after that. We also allow
   * the interrupt to fire early.)
   * This must be called while the task is stopped, and it must be called
   * before the task is allowed to run again if it's going to trigger ticks.
   * `ticks_period` of zero means don't interrupt at all.
   * Opens all relevant fds if necessary.
   */
  void start(Task* t, Ticks ticks_period);

  enum class Error {
    // Everything ok
    None,
    // A transient error was detected. Retrying might succeed.
    Transient,
  };

  /**
   * Suspend counting until the next start.
   * Returns the current value of the ticks counter.
   * `t` is used for debugging purposes.
   * If `error` is non-null,`*error` will be set to `Error::Transient`
   * if a transient error is detected, otherwise `Error::None`.
   * If `error` is null and a transient error is detected, it will be
   * treated as fatal.
   */
  Ticks stop(Task* t, Error* error = nullptr);

  /**
   * Close the perfcounter fds (if open). They will be automatically reopened if/when
   * reset is called again. The counters must not be currently running.
   */
  void close();

  /**
   * Return the number of ticks we need for an emulated branch.
   */
  static Ticks ticks_for_unconditional_indirect_branch(Task*);
  /**
   * Return the number of ticks we need for an emulated direct branch.
   */
  static Ticks ticks_for_unconditional_direct_branch(Task*);
  /**
   * Return the number of ticks we need for a direct call.
   */
  static Ticks ticks_for_direct_call(Task*);

  /**
   * Whether PMU on core i is supported.
   */
  static bool support_cpu(int cpu);

  /**
   * Returns what ticks mean for these counters.
   */
  TicksSemantics ticks_semantics() const { return ticks_semantics_; }

  /**
   * Return the fd we last used to generate the ticks-counter signal.
   */
  int ticks_interrupt_fd() const { return fd_ticks_interrupt.get(); }

  /* This choice is fairly arbitrary; linux doesn't use SIGSTKFLT so we
   * hope that tracees don't either. */
  enum { TIME_SLICE_SIGNAL = SIGSTKFLT };

  static bool is_rr_ticks_attr(const perf_event_attr& attr);

  static bool supports_ticks_semantics(TicksSemantics ticks_semantics);

  static TicksSemantics default_ticks_semantics();

  /**
   * When an interrupt is requested, at most this many ticks may elapse before
   * the interrupt is delivered.
   */
  uint32_t skid_size();

  /**
   * If Intel PT data collection is on, returns the accumulated raw PT data
   * and clears the internal buffer.
   * Otherwise returns an empty buffer.
   */
  PTData extract_intel_pt_data();

  /**
   * Start the PT copy thread. We need to do this early, before CPU binding
   * has occurred.
   */
  static void start_pt_copy_thread();

  /**
   * Try to use BPF to accelerate async signal processing
   */
#ifdef BPF
  bool accelerate_async_signal(const Registers& regs);
  uint64_t bpf_skips() const;
#else
  bool accelerate_async_signal(const Registers&) {
    return false;
  }
  uint64_t bpf_skips() const {
    return 0;
  }
#endif

private:
  template <typename Arch> void reset_arch_extras();

  /**
   * Use a separate skid_size for recording since we seem to see more skid
   * in practice during recording, in particular during the
   * async_signal_syscalls tests
   */
  uint32_t recording_skid_size() { return skid_size() * 5; }

  /**
   * If `error` is non-null,`*error` will be set to `Error::Transient`
   * if a transient error is detected, otherwise `Error::None`.
   * If `error` is null and a transient error is detected, it will be
   * treated as fatal.
   */
  Ticks read_ticks(Task* t, Error* error);

  // Only valid while 'counting' is true
  Ticks counting_period;
  pid_t tid;
  int pmu_index;
  // We use separate fds for counting ticks and for generating interrupts. The
  // former ignores ticks in aborted transactions, and does not support
  // sample_period; the latter does not ignore ticks in aborted transactions,
  // but does support sample_period.
  ScopedFd fd_ticks_measure;
  ScopedFd fd_minus_ticks_measure;
  ScopedFd fd_ticks_interrupt;
  ScopedFd fd_useless_counter;

  // x86(_64) specific counter to support recording HLE
  ScopedFd fd_ticks_in_transaction;

  // aarch64 specific counter to detect use of ll/sc instructions
  ScopedFd fd_strex_counter;

  // BPF-enabled hardware breakpoint for fast async signal emulation.
  ScopedFd fd_async_signal_accelerator;

  std::shared_ptr<BpfAccelerator> bpf;

  std::unique_ptr<PTState> pt_state;

  TicksSemantics ticks_semantics_;
  Enabled enabled;
  bool opened;
  bool counting;
};

} // namespace rr

#endif /* RR_PERF_COUNTERS_H_ */
