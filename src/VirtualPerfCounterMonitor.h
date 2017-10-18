/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_VIRTUAL_PERF_COUNTER_MONITOR_H_
#define RR_VIRTUAL_PERF_COUNTER_MONITOR_H_

#include "FileMonitor.h"
#include "TaskishUid.h"

struct perf_event_attr;

namespace rr {

/**
 * A FileMonitor to virtualize the performance counter that rr uses to count
 * ticks. Note that this doesn't support interrupts yet so recording rr replays
 * that involve async signals will not work!
 */
class VirtualPerfCounterMonitor : public FileMonitor {
public:
  static bool should_virtualize(const struct perf_event_attr& attr);

  VirtualPerfCounterMonitor(Task* t, Task* target,
                            const struct perf_event_attr& attr);
  virtual ~VirtualPerfCounterMonitor();

  virtual Type type() override { return VirtualPerfCounter; }

  virtual bool emulate_ioctl(RecordTask* t, uint64_t* result) override;
  virtual bool emulate_fcntl(RecordTask* t, uint64_t* result) override;
  virtual bool emulate_read(RecordTask* t, const std::vector<Range>& ranges,
                            LazyOffset& offset, uint64_t* result) override;

  Ticks target_ticks() const { return target_ticks_; }
  TaskUid target_tuid() const { return target_tuid_; }

  void synthesize_signal(RecordTask* t) const;

  enum { VIRTUAL_PERF_COUNTER_SIGNAL_SI_ERRNO = -1337 };

  static bool is_virtual_perf_counter_signal(siginfo_t* t) {
    return t->si_errno == VIRTUAL_PERF_COUNTER_SIGNAL_SI_ERRNO;
  }

  static VirtualPerfCounterMonitor* interrupting_virtual_pmc_for_task(Task* t);

private:
  void maybe_enable_interrupt(Task* t, uint64_t after);
  void disable_interrupt() const;

  Ticks initial_ticks;
  Ticks target_ticks_;
  TaskUid target_tuid_;
  pid_t owner_tid;
  int flags;
  int sig;
  bool enabled;

  static std::map<TaskUid, VirtualPerfCounterMonitor*> tasks_with_interrupts;
};

} // namespace rr

#endif /* RR_VIRTUAL_PERF_COUNTER_MONITOR_H_ */
