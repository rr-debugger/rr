/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "VirtualPerfCounterMonitor.h"

#include <linux/perf_event.h>
#include <stdlib.h>

#include "AutoRemoteSyscalls.h"
#include "RecordSession.h"
#include "RecordTask.h"
#include "log.h"

using namespace std;

namespace rr {

std::map<TaskUid, VirtualPerfCounterMonitor*>
    VirtualPerfCounterMonitor::tasks_with_interrupts =
        std::map<TaskUid, VirtualPerfCounterMonitor*>();

bool VirtualPerfCounterMonitor::should_virtualize(
    const struct perf_event_attr& attr) {
  return PerfCounters::is_ticks_attr(attr);
}

VirtualPerfCounterMonitor::VirtualPerfCounterMonitor(
    Task* t, Task* target, const struct perf_event_attr& attr)
    : initial_ticks(target->tick_count()),
      target_tuid_(target->tuid()),
      owner_tid(0),
      flags(0),
      sig(0),
      enabled(false) {
  ASSERT(t, should_virtualize(attr));
  if (t->session().is_recording()) {
    maybe_enable_interrupt(t, attr.sample_period);
  }
}

VirtualPerfCounterMonitor::~VirtualPerfCounterMonitor() { disable_interrupt(); }

bool VirtualPerfCounterMonitor::emulate_ioctl(RecordTask* t, uint64_t* result) {
  switch ((int)t->regs().arg2()) {
    case PERF_EVENT_IOC_ENABLE:
      *result = 0;
      enabled = true;
      break;
    case PERF_EVENT_IOC_DISABLE:
      *result = 0;
      enabled = false;
      break;
    case PERF_EVENT_IOC_RESET: {
      *result = 0;
      RecordTask* target = t->session().find_task(target_tuid());
      initial_ticks = target->tick_count();
      break;
    }
    case PERF_EVENT_IOC_PERIOD: {
      *result = 0;
      maybe_enable_interrupt(
          t, t->read_mem(remote_ptr<uint64_t>(t->regs().arg3())));
      break;
    }
    default:
      ASSERT(t, false) << "Unsupported perf event ioctl "
                       << HEX((int)t->regs().arg2());
      break;
  }
  return true;
}

bool VirtualPerfCounterMonitor::emulate_fcntl(RecordTask* t, uint64_t* result) {
  *result = -(int64_t)EINVAL;
  switch ((int)t->regs().arg2()) {
    case F_SETOWN_EX: {
      auto owner = t->read_mem(remote_ptr<struct f_owner_ex>(t->regs().arg3()));
      ASSERT(t, owner.type == F_OWNER_TID)
          << "Unsupported perf event F_SETOWN_EX type " << owner.type;
      ASSERT(t, owner.pid == target_tuid().tid())
          << "Perf event F_SETOWN_EX is only supported to the target tid";
      owner_tid = owner.pid;
      *result = 0;
      break;
    }
    case F_SETFL:
      ASSERT(t, !(t->regs().arg3() & ~O_ASYNC))
          << "Unsupported perf event flags " << HEX((int)t->regs().arg3());
      flags = (int)t->regs().arg3();
      *result = 0;
      break;
    case F_SETSIG:
      sig = (int)t->regs().arg3();
      *result = 0;
      break;
    default:
      ASSERT(t, false) << "Unsupported perf event fnctl "
                       << HEX((int)t->regs().arg2());
      break;
  }
  return true;
}

static size_t write_ranges(RecordTask* t,
                           const vector<FileMonitor::Range>& ranges, void* data,
                           size_t size) {
  uint8_t* p = static_cast<uint8_t*>(data);
  size_t s = size;
  size_t result = 0;
  for (auto& r : ranges) {
    size_t bytes = min(s, r.length);
    t->write_bytes_helper(r.data, bytes, p);
    s -= bytes;
    result += bytes;
  }
  return result;
}

bool VirtualPerfCounterMonitor::emulate_read(RecordTask* t,
                                             const vector<Range>& ranges,
                                             LazyOffset&, uint64_t* result) {
  RecordTask* target = t->session().find_task(target_tuid());
  if (target) {
    int64_t val = target->tick_count() - initial_ticks;
    *result = write_ranges(t, ranges, &val, sizeof(val));
  } else {
    *result = 0;
  }
  return true;
}

void VirtualPerfCounterMonitor::maybe_enable_interrupt(Task* t,
                                                       uint64_t after) {
  Task* target = t->session().find_task(target_tuid());
  if (after == 0 || after > 0xffffffff) {
    return;
  }

  auto previous =
      tasks_with_interrupts.insert(std::make_pair(target_tuid(), this));
  ASSERT(t, previous.second || previous.first->second == this)
      << "Multiple virtualized performance counters with interrupts\n\tFirst "
         "at "
      << previous.first->second << "\tSecond at " << this;

  target_ticks_ = target->tick_count() + after;
}

void VirtualPerfCounterMonitor::disable_interrupt() const {
  auto found = tasks_with_interrupts.find(target_tuid());
  if (found == tasks_with_interrupts.end()) {
    return;
  }

  if (found->second == this) {
    tasks_with_interrupts.erase(found);
  }
}

void VirtualPerfCounterMonitor::synthesize_signal(RecordTask* t) const {
  // Use NativeArch here because different versions of system headers
  // have inconsistent field naming.
  union {
    NativeArch::siginfo_t native_api;
    siginfo_t linux_api;
  } si;
  memset(&si, 0, sizeof(si));
  si.native_api.si_signo = sig;
  si.native_api.si_errno = VIRTUAL_PERF_COUNTER_SIGNAL_SI_ERRNO;
  LOG(debug) << "Synthesizing vpmc signal " << si.linux_api;
  t->stash_synthetic_sig(si.linux_api, NONDETERMINISTIC_SIG);
  disable_interrupt();
}

/* static */
VirtualPerfCounterMonitor*
VirtualPerfCounterMonitor::interrupting_virtual_pmc_for_task(Task* t) {
  auto found = tasks_with_interrupts.find(t->tuid());
  if (found == tasks_with_interrupts.end()) {
    return nullptr;
  }

  return found->second;
}

} // namespace rr
