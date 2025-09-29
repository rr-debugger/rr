/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "ContextSwitchEvent.h"

#include <fcntl.h>
#include <linux/perf_event.h>
#include <signal.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <optional>
#include <string>

#include "log.h"
#include "util.h"

using namespace std;

namespace rr {

static volatile int sigio_count;

static void sigio_handler(int, siginfo_t*, void*) {
  sigio_count += 1;
}

static bool can_use_switch_records() {
  struct perf_event_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.size = sizeof(attr);
  attr.type = PERF_TYPE_SOFTWARE;
  attr.config = PERF_COUNT_SW_DUMMY;
  attr.sample_period = 1;
  attr.watermark = 1;
  // We can't easily check PERF_RECORD_SWITCH directly
  // because there's no reliable way (as far as I know) to
  // force a context switch but still recover if no signal is
  // generated. So we test that generating a PERF_RECORD_MMAP
  // raises a signal instead.
  attr.mmap_data = 1;
  attr.wakeup_watermark = 1;
  attr.exclude_kernel = 1;
  attr.exclude_guest = 1;
  attr.disabled = 1;

  ScopedFd fd(syscall(SYS_perf_event_open, &attr, 0, -1, -1, 0));
  if (!fd.is_open()) {
    LOG(warn) << "Couldn't open a dummy event";
    return false;
  }

  PerfCounterBuffers buffers;
  buffers.allocate(fd, page_size(), 0);

  int ret = fcntl(fd, F_SETFL, FASYNC);
  if (ret < 0) {
    FATAL() << "Can't make fd async";
  }
  struct f_owner_ex own;
  own.type = F_OWNER_TID;
  own.pid = syscall(SYS_gettid);
  ret = fcntl(fd, F_SETOWN_EX, &own);
  if (ret < 0) {
    FATAL() << "Failed to fcntl(SETOWN_EX)";
  }

  struct sigaction sa;
  struct sigaction old_sa;
  sa.sa_sigaction = sigio_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_SIGINFO;
  ret = sigaction(SIGIO, &sa, &old_sa);
  if (ret < 0) {
    FATAL() << "Failed to install sighandler";
  }

  sigio_count = 0;
  ret = ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
  if (ret < 0) {
    FATAL() << "Failed to enable event";
  }
  void* p = mmap(nullptr, 1, PROT_READ, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  if (p == MAP_FAILED) {
    FATAL() << "Failed to mmap";
  }
  ret = ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
  if (ret < 0) {
    FATAL() << "Failed to disable event";
  }

  ret = munmap(p, 1);
  if (ret < 0) {
    FATAL() << "Failed to munmap";
  }
  ret = sigaction(SIGIO, &old_sa, nullptr);
  if (ret < 0) {
    FATAL() << "Failed to clean up sighandler";
  }

  if (sigio_count == 0) {
    // Old kernel
    LOG(info) << "PERF_RECORD_MMAP watermark failed to deliver signal";
    return false;
  }
  if (sigio_count > 1) {
    FATAL() << "Invalid SIGIO count";
  }

  return true;
}

static ContextSwitchEventStrategy init_strategy() {
  if (has_effective_caps(uint64_t(1) << CAP_SYS_ADMIN) ||
      has_effective_caps(uint64_t(1) << CAP_PERFMON)) {
    return ContextSwitchEventStrategy::STRATEGY_SW_CONTEXT_SWITCHES;
  }
  optional<int> perf_event_paranoid = read_perf_event_paranoid();
  if (perf_event_paranoid.has_value() && *perf_event_paranoid <= 1) {
    return ContextSwitchEventStrategy::STRATEGY_SW_CONTEXT_SWITCHES;
  }

  if (can_use_switch_records()) {
    return ContextSwitchEventStrategy::STRATEGY_RECORD_SWITCH;
  }

  string paranoid_value = "unknown";
  if (perf_event_paranoid.has_value()) {
    paranoid_value = std::to_string(*perf_event_paranoid);
  }
  CLEAN_FATAL() <<
      "rr needs /proc/sys/kernel/perf_event_paranoid <= 1, but it is "
          << paranoid_value << ".\n"
          << "Change it to 1, or use 'rr record -n' (slow).\n"
          << "Consider putting 'kernel.perf_event_paranoid = 1' in /etc/sysctl.d/10-rr.conf.\n"
          << "See 'man 8 sysctl', 'man 5 sysctl.d' (systemd systems)\n"
          << "and 'man 5 sysctl.conf' (non-systemd systems) for more details.";
  return ContextSwitchEventStrategy::STRATEGY_SW_CONTEXT_SWITCHES;
}

ContextSwitchEventStrategy ContextSwitchEvent::strategy() {
  static ContextSwitchEventStrategy strat = init_strategy();
  return strat;
}

bool ContextSwitchEvent::init(ScopedFd tracee_fd) {
  tracee_fd_ = std::move(tracee_fd);
  if (strategy() == ContextSwitchEventStrategy::STRATEGY_RECORD_SWITCH) {
    mmap_buffer = make_unique<PerfCounterBuffers>();
    bool ok = false;
    mmap_buffer->allocate(tracee_fd_, page_size(), 0, &ok);
    return ok;
  }
  return true;
}

void ContextSwitchEvent::drain_events() {
  if (mmap_buffer) {
    while (auto packet = mmap_buffer->next_packet()) {
    }
  }
}

} // namespace rr
