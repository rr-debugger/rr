/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_CONTEXT_SWITCH_EVENT_H_
#define RR_CONTEXT_SWITCH_EVENT_H_

#include <stdint.h>

#include <memory>

#include "PerfCounterBuffers.h"
#include "ScopedFd.h"
#include "preload/preload_interface.h"

namespace rr {

/**
 * For syscall buffering, we need to interrupt a tracee when it would block.
 * We do this by configuring a perf event to detect when the tracee is subject
 * to a context switch. When the perf event fires, it delivers a signal to the
 * tracee. The tracee syscallbuf code allocates the event fd and rr retrieves
 * it. We do it that way because both the tracee and rr need access to the
 * event fd.
 *
 * We can use `PERF_COUNT_SW_CONTEXT_SWITCHES` as the event. This is easy but
 * since it's a kernel event, unprivileged rr can't use it when
 * `perf_event_paranoid` is >= 2.
 *
 * Alternatively we can configure a dummy event and observe `PERF_RECORD_SWITCH`
 * records. This works with unprivileged rr when `perf_event_paranoid` == 2.
 * To trigger a signal when we get a `PERF_RECORD_SWITCH`, we set
 * `wakeup_watermark` so that appending any record to the ring buffer triggers
 * a wakeup. This requries configuring a ring buffer per tracee task; we can't
 * use a single ring buffer for multiple tracees, since when a tracee blocks
 * we need to send a signal directly to that specific tracee, not any others
 * and not rr. (We could deliver to rr and have rr interrupt the right tracee
 * but that would be slow.)
 * Unfortunately, in Linux kernels before 6.10, `watermark_wakeup` doesn't
 * trigger signals associated with the event fd. This bug was fixed in 6.10.
 *
 * So this class manages all the necessary logic. In particular we have to figure
 * out which strategy to use. We prefer to use `PERF_COUNT_SW_CONTEXT_SWITCHES`
 * if possible since we don't have to allocate ring buffers for those, so we'll
 * first check if that works. If it doesn't, we'll test if `PERF_RECORD_SWITCH`
 * works properly. If it doesn't, we produce the right error message and abort.
 * Then, if we're using `PERF_RECORD_SWITCH`, we need to allocate the ring buffer
 * and configure `wakeup_watermark`.
 */
class ContextSwitchEvent {
public:
  void init(ScopedFd tracee_fd);

  ScopedFd& tracee_fd() { return tracee_fd_; }

  // We need to determine the strategy before we configure syscallbuf to create
  // its tracee perf event fds.
  static ContextSwitchEventStrategy strategy();

  void drain_events();

private:
  // The fd retrieved from the tracee task that created it.
  ScopedFd tracee_fd_;
  // If we're using `PERF_RECORD_SWITCH` records, the
  // buffer we're using to trigger the watermark-wakeups.
  std::unique_ptr<PerfCounterBuffers> mmap_buffer;
};

} // namespace rr

#endif /* RR_CONTEXT_SWITCH_EVENT_H_ */
