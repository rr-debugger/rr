/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_STDIO_MONITOR_H_
#define RR_STDIO_MONITOR_H_

#include "FileMonitor.h"

namespace rr {

/**
 * A FileMonitor to track writes to rr's stdout/stderr fds.
 * StdioMonitor prevents syscallbuf from buffering output to those fds. It
 * adds the optional stdio markers. During replay, it echoes stdio writes.
 */
class StdioMonitor : public FileMonitor {
public:
  /**
   * Create a StdioMonitor that monitors writes to rr's original_fd
   * (STDOUT_FILENO or STDERR_FILENO).
   * Note that it's possible for a tracee to have a StdioMonitor associated
   * with a different fd, thanks to dup() etc.
   */
  StdioMonitor(int original_fd) : original_fd(original_fd) {}

  virtual Type type() override { return Stdio; }

  /**
   * Make writes to stdout/stderr blocking, to avoid nondeterminism in the
   * order in which the kernel actually performs such writes.
   * This theoretically introduces the possibility of deadlock between rr's
   * tracee and some external program reading rr's output
   * via a pipe ... but that seems unlikely to bite in practice.
   *
   * Also, if stdio-marking is enabled, prepend the stdio write with
   * "[rr <pid> <global-time>]".  This allows users to more easily correlate
   * stdio with trace event numbers.
   */
  virtual Switchable will_write(Task* t) override;

  /**
   * During replay, echo writes to stdout/stderr.
   */
  virtual void did_write(Task* t, const std::vector<Range>& ranges,
                         LazyOffset&) override;

private:
  int original_fd;
};

} // namespace rr

#endif /* RR_STDIO_MONITOR_H_ */
