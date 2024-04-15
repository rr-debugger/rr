/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "StdioMonitor.h"

#include "Flags.h"
#include "ReplaySession.h"
#include "ReplayTask.h"
#include "Session.h"
#include "log.h"

namespace rr {

Switchable StdioMonitor::will_write(Task* t) {
  if (t->session().mark_stdio()) {
    char buf[256];
    snprintf(buf, sizeof(buf) - 1, "[rr %d %ld]", t->tgid(), t->trace_time());
    ssize_t len = strlen(buf);
    if (write(original_fd, buf, len) != len) {
      ASSERT(t, false) << "Couldn't write to " << original_fd;
    }
  }

  return PREVENT_SWITCH;
}

void StdioMonitor::did_write(Task* t, const std::vector<Range>& ranges,
                             LazyOffset&) {
  ReplaySession* replay_session = t->session().as_replay();
  if (!replay_session || !replay_session->echo_stdio()) {
    return;
  }
  for (auto& r : ranges) {
    auto bytes = t->read_mem(r.data.cast<uint8_t>(), r.length);
    if (bytes.size() !=
        (size_t)write(original_fd, bytes.data(), bytes.size())) {
      ASSERT(t, false) << "Couldn't write to " << original_fd;
    }
  }
}

} // namespace rr
