/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "StdioMonitor.h"

#include "Flags.h"
#include "log.h"
#include "ReplaySession.h"
#include "Session.h"
#include "task.h"

Switchable StdioMonitor::will_write(Task* t) {
  if (Flags::get().mark_stdio) {
    char buf[256];
    snprintf(buf, sizeof(buf) - 1, "[rr %d %d]", t->tgid(), t->trace_time());
    ssize_t len = strlen(buf);
    if (write(original_fd, buf, len) != len) {
      ASSERT(t, false) << "Couldn't write to " << original_fd;
    }
  }

  return PREVENT_SWITCH;
}

void StdioMonitor::did_write(Task* t, const std::vector<Range>& ranges) {
  if (t->session().is_replaying() && t->replay_session().redirect_stdio()) {
    for (auto& r : ranges) {
      auto bytes = t->read_mem(r.data.cast<uint8_t>(), r.length);
      if (bytes.size() !=
          (size_t)write(original_fd, bytes.data(), bytes.size())) {
        ASSERT(t, false) << "Couldn't write to " << original_fd;
      }
    }
  }
}
