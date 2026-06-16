/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "StdioMonitor.h"

#include "Flags.h"
#include "ReplaySession.h"
#include "ReplayTask.h"
#include "Session.h"
#include "log.h"
#include "util.h"

namespace rr {

Switchable StdioMonitor::will_write(Task* t) {
  if (t->session().mark_stdio()) {
    char buf[256];
    snprintf(buf, sizeof(buf) - 1, "[rr %d %" PRId64 "]", t->tgid(), t->trace_time());
    write_all(original_fd, buf, strlen(buf));
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
    write_all(original_fd, bytes.data(), bytes.size());
  }
}

void StdioMonitor::serialize_type(
    pcp::FileMonitor::Builder& builder) const noexcept {
  builder.setStdio(original_fd);
}

} // namespace rr
