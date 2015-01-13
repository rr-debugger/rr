/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "StdioMonitor.h"

#include "Flags.h"
#include "log.h"
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
