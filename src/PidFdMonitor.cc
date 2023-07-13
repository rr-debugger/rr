/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "PidFdMonitor.h"

#include "Session.h"

namespace rr {

/* static */ PidFdMonitor*
PidFdMonitor::get(FdTable* fd_table, int fd) {
  FileMonitor* monitor = fd_table->get_monitor(fd);
  if (!monitor) {
    return NULL;
  }

  if (monitor->type() == PidFd) {
    return static_cast<PidFdMonitor*>(monitor);
  }

  return NULL;
}

FdTable::shr_ptr
PidFdMonitor::fd_table(Session& session) const {
  Task* t = session.find_task(tuid);
  if (!t) {
    return NULL;
  }

  return t->fd_table();
}

}
