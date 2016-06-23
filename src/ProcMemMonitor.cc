/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "ProcMemMonitor.h"

#include <stdlib.h>

#include "AutoRemoteSyscalls.h"
#include "log.h"
#include "ReplaySession.h"
#include "ReplayTask.h"

using namespace std;

namespace rr {

ProcMemMonitor::ProcMemMonitor(Task* t, const string& pathname) {
  // XXX this makes some assumptions about namespaces... Probably fails
  // if |t| is not the same pid namespace as rr
  if (pathname.substr(0, 6) == string("/proc/") &&
      pathname.substr(pathname.size() - 4, 4) == string("/mem")) {
    string s = pathname.substr(6, pathname.size() - 10);
    char* end;
    int tid = strtol(s.c_str(), &end, 10);
    if (!*end) {
      Task* target = t->session().find_task(tid);
      if (target) {
        tuid = target->tuid();
      }
    }
  }
}

void ProcMemMonitor::did_write(Task* t, const std::vector<Range>& ranges,
                               int64_t offset) {
  if (!t->session().is_replaying() || ranges.empty()) {
    return;
  }
  Task* target = t->session().find_task(tuid);
  if (!target) {
    return;
  }
  ASSERT(t, offset >= 0)
      << "Only pwrite/pwritev supported on /proc/<pid>/mem currently";
  // XXX to fix that, we'd have to track file offsets during replay or
  // have a way to store file offset in the trace
  for (auto& r : ranges) {
    auto bytes = t->read_mem(r.data.cast<uint8_t>(), r.length);
    target->write_mem(remote_ptr<uint8_t>(uintptr_t(offset)), bytes.data(),
                      bytes.size());
    offset += bytes.size();
  }
}

} // namespace rr
