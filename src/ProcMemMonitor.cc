/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "ProcMemMonitor.h"

#include <stdlib.h>

#include "AutoRemoteSyscalls.h"
#include "RecordSession.h"
#include "RecordTask.h"
#include "log.h"

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
                               LazyOffset& lazy_offset) {
  if (t->session().is_replaying() || ranges.empty()) {
    return;
  }
  auto* target = static_cast<RecordTask*>(t->session().find_task(tuid));
  if (!target) {
    return;
  }
  int64_t offset = lazy_offset.retrieve(false);
  for (auto& r : ranges) {
    target->record_remote(remote_ptr<void>(offset), r.length);
    offset += r.length;
  }
}

} // namespace rr
