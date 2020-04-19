/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "ProcMemMonitor.h"

#include <stdlib.h>

#include "AutoRemoteSyscalls.h"
#include "RecordSession.h"
#include "ReplaySession.h"
#include "ReplayTask.h"
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
  if (ranges.empty()) {
    return;
  }
  int64_t offset = lazy_offset.retrieve(true);

  // In prior versions of rr, we recorded this directly into the trace.
  // If so, there's nothing to do here.
  if (t->session().is_replaying() && t->session().as_replay()->explicit_proc_mem()) {
    return;
  }

  if (t->session().is_recording()) {
    // Nothing to do now (though we may have just recorded the offset)
    return;
  }

  auto* target = static_cast<ReplayTask*>(t->session().find_task(tuid));
  if (!target) {
    return;
  }

  for (auto& r : ranges) {
    auto bytes = t->read_mem(r.data.cast<uint8_t>(), r.length);
    remote_ptr<uint8_t> target_addr = offset;
    target->write_mem(target_addr, bytes.data(), r.length);
    target->vm()->maybe_update_breakpoints(target, target_addr,
                                           r.length);
    offset += r.length;
  }
}

} // namespace rr
