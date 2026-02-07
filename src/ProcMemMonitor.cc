/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "ProcMemMonitor.h"

#include <stdlib.h>

#include "AutoRemoteSyscalls.h"
#include "RecordSession.h"
#include "ReplaySession.h"
#include "ReplayTask.h"
#include "TaskishUid.h"
#include "log.h"

using namespace std;

namespace rr {

ProcMemMonitor::ProcMemMonitor(Task* t, const string& pathname) {
  // XXX this makes some assumptions about namespaces... Probably fails
  // if |t| is not the same pid namespace as rr
  int tid = parse_tid_from_proc_path(pathname, "/mem");
  if (tid > 0) {
    Task* target = t->session().find_task(tid);
    if (target) {
      auid = target->vm()->uid();
    }
  }
}

ProcMemMonitor::ProcMemMonitor(AddressSpaceUid auid) noexcept : auid(auid) {}

void ProcMemMonitor::did_write(Task* t, const std::vector<Range>& ranges,
                               LazyOffset& lazy_offset) {
  if (ranges.empty()) {
    return;
  }
  int64_t offset = lazy_offset.retrieve(true);

  // In prior versions of rr, we recorded this directly into the trace.
  // If so, there's nothing to do here.
  if (t->session().is_replaying() && t->session().as_replay()->has_trace_quirk(TraceReader::ExplicitProcMem)) {
    return;
  }

  if (t->session().is_recording()) {
    // Nothing to do now (though we may have just recorded the offset)
    return;
  }

  auto* target = t->session().find_address_space(auid);
  if (!target) {
    return;
  }

  ReplayTask* task = static_cast<ReplayTask*>(target->first_running_task());
  if (!task) {
    return;
  }

  for (auto& r : ranges) {
    auto bytes = t->read_mem(r.data.cast<uint8_t>(), r.length);
    remote_ptr<uint8_t> target_addr = offset;
    task->write_mem(target_addr, bytes.data(), r.length);
    target->maybe_update_breakpoints(task, target_addr,
                                     r.length);
    offset += r.length;
  }
}

bool ProcMemMonitor::target_is_vm(AddressSpace *vm) {
  return auid == vm->uid();
}

void ProcMemMonitor::serialize_type(
    pcp::FileMonitor::Builder& builder) const noexcept {
  auto pm = builder.initProcMem();
  pm.setExecCount(auid.exec_count());
  pm.setTid(auid.tid());
  pm.setSerial(auid.serial());
}

} // namespace rr
