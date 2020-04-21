/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include <sstream>

#include "SysCpuMonitor.h"
#include "RecordTask.h"
#include "RecordSession.h"
#include "Scheduler.h"

#include "log.h"

using namespace std;

namespace rr {

SysCpuMonitor::SysCpuMonitor(Task*, const string&) {
}

static string make_cpu_online_data(RecordTask* t) {
  const cpu_set_t cpus = t->session().scheduler().pretend_affinity_mask();
  int real_ncpus = sysconf(_SC_NPROCESSORS_CONF);
  bool last_was_set = false;
  std::stringstream result;
  bool first = true;
  for (int i = 0; i < real_ncpus; ++i) {
    bool this_is_set = CPU_ISSET(i, &cpus);
    if (this_is_set) {
      if (!last_was_set) {
        if (!first) {
          result << ",";
        }
        first = false;
        result << i;
      }
      if (!CPU_ISSET(i+1, &cpus)) {
        if (last_was_set) {
          result << "-" << i;
        }
      }
    }
    last_was_set = this_is_set;
  }
  result << "\n";
  return result.str();
}

bool SysCpuMonitor::emulate_read(
  RecordTask* t, const vector<Range>& ranges,
  LazyOffset& lazy_offset, uint64_t* result) {
  string data = make_cpu_online_data(t);
  int64_t offset = lazy_offset.retrieve(false);
  *result = t->write_ranges(ranges, (uint8_t*)data.data() + offset,
    offset > (ssize_t)data.size() ? 0 : data.size() - offset);
  return true;
}

} // namespace rr
