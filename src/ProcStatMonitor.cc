/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include <sys/stat.h>
#include <unistd.h>

#include <fstream>
#include <algorithm>

#include "ProcStatMonitor.h"
#include "RecordTask.h"
#include "RecordSession.h"
#include "Scheduler.h"

#include "log.h"
#include "util.h"

using namespace std;

namespace rr {

// Skip any lines that contain CPUs not in our cpu mask
static void filter_proc_stat(string& data, const cpu_set_t& active) {
  string::iterator pos = data.begin();
  while (pos + 4 < data.end()) {
    const char *cur_data = &*pos;
    static char cpu_str[] = "cpu";
    if (memcmp(cur_data, cpu_str, sizeof(cpu_str)-1) == 0 && isdigit(*(cur_data + 3))) {
      unsigned long cpu = strtoul((char*)cur_data + 3, NULL, 10);
      if (!CPU_ISSET(cpu, &active)) {
        pos = data.erase(pos, ++std::find(pos, data.end(), '\n'));
        continue;
      }
    }
    pos = ++std::find(pos, data.end(), '\n');
  }
}

ProcStatMonitor::ProcStatMonitor(Task* t, const string&) {
  if (t->session().is_replaying())
    return;
  // Grab all the data now and buffer it for later access. This matches what the
  // kernel does (execpt that it does the buffering on first access) and is
  // required to give userspace code a consistent view of the file.
  std::ifstream proc_stat("/proc/stat");
  if (!proc_stat.is_open()) {
    FATAL() << "Failed to process /proc/stat";
  }
  data = string(
    (std::istreambuf_iterator<char>(proc_stat)),
    (std::istreambuf_iterator<char>()));
  const cpu_set_t cpus = static_cast<RecordTask*>(t)->session().scheduler().pretend_affinity_mask();
  filter_proc_stat(data, cpus);
}

bool ProcStatMonitor::emulate_read(
  RecordTask* t, const vector<Range>& ranges,
  LazyOffset& lazy_offset, uint64_t* result) {
  int64_t offset = lazy_offset.retrieve(false);
  *result = t->write_ranges(ranges, (uint8_t*)data.data() + offset,
    (offset > (ssize_t)data.size()) ? 0 : data.size() - offset);
  return true;
}

} // namespace rr
