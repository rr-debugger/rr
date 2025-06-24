/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "CPUs.h"

#include <sched.h>
#include <unistd.h>

#include <filesystem>
#include <fstream>
#include <istream>
#include <sstream>
#include <string>

#include "log.h"

using namespace std;

namespace rr {

static bool hybrid_cpu_arch_parse_cpus(const filesystem::path& dir,
                                       CPUGroup* group) {
  ifstream file(dir / "cpus");
  if (!file.good()) {
    LOG(warn) << "File " << dir.string() << "/cpus not found";
    return false;
  }
  ostringstream sstr;
  sstr << file.rdbuf();
  string s = sstr.str();
  while (!s.empty() && s[s.size() - 1] == '\n') {
    s.resize(s.size() - 1);
  }
  if (s.empty()) {
    LOG(info) << "File " << dir.string() << "/cpus is empty after trimming.";
    return false;
  }
  size_t dash = s.find('-');
  if (dash == string::npos) {
    size_t end;
    group->start_cpu = stoi(s, &end);
    if (end != s.size()) {
      LOG(warn) << "Bad CPU index";
      return false;
    }
    group->end_cpu = group->start_cpu + 1;
    return true;
  }
  size_t end;
  group->start_cpu = stoi(s.substr(0, dash), &end);
  if (end != dash) {
    LOG(warn) << "Bad CPU index";
    return false;
  }
  int last_cpu = stoi(s.substr(dash + 1), &end);
  if (end != s.size() - (dash + 1)) {
    LOG(warn) << "Bad end CPU index";
    return false;
  }
  group->end_cpu = last_cpu + 1;
  return true;
}

static bool hybrid_cpu_arch_parse_type(const filesystem::path& dir,
                                       CPUGroup* group) {
  // See https://github.com/torvalds/linux/blob/master/tools/perf/Documentation/intel-hybrid.txt
  ifstream file(dir / "type");
  if (!file.good()) {
    LOG(warn) << "File " << dir.string() << "/type not found";
    return false;
  }
  ostringstream sstr;
  sstr << file.rdbuf();
  string s = sstr.str();
  while (!s.empty() && s[s.size() - 1] == '\n') {
    s.resize(s.size() - 1);
  }
  size_t end;
  group->type = stoi(s, &end);
  if (end != s.size()) {
    LOG(warn) << "Bad type";
    return false;
  }
  return true;
}

// Returns an empty list on many (all?) systems that aren't using hybrid cores.
// In that case, assume all CPUs have the same microarch.
static vector<CPUGroup> hybrid_cpu_arch_groups() {
  vector<CPUGroup> result;
  filesystem::path dir_path = "/sys/devices";
  if (!filesystem::is_directory(dir_path)) {
    return result;
  }
  for (const auto& entry : filesystem::directory_iterator(dir_path)) {
    auto file_name = entry.path().filename().string();
    if (file_name.find("cpu_") != 0) {
      continue;
    }
    CPUGroup group;
    group.name = file_name.substr(4);
    if (!hybrid_cpu_arch_parse_cpus(entry.path(), &group)) {
      continue;
    }
    if (!hybrid_cpu_arch_parse_type(entry.path(), &group)) {
      continue;
    }
    if (group.name == "core") {
      group.kind = CPUGroup::P_CORE;
    } else if (group.name == "atom" || group.name == "lowpower") {
      group.kind = CPUGroup::E_CORE;
    } else {
      group.kind = CPUGroup::UNKNOWN;
    }
    result.push_back(std::move(group));
  }
  return result;
}

const CPUs& CPUs::get() {
  static CPUs singleton;
  return singleton;
}

std::vector<int> CPUs::initial_affinity() const {
  std::vector<int> result;
  for (int i = 0; i < CPU_SETSIZE; ++i) {
    if (CPU_ISSET(i, &initial_affinity_)) {
      result.push_back(i);
    }
  }
  return result;
}

bool CPUs::set_affinity_to_cpu(int cpu) {
  DEBUG_ASSERT(cpu >= 0);

  cpu_set_t mask;
  CPU_ZERO(&mask);
  CPU_SET(cpu, &mask);
  if (0 > sched_setaffinity(0, sizeof(mask), &mask)) {
    if (errno == EINVAL) {
      return false;
    }
    FATAL() << "Couldn't bind to CPU " << cpu;
  }
  return true;
}

void CPUs::restore_initial_affinity(pid_t tid) const {
  int ret = sched_setaffinity(tid, sizeof(initial_affinity_), &initial_affinity_);
  if (ret < 0) {
    FATAL() << "restore_initial_affinity failed";
  }
}

CPUs::CPUs() {
  // sched_getaffinity intersects the task's `cpu_mask`
  // (/proc/.../status Cpus_allowed_list) with `cpu_active_mask`
  // which is almost the same as /sys/devices/system/cpu/online
  int ret = sched_getaffinity(0, sizeof(initial_affinity_), &initial_affinity_);
  if (ret < 0) {
    FATAL() << "failed to get initial affinity";
  }
  cpu_groups_ = hybrid_cpu_arch_groups();
}

}

