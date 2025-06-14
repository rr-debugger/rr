/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "CPUs.h"

#include <sched.h>

#include <fstream>
#include <filesystem>
#include <sstream>

#include "log.h"

using namespace std;

namespace rr {

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

static vector<CPUs::Group> get_cpu_arch_groups_from_sysfs() {
  vector<CPUs::Group> result;
  filesystem::path dir_path = "/sys/devices";
  if (!filesystem::is_directory(dir_path)) {
    return result;
  }
  for (const auto& entry : filesystem::directory_iterator(dir_path)) {
    if (entry.path().filename().string().find("cpu_") != 0) {
      continue;
    }
    ifstream file(entry.path() / "cpus");
    if (!file.good()) {
      LOG(warn) << "File " << entry.path().string() << "/cpus not found";
      continue;
    }
    ostringstream sstr;
    sstr << file.rdbuf();
    string s = sstr.str();
    size_t dash = s.find('-');
    if (dash == string::npos) {
      size_t end;
      int cpu_index = stoi(s, &end);
      if (end != s.size()) {
        LOG(warn) << "Bad CPU index";
        continue;
      }
      result.push_back(CPUs::Group{cpu_index, cpu_index + 1});
    } else {
      size_t end;
      int cpu_index = stoi(s.substr(0, dash), &end);
      if (end != dash) {
        LOG(warn) << "Bad CPU index";
        continue;
      }
      int cpu_index_end = stoi(s.substr(dash + 1), &end);
      if (end != dash) {
        LOG(warn) << "Bad end CPU index";
        continue;
      }
      result.push_back(CPUs::Group{cpu_index, cpu_index_end + 1});
    }
  }
  return result;
}

std::vector<CPUs::Group> CPUs::cpu_arch_groups() const {
  std::vector<CPUs::Group> result = get_cpu_arch_groups_from_sysfs();
  if (result.empty()) {
    // Assume they're all the same arch.
    int configured = sysconf(_SC_NPROCESSORS_CONF);
    if (configured < 1) {
      FATAL() << "sysconf failed";
    }
    result.push_back(Group{0, configured});
  }
  return result;
}

CPUs::CPUs() {
  // sched_getaffinity intersects the task's `cpu_mask`
  // (/proc/.../status Cpus_allowed_list) with `cpu_active_mask`
  // which is almost the same as /sys/devices/system/cpu/online
  int ret = sched_getaffinity(0, sizeof(initial_affinity_), &initial_affinity_);
  if (ret < 0) {
    FATAL() << "failed to get initial affinity";
  }
}

}

