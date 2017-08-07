/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "MonitoredSharedMemory.h"

#include <sys/mman.h>

#include "AddressSpace.h"
#include "AutoRemoteSyscalls.h"
#include "RecordTask.h"
#include "Session.h"
#include "core.h"
#include "log.h"

using namespace std;

namespace rr {

MonitoredSharedMemory::~MonitoredSharedMemory() { munmap(real_mem, size); }

static const char dconf_suffix[] = "/dconf/user";

void MonitoredSharedMemory::maybe_monitor(RecordTask* t,
                                          const string& file_name,
                                          const AddressSpace::Mapping& m,
                                          int tracee_fd, uint64_t offset) {
  size_t dconf_suffix_len = sizeof(dconf_suffix) - 1;
  if (file_name.size() < dconf_suffix_len ||
      file_name.substr(file_name.size() - dconf_suffix_len) != dconf_suffix) {
    return;
  }

  AutoRemoteSyscalls remote(t);

  ScopedFd fd = remote.retrieve_fd(tracee_fd);
  uint8_t* real_mem = static_cast<uint8_t*>(
      mmap(NULL, m.map.size(), PROT_READ, MAP_SHARED, fd, offset));
  ASSERT(t, real_mem != MAP_FAILED);

  auto result = shared_ptr<MonitoredSharedMemory>(
      new MonitoredSharedMemory(real_mem, m.map.size()));

  const AddressSpace::Mapping& shared =
      Session::steal_mapping(remote, m, move(result));
  // m may be invalid now
  memcpy(shared.local_addr, real_mem, shared.map.size());
}

MonitoredSharedMemory::shr_ptr MonitoredSharedMemory::subrange(uintptr_t,
                                                               uintptr_t) {
  DEBUG_ASSERT(false && "Subranges not supported yet!");
  return nullptr;
}

void MonitoredSharedMemory::check_all(RecordTask* t) {
  vector<remote_ptr<void>> addrs;
  for (auto a : t->vm()->monitored_addrs()) {
    addrs.push_back(a);
  }
  for (auto a : addrs) {
    auto m = t->vm()->mapping_of(a);
    if (m.monitored_shared_memory) {
      m.monitored_shared_memory->check_for_changes(t, m);
    }
  }
}

void MonitoredSharedMemory::check_for_changes(RecordTask* t,
                                              AddressSpace::Mapping& m) {
  ASSERT(t, m.map.size() == size);
  if (!m.local_addr) {
    // reestablish local mapping after a fork or whatever
    AutoRemoteSyscalls remote(t);
    auto msm = m.monitored_shared_memory;
    m = Session::recreate_shared_mmap(remote, m, Session::DISCARD_CONTENTS,
                                      move(msm));
  }
  if (!memcmp(m.local_addr, real_mem, size)) {
    return;
  }
  memcpy(m.local_addr, real_mem, size);
  t->record_local(m.map.start(), size, real_mem);
}
}
