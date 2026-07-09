/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "FdTable.h"

#include <limits.h>

#include <unordered_set>
#include <utility>

#include "BpfMapMonitor.h"
#include "FileMonitor.h"
#include "MagicSaveDataMonitor.h"
#include "MmappedFileMonitor.h"
#include "NonvirtualPerfCounterMonitor.h"
#include "ODirectFileMonitor.h"
#include "PreserveFileMonitor.h"
#include "ProcFdDirMonitor.h"
#include "ProcMemMonitor.h"
#include "ProcStatMonitor.h"
#include "RRPageMonitor.h"
#include "StdioMonitor.h"
#include "SysCpuMonitor.h"
#include "rr/rr.h"

#include "AddressSpace.h"
#include "RecordTask.h"
#include "ReplayTask.h"
#include "Session.h"
#include "core.h"
#include "log.h"

using namespace std;

namespace rr {

FdTable::shr_ptr FdTable::create(Task* t) {
  shr_ptr fds(new FdTable(t->session().syscallbuf_fds_disabled_size()));
  fds->insert_task(t);
  return fds;
}

void FdTable::insert_task(Task* t) {
  HasTaskSet::insert_task(t);
  ++vms[t->vm().get()];
}

void FdTable::erase_task(Task* t) {
  if (task_set().find(t) == task_set().end()) {
    return;
  }
  HasTaskSet::erase_task(t);
  auto it = vms.find(t->vm().get());
  if (it == vms.end()) {
    FATAL() << "Lost track of VM already?";
  }
  --it->second;
  if (!it->second) {
    vms.erase(it);
  }
}

void FdTable::add_monitor(Task* t, int fd, FileMonitor* monitor) {
  // In the future we could support multiple monitors on an fd, but we don't
  // need to yet.
  FileMonitor* current = get_monitor(fd);
  if (current) {
    ASSERT(t, false) << "Task " << t->rec_tid << " already monitoring fd "
      << fd << " " << file_monitor_type_name(current->type());
  }
  if (fd >= syscallbuf_fds_disabled_size && fds.count(fd) == 0) {
    fd_count_beyond_limit++;
  }
  fds[fd] = FileMonitor::shr_ptr(monitor);
  update_syscallbuf_fds_disabled(fd);
}

void FdTable::replace_monitor(Task* t, int fd, FileMonitor* monitor) {
  if (!is_monitoring(fd)) {
    add_monitor(t, fd, monitor);
  } else {
    fds[fd] = FileMonitor::shr_ptr(monitor);
  }
}

bool FdTable::is_rr_fd(int fd) {
  auto it = fds.find(fd);
  if (it == fds.end()) {
    return false;
  }
  return it->second->is_rr_fd();
}

bool FdTable::emulate_ioctl(int fd, RecordTask* t, uint64_t* result) {
  auto it = fds.find(fd);
  if (it == fds.end()) {
    return false;
  }
  return it->second->emulate_ioctl(t, result);
}

bool FdTable::emulate_fcntl(int fd, RecordTask* t, uint64_t* result) {
  auto it = fds.find(fd);
  if (it == fds.end()) {
    return false;
  }
  return it->second->emulate_fcntl(t, result);
}

bool FdTable::emulate_read(int fd, RecordTask* t,
                           const std::vector<FileMonitor::Range>& ranges,
                           FileMonitor::LazyOffset& offset, uint64_t* result) {
  auto it = fds.find(fd);
  if (it == fds.end()) {
    return false;
  }
  return it->second->emulate_read(t, ranges, offset, result);
}

void FdTable::filter_getdents(int fd, RecordTask* t) {
  auto it = fds.find(fd);
  if (it == fds.end()) {
    return;
  }
  it->second->filter_getdents(t);
}

Switchable FdTable::will_write(Task* t, int fd) {
  auto it = fds.find(fd);
  if (it == fds.end()) {
    return ALLOW_SWITCH;
  }
  return it->second->will_write(t);
}

void FdTable::did_write(Task* t, int fd,
                        const std::vector<FileMonitor::Range>& ranges,
                        FileMonitor::LazyOffset& offset) {
  auto it = fds.find(fd);
  if (it != fds.end()) {
    it->second->did_write(t, ranges, offset);
  }
}

void FdTable::did_dup(FdTable* table, int from, int to) {
  if (table->fds.count(from)) {
    if (to >= syscallbuf_fds_disabled_size && fds.count(to) == 0) {
      fd_count_beyond_limit++;
    }
    fds[to] = table->fds[from];
  } else {
    if (to >= syscallbuf_fds_disabled_size && fds.count(to) > 0) {
      fd_count_beyond_limit--;
    }
    fds.erase(to);
  }
  update_syscallbuf_fds_disabled(to);
}

void FdTable::did_close(int fd) {
  LOG(debug) << "Close fd " << fd;
  if (fd >= syscallbuf_fds_disabled_size && fds.count(fd) > 0) {
    fd_count_beyond_limit--;
  }
  fds.erase(fd);
  update_syscallbuf_fds_disabled(fd);
}

FileMonitor* FdTable::get_monitor(int fd) {
  auto it = fds.find(fd);
  if (it == fds.end()) {
    return nullptr;
  }
  return it->second.get();
}

static syscallbuf_fd_classes join_fd_classes_over_tasks(AddressSpace* vm, int fd,
    int syscallbuf_fds_disabled_size) {
  syscallbuf_fd_classes cls = FD_CLASS_UNTRACED;
  for (Task* t : vm->task_set()) {
    auto table = t->fd_table();
    if (table->is_monitoring(fd)) {
      if (cls != FD_CLASS_UNTRACED) {
        return FD_CLASS_TRACED;
      }
      cls = table->get_monitor(fd)->get_syscallbuf_class();
    } else if (fd >= syscallbuf_fds_disabled_size - 1 &&
        table->count_beyond_limit() > 0) {
      return FD_CLASS_TRACED;
    }
  }
  return cls;
}

void FdTable::update_syscallbuf_fds_disabled(int fd) {
  DEBUG_ASSERT(fd >= 0);
  DEBUG_ASSERT(task_set().size() > 0);

  // It's possible for tasks with different VMs to share this fd table.
  // But tasks with the same VM might have different fd tables...
  for (auto address_space : vms) {
    RecordTask* rt = nullptr;
    if (address_space.first->task_set().empty()) {
      FATAL() << "Address space must have at least one task";
    }
    for (Task* t : address_space.first->task_set()) {
      if (!t->session().is_recording()) {
        // We could return but we want to check that all our
        // AddressSpaces have tasks (i.e. aren't dead/dangling)
        break;
      }
      rt = static_cast<RecordTask*>(t);
      if (!rt->already_exited()) {
        break;
      }
      rt = nullptr;
    }
    if (rt && !rt->preload_globals.is_null()) {
      if (fd >= syscallbuf_fds_disabled_size) {
        fd = syscallbuf_fds_disabled_size - 1;
      }
      char disable = (char)join_fd_classes_over_tasks(address_space.first, fd,
          syscallbuf_fds_disabled_size);
      auto addr =
          REMOTE_PTR_FIELD(rt->preload_globals, syscallbuf_fd_class[0]) + fd;
      rt->write_mem(addr, disable);
      rt->record_local(addr, &disable);
    }
  }
}

void FdTable::init_syscallbuf_fds_disabled(Task* t) {
  if (!t->session().is_recording()) {
    return;
  }
  RecordTask* rt = static_cast<RecordTask*>(t);

  ASSERT(rt, has_task(rt));

  if (rt->preload_globals.is_null()) {
    return;
  }

  vector<char> disabled;
  disabled.resize(syscallbuf_fds_disabled_size, 0);

  // It's possible that some tasks in this address space have a different
  // FdTable. We need to disable syscallbuf for an fd if any tasks for this
  // address space are monitoring the fd.
  for (Task* vm_t : rt->vm()->task_set()) {
    for (auto& it : vm_t->fd_table()->fds) {
      int fd = it.first;
      DEBUG_ASSERT(fd >= 0);
      if (fd >= syscallbuf_fds_disabled_size) {
        fd = syscallbuf_fds_disabled_size - 1;
      }
      if (disabled[fd] == FD_CLASS_UNTRACED) {
        disabled[fd] = it.second->get_syscallbuf_class();
      } else {
        disabled[fd] = FD_CLASS_TRACED;
      }
    }
  }

  auto addr = REMOTE_PTR_FIELD(t->preload_globals, syscallbuf_fd_class[0]);
  rt->write_mem(addr, disabled.data(), syscallbuf_fds_disabled_size);
  rt->record_local(addr, disabled.data(), syscallbuf_fds_disabled_size);
}

void FdTable::close_after_exec(ReplayTask* t, const vector<int>& fds_to_close) {
  ASSERT(t, has_task(t));

  for (auto fd : fds_to_close) {
    did_close(fd);
  }
}

static bool is_fd_open(Task* t, int fd) {
  char path[PATH_MAX];
  sprintf(path, "/proc/%d/fd/%d", t->tid, fd);
  struct stat st;
  return 0 == lstat(path, &st);
}

vector<int> FdTable::fds_to_close_after_exec(RecordTask* t) {
  ASSERT(t, has_task(t));

  vector<int> fds_to_close;
  for (auto& it : fds) {
    if (!is_fd_open(t, it.first)) {
      fds_to_close.push_back(it.first);
    }
  }
  for (auto fd : fds_to_close) {
    did_close(fd);
  }
  return fds_to_close;
}

void FdTable::deserialize(Task* leader,
                          const pcp::ProcessSpace::Reader& leader_reader) {
  auto monitors = leader_reader.getMonitors();
  for (auto m : monitors) {
    FileMonitor::Type t = (FileMonitor::Type)m.getType();
    auto fd = m.getFd();
    if (!is_monitoring(m.getFd())) {
      switch (t) {
        case FileMonitor::Base:
          FATAL() << "Can't add abstract type";
          break;
        case FileMonitor::MagicSaveData:
          add_monitor(leader, fd, new MagicSaveDataMonitor());
          break;
        case FileMonitor::Mmapped: {
          const auto mmap = m.getMmap();
          add_monitor(leader, fd,
                      new MmappedFileMonitor(mmap.getDead(), mmap.getDevice(),
                                             mmap.getInode()));
        } break;
        case FileMonitor::Preserve:
          add_monitor(leader, fd, new PreserveFileMonitor());
          break;
        case FileMonitor::ProcFd: {
          const auto p_fd = m.getProcFd();
          const auto tuid = TaskUid(p_fd.getTid(), p_fd.getSerial());
          add_monitor(leader, fd, new ProcFdDirMonitor(tuid));
          break;
        }
        case FileMonitor::ProcMem: {
          const auto pmem = m.getProcMem();
          add_monitor(leader, fd,
                      new ProcMemMonitor(AddressSpaceUid(pmem.getTid(),
                                                         pmem.getSerial(),
                                                         pmem.getExecCount())));
        } break;
        case FileMonitor::Stdio:
          add_monitor(leader, fd, new StdioMonitor(m.getStdio()));
          break;
        case FileMonitor::VirtualPerfCounter:
          FATAL() << "VirtualPerCounter Monitor deserializing unimplemented!\n";
          break;
        case FileMonitor::NonvirtualPerfCounter:
          add_monitor(leader, fd, new NonvirtualPerfCounterMonitor());
          break;
        case FileMonitor::SysCpu:
          add_monitor(leader, fd, new SysCpuMonitor(leader, ""));
          break;
        case FileMonitor::ProcStat:
          add_monitor(
              leader, fd,
              new ProcStatMonitor(leader, data_to_str(m.getProcStat())));
          break;
        case FileMonitor::RRPage:
          add_monitor(leader, fd, new RRPageMonitor());
          break;
        case FileMonitor::ODirect:
          add_monitor(leader, fd, new ODirectFileMonitor());
          break;
        case FileMonitor::BpfMap:
          add_monitor(leader, fd,
                      new BpfMapMonitor(m.getBpf().getKeySize(),
                                        m.getBpf().getValueSize()));
          break;
        default:
          FATAL() << "unhandled FileMonitor: " << file_monitor_type_name(t);
      }
    }
  }
}

void FdTable::serialize(pcp::ProcessSpace::Builder& leader_builder) const {
  auto serialized_fd_mons = leader_builder.initMonitors(fds.size());
  auto mon_index = 0;
  for (const auto& mon : fds) {
    const auto fd = mon.first;
    const auto& monitor = mon.second;
    auto builder = serialized_fd_mons[mon_index++];
    monitor->serialize(fd, builder);
  }
}

} // namespace rr
