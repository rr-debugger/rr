/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "FdTable.h"

#include <limits.h>

#include <unordered_set>

#include "rr/rr.h"

#include "AddressSpace.h"
#include "RecordTask.h"
#include "ReplayTask.h"
#include "Session.h"
#include "core.h"
#include "log.h"

using namespace std;

namespace rr {

void FdTable::add_monitor(Task* t, int fd, FileMonitor* monitor) {
  // In the future we could support multiple monitors on an fd, but we don't
  // need to yet.
  ASSERT(t, !is_monitoring(fd)) << "Task " << t->rec_tid
    << " already monitoring fd " << fd;
  if (fd >= SYSCALLBUF_FDS_DISABLED_SIZE && fds.count(fd) == 0) {
    fd_count_beyond_limit++;
  }
  fds[fd] = FileMonitor::shr_ptr(monitor);
  update_syscallbuf_fds_disabled(fd);
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

void FdTable::did_dup(int from, int to) {
  if (fds.count(from)) {
    if (to >= SYSCALLBUF_FDS_DISABLED_SIZE && fds.count(to) == 0) {
      fd_count_beyond_limit++;
    }
    fds[to] = fds[from];
  } else {
    if (to >= SYSCALLBUF_FDS_DISABLED_SIZE && fds.count(to) > 0) {
      fd_count_beyond_limit--;
    }
    fds.erase(to);
  }
  update_syscallbuf_fds_disabled(to);
}

void FdTable::did_close(int fd) {
  LOG(debug) << "Close fd " << fd;
  if (fd >= SYSCALLBUF_FDS_DISABLED_SIZE && fds.count(fd) > 0) {
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

static syscallbuf_fd_classes join_fd_classes_over_tasks(AddressSpace* vm, int fd) {
  syscallbuf_fd_classes cls = FD_CLASS_UNTRACED;
  for (Task* t : vm->task_set()) {
    auto table = t->fd_table();
    if (table->is_monitoring(fd)) {
      if (cls != FD_CLASS_UNTRACED) {
        return FD_CLASS_TRACED;
      }
      cls = table->get_monitor(fd)->get_syscallbuf_class();
    } else if (fd >= SYSCALLBUF_FDS_DISABLED_SIZE - 1 &&
        table->count_beyond_limit() > 0) {
      return FD_CLASS_TRACED;
    }
  }
  return cls;
}

void FdTable::update_syscallbuf_fds_disabled(int fd) {
  DEBUG_ASSERT(fd >= 0);
  DEBUG_ASSERT(task_set().size() > 0);

  unordered_set<AddressSpace*> vms_updated;
  // It's possible for tasks with different VMs to share this fd table.
  // But tasks with the same VM might have different fd tables...
  for (Task* t : task_set()) {
    if (!t->session().is_recording()) {
      return;
    }
    RecordTask* rt = static_cast<RecordTask*>(t);

    AddressSpace* vm = rt->vm().get();
    if (vms_updated.find(vm) != vms_updated.end()) {
      continue;
    }
    vms_updated.insert(vm);

    if (!rt->preload_globals.is_null()) {
      if (fd >= SYSCALLBUF_FDS_DISABLED_SIZE) {
        fd = SYSCALLBUF_FDS_DISABLED_SIZE - 1;
      }
      char disable = (char)join_fd_classes_over_tasks(vm, fd);
      auto addr =
          REMOTE_PTR_FIELD(t->preload_globals, syscallbuf_fd_class[0]) + fd;
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

  char disabled[SYSCALLBUF_FDS_DISABLED_SIZE];
  memset(disabled, 0, sizeof(disabled));

  // It's possible that some tasks in this address space have a different
  // FdTable. We need to disable syscallbuf for an fd if any tasks for this
  // address space are monitoring the fd.
  for (Task* vm_t : rt->vm()->task_set()) {
    for (auto& it : vm_t->fd_table()->fds) {
      int fd = it.first;
      DEBUG_ASSERT(fd >= 0);
      if (fd >= SYSCALLBUF_FDS_DISABLED_SIZE) {
        fd = SYSCALLBUF_FDS_DISABLED_SIZE - 1;
      }
      if (disabled[fd] == FD_CLASS_UNTRACED) {
        disabled[fd] = it.second->get_syscallbuf_class();
      } else {
        disabled[fd] = FD_CLASS_TRACED;
      }
    }
  }

  auto addr = REMOTE_PTR_FIELD(t->preload_globals, syscallbuf_fd_class[0]);
  rt->write_mem(addr, disabled, SYSCALLBUF_FDS_DISABLED_SIZE);
  rt->record_local(addr, disabled, SYSCALLBUF_FDS_DISABLED_SIZE);
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

} // namespace rr
