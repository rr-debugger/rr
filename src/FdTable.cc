/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "FdTable.h"

#include <limits.h>

#include <unordered_set>

#include "rr/rr.h"

#include "log.h"
#include "Session.h"
#include "Task.h"

using namespace std;

namespace rr {

void FdTable::add_monitor(int fd, FileMonitor* monitor) {
  // In the future we could support multiple monitors on an fd, but we don't
  // need to yet.
  assert(!is_monitoring(fd));
  fds[fd] = FileMonitor::shr_ptr(monitor);
  update_syscallbuf_fds_disabled(fd);
}

bool FdTable::allow_close(int fd) {
  auto it = fds.find(fd);
  if (it == fds.end()) {
    return true;
  }
  return it->second->allow_close();
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
                           off_t offset, uint64_t* result) {
  auto it = fds.find(fd);
  if (it == fds.end()) {
    return false;
  }
  return it->second->emulate_read(t, ranges, offset, result);
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
                        off_t offset) {
  auto it = fds.find(fd);
  if (it != fds.end()) {
    it->second->did_write(t, ranges, offset);
  }
}

void FdTable::did_dup(int from, int to) {
  if (fds.count(from)) {
    fds[to] = fds[from];
  } else {
    fds.erase(to);
  }
  update_syscallbuf_fds_disabled(to);
}

void FdTable::did_close(int fd) {
  fds.erase(fd);
  update_syscallbuf_fds_disabled(fd);
}

static bool is_fd_monitored_in_any_task(AddressSpace* vm, int fd) {
  for (Task* t : vm->task_set()) {
    if (t->fd_table()->is_monitoring(fd)) {
      return true;
    }
  }
  return false;
}

void FdTable::update_syscallbuf_fds_disabled(int fd) {
  assert(fd >= 0);
  assert(task_set().size() > 0);

  unordered_set<AddressSpace*> vms_updated;
  // It's possible for tasks with different VMs to share this fd table.
  // But tasks with the same VM might have different fd tables...
  for (Task* t : task_set()) {
    AddressSpace* vm = t->vm().get();
    if (vms_updated.find(vm) != vms_updated.end()) {
      continue;
    }
    vms_updated.insert(vm);

    if (!t->preload_globals.is_null() && fd < SYSCALLBUF_FDS_DISABLED_SIZE) {
      bool disable = is_fd_monitored_in_any_task(vm, fd);
      t->write_mem(
          REMOTE_PTR_FIELD(t->preload_globals, syscallbuf_fds_disabled[0]) + fd,
          (char)disable);
    }
  }
}

void FdTable::init_syscallbuf_fds_disabled(Task* t) {
  ASSERT(t, has_task(t));

  if (t->preload_globals.is_null()) {
    return;
  }

  char disabled[SYSCALLBUF_FDS_DISABLED_SIZE];
  memset(disabled, 0, sizeof(disabled));

  // It's possible that some tasks in this address space have a different
  // FdTable. We need to disable syscallbuf for an fd if any tasks for this
  // address space are monitoring the fd.
  for (Task* vm_t : t->vm()->task_set()) {
    for (auto& it : vm_t->fd_table()->fds) {
      int fd = it.first;
      assert(fd >= 0);
      if (fd < SYSCALLBUF_FDS_DISABLED_SIZE) {
        disabled[fd] = 1;
      }
    }
  }

  t->write_mem(REMOTE_PTR_FIELD(t->preload_globals, syscallbuf_fds_disabled[0]),
               disabled, SYSCALLBUF_FDS_DISABLED_SIZE);
}

static bool is_fd_open(Task* t, int fd) {
  char path[PATH_MAX];
  sprintf(path, "/proc/%d/fd/%d", t->tid, fd);
  struct stat st;
  return 0 == lstat(path, &st);
}

void FdTable::update_for_cloexec(Task* t, TraceTaskEvent& event) {
  ASSERT(t, has_task(t));

  vector<int> fds_to_close;

  if (t->session().is_recording()) {
    for (auto& it : fds) {
      if (!is_fd_open(t, it.first)) {
        fds_to_close.push_back(it.first);
      }
    }
    event.set_fds_to_close(fds_to_close);
  } else {
    fds_to_close = event.fds_to_close();
  }

  for (auto fd : fds_to_close) {
    did_close(fd);
  }
}

} // namespace rr
