/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "FdTable.h"

#include <unordered_set>

#include "task.h"

using namespace std;

void FdTable::dup(int from, int to) {
  if (fds.count(from)) {
    fds[to] = fds[from];
  } else {
    fds.erase(to);
  }
  update_syscallbuf_fds_disabled(to);
}

void FdTable::close(int fd) {
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

  unordered_set<AddressSpace*> vms_updated;
  // It's possible for tasks with different VMs to share this fd table.
  // But tasks with the same VM might have different fd tables...
  for (Task* t : task_set()) {
    AddressSpace* vm = t->vm().get();
    if (vms_updated.find(vm) != vms_updated.end()) {
      continue;
    }
    vms_updated.insert(vm);

    if (!t->syscallbuf_fds_disabled_child.is_null() &&
        fd < SYSCALLBUF_FDS_DISABLED_SIZE) {
      bool is_monitored = is_fd_monitored_in_any_task(vm, fd);
      t->write_mem(t->syscallbuf_fds_disabled_child + fd, (char)is_monitored);
    }
  }
}

void FdTable::init_syscallbuf_fds_disabled(Task* t) {
  if (t->syscallbuf_fds_disabled_child.is_null()) {
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

  t->write_mem(t->syscallbuf_fds_disabled_child, disabled,
               SYSCALLBUF_FDS_DISABLED_SIZE);
}
