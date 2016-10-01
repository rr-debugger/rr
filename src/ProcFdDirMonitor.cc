/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "ProcFdDirMonitor.h"

#include <dirent.h>
#include <stdlib.h>

#include "AutoRemoteSyscalls.h"
#include "RecordSession.h"
#include "RecordTask.h"
#include "log.h"

using namespace std;

namespace rr {

ProcFdDirMonitor::ProcFdDirMonitor(Task* t, const string& pathname) {
  // XXX this makes some assumptions about namespaces... Probably fails
  // if |t| is not the same pid namespace as rr
  int ends_with_slash = (pathname.back() == '/');
  if (pathname.substr(0, 6) == string("/proc/") &&
      pathname.substr(pathname.size() - 3 - ends_with_slash, 3) ==
          string("/fd")) {
    string s = pathname.substr(6, pathname.size() - 9 - ends_with_slash);
    char* end;
    int tid = strtol(s.c_str(), &end, 10);
    if (!*end) {
      Task* target = t->session().find_task(tid);
      if (target) {
        tuid = target->tuid();
      }
    }
  }
}

// returns the number of valid dirent structs left in the buffer
template <typename D>
static int filter_dirent_structs(RecordTask* t, uint8_t* buf, size_t size) {
  int bytes = 0;
  size_t current_offset = 0;
  while (1) {
    if (current_offset == size) {
      break;
    }

    D* current_struct = reinterpret_cast<D*>(buf + current_offset);
    auto next_off = current_offset + current_struct->d_reclen;

    char* fname = (char*)current_struct->d_name;
    char* end;
    int fd = strtol(fname, &end, 10);
    if (!*end && t->fd_table()->is_rr_fd(fd)) {
      // Skip this entry.
      memmove(current_struct, buf + next_off, size - next_off);
      size -= (next_off - current_offset);
      next_off = current_offset;
    } else {
      // Either this is a tracee fd or not an fd at all (e.g. '.')
      bytes += current_struct->d_reclen;
    }

    current_offset = next_off;
  }

  return bytes;
}

template <typename Arch> static void filter_dirents_arch(RecordTask* t) {
  auto regs = t->regs();
  remote_ptr<uint8_t> ptr(regs.arg2());
  size_t len = regs.arg3();

  if (regs.syscall_failed() || !regs.syscall_result()) {
    return;
  }

  while (1) {
    vector<uint8_t> buf = t->read_mem(ptr, len);
    int bytes = regs.syscall_result();
    if (regs.original_syscallno() == Arch::getdents64) {
      bytes =
          filter_dirent_structs<typename Arch::dirent64>(t, buf.data(), bytes);
    } else {
      bytes =
          filter_dirent_structs<typename Arch::dirent>(t, buf.data(), bytes);
    }

    if (bytes > 0) {
      t->write_mem(ptr, buf.data(), bytes);
      regs.set_syscall_result(bytes);
      t->set_regs(regs);
      // Explicitly record what the kernel may have touched and we discarded,
      // because it's userspace modification that will not be caught otherwise.
      if (len > (size_t)bytes) {
        t->record_remote(ptr + bytes, len - bytes);
      }
      return;
    }

    // We filtered out all the entries, so we need to repeat the syscall.
    {
      AutoRemoteSyscalls remote(t);
      remote.syscall(regs.original_syscallno(), regs.arg1(), regs.arg2(),
                     regs.arg3());
      // Only copy over the syscall result. In particular, we don't want to
      // copy the AutoRemoteSyscalls ip().
      regs.set_syscall_result(t->regs().syscall_result());
    }

    if (regs.syscall_failed() || regs.syscall_result() == 0) {
      // Save the new syscall result, and record the buffer we will otherwise
      // ignore.
      t->record_remote(ptr, len);
      t->set_regs(regs);
      return;
    }
  }
}

static void filter_dirents(RecordTask* t) {
  RR_ARCH_FUNCTION(filter_dirents_arch, t->arch(), t);
}

void ProcFdDirMonitor::filter_getdents(RecordTask* t) {
  ASSERT(t, !t->session().is_replaying());
  auto* target = static_cast<RecordTask*>(t->session().find_task(tuid));
  if (!target) {
    return;
  }

  filter_dirents(t);
}

} // namespace rr
