/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "FileMonitor.h"

#include <linux/limits.h>

#include <rr/rr.h>

#include <vector>

#include "RecordTask.h"
#include "ReplayTask.h"
#include "Session.h"
#include "log.h"

namespace rr {
using namespace std;

template <typename Arch>
static bool is_implicit_offset_syscall_arch(int syscallno) {
  return syscallno == Arch::writev || syscallno == Arch::write ||
         syscallno == Arch::readv || syscallno == Arch::read;
}

template <typename Arch>
static bool is_write_syscall_arch(int syscallno) {
  return syscallno == Arch::writev || syscallno == Arch::write ||
         syscallno == Arch::pwrite64 || syscallno == Arch::pwritev;
}

static bool is_implict_offset_syscall(SupportedArch arch, int syscallno) {
  RR_ARCH_FUNCTION(is_implicit_offset_syscall_arch, arch, syscallno);
}

template <typename Arch>
static int64_t retrieve_offset_arch(Task* t, int syscallno,
                                    const Registers& regs) {
  switch (syscallno) {
    case Arch::pwrite64:
    case Arch::pwritev:
    case Arch::pread64:
    case Arch::preadv: {
      if (sizeof(typename Arch::unsigned_word) == 4) {
        return regs.arg4() | (uint64_t(regs.arg5_signed()) << 32);
      }
      return regs.arg4_signed();
    }
    case Arch::readv:
    case Arch::read:
    case Arch::writev:
    case Arch::write: {
      ASSERT(t, t->session().is_recording())
          << "Can only read a file descriptor's offset while recording";
      int fd = regs.orig_arg1_signed();
      int64_t offset = t->fd_offset(fd);
      return is_write_syscall_arch<Arch>(syscallno) ?
        // The pos we just read, was after the write completed. Luckily, we do
        // know how many bytes were written.
        offset - regs.syscall_result() :
        offset;
    }
    default: {
      ASSERT(t, false) << "Can not retrieve offset for this system call.";
      return -1;
    }
  }
}

static int64_t retrieve_offset(Task* t, int syscallno, const Registers& regs) {
  RR_ARCH_FUNCTION(retrieve_offset_arch, t->arch(), t, syscallno, regs);
}

int64_t FileMonitor::LazyOffset::retrieve(bool needed_for_replay) {
  bool is_replay = t->session().is_replaying();
  bool is_implicit_offset = is_implict_offset_syscall(t->arch(), syscallno);
  ASSERT(t, needed_for_replay || !is_replay);
  // There is no way we can figure out this information now, so retrieve it
  // from the trace (we record it below under the same circumstance).
  if (is_replay && is_implicit_offset) {
    return static_cast<ReplayTask*>(t)
        ->current_trace_frame()
        .event()
        .Syscall()
        .write_offset;
  }
  int64_t offset = retrieve_offset(t, syscallno, regs);
  if (needed_for_replay && is_implicit_offset) {
    static_cast<RecordTask*>(t)->ev().Syscall().write_offset = offset;
  }
  return offset;
}
}
