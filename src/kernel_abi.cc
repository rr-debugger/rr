/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

// Include remote_ptr.h first since it (indirectly) requires a definition of
// ERANGE, which other headers below #undef :-(
#include "remote_ptr.h"

// Get all the kernel definitions so we can verify our alternative versions.
#include <arpa/inet.h>
#include <asm/ldt.h>
#include <dirent.h>
#include <elf.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <linux/ethtool.h>
#include <linux/filter.h>
#include <linux/futex.h>
#include <linux/if_bonding.h>
#include <linux/ipc.h>
#include <linux/mqueue.h>
#include <linux/msg.h>
#include <linux/net.h>
#include <linux/netfilter/x_tables.h>
#include <linux/sem.h>
#include <linux/shm.h>
#include <linux/sockios.h>
#include <linux/sysctl.h>
#include <linux/usbdevice_fs.h>
#include <linux/videodev2.h>
#include <linux/wireless.h>
#include <poll.h>
#include <signal.h>
#include <sound/asound.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/quota.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/timex.h>
#include <sys/un.h>
#include <sys/user.h>
#include <sys/utsname.h>
#include <sys/vfs.h>
#include <termios.h>

// Used to verify definitions in kernel_abi.h
namespace rr {
#define RR_VERIFY_TYPE_ARCH(arch_, system_type_, rr_type_)                     \
  static_assert(Verifier<arch_, system_type_, rr_type_>::same_size,            \
                "type " #system_type_ " not correctly defined");

// For instances where the system type and the rr type are named differently.
#define RR_VERIFY_TYPE_EXPLICIT(system_type_, rr_type_)                        \
  RR_VERIFY_TYPE_ARCH(arch_, system_type_, rr_type_)

// For instances where the system type and the rr type are named identically.
#define RR_VERIFY_TYPE(type_) RR_VERIFY_TYPE_EXPLICIT(::type_, type_)
}

#include "kernel_abi.h"

#include <stdlib.h>

#include "AddressSpace.h"
#include "Session.h"
#include "Task.h"

#include "preload/preload_interface.h"

using namespace std;

namespace rr {

#define CHECK_ELF(cond)                                                        \
  static_assert(cond, "ELF constant defined incorrectly" #cond)

CHECK_ELF(ELFCLASSNONE == ELFCLASS::CLASSNONE);
CHECK_ELF(ELFCLASS32 == ELFCLASS::CLASS32);
CHECK_ELF(ELFCLASS64 == ELFCLASS::CLASS64);

CHECK_ELF(EM_386 == EM::I386);
CHECK_ELF(EM_X86_64 == EM::X86_64);

CHECK_ELF(ELFDATA2LSB == ELFENDIAN::DATA2LSB);

static const uint8_t int80_insn[] = { 0xcd, 0x80 };
static const uint8_t sysenter_insn[] = { 0x0f, 0x34 };
static const uint8_t syscall_insn[] = { 0x0f, 0x05 };

bool get_syscall_instruction_arch(Task* t, remote_code_ptr ptr,
                                  SupportedArch* arch) {
  // Lots of syscalls occur in the rr page and we know what it contains without
  // looking at it.
  // (Without this optimization we spend a few % of all CPU time in this
  // function in a syscall-dominated trace.)
  if (t->vm()->has_rr_page()) {
    const AddressSpace::SyscallType* type =
        AddressSpace::rr_page_syscall_from_entry_point(ptr);
    if (type && (type->enabled == AddressSpace::RECORDING_AND_REPLAY ||
                 type->enabled == (t->session().is_recording()
                                       ? AddressSpace::RECORDING_ONLY
                                       : AddressSpace::REPLAY_ONLY))) {
      // rr-page syscalls are always the task's arch
      *arch = t->arch();
      return true;
    }
  }

  bool ok = true;
  vector<uint8_t> code = t->read_mem(ptr.to_data_ptr<uint8_t>(), 2, &ok);
  if (!ok) {
    return false;
  }
  switch (t->arch()) {
    // Compatibility mode switch can happen in user space (but even without
    // such tricks, int80, which uses the 32bit syscall table, can be invoked
    // from 64bit processes).
    case x86:
    case x86_64:
      if (memcmp(code.data(), int80_insn, sizeof(int80_insn)) == 0 ||
          memcmp(code.data(), sysenter_insn, sizeof(sysenter_insn)) == 0) {
        *arch = x86;
      } else if (memcmp(code.data(), syscall_insn, sizeof(syscall_insn)) == 0) {
        *arch = x86_64;
      } else {
        return false;
      }
      return true;
    default:
      return false;
  }
}

bool is_at_syscall_instruction(Task* t, remote_code_ptr ptr) {
  SupportedArch arch;
  return get_syscall_instruction_arch(t, ptr, &arch);
}

vector<uint8_t> syscall_instruction(SupportedArch arch) {
  switch (arch) {
    case x86:
      return vector<uint8_t>(int80_insn, int80_insn + sizeof(int80_insn));
    case x86_64:
      return vector<uint8_t>(syscall_insn, syscall_insn + sizeof(syscall_insn));
    default:
      DEBUG_ASSERT(0 && "Need to define syscall instruction");
      return vector<uint8_t>();
  }
}

ssize_t syscall_instruction_length(SupportedArch arch) {
  switch (arch) {
    case x86:
    case x86_64:
      return 2;
    default:
      DEBUG_ASSERT(0 && "Need to define syscall instruction length");
      return 0;
  }
}

template <typename Arch>
static void assign_sigval(typename Arch::sigval_t& to,
                          const NativeArch::sigval_t& from) {
  // si_ptr/si_int are a union and we don't know which part is valid.
  // The only case where it matters is when we're mapping 64->32, in which
  // case we can just assign the ptr first (which is bigger) and then the
  // int (to be endian-independent).
  to.sival_ptr = from.sival_ptr.rptr();
  to.sival_int = from.sival_int;
}

template <typename Arch>
static void set_arch_siginfo_arch(const siginfo_t& src, void* dest,
                                  size_t dest_size) {
  // Copying this structure field-by-field instead of just memcpy'ing
  // siginfo into si serves two purposes: performs 64->32 conversion if
  // necessary, and ensures garbage in any holes in siginfo isn't copied to the
  // tracee.
  auto si = static_cast<typename Arch::siginfo_t*>(dest);
  DEBUG_ASSERT(dest_size == sizeof(*si));

  union {
    NativeArch::siginfo_t native_api;
    siginfo_t linux_api;
  } u;
  u.linux_api = src;
  auto& siginfo = u.native_api;

  si->si_signo = siginfo.si_signo;
  si->si_errno = siginfo.si_errno;
  si->si_code = siginfo.si_code;
  switch (siginfo.si_code) {
    case SI_USER:
    case SI_TKILL:
      si->_sifields._kill.si_pid_ = siginfo._sifields._kill.si_pid_;
      si->_sifields._kill.si_uid_ = siginfo._sifields._kill.si_uid_;
      break;
    case SI_QUEUE:
    case SI_MESGQ:
      si->_sifields._rt.si_pid_ = siginfo._sifields._rt.si_pid_;
      si->_sifields._rt.si_uid_ = siginfo._sifields._rt.si_uid_;
      assign_sigval<Arch>(si->_sifields._rt.si_sigval_,
                          siginfo._sifields._rt.si_sigval_);
      break;
    case SI_TIMER:
      si->_sifields._timer.si_overrun_ = siginfo._sifields._timer.si_overrun_;
      si->_sifields._timer.si_tid_ = siginfo._sifields._timer.si_tid_;
      assign_sigval<Arch>(si->_sifields._timer.si_sigval_,
                          siginfo._sifields._timer.si_sigval_);
      break;
    default:
      switch (siginfo.si_signo) {
        case SIGCHLD:
          si->_sifields._sigchld.si_pid_ = siginfo._sifields._sigchld.si_pid_;
          si->_sifields._sigchld.si_uid_ = siginfo._sifields._sigchld.si_uid_;
          si->_sifields._sigchld.si_status_ =
              siginfo._sifields._sigchld.si_status_;
          si->_sifields._sigchld.si_utime_ =
              siginfo._sifields._sigchld.si_utime_;
          si->_sifields._sigchld.si_stime_ =
              siginfo._sifields._sigchld.si_stime_;
          break;
        case SIGILL:
        case SIGBUS:
        case SIGFPE:
        case SIGSEGV:
        case SIGTRAP:
          si->_sifields._sigfault.si_addr_ =
              siginfo._sifields._sigfault.si_addr_.rptr();
          si->_sifields._sigfault.si_addr_lsb_ =
              siginfo._sifields._sigfault.si_addr_lsb_;
          break;
        case SIGIO:
          si->_sifields._sigpoll.si_band_ = siginfo._sifields._sigpoll.si_band_;
          si->_sifields._sigpoll.si_fd_ = siginfo._sifields._sigpoll.si_fd_;
          break;
        case SIGSYS:
          si->_sifields._sigsys._call_addr =
              siginfo._sifields._sigsys._call_addr.rptr();
          si->_sifields._sigsys._syscall = siginfo._sifields._sigsys._syscall;
          si->_sifields._sigsys._arch = siginfo._sifields._sigsys._arch;
          break;
      }
  }
}

void set_arch_siginfo(const siginfo_t& siginfo, SupportedArch a, void* dest,
                      size_t dest_size) {
  RR_ARCH_FUNCTION(set_arch_siginfo_arch, a, siginfo, dest, dest_size);
}
}
