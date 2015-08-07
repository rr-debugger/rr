/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "SeccompFilterRewriter.h"

#include <linux/filter.h>
#include <linux/seccomp.h>

#include <algorithm>

#include "AddressSpace.h"
#include "AutoRemoteSyscalls.h"
#include "kernel_abi.h"
#include "log.h"
#include "Registers.h"
#include "seccomp-bpf.h"
#include "task.h"

using namespace std;

static void set_syscall_result(Task* t, long ret) {
  Registers r = t->regs();
  r.set_syscall_result(ret);
  t->set_regs(r);
}

template <typename Arch>
static void install_patched_seccomp_filter_arch(Task* t) {
  // Take advantage of the fact that the filter program is arg3() in both
  // prctl and seccomp syscalls.
  bool ok = true;
  auto prog =
      t->read_mem(remote_ptr<typename Arch::sock_fprog>(t->regs().arg3()), &ok);
  if (!ok) {
    set_syscall_result(t, -EFAULT);
    return;
  }
  auto code = t->read_mem(prog.filter.rptr(), prog.len, &ok);
  if (!ok) {
    set_syscall_result(t, -EFAULT);
    return;
  }
  // Convert ERRNO/TRAP returns to TRACE returns so that rr can handle them.
  // See handle_ptrace_event in RecordSession.
  for (auto& u : code) {
    if (BPF_CLASS(u.code) == BPF_RET) {
      // XXX If we need to support RET with A/X registers, we should
      // extend the filter patch to dynamically cap the errno (if any) to
      // max_errno and switch to SECCOMP_RET_TRACE.
      ASSERT(t, BPF_RVAL(u.code) == BPF_K)
          << "seccomp-bpf program uses BPF_RET with A/X register, not "
             "supported";
      if ((u.k & SECCOMP_RET_ACTION) == SECCOMP_RET_ERRNO) {
        // The kernel caps the max errno to 4095, so we may as well do that
        // here. This means filter data values > 4095 cannot be generated
        // by this filter, which lets us disambiguate seccomp errno filter
        // returns from our filter returns.
        int filter_errno = min<int>(MAX_ERRNO, u.k & SECCOMP_RET_DATA);
        // Instead of forcing an errno return directly, trigger a ptrace
        // trap so we can detect and handle it.
        u.k = filter_errno | SECCOMP_RET_TRACE;
      } else if ((u.k & SECCOMP_RET_ACTION) == SECCOMP_RET_TRAP) {
        ASSERT(t, (u.k & SECCOMP_RET_DATA) == 0)
            << "nonzero SECCOMP_RET_DATA not supported for SECCOMP_RET_TRAP";
        u.k = EMULATE_RET_TRAP | SECCOMP_RET_TRACE;
      }
    }
  }

  uintptr_t privileged_in_untraced_syscall_ip =
      AddressSpace::rr_page_ip_in_privileged_untraced_syscall()
          .register_value();
  uintptr_t privileged_in_traced_syscall_ip =
      AddressSpace::rr_page_ip_in_privileged_traced_syscall().register_value();
  assert(privileged_in_untraced_syscall_ip ==
         uint32_t(privileged_in_untraced_syscall_ip));
  assert(privileged_in_traced_syscall_ip ==
         uint32_t(privileged_in_traced_syscall_ip));

  static const typename Arch::sock_filter prefix[] = {
    ALLOW_SYSCALLS_FROM_CALLSITE(uint32_t(privileged_in_untraced_syscall_ip)),
    ALLOW_SYSCALLS_FROM_CALLSITE(uint32_t(privileged_in_traced_syscall_ip))
  };
  code.insert(code.begin(), prefix, prefix + array_length(prefix));

  long ret;
  {
    AutoRemoteSyscalls remote(t);
    AutoRestoreMem mem(remote, nullptr,
                       sizeof(prog) +
                           code.size() * sizeof(typename Arch::sock_filter));
    auto code_ptr = mem.get().cast<typename Arch::sock_filter>();
    t->write_mem(code_ptr, code.data(), code.size());
    prog.len = code.size();
    prog.filter = code_ptr;
    auto prog_ptr = remote_ptr<void>(code_ptr + code.size())
                        .cast<typename Arch::sock_fprog>();
    t->write_mem(prog_ptr, prog);

    ret = remote.syscall(t->regs().original_syscallno(), t->regs().arg1(),
                         t->regs().arg2(), prog_ptr);
  }
  set_syscall_result(t, ret);
}

void SeccompFilterRewriter::install_patched_seccomp_filter(Task* t) {
  RR_ARCH_FUNCTION(install_patched_seccomp_filter_arch, t->arch(), t);
}
