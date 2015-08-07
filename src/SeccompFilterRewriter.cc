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
static void install_patched_seccomp_filter_arch(
    Task* t, unordered_map<uint32_t, uint16_t>& result_to_index,
    vector<uint32_t>& index_to_result) {
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
  // Convert all returns to TRACE returns so that rr can handle them.
  // See handle_ptrace_event in RecordSession.
  for (auto& u : code) {
    if (BPF_CLASS(u.code) == BPF_RET) {
      ASSERT(t, BPF_RVAL(u.code) == BPF_K)
          << "seccomp-bpf program uses BPF_RET with A/X register, not "
             "supported";
      if (u.k != SECCOMP_RET_ALLOW) {
        if (result_to_index.find(u.k) == result_to_index.end()) {
          ASSERT(t, index_to_result.size() < SECCOMP_RET_DATA)
              << "Too many distinct constants used in seccomp-bpf programs";
          result_to_index[u.k] = index_to_result.size();
          index_to_result.push_back(u.k);
        }
        u.k = result_to_index[u.k] | SECCOMP_RET_TRACE;
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
  RR_ARCH_FUNCTION(install_patched_seccomp_filter_arch, t->arch(), t,
                   result_to_index, index_to_result);
}
