/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "SeccompFilterRewriter.h"

#include <linux/filter.h>
#include <linux/seccomp.h>

#include <algorithm>

#include "AddressSpace.h"
#include "AutoRemoteSyscalls.h"
#include "RecordTask.h"
#include "Registers.h"
#include "ThreadGroup.h"
#include "kernel_abi.h"
#include "log.h"
#include "seccomp-bpf.h"

using namespace std;

namespace rr {

static void set_syscall_result(RecordTask* t, long ret) {
  Registers r = t->regs();
  r.set_syscall_result(ret);
  t->set_regs(r);
}

static void pass_through_seccomp_filter(RecordTask* t) {
  long ret;
  {
    AutoRemoteSyscalls remote(t);
    ret = remote.syscall(t->regs().original_syscallno(), t->regs().arg1(),
                         t->regs().arg2(), t->regs().arg3());
  }
  set_syscall_result(t, ret);
  ASSERT(t, t->regs().syscall_failed());
}

template <typename Arch>
static void install_patched_seccomp_filter_arch(
    RecordTask* t, unordered_map<uint32_t, uint16_t>& result_to_index,
    vector<uint32_t>& index_to_result) {
  // Take advantage of the fact that the filter program is arg3() in both
  // prctl and seccomp syscalls.
  bool ok = true;
  auto prog =
      t->read_mem(remote_ptr<typename Arch::sock_fprog>(t->regs().arg3()), &ok);
  if (!ok) {
    // We'll probably return EFAULT but a kernel that doesn't support
    // seccomp(2) should return ENOSYS instead, so just run the original
    // system call to get the correct error.
    pass_through_seccomp_filter(t);
    return;
  }
  auto code = t->read_mem(prog.filter.rptr(), prog.len, &ok);
  if (!ok) {
    pass_through_seccomp_filter(t);
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
          ASSERT(t,
                 SeccompFilterRewriter::BASE_CUSTOM_DATA +
                         index_to_result.size() <
                     SECCOMP_RET_DATA)
              << "Too many distinct constants used in seccomp-bpf programs";
          result_to_index[u.k] = index_to_result.size();
          index_to_result.push_back(u.k);
        }
        u.k = (SeccompFilterRewriter::BASE_CUSTOM_DATA + result_to_index[u.k]) |
              SECCOMP_RET_TRACE;
      }
    }
  }

  SeccompFilter<typename Arch::sock_filter> f;
  for (auto& e : AddressSpace::rr_page_syscalls()) {
    if (e.privileged == AddressSpace::PRIVILEGED) {
      auto ip = AddressSpace::rr_page_syscall_exit_point(e.traced, e.privileged,
                                                         e.enabled);
      f.allow_syscalls_from_callsite(ip);
    }
  }
  f.filters.insert(f.filters.end(), code.begin(), code.end());

  long ret;
  {
    AutoRemoteSyscalls remote(t);
    AutoRestoreMem mem(
        remote, nullptr,
        sizeof(prog) + f.filters.size() * sizeof(typename Arch::sock_filter));
    auto code_ptr = mem.get().cast<typename Arch::sock_filter>();
    t->write_mem(code_ptr, f.filters.data(), f.filters.size());
    prog.len = f.filters.size();
    prog.filter = code_ptr;
    auto prog_ptr = remote_ptr<void>(code_ptr + f.filters.size())
                        .cast<typename Arch::sock_fprog>();
    t->write_mem(prog_ptr, prog);

    ret = remote.syscall(t->regs().original_syscallno(), t->regs().arg1(),
                         t->regs().arg2(), prog_ptr);
  }
  set_syscall_result(t, ret);

  if (!t->regs().syscall_failed()) {
    if (is_seccomp_syscall(t->regs().original_syscallno(), t->arch()) &&
        (t->regs().arg2() & SECCOMP_FILTER_FLAG_TSYNC)) {
      for (Task* tt : t->thread_group()->task_set()) {
        static_cast<RecordTask*>(tt)->prctl_seccomp_status = 2;
      }
    } else {
      t->prctl_seccomp_status = 2;
    }
  }
}

void SeccompFilterRewriter::install_patched_seccomp_filter(RecordTask* t) {
  RR_ARCH_FUNCTION(install_patched_seccomp_filter_arch, t->arch(), t,
                   result_to_index, index_to_result);
}

bool SeccompFilterRewriter::map_filter_data_to_real_result(RecordTask* t,
                                                           uint16_t value,
                                                           uint32_t* result) {
  if (value < BASE_CUSTOM_DATA) {
    return false;
  }
  ASSERT(t, value < BASE_CUSTOM_DATA + index_to_result.size());
  *result = index_to_result[value - BASE_CUSTOM_DATA];
  return true;
}

} // namespace rr
