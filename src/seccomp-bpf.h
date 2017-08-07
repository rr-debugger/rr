/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

/*
 * seccomp example for x86 (32-bit and 64-bit) with BPF macros
 *
 * Copyright (c) 2012 The Chromium OS Authors <chromium-os-dev@chromium.org>
 * Authors:
 *  Will Drewry <wad@chromium.org>
 *  Kees Cook <keescook@chromium.org>
 *
 * The code may be used by anyone for any purpose, and can serve as a
 * starting point for developing applications using mode 2 seccomp.
 */
#ifndef RR_SECCOMP_BPF_H_
#define RR_SECCOMP_BPF_H_

#define _GNU_SOURCE 1
#include <errno.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <asm/unistd.h>

#include <vector>

#include "core.h"
#include "remote_code_ptr.h"

#include <sys/prctl.h>
#include <sys/user.h>
#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#endif

#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/unistd.h>
#ifdef HAVE_LINUX_SECCOMP_H
#include <linux/seccomp.h>
#endif
#ifndef SECCOMP_MODE_FILTER
#define SECCOMP_MODE_FILTER 2 /* uses user-supplied filter. */

#define SECCOMP_RET_KILL 0x00000000U
#define SECCOMP_RET_TRAP 0x00030000U
#define SECCOMP_RET_ERRNO 0x00050000U
#define SECCOMP_RET_TRACE 0x7ff00000U
#define SECCOMP_RET_ALLOW 0x7fff0000U

#define SECCOMP_RET_ACTION 0x7fff0000U
#define SECCOMP_RET_DATA 0x0000ffffU

struct seccomp_data {
  int nr;
  __u32 arch;
  __u64 instruction_pointer;
  __u64 args[6];
};
#endif

namespace rr {

#define inst_ptr (offsetof(struct seccomp_data, instruction_pointer))

template <typename T> class SeccompFilter {
public:
  void allow() {
    filters.push_back(BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_ALLOW));
  }
  void trace() {
    filters.push_back(
        BPF_STMT(BPF_RET + BPF_K, SECCOMP_RET_TRACE | SECCOMP_RET_DATA));
  }
  void allow_syscalls_from_callsite(remote_code_ptr ip) {
    uint32_t v(ip.register_value());
    DEBUG_ASSERT(ip.register_value() == v);
    filters.push_back(BPF_STMT(BPF_LD + BPF_W + BPF_ABS, inst_ptr));
    filters.push_back(BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, v, 0, 1));
    allow();
  }
  std::vector<T> filters;
};
}

#endif /* RR_SECCOMP_BPF_H_ */
