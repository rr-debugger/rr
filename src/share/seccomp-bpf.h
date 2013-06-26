/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

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
#ifndef _SECCOMP_BPF_H_
#define _SECCOMP_BPF_H_

#define _GNU_SOURCE 1
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <errno.h>
#include <signal.h>
#include <string.h>
#include <unistd.h>

#include <asm/unistd.h>

#include <sys/user.h>
#include <sys/prctl.h>
#ifndef PR_SET_NO_NEW_PRIVS
# define PR_SET_NO_NEW_PRIVS 38
#endif

#include <linux/unistd.h>
#include <linux/audit.h>
#include <linux/filter.h>
#ifdef HAVE_LINUX_SECCOMP_H
# include <linux/seccomp.h>
#endif
#ifndef SECCOMP_MODE_FILTER
# define SECCOMP_MODE_FILTER	2 /* uses user-supplied filter. */
# define SECCOMP_RET_KILL	0x00000000U /* kill the task immediately */
# define SECCOMP_RET_TRAP	0x00030000U /* disallow and force a SIGSYS */
# define SECCOMP_RET_ALLOW	0x7fff0000U /* allow */
# define SECCOMP_RET_TRACE	0x7ff00000U /* trace */
struct seccomp_data {
    int nr;
    __u32 arch;
    __u64 instruction_pointer;
    __u64 args[6];
};
#endif
#ifndef SYS_SECCOMP
# define SYS_SECCOMP 1
#endif

#define syscall_nr (offsetof(struct seccomp_data, nr))
#define arch_nr (offsetof(struct seccomp_data, arch))
#define inst_ptr (offsetof(struct seccomp_data, instruction_pointer))
#define args(i) (offsetof(struct seccomp_data, args[i]))

#if defined(__i386__)
# define REG_SYSCALL	REG_EAX
# define ARCH_NR	AUDIT_ARCH_I386
#elif defined(__x86_64__)
# define REG_SYSCALL	REG_RAX
# define ARCH_NR	AUDIT_ARCH_X86_64
#else
# warning "Platform does not support seccomp filter yet"
# define REG_SYSCALL	0
# define ARCH_NR	0
#endif

#define EXAMINE_SYSCALL \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, syscall_nr)

/**
 * this macro determines whether the instruction pointer is within the given
 * library bounds and trace the call if it is not. If it is, allow it to continue.
 *
 * logic is:
 * if eip > libend goto trace;
 * if eip >= libstart goto continue;
 * allow if clone or fork
 * kill if poll or socket
 * trace;
 * continue;
 */

#define ALLOW_SYSCALLS_FROM_CALLSITE(callsite) \
 	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, inst_ptr), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, callsite, 0, 1), \
	ALLOW_PROCESS

#define ALLOW_SYSCALL(name) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_##name, 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)

#define KILL_SYSCALL(name) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_##name, 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL)

/**
 * logic is:
 * if !socketcall goto continue;
 * grab the operation from arg0
 * if (op is blocking) goto trace;
 * allow;
 * trace;
 * continue filtering;
 */
#define ALLOW_SOCKETCALL \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_socketcall, 0, 5), \
	BPF_STMT(BPF_LD+BPF_W+BPF_ABS, args(0)), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SYS_RECV, 2, 0), \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, SYS_ACCEPT, 1, 0), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRACE)

#define TRACE_SYSCALL(name) \
	BPF_JUMP(BPF_JMP+BPF_JEQ+BPF_K, __NR_##name, 0, 1), \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRACE)

#define KILL_PROCESS \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_KILL)

#define ALLOW_PROCESS \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_ALLOW)

#define TRACE_PROCESS \
	BPF_STMT(BPF_RET+BPF_K, SECCOMP_RET_TRACE)

#endif /* _SECCOMP_BPF_H_ */
