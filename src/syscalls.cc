/* -*- Mode: C++; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "syscalls.h"

#include <assert.h>
#include <syscall.h>

const char* syscallname(int syscall, supported_arch arch)
{
	assert(arch == x86);
	switch (syscall) {
#define SYSCALLNO_X86(num)
#define SYSCALLNO_X86_64(num)
#define SYSCALL_UNDEFINED_X86_64()
#define CASE(_name) 					\
		case static_cast<int>(SyscallsX86::_name): return #_name;
#define SYSCALL_DEF0(_name, _)				\
		CASE(_name)
#define SYSCALL_DEF1(_name, _, _1, _2)			\
		CASE(_name)
#define SYSCALL_DEF1_DYNSIZE(_name, _, _1, _2)		\
		CASE(_name)
#define SYSCALL_DEF1_STR(_name, _, _1)			\
		CASE(_name)
#define SYSCALL_DEF2(_name, _, _1, _2, _3, _4)		\
		CASE(_name)
#define SYSCALL_DEF3(_name, _, _1, _2, _3, _4, _5, _6)	\
		CASE(_name)
#define SYSCALL_DEF4(_name, _, _1, _2, _3, _4, _5, _6, _7, _8)	\
		CASE(_name)
#define SYSCALL_DEF_IRREG(_name, _)			\
		CASE(_name)
#define SYSCALL_DEF_UNSUPPORTED(_name)			\
		CASE(_name)

#include "syscall_defs.h"

#undef CASE

	case SYS_restart_syscall:
		return "restart_syscall";
	default:
		return "<unknown-syscall>";
	}
}
