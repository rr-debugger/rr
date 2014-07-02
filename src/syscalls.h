/* -*- Mode: C++; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#ifndef RR_SYSCALLS_H_
#define RR_SYSCALLS_H_

#include "types.h"

enum class SyscallsX86 {

#define SYSCALLNO_X86(num)				\
		dummy_ ## num = num - 1,
#define SYSCALL_DEF0(_name, _type)			\
		_name,
#define SYSCALL_DEF1(_name, _type, _1, _2)		\
		_name,
#define SYSCALL_DEF1_DYNSIZE(_name, _type, _1, _2)	\
		_name,
#define SYSCALL_DEF1_STR(_name, _type, _1)		\
		_name,
#define SYSCALL_DEF2(_name, _type, _1, _2, _3, _4)	\
		_name,
#define SYSCALL_DEF3(_name, _type, _1, _2, _3, _4, _5, _6)	\
		_name,
#define SYSCALL_DEF4(_name, _type, _1, _2, _3, _4, _5, _6, _7, _8)	\
		_name,
#define SYSCALL_DEF_IRREG(_name, _type)			\
		_name,
#define SYSCALL_DEF_UNSUPPORTED(_name)			\
		_name,

#include "syscall_defs.h"

	COUNT
};

/**
 * Return the symbolic name of |syscall|, f.e. "read", or "???syscall"
 * if unknown.
 */
const char* syscallname(int syscall, supported_arch arch);

#endif
