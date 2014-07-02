/* -*- Mode: C++; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#ifndef RR_SYSCALLS_H_
#define RR_SYSCALLS_H_

#include "types.h"

/**
 * Return the symbolic name of |syscall|, f.e. "read", or "???syscall"
 * if unknown.
 */
const char* syscallname(int syscall, supported_arch arch);

#endif
