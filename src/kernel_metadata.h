/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_SYSCALLS_H_
#define RR_SYSCALLS_H_

#include "kernel_abi.h"

/**
 * Return the symbolic name of |syscall|, f.e. "read", or "???syscall"
 * if unknown.
 */
const char* syscall_name(int syscall, SupportedArch arch);

#endif
