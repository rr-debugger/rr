/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_SYSCALLS_H_
#define RR_SYSCALLS_H_

#include "kernel_abi.h"

/**
 * Return the symbolic name of |syscall|, f.e. "read", or "???syscall"
 * if unknown.
 */
const char* syscall_name(int syscall, SupportedArch arch);

/**
 * Return the symbolic name of the PTRACE_EVENT_* |event|, or
 * "???EVENT" if unknown.
 */
const char* ptrace_event_name(int event);

/**
 * Return the symbolic name of the PTRACE_ |request|, or "???REQ" if
 * unknown.
 */
const char* ptrace_req_name(int request);

/**
 * Return the symbolic name of |sig|, f.e. "SIGILL", or "???signal" if
 * unknown.
 */
const char* signal_name(int sig);

/**
 * Return true iff replaying |syscall| will never ever require
 * actually executing it, i.e. replay of |syscall| is always
 * emulated.
 */
bool is_always_emulated_syscall(int syscall, SupportedArch arch);

#endif
