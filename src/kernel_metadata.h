/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_SYSCALLS_H_
#define RR_SYSCALLS_H_

#include <signal.h>

#include <iostream>
#include <string>

#include "kernel_abi.h"

namespace rr {

/**
 * Return the symbolic name of the architecture `arch`.
 */
std::string arch_name(SupportedArch arch);

/**
 * Return the symbolic name of |syscall|, f.e. "read", or "syscall(%d)"
 * if unknown.
 */
std::string syscall_name(int syscall, SupportedArch arch);

/**
 * Return the symbolic name of the PTRACE_EVENT_* |event|, or
 * "PTRACE_EVENT(%d)" if unknown.
 */
std::string ptrace_event_name(int event);

/**
 * Return the symbolic name of the PTRACE_ |request|, or "PTRACE_REQUEST(%d)" if
 * unknown.
 */
template <typename Arch>
std::string ptrace_req_name(int request);

/**
 * Return the symbolic name of |sig|, f.e. "SIGILL", or "signal(%d)" if
 * unknown.
 */
std::string signal_name(int sig);

/**
 * Return true if this is some kind of sigreturn syscall.
 */
bool is_sigreturn(int syscall, SupportedArch arch);

/**
 * Return the symbolic error name (e.g. "EINVAL") for errno.
 */
std::string errno_name(int err);

/* Same as errno_name, but returns a pointer to static memory or NULL if
allocation would be required. Suitable for use in volatile contexts */
const char *errno_name_cstr(int err);

/**
 * Return the symbolic name (e.g. "SI_USER") for an si_code.
 */
std::string sicode_name(int code, int sig);

int shm_flags_to_mmap_prot(int flags);

/**
 * Print string explaining xsave feature bits
 */
std::string xsave_feature_string(uint64_t xsave_features);

/**
 * Return whether this is a core dumping signal or not.
 */
bool is_coredumping_signal(int signo);

/**
 * Convert a raw native siginfo_t to our arch siginfo_t.
 */
NativeArch::siginfo_t convert_to_native_siginfo(SupportedArch arch,
    const void* data, size_t size);

std::string prot_flags_string(int prot);

} // namespace rr

#endif
