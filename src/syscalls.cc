/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "syscalls.h"

#include <assert.h>
#include <syscall.h>

#include "kernel_abi.h"

using namespace rr;

#include "SyscallnameArch.generated"

const char* syscall_name(int syscall, SupportedArch arch) {
  RR_ARCH_FUNCTION(syscallname_arch, arch, syscall)
}
