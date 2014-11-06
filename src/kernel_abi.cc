/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "kernel_abi.h"

using namespace rr;

const uint8_t X86Arch::syscall_insn[2] = { 0xcd, 0x80 };
const uint8_t X64Arch::syscall_insn[2] = { 0x0f, 0x05 };
