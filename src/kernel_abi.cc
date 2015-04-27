/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "kernel_abi.h"

#include <stdlib.h>

#include "task.h"

using namespace std;

static const uint8_t int80_insn[] = { 0xcd, 0x80 };
static const uint8_t sysenter_insn[] = { 0x0f, 0x34 };
static const uint8_t syscall_insn[] = { 0x0f, 0x05 };

namespace rr {

bool is_at_syscall_instruction(Task* t, remote_code_ptr ptr) {
  vector<uint8_t> code = t->read_mem(ptr.to_data_ptr<uint8_t>(), 2);
  switch (t->arch()) {
    case x86:
      return memcmp(code.data(), int80_insn, sizeof(int80_insn)) == 0 ||
             memcmp(code.data(), sysenter_insn, sizeof(sysenter_insn)) == 0;
    case x86_64:
      return memcmp(code.data(), syscall_insn, sizeof(syscall_insn)) == 0 ||
             memcmp(code.data(), sysenter_insn, sizeof(sysenter_insn)) == 0;
    default:
      assert(0 && "Need to define syscall instructions");
      return false;
  }
}

vector<uint8_t> syscall_instruction(SupportedArch arch) {
  switch (arch) {
    case x86:
      return vector<uint8_t>(int80_insn, int80_insn + sizeof(int80_insn));
    case x86_64:
      return vector<uint8_t>(syscall_insn, syscall_insn + sizeof(syscall_insn));
    default:
      assert(0 && "Need to define syscall instruction");
      return vector<uint8_t>();
  }
}

ssize_t syscall_instruction_length(SupportedArch arch) {
  switch (arch) {
    case x86:
    case x86_64:
      return 2;
    default:
      assert(0 && "Need to define syscall instruction length");
      return 0;
  }
}
}
