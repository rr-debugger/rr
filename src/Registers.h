/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_REGISTERS_H_
#define RR_REGISTERS_H_

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include <vector>

#include "GDBRegister.h"
#include "kernel_abi.h"

/**
 * A Registers object contains values for all general-purpose registers.
 * These must include all registers used to pass syscall parameters and return
 * syscall results.
 *
 * When reading register values, be sure to cast the result to the correct
 * type according to the kernel docs. E.g. int values should be cast
 * to int explicitly (or implicitly, by assigning to an int-typed variable),
 * size_t should be cast to size_t, etc. If the type is signed, call the
 * _signed getter. This ensures that when building rr 64-bit we will use the
 * right number of register bits whether the tracee is 32-bit or 64-bit, and
 * get sign-extension right.
 */
class Registers {
public:
  SupportedArch arch() const { return x86; }

  // Return a pointer that can be passed to ptrace's PTRACE_GETREGS et al.
  void* ptrace_registers() { return &u.x86regs; }

  uintptr_t ip() const { return u.x86regs.eip; }
  void set_ip(uintptr_t addr) { u.x86regs.eip = addr; }
  uintptr_t sp() const { return u.x86regs.esp; }
  void set_sp(uintptr_t addr) { u.x86regs.esp = addr; }
  uintptr_t fp() const { return u.x86regs.ebp; }
  void set_fp(uintptr_t addr) { u.x86regs.ebp = addr; }

  // Access the registers holding system-call numbers, results, and
  // parameters.

  intptr_t syscallno() const { return u.x86regs.eax; }
  void set_syscallno(intptr_t syscallno) { u.x86regs.eax = syscallno; }

  uintptr_t syscall_result() const { return u.x86regs.eax; }
  intptr_t syscall_result_signed() const { return u.x86regs.eax; }
  void set_syscall_result(uintptr_t syscall_result) { u.x86regs.eax = syscall_result; }

  /**
   * This pseudo-register holds the system-call number when we get ptrace
   * enter-system-call and exit-system-call events. Setting it changes
   * the system-call executed when resuming after an enter-system-call
   * event.
   */
  intptr_t original_syscallno() const { return u.x86regs.orig_eax; }
  void set_original_syscallno(intptr_t syscallno) { u.x86regs.orig_eax = syscallno; }

  uintptr_t arg1() const { return u.x86regs.ebx; }
  intptr_t arg1_signed() const { return u.x86regs.ebx; }
  void set_arg1(uintptr_t value) { u.x86regs.ebx = value; }

  uintptr_t arg2() const { return u.x86regs.ecx; }
  intptr_t arg2_signed() const { return u.x86regs.ecx; }
  void set_arg2(uintptr_t value) { u.x86regs.ecx = value; }

  uintptr_t arg3() const { return u.x86regs.edx; }
  intptr_t arg3_signed() const { return u.x86regs.edx; }
  void set_arg3(uintptr_t value) { u.x86regs.edx = value; }

  uintptr_t arg4() const { return u.x86regs.esi; }
  intptr_t arg4_signed() const { return u.x86regs.esi; }
  void set_arg4(uintptr_t value) { u.x86regs.esi = value; }

  uintptr_t arg5() const { return u.x86regs.edi; }
  intptr_t arg5_signed() const { return u.x86regs.edi; }
  void set_arg5(uintptr_t value) { u.x86regs.edi = value; }

  uintptr_t arg6() const { return u.x86regs.ebp; }
  intptr_t arg6_signed() const { return u.x86regs.ebp; }
  void set_arg6(uintptr_t value) { u.x86regs.ebp = value; }

  /**
   * Set the output registers of the |rdtsc| instruction.
   */
  void set_rdtsc_output(uint64_t value) {
    u.x86regs.eax = value & 0xffffffff;
    u.x86regs.edx = value >> 32;
  }

  /**
   * Set the register containing syscall argument |Index| to
   * |value|.
   */
  template <int Index, typename T> void set_arg(T value) {
    set_arg<Index>(uintptr_t(value));
  }

  template <int Index> void set_arg(uintptr_t value) {
    static_assert(1 <= Index && Index <= 6, "Index must be in range");
    switch (Index) {
      case 1:
        return set_arg1(value);
      case 2:
        return set_arg2(value);
      case 3:
        return set_arg3(value);
      case 4:
        return set_arg4(value);
      case 5:
        return set_arg5(value);
      case 6:
        return set_arg6(value);
    }
  }

  void print_register_file(FILE* f) const;
  void print_register_file_compact(FILE* f) const;
  void print_register_file_for_trace(FILE*, bool raw_dump) const;

  /**
   * Return true if |reg1| matches |reg2|.  If |mismatch_behavior|
   * is BAIL_ON_MISMATCH, mismatched registers will be logged as
   * errors; if |mismatch_behavior| is LOG_MISMATCHES, mismatched
   * registers will be logged as informative messages.
   */
  static bool compare_register_files(const char* name1, const Registers* reg1,
                                     const char* name2, const Registers* reg2,
                                     int mismatch_behavior);

  /**
   * Return the total number of registers for this target.
   */
  size_t total_registers() const { return DREG_NUM_LINUX_I386; }

  // TODO: refactor me to use the DbgRegister helper from
  // debugger_gdb.h.

  /**
   * Write the value for register |regno| into |buf|, which should
   * be large enough to hold any register supported by the target.
   * Return the size of the register in bytes and set |defined| to
   * indicate whether a useful value has been written to |buf|.
   */
  size_t read_register(uint8_t* buf, GDBRegister regno, bool* defined) const;

  /**
   * Update the registe named |reg_name| to |value| with
   * |value_size| number of bytes.
   */
  void write_register(GDBRegister reg_name, const uint8_t* value,
                      size_t value_size);

private:
  union AllRegisters {
    rr::X86Arch::user_regs_struct x86regs;
  } u;
};

#endif /* RR_REGISTERS_H_ */
