/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_REGISTERS_H_
#define RR_REGISTERS_H_

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <vector>

#include "GDBRegister.h"
#include "kernel_abi.h"
#include "kernel_supplement.h"
#include "remote_ptr.h"

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
  Registers() { memset(&u, 0, sizeof(u)); }

  SupportedArch arch() const {
    // TODO: make the architecture settable, so we can exec 32-bit processes
    // from 64-bit ones and vice-versa.
#if defined(__x86_64__)
    return x86_64;
#elif defined(__i386__)
    return x86;
#else
#error unknown CPU architecture
#endif
  }

  // Return a pointer that can be passed to ptrace's PTRACE_GETREGS et al.
  void* ptrace_registers() {
    switch (arch()) {
      case x86:
        return &u.x86regs;
      case x86_64:
        return &u.x64regs;
      default:
        assert(0 && "unknown architecture");
    }
  }

  const void* ptrace_registers() const {
    switch (arch()) {
      case x86:
        return &u.x86regs;
      case x86_64:
        return &u.x64regs;
      default:
        assert(0 && "unknown architecture");
    }
  }

#define RR_GET_REG(x86case, x64case)                                           \
  (arch() == x86 ? u.x86regs.x86case                                           \
                 : arch() == x86_64                                            \
                       ? u.x64regs.x64case                                     \
                       : (assert(0 && "unknown architecture"), uintptr_t(-1)))
#define RR_SET_REG(x86case, x64case, value)                                    \
  switch (arch()) {                                                            \
    case x86:                                                                  \
      u.x86regs.x86case = (value);                                             \
      break;                                                                   \
    case x86_64:                                                               \
      u.x64regs.x64case = (value);                                             \
      break;                                                                   \
    default:                                                                   \
      assert(0 && "unknown architecture");                                     \
  }

  uintptr_t ip() const { return RR_GET_REG(eip, rip); }
  void set_ip(uintptr_t addr) { RR_SET_REG(eip, rip, addr); }
  uintptr_t sp() const { return RR_GET_REG(esp, rsp); }
  void set_sp(uintptr_t addr) { RR_SET_REG(esp, rsp, addr); }

  // Access the registers holding system-call numbers, results, and
  // parameters.

  intptr_t syscallno() const { return RR_GET_REG(eax, rax); }
  void set_syscallno(intptr_t syscallno) { RR_SET_REG(eax, rax, syscallno); }

  uintptr_t syscall_result() const { return RR_GET_REG(eax, rax); }
  intptr_t syscall_result_signed() const { return RR_GET_REG(eax, rax); }
  void set_syscall_result(uintptr_t syscall_result) {
    RR_SET_REG(eax, rax, syscall_result);
  }
  template <typename T> void set_syscall_result(remote_ptr<T> syscall_result) {
    RR_SET_REG(eax, rax, syscall_result.as_int());
  }

  /**
   * Returns true if syscall_result() indicates failure.
   */
  bool syscall_failed() const {
    auto result = syscall_result_signed();
    return -ERANGE <= result && result < 0;
  }
  /**
   * Returns true if syscall_result() indicates a syscall restart.
   */
  bool syscall_may_restart() const {
    switch (-syscall_result_signed()) {
      case ERESTART_RESTARTBLOCK:
      case ERESTARTNOINTR:
      case ERESTARTNOHAND:
      case ERESTARTSYS:
        return true;
      default:
        return false;
    }
  }

  /**
   * This pseudo-register holds the system-call number when we get ptrace
   * enter-system-call and exit-system-call events. Setting it changes
   * the system-call executed when resuming after an enter-system-call
   * event.
   */
  intptr_t original_syscallno() const { return RR_GET_REG(orig_eax, orig_rax); }
  void set_original_syscallno(intptr_t syscallno) {
    RR_SET_REG(orig_eax, orig_rax, syscallno);
  }

  uintptr_t arg1() const { return RR_GET_REG(ebx, rdi); }
  intptr_t arg1_signed() const { return RR_GET_REG(ebx, rdi); }
  void set_arg1(uintptr_t value) { RR_SET_REG(ebx, rdi, value); }
  template <typename T> void set_arg1(remote_ptr<T> value) {
    RR_SET_REG(ebx, rdi, value.as_int());
  }

  uintptr_t arg2() const { return RR_GET_REG(ecx, rsi); }
  intptr_t arg2_signed() const { return RR_GET_REG(ecx, rsi); }
  void set_arg2(uintptr_t value) { RR_SET_REG(ecx, rsi, value); }
  template <typename T> void set_arg2(remote_ptr<T> value) {
    RR_SET_REG(ecx, rsi, value.as_int());
  }

  uintptr_t arg3() const { return RR_GET_REG(edx, rdx); }
  intptr_t arg3_signed() const { return RR_GET_REG(edx, rdx); }
  void set_arg3(uintptr_t value) { RR_SET_REG(edx, rdx, value); }
  template <typename T> void set_arg3(remote_ptr<T> value) {
    RR_SET_REG(edx, rdx, value.as_int());
  }

  uintptr_t arg4() const { return RR_GET_REG(esi, r10); }
  intptr_t arg4_signed() const { return RR_GET_REG(esi, r10); }
  void set_arg4(uintptr_t value) { RR_SET_REG(esi, r10, value); }
  template <typename T> void set_arg4(remote_ptr<T> value) {
    RR_SET_REG(esi, r10, value.as_int());
  }

  uintptr_t arg5() const { return RR_GET_REG(edi, r8); }
  intptr_t arg5_signed() const { return RR_GET_REG(edi, r8); }
  void set_arg5(uintptr_t value) { RR_SET_REG(edi, r8, value); }
  template <typename T> void set_arg5(remote_ptr<T> value) {
    RR_SET_REG(edi, r8, value.as_int());
  }

  uintptr_t arg6() const { return RR_GET_REG(ebp, r9); }
  intptr_t arg6_signed() const { return RR_GET_REG(ebp, r9); }
  void set_arg6(uintptr_t value) { RR_SET_REG(ebp, r9, value); }
  template <typename T> void set_arg6(remote_ptr<T> value) {
    RR_SET_REG(ebp, r9, value.as_int());
  }

  /**
   * Set the output registers of the |rdtsc| instruction.
   */
  void set_rdtsc_output(uint64_t value) {
    RR_SET_REG(eax, rax, value & 0xffffffff);
    RR_SET_REG(edx, rdx, value >> 32);
  }

  /**
   * Set the register containing syscall argument |Index| to
   * |value|.
   */
  template <int Index, typename T> void set_arg(T value) {
    set_arg<Index>(uintptr_t(value));
  }

  template <int Index, typename T> void set_arg(remote_ptr<T> value) {
    set_arg<Index>(value.as_int());
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
  void print_register_file_for_trace(FILE* f) const;
  void print_register_file_for_trace_raw(FILE* f) const;

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
  size_t total_registers() const;

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
  template <typename Arch>
  void print_register_file_arch(FILE* f, const char* formats[]) const;

  enum TraceStyle {
    Annotated,
    Raw,
  };

  template <typename Arch>
  void print_register_file_for_trace_arch(FILE* f, TraceStyle style,
                                          const char* formats[]) const;

  template <typename Arch>
  static bool compare_registers_arch(const char* name1, const Registers* reg1,
                                     const char* name2, const Registers* reg2,
                                     int mismatch_behavior);

  template <typename Arch>
  size_t read_register_arch(uint8_t* buf, GDBRegister regno,
                            bool* defined) const;

  template <typename Arch>
  void write_register_arch(GDBRegister regno, const uint8_t* value,
                           size_t value_size);

  template <typename Arch> size_t total_registers_arch() const;

  union AllRegisters {
    rr::X86Arch::user_regs_struct x86regs;
    rr::X64Arch::user_regs_struct x64regs;
  } u;
};

#endif /* RR_REGISTERS_H_ */
