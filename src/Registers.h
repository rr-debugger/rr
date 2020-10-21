/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_REGISTERS_H_
#define RR_REGISTERS_H_

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/user.h>

#include "GdbRegister.h"
#include "core.h"
#include "kernel_abi.h"
#include "remote_code_ptr.h"
#include "remote_ptr.h"

struct iovec;

namespace rr {

class ReplayTask;

enum MismatchBehavior {
  EXPECT_MISMATCHES = 0,
  LOG_MISMATCHES,
  BAIL_ON_MISMATCH
};

const uintptr_t X86_RESERVED_FLAG = 1 << 1;
const uintptr_t X86_ZF_FLAG = 1 << 6;
const uintptr_t X86_TF_FLAG = 1 << 8;
const uintptr_t X86_IF_FLAG = 1 << 9;
const uintptr_t X86_DF_FLAG = 1 << 10;
const uintptr_t X86_RF_FLAG = 1 << 16;
const uintptr_t X86_ID_FLAG = 1 << 21;

const uintptr_t AARCH64_DBG_SPSR_SS = 1 << 21;

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
 *
 * We have different register sets for different architectures. To ensure a
 * trace can be dumped/processed by an rr build on any platform, we allow
 * Registers to contain registers for any architecture. So we store them
 * in a union of Arch::user_regs_structs for each known Arch.
 */
class Registers {
public:
  enum { MAX_SIZE = 16 };

  Registers(SupportedArch a = SupportedArch(-1)) : arch_(a) {
    memset(&u, 0, sizeof(u));
  }

  SupportedArch arch() const { return arch_; }

  void set_arch(SupportedArch a) { arch_ = a; }

  /**
   * Copy a user_regs_struct into these Registers. If the tracee architecture
   * is not rr's native architecture, then it must be a 32-bit tracee with a
   * 64-bit rr. In that case the user_regs_struct is 64-bit and we extract
   * the 32-bit register values from it into u.x86regs.
   * It's invalid to call this when the Registers' arch is 64-bit and the
   * rr build is 32-bit, or when the Registers' arch is completely different
   * to the rr build (e.g. ARM vs x86).
   */
  void set_from_ptrace(const NativeArch::user_regs_struct& ptrace_regs);

  /**
   * Get a user_regs_struct from these Registers. If the tracee architecture
   * is not rr's native architecture, then it must be a 32-bit tracee with a
   * 64-bit rr. In that case the user_regs_struct is 64-bit and we copy
   * the 32-bit register values from u.x86regs into it.
   * It's invalid to call this when the Registers' arch is 64-bit and the
   * rr build is 32-bit, or when the Registers' arch is completely different
   * to the rr build (e.g. ARM vs x86).
   */
  NativeArch::user_regs_struct get_ptrace() const;
  iovec get_ptrace_iovec();

  /**
   * Get a user_regs_struct for a particular Arch from these Registers.
   * It's invalid to call this when 'arch' is 64-bit and the
   * rr build is 32-bit, or when the Registers' arch is completely different
   * to the rr build (e.g. ARM vs x86).
   */
  std::vector<uint8_t> get_ptrace_for_arch(SupportedArch arch) const;
  struct InternalData {
    const uint8_t* data;
    size_t size;
  };

  /**
   * Get the register content to save in the trace.
   */
  InternalData get_regs_for_trace() const;

  /**
   * Equivalent to get_ptrace_for_arch(arch()) but doesn't copy.
   */
  InternalData get_ptrace_for_self_arch() const;

  /**
   * Copy an arch-specific user_regs_struct into these Registers.
   * It's invalid to call this when 'arch' is 64-bit and the
   * rr build is 32-bit, or when the Registers' arch is completely different
   * to the rr build (e.g. ARM vs x86).
   */
  void set_from_ptrace_for_arch(SupportedArch arch, const void* data,
                                size_t size);

  /**
   * Copy from the arch-specific structure returned in get_regs_for_trace()
   * back into *this
   */
  void set_from_trace(SupportedArch arch, const void* data,
                      size_t size);

#define ARCH_SWITCH_CASE(rettype, x86case, x64case, arm64case)                 \
(([=](void) -> rettype {                                                       \
  switch (arch()) {                                                            \
    default:                                                                   \
      DEBUG_ASSERT(0 && "unknown architecture");                               \
      RR_FALLTHROUGH; /* Fall through to avoid warnings */                     \
    case x86: {                                                                \
      x86case;                                                                 \
      break;                                                                   \
    }                                                                          \
    case x86_64: {                                                             \
      x64case;                                                                 \
      break;                                                                   \
    }                                                                          \
    case aarch64: {                                                            \
      arm64case;                                                               \
      break;                                                                   \
    }                                                                          \
  }                                                                            \
})())

#define RR_GET_REG(x86case, x64case, arm64case)                                \
  ARCH_SWITCH_CASE(uint64_t,                                                   \
    return (uint32_t)u.x86regs.x86case,                                        \
    return u.x64regs.x64case,                                                  \
    return u.arm64regs.arm64case)

#define RR_GET_REG_SIGNED(x86case, x64case, arm64case)                         \
  ARCH_SWITCH_CASE(int64_t,                                                    \
    return (int32_t)u.x86regs.x86case,                                         \
    return u.x64regs.x64case,                                                  \
    return u.arm64regs.arm64case)

#define RR_GET_REG_X86(x86case, x64case)                                       \
  ARCH_SWITCH_CASE(uint64_t,                                                   \
    return (uint32_t)u.x86regs.x86case,                                        \
    return u.x64regs.x64case,                                                  \
    DEBUG_ASSERT(0 && "Hit an x86-only case, but this is not x86"); return 0)

#define RR_UPDATE_CHECK(loc, value) bool changed = (uintptr_t)loc != (uintptr_t)(value); \
  loc = (value); \
  return changed;
#define RR_SET_REG(x86case, x64case, arm64case, value)                         \
  ARCH_SWITCH_CASE(bool,                                                       \
    RR_UPDATE_CHECK(u.x86regs.x86case, value),                                 \
    RR_UPDATE_CHECK(u.x64regs.x64case, value),                                 \
    RR_UPDATE_CHECK(u.arm64regs.arm64case, value))

#define RR_SET_REG_X86(x86case, x64case, value)                                \
  ARCH_SWITCH_CASE(bool,                                                       \
    RR_UPDATE_CHECK(u.x86regs.x86case, value),                                 \
    RR_UPDATE_CHECK(u.x64regs.x64case, value),                                 \
    DEBUG_ASSERT(0 && "Hit an x86-only case, but this is not x86"); return false)

  remote_code_ptr ip() const { return RR_GET_REG(eip, rip, pc); }
  bool set_ip(remote_code_ptr addr) {
    return RR_SET_REG(eip, rip, pc, addr.register_value());
  }
  remote_ptr<void> sp() const { return RR_GET_REG(esp, rsp, sp); }
  bool set_sp(remote_ptr<void> addr) { return RR_SET_REG(esp, rsp, sp, addr.as_int()); }

  // Access the registers holding system-call numbers, results, and
  // parameters.

  intptr_t syscallno() const { return (int)RR_GET_REG(eax, rax, x[8]); }
  bool set_syscallno(intptr_t syscallno) { return RR_SET_REG(eax, rax, x[8], syscallno); }

  /**
   * This pseudo-register holds the system-call number when we get ptrace
   * enter-system-call and exit-system-call events. Setting it changes
   * the system-call executed when resuming after an enter-system-call
   * event.
   */
  intptr_t original_syscallno() const {
    return RR_GET_REG_SIGNED(orig_eax, orig_rax, orig_syscall);
  }
  bool set_original_syscallno(intptr_t syscallno) {
    return RR_SET_REG(orig_eax, orig_rax, orig_syscall, syscallno);
  }

  #define SYSCALL_REGISTER(name, x86case, x64case, arm64case)                  \
  uintptr_t name() const { return RR_GET_REG(x86case, x64case, arm64case); }   \
  intptr_t name ## _signed() const {                                           \
    return RR_GET_REG_SIGNED(x86case, x64case, arm64case);                     \
  }                                                                            \
  bool set_ ## name(uintptr_t value) {                                         \
    return RR_SET_REG(x86case, x64case, arm64case, value);                     \
  }                                                                            \
  template <typename T> bool set_ ## name(remote_ptr<T> value) {               \
    return RR_SET_REG(x86case, x64case, arm64case, value.as_int());            \
  }

  SYSCALL_REGISTER(syscall_result, eax, rax, x[0]);
  SYSCALL_REGISTER(orig_arg1, ebx, rdi, orig_x0)
  SYSCALL_REGISTER(arg1, ebx, rdi, x[0])
  SYSCALL_REGISTER(arg2, ecx, rsi, x[1])
  SYSCALL_REGISTER(arg3, edx, rdx, x[2])
  SYSCALL_REGISTER(arg4, esi, r10, x[3])
  SYSCALL_REGISTER(arg5, edi, r8, x[4])
  SYSCALL_REGISTER(arg6, ebp, r9, x[5])

  uintptr_t arg(int index) const {
    switch (index) {
      case 1:
        return arg1();
      case 2:
        return arg2();
      case 3:
        return arg3();
      case 4:
        return arg4();
      case 5:
        return arg5();
      case 6:
        return arg6();
      default:
        DEBUG_ASSERT(0 && "Argument index out of range");
        return 0;
    }
  }

  /**
   * Set the register containing syscall argument |Index| to
   * |value|.
   */
  template <int Index> bool set_arg(std::nullptr_t) { return set_arg(Index, 0); }
  template <int Index, typename T> bool set_arg(remote_ptr<T> value) {
    return set_arg(Index, value.as_int());
  }
  template <int Index, typename T> bool set_arg(T value) {
    return set_arg(Index, uintptr_t(value));
  }

  bool set_arg(int index, uintptr_t value) {
    switch (index) {
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
      default:
        DEBUG_ASSERT(0 && "Argument index out of range");
        return false;
    }
  }

  bool set_orig_arg(int index, uintptr_t value) {
    switch (index) {
      case 1:
        return set_orig_arg1(value);
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
      default:
        DEBUG_ASSERT(0 && "Argument index out of range");
        return false;
    }
  }

  /**
   * Returns true if syscall_result() indicates failure.
   */
  bool syscall_failed() const;

  /**
   * Returns true if syscall_result() indicates a syscall restart.
   */
  bool syscall_may_restart() const;

  // Some X86-specific stuff follows. Use of these accessors should be guarded
  // by an architecture test.
  /**
   * Set the output registers of the |rdtsc| instruction.
   */
  void set_rdtsc_output(uint64_t value) {
    RR_SET_REG_X86(eax, rax, value & 0xffffffff);
    RR_SET_REG_X86(edx, rdx, value >> 32);
  }

  void set_cpuid_output(uint32_t eax, uint32_t ebx, uint32_t ecx,
                        uint32_t edx) {
    RR_SET_REG_X86(eax, rax, eax);
    RR_SET_REG_X86(ebx, rbx, ebx);
    RR_SET_REG_X86(ecx, rcx, ecx);
    RR_SET_REG_X86(edx, rdx, edx);
  }

  bool set_r8(uintptr_t value) {
    DEBUG_ASSERT(arch() == x86_64);
    RR_UPDATE_CHECK(u.x64regs.r8, value);
  }

  bool set_r9(uintptr_t value) {
    DEBUG_ASSERT(arch() == x86_64);
    RR_UPDATE_CHECK(u.x64regs.r9, value);
  }

  bool set_r10(uintptr_t value) {
    DEBUG_ASSERT(arch() == x86_64);
    RR_UPDATE_CHECK(u.x64regs.r10, value);
  }

  bool set_r11(uintptr_t value) {
    DEBUG_ASSERT(arch() == x86_64);
    RR_UPDATE_CHECK(u.x64regs.r11, value);
  }

  uintptr_t di() const { return RR_GET_REG_X86(edi, rdi); }
  bool set_di(uintptr_t value) { return RR_SET_REG_X86(edi, rdi, value); }

  uintptr_t si() const { return RR_GET_REG_X86(esi, rsi); }
  bool set_si(uintptr_t value) { return RR_SET_REG_X86(esi, rsi, value); }

  uintptr_t cx() const { return RR_GET_REG_X86(ecx, rcx); }
  bool set_cx(uintptr_t value) { return RR_SET_REG_X86(ecx, rcx, value); }

  uintptr_t ax() const { return RR_GET_REG_X86(eax, rax); }
  uintptr_t bp() const { return RR_GET_REG_X86(ebp, rbp); }

  uintptr_t flags() const { return RR_GET_REG_X86(eflags, eflags); };
  bool set_flags(uintptr_t value) { return RR_SET_REG_X86(eflags, eflags, value); }
  bool zf_flag() const { return flags() & X86_ZF_FLAG; }
  bool df_flag() const { return flags() & X86_DF_FLAG; }

  uintptr_t fs_base() const {
    DEBUG_ASSERT(arch() == x86_64);
    return u.x64regs.fs_base;
  }
  uintptr_t gs_base() const {
    DEBUG_ASSERT(arch() == x86_64);
    return u.x64regs.gs_base;
  }

  void set_fs_base(uintptr_t fs_base) {
    DEBUG_ASSERT(arch() == x86_64);
    u.x64regs.fs_base = fs_base;
  }
  void set_gs_base(uintptr_t gs_base) {
    DEBUG_ASSERT(arch() == x86_64);
    u.x64regs.gs_base = gs_base;
  }

  uint64_t cs() const { return RR_GET_REG_X86(xcs, cs); }
  uint64_t ss() const { return RR_GET_REG_X86(xss, ss); }
  uint64_t ds() const { return RR_GET_REG_X86(xds, ds); }
  uint64_t es() const { return RR_GET_REG_X86(xes, es); }
  uint64_t fs() const { return RR_GET_REG_X86(xfs, fs); }
  uint64_t gs() const { return RR_GET_REG_X86(xgs, gs); }

  // End of X86-specific stuff
  // Begin aarch64 specific accessors
  uintptr_t pstate() const {
    DEBUG_ASSERT(arch() == aarch64);
    return u.arm64regs.pstate;
  }

  void set_pstate(uintptr_t pstate) {
    DEBUG_ASSERT(arch() == aarch64);
    u.arm64regs.pstate = pstate;
  }

  void set_x7(uintptr_t x7) {
    DEBUG_ASSERT(arch() == aarch64);
    u.arm64regs.x[7] = x7;
  }

  uintptr_t x1() const {
    DEBUG_ASSERT(arch() == aarch64);
    return u.arm64regs.x[1];
  }

  uintptr_t x7() const {
    DEBUG_ASSERT(arch() == aarch64);
    return u.arm64regs.x[7];
  }
  // End of aarch64 specific accessors

  /**
   * Modify the processor's single step flag. On x86 this is the TF flag in the
   * eflags register.
   */
  bool x86_singlestep_flag();
  void clear_x86_singlestep_flag();

  /**
   * Aarch64 has two flags that control single stepping. An EL1 one that
   * enables singlestep execeptions and an EL0 one in pstate (SPSR_SS). The EL1 bit
   * is controlled by PTRACE_SINGLESTEP (it gets turned on upon the first
   * PTRACE_(SYSEMU_)SINGLESTEP and turned off on any other ptrace resume).
   * The EL0 bit controls whether an exception is taken *before* execution
   * of the next instruction (an exception is taken when the bit is *clear*).
   * The hardware clears this bit whenever an instruction completes. Thus, to
   * ensure that a single step actually happens, regardless of how we got to
   * this step, we must both using PTRACE_SINGLESTEP and *set* the SPSR_SS bit.
   * Otherwise, if we got to this stop via single step, the SPSR_SS bit will
   * likely already be clear, and we'd take a single step exception without
   * ever having executed any userspace instructions whatsoever.
   */
  bool aarch64_singlestep_flag();
  void set_aarch64_singlestep_flag();

  void print_register_file(FILE* f) const;
  void print_register_file_compact(FILE* f) const;
  void print_register_file_for_trace_raw(FILE* f) const;

  /**
   * Return true if |reg1| matches |reg2|.  Passing EXPECT_MISMATCHES
   * indicates that the caller is using this as a general register
   * compare and nothing special should be done if the register files
   * mismatch.  Passing LOG_MISMATCHES will log the registers that don't
   * match.  Passing BAIL_ON_MISMATCH will additionally abort on
   * mismatch.
   */
  static bool compare_register_files(ReplayTask* t, const char* name1,
                                     const Registers& reg1, const char* name2,
                                     const Registers& reg2,
                                     MismatchBehavior mismatch_behavior);

  bool matches(const Registers& other) const {
    return compare_register_files(nullptr, nullptr, *this, nullptr, other,
                                  EXPECT_MISMATCHES);
  }

  // TODO: refactor me to use the GdbRegisterValue helper from
  // GdbConnection.h.

  /**
   * Write the value for register |regno| into |buf|, which should
   * be large enough to hold any register supported by the target.
   * Return the size of the register in bytes and set |defined| to
   * indicate whether a useful value has been written to |buf|.
   */
  size_t read_register(uint8_t* buf, GdbRegister regno, bool* defined) const;

  /**
   * Write the value for register |offset| into |buf|, which should
   * be large enough to hold any register supported by the target.
   * Return the size of the register in bytes and set |defined| to
   * indicate whether a useful value has been written to |buf|.
   * |offset| is the offset of the register within a user_regs_struct.
   */
  size_t read_register_by_user_offset(uint8_t* buf, uintptr_t offset,
                                      bool* defined) const;

  /**
   * Update the register named |reg_name| to |value| with
   * |value_size| number of bytes.
   */
  void write_register(GdbRegister reg_name, const void* value,
                      size_t value_size);

  /**
   * Update the register at user offset |offset| to |value|, taking the low
   * bytes if necessary.
   */
  void write_register_by_user_offset(uintptr_t offset, uintptr_t value);


  bool operator==(const Registers &other) const {
    if (arch() != other.arch()) {
      return false;
    }
    switch (arch()) {
      case x86:
        return memcmp(&u.x86regs, &other.u.x86regs, sizeof(u.x86regs)) == 0;
      case x86_64:
        return memcmp(&u.x64regs, &other.u.x64regs, sizeof(u.x64regs)) == 0;
      case aarch64:
        return memcmp(&u.arm64regs, &other.u.arm64regs, sizeof(u.arm64regs)) == 0;
      default:
        DEBUG_ASSERT(0 && "Unknown architecture");
        return false;
    }
  }

  bool operator!=(const Registers &other) const {
    return !(*this == other);
  }

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
  static bool compare_registers_core(const char* name1, const Registers& reg1,
                                     const char* name2, const Registers& reg2,
                                     MismatchBehavior mismatch_behavior);

  template <typename Arch>
  static bool compare_registers_arch(const char* name1, const Registers& reg1,
                                     const char* name2, const Registers& reg2,
                                     MismatchBehavior mismatch_behavior);

  static bool compare_register_files_internal(
      const char* name1, const Registers& reg1, const char* name2,
      const Registers& reg2, MismatchBehavior mismatch_behavior);

  template <typename Arch>
  size_t read_register_arch(uint8_t* buf, GdbRegister regno,
                            bool* defined) const;

  template <typename Arch>
  size_t read_register_by_user_offset_arch(uint8_t* buf, uintptr_t offset,
                                           bool* defined) const;

  template <typename Arch>
  void write_register_arch(GdbRegister regno, const void* value,
                           size_t value_size);

  template <typename Arch>
  void write_register_by_user_offset_arch(uintptr_t offset, uintptr_t value);

  template <typename Arch> size_t total_registers_arch() const;

  SupportedArch arch_;
  union {
    rr::X86Arch::user_regs_struct x86regs;
    rr::X64Arch::user_regs_struct x64regs;
    struct {
      // This is the NT_PRSTATUS regset
      union {
        rr::ARM64Arch::user_regs_struct _ptrace;
        // This duplicates the field names of the user_regs_struct and makes
        // them available as fields of arm64regs for easy access.
        struct {
          uint64_t x[31];
          uint64_t sp;
          uint64_t pc;
          uint64_t pstate;
        };
      };
      // This is not exposed through GETREGSET. We track it manually
      uint64_t orig_x0;
      // This is the NT_ARM_SYSTEM_CALL regset
      int orig_syscall;
    } arm64regs;
  } u;
};

template <typename ret, typename callback>
ret with_converted_registers(const Registers& regs, SupportedArch arch,
                             callback f) {
  if (regs.arch() != arch) {
    // If this is a cross architecture syscall, first convert the registers.
    Registers converted_regs(arch);
    std::vector<uint8_t> data = regs.get_ptrace_for_arch(arch);
    converted_regs.set_from_ptrace_for_arch(arch, data.data(), data.size());
    return f(converted_regs);
  }
  return f(regs);
}

std::ostream& operator<<(std::ostream& stream, const Registers& r);

} // namespace rr

#endif /* RR_REGISTERS_H_ */
