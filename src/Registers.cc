/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

//#define DEBUGTAG "registers"

#include "Registers.h"

#include <assert.h>
#include <string.h>

#include "log.h"
#include "util.h"

struct RegisterValue {
  // The name of this register.
  const char* name;
  // The offsetof the register in user_regs_struct.
  size_t offset;
  // The size of the register.  0 means we cannot read it.
  size_t nbytes;
  // Mask to be applied to register values prior to comparing them.  Will
  // typically be ((1 << nbytes) - 1), but some registers may have special
  // comparison semantics.
  uint64_t comparison_mask;

  constexpr RegisterValue()
    : name(nullptr), offset(0), nbytes(0), comparison_mask(0)
  {}

  RegisterValue(const char* name_, size_t offset_, size_t nbytes_)
    : name(name_), offset(offset_), nbytes(nbytes_)
  {
    comparison_mask = mask_for_nbytes(nbytes_);
  }

  RegisterValue(const char* name_, size_t offset_, size_t nbytes_,
                uint64_t comparison_mask_)
    : name(name_), offset(offset_), nbytes(nbytes_)
    , comparison_mask(comparison_mask_)
  {
    // Ensure no bits are set outside of the register's bitwidth.
    assert((comparison_mask_ & ~mask_for_nbytes(nbytes_)) == 0);
  }
  // Returns a pointer to the register in |regs| represented by |offset|.
  // |regs| is assumed to be a pointer to the user_struct_regs for the
  // appropriate architecture.
  void* pointer_into(void* regs) {
    return static_cast<char*>(regs) + offset;
  }

  const void* pointer_into(const void* regs) {
    return static_cast<const char*>(regs) + offset;
  }

private:
  uint64_t mask_for_nbytes(size_t nbytes) {
    assert(nbytes <= sizeof(comparison_mask));
    return ((nbytes == sizeof(comparison_mask)) ? uint64_t(0)
                                                : (uint64_t(1) << nbytes * 8)) -
           1;
  }
};

template<typename T>
struct RegisterInfo;

template<>
struct RegisterInfo<rr::X86Arch> {
  static bool ignore_undefined_register(GDBRegister regno) {
    return regno == DREG_FOSEG || regno == DREG_MXCSR;
  }
  static struct RegisterValue registers[DREG_NUM_LINUX_I386];
};

template<>
struct RegisterInfo<rr::X64Arch> {
  static bool ignore_undefined_register(GDBRegister regno) {
    return regno == DREG_64_FOSEG || regno == DREG_64_MXCSR;
  }
  static struct RegisterValue registers[DREG_NUM_LINUX_X86_64];
};

struct RegisterValue RegisterInfo<rr::X86Arch>::registers[DREG_NUM_LINUX_I386];
struct RegisterValue RegisterInfo<rr::X64Arch>::registers[DREG_NUM_LINUX_X86_64];

// You might think, "why can't we use designated initializers here?"  Doing so
// would be most convenient, except that designated initializers are not a part
// of C++11.  While they are sort-of-supported as a GNU extension in GCC
// (despite claims to the contrary in the manual), they are only supported so
// long as the index of your designated initializer corresponds to the index of
// the array you are initializing.  That is, they are useful for documentation
// purposes, but they are not useful for initializing a sparse array, as we
// have here.
static void initialize_register_tables() {
  static bool initialized = false;

  if (initialized) {
    return;
  }

#define RV_ARCH(gdb_suffix, name, arch, extra_ctor_args)        \
  do {                                          \
    size_t offset = offsetof(arch::user_regs_struct, name);     \
    size_t nbytes = sizeof(((arch::user_regs_struct*)0)->name); \
    RegisterInfo<arch>::registers[DREG_##gdb_suffix] =          \
      RegisterValue(#name, offset, nbytes extra_ctor_args);     \
  } while(0)
#define RV_X86(gdb_suffix, name)                \
  RV_ARCH(gdb_suffix, name, rr::X86Arch, /* empty */)
#define RV_X64(gdb_suffix, name)                \
  RV_ARCH(gdb_suffix, name, rr::X64Arch, /* empty */)
#define COMMA ,
#define RV_X86_WITH_MASK(gdb_suffix, name, comparison_mask)     \
  RV_ARCH(gdb_suffix, name, rr::X86Arch, COMMA comparison_mask)
#define RV_X64_WITH_MASK(gdb_suffix, name, comparison_mask)     \
  RV_ARCH(gdb_suffix, name, rr::X64Arch, COMMA comparison_mask)
  
  initialized = true;

  /* The following are eflags that have been observed to be non-deterministic
     in practice.  We need to mask them off when comparing registers to
     prevent replay from diverging.  */
  enum {
    /* The linux kernel has been observed to report this as zero in some
       states during system calls.  It always seems to be 1 during user-space
       execution so we should be able to ignore it.  */
    RESERVED_FLAG_1 = 1 << 1,
    /* According to http://www.logix.cz/michal/doc/i386/chp04-01.htm:

         The RF flag temporarily disables debug exceptions so that an 
         instruction can be restarted after a debug exception without
         immediately causing another debug exception.  Refer to Chapter 12
         for details.

       Chapter 12 isn't particularly clear on the point, but the flag appears
       to be set by |int3| exceptions.

       This divergence has been observed when continuing a tracee to an
       execution target by setting an |int3| breakpoint, which isn't used
       during recording.  No single-stepping was used during the recording
       either.  */
    RESUME_FLAG = 1 << 16,
    /* It is no longer knonw why this bit is ignored.  */
    CPUID_ENABLED_FLAG = 1 << 21,
  };
  const uint64_t deterministic_eflags_mask =
    ~uint32_t(RESERVED_FLAG_1 | RESUME_FLAG | CPUID_ENABLED_FLAG);

  RV_X86(EAX, eax);
  RV_X86(ECX, ecx);
  RV_X86(EDX, edx);
  RV_X86(EBX, ebx);
  RV_X86(ESP, esp);
  RV_X86(EBP, ebp);
  RV_X86(ESI, esi);
  RV_X86(EDI, edi);
  RV_X86(EIP, eip);
  RV_X86_WITH_MASK(EFLAGS, eflags, deterministic_eflags_mask);
  RV_X86_WITH_MASK(CS, xcs, 0);
  RV_X86_WITH_MASK(SS, xss, 0);
  RV_X86_WITH_MASK(DS, xds, 0);
  RV_X86_WITH_MASK(ES, xes, 0);
  RV_X86(FS, xfs);
  RV_X86(GS, xgs);
  // Handled specially elsewhere.
  RV_X86_WITH_MASK(ORIG_EAX, orig_eax, 0);

  RV_X64(RAX, rax);
  RV_X64(RCX, rcx);
  RV_X64(RDX, rdx);
  RV_X64(RBX, rbx);
  RV_X64_WITH_MASK(RSP, rsp, 0);
  RV_X64(RBP, rbp);
  RV_X64(RSI, rsi);
  RV_X64(RDI, rdi);
  RV_X64(R8, r8);
  RV_X64(R9, r9);
  RV_X64(R10, r10);
  RV_X64(R11, r11);
  RV_X64(R12, r12);
  RV_X64(R13, r13);
  RV_X64(R14, r14);
  RV_X64(R15, r15);
  RV_X64(RIP, rip);
  RV_X64_WITH_MASK(64_EFLAGS, eflags, deterministic_eflags_mask);
  RV_X64_WITH_MASK(64_CS, cs, 0);
  RV_X64_WITH_MASK(64_SS, ss, 0);
  RV_X64_WITH_MASK(64_DS, ds, 0);
  RV_X64_WITH_MASK(64_ES, es, 0);
  RV_X64(64_FS, fs);
  RV_X64(64_GS, gs);
  // Handled specially elsewhere.
  RV_X64_WITH_MASK(ORIG_RAX, orig_rax, 0);

#undef RV_X64
#undef RV_X86
#undef RV_ARCH
}

void Registers::print_register_file(FILE* f) const {
  fprintf(f, "Printing register file:\n");
  fprintf(f, "eax: %x\n", u.x86regs.eax);
  fprintf(f, "ebx: %x\n", u.x86regs.ebx);
  fprintf(f, "ecx: %x\n", u.x86regs.ecx);
  fprintf(f, "edx: %x\n", u.x86regs.edx);
  fprintf(f, "esi: %x\n", u.x86regs.esi);
  fprintf(f, "edi: %x\n", u.x86regs.edi);
  fprintf(f, "ebp: %x\n", u.x86regs.ebp);
  fprintf(f, "esp: %x\n", u.x86regs.esp);
  fprintf(f, "eip: %x\n", u.x86regs.eip);
  fprintf(f, "eflags %x\n", u.x86regs.eflags);
  fprintf(f, "orig_eax %x\n", u.x86regs.orig_eax);
  fprintf(f, "xcs: %x\n", u.x86regs.xcs);
  fprintf(f, "xds: %x\n", u.x86regs.xds);
  fprintf(f, "xes: %x\n", u.x86regs.xes);
  fprintf(f, "xfs: %x\n", u.x86regs.xfs);
  fprintf(f, "xgs: %x\n", u.x86regs.xgs);
  fprintf(f, "xss: %x\n", u.x86regs.xss);
  fprintf(f, "\n");
}

void Registers::print_register_file_compact(FILE* f) const {
  fprintf(f, "eax:%x ebx:%x ecx:%x edx:%x esi:%x edi:%x ebp:%x esp:%x eip:%x "
             "eflags:%x",
          u.x86regs.eax, u.x86regs.ebx, u.x86regs.ecx, u.x86regs.edx,
          u.x86regs.esi, u.x86regs.edi, u.x86regs.ebp, u.x86regs.esp,
          u.x86regs.eip, u.x86regs.eflags);
}

void Registers::print_register_file_for_trace(FILE* f) const {
  fprintf(
      f, "  eax:0x%x ebx:0x%x ecx:0x%x edx:0x%x esi:0x%x edi:0x%x ebp:0x%x\n"
         "  eip:0x%x esp:0x%x eflags:0x%x orig_eax:%d xfs:0x%x xgs:0x%x\n",
      u.x86regs.eax, u.x86regs.ebx, u.x86regs.ecx, u.x86regs.edx, u.x86regs.esi,
      u.x86regs.edi, u.x86regs.ebp, u.x86regs.eip, u.x86regs.esp,
      u.x86regs.eflags, u.x86regs.orig_eax, u.x86regs.xfs, u.x86regs.xgs);
}

void Registers::print_register_file_for_trace_raw(FILE* f) const {
  fprintf(f, " %d %d %d %d %d %d %d"
             " %d %d %d %d",
          u.x86regs.eax, u.x86regs.ebx, u.x86regs.ecx, u.x86regs.edx,
          u.x86regs.esi, u.x86regs.edi, u.x86regs.ebp, u.x86regs.orig_eax,
          u.x86regs.esp, u.x86regs.eip, u.x86regs.eflags);
}

static void maybe_print_reg_mismatch(int mismatch_behavior, const char* regname,
                                     const char* label1, long val1,
                                     const char* label2, long val2) {
  if (mismatch_behavior >= BAIL_ON_MISMATCH) {
    LOG(error) << regname << " " << HEX(val1) << " != " << HEX(val2) << " ("
               << label1 << " vs. " << label2 << ")";
  } else if (mismatch_behavior >= LOG_MISMATCHES) {
    LOG(info) << regname << " " << HEX(val1) << " != " << HEX(val2) << " ("
              << label1 << " vs. " << label2 << ")";
  }
}

/*static*/ bool Registers::compare_register_files(const char* name1,
                                                  const Registers* reg1,
                                                  const char* name2,
                                                  const Registers* reg2,
                                                  int mismatch_behavior) {
  bool match = true;

#define REGCMP(_reg)                                                           \
  do {                                                                         \
    if (reg1->_reg != reg2->_reg) {                                            \
      maybe_print_reg_mismatch(mismatch_behavior, #_reg, name1, reg1->_reg,    \
                               name2, reg2->_reg);                             \
      match = false;                                                           \
    }                                                                          \
  } while (0)

  REGCMP(u.x86regs.eax);
  REGCMP(u.x86regs.ebx);
  REGCMP(u.x86regs.ecx);
  REGCMP(u.x86regs.edx);
  REGCMP(u.x86regs.esi);
  REGCMP(u.x86regs.edi);
  REGCMP(u.x86regs.ebp);
  REGCMP(u.x86regs.eip);
  REGCMP(u.x86regs.xfs);
  REGCMP(u.x86regs.xgs);

  /* Negative orig_eax values, observed at SCHED events and signals,
     seemingly can vary between recording and replay on some kernels
     (e.g. Linux ubuntu 3.13.0-24-generic). They probably reflect
     signals sent or something like that.
  */
  if (reg1->u.x86regs.orig_eax >= 0 || reg2->u.x86regs.orig_eax >= 0) {
    REGCMP(u.x86regs.orig_eax);
  }

  /* The following are eflags that have been observed to be
   * nondeterministic in practice.  We need to mask them off in
   * this comparison to prevent replay from diverging. */
  enum {
    /* The linux kernel has been observed to report this
     * as zero in some states during system calls. It
     * always seems to be 1 during user-space execution so
     * we should be able to ignore it. */
    RESERVED_FLAG_1 = 1 << 1,
    /* According to www.logix.cz/michal/doc/i386/chp04-01.htm
     *
     *   The RF flag temporarily disables debug exceptions
     *   so that an instruction can be restarted after a
     *   debug exception without immediately causing
     *   another debug exception. Refer to Chapter 12 for
     *   details.
     *
     * Chapter 12 isn't particularly clear on the point,
     * but the flag appears to be set by |int3|
     * exceptions.
     *
     * This divergence has been observed when continuing a
     * tracee to an execution target by setting an |int3|
     * breakpoint, which isn't used during recording.  No
     * single-stepping was used during the recording
     * either.
     */
    RESUME_FLAG = 1 << 16,
    /* It's no longer known why this bit is ignored. */
    CPUID_ENABLED_FLAG = 1 << 21,
  };
  /* check the deterministic eflags */
  const long det_mask = ~(RESERVED_FLAG_1 | RESUME_FLAG | CPUID_ENABLED_FLAG);
  long eflags1 = (reg1->u.x86regs.eflags & det_mask);
  long eflags2 = (reg2->u.x86regs.eflags & det_mask);
  if (eflags1 != eflags2) {
    maybe_print_reg_mismatch(mismatch_behavior, "deterministic eflags", name1,
                             eflags1, name2, eflags2);
    match = false;
  }

  return match;
}

template<typename Arch>
size_t Registers::read_register_arch(uint8_t* buf, GDBRegister regno,
                                     bool* defined) const {
  assert(regno < total_registers());
  // Make sure these two definitions don't get out of sync.
  assert(array_length(RegisterInfo<Arch>::registers) == total_registers());

  initialize_register_tables();
  RegisterValue& rv = RegisterInfo<Arch>::registers[regno];
  if (rv.nbytes == 0) {
    *defined = false;
  } else {
    *defined = true;
    memcpy(buf, rv.pointer_into(ptrace_registers()), rv.nbytes);
  }

  return rv.nbytes;
}

size_t Registers::read_register(uint8_t* buf, GDBRegister regno,
                                bool* defined) const {
  RR_ARCH_FUNCTION(read_register_arch, arch(), buf, regno, defined);
}

template<typename Arch>
void Registers::write_register_arch(GDBRegister regno, const uint8_t* value,
                                    size_t value_size) {
  initialize_register_tables();
  RegisterValue& rv = RegisterInfo<Arch>::registers[regno];

  if (rv.nbytes == 0) {
    // TODO: can we get away with not writing these?
    if (RegisterInfo<Arch>::ignore_undefined_register(regno)) {
      return;
    }
    LOG(warn) << "Unhandled register name " << regno;
  } else {
    assert(value_size == rv.nbytes);
    memcpy(rv.pointer_into(ptrace_registers()), value, value_size);
  }
}

void Registers::write_register(GDBRegister regno, const uint8_t* value,
                               size_t value_size) {
  RR_ARCH_FUNCTION(write_register_arch, arch(), regno, value, value_size);
}
