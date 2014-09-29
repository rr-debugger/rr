/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

//#define DEBUGTAG "registers"

#include "Registers.h"

#include <array>
#include <initializer_list>
#include <utility>

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
      : name(nullptr), offset(0), nbytes(0), comparison_mask(0) {}

  RegisterValue(const char* name_, size_t offset_, size_t nbytes_)
      : name(name_), offset(offset_), nbytes(nbytes_) {
    comparison_mask = mask_for_nbytes(nbytes_);
  }

  RegisterValue(const char* name_, size_t offset_, size_t nbytes_,
                uint64_t comparison_mask_)
      : name(name_),
        offset(offset_),
        nbytes(nbytes_),
        comparison_mask(comparison_mask_) {
    // Ensure no bits are set outside of the register's bitwidth.
    assert((comparison_mask_ & ~mask_for_nbytes(nbytes_)) == 0);
  }
  // Returns a pointer to the register in |regs| represented by |offset|.
  // |regs| is assumed to be a pointer to the user_struct_regs for the
  // appropriate architecture.
  void* pointer_into(void* regs) { return static_cast<char*>(regs) + offset; }

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

typedef std::pair<size_t, RegisterValue> RegisterInit;

template<size_t N>
struct RegisterTable : std::array<RegisterValue, N> {
  RegisterTable(std::initializer_list<RegisterInit> list) {
    for (auto& ri : list) {
      (*this)[ri.first] = ri.second;
    }
  }
};

template <typename T> struct RegisterInfo;

template <> struct RegisterInfo<rr::X86Arch> {
  static bool ignore_undefined_register(GDBRegister regno) {
    return regno == DREG_FOSEG || regno == DREG_MXCSR;
  }
  static const size_t num_registers = DREG_NUM_LINUX_I386;
  typedef RegisterTable<num_registers> Table;
  static Table registers;
};

template <> struct RegisterInfo<rr::X64Arch> {
  static bool ignore_undefined_register(GDBRegister regno) {
    return regno == DREG_64_FOSEG || regno == DREG_64_MXCSR;
  }
  static const size_t num_registers = DREG_NUM_LINUX_X86_64;
  typedef RegisterTable<num_registers> Table;
  static Table registers;
};

#define RV_ARCH(gdb_suffix, name, arch, extra_ctor_args)                \
  RegisterInit(DREG_##gdb_suffix,                                       \
               RegisterValue(#name,                                     \
                             offsetof(arch::user_regs_struct, name),    \
                             sizeof(((arch::user_regs_struct*)0)->name) extra_ctor_args))
#define RV_X86(gdb_suffix, name)                                               \
  RV_ARCH(gdb_suffix, name, rr::X86Arch, /* empty */)
#define RV_X64(gdb_suffix, name)                                               \
  RV_ARCH(gdb_suffix, name, rr::X64Arch, /* empty */)
#define COMMA ,
#define RV_X86_WITH_MASK(gdb_suffix, name, comparison_mask)                    \
  RV_ARCH(gdb_suffix, name, rr::X86Arch, COMMA comparison_mask)
#define RV_X64_WITH_MASK(gdb_suffix, name, comparison_mask)                    \
  RV_ARCH(gdb_suffix, name, rr::X64Arch, COMMA comparison_mask)

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
  /* It is no longer known why this bit is ignored.  */
  CPUID_ENABLED_FLAG = 1 << 21,
};
const uint64_t deterministic_eflags_mask =
  ~uint32_t(RESERVED_FLAG_1 | RESUME_FLAG | CPUID_ENABLED_FLAG);

RegisterInfo<rr::X86Arch>::Table RegisterInfo<rr::X86Arch>::registers = {
  RV_X86(EAX, eax),
  RV_X86(ECX, ecx),
  RV_X86(EDX, edx),
  RV_X86(EBX, ebx),
  RV_X86(ESP, esp),
  RV_X86(EBP, ebp),
  RV_X86(ESI, esi),
  RV_X86(EDI, edi),
  RV_X86(EIP, eip),
  RV_X86_WITH_MASK(EFLAGS, eflags, deterministic_eflags_mask),
  RV_X86_WITH_MASK(CS, xcs, 0),
  RV_X86_WITH_MASK(SS, xss, 0),
  RV_X86_WITH_MASK(DS, xds, 0),
  RV_X86_WITH_MASK(ES, xes, 0),
  RV_X86(FS, xfs),
  RV_X86(GS, xgs),
  // The comparison for this is handled specially elsewhere.
  RV_X86_WITH_MASK(ORIG_EAX, orig_eax, 0),
};

RegisterInfo<rr::X64Arch>::Table RegisterInfo<rr::X64Arch>::registers = {
  RV_X64(RAX, rax),
  RV_X64(RCX, rcx),
  RV_X64(RDX, rdx),
  RV_X64(RBX, rbx),
  RV_X64_WITH_MASK(RSP, rsp, 0),
  RV_X64(RBP, rbp),
  RV_X64(RSI, rsi),
  RV_X64(RDI, rdi),
  RV_X64(R8, r8),
  RV_X64(R9, r9),
  RV_X64(R10, r10),
  RV_X64(R11, r11),
  RV_X64(R12, r12),
  RV_X64(R13, r13),
  RV_X64(R14, r14),
  RV_X64(R15, r15),
  RV_X64(RIP, rip),
  RV_X64_WITH_MASK(64_EFLAGS, eflags, deterministic_eflags_mask),
  RV_X64_WITH_MASK(64_CS, cs, 0),
  RV_X64_WITH_MASK(64_SS, ss, 0),
  RV_X64_WITH_MASK(64_DS, ds, 0),
  RV_X64_WITH_MASK(64_ES, es, 0),
  RV_X64(64_FS, fs),
  RV_X64(64_GS, gs),
  // The comparison for this is handled specially elsewhere.
  RV_X64_WITH_MASK(ORIG_RAX, orig_rax, 0),
};

#undef RV_X64
#undef RV_X86
#undef RV_ARCH

// 32-bit format, 64-bit format for all of these.
// format_index in RegisterPrinting depends on the ordering here.
static const char* hex_format[] = { "%" PRIx32, "%" PRIx64 };
static const char* hex_format_leading_0x[] = { "0x%" PRIx32, "0x%" PRIx64 };
// static const char* decimal_format[] = { "%" PRId32, "%" PRId64 };

template <size_t nbytes> struct RegisterPrinting;

template <> struct RegisterPrinting<4> {
  typedef uint32_t type;
  static const size_t format_index = 0;
};

template <> struct RegisterPrinting<8> {
  typedef uint64_t type;
  static const size_t format_index = 1;
};

template <size_t nbytes>
void print_single_register(FILE* f, const char* name, const void* register_ptr,
                           const char* formats[]) {
  typename RegisterPrinting<nbytes>::type val;
  memcpy(&val, register_ptr, nbytes);
  if (name) {
    fprintf(f, "%s:", name);
  } else {
    fprintf(f, " ");
  }
  fprintf(f, formats[RegisterPrinting<nbytes>::format_index], val);
}

template <typename Arch>
void Registers::print_register_file_arch(FILE* f, const char* formats[]) const {
  fprintf(f, "Printing register file:\n");
  const void* user_regs = ptrace_registers();
  for (auto& rv : RegisterInfo<Arch>::registers) {
    if (rv.nbytes == 0) {
      continue;
    }
    switch (rv.nbytes) {
      case 8:
        print_single_register<8>(f, rv.name, rv.pointer_into(user_regs),
                                 formats);
        break;
      case 4:
        print_single_register<4>(f, rv.name, rv.pointer_into(user_regs),
                                 formats);
        break;
      default:
        assert(0 && "bad register size");
    }
    fprintf(f, "\n");
  }
  fprintf(f, "\n");
}

void Registers::print_register_file(FILE* f) const {
  RR_ARCH_FUNCTION(print_register_file_arch, arch(), f, hex_format);
}

template <typename Arch>
void Registers::print_register_file_for_trace_arch(
    FILE* f, TraceStyle style, const char* formats[]) const {
  const void* user_regs = ptrace_registers();
  for (auto& rv : RegisterInfo<Arch>::registers) {
    if (rv.nbytes == 0) {
      continue;
    }

    fprintf(f, " ");
    const char* name = (style == Annotated ? rv.name : nullptr);

    switch (rv.nbytes) {
      case 8:
        print_single_register<8>(f, name, rv.pointer_into(user_regs), formats);
        break;
      case 4:
        print_single_register<4>(f, name, rv.pointer_into(user_regs), formats);
        break;
      default:
        assert(0 && "bad register size");
    }
  }
  fprintf(f, "\n");
}

void Registers::print_register_file_compact(FILE* f) const {
  RR_ARCH_FUNCTION(print_register_file_for_trace_arch, arch(), f, Annotated,
                   hex_format);
}

void Registers::print_register_file_for_trace(FILE* f) const {
  RR_ARCH_FUNCTION(print_register_file_for_trace_arch, arch(), f, Annotated,
                   hex_format_leading_0x);
}

void Registers::print_register_file_for_trace_raw(FILE* f) const {
  fprintf(f, " %d %d %d %d %d %d %d"
             " %d %d %d %d",
          u.x86regs.eax, u.x86regs.ebx, u.x86regs.ecx, u.x86regs.edx,
          u.x86regs.esi, u.x86regs.edi, u.x86regs.ebp, u.x86regs.orig_eax,
          u.x86regs.esp, u.x86regs.eip, u.x86regs.eflags);
}

static void maybe_print_reg_mismatch(int mismatch_behavior, const char* regname,
                                     const char* label1, uint64_t val1,
                                     const char* label2, uint64_t val2) {
  if (mismatch_behavior >= BAIL_ON_MISMATCH) {
    LOG(error) << regname << " " << HEX(val1) << " != " << HEX(val2) << " ("
               << label1 << " vs. " << label2 << ")";
  } else if (mismatch_behavior >= LOG_MISMATCHES) {
    LOG(info) << regname << " " << HEX(val1) << " != " << HEX(val2) << " ("
              << label1 << " vs. " << label2 << ")";
  }
}

template <typename Arch>
static bool compare_registers_core(const char* name1, const Registers* reg1,
                                   const char* name2, const Registers* reg2,
                                   int mismatch_behavior) {
  bool match = true;

  for (auto& rv : RegisterInfo<Arch>::registers) {
    if (rv.nbytes == 0) {
      continue;
    }

    // Disregard registers that will trivially compare equal.
    if (rv.comparison_mask == 0) {
      continue;
    }

    // XXX correct but oddly displayed for big-endian processors.
    uint64_t val1 = 0, val2 = 0;
    memcpy(&val1, rv.pointer_into(reg1->ptrace_registers()), rv.nbytes);
    memcpy(&val2, rv.pointer_into(reg2->ptrace_registers()), rv.nbytes);
    val1 &= rv.comparison_mask;
    val2 &= rv.comparison_mask;

    if (val1 != val2) {
      maybe_print_reg_mismatch(mismatch_behavior, rv.name, name1, val1, name2,
                               val2);
      match = false;
    }
  }

  return match;
}

// A handy macro for compare_registers_arch specializations.
#define REGCMP(_reg)                                                           \
  do {                                                                         \
    if (reg1->_reg != reg2->_reg) {                                            \
      maybe_print_reg_mismatch(mismatch_behavior, #_reg, name1, reg1->_reg,    \
                               name2, reg2->_reg);                             \
      match = false;                                                           \
    }                                                                          \
  } while (0)

// A wrapper around compare_registers_core so registers requiring special
// processing can be handled via template specialization.
template <typename Arch>
/* static */ bool Registers::compare_registers_arch(const char* name1,
                                                    const Registers* reg1,
                                                    const char* name2,
                                                    const Registers* reg2,
                                                    int mismatch_behavior) {
  // Default behavior.
  return compare_registers_core<Arch>(name1, reg1, name2, reg2,
                                      mismatch_behavior);
}

template <>
/* static */ bool Registers::compare_registers_arch<rr::X86Arch>(
    const char* name1, const Registers* reg1, const char* name2,
    const Registers* reg2, int mismatch_behavior) {
  bool match = compare_registers_core<rr::X86Arch>(name1, reg1, name2, reg2,
                                                   mismatch_behavior);
  /* Negative orig_eax values, observed at SCHED events and signals,
     seemingly can vary between recording and replay on some kernels
     (e.g. Linux ubuntu 3.13.0-24-generic). They probably reflect
     signals sent or something like that.
  */
  if (reg1->u.x86regs.orig_eax >= 0 || reg2->u.x86regs.orig_eax >= 0) {
    REGCMP(u.x86regs.orig_eax);
  }
  return match;
}

template <>
/* static */ bool Registers::compare_registers_arch<rr::X64Arch>(
    const char* name1, const Registers* reg1, const char* name2,
    const Registers* reg2, int mismatch_behavior) {
  bool match = compare_registers_core<rr::X64Arch>(name1, reg1, name2, reg2,
                                                   mismatch_behavior);
  // XXX haven't actually observed this to be true on x86-64 yet, but
  // assuming that it follows the x86 behavior.
  if (reg1->u.x64regs.orig_rax >= 0 || reg2->u.x64regs.orig_rax >= 0) {
    REGCMP(u.x64regs.orig_rax);
  }
  return match;
}

/*static*/ bool Registers::compare_register_files(const char* name1,
                                                  const Registers* reg1,
                                                  const char* name2,
                                                  const Registers* reg2,
                                                  int mismatch_behavior) {
  assert(reg1->arch() == reg2->arch());
  RR_ARCH_FUNCTION(compare_registers_arch, reg1->arch(), name1, reg1, name2,
                   reg2, mismatch_behavior);
}

template <typename Arch>
size_t Registers::read_register_arch(uint8_t* buf, GDBRegister regno,
                                     bool* defined) const {
  assert(regno < total_registers());
  // Make sure these two definitions don't get out of sync.
  assert(array_length(RegisterInfo<Arch>::registers) == total_registers());

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

template <typename Arch>
void Registers::write_register_arch(GDBRegister regno, const uint8_t* value,
                                    size_t value_size) {
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

template <typename Arch>
size_t Registers::total_registers_arch() const {
  return RegisterInfo<Arch>::num_registers;
}

size_t Registers::total_registers() const {
  RR_ARCH_FUNCTION(total_registers_arch, arch());
}
