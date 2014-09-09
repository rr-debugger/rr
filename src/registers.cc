/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

//#define DEBUGTAG "registers"

#include "registers.h"

#include <assert.h>
#include <string.h>

#include "log.h"
#include "util.h"

// This is the byte offset at which the ST0-7 register data begins
// with an xsave (or fxsave) block.
static const int st_regs_offset = 32;
// NB: each STx register holds 10 bytes of actual data, but each
// occupies 16 bytes of space within (f)xsave, presumably for
// alignment purposes.
static const int st_reg_space = 16;

// Byte offset at which the XMM0-7 register data begins with (f)xsave.
static const int xmm_regs_offset = 160;
static const int xmm_reg_space = 16;

// Look up the byte offset in an (f)xsave region at which one of the
// named fxsave DebuggerRegisters begins.  These registers begin at
// DREG_FIRST_FXSAVE_REG and end at DREG_LAST_FXSAVE_REG.
//
// To find an offset in the array, index it by
//
//   fxsave_reg_offset[regname - DREG_FIRST_FXSAVE_REG]|
//
static const int fxsave_reg_offset[] = {
  // DREG_ST0-DREG_ST7
  st_regs_offset + st_reg_space * 0,   st_regs_offset + st_reg_space * 1,
  st_regs_offset + st_reg_space * 2,   st_regs_offset + st_reg_space * 3,
  st_regs_offset + st_reg_space * 4,   st_regs_offset + st_reg_space * 5,
  st_regs_offset + st_reg_space * 6,   st_regs_offset + st_reg_space * 7,
  0,  // DREG_FCTRL
  2,  // DREG_FSTAT
  4,  // DREG_FTAG
  12, // DREG_FISEG
  8,  // DREG_FIOFF
  20, // DREG_FOSEG
  16, // DREG_FOOFF
  6,  // DREG_FOP

  // DREG_XMM0-DREG_XMM7
  xmm_regs_offset + xmm_reg_space * 0, xmm_regs_offset + xmm_reg_space * 1,
  xmm_regs_offset + xmm_reg_space * 2, xmm_regs_offset + xmm_reg_space * 3,
  xmm_regs_offset + xmm_reg_space * 4, xmm_regs_offset + xmm_reg_space * 5,
  xmm_regs_offset + xmm_reg_space * 6, xmm_regs_offset + xmm_reg_space * 7,

  // DREG_MXCSR
  24,
};

void Registers::print_register_file(FILE* f) const {
  fprintf(f, "Printing register file:\n");
  fprintf(f, "eax: %x\n", eax);
  fprintf(f, "ebx: %x\n", ebx);
  fprintf(f, "ecx: %x\n", ecx);
  fprintf(f, "edx: %x\n", edx);
  fprintf(f, "esi: %x\n", esi);
  fprintf(f, "edi: %x\n", edi);
  fprintf(f, "ebp: %x\n", ebp);
  fprintf(f, "esp: %x\n", esp);
  fprintf(f, "eip: %x\n", eip);
  fprintf(f, "eflags %x\n", eflags);
  fprintf(f, "orig_eax %x\n", orig_eax);
  fprintf(f, "xcs: %x\n", xcs);
  fprintf(f, "xds: %x\n", xds);
  fprintf(f, "xes: %x\n", xes);
  fprintf(f, "xfs: %x\n", xfs);
  fprintf(f, "xgs: %x\n", xgs);
  fprintf(f, "xss: %x\n", xss);
  fprintf(f, "\n");
}

void Registers::print_register_file_compact(FILE* f) const {
  fprintf(f, "eax:%x ebx:%x ecx:%x edx:%x esi:%x edi:%x ebp:%x esp:%x eip:%x "
             "eflags:%x",
          eax, ebx, ecx, edx, esi, edi, ebp, esp, eip, eflags);
}

void Registers::print_register_file_for_trace(FILE* f, bool raw_dump) const {
  if (raw_dump) {
    fprintf(f, " %d %d %d %d %d %d %d"
               " %d %d %d %d",
            eax, ebx, ecx, edx, esi, edi, ebp, orig_eax, esp, eip, eflags);
  } else {
    fprintf(f,
            "  eax:0x%x ebx:0x%x ecx:0x%x edx:0x%x esi:0x%x edi:0x%x ebp:0x%x\n"
            "  eip:0x%x esp:0x%x eflags:0x%x orig_eax:%d xfs:0x%x xgs:0x%x\n",
            eax, ebx, ecx, edx, esi, edi, ebp, eip, esp, eflags, orig_eax, xfs,
            xgs);
  }
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

  REGCMP(eax);
  REGCMP(ebx);
  REGCMP(ecx);
  REGCMP(edx);
  REGCMP(esi);
  REGCMP(edi);
  REGCMP(ebp);
  REGCMP(eip);
  REGCMP(xfs);
  REGCMP(xgs);

  /* Negative orig_eax values, observed at SCHED events and signals,
     seemingly can vary between recording and replay on some kernels
     (e.g. Linux ubuntu 3.13.0-24-generic). They probably reflect
     signals sent or something like that.
  */
  if (reg1->orig_eax >= 0 || reg2->orig_eax >= 0) {
    REGCMP(orig_eax);
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
  long eflags1 = (reg1->eflags & det_mask);
  long eflags2 = (reg2->eflags & det_mask);
  if (eflags1 != eflags2) {
    maybe_print_reg_mismatch(mismatch_behavior, "deterministic eflags", name1,
                             eflags1, name2, eflags2);
    match = false;
  }

  return match;
}

template <typename T> static size_t copy_register_value(uint8_t* buf, T src) {
  memcpy(buf, &src, sizeof(src));
  return sizeof(src);
}

size_t Registers::read_register(uint8_t* buf, unsigned int regno,
                                bool* defined) const {
  assert(regno < total_registers());

  *defined = true;
  switch (regno) {
    case DREG_EAX:
      return copy_register_value(buf, eax);
    case DREG_ECX:
      return copy_register_value(buf, ecx);
    case DREG_EDX:
      return copy_register_value(buf, edx);
    case DREG_EBX:
      return copy_register_value(buf, ebx);
    case DREG_ESP:
      return copy_register_value(buf, esp);
    case DREG_EBP:
      return copy_register_value(buf, ebp);
    case DREG_ESI:
      return copy_register_value(buf, esi);
    case DREG_EDI:
      return copy_register_value(buf, edi);
    case DREG_EIP:
      return copy_register_value(buf, eip);
    case DREG_EFLAGS:
      return copy_register_value(buf, eflags);
    case DREG_CS:
      return copy_register_value(buf, xcs);
    case DREG_SS:
      return copy_register_value(buf, xss);
    case DREG_DS:
      return copy_register_value(buf, xds);
    case DREG_ES:
      return copy_register_value(buf, xes);
    case DREG_FS:
      return copy_register_value(buf, xfs);
    case DREG_GS:
      return copy_register_value(buf, xgs);
    case DREG_ORIG_EAX:
      return copy_register_value(buf, orig_eax);
  }
  *defined = false;
  return 0;
}

template <typename T>
static void set_register_value(const uint8_t* buf, size_t buf_size, T* src) {
  assert(sizeof(*src) == buf_size);
  memcpy(src, buf, sizeof(*src));
}

void Registers::write_register(unsigned reg_name, const uint8_t* value,
                               size_t value_size) {
  switch (reg_name) {
    case DREG_EAX:
      return set_register_value(value, value_size, &eax);
    case DREG_ECX:
      return set_register_value(value, value_size, &ecx);
    case DREG_EDX:
      return set_register_value(value, value_size, &edx);
    case DREG_EBX:
      return set_register_value(value, value_size, &ebx);
    case DREG_ESP:
      return set_register_value(value, value_size, &esp);
    case DREG_EBP:
      return set_register_value(value, value_size, &ebp);
    case DREG_ESI:
      return set_register_value(value, value_size, &esi);
    case DREG_EDI:
      return set_register_value(value, value_size, &edi);
    case DREG_EIP:
      return set_register_value(value, value_size, &eip);
    case DREG_EFLAGS:
      return set_register_value(value, value_size, &eflags);
    case DREG_CS:
      return set_register_value(value, value_size, &xcs);
    case DREG_SS:
      return set_register_value(value, value_size, &xss);
    case DREG_DS:
      return set_register_value(value, value_size, &xds);
    case DREG_ES:
      return set_register_value(value, value_size, &xes);
    case DREG_FS:
      return set_register_value(value, value_size, &xfs);
    case DREG_GS:
      return set_register_value(value, value_size, &xgs);

    case DREG_FOSEG:
    case DREG_MXCSR:
      // TODO: can we get away with not writing these?
      return;

    // TODO remainder of register set
    default:
      LOG(warn) << "Unhandled register name " << reg_name;
  }
}

size_t ExtraRegisters::read_register(uint8_t* buf, unsigned int regno,
                                     bool* defined) const {
  assert(format_ != NONE);
  // Fortunately (though it's probably not coincidence)
  // user_fpxregs_struct has the same layout as the XSAVE area.

  size_t num_bytes;
  switch (regno) {
    case DREG_ST0:
    case DREG_ST1:
    case DREG_ST2:
    case DREG_ST3:
    case DREG_ST4:
    case DREG_ST5:
    case DREG_ST6:
    case DREG_ST7:
      num_bytes = 10;
      break;
    case DREG_FCTRL:
    case DREG_FSTAT:
    case DREG_FTAG:
    case DREG_FISEG:
    case DREG_FOSEG:
    case DREG_FOP:
      // NB: these registers only occupy 2 bytes of space in
      // the (f)xsave region, but gdb's default x86 target
      // config expects us to send back 4 bytes of data for
      // each.
      num_bytes = 4;
      break;
    case DREG_FIOFF:
    case DREG_FOOFF:
      num_bytes = 4;
      break;
    case DREG_XMM0:
    case DREG_XMM1:
    case DREG_XMM2:
    case DREG_XMM3:
    case DREG_XMM4:
    case DREG_XMM5:
    case DREG_XMM6:
    case DREG_XMM7:
      num_bytes = 16;
      break;
    case DREG_MXCSR:
      num_bytes = 4;
      break;
    case DREG_YMM0H:
    case DREG_YMM1H:
    case DREG_YMM2H:
    case DREG_YMM3H:
    case DREG_YMM4H:
    case DREG_YMM5H:
    case DREG_YMM6H:
    case DREG_YMM7H:
      // TODO: support AVX registers
      *defined = false;
      return 16;
    default:
      *defined = false;
      return 0;
  }
  assert(num_bytes > 0);
  assert(regno >= DREG_FIRST_FXSAVE_REG);
  size_t fxsave_idx = regno - DREG_FIRST_FXSAVE_REG;
  assert(fxsave_idx < ALEN(fxsave_reg_offset));

  if (empty()) {
    *defined = false;
    return num_bytes;
  }

  *defined = true;
  ssize_t offset = fxsave_reg_offset[fxsave_idx];
  assert(offset >= 0);
  assert(offset + num_bytes <= data.size());

  memcpy(buf, data.data() + offset, num_bytes);
  return num_bytes;
}
