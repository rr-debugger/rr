/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

//#define DEBUGTAG "registers"

#include "Registers.h"

#include <assert.h>
#include <string.h>

#include "log.h"
#include "util.h"

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

void Registers::print_register_file_for_trace(FILE* f, bool raw_dump) const {
  if (raw_dump) {
    fprintf(f, " %d %d %d %d %d %d %d"
               " %d %d %d %d",
            u.x86regs.eax, u.x86regs.ebx, u.x86regs.ecx, u.x86regs.edx,
            u.x86regs.esi, u.x86regs.edi, u.x86regs.ebp, u.x86regs.orig_eax,
            u.x86regs.esp, u.x86regs.eip, u.x86regs.eflags);
  } else {
    fprintf(f,
            "  eax:0x%x ebx:0x%x ecx:0x%x edx:0x%x esi:0x%x edi:0x%x ebp:0x%x\n"
            "  eip:0x%x esp:0x%x eflags:0x%x orig_eax:%d xfs:0x%x xgs:0x%x\n",
            u.x86regs.eax, u.x86regs.ebx, u.x86regs.ecx, u.x86regs.edx,
            u.x86regs.esi, u.x86regs.edi, u.x86regs.ebp, u.x86regs.eip,
            u.x86regs.esp, u.x86regs.eflags, u.x86regs.orig_eax, u.x86regs.xfs,
            u.x86regs.xgs);
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

template <typename T> static size_t copy_register_value(uint8_t* buf, T src) {
  memcpy(buf, &src, sizeof(src));
  return sizeof(src);
}

size_t Registers::read_register(uint8_t* buf, GDBRegister regno,
                                bool* defined) const {
  assert(regno < total_registers());

  *defined = true;
  switch (regno) {
    case DREG_EAX:
      return copy_register_value(buf, u.x86regs.eax);
    case DREG_ECX:
      return copy_register_value(buf, u.x86regs.ecx);
    case DREG_EDX:
      return copy_register_value(buf, u.x86regs.edx);
    case DREG_EBX:
      return copy_register_value(buf, u.x86regs.ebx);
    case DREG_ESP:
      return copy_register_value(buf, u.x86regs.esp);
    case DREG_EBP:
      return copy_register_value(buf, u.x86regs.ebp);
    case DREG_ESI:
      return copy_register_value(buf, u.x86regs.esi);
    case DREG_EDI:
      return copy_register_value(buf, u.x86regs.edi);
    case DREG_EIP:
      return copy_register_value(buf, u.x86regs.eip);
    case DREG_EFLAGS:
      return copy_register_value(buf, u.x86regs.eflags);
    case DREG_CS:
      return copy_register_value(buf, u.x86regs.xcs);
    case DREG_SS:
      return copy_register_value(buf, u.x86regs.xss);
    case DREG_DS:
      return copy_register_value(buf, u.x86regs.xds);
    case DREG_ES:
      return copy_register_value(buf, u.x86regs.xes);
    case DREG_FS:
      return copy_register_value(buf, u.x86regs.xfs);
    case DREG_GS:
      return copy_register_value(buf, u.x86regs.xgs);
    case DREG_ORIG_EAX:
      return copy_register_value(buf, u.x86regs.orig_eax);
    default:
      *defined = false;
      return 0;
  }
}

template <typename T>
static void set_register_value(const uint8_t* buf, size_t buf_size, T* src) {
  assert(sizeof(*src) == buf_size);
  memcpy(src, buf, sizeof(*src));
}

void Registers::write_register(GDBRegister reg_name, const uint8_t* value,
                               size_t value_size) {
  switch (reg_name) {
    case DREG_EAX:
      return set_register_value(value, value_size, &u.x86regs.eax);
    case DREG_ECX:
      return set_register_value(value, value_size, &u.x86regs.ecx);
    case DREG_EDX:
      return set_register_value(value, value_size, &u.x86regs.edx);
    case DREG_EBX:
      return set_register_value(value, value_size, &u.x86regs.ebx);
    case DREG_ESP:
      return set_register_value(value, value_size, &u.x86regs.esp);
    case DREG_EBP:
      return set_register_value(value, value_size, &u.x86regs.ebp);
    case DREG_ESI:
      return set_register_value(value, value_size, &u.x86regs.esi);
    case DREG_EDI:
      return set_register_value(value, value_size, &u.x86regs.edi);
    case DREG_EIP:
      return set_register_value(value, value_size, &u.x86regs.eip);
    case DREG_EFLAGS:
      return set_register_value(value, value_size, &u.x86regs.eflags);
    case DREG_CS:
      return set_register_value(value, value_size, &u.x86regs.xcs);
    case DREG_SS:
      return set_register_value(value, value_size, &u.x86regs.xss);
    case DREG_DS:
      return set_register_value(value, value_size, &u.x86regs.xds);
    case DREG_ES:
      return set_register_value(value, value_size, &u.x86regs.xes);
    case DREG_FS:
      return set_register_value(value, value_size, &u.x86regs.xfs);
    case DREG_GS:
      return set_register_value(value, value_size, &u.x86regs.xgs);

    case DREG_FOSEG:
    case DREG_MXCSR:
      // TODO: can we get away with not writing these?
      return;

    // TODO remainder of register set
    default:
      LOG(warn) << "Unhandled register name " << reg_name;
  }
}
