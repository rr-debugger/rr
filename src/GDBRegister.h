/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_GDB_REGISTER_H_
#define RR_GDB_REGISTER_H_

/**
 * This is the register numbering used by GDB.
 */
enum GDBRegister {
  DREG_EAX,
  DREG_ECX,
  DREG_EDX,
  DREG_EBX,
  DREG_ESP,
  DREG_EBP,
  DREG_ESI,
  DREG_EDI,
  DREG_EIP,
  DREG_EFLAGS,
  DREG_CS,
  DREG_SS,
  DREG_DS,
  DREG_ES,
  DREG_FS,
  DREG_GS,
  DREG_FIRST_FXSAVE_REG,
  DREG_ST0 = DREG_FIRST_FXSAVE_REG,
  DREG_ST1,
  DREG_ST2,
  DREG_ST3,
  DREG_ST4,
  DREG_ST5,
  DREG_ST6,
  DREG_ST7,
  // These are the names GDB gives the registers.
  DREG_FCTRL,
  DREG_FSTAT,
  DREG_FTAG,
  DREG_FISEG,
  DREG_FIOFF,
  DREG_FOSEG,
  DREG_FOOFF,
  DREG_FOP,
  DREG_XMM0,
  DREG_XMM1,
  DREG_XMM2,
  DREG_XMM3,
  DREG_XMM4,
  DREG_XMM5,
  DREG_XMM6,
  DREG_XMM7,
  DREG_MXCSR,
  // XXX the last fxsave reg on *x86*
  DREG_LAST_FXSAVE_REG = DREG_MXCSR,
  DREG_ORIG_EAX,
  DREG_NUM_LINUX_I386,
  DREG_YMM0H,
  DREG_YMM1H,
  DREG_YMM2H,
  DREG_YMM3H,
  DREG_YMM4H,
  DREG_YMM5H,
  DREG_YMM6H,
  DREG_YMM7H,
  // Last register we can find in user_regs_struct
  // (except for orig_eax).
  DREG_NUM_USER_REGS = DREG_GS + 1,
};

#endif /* RR_GDB_REGISTER_H_ */
