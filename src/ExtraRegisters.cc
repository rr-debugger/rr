/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

//#define DEBUGTAG "registers"

#include "ExtraRegisters.h"

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

size_t ExtraRegisters::read_register(uint8_t* buf, GDBRegister regno,
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
  assert(fxsave_idx < array_length(fxsave_reg_offset));

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
