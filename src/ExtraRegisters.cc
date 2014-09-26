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

// The same thing, but for a 64-bit fxsave region.
//
// To find an offset in the array, index it by
//
//   fxsave_64_reg_offset[regname - DREG_64_FIRST_FXSAVE_REG]
//
static const int fxsave_64_reg_offset[] = {
  // DREG_64_ST0-DREG_64_ST7
  st_regs_offset + st_reg_space * 0,   st_regs_offset + st_reg_space * 1,
  st_regs_offset + st_reg_space * 2,   st_regs_offset + st_reg_space * 3,
  st_regs_offset + st_reg_space * 4,   st_regs_offset + st_reg_space * 5,
  st_regs_offset + st_reg_space * 6,   st_regs_offset + st_reg_space * 7,
  // The Intel documentation says that the following layout is only valid in
  // 32-bit mode, or when fxsave is executed in 64-bit mode without an
  // appropriate REX prefix.  The kernel seems to only use fxsave with the
  // REX prefix, so one would think these offsets would be different.  But
  // GDB seems happy to use these offsets, so that's what we use too.
  0,  // DREG_64_FCTRL
  2,  // DREG_64_FSTAT
  4,  // DREG_64_FTAG
  12, // DREG_64_FISEG
  8,  // DREG_64_FIOFF
  20, // DREG_64_FOSEG
  16, // DREG_64_FOOFF
  6,  // DREG_64_FOP

  // DREG_64_XMM0-DREG_64_XMM15
  xmm_regs_offset + xmm_reg_space * 0, xmm_regs_offset + xmm_reg_space * 1,
  xmm_regs_offset + xmm_reg_space * 2, xmm_regs_offset + xmm_reg_space * 3,
  xmm_regs_offset + xmm_reg_space * 4, xmm_regs_offset + xmm_reg_space * 5,
  xmm_regs_offset + xmm_reg_space * 6, xmm_regs_offset + xmm_reg_space * 7,
  xmm_regs_offset + xmm_reg_space * 8, xmm_regs_offset + xmm_reg_space * 9,
  xmm_regs_offset + xmm_reg_space * 10, xmm_regs_offset + xmm_reg_space * 11,
  xmm_regs_offset + xmm_reg_space * 12, xmm_regs_offset + xmm_reg_space * 13,
  xmm_regs_offset + xmm_reg_space * 14, xmm_regs_offset + xmm_reg_space * 15,

  // DREG_64_MXCSR
  24,
};

// Return the size of the register |regno|.  If |*can_read| is set to false,
// then we don't know how to read this register.
size_t ExtraRegisters::register_size(GDBRegister regno, bool* can_read) const {
  assert(format_ != NONE);

  if (format_ == XSAVE || format_ == FPXREGS) {
    // Fortunately (though it's probably not coincidence)
    // user_fpxregs_struct has the same layout as the XSAVE area.

    switch (regno) {
      case DREG_ST0:
      case DREG_ST1:
      case DREG_ST2:
      case DREG_ST3:
      case DREG_ST4:
      case DREG_ST5:
      case DREG_ST6:
      case DREG_ST7:
        return 10;
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
        return 4;
      case DREG_FIOFF:
      case DREG_FOOFF:
        return 4;
      case DREG_XMM0:
      case DREG_XMM1:
      case DREG_XMM2:
      case DREG_XMM3:
      case DREG_XMM4:
      case DREG_XMM5:
      case DREG_XMM6:
      case DREG_XMM7:
        return 16;
      case DREG_MXCSR:
        return 4;
      case DREG_YMM0H:
      case DREG_YMM1H:
      case DREG_YMM2H:
      case DREG_YMM3H:
      case DREG_YMM4H:
      case DREG_YMM5H:
      case DREG_YMM6H:
      case DREG_YMM7H:
        // TODO: support AVX registers
        *can_read = false;
        return 16;
      default:
        *can_read = false;
        return 0;
    }
  } else {
    switch (regno) {
      case DREG_64_ST0:
      case DREG_64_ST1:
      case DREG_64_ST2:
      case DREG_64_ST3:
      case DREG_64_ST4:
      case DREG_64_ST5:
      case DREG_64_ST6:
      case DREG_64_ST7:
        return 10;
      case DREG_64_FCTRL:
      case DREG_64_FSTAT:
      case DREG_64_FTAG:
      case DREG_64_FISEG:
      case DREG_64_FOSEG:
      case DREG_64_FOP:
        // NB: these registers only occupy 2 bytes of space in
        // the (f)xsave region, but gdb's default x86-64 target
        // config expects us to send back 4 bytes of data for
        // each.
        return 4;
      case DREG_64_FIOFF:
      case DREG_64_FOOFF:
        return 4;
      case DREG_64_XMM0:
      case DREG_64_XMM1:
      case DREG_64_XMM2:
      case DREG_64_XMM3:
      case DREG_64_XMM4:
      case DREG_64_XMM5:
      case DREG_64_XMM6:
      case DREG_64_XMM7:
      case DREG_64_XMM8:
      case DREG_64_XMM9:
      case DREG_64_XMM10:
      case DREG_64_XMM11:
      case DREG_64_XMM12:
      case DREG_64_XMM13:
      case DREG_64_XMM14:
      case DREG_64_XMM15:
        return 16;
      case DREG_64_MXCSR:
        return 4;
      case DREG_64_YMM0H:
      case DREG_64_YMM1H:
      case DREG_64_YMM2H:
      case DREG_64_YMM3H:
      case DREG_64_YMM4H:
      case DREG_64_YMM5H:
      case DREG_64_YMM6H:
      case DREG_64_YMM7H:
      case DREG_64_YMM8H:
      case DREG_64_YMM9H:
      case DREG_64_YMM10H:
      case DREG_64_YMM11H:
      case DREG_64_YMM12H:
      case DREG_64_YMM13H:
      case DREG_64_YMM14H:
      case DREG_64_YMM15H:
        // TODO: support AVX registers
        *can_read = false;
        return 16;
      default:
        *can_read = false;
        return 0;
    }
  }
}

size_t ExtraRegisters::read_register(uint8_t* buf, GDBRegister regno,
                                     bool* defined) const {
  assert(format_ != NONE);

  bool can_read = true;
  size_t num_bytes = register_size(regno, &can_read);
  if (!can_read) {
    *defined = false;
    return num_bytes;
  }

  assert(num_bytes > 0);
  if (empty()) {
    *defined = false;
    return num_bytes;
  }

  size_t fxsave_idx;
  const int* fxsave_offsets;
  size_t fxsave_offsets_length;

  if (format_ == XSAVE64) {
    assert(regno >= DREG_64_FIRST_FXSAVE_REG);
    fxsave_idx = regno - DREG_64_FIRST_FXSAVE_REG;
    fxsave_offsets = &fxsave_64_reg_offset[0];
    fxsave_offsets_length = array_length(fxsave_64_reg_offset);
  } else {
    assert(regno >= DREG_FIRST_FXSAVE_REG);
    fxsave_idx = regno - DREG_FIRST_FXSAVE_REG;
    fxsave_offsets = &fxsave_reg_offset[0];
    fxsave_offsets_length = array_length(fxsave_reg_offset);
  }
  assert(fxsave_idx < fxsave_offsets_length);

  *defined = true;
  ssize_t offset = fxsave_offsets[fxsave_idx];
  assert(offset >= 0);
  assert(offset + num_bytes <= data.size());

  memcpy(buf, data.data() + offset, num_bytes);
  return num_bytes;
}
