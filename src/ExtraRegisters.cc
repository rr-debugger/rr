/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "ExtraRegisters.h"

#include <assert.h>
#include <string.h>

#include "log.h"
#include "util.h"

using namespace std;

namespace rr {

// This is the byte offset at which the ST0-7 register data begins
// with an xsave (or fxsave) block.
static const int st_regs_offset = 32;
// NB: each STx register holds 10 bytes of actual data, but each
// occupies 16 bytes of space within (f)xsave, presumably for
// alignment purposes.
static const int st_reg_space = 16;

// Byte offset at which the XMM0-15 register data begins with (f)xsave.
static const int xmm_regs_offset = 160;
static const int xmm_reg_space = 16;

static const uint8_t fxsave_387_ctrl_offsets[] = {
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
};

struct RegData {
  int offset;
  int size;
  int xsave_feature_bit;

  RegData(int offset = -1, int size = 0)
      : offset(offset), size(size), xsave_feature_bit(-1) {}
};

static bool reg_in_range(GdbRegister regno, GdbRegister low, GdbRegister high,
                         int offset_base, int offset_stride, int size,
                         RegData* out) {
  if (regno < low || regno > high) {
    return false;
  }
  out->offset = offset_base + offset_stride * (regno - low);
  out->size = size;
  return true;
}

static const int AVX_FEATURE = 2;

static const size_t xsave_header_offset = 512;
static const size_t xsave_header_size = 64;
// This is always at 576 since AVX is always the first optional feature,
// if present.
static const size_t AVX_xsave_offset = 576;

// Return the size and data location of register |regno|.
// If we can't read the register, returns -1 in 'offset'.
static RegData xsave_register_data(SupportedArch arch, GdbRegister regno) {
  // Check regno is in range, and if it's 32-bit then convert it to the
  // equivalent 64-bit register.
  switch (arch) {
    case x86:
      // Convert regno to the equivalent 64-bit version since the XSAVE layout
      // is compatible
      if (regno >= DREG_XMM0 && regno <= DREG_XMM7) {
        regno = (GdbRegister)(regno - DREG_XMM0 + DREG_64_XMM0);
        break;
      }
      if (regno >= DREG_YMM0H && regno <= DREG_YMM7H) {
        regno = (GdbRegister)(regno - DREG_YMM0H + DREG_64_YMM0H);
        break;
      }
      if (regno < DREG_FIRST_FXSAVE_REG || regno > DREG_LAST_FXSAVE_REG) {
        return RegData();
      }
      if (regno == DREG_MXCSR) {
        regno = DREG_64_MXCSR;
      } else {
        regno = (GdbRegister)(regno - DREG_FIRST_FXSAVE_REG +
                              DREG_64_FIRST_FXSAVE_REG);
      }
      break;
    case x86_64:
      break;
    default:
      assert(0 && "Unknown arch");
      return RegData();
  }

  RegData result;
  if (reg_in_range(regno, DREG_64_ST0, DREG_64_ST7, st_regs_offset,
                   st_reg_space, 10, &result)) {
    return result;
  }
  if (reg_in_range(regno, DREG_64_XMM0, DREG_64_XMM15, xmm_regs_offset,
                   xmm_reg_space, 16, &result)) {
    return result;
  }

  if (reg_in_range(regno, DREG_64_YMM0H, DREG_64_YMM15H, AVX_xsave_offset, 16,
                   16, &result)) {
    result.xsave_feature_bit = AVX_FEATURE;
    return result;
  }

  if (regno < DREG_64_FIRST_FXSAVE_REG || regno > DREG_64_LAST_FXSAVE_REG) {
    return RegData();
  }
  if (regno == DREG_64_MXCSR) {
    return RegData(24, 4);
  }
  assert(regno >= DREG_64_FCTRL && regno <= DREG_64_FOP);
  // NB: most of these registers only occupy 2 bytes of space in
  // the (f)xsave region, but gdb's default x86 target
  // config expects us to send back 4 bytes of data for
  // each.
  return RegData(fxsave_387_ctrl_offsets[regno - DREG_64_FCTRL], 4);
}

size_t ExtraRegisters::read_register(uint8_t* buf, GdbRegister regno,
                                     bool* defined) const {
  if (format_ != XSAVE) {
    *defined = false;
    return 0;
  }

  auto reg_data = xsave_register_data(arch(), regno);
  if (reg_data.offset < 0 || empty()) {
    *defined = false;
    return reg_data.size;
  }

  assert(reg_data.size > 0);
  // If this is just FXSAVE(64) data then we we have no XSAVE header and no
  // XSAVE(64) features enabled.
  uint64_t xsave_features =
      data_.size() < xsave_header_offset + xsave_header_size
          ? 0
          : *reinterpret_cast<const uint64_t*>(data_.data() +
                                               xsave_header_offset);

  *defined = true;

  // Apparently before any AVX registers are used, the feature bit is not set
  // in the XSAVE data, so we'll just return 0 for them here.
  if (reg_data.xsave_feature_bit >= 0 &&
      !(xsave_features & (1 << reg_data.xsave_feature_bit))) {
    memset(buf, 0, reg_data.size);
  } else {
    assert(size_t(reg_data.offset + reg_data.size) <= data_.size());
    memcpy(buf, data_.data() + reg_data.offset, reg_data.size);
  }
  return reg_data.size;
}

static void print_reg(const ExtraRegisters& r, GdbRegister low, GdbRegister hi,
                      const char* name, FILE* f) {
  uint8_t buf[128];
  bool defined = false;
  size_t len = r.read_register(buf, low, &defined);
  assert(defined && len <= 64);
  if (hi != GdbRegister(0)) {
    size_t len2 = r.read_register(buf + len, hi, &defined);
    if (defined) {
      assert(len == len2);
      len += len2;
    }
  }
  char out[257];
  for (int i = len - 1; i >= 0; --i) {
    sprintf(out + (len - 1 - i) * 2, "%02x", buf[i]);
  }
  fprintf(f, "%s:%s ", name, out);
}

static void print_regs(const ExtraRegisters& r, GdbRegister low, GdbRegister hi,
                       int num_regs, const char* name_base, FILE* f) {
  for (int i = 0; i < num_regs; ++i) {
    char buf[80];
    sprintf(buf, "%s%d", name_base, i);
    print_reg(r, (GdbRegister)(low + i),
              hi == GdbRegister(0) ? hi : (GdbRegister)(hi + i), buf, f);
  }
}

void ExtraRegisters::print_register_file_compact(FILE* f) const {
  switch (arch_) {
    case x86:
      print_regs(*this, DREG_ST0, GdbRegister(0), 8, "st", f);
      print_regs(*this, DREG_XMM0, DREG_YMM0H, 8, "ymm", f);
      break;
    case x86_64:
      print_regs(*this, DREG_64_ST0, GdbRegister(0), 8, "st", f);
      print_regs(*this, DREG_64_XMM0, DREG_64_YMM0H, 16, "ymm", f);
      break;
    default:
      assert(0 && "Unknown arch");
      break;
  }
}

static X86Arch::user_fpregs_struct convert_fxsave_to_x86_fpregs(
    const X86Arch::user_fpxregs_struct& buf) {
  X86Arch::user_fpregs_struct result;

  for (int i = 0; i < 8; ++i) {
    memcpy(reinterpret_cast<uint8_t*>(result.st_space) + i * 10,
           &buf.st_space[i * 4], 10);
  }

  result.cwd = buf.cwd | 0xffff0000;
  result.swd = buf.swd | 0xffff0000;
  // XXX Computing the correct twd is a pain. It probably doesn't matter to us
  // in practice.
  result.twd = 0;
  result.fip = buf.fip;
  result.fcs = buf.fcs;
  result.foo = buf.foo;
  result.fos = buf.fos;

  return result;
}

static void convert_x86_fpregs_to_fxsave(const X86Arch::user_fpregs_struct& buf,
                                         X86Arch::user_fpxregs_struct* result) {
  for (int i = 0; i < 8; ++i) {
    memcpy(&result->st_space[i * 4],
           reinterpret_cast<const uint8_t*>(buf.st_space) + i * 10, 10);
  }

  result->cwd = buf.cwd;
  result->swd = buf.swd;
  // XXX Computing the correct twd is a pain. It probably doesn't matter to us
  // in practice.
  result->fip = buf.fip;
  result->fcs = buf.fcs;
  result->foo = buf.foo;
  result->fos = buf.fos;
}

template <typename T> static vector<uint8_t> to_vector(const T& v) {
  vector<uint8_t> result;
  result.resize(sizeof(T));
  memcpy(result.data(), &v, sizeof(T));
  return result;
}

vector<uint8_t> ExtraRegisters::get_user_fpregs_struct(
    SupportedArch arch) const {
  assert(format_ == XSAVE);
  switch (arch) {
    case x86:
      assert(data_.size() >= sizeof(X86Arch::user_fpxregs_struct));
      return to_vector(convert_fxsave_to_x86_fpregs(
          *reinterpret_cast<const X86Arch::user_fpxregs_struct*>(
              data_.data())));
    case x86_64:
      assert(data_.size() >= sizeof(X64Arch::user_fpregs_struct));
      return to_vector(
          *reinterpret_cast<const X64Arch::user_fpregs_struct*>(data_.data()));
    default:
      assert(0 && "Unknown arch");
      return vector<uint8_t>();
  }
}

void ExtraRegisters::set_user_fpregs_struct(SupportedArch arch, void* data,
                                            size_t size) {
  assert(format_ == XSAVE);
  switch (arch) {
    case x86:
      assert(size >= sizeof(X86Arch::user_fpregs_struct));
      assert(data_.size() >= sizeof(X86Arch::user_fpxregs_struct));
      convert_x86_fpregs_to_fxsave(
          *static_cast<X86Arch::user_fpregs_struct*>(data),
          reinterpret_cast<X86Arch::user_fpxregs_struct*>(data_.data()));
      return;
    case x86_64:
      assert(data_.size() >= sizeof(X64Arch::user_fpregs_struct));
      assert(size >= sizeof(X64Arch::user_fpregs_struct));
      memcpy(data_.data(), data, sizeof(X64Arch::user_fpregs_struct));
      return;
    default:
      assert(0 && "Unknown arch");
  }
}

X86Arch::user_fpxregs_struct ExtraRegisters::get_user_fpxregs_struct() const {
  assert(format_ == XSAVE);
  assert(arch_ == x86);
  assert(data_.size() >= sizeof(X86Arch::user_fpxregs_struct));
  return *reinterpret_cast<const X86Arch::user_fpxregs_struct*>(data_.data());
}

void ExtraRegisters::set_user_fpxregs_struct(
    const X86Arch::user_fpxregs_struct& regs) {
  assert(format_ == XSAVE);
  assert(arch_ == x86);
  assert(data_.size() >= sizeof(X86Arch::user_fpxregs_struct));
  memcpy(data_.data(), &regs, sizeof(regs));
}

} // namespace rr
