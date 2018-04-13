/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "ExtraRegisters.h"

#include <string.h>

#include "core.h"
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
static const size_t xsave_header_end = xsave_header_offset + xsave_header_size;
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
      DEBUG_ASSERT(0 && "Unknown arch");
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
  DEBUG_ASSERT(regno >= DREG_64_FCTRL && regno <= DREG_64_FOP);
  // NB: most of these registers only occupy 2 bytes of space in
  // the (f)xsave region, but gdb's default x86 target
  // config expects us to send back 4 bytes of data for
  // each.
  return RegData(fxsave_387_ctrl_offsets[regno - DREG_64_FCTRL], 4);
}

static uint64_t xsave_features(const vector<uint8_t>& data) {
  // If this is just FXSAVE(64) data then we we have no XSAVE header and no
  // XSAVE(64) features enabled.
  return data.size() < xsave_header_offset + xsave_header_size
             ? 0
             : *reinterpret_cast<const uint64_t*>(data.data() +
                                                  xsave_header_offset);
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

  DEBUG_ASSERT(reg_data.size > 0);

  *defined = true;

  // Apparently before any AVX registers are used, the feature bit is not set
  // in the XSAVE data, so we'll just return 0 for them here.
  if (reg_data.xsave_feature_bit >= 0 &&
      !(xsave_features(data_) & (1 << reg_data.xsave_feature_bit))) {
    memset(buf, 0, reg_data.size);
  } else {
    DEBUG_ASSERT(size_t(reg_data.offset + reg_data.size) <= data_.size());
    memcpy(buf, data_.data() + reg_data.offset, reg_data.size);
  }
  return reg_data.size;
}

static const int xinuse_offset = 512;

uint64_t ExtraRegisters::read_xinuse(bool* defined) const {
  uint64_t ret;
  if (format_ != XSAVE || data_.size() < 512 + sizeof(ret)) {
    *defined = false;
    return 0;
  }

  memcpy(&ret, data_.data() + xinuse_offset, sizeof(ret));
  return ret;
}

void ExtraRegisters::validate(Task* t) {
  if (format_ != XSAVE) {
    return;
  }

  ASSERT(t, data_.size() >= 512);
  uint32_t offset = 512;
  if (data_.size() > offset) {
    ASSERT(t, data_.size() >= offset + 64);
    offset += 64;
    uint64_t features = xsave_features(data_);
    if (features & AVX_FEATURE) {
      ASSERT(t, data_.size() >= offset + 256);
    }
  }
}

static void print_reg(const ExtraRegisters& r, GdbRegister low, GdbRegister hi,
                      const char* name, FILE* f) {
  uint8_t buf[128];
  bool defined = false;
  size_t len = r.read_register(buf, low, &defined);
  DEBUG_ASSERT(defined && len <= 64);
  if (hi != GdbRegister(0)) {
    size_t len2 = r.read_register(buf + len, hi, &defined);
    if (defined) {
      DEBUG_ASSERT(len == len2);
      len += len2;
    }
  }
  char out[257];
  bool printed_digit = false;
  char* p = out;
  for (int i = len - 1; i >= 0; --i) {
    if (!printed_digit && !buf[i] && i > 0) {
      continue;
    }
    p += sprintf(p, printed_digit ? "%02x" : "%x", buf[i]);
    printed_digit = true;
  }
  fprintf(f, "%s:0x%s", name, out);
}

static void print_regs(const ExtraRegisters& r, GdbRegister low, GdbRegister hi,
                       int num_regs, const char* name_base, FILE* f) {
  for (int i = 0; i < num_regs; ++i) {
    char buf[80];
    sprintf(buf, "%s%d", name_base, i);
    print_reg(r, (GdbRegister)(low + i),
              hi == GdbRegister(0) ? hi : (GdbRegister)(hi + i), buf, f);
    if (i < num_regs - 1) {
      fputc(' ', f);
    }
  }
}

void ExtraRegisters::print_register_file_compact(FILE* f) const {
  switch (arch_) {
    case x86:
      print_regs(*this, DREG_ST0, GdbRegister(0), 8, "st", f);
      fputc(' ', f);
      print_regs(*this, DREG_XMM0, DREG_YMM0H, 8, "ymm", f);
      break;
    case x86_64:
      print_regs(*this, DREG_64_ST0, GdbRegister(0), 8, "st", f);
      fputc(' ', f);
      print_regs(*this, DREG_64_XMM0, DREG_64_YMM0H, 16, "ymm", f);
      break;
    default:
      DEBUG_ASSERT(0 && "Unknown arch");
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

bool ExtraRegisters::set_to_raw_data(SupportedArch a, Format format,
                                     const uint8_t* data, size_t data_size,
                                     const XSaveLayout& layout) {
  arch_ = a;
  format_ = NONE;

  if (format == NONE) {
    return true;
  }
  if (format != XSAVE) {
    LOG(error) << "Unknown ExtraRegisters format: " << format;
    return false;
  }
  format_ = XSAVE;

  // Now we have to convert from the input XSAVE format to our
  // native XSAVE format. Be careful to handle possibly-corrupt input data.

  const XSaveLayout& native_layout = xsave_native_layout();
  if (data_size != layout.full_size) {
    LOG(error) << "Invalid XSAVE data length: " << data_size << ", expected "
               << layout.full_size;
    return false;
  }
  data_.resize(native_layout.full_size);
  DEBUG_ASSERT(data_.size() >= xsave_header_offset);
  if (layout.full_size < xsave_header_offset) {
    LOG(error) << "Invalid XSAVE layout size: " << layout.full_size;
    return false;
  }
  memcpy(data_.data(), data, xsave_header_offset);
  memset(data_.data() + xsave_header_offset, 0,
         data_.size() - xsave_header_offset);

  // Check for unsupported features being used
  if (layout.full_size >= xsave_header_end) {
    uint64_t features_used;
    memcpy(&features_used, data + xsave_header_offset, sizeof(features_used));
    if (features_used & ~native_layout.supported_feature_bits) {
      LOG(error) << "Unsupported CPU features found: got " << HEX(features_used)
                 << " (" << xsave_feature_string(features_used)
                 << "), supported: "
                 << HEX(native_layout.supported_feature_bits)
                 << " ("
                 << xsave_feature_string(native_layout.supported_feature_bits)
                 << "); Consider using `rr cpufeatures` and "
                 << "`rr record --disable-cpuid-features-(ext)`";
      return false;
    }
  }

  if (native_layout.full_size < xsave_header_end) {
    // No XSAVE supported here, we're done!
    return true;
  }
  if (layout.full_size < xsave_header_end) {
    // Degenerate XSAVE format without an actual XSAVE header. Assume x87+XMM
    // are in use.
    uint64_t assume_features_used = 0x3;
    memcpy(data_.data() + xsave_header_offset, &assume_features_used,
           sizeof(assume_features_used));
    return true;
  }

  // OK, now both our native layout and the input layout are using the full
  // XSAVE header. Copy the header.
  memcpy(data_.data() + xsave_header_offset, data + xsave_header_offset,
         xsave_header_size);

  // Now copy each optional and present area into the right place in our struct
  uint64_t features_present;
  memcpy(&features_present, data + xsave_header_offset,
         sizeof(features_present));
  for (size_t i = 2; i < 64; ++i) {
    if (features_present & (uint64_t(1) << i)) {
      const XSaveFeatureLayout& feature = layout.feature_layouts[i];
      if (uint64_t(feature.offset) + feature.size > layout.full_size) {
        LOG(error) << "Invalid feature region: " << feature.offset << "+"
                   << feature.size << " > " << layout.full_size;
        return false;
      }
      const XSaveFeatureLayout& native_feature =
          native_layout.feature_layouts[i];
      if (feature.size != native_feature.size) {
        LOG(error) << "Feature " << i << " has wrong size " << feature.size
                   << ", expected " << native_feature.size;
        return false;
      }
      // The CPU should guarantee these
      DEBUG_ASSERT(native_feature.offset > 0);
      DEBUG_ASSERT(native_feature.offset + native_feature.size <=
                   native_layout.full_size);
      memcpy(data_.data() + native_feature.offset, data + feature.offset,
             feature.size);
    }
  }

  return true;
}

vector<uint8_t> ExtraRegisters::get_user_fpregs_struct(
    SupportedArch arch) const {
  DEBUG_ASSERT(format_ == XSAVE);
  switch (arch) {
    case x86:
      DEBUG_ASSERT(data_.size() >= sizeof(X86Arch::user_fpxregs_struct));
      return to_vector(convert_fxsave_to_x86_fpregs(
          *reinterpret_cast<const X86Arch::user_fpxregs_struct*>(
              data_.data())));
    case x86_64:
      DEBUG_ASSERT(data_.size() >= sizeof(X64Arch::user_fpregs_struct));
      return to_vector(
          *reinterpret_cast<const X64Arch::user_fpregs_struct*>(data_.data()));
    default:
      DEBUG_ASSERT(0 && "Unknown arch");
      return vector<uint8_t>();
  }
}

void ExtraRegisters::set_user_fpregs_struct(Task* t, SupportedArch arch,
                                            void* data, size_t size) {
  DEBUG_ASSERT(format_ == XSAVE);
  switch (arch) {
    case x86:
      ASSERT(t, size >= sizeof(X86Arch::user_fpregs_struct));
      ASSERT(t, data_.size() >= sizeof(X86Arch::user_fpxregs_struct));
      convert_x86_fpregs_to_fxsave(
          *static_cast<X86Arch::user_fpregs_struct*>(data),
          reinterpret_cast<X86Arch::user_fpxregs_struct*>(data_.data()));
      return;
    case x86_64:
      ASSERT(t, data_.size() >= sizeof(X64Arch::user_fpregs_struct));
      ASSERT(t, size >= sizeof(X64Arch::user_fpregs_struct));
      memcpy(data_.data(), data, sizeof(X64Arch::user_fpregs_struct));
      return;
    default:
      DEBUG_ASSERT(0 && "Unknown arch");
  }
}

X86Arch::user_fpxregs_struct ExtraRegisters::get_user_fpxregs_struct() const {
  DEBUG_ASSERT(format_ == XSAVE);
  DEBUG_ASSERT(arch_ == x86);
  DEBUG_ASSERT(data_.size() >= sizeof(X86Arch::user_fpxregs_struct));
  return *reinterpret_cast<const X86Arch::user_fpxregs_struct*>(data_.data());
}

void ExtraRegisters::set_user_fpxregs_struct(
    Task* t, const X86Arch::user_fpxregs_struct& regs) {
  ASSERT(t, format_ == XSAVE);
  ASSERT(t, arch_ == x86);
  ASSERT(t, data_.size() >= sizeof(X86Arch::user_fpxregs_struct));
  memcpy(data_.data(), &regs, sizeof(regs));
}

static void set_word(SupportedArch arch, vector<uint8_t>& v, GdbRegister r,
                     int word) {
  RegData d = xsave_register_data(arch, r);
  DEBUG_ASSERT(d.size == 4);
  DEBUG_ASSERT(d.offset + d.size <= (int)v.size());
  DEBUG_ASSERT(-1 == d.xsave_feature_bit);
  *reinterpret_cast<int*>(v.data() + d.offset) = word;
}

void ExtraRegisters::reset() {
  DEBUG_ASSERT(format_ == XSAVE);
  memset(data_.data(), 0, data_.size());
  switch (arch()) {
    case x86_64: {
      set_word(arch(), data_, DREG_64_MXCSR, 0x1f80);
      set_word(arch(), data_, DREG_64_FCTRL, 0x37f);
      break;
    }
    case x86: {
      set_word(arch(), data_, DREG_MXCSR, 0x1f80);
      set_word(arch(), data_, DREG_FCTRL, 0x37f);
      break;
    }
    default:
      DEBUG_ASSERT(0 && "Unknown arch");
      break;
  }
  uint64_t xinuse;
  if (data_.size() >= xinuse_offset + sizeof(xinuse)) {
    /* We have observed (Skylake, Linux 4.10) the system setting XINUSE's 0 bit
     * to indicate x87-in-use, at times unrelated to x87 actually being used.
     * Work around this by setting the bit unconditionally after exec.
     */
    memcpy(&xinuse, data_.data() + xinuse_offset, sizeof(xinuse));
    xinuse |= 1;
    memcpy(data_.data() + xinuse_offset, &xinuse, sizeof(xinuse));
  }
}

} // namespace rr
