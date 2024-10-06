/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "ExtraRegisters.h"

#include <string.h>

#include "ReplayTask.h"
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

static const int fip_offset = 8;
static const int fop_offset = 6;
static const int fdp_offset = 16;
static const int mxcsr_offset = 24;

struct RegData {
  int offset;
  int size;
  int xsave_feature_bit;

  RegData(int offset = -1, int size = 0)
      : offset(offset), size(size), xsave_feature_bit(-1) {}
};

static bool reg_in_range(GdbServerRegister regno, GdbServerRegister low, GdbServerRegister high,
                         int offset_base, int offset_stride, int size,
                         RegData* out) {
  if (regno < low || regno > high) {
    return false;
  }
  out->offset = offset_base + offset_stride * (regno - low);
  out->size = size;
  return true;
}

static constexpr int AVX_FEATURE_BIT = 2;
static constexpr int AVX_OPMASK_FEATURE_BIT = 5;
static constexpr int AVX_ZMM_HI256_FEATURE_BIT = 6;
static constexpr int AVX_ZMM_HI16_FEATURE_BIT = 7;
static constexpr int PKRU_FEATURE_BIT = 9;

static const uint64_t PKRU_FEATURE_MASK = 1 << PKRU_FEATURE_BIT;

static const size_t xsave_header_offset = 512;
static const size_t xsave_header_size = 64;
static const size_t xsave_header_end = xsave_header_offset + xsave_header_size;
struct RegisterConfig {
  int8_t feature;
  GdbServerRegister base;
  int8_t size;
  int stride;

  int register_offset(GdbServerRegister reg, int base_offset) const noexcept {
    const auto& layout = xsave_native_layout();
    return layout.feature_layouts[feature].offset + base_offset + (reg - base) * stride;
  }
};

static constexpr std::array<RegisterConfig, 6> RegisterConfigLookupTable{
  { { AVX_FEATURE_BIT, DREG_64_YMM0H, 16, 16 },
    { AVX_ZMM_HI16_FEATURE_BIT, DREG_64_XMM16, 16, 64 },
    { AVX_ZMM_HI16_FEATURE_BIT, DREG_64_YMM16H, 16, 64 },
    { AVX_ZMM_HI256_FEATURE_BIT, DREG_64_ZMM0H, 32, 32 },
    { AVX_ZMM_HI16_FEATURE_BIT, DREG_64_ZMM16H, 32, 64 },
    { AVX_OPMASK_FEATURE_BIT, DREG_64_K0, 8, 8 } }
};

static constexpr auto YMM16_31 = 0b10;
static constexpr auto ZMM16_31 = 0b100;

// Every range of registers (except K0-7) are 16 registers long. We use this fact to build
// a lookup table, for the AVX2 and AVX512 registers.
static bool reg_is_avx2_or_512(GdbServerRegister reg, RegData& out) noexcept {
  if(reg < DREG_64_YMM0H || reg > DREG_64_K7) {
    return false;
  }

  const auto selector = (reg - DREG_64_YMM0H) >> 4;
  DEBUG_ASSERT(selector >= 0 && selector <= 5 && "GdbServerRegister enum values has been changed.");
  const auto cfg = RegisterConfigLookupTable[selector];
  out.xsave_feature_bit = cfg.feature;
  out.size = cfg.size;

  // only YMM16-31 and ZMM16-31 have a base offset (16 and 32 respectively)
  const auto base_offset = cfg.size * (selector == YMM16_31) | cfg.size * (selector == ZMM16_31);
  out.offset = cfg.register_offset(reg, base_offset);
  return true;
}

// Return the size and data location of register |regno|.
// If we can't read the register, returns -1 in 'offset'.
static RegData xsave_register_data(SupportedArch arch, GdbServerRegister regno) {
  // Check regno is in range, and if it's 32-bit then convert it to the
  // equivalent 64-bit register.
  switch (arch) {
    case x86:
      // Convert regno to the equivalent 64-bit version since the XSAVE layout
      // is compatible
      if (regno >= DREG_XMM0 && regno <= DREG_XMM7) {
        regno = (GdbServerRegister)(regno - DREG_XMM0 + DREG_64_XMM0);
        break;
      }
      if (regno >= DREG_YMM0H && regno <= DREG_YMM7H) {
        regno = (GdbServerRegister)(regno - DREG_YMM0H + DREG_64_YMM0H);
        break;
      }
      if(regno >= DREG_ZMM0H && regno <= DREG_ZMM7H) {
        regno = (GdbServerRegister)(regno - DREG_ZMM0H + DREG_64_ZMM0H);
        break;
      }
      if(regno >= DREG_K0 && regno <= DREG_K7) {
        regno = (GdbServerRegister)(regno - DREG_K0 + DREG_64_K0);
        break;
      }
      if (regno == DREG_MXCSR) {
        regno = DREG_64_MXCSR;
      } else if (regno == DREG_PKRU) {
        regno = DREG_64_PKRU;
      } else if (regno < DREG_FIRST_FXSAVE_REG || regno > DREG_LAST_FXSAVE_REG) {
        return RegData();
      } else {
        regno = (GdbServerRegister)(regno - DREG_FIRST_FXSAVE_REG +
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

  if(reg_is_avx2_or_512(regno, result)) {
    return result;
  }

  if (regno == DREG_64_PKRU) {
    const XSaveLayout& layout = xsave_native_layout();
    if (PKRU_FEATURE_BIT > layout.feature_layouts.size()) {
      return RegData();
    }

    const XSaveFeatureLayout& fl = layout.feature_layouts[PKRU_FEATURE_BIT];
    result.offset = fl.offset;
    // NB: the PKRU *region* may be 8 bytes to maintain alignment but the
    // PKRU *register* is only the first 4 bytes.
    result.size = 4;
    result.xsave_feature_bit = PKRU_FEATURE_BIT;
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

static const uint64_t* xsave_features(const vector<uint8_t>& data) {
  // If this is just FXSAVE(64) data then we we have no XSAVE header and no
  // XSAVE(64) features enabled.
  return data.size() < xsave_header_offset + xsave_header_size
             ? nullptr
             : reinterpret_cast<const uint64_t*>(data.data() +
                                                 xsave_header_offset);

}

static uint64_t* xsave_features(vector<uint8_t>& data) {
  // If this is just FXSAVE(64) data then we we have no XSAVE header and no
  // XSAVE(64) features enabled.
  return data.size() < xsave_header_offset + xsave_header_size
             ? nullptr
             : reinterpret_cast<uint64_t*>(data.data() + xsave_header_offset);
}

size_t ExtraRegisters::read_register(uint8_t* buf, GdbServerRegister regno,
                                     bool* defined) const {
  if (format_ == NT_FPR) {
    if (arch() != aarch64) {
      *defined = false;
      return 0;
    }

    RegData reg_data;
    if (DREG_V0 <= regno && regno <= DREG_V31) {
      reg_data = RegData(offsetof(ARM64Arch::user_fpsimd_state, vregs[0]) +
        ((regno - DREG_V0) * 16), 16);
    } else if (regno == DREG_FPSR) {
      reg_data = RegData(offsetof(ARM64Arch::user_fpsimd_state, fpsr),
                         sizeof(uint32_t));
    } else if (regno == DREG_FPCR) {
      reg_data = RegData(offsetof(ARM64Arch::user_fpsimd_state, fpcr),
                         sizeof(uint32_t));
    } else {
      *defined = false;
      return 0;
    }

    DEBUG_ASSERT(size_t(reg_data.offset + reg_data.size) <= data_.size());
    *defined = true;
    memcpy(buf, data_.data() + reg_data.offset, reg_data.size);
    return reg_data.size;
  }

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
  const uint64_t* xsave_features_ = xsave_features(data_);
  if (reg_data.xsave_feature_bit >= 0 &&
      (!xsave_features_ ||
       !(*xsave_features_ & (1 << reg_data.xsave_feature_bit)))) {
    memset(buf, 0, reg_data.size);
  } else {
    DEBUG_ASSERT(size_t(reg_data.offset + reg_data.size) <= data_.size());
    memcpy(buf, data_.data() + reg_data.offset, reg_data.size);
  }
  return reg_data.size;
}

bool ExtraRegisters::write_register(GdbServerRegister regno, const void* value,
                                    size_t value_size) {
  if (format_ == NT_FPR) {
    if (arch() != aarch64) {
      return false;
    }

    RegData reg_data;
    if (DREG_V0 <= regno && regno <= DREG_V31) {
      reg_data = RegData(offsetof(ARM64Arch::user_fpsimd_state, vregs[0]) +
        ((regno - DREG_V0) * 16), 16);
    } else if (regno == DREG_FPSR) {
      reg_data = RegData(offsetof(ARM64Arch::user_fpsimd_state, fpsr),
                         sizeof(uint32_t));
    } else if (regno == DREG_FPCR) {
      reg_data = RegData(offsetof(ARM64Arch::user_fpsimd_state, fpcr),
                         sizeof(uint32_t));
    } else {
      return false;
    }

    DEBUG_ASSERT(reg_data.size > 0);
    if ((size_t)reg_data.size != value_size) {
      LOG(warn) << "Register " << regno << "has mismatched sizes ("
                << reg_data.size << " vs " << value_size << ")";
      return false;
    }

    DEBUG_ASSERT(size_t(reg_data.offset + reg_data.size) <= data_.size());
    memcpy(data_.data() + reg_data.offset, value, value_size);
    return true;
  }

  if (format_ != XSAVE) {
    return false;
  }

  auto reg_data = xsave_register_data(arch(), regno);
  if (reg_data.offset < 0 || empty()) {
    return false;
  }

  DEBUG_ASSERT(reg_data.size > 0);
  if ((size_t)reg_data.size != value_size) {
    LOG(warn) << "Register " << regno << "has mismatched sizes ("
              << reg_data.size << " vs " << value_size << ")";
    return false;
  }

  if (reg_data.xsave_feature_bit >= 0) {
    uint64_t* xsave_features_ = xsave_features(data_);
    if (!xsave_features_) {
      return false;
    }

    *xsave_features_ |= (1 << reg_data.xsave_feature_bit);
  }

  memcpy(data_.data() + reg_data.offset, value, value_size);
  return true;
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

uint64_t ExtraRegisters::read_fip(bool* defined) const {
  if (format_ != XSAVE) {
    *defined = false;
    return 0;
  }

  uint64_t ret;
  memcpy(&ret, data_.data() + fip_offset, sizeof(ret));
  return ret;
}

uint16_t ExtraRegisters::read_fop(bool* defined) const {
  if (format_ != XSAVE) {
    *defined = false;
    return 0;
  }

  uint16_t ret;
  memcpy(&ret, data_.data() + fop_offset, sizeof(ret));
  return ret;
}

uint32_t ExtraRegisters::read_mxcsr(bool* defined) const {
  if (format_ != XSAVE) {
    *defined = false;
    return 0;
  }

  uint32_t ret;
  memcpy(&ret, data_.data() + mxcsr_offset, sizeof(ret));
  return ret;
}

bool ExtraRegisters::clear_fip_fdp() {
  if (format_ != XSAVE) {
    return false;
  }

  bool ret = false;
  uint64_t v;
  memcpy(&v, data_.data() + fip_offset, sizeof(v));
  if (v != 0) {
    ret = true;
    memset(data_.data() + fip_offset, 0, 8);
  }
  memcpy(&v, data_.data() + fdp_offset, sizeof(v));
  if (v != 0) {
    ret = true;
    memset(data_.data() + fdp_offset, 0, 8);
  }
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
    const uint64_t* features = xsave_features(data_);
    if (features && (*features & (1 << AVX_FEATURE_BIT))) {
      ASSERT(t, data_.size() >= offset + 256);
    }
  }
}

static size_t get_full_value(const ExtraRegisters& r, GdbServerRegister low, GdbServerRegister hi,
                             uint8_t buf[128]) {
  bool defined = false;
  size_t len = r.read_register(buf, low, &defined);
  DEBUG_ASSERT(defined && len <= 64);
  if (hi != GdbServerRegister(0)) {
    size_t len2 = r.read_register(buf + len, hi, &defined);
    if (defined) {
      DEBUG_ASSERT(len == len2);
      len += len2;
    }
  }
  return len;
}

static string reg_to_string(const ExtraRegisters& r, GdbServerRegister low, GdbServerRegister hi) {
  uint8_t buf[128];
  size_t len = get_full_value(r, low, hi, buf);
  bool printed_digit = false;
  char out_buf[257];
  char* p = out_buf;
  for (int i = len - 1; i >= 0; --i) {
    if (!printed_digit && !buf[i] && i > 0) {
      continue;
    }
    p += sprintf(p, printed_digit ? "%02x" : "%x", buf[i]);
    printed_digit = true;
  }
  return out_buf;
}

static void print_reg(const ExtraRegisters& r, GdbServerRegister low, GdbServerRegister hi,
                      const char* name, FILE* f) {
  string out = reg_to_string(r, low, hi);
  fprintf(f, "%s:0x%s", name, out.c_str());
}

static void print_regs(const ExtraRegisters& r, GdbServerRegister low, GdbServerRegister hi,
                       int num_regs, const char* name_base, FILE* f) {
  for (int i = 0; i < num_regs; ++i) {
    char buf[80];
    sprintf(buf, "%s%d", name_base, i);
    print_reg(r, (GdbServerRegister)(low + i),
              hi == GdbServerRegister(0) ? hi : (GdbServerRegister)(hi + i), buf, f);
    if (i < num_regs - 1) {
      fputc(' ', f);
    }
  }
}

void ExtraRegisters::print_register_file_compact(FILE* f) const {
  switch (arch_) {
    case x86:
      print_regs(*this, DREG_ST0, GdbServerRegister(0), 8, "st", f);
      fputc(' ', f);
      print_regs(*this, DREG_XMM0, DREG_YMM0H, 8, "ymm", f);
      break;
    case x86_64:
      print_regs(*this, DREG_64_ST0, GdbServerRegister(0), 8, "st", f);
      fputc(' ', f);
      print_regs(*this, DREG_64_XMM0, DREG_64_YMM0H, 16, "ymm", f);
      break;
    case aarch64:
      DEBUG_ASSERT(format_ == NT_FPR);
      print_regs(*this, DREG_V0, GdbServerRegister(0), 32, "v", f);
      fputc(' ', f);
      print_reg(*this, DREG_FPSR, GdbServerRegister(0), "fpsr", f);
      fputc(' ', f);
      print_reg(*this, DREG_FPCR, GdbServerRegister(0), "fpcr", f);
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

static uint32_t features_used(const uint8_t* data) {
  uint64_t features;
  memcpy(&features, data + xsave_header_offset, sizeof(features));
  return features;
}

template <typename Arch>
bool memcpy_fpr_regs_arch(std::vector<uint8_t>& dest, const uint8_t* src,
                          size_t data_size) {
  if (data_size != sizeof(typename Arch::user_fpregs_struct)) {
    LOG(error) << "Invalid FPR data length: " << data_size << " for architecture " <<
      arch_name(Arch::arch()) << ", expected " << sizeof(typename Arch::user_fpregs_struct);
    return false;
  }
  dest.resize(sizeof(typename Arch::user_fpregs_struct));
  memcpy(dest.data(), src, sizeof(typename Arch::user_fpregs_struct));
  return true;
}

bool memcpy_fpr_regs_arch(SupportedArch arch, std::vector<uint8_t>& dest,
                          const uint8_t* src, size_t data_size) {
  RR_ARCH_FUNCTION(memcpy_fpr_regs_arch, arch, dest, src, data_size)
}

bool ExtraRegisters::set_to_raw_data(SupportedArch a, Format format,
                                     const uint8_t* data, size_t data_size,
                                     const XSaveLayout& layout) {
  arch_ = a;
  format_ = NONE;

  if (format == NONE) {
    return true;
  } else if (format == NT_FPR) {
    if (!memcpy_fpr_regs_arch(a, data_, data, data_size)) {
      return false;
    }
    format_ = NT_FPR;
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
    uint64_t features = features_used(data);
    /* Mask off the PKRU bit unconditionally here.
     * We want traces that are recorded on machines with PKRU but
     * that don't actually use PKRU to be replayable on machines
     * without PKRU. Linux, however, sets the PKRU register to
     * 0x55555554 (only the default key is allowed to access memory),
     * while the default hardware value is 0, so in some sense
     * PKRU is always in use.
     *
     * There are three classes of side effects of the pkey feature.
     * 1. The direct effects of syscalls such as pkey_alloc/pkey_mprotect
     *    on registers.
     * 2. Traps generated by the CPU when the protection keys are violated.
     * 3. The RDPKRU instruction writing to EAX.
     *
     * The first two are replayed exactly by rr. The latter will trigger
     * SIGILL on any machine without PKRU, which is no different from
     * any other new CPU instruction that doesn't have its own XSAVE
     * feature bit. So ignore the PKRU bit here and leave users on their
     * own with respect to RDPKRU.
     */
    features &= ~PKRU_FEATURE_MASK;
    if (features & ~native_layout.supported_feature_bits) {
      LOG(error) << "Unsupported CPU features found: got " << HEX(features)
                 << " (" << xsave_feature_string(features)
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

  uint64_t features = features_used(data);
  // OK, now both our native layout and the input layout are using the full
  // XSAVE header. Copy each optional and present area into the right place
  // in our struct.
  for (size_t i = 2; i < 64; ++i) {
    if (features & (uint64_t(1) << i)) {
      if (i >= layout.feature_layouts.size()) {
        LOG(error) << "Invalid feature " << i << " beyond max layout "
                   << layout.feature_layouts.size();
        return false;
      }
      const XSaveFeatureLayout& feature = layout.feature_layouts[i];
      if (uint64_t(feature.offset) + feature.size > layout.full_size) {
        LOG(error) << "Invalid feature region: " << feature.offset << "+"
                   << feature.size << " > " << layout.full_size;
        return false;
      }
      if (i >= native_layout.feature_layouts.size()) {
        if (i == PKRU_FEATURE_BIT) {
          // The native arch doesn't support PKRU.
          // This must be during replay, and as the comments above explain,
          // it's OK to not set PKRU during replay on a pre-PKRU CPU, so
          // we can just ignore this.
          features &= ~PKRU_FEATURE_MASK;
          continue;
        } else {
          LOG(error) << "Invalid feature " << i << " beyond max layout "
                     << layout.feature_layouts.size();
          return false;
        }
      }
      const XSaveFeatureLayout& native_feature =
          native_layout.feature_layouts[i];
      if (native_feature.size == 0 && i == PKRU_FEATURE_BIT) {
        // See the above comment about PKRU.
        features &= ~PKRU_FEATURE_MASK;
        continue;
      }
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

  // Copy the header. Make sure to use our updated `features`.
  memcpy(data_.data() + xsave_header_offset, &features, sizeof(features));
  memcpy(data_.data() + xsave_header_offset + sizeof(features),
         data + xsave_header_offset + sizeof(features),
         xsave_header_size - sizeof(features));

  return true;
}

vector<uint8_t> ExtraRegisters::get_user_fpregs_struct(
    SupportedArch arch) const {
  switch (arch) {
    case x86:
      DEBUG_ASSERT(format_ == XSAVE);
      DEBUG_ASSERT(data_.size() >= sizeof(X86Arch::user_fpxregs_struct));
      return to_vector(convert_fxsave_to_x86_fpregs(
          *reinterpret_cast<const X86Arch::user_fpxregs_struct*>(
              data_.data())));
    case x86_64:
      DEBUG_ASSERT(format_ == XSAVE);
      DEBUG_ASSERT(data_.size() >= sizeof(X64Arch::user_fpregs_struct));
      return to_vector(
          *reinterpret_cast<const X64Arch::user_fpregs_struct*>(data_.data()));
    case aarch64:
      DEBUG_ASSERT(format_ == NT_FPR);
      DEBUG_ASSERT(data_.size() == sizeof(ARM64Arch::user_fpregs_struct));
      return to_vector(
          *reinterpret_cast<const ARM64Arch::user_fpregs_struct*>(data_.data()));
    default:
      DEBUG_ASSERT(0 && "Unknown arch");
      return vector<uint8_t>();
  }
}

void ExtraRegisters::set_user_fpregs_struct(Task* t, SupportedArch arch,
                                            void* data, size_t size) {
  switch (arch) {
    case x86:
      DEBUG_ASSERT(format_ == XSAVE);
      ASSERT(t, size >= sizeof(X86Arch::user_fpregs_struct));
      ASSERT(t, data_.size() >= sizeof(X86Arch::user_fpxregs_struct));
      convert_x86_fpregs_to_fxsave(
          *static_cast<X86Arch::user_fpregs_struct*>(data),
          reinterpret_cast<X86Arch::user_fpxregs_struct*>(data_.data()));
      return;
    case x86_64:
      DEBUG_ASSERT(format_ == XSAVE);
      ASSERT(t, data_.size() >= sizeof(X64Arch::user_fpregs_struct));
      ASSERT(t, size >= sizeof(X64Arch::user_fpregs_struct));
      memcpy(data_.data(), data, sizeof(X64Arch::user_fpregs_struct));
      return;
    case aarch64:
      DEBUG_ASSERT(format_ == NT_FPR);
      ASSERT(t, size >= sizeof(ARM64Arch::user_fpregs_struct));
      ASSERT(t, data_.size() >= sizeof(ARM64Arch::user_fpregs_struct));
      memcpy(data_.data(), data, sizeof(ARM64Arch::user_fpregs_struct));
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

static void set_word(SupportedArch arch, vector<uint8_t>& v, GdbServerRegister r,
                     int word) {
  RegData d = xsave_register_data(arch, r);
  DEBUG_ASSERT(d.size == 4);
  DEBUG_ASSERT(d.offset + d.size <= (int)v.size());
  DEBUG_ASSERT(-1 == d.xsave_feature_bit);
  *reinterpret_cast<int*>(v.data() + d.offset) = word;
}

void ExtraRegisters::reset() {
  memset(data_.data(), 0, data_.size());
  if (is_x86ish(arch())) {
    DEBUG_ASSERT(format_ == XSAVE);
    if (arch() == x86_64) {
      set_word(arch(), data_, DREG_64_MXCSR, 0x1f80);
      set_word(arch(), data_, DREG_64_FCTRL, 0x37f);
    } else {
      set_word(arch(), data_, DREG_MXCSR, 0x1f80);
      set_word(arch(), data_, DREG_FCTRL, 0x37f);
    }
    uint64_t xinuse;
    if (data_.size() >= xinuse_offset + sizeof(xinuse)) {
      memcpy(&xinuse, data_.data() + xinuse_offset, sizeof(xinuse));

      /* We have observed (Skylake, Linux 4.10) the system setting XINUSE's 0 bit
      * to indicate x87-in-use, at times unrelated to x87 actually being used.
      * Work around this by setting the bit unconditionally after exec.
      */
      xinuse |= 1;

      /* If the system supports the PKRU feature, the PKRU feature bit must be
      * set in order to get the kernel to properly update the PKRU register
      * value. If this is not set, it has been observed that the PKRU register
      * may occasionally contain "stale" values, particularly after involuntary
      * context switches.
      * Avoid this issue by setting the bit if the feature is supported by the
      * CPU.
      */
      if (xcr0() & PKRU_FEATURE_MASK) {
        RegData d = xsave_register_data(arch(), arch() == x86_64 ? DREG_64_PKRU : DREG_PKRU);
        DEBUG_ASSERT(d.xsave_feature_bit == PKRU_FEATURE_BIT);
        DEBUG_ASSERT(d.offset + d.size <= (int)data_.size());
        *reinterpret_cast<int*>(data_.data() + d.offset) = 0x55555554;
        xinuse |= PKRU_FEATURE_MASK;
      }

      memcpy(data_.data() + xinuse_offset, &xinuse, sizeof(xinuse));
    }
  } else {
    DEBUG_ASSERT(format_ == NT_FPR);
    DEBUG_ASSERT(arch() == aarch64 &&
      "Ensure that nothing is required here for your architecture.");
  }
}

static void compare_regs(const ExtraRegisters& reg1,
                         const ExtraRegisters& reg2,
                         GdbServerRegister low, GdbServerRegister hi,
                         int num_regs, const char* name_base,
                         Registers::Comparison& result) {
  for (int i = 0; i < num_regs; ++i) {
    GdbServerRegister this_low = (GdbServerRegister)(low + i);
    GdbServerRegister this_hi = hi == GdbServerRegister(0) ? hi : (GdbServerRegister)(hi + i);
    uint8_t buf1[128];
    size_t len1 = get_full_value(reg1, this_low, this_hi, buf1);
    uint8_t buf2[128];
    size_t len2 = get_full_value(reg2, this_low, this_hi, buf2);
    DEBUG_ASSERT(len1 == len2);

    if (!memcmp(buf1, buf2, len1)) {
      continue;
    }

    ++result.mismatch_count;
    if (result.store_mismatches) {
      char regname[80];
      sprintf(regname, "%s%d", name_base, i);
      result.mismatches.push_back({regname, reg_to_string(reg1, this_low, this_hi),
          reg_to_string(reg2, this_low, this_hi)});
    }
  }
}

void ExtraRegisters::compare_internal(const ExtraRegisters& reg2,
  Registers::Comparison& result) const {
  if (arch() != reg2.arch()) {
    FATAL() << "Can't compare register files with different archs";
  }

  if (format() == NONE || reg2.format() == NONE) {
    // Not enough data to check anything
    return;
  }
  if (format() != reg2.format()) {
    FATAL() << "Can't compare register files with different formats";
  }

  switch (arch()) {
    case x86:
      compare_regs(*this, reg2, DREG_ST0, GdbServerRegister(0), 8, "st", result);
      compare_regs(*this, reg2, DREG_XMM0, DREG_YMM0H, 8, "ymm", result);
      break;
    case x86_64:
      compare_regs(*this, reg2, DREG_64_ST0, GdbServerRegister(0), 8, "st", result);
      compare_regs(*this, reg2, DREG_64_XMM0, DREG_64_YMM0H, 8, "ymm", result);
      break;
    case aarch64:
      DEBUG_ASSERT(format_ == NT_FPR);
      compare_regs(*this, reg2, DREG_V0, GdbServerRegister(0), 32, "v", result);
      break;
    default:
      DEBUG_ASSERT(0 && "Unknown arch");
      break;
  }
}

} // namespace rr
