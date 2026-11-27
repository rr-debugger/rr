/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_ASSEMBLER_H_
#define RR_ASSEMBLER_H_

#include <stdint.h>
#include <string.h>

#include <utility>

#include "dr_api.h"

#ifndef remix_assert
#include "remix_util.h"
#endif

#ifdef __clang__
#define REMIX_ASM_TARGET_BEGIN _Pragma("clang attribute push (__attribute__((target(\"no-sse\"))), apply_to=function)")
#define REMIX_ASM_TARGET_END   _Pragma("clang attribute pop")
#elif defined(__GNUC__)
#define REMIX_ASM_TARGET_BEGIN _Pragma("GCC push_options") \
    _Pragma("GCC target(\"no-sse\")")
#define REMIX_ASM_TARGET_END   _Pragma("GCC pop_options")
#else
#error Unknown compiler
#endif

REMIX_ASM_TARGET_BEGIN

/**
 * Let the compiler know our generated code doesn't alias any of our other
 * data (application code/data or remix code/data), by accessing it through
 * pointers to this struct.
 */
struct GeneratedCode {
  uint8_t v;
};

/**
 * A very limited assembler, but it can easily be extended as needed.
 * Use this when instruction types, operand types and register sizes are known
 * at compile time. It's very efficient and concise.
 * Otherwise we use the DynamoRio assembler.
 *
 * We only support a subset of instruction forms (i.e. overloads of
 * the instruction-emitter method), but for each one we support, we support it
 * completely so any incompleteness is caught at compile time.
 */
class Assembler {
public:
  Assembler(GeneratedCode* output) : output(output) {}

  GeneratedCode* next() const { return output; }
  void reset(GeneratedCode* o) { output = o; }

  // Simple write-and-update methods that avoid triggering "can alias anything"
  static GeneratedCode* write(GeneratedCode* output, uint8_t v) {
    output->v = v;
    return output + 1;
  }
  static GeneratedCode* write(GeneratedCode* output, int8_t v) {
    output->v = v;
    return output + 1;
  }
  template <typename T>
  static GeneratedCode* write(GeneratedCode* output, T v) {
    *reinterpret_cast<T*>(output) = v;
    return output + sizeof(v);
  }

  // |imm| emits raw data.

  void imm() {}

  template <typename T> void imm(T* buf, size_t len) {
    memcpy(output, buf, len);
    output += len;
  }

  template <typename... Rest> void imm(uint8_t v, Rest&&... params) {
    output = write(output, v);
    imm(std::forward<Rest>(params)...);
  }
  template <typename... Rest> void imm(int8_t v, Rest&&... params) {
    output = write(output, v);
    imm(std::forward<Rest>(params)...);
  }
  template <typename... Rest> void imm(int v, Rest&&... params) {
    remix_assert(v == (uint8_t)v);
    output = write(output, (uint8_t)v);
    imm(std::forward<Rest>(params)...);
  }

  struct CondByte {
    CondByte() : present(0), byte(0) {}
    CondByte(uint8_t byte) : present(1), byte(byte) {}
    uint8_t present;
    uint8_t byte;
  };
  template <typename... Rest> void imm(CondByte b, Rest&&... params) {
    if (b.present) {
      output = write(output, b.byte);
    }
    imm(std::forward<Rest>(params)...);
  }

  struct VexPrefix {
    VexPrefix() : third_byte_present(0), byte1(0), byte2(0), byte3(0) {}
    VexPrefix(uint8_t byte1, uint8_t byte2)
        : third_byte_present(0), byte1(byte1), byte2(byte2), byte3(0) {}
    VexPrefix(uint8_t byte1, uint8_t byte2, uint8_t byte3)
        : third_byte_present(1), byte1(byte1), byte2(byte2), byte3(byte3) {}
    uint8_t third_byte_present;
    uint8_t byte1;
    uint8_t byte2;
    uint8_t byte3;
  };
  template <typename... Rest> void imm(VexPrefix v, Rest&&... params) {
    output = write(output, v.byte1);
    output = write(output, v.byte2);
    if (v.third_byte_present) {
      output = write(output, v.byte3);
    }
    imm(std::forward<Rest>(params)...);
  }

  struct EvexPrefix {
    uint8_t p0;
    uint8_t p1;
    uint8_t p2;
  };
  template <typename... Rest> void imm(EvexPrefix e, Rest&&... params) {
    output = write(output, (uint8_t)0x62);
    output = write(output, e.p0);
    output = write(output, e.p1);
    output = write(output, e.p2);
    imm(std::forward<Rest>(params)...);
  }

  struct IPRelPC {
    explicit IPRelPC(void* p) : p(p) {}
    void* p;
  };
  void imm(IPRelPC p) { imm_iprel(p.p); }
  struct IPRel256 {
    explicit IPRel256(void* p) : p(p) {}
    void* p;
  };
  void imm(IPRel256 p) { imm_iprel(p.p); }
  struct IPRel128 {
    explicit IPRel128(void* p) : p(p) {}
    void* p;
  };
  void imm(IPRel128 p) { imm_iprel(p.p); }
  /**
   * Can only be used directly as the last parameter to 'imm'. Otherwise
   * use ForwardIPRel.
   */
  struct IPRel64 {
    explicit IPRel64(void* p) : p(p) {}
    void* p;
  };
  void imm(IPRel64 p) { imm_iprel(p.p); }
  /**
   * Can only be used directly as the last parameter to 'imm'. Otherwise
   * use ForwardIPRel.
   */
  struct IPRel32 {
    explicit IPRel32(void* p) : p(p) {}
    void* p;
  };
  void imm(IPRel32 p) { imm_iprel(p.p); }
  /**
   * Can only be used directly as the last parameter to 'imm'. Otherwise
   * use ForwardIPRel.
   */
  struct IPRel16 {
    explicit IPRel16(void* p) : p(p) {}
    void* p;
  };
  void imm(IPRel16 p) { imm_iprel(p.p); }
  struct IPRelConst {
    explicit IPRelConst(const void* p) : p(p) {}
    const void* p;
  };
  void imm(IPRelConst p) { imm_iprel(p.p); }

  /**
   * A location in generated code that can be used once before it's bound.
   */
  template <typename T> struct ForwardIPRel {
    ForwardIPRel() : patch(nullptr), resolved(false) {}
    ForwardIPRel(const ForwardIPRel&) = delete;
    ~ForwardIPRel() {
      // Check that it was resolved or never used
      remix_assert(resolved || !patch);
    }
    void resolve(intptr_t delta) {
      remix_assert(!resolved);
      if (patch) {
        T d = delta;
        remix_assert(d == delta);
        write(patch, d);
      }
      resolved = true;
    }
    GeneratedCode* patch;
    bool resolved;
  };
  template <typename... Rest>
  void imm(ForwardIPRel<int8_t>& p, Rest&&... params) {
    p.patch = output;
    output += sizeof(int8_t);
    imm(std::forward<Rest>(params)...);
  }
  template <typename... Rest>
  void imm(ForwardIPRel<int32_t>& p, Rest&&... params) {
    p.patch = output;
    output += sizeof(int32_t);
    imm(std::forward<Rest>(params)...);
  }
  template <typename T> void label(ForwardIPRel<T>& rel) {
    rel.resolve(output - (rel.patch + sizeof(T)));
  }
  template <typename T> void resolve(ForwardIPRel<T>& rel, void* p) {
    rel.resolve(static_cast<GeneratedCode*>(p) - output);
  }

  template <typename T> struct Imm {
    typedef T Wrapped;
    explicit Imm(T v) : v(v) {}
    T v;
  };
  template <typename T, typename... Rest> void imm(T v, Rest&&... params) {
    output = write(output, (typename T::Wrapped)v.v);
    imm(std::forward<Rest>(params)...);
  }

  // Registers are typed according to size and class.

  class Reg512 {
  public:
    friend class Assembler;
    static Reg512 from_dr(reg_id_t i) {
      remix_assert(i >= DR_REG_START_ZMM && i <= DR_REG_STOP_ZMM);
      return Reg512(i);
    }
    reg_id_t id() const { return r + DR_REG_START_ZMM; }
    bool operator==(const Reg512& other) { return other.r == r; }
    bool operator!=(const Reg512& other) { return other.r != r; }

  private:
    explicit Reg512(reg_id_t i) : r(i - DR_REG_START_ZMM) {}
    uint8_t r;
  };
  class Reg256 {
  public:
    friend class Assembler;
    static Reg256 from_dr(reg_id_t i) {
      remix_assert(i >= DR_REG_START_YMM && i <= DR_REG_STOP_YMM);
      return Reg256(i);
    }
    static Reg256 YMM0() { return Reg256(DR_REG_YMM0); }
    reg_id_t id() const { return r + DR_REG_START_YMM; }
    bool operator==(const Reg256& other) { return other.r == r; }
    bool operator!=(const Reg256& other) { return other.r != r; }

  private:
    explicit Reg256(reg_id_t i) : r(i - DR_REG_START_YMM) {}
    uint8_t r;
  };
  class Reg128 {
  public:
    friend class Assembler;
    static Reg128 from_dr(reg_id_t i) {
      remix_assert(i >= DR_REG_START_XMM && i <= DR_REG_STOP_XMM);
      return Reg128(i);
    }
    static Reg128 XMM0() { return Reg128(DR_REG_XMM0); }
    reg_id_t id() const { return r + DR_REG_START_XMM; }
    bool operator==(const Reg128& other) { return other.r == r; }
    bool operator!=(const Reg128& other) { return other.r != r; }

  private:
    explicit Reg128(reg_id_t i) : r(i - DR_REG_START_XMM) {}
    uint8_t r;
  };
  class Reg64 {
  public:
    friend class Assembler;
    static Reg64 from_dr(reg_id_t i) {
      remix_assert(i >= DR_REG_RAX && i <= DR_REG_R15);
      return Reg64(i);
    }
    static Reg64 RAX() { return Reg64(DR_REG_RAX); }
    static Reg64 RCX() { return Reg64(DR_REG_RCX); }
    static Reg64 RDX() { return Reg64(DR_REG_RDX); }
    static Reg64 RSI() { return Reg64(DR_REG_RSI); }
    static Reg64 RDI() { return Reg64(DR_REG_RDI); }
    static Reg64 RSP() { return Reg64(DR_REG_RSP); }
    static Reg64 RBP() { return Reg64(DR_REG_RBP); }
    static Reg64 R8() { return Reg64(DR_REG_R8); }
    static Reg64 R9() { return Reg64(DR_REG_R9); }
    static Reg64 R10() { return Reg64(DR_REG_R10); }
    static Reg64 R11() { return Reg64(DR_REG_R11); }
    static Reg64 R15() { return Reg64(DR_REG_R15); }
    reg_id_t id() const { return r + DR_REG_RAX; }
    bool operator==(const Reg64& other) { return other.r == r; }
    bool operator!=(const Reg64& other) { return other.r != r; }

  private:
    explicit Reg64(reg_id_t i) : r(i - DR_REG_RAX) {}
    uint8_t r;
  };
  class Reg32 {
  public:
    friend class Assembler;
    static Reg32 from_dr(reg_id_t i) {
      remix_assert(i >= DR_REG_EAX && i <= DR_REG_R15D);
      return Reg32(i);
    }
    static Reg32 EAX() { return Reg32(DR_REG_EAX); }
    static Reg32 EBX() { return Reg32(DR_REG_EBX); }
    static Reg32 ECX() { return Reg32(DR_REG_ECX); }
    static Reg32 EDX() { return Reg32(DR_REG_EDX); }
    static Reg32 ESI() { return Reg32(DR_REG_ESI); }
    static Reg32 R8D() { return Reg32(DR_REG_R8); }
    static Reg32 R9D() { return Reg32(DR_REG_R9D); }
    static Reg32 R10D() { return Reg32(DR_REG_R10D); }
    static Reg32 R11D() { return Reg32(DR_REG_R11D); }
    reg_id_t id() const { return r + DR_REG_EAX; }
    bool operator==(const Reg32& other) { return other.r == r; }
    bool operator!=(const Reg32& other) { return other.r != r; }

  private:
    explicit Reg32(reg_id_t i) : r(i - DR_REG_EAX) {}
    uint8_t r;
  };
  class Reg16 {
  public:
    friend class Assembler;
    static Reg16 from_dr(reg_id_t i) {
      remix_assert(i >= DR_REG_AX && i <= DR_REG_R15W);
      return Reg16(i);
    }
    static Reg16 AX() { return Reg16(DR_REG_AX); }
    static Reg16 R8W() { return Reg16(DR_REG_R8W); }
    static Reg16 R9W() { return Reg16(DR_REG_R9W); }
    static Reg16 R11W() { return Reg16(DR_REG_R11W); }
    reg_id_t id() const { return r + DR_REG_AX; }
    bool operator==(const Reg16& other) { return other.r == r; }
    bool operator!=(const Reg16& other) { return other.r != r; }

  private:
    explicit Reg16(reg_id_t i) : r(i - DR_REG_AX) {}
    uint8_t r;
  };
  enum REXRequirement { REX_REQUIRED, REX_FORBIDDEN, REX_OK };
  class Reg8 {
  public:
    friend class Assembler;
    static Reg8 from_dr(reg_id_t i) {
      remix_assert(i >= DR_REG_AL && i <= DR_REG_DIL);
      return Reg8(i);
    }
    static Reg8 AL() { return Reg8(DR_REG_AL); }
    static Reg8 AH() { return Reg8(DR_REG_AH); }
    static Reg8 R8L() { return Reg8(DR_REG_R8L); }
    static Reg8 R9L() { return Reg8(DR_REG_R9L); }
    static Reg8 R10L() { return Reg8(DR_REG_R10L); }
    reg_id_t id() const {
      return r + DR_REG_AL + (req == REX_REQUIRED ? DR_REG_SPL - DR_REG_AH : 0);
    }
    bool operator==(const Reg8& other) { return other.r == r; }
    bool operator!=(const Reg8& other) { return other.r != r; }

  private:
    explicit Reg8(reg_id_t i) : r(i - DR_REG_AL), req(REX_OK) {
      if (i >= DR_REG_SPL && i <= DR_REG_DIL) {
        req = REX_REQUIRED;
        r = i - DR_REG_SPL + DR_REG_AH - DR_REG_AL;
      } else if (i >= DR_REG_AH && i <= DR_REG_BH) {
        req = REX_FORBIDDEN;
      }
    }
    uint8_t r;
    REXRequirement req;
  };
  class RegK {
  public:
    friend class Assembler;
    static RegK from_dr(reg_id_t i) {
      remix_assert(reg_is_opmask(i));
      return RegK(i);
    }
    static RegK K7() { return RegK(DR_REG_K7); }
  private:
    explicit RegK(reg_id_t i) : r(i - DR_REG_K0) {}
    uint8_t r;
  };

  static Reg32 to32(Reg64 reg) { return Reg32(reg.r + DR_REG_EAX); }
  static Reg16 to16(Reg64 reg) { return Reg16(reg.r + DR_REG_AX); }
  static Reg8 to8(Reg64 reg) {
    if (reg.id() >= DR_REG_RSP && reg.id() <= DR_REG_RDI) {
      return Reg8(reg.id() - DR_REG_RSP + DR_REG_SPL);
    }
    return Reg8(reg.r + DR_REG_AL);
  }

  class RegMem512 {
  public:
    explicit RegMem512(Reg64 reg) : reg(reg) {}
    Reg64 reg;
  };
  class RegMem256 {
  public:
    explicit RegMem256(Reg64 reg) : reg(reg) {}
    Reg64 reg;
  };
  class RegMem128 {
  public:
    explicit RegMem128(Reg64 reg) : reg(reg) {}
    Reg64 reg;
  };
  class RegMem64 {
  public:
    explicit RegMem64(Reg64 reg) : reg(reg) {}
    Reg64 reg;
  };
  class RegMem32 {
  public:
    explicit RegMem32(Reg64 reg) : reg(reg) {}
    Reg64 reg;
  };
  class RegMem16 {
  public:
    explicit RegMem16(Reg64 reg) : reg(reg) {}
    Reg64 reg;
  };
  class RegMem8 {
  public:
    explicit RegMem8(Reg64 reg) : reg(reg) {}
    Reg64 reg;
  };

  class AbsMem64 {
  public:
    explicit AbsMem64(uint32_t addr) : addr(addr) {}
    uint32_t addr;
  };

  // Instruction emitters. We are free to emit the shortest/fastest instruction
  // with the semantics of the requested instruction.

  void jmp(void* addr) {
    intptr_t short_delta = static_cast<GeneratedCode*>(addr) - (output + 2);
    if (short_delta == (int8_t)short_delta) {
      imm(0xeb, (int8_t)short_delta);
    } else {
      imm(0xe9, IPRelPC(addr));
    }
  }
  void jmp(Reg64 reg) {
    imm(cond_rex_b_default(reg), 0xff, modrm_rm(0xE0, reg));
  }

  // Call this instead of 'jmp' when you know the destination won't be within
  // a 7-bit displacement.
  void jmp_long(void* addr) { imm(0xe9, IPRelPC(addr)); }

  void jcc(dr_pred_type_t cond, ForwardIPRel<int8_t>& addr) {
    remix_assert(cond >= DR_PRED_O && cond <= DR_PRED_NLE);
    imm(0x70 + (cond - DR_PRED_O), addr);
  }
  void jcxz(Reg64 reg, ForwardIPRel<int8_t>& addr) {
    remix_assert(reg.id() == DR_REG_RCX);
    imm(0xe3, addr);
  }
  void jcxz(Reg32 reg, ForwardIPRel<int8_t>& addr) {
    remix_assert(reg.id() == DR_REG_ECX);
    imm(0x67, 0xe3, addr);
  }

  void call(void* addr) { imm(0xe8, IPRelPC(addr)); }

  // GAS syntax; from reg to addr
  void mov(Reg64 src, IPRel64 addr) {
    imm(rex_r(src), 0x89, modrm_iprel(src), addr);
  }
  void mov(IPRel64 addr, Reg64 dst) {
    imm(rex_r(dst), 0x8b, modrm_iprel(dst), addr);
  }
  void mov(AbsMem64 addr, Reg64 dst) {
    imm(rex_r(dst), 0x8b, modrm_sib(dst), 0x25, Imm<uint32_t>(addr.addr));
  }
  void mov(Reg32 src, IPRel32 addr) {
    imm(cond_rex_r(src), 0x89, modrm_iprel(src), addr);
  }
  void mov(IPRel32 addr, Reg32 dst) {
    imm(cond_rex_r(dst), 0x8b, modrm_iprel(dst), addr);
  }
  void mov(Reg16 src, IPRel16 addr) {
    imm(0x66, cond_rex_r(src), 0x89, modrm_iprel(src), addr);
  }
  void mov(IPRel16 addr, Reg16 dst) {
    imm(0x66, cond_rex_r(dst), 0x8b, modrm_iprel(dst), addr);
  }
  void mov(int64_t v, Reg64 dst) {
    if (uint32_t(v) == v) {
      // zero-extending 5/6-byte form
      imm(cond_rex_b(to32(dst)), 0xb8 + (dst.r & 7), Imm<uint32_t>(v));
    } else if (int32_t(v) == v) {
      // sign-extending 7-byte form
      imm(rex_b(dst), 0xc7, modrm_rm(0xc0, dst), Imm<int32_t>(v));
    } else {
      // full 10-byte form
      imm(rex_b(dst), 0xb8 + (dst.r & 7), Imm<int64_t>(v));
    }
  }
  void mov(uint32_t v, Reg32 dst) {
    // zero extending
    imm(cond_rex_b(dst), 0xb8 + (dst.r & 7), Imm<uint32_t>(v));
  }
  void mov(int8_t v, Reg8 dst) {
    imm(cond_rex_b(dst), 0xb0 + (dst.r & 7), Imm<int8_t>(v));
  }
  void mov(void* v, Reg64 dst) { mov(uintptr_t(v), dst); }
  void mov(int32_t v, IPRel64 addr) {
    ForwardIPRel<int32_t> rel;
    imm(0x48, 0xc7, modrm_iprel(), rel, Imm<int32_t>(v));
    resolve(rel, addr.p);
  }
  void mov(int32_t v, RegMem64 dst, int32_t offset = 0) {
    imm(rex_b(dst.reg), 0xc7);
    emit_reg_base_offset(0, dst.reg, offset);
    imm(Imm<int32_t>(v));
  }
  void mov(int32_t v, RegMem32 dst, int32_t offset = 0) {
    imm(cond_rex_b_default(dst.reg), 0xc7);
    emit_reg_base_offset(0, dst.reg, offset);
    imm(Imm<int32_t>(v));
  }
  void mov(int32_t v, IPRel32 addr) {
    ForwardIPRel<int32_t> rel;
    imm(0xc7, modrm_iprel(), rel, Imm<int32_t>(v));
    resolve(rel, addr.p);
  }
  void mov(int16_t v, RegMem16 dst, int32_t offset = 0) {
    imm(0x66, cond_rex_b_default(dst.reg), 0xc7);
    emit_reg_base_offset(0, dst.reg, offset);
    imm(Imm<int16_t>(v));
  }
  void mov(int8_t v, RegMem8 dst, int32_t offset = 0) {
    imm(cond_rex_b_default(dst.reg), 0xc6);
    emit_reg_base_offset(0, dst.reg, offset);
    imm(Imm<int8_t>(v));
  }
  void mov(Reg128 src, Reg128 dst) {
    imm(0x66, cond_rex_rb(dst, src), 0x0f, 0x6f, modrm_reg_reg(dst, src));
  }
  void movss(Reg128 src, Reg128 dst) {
    imm(0xf3, cond_rex_rb(dst, src), 0x0f, 0x10, modrm_reg_reg(dst, src));
  }
  void movss_v(Reg128 src1, Reg128 src2, Reg128 dst) {
    // try to get a shorter encoding by avoiding having to set B
    if (dst.r & 0x8) {
      imm(vex_128_f3_0f_rbv(dst, src2, src1), 0x11, modrm_reg_reg(dst, src2));
    } else {
      imm(vex_128_f3_0f_rbv(src2, dst, src1), 0x10, modrm_reg_reg(src2, dst));
    }
  }
  void mov(Reg128 src, IPRel128 dst) {
    imm(0x66, cond_rex_r(src), 0x0f, 0x7f, modrm_iprel(src), dst);
  }
  void mov(IPRel128 src, Reg128 dst) {
    imm(0x66, cond_rex_r(dst), 0x0f, 0x6f, modrm_iprel(dst), src);
  }
  void mov(Reg256 src, Reg256 dst) {
    // try to get a shorter encoding by avoiding having to set B
    if (dst.r & 0x8) {
      imm(vex_256_66_0f_rb(dst, src), 0x6f, modrm_reg_reg(dst, src));
    } else {
      imm(vex_256_66_0f_rb(src, dst), 0x7f, modrm_reg_reg(src, dst));
    }
  }
  void mov(Reg256 src, IPRel256 dst) {
    imm(vex_256_66_0f_r(src), 0x7f, modrm_iprel(src), dst);
  }
  void mov(IPRel256 src, Reg256 dst) {
    imm(vex_256_66_0f_r(dst), 0x6f, modrm_iprel(dst), src);
  }
  void mov_unaligned(Reg128 src, RegMem128 dst, int32_t offset = 0) {
    if (src.r >= 16) {
      imm(evex_128_f3_0f_w0_rb(src, dst.reg), 0x7f);
    } else {
      imm(0xf3, cond_rex_rb(src, dst.reg), 0x0f, 0x7f);
    }
    emit_reg_base_offset(src.r, dst.reg, offset);
  }
  void mov_unaligned_v(Reg128 src, RegMem128 dst, int32_t offset = 0) {
    remix_assert(src.r < 16);
    imm(vex_128_f3_0f_rb(src, dst.reg), 0x7f);
    emit_reg_base_offset(src.r, dst.reg, offset);
  }
  void mov_unaligned(RegMem128 src, int32_t offset, Reg128 dst) {
    if (dst.r >= 16) {
      imm(evex_128_f3_0f_w0_rb(dst, src.reg), 0x6f);
    } else {
      imm(0xf3, cond_rex_rb(dst, src.reg), 0x0f, 0x6f);
    }
    emit_reg_base_offset(dst.r, src.reg, offset);
  }
  void mov_unaligned_v(RegMem128 src, int32_t offset, Reg128 dst) {
    if (dst.r >= 16) {
      imm(evex_128_f3_0f_w0_rb(dst, src.reg), 0x6f);
    } else {
      imm(vex_128_f3_0f_rb(dst, src.reg), 0x6f);
    }
    emit_reg_base_offset(dst.r, src.reg, offset);
  }
  void mov_unaligned(RegMem256 src, int32_t offset, Reg256 dst) {
    if (dst.r >= 16) {
      imm(evex_256_f3_0f_w0_rb(dst, src.reg), 0x6f);
    } else {
      imm(vex_256_f3_0f_rb(dst, src.reg), 0x6f);
    }
    emit_reg_base_offset(dst.r, src.reg, offset);
  }
  void mov_unaligned(Reg256 src, RegMem256 dst, int32_t offset = 0) {
    if (src.r >= 16) {
      imm(evex_256_f3_0f_w0_rb(src, dst.reg), 0x7f);
    } else {
      imm(vex_256_f3_0f_rb(src, dst.reg), 0x7f);
    }
    emit_reg_base_offset(src.r, dst.reg, offset);
  }
  void mov_unaligned(RegMem512 src, int32_t offset, Reg512 dst) {
    imm(evex_512_f3_0f_w0_rb(dst, src.reg), 0x6f);
    emit_reg_base_offset(dst.r, src.reg, offset);
  }
  void mov_unaligned(Reg512 src, RegMem512 dst, int32_t offset = 0) {
    imm(evex_512_f3_0f_w0_rb(src, dst.reg), 0x7f);
    emit_reg_base_offset(src.r, dst.reg, offset);
  }
  void mov(Reg64 src, RegMem64 dst, int32_t offset = 0) {
    imm(rex_rb(src, dst.reg), 0x89);
    emit_reg_base_offset(src.r, dst.reg, offset);
  }
  void mov(Reg64 src, RegMem64 dst) {
    mov(src, dst, 0);
  }
  void mov(Reg32 src, RegMem32 dst, int32_t offset = 0) {
    imm(cond_rex_rb(src, dst.reg), 0x89);
    emit_reg_base_offset(src.r, dst.reg, offset);
  }
  void mov(Reg16 src, RegMem16 dst, int32_t offset = 0) {
    imm(0x66, cond_rex_rb(src, dst.reg), 0x89);
    emit_reg_base_offset(src.r, dst.reg, offset);
  }
  void mov(Reg8 src, RegMem8 dst, int32_t offset = 0) {
    imm(cond_rex_rb(src, dst.reg), 0x88);
    emit_reg_base_offset(src.r, dst.reg, offset);
  }
  void mov(RegMem64 src, Reg64 dst) {
    mov(src, 0, dst);
  }
  void mov(RegMem32 src, Reg32 dst) {
    mov(src, 0, dst);
  }
  void mov(RegMem64 src, int32_t offset, Reg64 dst) {
    imm(rex_rb(dst, src.reg), 0x8b);
    emit_reg_base_offset(dst.r, src.reg, offset);
  }
  void mov(RegMem32 src, int32_t offset, Reg32 dst) {
    imm(cond_rex_rb(dst, src.reg), 0x8b);
    emit_reg_base_offset(dst.r, src.reg, offset);
  }
  void mov(RegMem16 src, int32_t offset, Reg16 dst) {
    imm(0x66, cond_rex_rb(dst, src.reg), 0x8b);
    emit_reg_base_offset(dst.r, src.reg, offset);
  }
  void mov(RegMem16 src, Reg16 dst) {
    mov(src, 0, dst);
  }
  void mov(RegMem8 src, int32_t offset, Reg8 dst) {
    imm(cond_rex_rb(dst, src.reg), 0x8a);
    emit_reg_base_offset(dst.r, src.reg, offset);
  }
  void mov(Reg64 src, Reg64 dst) {
    imm(rex_rb(src, dst), 0x89, modrm_reg_reg(src, dst));
  }
  void mov(Reg32 src, Reg32 dst) {
    imm(cond_rex_rb(src, dst), 0x89, modrm_reg_reg(src, dst));
  }
  void mov(Reg16 src, Reg16 dst) {
    imm(0x66, cond_rex_rb(src, dst), 0x89, modrm_reg_reg(src, dst));
  }

  void movzx(Reg8 src, Reg32 dst) {
    imm(cond_rex_rb(dst, src), 0x0f, 0xb6, modrm_reg_reg(src, dst));
  }

  void xchg(Reg64 r1, Reg64 r2) {
    if (r1.r == 0) {
      imm(rex_r(r2), 0x90 + (r2.r & 7));
    } else if (r2.r == 0) {
      imm(rex_r(r1), 0x90 + (r1.r & 7));
    } else {
      imm(rex_rb(r1, r2), 0x87, modrm_reg_reg(r1, r2));
    }
  }

  void lea(IPRel64 addr, Reg64 dst) {
    imm(rex_r(dst), 0x8d, modrm_iprel(dst), addr);
  }
  void lea(IPRelConst addr, Reg64 dst) {
    imm(rex_r(dst), 0x8d, modrm_iprel(dst), addr);
  }
  void lea(ForwardIPRel<int32_t>& addr, Reg64 dst) {
    imm(rex_r(dst), 0x8d, modrm_iprel(dst), addr);
  }
  void lea(RegMem64 base, int32_t disp, Reg64 dst) {
    imm(rex_rb(dst, base.reg), 0x8d);
    emit_reg_base_offset(dst.r, base.reg, disp);
  }
  void lea(RegMem32 base, int32_t disp, Reg32 dst) {
    imm(cond_rex_rb(dst, base.reg), 0x8d);
    emit_reg_base_offset(dst.r, base.reg, disp);
  }
  void lea(RegMem64 base, Reg64 index, Reg64 dst) {
    lea(base, index, 1, dst);
  }
  void lea(RegMem64 base, Reg64 index, uint8_t scale, Reg64 dst) {
    imm(rex_rxb(dst, index, base), 0x8d, modrm_sib(dst),
        sib(scale, index, base.reg));
  }
  void lea(RegMem32 base, Reg32 index, Reg32 dst) {
    imm(0x67, cond_rex_rxb(dst, index, base), 0x8d, modrm_sib(dst),
        sib(1, index, base));
  }

  void push(Reg64 reg) { imm(cond_rex_b_default(reg), 0x50 + (reg.r & 7)); }
  void push(RegMem64 src, int32_t offset = 0) {
    imm(cond_rex_b_default(src.reg), 0xff);
    emit_reg_base_offset(6, src.reg, offset);
  }
  void push(RegMem16 src, int32_t offset = 0) {
    imm(0x66, cond_rex_b_default(src.reg), 0xff);
    emit_reg_base_offset(6, src.reg, offset);
  }
  void pop(Reg64 reg) { imm(cond_rex_b_default(reg), 0x58 + (reg.r & 7)); }
  void popf() { imm(0x9d); }
  void popf16() { imm(0x66, 0x9d); }

  void cmp(Reg64 left, Reg64 right) {
    imm(rex_rb(left, right), 0x39, modrm_reg_reg(left, right));
  }
  void cmp(Reg32 left, Reg32 right) {
    imm(cond_rex_rb(left, right), 0x39, modrm_reg_reg(left, right));
  }

  void add(Reg64 src, IPRel64 addr) {
    imm(rex_r(src), 0x01, modrm_iprel(src), addr);
  }
  void add(Reg64 src, Reg64 dst) {
    imm(rex_rb(src, dst), 0x01, modrm_reg_reg(src, dst));
  }
  void add(Reg64 src, RegMem64 dst) {
    imm(rex_rb(src, dst.reg), 0x01);
    emit_reg_base_offset(src.r, dst.reg, 0);
  }
  void add(Reg32 src, IPRel32 addr) {
    imm(cond_rex_r(src), 0x01, modrm_iprel(src), addr);
  }
  void add(int32_t v, IPRel32 addr) {
    ForwardIPRel<int32_t> rel;
    if (int8_t(v) == v) {
      imm(0x83, modrm_iprel(), rel, Imm<int8_t>(v));
    } else {
      imm(0x81, modrm_iprel(), rel, Imm<int32_t>(v));
    }
    resolve(rel, addr.p);
  }
  void add(int32_t v, IPRel64 addr) {
    ForwardIPRel<int32_t> rel;
    if (int8_t(v) == v) {
      imm(0x48, 0x83, modrm_iprel(), rel, Imm<int8_t>(v));
    } else {
      imm(0x48, 0x81, modrm_iprel(), rel, Imm<int32_t>(v));
    }
    resolve(rel, addr.p);
  }
  void add(int8_t v, Reg8 reg) {
    if (reg.r == 0) {
      imm(0x04, v);
    } else {
      imm(cond_rex_b(reg), 0x80, modrm_rm(0xc0, reg), v);
    }
  }

  void _and(IPRel64 addr, Reg32 dst) {
    imm(cond_rex_r(dst), 0x23, modrm_iprel(dst), addr);
  }
  void _and(int16_t v, RegMem16 dst, int32_t offset = 0) {
    imm(0x66, cond_rex_b_default(dst.reg), 0x81);
    emit_reg_base_offset(4, dst.reg, offset);
    imm(Imm<int16_t>(v));
  }
  void _and(int32_t v, RegMem32 dst, int32_t offset = 0) {
    imm(cond_rex_b_default(dst.reg), 0x81);
    emit_reg_base_offset(4, dst.reg, offset);
    imm(Imm<int32_t>(v));
  }

  void sub(Reg64 src, Reg64 dst) {
    imm(rex_rb(src, dst), 0x29, modrm_reg_reg(src, dst));
  }
  void sub(Reg32 src, Reg32 dst) {
    imm(cond_rex_rb(src, dst), 0x29, modrm_reg_reg(src, dst));
  }
  void sub(int8_t v, Reg64 dst) {
    imm(rex_b(dst), 0x83, modrm_rm(0xe8, dst), v);
  }

  // These instructions have slightly different flag effects so we let the
  // caller select explicitly.
  void shl(Reg64 dst) { imm(rex_b(dst), 0xd1, modrm_rm(0xE0, dst)); }
  void shl(uint8_t count, Reg64 dst) {
    imm(rex_b(dst), 0xc1, modrm_rm(0xE0, dst), Imm<uint8_t>(count));
  }

  void inc(IPRel64 addr) { imm(0x48, 0xff, modrm_iprel(), addr); }
  void inc(IPRel32 addr) { imm(0xff, modrm_iprel(), addr); }

  void lahf() { imm(0x9f); }
  void sahf() { imm(0x9e); }

  void setcc(dr_pred_type_t cc, Reg8 reg) {
    remix_assert(cc >= DR_PRED_O && cc <= DR_PRED_NLE);
    imm(cond_rex_b(reg), 0x0f, 0x90 + (cc - DR_PRED_O), modrm_rm(0xc0, reg));
  }

  void syscall() { imm(0x0f, 0x05); }

  void instruction(instr_t& instruction) {
    byte* out = reinterpret_cast<byte*>(output);
    output = reinterpret_cast<GeneratedCode*>(
        instr_encode(GLOBAL_DCONTEXT, &instruction, out));
    remix_assert(output != nullptr);
  }

  void kmovq(RegK src, RegK dst) {
    imm(VexPrefix(0xc4, 0xe1, 0xf8), Imm<uint8_t>(0x90),
        Imm<uint8_t>(0xc0 | (dst.r << 3) | src.r));
  }
  void kmovq(RegK src, IPRel64 dst) {
    imm(VexPrefix(0xc4, 0xe1, 0xf8), Imm<uint8_t>(0x91),
        Imm<uint8_t>(modrm_iprel(src)), dst);
  }
  void kmovq(IPRel64 src, RegK dst) {
    imm(VexPrefix(0xc4, 0xe1, 0xf8), Imm<uint8_t>(0x90),
        Imm<uint8_t>(modrm_iprel(dst)), src);
  }
  void kmovq(RegMem64 src, int32_t offset, RegK dst) {
    imm(vex_l0_0f_w1_kb(src.reg), Imm<uint8_t>(0x90));
    emit_reg_base_offset(dst.r, src.reg, offset);
  }
  void kmovq(RegK src, RegMem64 dst, int32_t offset) {
    imm(vex_l0_0f_w1_kb(dst.reg), Imm<uint8_t>(0x91));
    emit_reg_base_offset(src.r, dst.reg, offset);
  }

  void vstmxcsr(RegMem32 dst, int32_t offset) {
    imm((dst.reg.r & 8) ? VexPrefix(0xc4, 0xc1, 0x78) : VexPrefix(0xc5, 0xf8),
        Imm<uint8_t>(0xae));
    emit_reg_base_offset(3, dst.reg, offset);
  }

  void vldmxcsr(RegMem32 src, int32_t offset) {
    imm((src.reg.r & 8) ? VexPrefix(0xc4, 0xc1, 0x78) : VexPrefix(0xc5, 0xf8),
        Imm<uint8_t>(0xae));
    emit_reg_base_offset(2, src.reg, offset);
  }

  void nops(uint32_t count) {
    uint32_t remaining = count;
    while (remaining >= 10) {
      imm(0x66, 0x2e, 0x0f, 0x1f, 0x84, 0, 0, 0, 0, 0);
      remaining -= 10;
    }
    switch (remaining) {
      case 1:
        imm(0x90);
        break;
      case 2:
        imm(0x66, 0x90);
        break;
      case 3:
        imm(0x0f, 0x1f, 0);
        break;
      case 4:
        imm(0x0f, 0x1f, 0x40, 0);
        break;
      case 5:
        imm(0x0f, 0x1f, 0x44, 0, 0);
        break;
      case 6:
        imm(0x66, 0x0f, 0x1f, 0x44, 0, 0);
        break;
      case 7:
        imm(0x0f, 0x1f, 0x80, 0, 0, 0, 0);
        break;
      case 8:
        imm(0x0f, 0x1f, 0x84, 0, 0, 0, 0, 0);
        break;
      case 9:
        imm(0x66, 0x0f, 0x1f, 0x84, 0, 0, 0, 0, 0);
        break;
      default:
        break;
    }
  }

private:
  void imm_iprel(const void* p) {
    intptr_t delta = static_cast<const GeneratedCode*>(p) - (output + 4);
    int32_t d = delta;
    remix_assert(d == delta);
    output = write(output, d);
  }

  // Encoding helpers
  void emit_reg_base_offset(int r, Reg64 base, int32_t offset) {
    CondByte maybe_sib = necessary_sib_for_base(base);
    if (offset == 0) {
      imm(modrm(r, base), maybe_sib);
    } else if (int8_t(offset) == offset) {
      imm(modrm_disp8(r, base), maybe_sib, Imm<int8_t>(offset));
    } else {
      imm(modrm_disp32(r, base), maybe_sib, Imm<int32_t>(offset));
    }
  }

  static uint8_t rex_rb(Reg64 r, Reg64 b) {
    return 0x48 + ((r.r & 8) ? 0x4 : 0) + ((b.r & 8) ? 0x1 : 0);
  }
  static uint8_t rex_r(Reg64 r) { return (r.r & 8) ? 0x4c : 0x48; }
  static uint8_t rex_b(Reg64 b) { return (b.r & 8) ? 0x49 : 0x48; }
  static CondByte cond_rex_b_default(Reg64 b) {
    return (b.r & 8) ? CondByte(0x41) : CondByte();
  }
  static uint8_t rex_rxb(Reg64 r, Reg64 x, RegMem64 b) {
    return 0x48 + ((r.r & 8) ? 0x4 : 0) + ((x.r & 8) ? 0x2 : 0) +
           ((b.reg.r & 8) ? 0x1 : 0);
  }

  static CondByte cond_rex_rb(Reg128 r, Reg128 b) {
    return ((r.r | b.r) & 8)
               ? CondByte(((r.r & 8) ? 0x44 : 0x40) + ((b.r & 8) ? 0x1 : 0))
               : CondByte();
  }

  static CondByte cond_rex_rb(Reg128 r, Reg64 b) {
    return ((r.r | b.r) & 8)
               ? CondByte(((r.r & 8) ? 0x44 : 0x40) + ((b.r & 8) ? 0x1 : 0))
               : CondByte();
  }

  static CondByte cond_rex_rb(Reg32 r, Reg32 b) {
    return ((r.r | b.r) & 8)
               ? CondByte(((r.r & 8) ? 0x44 : 0x40) + ((b.r & 8) ? 0x1 : 0))
               : CondByte();
  }
  static CondByte cond_rex_rb(Reg32 r, Reg64 b) {
    return ((r.r | b.r) & 8)
               ? CondByte(((r.r & 8) ? 0x44 : 0x40) + ((b.r & 8) ? 0x1 : 0))
               : CondByte();
  }
  static CondByte cond_rex_rb(Reg32 r, Reg8 b) {
    return ((r.r | b.r) & 8)
               ? CondByte(((r.r & 8) ? 0x44 : 0x40) + ((b.r & 8) ? 0x1 : 0))
               : CondByte();
  }
  static CondByte cond_rex_r(Reg128 r) {
    return (r.r & 8) ? CondByte(0x44) : CondByte();
  }
  static CondByte cond_rex_r(Reg32 r) {
    return (r.r & 8) ? CondByte(0x44) : CondByte();
  }
  static CondByte cond_rex_r(Reg16 r) {
    return (r.r & 8) ? CondByte(0x44) : CondByte();
  }
  static CondByte cond_rex_b(Reg32 b) {
    return (b.r & 8) ? CondByte(0x41) : CondByte();
  }
  static CondByte cond_rex_rxb(Reg32 r, Reg32 x, RegMem32 b) {
    return ((r.r | x.r | b.reg.r) & 8)
               ? CondByte(((r.r & 8) ? 0x44 : 0x40) + ((x.r & 8) ? 0x2 : 0) +
                          ((b.reg.r & 8) ? 0x1 : 0))
               : CondByte();
  }

  static CondByte cond_rex_rb(Reg16 r, Reg16 b) {
    return ((r.r | b.r) & 8)
               ? CondByte(((r.r & 8) ? 0x44 : 0x40) + ((b.r & 8) ? 0x1 : 0))
               : CondByte();
  }
  static CondByte cond_rex_rb(Reg16 r, Reg64 b) {
    return ((r.r | b.r) & 8)
               ? CondByte(((r.r & 8) ? 0x44 : 0x40) + ((b.r & 8) ? 0x1 : 0))
               : CondByte();
  }

  static CondByte cond_rex_b(Reg8 b) {
    return (b.req == REX_REQUIRED || (b.r & 8))
               ? CondByte(0x40 + ((b.r & 8) ? 0x1 : 0))
               : CondByte();
  }
  static CondByte cond_rex_rb(Reg8 r, Reg64 b) {
    remix_assert(r.req != REX_FORBIDDEN || !(b.r & 8));
    return (r.req == REX_REQUIRED || ((r.r | b.r) & 8))
               ? CondByte(((r.r & 8) ? 0x44 : 0x40) + ((b.r & 8) ? 0x1 : 0))
               : CondByte();
  }

  static uint8_t rex_rb(Reg64 r, RegMem64 b) {
    return ((r.r & 8) ? 0x4c : 0x48) + ((b.reg.r & 8) ? 0x1 : 0);
  }
  static CondByte cond_rex_rb(Reg32 r, RegMem32 b) {
    return ((r.r | b.reg.r) & 8)
               ? CondByte(((r.r & 8) ? 0x44 : 0x40) + ((b.reg.r & 8) ? 0x1 : 0))
               : CondByte();
  }

  static VexPrefix vex_128_f3_0f_rb(Reg128 r, Reg64 b) {
    return (b.r & 8) ? VexPrefix(0xc4, (r.r & 8) ? 0x41 : 0xc1, 0x7a)
                     : VexPrefix(0xc5, (r.r & 8) ? 0x7a : 0xfa);
  }

  static VexPrefix vex_128_f3_0f_rbv(Reg128 r, Reg128 b, Reg128 v) {
    uint8_t bits = ((v.r ^ 15) << 3) + 2;
    return (b.r & 8) ? VexPrefix(0xc4, (r.r & 8) ? 0x41 : 0xc1, bits)
                     : VexPrefix(0xc5, (r.r & 8) ? bits : bits | 0x80);
  }

  static VexPrefix vex_256_f3_0f_rb(Reg256 r, Reg64 b) {
    return (b.r & 8) ? VexPrefix(0xc4, (r.r & 8) ? 0x41 : 0xc1, 0x7e)
                     : VexPrefix(0xc5, (r.r & 8) ? 0x7e : 0xfe);
  }

  static VexPrefix vex_256_66_0f_r(Reg256 r) {
    return VexPrefix(0xc5, (r.r & 8) ? 0x7d : 0xfd);
  }

  static VexPrefix vex_256_66_0f_rb(Reg256 r, Reg256 b) {
    return (b.r & 8) ? VexPrefix(0xc4, (r.r & 8) ? 0x41 : 0xc1, 0x7d)
                     : VexPrefix(0xc5, (r.r & 8) ? 0x7d : 0xfd);
  }

  static VexPrefix vex_l0_0f_w1_kb(Reg64 b) {
    return VexPrefix(0xc4, (b.r & 8) ? 0xc1 : 0xe1, 0xf8);
  }

  static EvexPrefix evex_512_f3_0f_w0_rb(Reg512 r, Reg64 b) {
    uint8_t p0 = ((r.r & 8) ? 0 : 0x80) | 0x40
               | ((b.r & 8) ? 0 : 0x20) | ((r.r & 16) ? 0 : 0x10) | 0x01;
    return { p0, 0x7e, 0x48 };
  }

  static EvexPrefix evex_256_f3_0f_w0_rb(Reg256 r, Reg64 b) {
    uint8_t p0 = ((r.r & 8) ? 0 : 0x80) | 0x40
               | ((b.r & 8) ? 0 : 0x20) | ((r.r & 16) ? 0 : 0x10) | 0x01;
    return { p0, 0x7e, 0x28 };
  }

  static EvexPrefix evex_128_f3_0f_w0_rb(Reg128 r, Reg64 b) {
    uint8_t p0 = ((r.r & 8) ? 0 : 0x80) | 0x40
               | ((b.r & 8) ? 0 : 0x20) | ((r.r & 16) ? 0 : 0x10) | 0x01;
    return { p0, 0x7e, 0x08 };
  }

  static CondByte necessary_sib_for_base(Reg64 r) {
    return (r.r & 7) == 4 ? CondByte(0x24) : CondByte();
  }

  static uint8_t modrm_iprel(RegK reg) { return (reg.r << 3) + 5; }
  static uint8_t modrm_iprel(Reg256 reg) { return ((reg.r & 7) << 3) + 5; }
  static uint8_t modrm_iprel(Reg128 reg) { return ((reg.r & 7) << 3) + 5; }
  static uint8_t modrm_iprel(Reg64 reg) { return ((reg.r & 7) << 3) + 5; }
  static uint8_t modrm_iprel(Reg32 reg) { return ((reg.r & 7) << 3) + 5; }
  static uint8_t modrm_iprel(Reg16 reg) { return ((reg.r & 7) << 3) + 5; }
  static uint8_t modrm_iprel() { return 5; }
  static uint8_t modrm_rm(uint8_t mod, Reg64 rm) { return mod + (rm.r & 7); }
  static uint8_t modrm(int reg, Reg64 rm) {
    return ((reg & 7) << 3) + (rm.r & 7);
  }
  static uint8_t modrm_disp8(int reg, Reg64 rm) {
    return 0x40 + ((reg & 7) << 3) + (rm.r & 7);
  }
  static uint8_t modrm_disp32(int reg, Reg64 rm) {
    return 0x80 + ((reg & 7) << 3) + (rm.r & 7);
  }
  static uint8_t modrm_sib(Reg64 reg) { return ((reg.r & 7) << 3) + 0x4; }
  static uint8_t modrm_sib_disp8(Reg64 reg) {
    return 0x40 + ((reg.r & 7) << 3) + 4;
  }
  static uint8_t modrm_sib_disp32(Reg64 reg) {
    return 0x80 + ((reg.r & 7) << 3) + 4;
  }
  static uint8_t modrm_reg_reg(Reg256 reg, Reg256 rm) {
    return 0xc0 + ((reg.r & 7) << 3) + (rm.r & 7);
  }
  static uint8_t modrm_reg_reg(Reg128 reg, Reg128 rm) {
    return 0xc0 + ((reg.r & 7) << 3) + (rm.r & 7);
  }
  static uint8_t modrm_reg_reg(Reg64 reg, Reg64 rm) {
    return 0xc0 + ((reg.r & 7) << 3) + (rm.r & 7);
  }
  static uint8_t modrm_reg_reg(Reg32 reg, Reg32 rm) {
    return 0xc0 + ((reg.r & 7) << 3) + (rm.r & 7);
  }
  static uint8_t modrm_reg_reg(Reg16 reg, Reg16 rm) {
    return 0xc0 + ((reg.r & 7) << 3) + (rm.r & 7);
  }
  static uint8_t modrm_reg_reg(Reg8 reg, Reg32 rm) {
    return 0xc0 + ((reg.r & 7) << 3) + (rm.r & 7);
  }
  static uint8_t modrm_sib(Reg32 reg) { return ((reg.r & 7) << 3) + 0x4; }
  static uint8_t modrm_rm(uint8_t mod, Reg8 rm) { return mod + (rm.r & 7); }

  static uint8_t scale_to_sib(uint8_t scale) {
    switch (scale) {
      case 1: return 0 << 6;
      case 2: return 1 << 6;
      case 4: return 2 << 6;
      case 8: return 3 << 6;
      default:
        remix_assert(0 && "Invalid scale");
        return 0;
    }
  }
  static uint8_t sib(uint8_t scale, Reg64 index, Reg64 base) {
    return scale_to_sib(scale) + ((index.r & 7) << 3) + (base.r & 7);
  }
  static uint8_t sib(Reg64 base) { return (4 << 3) + (base.r & 7); }
  static uint8_t sib(uint8_t scale, Reg32 index, RegMem32 base) {
    return scale_to_sib(scale) + ((index.r & 7) << 3) + (base.reg.r & 7);
  }

  GeneratedCode* output;
};

REMIX_ASM_TARGET_END

#endif /* RR_ASSEMBLER_H_ */
