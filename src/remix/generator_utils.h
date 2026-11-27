/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_GENERATOR_UTILS_H_
#define RR_GENERATOR_UTILS_H_

#include "Assembler.h"

/**
 * |reg| must be 64-bit.
 * If |match| is an 8-bit register, return the 8-bit version of |reg|.
 * if |match| is a 16-bit register, return the 16-bit version of |reg|.
 * If |match| is a 32-bit register, return the 32-bit version of |reg|.
 * If |match| is a 64-bit register or DR_REG_NULL, return |reg|.
 */
inline reg_id_t match_reg_size(reg_id_t reg, reg_id_t match) {
  remix_assert(DR_REG_RAX <= reg && reg <= DR_REG_R15);
  if (DR_REG_NULL == match || (DR_REG_RAX <= match && match <= DR_REG_R15)) {
    return reg;
  }
  if (DR_REG_EAX <= match && match <= DR_REG_R15D) {
    return reg - DR_REG_RAX + DR_REG_EAX;
  }
  if (DR_REG_AX <= match && match <= DR_REG_R15W) {
    return reg - DR_REG_RAX + DR_REG_AX;
  }
  if (DR_REG_AH <= match && match <= DR_REG_BH) {
    if (DR_REG_RAX <= reg && reg <= DR_REG_RBX) {
      return reg - DR_REG_RAX + DR_REG_AH;
    }
    // The other registers don't have an equivalent ...
    remix_assert(false);
    return DR_REG_NULL;
  }
  if (DR_REG_AL <= match && match <= DR_REG_DIL) {
    if (DR_REG_RAX <= reg && reg <= DR_REG_RBX) {
      return reg - DR_REG_RAX + DR_REG_AL;
    }
    if (DR_REG_RSP <= reg && reg <= DR_REG_RDI) {
      return reg - DR_REG_RSP + DR_REG_SPL;
    }
    if (DR_REG_R8 <= reg && reg <= DR_REG_R15) {
      return reg - DR_REG_R8 + DR_REG_R8L;
    }
  }
  remix_assert(false);
  return DR_REG_NULL;
}

inline reg_id_t to_64(reg_id_t reg) {
  if (reg >= DR_REG_RAX && reg <= DR_REG_R15) {
    return reg;
  }
  if (reg >= DR_REG_EAX && reg <= DR_REG_R15D) {
    return reg - DR_REG_EAX + DR_REG_RAX;
  }
  if (reg >= DR_REG_AX && reg <= DR_REG_R15W) {
    return reg - DR_REG_AX + DR_REG_RAX;
  }
  if (reg >= DR_REG_AL && reg <= DR_REG_BL) {
    return reg - DR_REG_AL + DR_REG_RAX;
  }
  if (reg >= DR_REG_AH && reg <= DR_REG_BH) {
    return reg - DR_REG_AH + DR_REG_RAX;
  }
  if (reg >= DR_REG_R8L && reg <= DR_REG_R15L) {
    return reg - DR_REG_R8L + DR_REG_R8;
  }
  if (reg >= DR_REG_SPL && reg <= DR_REG_DIL) {
    return reg - DR_REG_SPL + DR_REG_RSP;
  }
  return DR_REG_NULL;
}

inline reg_id_t to_128(reg_id_t reg) {
  if (reg >= DR_REG_START_XMM && reg <= DR_REG_STOP_XMM) {
    return reg;
  }
  return DR_REG_NULL;
}

inline reg_id_t to_256(reg_id_t reg) {
  if (reg >= DR_REG_START_YMM && reg <= DR_REG_STOP_YMM) {
    return reg;
  }
  if (reg >= DR_REG_START_XMM && reg <= DR_REG_STOP_XMM) {
    return reg - DR_REG_START_XMM + DR_REG_START_YMM;
  }
  return DR_REG_NULL;
}

inline reg_id_t to_512(reg_id_t reg) {
  if (reg >= DR_REG_START_ZMM && reg <= DR_REG_STOP_ZMM) {
    return reg;
  }
  if (reg >= DR_REG_START_XMM && reg <= DR_REG_STOP_XMM) {
    return reg - DR_REG_START_XMM + DR_REG_START_ZMM;
  }
  if (reg >= DR_REG_START_YMM && reg <= DR_REG_STOP_YMM) {
    return reg - DR_REG_START_YMM + DR_REG_START_ZMM;
  }
  return DR_REG_NULL;
}

inline Assembler::Reg64 RAX() { return Assembler::Reg64::RAX(); }
inline Assembler::Reg64 RCX() { return Assembler::Reg64::RCX(); }
inline Assembler::Reg64 RDX() { return Assembler::Reg64::RDX(); }
inline Assembler::Reg64 RSI() { return Assembler::Reg64::RSI(); }
inline Assembler::Reg64 RDI() { return Assembler::Reg64::RDI(); }
inline Assembler::Reg64 RSP() { return Assembler::Reg64::RSP(); }
inline Assembler::Reg64 RBP() { return Assembler::Reg64::RBP(); }
inline Assembler::Reg64 R8() { return Assembler::Reg64::R8(); }
inline Assembler::Reg64 R9() { return Assembler::Reg64::R9(); }
inline Assembler::Reg64 R10() { return Assembler::Reg64::R10(); }
inline Assembler::Reg64 R11() { return Assembler::Reg64::R11(); }
inline Assembler::Reg64 R15() { return Assembler::Reg64::R15(); }

inline Assembler::Reg32 EAX() { return Assembler::Reg32::EAX(); }
inline Assembler::Reg32 EBX() { return Assembler::Reg32::EBX(); }
inline Assembler::Reg32 ECX() { return Assembler::Reg32::ECX(); }
inline Assembler::Reg32 EDX() { return Assembler::Reg32::EDX(); }
inline Assembler::Reg32 ESI() { return Assembler::Reg32::ESI(); }
inline Assembler::Reg32 R8D() { return Assembler::Reg32::R8D(); }
inline Assembler::Reg32 R9D() { return Assembler::Reg32::R9D(); }
inline Assembler::Reg32 R10D() { return Assembler::Reg32::R10D(); }
inline Assembler::Reg32 R11D() { return Assembler::Reg32::R11D(); }

inline Assembler::Reg16 AX() { return Assembler::Reg16::AX(); }
inline Assembler::Reg16 R8W() { return Assembler::Reg16::R8W(); }
inline Assembler::Reg16 R9W() { return Assembler::Reg16::R9W(); }
inline Assembler::Reg16 R11W() { return Assembler::Reg16::R11W(); }

inline Assembler::Reg8 AL() { return Assembler::Reg8::AL(); }
inline Assembler::Reg8 AH() { return Assembler::Reg8::AH(); }
inline Assembler::Reg8 R8L() { return Assembler::Reg8::R8L(); }
inline Assembler::Reg8 R9L() { return Assembler::Reg8::R9L(); }
inline Assembler::Reg8 R10L() { return Assembler::Reg8::R10L(); }

inline bool reg_is_variable_opmask(reg_id_t reg) { return reg >= DR_REG_K1 && reg <= DR_REG_K7; }

inline bool has_variable_opmask(instr_t* instr) {
  if (instr_num_srcs(instr) == 0) {
    return false;
  }

  opnd_t src = instr_get_src(instr, 0);
  return OPND_IS_REG(src) && reg_is_variable_opmask(opnd_get_reg(src));
}

/* Returns true iff `instr` is a cache flush of some sort (i.e. non-architectural).
 * This should be in DynamoRIO but implementing it for DR's non-x86 architectures
 * is a lot harder.
 */
inline bool instr_is_cache_flush(instr_t* instr) {
  switch (instr_get_opcode(instr)) {
  case OP_clflush:
  case OP_clflushopt:
  case OP_clwb:
  case OP_cldemote:
    return true;
  default:
    return false;
  }
}

#define INSTR_HAS_EVEX_FAULT_SUPPRESSION 1
#define INSTR_CAN_MODIFY_MXCSR 2

inline uint8_t instr_has_fault_suppression(instr_t* instr) {
  switch (instr_get_opcode(instr)) {
  // E2
  case OP_vaddpd:
  case OP_vaddps:
  case OP_vcmppd:
  case OP_vcmpps:
  case OP_vcvtdq2ps:
  case OP_vcvtpd2dq:
  case OP_vcvtpd2ps:
  case OP_vcvtpd2qq:
  case OP_vcvtpd2udq:
  case OP_vcvtpd2uqq:
  case OP_vcvtps2dq:
  case OP_vcvtps2udq:
  case OP_vcvtqq2pd:
  case OP_vcvtqq2ps:
  case OP_vcvttpd2dq:
  case OP_vcvttpd2qq:
  case OP_vcvttpd2udq:
  case OP_vcvttpd2uqq:
  case OP_vcvttps2dq:
  case OP_vcvttps2udq:
  case OP_vcvtudq2ps:
  case OP_vcvtuqq2pd:
  case OP_vcvtuqq2ps:
  case OP_vdivpd:
  case OP_vdivps:
  case OP_vexp2pd:
  case OP_vexp2ps:
  case OP_vfixupimmpd:
  case OP_vfixupimmps:
  case OP_vfmadd132pd:
  case OP_vfmadd213pd:
  case OP_vfmadd231pd:
  case OP_vfmadd132ps:
  case OP_vfmadd213ps:
  case OP_vfmadd231ps:
  case OP_vfmaddsub132pd:
  case OP_vfmaddsub213pd:
  case OP_vfmaddsub231pd:
  case OP_vfmaddsub132ps:
  case OP_vfmaddsub213ps:
  case OP_vfmaddsub231ps:
  case OP_vfmsubadd132pd:
  case OP_vfmsubadd213pd:
  case OP_vfmsubadd231pd:
  case OP_vfmsubadd132ps:
  case OP_vfmsubadd213ps:
  case OP_vfmsubadd231ps:
  case OP_vfmsub132pd:
  case OP_vfmsub213pd:
  case OP_vfmsub231pd:
  case OP_vfmsub132ps:
  case OP_vfmsub213ps:
  case OP_vfmsub231ps:
  case OP_vfnmadd132pd:
  case OP_vfnmadd213pd:
  case OP_vfnmadd231pd:
  case OP_vfnmadd132ps:
  case OP_vfnmadd213ps:
  case OP_vfnmadd231ps:
  case OP_vfnmsub132pd:
  case OP_vfnmsub213pd:
  case OP_vfnmsub231pd:
  case OP_vfnmsub132ps:
  case OP_vfnmsub213ps:
  case OP_vfnmsub231ps:
  case OP_vgetexppd:
  case OP_vgetexpps:
  case OP_vgetmantpd:
  case OP_vgetmantps:
  case OP_vmaxpd:
  case OP_vmaxps:
  case OP_vminpd:
  case OP_vminps:
  case OP_vmulpd:
  case OP_vmulps:
  case OP_vrangepd:
  case OP_vrangeps:
  case OP_vreducepd:
  case OP_vreduceps:
  case OP_vrndscalepd:
  case OP_vrndscaleps:
  case OP_vrcp28pd:
  case OP_vrcp28ps:
  case OP_vrsqrt28pd:
  case OP_vrsqrt28ps:
  case OP_vscalefpd:
  case OP_vscalefps:
  case OP_vsqrtpd:
  case OP_vsqrtps:
  case OP_vsubpd:
  case OP_vsubps:
  // E3
  case OP_vaddsd:
  case OP_vaddss:
  case OP_vcmpsd:
  case OP_vcmpss:
  case OP_vcvtps2qq:
  case OP_vcvtps2uqq:
  case OP_vcvtps2pd:
  case OP_vcvtsd2ss:
  case OP_vcvtsi2sd:
  case OP_vcvtsi2ss:
  case OP_vcvtss2sd:
  case OP_vcvttps2qq:
  case OP_vcvttps2uqq:
  case OP_vcvtusi2sd:
  case OP_vcvtusi2ss:
  case OP_vdivsd:
  case OP_vdivss:
  case OP_vfmadd132sd:
  case OP_vfmadd213sd:
  case OP_vfmadd231sd:
  case OP_vfmadd132ss:
  case OP_vfmadd213ss:
  case OP_vfmadd231ss:
  case OP_vfmsub132sd:
  case OP_vfmsub213sd:
  case OP_vfmsub231sd:
  case OP_vfmsub132ss:
  case OP_vfmsub213ss:
  case OP_vfmsub231ss:
  case OP_vfnmadd132sd:
  case OP_vfnmadd213sd:
  case OP_vfnmadd231sd:
  case OP_vfnmadd132ss:
  case OP_vfnmadd213ss:
  case OP_vfnmadd231ss:
  case OP_vfnmsub132sd:
  case OP_vfnmsub213sd:
  case OP_vfnmsub231sd:
  case OP_vfnmsub132ss:
  case OP_vfnmsub213ss:
  case OP_vfnmsub231ss:
  case OP_vfixupimmsd:
  case OP_vfixupimmss:
  case OP_vgetexpsd:
  case OP_vgetexpss:
  case OP_vgetmantsd:
  case OP_vgetmantss:
  case OP_vmaxsd:
  case OP_vmaxss:
  case OP_vminsd:
  case OP_vminss:
  case OP_vmulsd:
  case OP_vmulss:
  case OP_vrangesd:
  case OP_vrangess:
  case OP_vreducesd:
  case OP_vreducess:
  case OP_vrndscalesd:
  case OP_vrndscaless:
  case OP_vscalefsd:
  case OP_vscalefss:
  case OP_vrcp28sd:
  case OP_vrcp28ss:
  case OP_vrsqrt28sd:
  case OP_vrsqrt28ss:
  case OP_vsqrtsd:
  case OP_vsqrtss:
  case OP_vsubsd:
  case OP_vsubss:
  // E11
  case OP_vcvtps2ph:
    return INSTR_HAS_EVEX_FAULT_SUPPRESSION | INSTR_CAN_MODIFY_MXCSR;
  // E1
  case OP_vmovapd:
  case OP_vmovaps:
  case OP_vmovdqa32:
  case OP_vmovdqa64:
  // E4
  case OP_vandpd:
  case OP_vandps:
  case OP_vandnpd:
  case OP_vandnps:
  case OP_vblendmpd:
  case OP_vblendmps:
  case OP_vfpclasspd:
  case OP_vfpclassps:
  case OP_vorpd:
  case OP_vorps:
  case OP_vpabsd:
  case OP_vpabsq:
  case OP_vpaddd:
  case OP_vpaddq:
  case OP_vpandd:
  case OP_vpandq:
  case OP_vpandnd:
  case OP_vpandnq:
  case OP_vpblendmb:
  case OP_vpblendmd:
  case OP_vpblendmq:
  case OP_vpblendmw:
  case OP_vpcmpd:
  case OP_vpcmpeqd:
  case OP_vpcmpeqq:
  case OP_vpcmpgtd:
  case OP_vpcmpgtq:
  case OP_vpcmpq:
  case OP_vpcmpud:
  case OP_vpcmpuq:
  case OP_vplzcntd:
  case OP_vplzcntq:
  case OP_vpmadd52luq:
  case OP_vpmadd52huq:
  case OP_vpmaxsd:
  case OP_vpmaxsq:
  case OP_vpmaxud:
  case OP_vpmaxuq:
  case OP_vpminsd:
  case OP_vpminsq:
  case OP_vpminud:
  case OP_vpminuq:
  case OP_vpmulld:
  case OP_vpmullq:
  case OP_vpmuludq:
  case OP_vpmuldq:
  case OP_vpord:
  case OP_vporq:
  case OP_vprold:
  case OP_vprolq:
  case OP_vprolvd:
  case OP_vprolvq:
  case OP_vprord:
  case OP_vprorq:
  case OP_vprorvd:
  case OP_vprorvq:
  case OP_vpsravw:
  case OP_vpsravd:
  case OP_vpsravq:
  case OP_vpsubd:
  case OP_vpsubq:
  case OP_vpsubusb:
  case OP_vpsubusw:
  case OP_vpternlogd:
  case OP_vpternlogq:
  case OP_vptestmd:
  case OP_vptestmq:
  case OP_vptestnmd:
  case OP_vptestnmq:
  case OP_vpxord:
  case OP_vpxorq:
  case OP_vpsllvd:
  case OP_vpsllvq:
  case OP_vpsrlvd:
  case OP_vpsrlvq:
  case OP_vrcp14pd:
  case OP_vrcp14ps:
  case OP_vrsqrt14pd:
  case OP_vrsqrt14ps:
  case OP_vxorpd:
  case OP_vxorps:
  // E4.nb
  case OP_vcompresspd:
  case OP_vcompressps:
  case OP_vexpandpd:
  case OP_vexpandps:
  case OP_vmovdqu8:
  case OP_vmovdqu16:
  case OP_vmovdqu32:
  case OP_vmovdqu64:
  case OP_vmovupd:
  case OP_vmovups:
  case OP_vpabsb:
  case OP_vpabsw:
  case OP_vpaddb:
  case OP_vpaddw:
  case OP_vpaddsb:
  case OP_vpaddsw:
  case OP_vpaddusb:
  case OP_vpaddusw:
  case OP_vpavgb:
  case OP_vpavgw:
  case OP_vpcmpb:
  case OP_vpcmpeqb:
  case OP_vpcmpeqw:
  case OP_vpcmpgtb:
  case OP_vpcmpgtw:
  case OP_vpcmpw:
  case OP_vpcmpub:
  case OP_vpcmpuw:
  case OP_vpcompressd:
  case OP_vpcompressq:
  case OP_vpexpandd:
  case OP_vpexpandq:
  case OP_vpmaxsb:
  case OP_vpmaxsw:
  case OP_vpmaxub:
  case OP_vpmaxuw:
  case OP_vpminsb:
  case OP_vpminsw:
  case OP_vpminub:
  case OP_vpminuw:
  case OP_vpmulhrsw:
  case OP_vpmulhuw:
  case OP_vpmulhw:
  case OP_vpmullw:
  case OP_vpsllvw:
  case OP_vpsrlvw:
  case OP_vpsubb:
  case OP_vpsubw:
  case OP_vpsubsb:
  case OP_vpsubsw:
  case OP_vptestmb:
  case OP_vptestmw:
  case OP_vptestnmb:
  case OP_vptestnmw:
  // E5
  case OP_vpmovsxbw:
  case OP_vpmovsxbd:
  case OP_vpmovsxbq:
  case OP_vpmovsxwd:
  case OP_vpmovsxwq:
  case OP_vpmovsxdq:
  case OP_vpmovzxbw:
  case OP_vpmovzxbd:
  case OP_vpmovzxbq:
  case OP_vpmovzxwd:
  case OP_vpmovzxwq:
  case OP_vpmovzxdq:
  case OP_vcvtdq2pd:
  case OP_vcvtudq2pd:
  // E6
  case OP_vbroadcastf32x2:
  case OP_vbroadcastf32x4:
  case OP_vbroadcastf64x2:
  case OP_vbroadcastf32x8:
  case OP_vbroadcastf64x4:
  case OP_vbroadcasti32x2:
  case OP_vbroadcasti32x4:
  case OP_vbroadcasti64x2:
  case OP_vbroadcasti32x8:
  case OP_vbroadcasti64x4:
  case OP_vbroadcastsd:
  case OP_vbroadcastss:
  case OP_vfpclasssd:
  case OP_vfpclassss:
  case OP_vpbroadcastb:
  case OP_vpbroadcastd:
  case OP_vpbroadcastw:
  case OP_vpbroadcastq:
  case OP_vpmovqb:
  case OP_vpmovsqb:
  case OP_vpmovusqb:
  case OP_vpmovqw:
  case OP_vpmovsqw:
  case OP_vpmovusqw:
  case OP_vpmovqd:
  case OP_vpmovsqd:
  case OP_vpmovusqd:
  case OP_vpmovdb:
  case OP_vpmovsdb:
  case OP_vpmovusdb:
  case OP_vpmovdw:
  case OP_vpmovsdw:
  case OP_vpmovusdw:
  case OP_vpmovwb:
  case OP_vpmovswb:
  case OP_vpmovuswb:
  // E10
  case OP_vmovsd:
  case OP_vmovss:
  case OP_vrcp14sd:
  case OP_vrcp14ss:
  case OP_vrsqrt14sd:
  case OP_vrsqrt14ss:
  // E11
  case OP_vcvtph2ps:
  // E12
  case OP_vgatherdps:
  case OP_vgatherdpd:
  case OP_vgatherqps:
  case OP_vgatherqpd:
  case OP_vpgatherdd:
  case OP_vpgatherdq:
  case OP_vpgatherqd:
  case OP_vpgatherqq:
  case OP_vpscatterdd:
  case OP_vpscatterdq:
  case OP_vpscatterqd:
  case OP_vpscatterqq:
  case OP_vscatterdpd:
  case OP_vscatterdps:
  case OP_vscatterqpd:
  case OP_vscatterqps:
    return INSTR_HAS_EVEX_FAULT_SUPPRESSION;
  // E4/E4.nb shifts: fault suppression only in the immediate form.
  case OP_vpslld:
  case OP_vpsllq:
  case OP_vpsllw:
  case OP_vpsrad:
  case OP_vpsraq:
  case OP_vpsraw:
  case OP_vpsrld:
  case OP_vpsrlq:
  case OP_vpsrlw:
    return opnd_is_immed_int(instr_get_src(instr, instr_num_srcs(instr) - 1)) ?
      INSTR_HAS_EVEX_FAULT_SUPPRESSION : 0;
  default:
    return 0;
  }
}

inline bool
instr_may_write_avx512_register(instr_t *instr)
{
  for (int i = 0; i < instr_num_dsts(instr); ++i) {
    opnd_t dst = instr_get_dst(instr, i);
    if (opnd_is_reg(dst)) {
      if (reg_is_avx512(opnd_get_reg(dst)))
        return true;
    }
  }
  return false;
}

static inline int
make_unaligned(int opcode) {
  switch (opcode) {
    case OP_movapd:
      return OP_movupd;
    case OP_movaps:
      return OP_movups;
    case OP_vmovapd:
      return OP_vmovupd;
    case OP_vmovaps:
      return OP_vmovups;

    case OP_movdqa:
      return OP_movdqu;
    case OP_vmovdqa:
      return OP_vmovdqu;

    case OP_vmovdqa32:
      return OP_vmovdqu32;
    case OP_vmovdqa64:
      return OP_vmovdqu64;

    default:
      return opcode;
  }
}

extern uint64_t tracee_xcr0;

inline bool tracee_has_avx512() {
  return !!(tracee_xcr0 & 0xE0);
}

#endif // RR_GENERATOR_UTILS_H_
