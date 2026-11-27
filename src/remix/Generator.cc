/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "Generator.h"

#include "generator_utils.h"
#include "remix_util.h"
#include "xsave_utils.h"
#include "../core.h"

REMIX_TARGET_BEGIN

using namespace std;

const int Generator::scratch_user_regs_struct_offsets[4] = {
  offsetof(struct user_regs_struct, r8), offsetof(struct user_regs_struct, r9),
  offsetof(struct user_regs_struct, r10), offsetof(struct user_regs_struct, r11)
};

instr_t Generator::instruction_buf[MAX_BYTES_PER_FRAGMENT + 1];
instr_t Generator::tmp_instruction;
void* Generator::analysis_buf;
app_pc Generator::allow_rdrand_start;
app_pc Generator::allow_rdrand_end;
const uintptr_t Generator::rdrand_return_value = 0xabadcafedeadbeef;
bool Generator::seen_hle;

void Generator::emit_save_flags(reg_id_t scratch) {
  emit_.mov(RAX(), Reg64::from_dr(scratch));
  emit_.lahf();
  emit_.setcc(DR_PRED_O, AL());
}

void Generator::emit_restore_flags(reg_id_t scratch) {
  emit_.add(0x7f, AL());
  emit_.sahf();
  emit_.mov(Reg64::from_dr(scratch), RAX());
}

void Generator::emit_store_constant_bytes(int size, uint8_t* bytes, Reg64 reg,
                                          int offset) {
  while (size >= 4) {
    emit_.mov(*reinterpret_cast<int32_t*>(bytes), RegMem32(reg), offset);
    size -= 4;
    bytes += 4;
    offset += 4;
  }
  if (size >= 2) {
    emit_.mov(*reinterpret_cast<int16_t*>(bytes), RegMem16(reg), offset);
    size -= 2;
    bytes += 2;
    offset += 2;
  }
  if (size >= 1) {
    emit_.mov(int8_t(*bytes), RegMem8(reg), offset);
  }
}

void Generator::emit_copy_bytes(Reg64 src, int src_offset, int size, Reg64 dst,
                                int dst_offset, Reg64 tmp) {
  while (size >= 8) {
    emit_.mov(RegMem64(src), src_offset, tmp);
    emit_.mov(tmp, RegMem64(dst), dst_offset);
    src_offset += 8;
    dst_offset += 8;
    size -= 8;
  }
  if (size >= 4) {
    emit_.mov(RegMem32(src), src_offset, Assembler::to32(tmp));
    emit_.mov(Assembler::to32(tmp), RegMem32(dst), dst_offset);
    src_offset += 4;
    dst_offset += 4;
    size -= 4;
  }
  if (size >= 2) {
    emit_.mov(RegMem16(src), src_offset, Assembler::to16(tmp));
    emit_.mov(Assembler::to16(tmp), RegMem16(dst), dst_offset);
    src_offset += 2;
    dst_offset += 2;
    size -= 2;
  }
  if (size >= 1) {
    emit_.mov(RegMem8(src), src_offset, Assembler::to8(tmp));
    emit_.mov(Assembler::to8(tmp), RegMem8(dst), dst_offset);
  }
}

void Generator::init() {
  for (auto& instr : instruction_buf) {
    instr_init(GLOBAL_DCONTEXT, &instr);
  }
  instr_init(GLOBAL_DCONTEXT, &tmp_instruction);
}

extern "C" AsmStub breakpoint_stop_stub;
extern "C" AsmStub sync_signal_stop_stub;
extern "C" AsmStub unconditional_stop_stub;
extern "C" AsmStub conditional_stop_stub;
extern "C" AsmStub conditional_breakpoint_fault_stop_stub;
extern "C" AsmStub conditional_syscall_stop_stub;
extern "C" AsmStub monitor_syscall_before_stub;
extern "C" AsmStub monitor_syscall_stub;

extern "C" AsmStub flush_pending_fip_stub;
extern "C" AsmStub xgetbv_stub;
extern "C" AsmStub handle_xsave_stub;
extern "C" AsmStub pushf_stub;
extern "C" AsmStub pushf16_stub;

extern "C" AsmStub indirect_jump_stub_0_0;
extern "C" AsmStub indirect_jump_stub_0_1;
extern "C" AsmStub indirect_jump_stub_0_2;
extern "C" AsmStub indirect_jump_stub_0_3;
extern "C" AsmStub indirect_jump_stub_0_4;
extern "C" AsmStub indirect_jump_stub_0_5;
extern "C" AsmStub indirect_jump_stub_0_6;
extern "C" AsmStub indirect_jump_stub_0_7;
extern "C" AsmStub indirect_jump_stub_1_0;
extern "C" AsmStub indirect_jump_stub_1_1;
extern "C" AsmStub indirect_jump_stub_1_2;
extern "C" AsmStub indirect_jump_stub_1_3;
extern "C" AsmStub indirect_jump_stub_1_4;
extern "C" AsmStub indirect_jump_stub_1_5;
extern "C" AsmStub indirect_jump_stub_1_6;
extern "C" AsmStub indirect_jump_stub_1_7;
extern "C" AsmStub singlestep_indirect_jump_stub;
extern "C" AsmStub indirect_call_stub_0_0;
extern "C" AsmStub indirect_call_stub_0_1;
extern "C" AsmStub indirect_call_stub_0_2;
extern "C" AsmStub indirect_call_stub_0_3;
extern "C" AsmStub indirect_call_stub_0_4;
extern "C" AsmStub indirect_call_stub_0_5;
extern "C" AsmStub indirect_call_stub_0_6;
extern "C" AsmStub indirect_call_stub_0_7;
extern "C" AsmStub indirect_call_stub_1_0;
extern "C" AsmStub indirect_call_stub_1_1;
extern "C" AsmStub indirect_call_stub_1_2;
extern "C" AsmStub indirect_call_stub_1_3;
extern "C" AsmStub indirect_call_stub_1_4;
extern "C" AsmStub indirect_call_stub_1_5;
extern "C" AsmStub indirect_call_stub_1_6;
extern "C" AsmStub indirect_call_stub_1_7;

extern "C" AsmStub new_conditional_branch_taken_stub;
extern "C" AsmStub new_conditional_branch_not_taken_stub;
extern "C" AsmStub untranslated_branch_stub;
extern "C" AsmStub call_stub;
extern "C" AsmStub ret_stub;

extern "C" AsmStub directed_return_stub;

extern "C" AsmStub correct_single_rcp_rsqrt_stub;
extern "C" AsmStub correct_packed_rcp_rsqrt_stub;
extern "C" AsmStub correct_single_vex_rcp_rsqrt_stub;
extern "C" AsmStub correct_packed_vex_rcp_rsqrt_stub;
extern "C" AsmStub correct_packed_ymm_rcp_rsqrt_stub;

const RcpRsqrtEmulationTable* zen_rcp();
const RcpRsqrtEmulationTable* zen_rsqrt();

static const int INDIRECT_JUMP_STUB_COUNT = 8;
static uint8_t* indirect_jump_stubs[TRANSLATION_MODES][INDIRECT_JUMP_STUB_COUNT] =
    { {
          indirect_jump_stub_0_0, indirect_jump_stub_0_1,
          indirect_jump_stub_0_2, indirect_jump_stub_0_3,
          indirect_jump_stub_0_4, indirect_jump_stub_0_5,
          indirect_jump_stub_0_6, indirect_jump_stub_0_7,
      },
      {
          indirect_jump_stub_1_0, indirect_jump_stub_1_1,
          indirect_jump_stub_1_2, indirect_jump_stub_1_3,
          indirect_jump_stub_1_4, indirect_jump_stub_1_5,
          indirect_jump_stub_1_6, indirect_jump_stub_1_7,
      } };
static int next_indirect_jump_stub;

static uint8_t* choose_indirect_jump_stub() {
  if (singlestep_mode) {
    // Use a stub that just returns from run_fragment with the correct next PC
    // set. We don't want to execute any more code in that case.
    return singlestep_indirect_jump_stub;
  }
  // Cycle through indirect jump stubs. We use multiple stubs in the hope
  // (not yet measured) that this improves indirect branch prediction, since
  // indirect jumps are coming from eight different branch instructions instead
  // of just one.
  uint8_t* result = indirect_jump_stubs[Translation::translation_mode()]
                                       [next_indirect_jump_stub];
  next_indirect_jump_stub =
      (next_indirect_jump_stub + 1) & (INDIRECT_JUMP_STUB_COUNT - 1);
  return result;
}

static uint8_t* indirect_call_stubs[TRANSLATION_MODES][INDIRECT_JUMP_STUB_COUNT] =
    { {
          indirect_call_stub_0_0, indirect_call_stub_0_1,
          indirect_call_stub_0_2, indirect_call_stub_0_3,
          indirect_call_stub_0_4, indirect_call_stub_0_5,
          indirect_call_stub_0_6, indirect_call_stub_0_7,
      },
      {
          indirect_call_stub_1_0, indirect_call_stub_1_1,
          indirect_call_stub_1_2, indirect_call_stub_1_3,
          indirect_call_stub_1_4, indirect_call_stub_1_5,
          indirect_call_stub_1_6, indirect_call_stub_1_7,
      } };
static int next_indirect_call_stub;

static uint8_t* choose_indirect_call_stub() {
  remix_assert(!singlestep_mode);
  // Cycle through indirect call stubs. We use multiple stubs in the hope
  // (not yet measured) that this improves indirect branch prediction, since
  // indirect calls are coming from eight different branch instructions instead
  // of just one.
  uint8_t* result = indirect_call_stubs[Translation::translation_mode()]
                                       [next_indirect_call_stub];
  next_indirect_call_stub =
      (next_indirect_call_stub + 1) & (INDIRECT_JUMP_STUB_COUNT - 1);
  return result;
}

void Generator::emit_unconditional_stop() {
  emit_.jmp_long(unconditional_stop_stub);
}

void Generator::emit_conditional_stop() {
  // Call the conditional_stop_stub. We can't use the stack so we put the return
  // address in %r8.
  Assembler::ForwardIPRel<int32_t> label;
  emit_.lea(label, R8());
  emit_.jmp_long(conditional_stop_stub);
  emit_.label(label);
}

void Generator::emit_conditional_breakpoint_fault_stop() {
  // Call the conditional_stop_stub. We can't use the stack so we put the return
  // address in %r8.
  Assembler::ForwardIPRel<int32_t> label;
  emit_.lea(label, R8());
  emit_.jmp_long(conditional_breakpoint_fault_stop_stub);
  emit_.label(label);
}

void Generator::emit_conditional_syscall_stop() {
  // Match the logic in ReplaySession::cont_syscall_boundary
  for (auto s : remix_rr_page_syscalls) {
    if ((app_pc)s.addr == start_pc && s.traced == UNTRACED &&
        s.enabled == REPLAY_ONLY) {
      // Never stop at syscalls here.
      return;
    }
  }

  // Call the conditional_syscall_stop_stub with our PC in R9 in case we need
  // to stop.
  emit_.mov(start_pc, R9());
  // Just in case we feel like using it later...
  scratch_regs_hold_rip |= 1 << 1;
  Assembler::ForwardIPRel<int32_t> label;
  emit_.lea(label, R8());
  emit_.jmp_long(conditional_syscall_stop_stub);
  emit_.label(label);
}

void Generator::emit_monitor_before_syscall(uint8_t is_32bit) {
  // Save rax so we can read it after the syscall has returned.
  emit_.mov(RAX(), IPRel64(&remix_registers.orig_rax));

  emit_spill_scratch_registers();
  set_scratch_regs_match_application(0);
  Assembler::ForwardIPRel<int32_t> label;
  emit_.lea(label, R8());
  emit_.mov(int32_t(is_32bit), R9D());
  emit_.jmp_long(monitor_syscall_before_stub);
  emit_.label(label);
}

void Generator::emit_monitor_after_syscall(uint8_t is_32bit) {
  emit_spill_scratch_registers();
  set_scratch_regs_match_application(0);
  Assembler::ForwardIPRel<int32_t> label;
  emit_.lea(label, R8());
  emit_.mov(int32_t(is_32bit), R9D());
  // This can invalidate the current fragment. That's OK, there's no way the
  // 5-byte jump inserted at the start of the fragment by invalidation can
  // overwrite code after this jump.
  emit_.jmp_long(monitor_syscall_stub);
  emit_.label(label);
}

void Generator::emit_syscall() {
  emit_monitor_before_syscall(0);
  emit_load_scratch_registers();
  emit_.syscall();
  // r11 has been set so make sure we spill it eventually
  uint8_t r11_mask = dr_reg_to_scratch_mask(DR_REG_R11);
  scratch_regs_hold_rip &= ~r11_mask;
  regs_match_application |= r11_mask << 8;
  scratch_regs_dirty |= r11_mask;
  emit_monitor_after_syscall(0);
}

void Generator::emit_int_syscall() {
  emit_monitor_before_syscall(1);
  emit_load_scratch_registers();
  emit_.instruction(current_instruction());
  emit_monitor_after_syscall(1);
}

void Generator::emit_handle_unrecorded_cpuid_fault() {
  Assembler::ForwardIPRel<int32_t> label;
  emit_.lea(label, R8());
  emit_.mov(HANDLE_UNRECORDED_CPUID_FAULT_ADDRESS, R9());
  emit_.jmp(R9());
  emit_.label(label);
}

void Generator::emit_flush_pending_fip() {
  emit_spill_scratch_registers();
  set_scratch_regs_match_application(0);
  scratch_regs_hold_rip = 0;
  Assembler::ForwardIPRel<int32_t> label;
  emit_.lea(label, R11());
  emit_.jmp_long(flush_pending_fip_stub);
  emit_.label(label);
}

void Generator::emit_corrected_rcp_rsqrt(GeneratedFragment* generated,
                                         app_pc end_pc,
                                         const RcpRsqrtEmulationTable* table,
                                         AsmStub stub) {
  instr_t& instruction = current_instruction();
  if (!correct_rcp_rsqrt) {
    emit_.instruction(instruction);
    return;
  }

  emit_spill_scratch_registers();
  set_scratch_regs_match_application(0);
  scratch_regs_hold_rip = 0;
  emit_.lea(Assembler::IPRelConst(table), R8());

  opnd_t dst_operand = instr_get_dst(&instruction, 0);
  remix_assert(OPND_IS_REG(dst_operand));
  reg_id_t dst_reg = OPND_GET_REG(dst_operand);
  reg_id_t tmp_reg;
  bool is_vex;
  bool is_vex_single;
  bool is_single;
  if (opnd_get_size(dst_operand) == OPSZ_32) {
    tmp_reg = DR_REG_YMM0;
    stub = correct_packed_ymm_rcp_rsqrt_stub;
    is_vex = true;
    is_vex_single = false;
    is_single = false;
  } else {
    is_vex = stub == correct_single_vex_rcp_rsqrt_stub || stub == correct_packed_vex_rcp_rsqrt_stub;
    is_vex_single = stub == correct_single_vex_rcp_rsqrt_stub;
    is_single = stub == correct_single_rcp_rsqrt_stub || stub == correct_single_vex_rcp_rsqrt_stub;
    tmp_reg = DR_REG_XMM0;
  }

  // Save temp register value
  if (is_vex) {
    // Save full YMM register since we might clear the upper bits
    emit_.mov(Reg256::YMM0(), Assembler::IPRel256(saved_mm_regs));
  } else {
    // Avoid using non-VEX instructions; YMM might not even be present
    emit_.mov(Reg128::XMM0(), Assembler::IPRel128(saved_mm_regs));
  }

  // Get the input value into tmp_reg
  init_tmp_instruction();
  opnd_t src_operand = instr_get_src(&instruction, is_vex_single ? 1 : 0);
  int op;
  if (is_single) {
    op = OP_movss;
  } else if (is_vex) {
    op = OP_vmovdqu;
  } else {
    op = OP_movdqu;
  }
  instr_set_opcode(&tmp_instruction, op);
  instr_set_num_opnds(GLOBAL_DCONTEXT, &tmp_instruction, 1, 1);
  instr_set_src(&tmp_instruction, 0, src_operand);
  opnd_t tmp_reg_operand = opnd_create_reg(tmp_reg);
  instr_set_dst(&tmp_instruction, 0, tmp_reg_operand);
  emit_.instruction(tmp_instruction);

  // Save input value at saved_mm_regs+32
  if (tmp_reg == DR_REG_YMM0) {
    emit_.mov(Reg256::YMM0(), Assembler::IPRel256(saved_mm_regs + 32));
  } else {
    emit_.mov(Reg128::XMM0(), Assembler::IPRel128(saved_mm_regs + 32));
  }

  // Apply our instruction operation
  init_tmp_instruction();
  instr_set_opcode(&tmp_instruction, instr_get_opcode(&instruction));
  instr_set_num_opnds(GLOBAL_DCONTEXT, &tmp_instruction, 1, is_vex_single ? 2 : 1);
  instr_set_src(&tmp_instruction, 0, tmp_reg_operand);
  if (is_vex_single) {
    instr_set_src(&tmp_instruction, 1, tmp_reg_operand);
  }
  instr_set_dst(&tmp_instruction, 0, tmp_reg_operand);
  emit_.instruction(tmp_instruction);

  // Fix up the result(s)
  Assembler::ForwardIPRel<int32_t> label;
  emit_.lea(label, R10());
  emit_.jmp_long(stub);
  emit_.label(label);

  if (dst_reg != tmp_reg) {
    // Move result to correct register and restore value of tmp_reg
    if (is_vex) {
      // Copy full YMM0 since vex-encoded variants set all bits of the
      // output register.
      emit_.mov(Reg256::YMM0(), Reg256::from_dr(to_256(dst_reg)));
      emit_.mov(Assembler::IPRel256(saved_mm_regs), Reg256::YMM0());
    } else {
      if (stub == correct_single_rcp_rsqrt_stub) {
        // Only the bottom 32 bits of the destination XMM register are changed
        emit_.movss(Reg128::XMM0(), Reg128::from_dr(dst_reg));
      } else {
        emit_.mov(Reg128::XMM0(), Reg128::from_dr(dst_reg));
      }
      emit_.mov(Assembler::IPRel128(saved_mm_regs), Reg128::XMM0());
    }
  }
  if (is_vex_single) {
    opnd_t merge_operand = instr_get_src(&instruction, 0);
    remix_assert(OPND_IS_REG(merge_operand));
    // Need to merge in bits 32-127 of input operand 0. Seriously Intel?
    emit_.movss_v(Reg128::from_dr(OPND_GET_REG(merge_operand)), Reg128::from_dr(dst_reg), Reg128::from_dr(dst_reg));
  }

  // Emulation ends the current fragment.
  generated->set_next_pc(end_pc);
}

static CPUIDData extended_features() {
  static CPUIDData cpuid_result = cpuid(7, 0);
  return cpuid_result;
}

static CPUIDData extended_processor_info() {
  static CPUIDData cpuid_result = cpuid(0x80000001, 0);
  return cpuid_result;
}

static bool cpu_has_lzcnt() {
  return (extended_processor_info().ecx & 1 << 5) != 0;
}

static bool cpu_has_sha() {
  return (extended_features().ebx & 1 << 29) != 0;
}

void Generator::emit_corrected_lzcnt() {
  instr_t& instruction = current_instruction();
  if (!correct_lzcnt) {
    emit_.instruction(instruction);
    return;
  }

  static bool host_has_lzcnt = cpu_has_lzcnt();
  // Backporting from a machine with lzcnt to one without is not supported.
  remix_assert(host_has_lzcnt);

  init_tmp_instruction();
  instr_set_opcode(&tmp_instruction, OP_bsr);
  instr_set_num_opnds(GLOBAL_DCONTEXT, &tmp_instruction, 1, 1);
  instr_set_src(&tmp_instruction, 0, instr_get_src(&instruction, 0));
  instr_set_dst(&tmp_instruction, 0, instr_get_dst(&instruction, 0));
  instr_set_predicate(&tmp_instruction, DR_PRED_COMPLEX);
  emit_.instruction(tmp_instruction);
}

bool has_tzcnt() {
  auto cpuid_result = cpuid(0x7, 0);
  return (cpuid_result.ebx & 1 << 3) != 0;
}

void Generator::emit_corrected_tzcnt() {
  instr_t& instruction = current_instruction();
  if (!correct_tzcnt) {
    emit_.instruction(instruction);
    return;
  }

  static bool host_has_tzcnt = has_tzcnt();
  // Backporting from a machine with tzcnt to one without is not supported.
  remix_assert(host_has_tzcnt);

  init_tmp_instruction();
  instr_set_opcode(&tmp_instruction, OP_bsf);
  instr_set_num_opnds(GLOBAL_DCONTEXT, &tmp_instruction, 1, 1);
  instr_set_src(&tmp_instruction, 0, instr_get_src(&instruction, 0));
  instr_set_dst(&tmp_instruction, 0, instr_get_dst(&instruction, 0));
  instr_set_predicate(&tmp_instruction, DR_PRED_COMPLEX);
  emit_.instruction(tmp_instruction);
}

void Generator::emit_pushf(opnd_size_t operand_size) {
  take_scratch_registers(Generator::dr_regs_to_scratch_mask(
        DR_REG_R9, DR_REG_R10, DR_REG_R11));
  Assembler::ForwardIPRel<int32_t> label;
  emit_.lea(label, R10());
  emit_.jmp_long(operand_size == OPSZ_2 ? pushf16_stub : pushf_stub);
  emit_.label(label);
  release_scratch_registers(Generator::dr_regs_to_scratch_mask(
        DR_REG_R9, DR_REG_R10, DR_REG_R11));
}

void Generator::emit_popf() {
  take_scratch_register(DR_REG_R11);
  emit_.mov(RegMem32(RSP()), R11D());
  emit_.mov(R11D(), IPRel32(&extra_rflags));
  // It's OK to alter flags here since we pop them in the next instruction
  emit_._and((int32_t)~(RFLAG_AC | RFLAG_TF), RegMem32(RSP()));
  emit_.popf();
  // Restore application memory that we just modified
  emit_.mov(IPRel32(&extra_rflags), R11D());
  emit_.mov(R11D(), RegMem32(RSP()), -8);
  release_scratch_register(DR_REG_R11);
}

void Generator::emit_popf16() {
  take_scratch_register(DR_REG_R11);
  // Use a 16-bit load here because we're only popping 16 bits of flags
  emit_.mov(RegMem16(RSP()), R11W());
  emit_.mov(R11W(), IPRel16(&extra_rflags));
  // It's OK to alter flags here since we pop them in the next instruction.
  // We can ignore RFLAG_AC here since popping 16 bits into EFLAGS can't
  // change it.
  emit_._and((uint16_t)~RFLAG_TF, RegMem16(RSP()));
  emit_.popf16();
  // Restore application memory that we just modified
  emit_.mov(IPRel16(&extra_rflags), R11W());
  emit_.mov(R11W(), RegMem16(RSP()), -2);
  release_scratch_register(DR_REG_R11);
}

void Generator::emit_xgetbv() {
  emit_spill_scratch_registers();
  set_scratch_regs_match_application(0);
  scratch_regs_hold_rip = 0;
  Assembler::ForwardIPRel<int32_t> label;
  emit_.lea(label, R10());
  emit_.jmp_long(xgetbv_stub);
  emit_.label(label);
}

void report_instruction_error(app_pc pc, int opcode, RemixErrorCode code) {
  remix_error_details.code = code;
  remix_error_details.pc = (uint64_t)pc;
  int out_chars;
  disassemble_set_syntax(DR_DISASM_INTEL);
  disassemble_to_buffer(GLOBAL_DCONTEXT, pc, pc, false, false, remix_error_details.disassembly,
                        sizeof(remix_error_details.disassembly), &out_chars);
  // Chop off trailing newline
  remix_error_details.disassembly[out_chars - 1] = 0;
  remix_abort("Unsupported instruction at %p (opcode %s)", pc,
              decode_opcode_name(opcode));
}

static void instruction_unsupported_for_replay(app_pc pc, int opcode) {
  report_instruction_error(pc, opcode, REMIX_ERROR_INSTRUCTION_UNSUPPORTED_FOR_REPLAY);
}

static void instruction_unsupported_on_this_cpu(app_pc pc, int opcode, const char* family) {
  strcpy(remix_error_details.instruction_family, family);
  report_instruction_error(pc, opcode, REMIX_ERROR_INSTRUCTION_UNSUPPORTED_ON_THIS_CPU);
}

void Generator::emit_rdrand(app_pc pc) {
  if (pc < Generator::allow_rdrand_start || pc >= Generator::allow_rdrand_end) {
    instruction_unsupported_for_replay(pc, instr_get_opcode(&current_instruction()));
  }
  remix_log(REMIX_LOG_GEN, "Allowing rdrand at %p", pc);
  instr_t& instruction = current_instruction();
  opnd_t dst = instr_get_dst(&instruction, 0);
  remix_assert(OPND_IS_REG(dst));
  reg_id_t dst_reg = OPND_GET_REG(dst);

  take_scratch_registers(Generator::dr_regs_to_scratch_mask(
        DR_REG_R9, DR_REG_R10));
  emit_.mov(RCX(), R10());
  emit_.mov(IPRel64(&remix_rcb), RCX());
  emit_.mov(IPRel64((void*)&Generator::rdrand_return_value), R9());
  emit_.imm(0x49, 0xd3, 0xc1); // ROL %r9, %cl
  emit_.mov(RAX(), RCX());
  emit_.mov(0x03, AH());
  emit_.sahf();
  emit_.mov(RCX(), RAX());
  emit_.mov(R10(), RCX());
  switch (opnd_get_size(dst)) {
  case OPSZ_8:
    emit_.mov(R9(), Reg64::from_dr(dst_reg));
    break;
  case OPSZ_4:
    emit_.mov(R9D(), Reg32::from_dr(dst_reg));
    break;
  default:
    remix_abort("Unsupported rdrand size");
    break;
  }
  release_scratch_registers(Generator::dr_regs_to_scratch_mask(
        DR_REG_R9, DR_REG_R10));
}

void Generator::emit_xsave_wrapper() {
  emit_spill_scratch_registers();
  set_scratch_regs_match_application(0);
  scratch_regs_hold_rip = 0;

  // Before we destroy any scratch register values, save the memory operand
  // address to r8.
  instr_t& instruction = current_instruction();
  auto opcode = instr_get_opcode(&instruction);
  opnd_t mem_opnd;
  switch (opcode) {
  case OP_xsavec32:
  case OP_xsavec64:
  case OP_xsave32:
  case OP_xsave64:
    mem_opnd = instr_get_dst(&instruction, 0);
    break;

  case OP_xrstor32:
  case OP_xrstor64:
    mem_opnd = instr_get_src(&instruction, 0);
    break;

  default:
    remix_abort("Unexpected opcode %d", opcode);
  }
  init_tmp_instruction();
  instr_set_opcode(&tmp_instruction, OP_lea);
  instr_set_num_opnds(GLOBAL_DCONTEXT, &tmp_instruction, 1, 1);
  opnd_set_size(&mem_opnd, OPSZ_lea);
  instr_set_src(&tmp_instruction, 0, mem_opnd);
  instr_set_dst(&tmp_instruction, 0, opnd_create_reg(DR_REG_R8));
  emit_.instruction(tmp_instruction);

  emit_.mov(opcode, R9());

  Assembler::ForwardIPRel<int32_t> label;
  emit_.lea(label, R11());
  emit_.jmp_long(handle_xsave_stub);
  emit_.label(label);
  return;
}

void Generator::emit_load_scratch_register_to_other_reg(uint8_t mask,
                                                        reg_id_t dest) {
  for (int i = SCRATCH_COUNT - 1; i >= 0; --i) {
    if (mask & (1 << i)) {
      emit_.mov(IPRel64(reinterpret_cast<uint8_t*>(&remix_registers) +
                        scratch_user_regs_struct_offsets[i]),
                Reg64::from_dr(dest));
    }
  }
}

void Generator::emit_load_scratch_registers(uint8_t mask) {
  remix_assert(!(scratch_regs_reserved_ & mask));
  uint8_t regs_to_load = mask & ~scratch_regs_match_application();
  // Emit in reverse order so that memory addresses increase
  for (int i = SCRATCH_COUNT - 1; i >= 0; --i) {
    if (regs_to_load & (1 << i)) {
      emit_.mov(IPRel64(reinterpret_cast<uint8_t*>(&remix_registers) +
                        scratch_user_regs_struct_offsets[i]),
                scratch_reg(i));
    }
  }
  regs_match_application |= regs_to_load << 8;
  scratch_regs_hold_rip &= ~regs_to_load;
}

void Generator::emit_spill_scratch_registers(uint8_t mask) {
  uint8_t regs_to_spill = mask & scratch_regs_dirty;
  // Emit in reverse order so that memory addresses increase
  for (int i = SCRATCH_COUNT - 1; i >= 0; --i) {
    if (regs_to_spill & (1 << i)) {
      emit_.mov(scratch_reg(i),
                IPRel64(reinterpret_cast<uint8_t*>(&remix_registers) +
                        scratch_user_regs_struct_offsets[i]));
    }
  }
  scratch_regs_dirty &= ~regs_to_spill;
}

void Generator::take_scratch_registers(uint8_t mask) {
  remix_assert(!(scratch_regs_reserved_ & mask));
  emit_spill_scratch_registers(mask);
  regs_match_application &= ~(mask << 8);
  scratch_regs_hold_rip &= ~mask;
  scratch_regs_reserved_ |= mask;
}

void Generator::release_scratch_registers(uint8_t mask) {
  remix_assert((scratch_regs_reserved_ & mask) == mask);
  remix_assert(!(scratch_regs_dirty & mask));
  scratch_regs_reserved_ &= ~mask;
}

void Generator::emit_repeating_string_instruction() {
  instr_t& instruction = current_instruction();

  if (Translation::translation_mode()) {
    emit_.instruction(instruction);
    return;
  }

  app_pc pc = instr_get_raw_bits(&instruction);
  if (singlestep_mode == STOP_SINGLESTEP) {
    // Use the STOP_AT_TARGET path, with some tweaks. Some of the work
    // becomes redundant, but who cares, singlestep generated code perf
    // doesn't
    // matter.
    // Note that STOP_SINGLESTEP_FASTFORWARD treats repeating string
    // instructions as a single step so doesn't get special treatment here.
  } else {
    if (stop_mode != STOP_AT_TARGET || pc != stop_pc) {
      emit_.instruction(instruction);
      return;
    }
  }

  // We're singlestepping or at stop_pc, so this is the first instruction
  // and our scratch registers are free to use without further work.
  remix_assert(!scratch_regs_match_application());

  // The basic problem here is that the target state might be reached by some
  // iteration of the string instruction that's not the last. So we check if
  // CX is greater than than target_CX; if it is, then we might reach
  // the target state after performing CX - target_CX iterations, so we
  // subtract target_CX from CX, do the repeated instruction, fix CX by
  // adding target_CX back to it, and then go and retry the stop-check at the
  // fragment start. If CX is <= targetCX coming in then we can
  // just run the instruction normally (we know we're not already in the
  // target state).

  // We support seven repeating string instruction OP_s, and each one has four
  // possible sizes and two possible CX sizes, so creating static stubs is
  // too hard. Plus there are two different ways to exit each stub. We'll just
  // emit everything inline.
  opnd_t cx = instr_get_dst(&instruction, instr_num_dsts(&instruction) - 1);
  remix_assert(OPND_IS_REG(cx));
  reg_id_t cx_reg = OPND_GET_REG(cx);
  remix_assert(cx_reg == DR_REG_RCX || cx_reg == DR_REG_ECX);
  opnd_size_t count_size = opnd_get_size(cx);

  Assembler::ForwardIPRel<int8_t> cannot_hit_target;
  Assembler::ForwardIPRel<int8_t> end;

  emit_save_flags();
  if (singlestep_mode == STOP_SINGLESTEP) {
    emit_.lea(RegMem64(RCX()), -1, R8());
  } else {
    emit_.mov(IPRel64(&remix_target_registers.rcx), R8());
  }
  // Check whether performing some iterations of the loop may reduce RCX/ECX
  // to the target value. Note that if the target is zero we can't hit the
  // target value since the next state will be CX==0 at the following
  // instruction.
  if (count_size == OPSZ_8) {
    emit_.cmp(R8(), RCX());
  } else {
    emit_.cmp(R8D(), ECX());
  }
  emit_.jcc(DR_PRED_BE, cannot_hit_target);
  emit_.mov(RCX(), R10());
  if (count_size == OPSZ_8) {
    emit_.sub(R8(), RCX());
  } else {
    emit_.sub(R8D(), ECX());
  }

  // Stash saved flags to R9 before we restore RAX
  emit_.mov(RAX(), R9());
  emit_restore_flags();
  // We need RAX and FLAGS here to be their application values so that the
  // instruction does the right things
  emit_.instruction(instruction);
  // Fix CX without affecting flags
  if (count_size == OPSZ_8) {
    emit_.lea(RegMem64(RCX()), R8(), RCX());
  } else {
    emit_.lea(RegMem32(RCX()), R8D(), ECX());
  }
  // If this was the last iteration then we need to advance to the next pc
  if (count_size == OPSZ_8) {
    emit_.jcxz(RCX(), end);
  } else {
    emit_.jcxz(ECX(), end);
  }
  // For conditional repeats, if the condition is false now, we don't
  // want to iterate any further (and we didn't hit the target state).
  switch (instr_get_opcode(&instruction)) {
    case OP_rep_scas:
    case OP_rep_cmps:
      emit_.jcc(DR_PRED_NZ, end);
      break;
    case OP_repne_scas:
    case OP_repne_cmps:
      emit_.jcc(DR_PRED_Z, end);
      break;
    default:
      break;
  }

  // The CPU only changes the flags on the last iteration of the string
  // instruction. So the flags have been updated, but this isn't supposed to be
  // the last iteration of the string instruction, so we need to undo that.
  emit_.mov(R9(), RAX());
  emit_restore_flags();

  visit_interrupted_instruction_codegen();

  if (singlestep_mode == STOP_SINGLESTEP) {
    // We must return to the control loop now, so build a stub to do that,
    // leaving us in the right state, ready to execute this instruction again.
    emit_directed_return(pc);
  } else {
    // We need to iterate further, and we might have reached the
    // target state.
    emit_.jmp(code_buffer.next());
  }

  // This is unreachable if stop_mode == STOP_SINGLESTEP ... we can always
  // hit the target.
  emit_.label(cannot_hit_target);
  emit_restore_flags();
  emit_.instruction(instruction);

  // This is reachable if stop_mode == STOP_SINGLESTEP ... when we execute the
  // last iteration of a string instruction.
  emit_.label(end);
}

void Generator::emit_directed_return(app_pc next_pc) {
  // Emit code to return from run_fragment with remix_registers.rip set to
  // |next_pc|.
  emit_.mov(next_pc, R8());
  emit_.jmp_long(directed_return_stub);
}

static GeneratedCode* emit_untranslated_branch_stub(app_pc next_pc,
                                                    GeneratedCode* jmp_offset) {
  GeneratedCode* result = stub_buffer.next();
  Assembler stub_emit(result);
  stub_emit.mov(next_pc, R8());
  stub_emit.lea(Assembler::IPRel64(jmp_offset), R9());
  stub_emit.jmp_long(untranslated_branch_stub);
  stub_buffer.mark_allocated(stub_emit.next());
  return result;
}

void Generator::emit_patchable_directed_return(app_pc next_pc) {
  // Emit code to return from run_fragment with remix_registers.rip set to
  // |next_pc|, which will then be patched to jump directly to the |next_pc|
  // translation.
  GeneratedCode* stub = stub_buffer.next();
  emit_.jmp_long(stub);
  emit_untranslated_branch_stub(next_pc, emit_.next() - 4);
}

void Generator::end_fragment_with_jump(GeneratedFragment* generated) {
  visit_control_flow_change_before_codegen();
  opnd_t operand = instr_get_src(&current_instruction(), 0);
  remix_assert(OPND_IS_NEAR_PC(operand));
  app_pc addr = opnd_get_pc(operand);
  generated->set_next_pc(addr);
}

void Generator::emit_load_indirect_pc_to_r10() {
  // All application registers used by |instruction| must be valid entering
  // here.
  take_scratch_register(DR_REG_R10);

  init_tmp_instruction();
  instr_set_opcode(&tmp_instruction, OP_mov_ld);
  instr_set_num_opnds(GLOBAL_DCONTEXT, &tmp_instruction, 1, 1);
  opnd_t operand = instr_get_src(&current_instruction(), 0);
  instr_set_src(&tmp_instruction, 0, operand);
  instr_set_dst(&tmp_instruction, 0, opnd_create_reg(DR_REG_R10));
  emit_.instruction(tmp_instruction);
}

void Generator::end_fragment_with_indirect_jump() {
  emit_load_indirect_pc_to_r10();
  visit_control_flow_change_before_codegen();
  emit_spill_scratch_registers();
  emit_.jmp_long(choose_indirect_jump_stub());
  release_scratch_register(DR_REG_R10);
}

Assembler::Reg64 Generator::find_first_scratch_reg(uint8_t mask,
                                                   uint8_t try_to_avoid_regs) {
  if (mask & ~try_to_avoid_regs & ALL_SCRATCH_REGS) {
    // We can avoid |try_to_avoid_regs|; do so.
    mask &= ~try_to_avoid_regs;
  }
  for (int i = 0; i < Generator::SCRATCH_COUNT; ++i) {
    if (mask & (1 << i)) {
      return Generator::scratch_reg(i);
    }
  }
  remix_abort("Empty mask");
  return RAX();
}

void Generator::emit_push_return_address(app_pc ret_pc) {
  take_scratch_register(DR_REG_R8);

  if (scratch_regs_hold_rip) {
    // Can't overflow 32 bits since this fragment can be at most
    // MAX_BYTES_PER_FRAGMENT bytes long in source instructions, so the
    // generated code for a fragment is bounded. Must be >= 0.
    int32_t ret_pc_offset = ret_pc - start_pc;
    emit_.lea(RegMem64(find_first_scratch_reg(scratch_regs_hold_rip, 0)),
              ret_pc_offset, R8());
  } else {
    emit_.mov(ret_pc, R8());
  }
  emit_.push(R8());
}

GeneratedCode* Generator::code_for_direct_jump(app_pc pc) {
  GeneratedCode* b = Translation::lookup(pc);
  // Don't emit a direct jump if we're singlestepping; we must return to the
  // control loop.
  if (b && !singlestep_mode && !is_visited_pc(pc)) {
    return b;
  }
  return nullptr;
}

void Generator::end_fragment_with_call(app_pc end_pc,
                                       GeneratedFragment* generated) {
  emit_push_return_address(end_pc);
  visit_control_flow_change_before_codegen();
  emit_spill_scratch_registers();
  opnd_t operand = instr_get_src(&current_instruction(), 0);
  remix_assert(OPND_IS_NEAR_PC(operand));
  app_pc addr = opnd_get_pc(operand);
  // R8 still holds return address
  emit_.mov(RSP(), R9());
  emit_.mov(IPRel64(&return_address_rsp), RSP());
  Assembler::ForwardIPRel<int32_t> label;
  GeneratedCode* callee = code_for_direct_jump(addr);
  if (callee) {
    emit_.lea(IPRel64(callee), R11());
  } else {
    emit_.lea(label, R11());
    generated->set_next_pc(addr);
  }
  emit_.call(call_stub);
  release_scratch_register(DR_REG_R8);
  // This is what gets returned to when we return via the return-address stack
  emit_.mov(R9(), RSP());
  // Given the 'call' needs to be translated, the 'ret' will almost certainly
  // need to be translated, so no point in optimizing further; assume we'll
  // have to return to the translation loop when the return happens.
  emit_patchable_directed_return(end_pc);
  emit_.label(label);
}

void Generator::end_fragment_with_indirect_call(app_pc end_pc) {
  emit_load_indirect_pc_to_r10();
  emit_push_return_address(end_pc);
  visit_control_flow_change_before_codegen();
  emit_spill_scratch_registers();
  if (singlestep_mode) {
    // Use a stub that just returns from run_fragment with the correct next PC
    // set. We don't want to execute any more code in that case.
    emit_.jmp_long(singlestep_indirect_jump_stub);
  } else {
    // R8 still holds return address
    emit_.mov(RSP(), R9());
    emit_.mov(IPRel64(&return_address_rsp), RSP());
    emit_.call(choose_indirect_call_stub());
    // This is what gets returned to when we return via the return-address stack
    emit_.mov(R9(), RSP());
    // Given the 'call' needs to be translated, the 'ret' will almost certainly
    // need to be translated, so no point in optimizing further; assume we'll
    // have to return to the translation loop when the return happens.
    emit_patchable_directed_return(end_pc);
  }
  release_scratch_registers(Generator::dr_reg_to_scratch_mask(DR_REG_R8) |
                            Generator::dr_reg_to_scratch_mask(DR_REG_R10));
}

static void end_ret(Assembler& emit_) {
  if (singlestep_mode) {
    // Use a stub that just returns from run_fragment with the correct next PC
    // set. We don't want to execute any more code in that case.
    emit_.jmp_long(singlestep_indirect_jump_stub);
  } else {
    emit_.jmp_long(ret_stub);
  }
}

void Generator::end_fragment_with_ret() {
  emit_spill_scratch_registers();
  emit_.pop(R10());
  opnd_t operand = instr_get_src(&current_instruction(), 0);
  if (OPND_IS_IMMED_INT(operand)) {
    emit_.lea(RegMem64(RSP()), opnd_get_immed_int(operand), RSP());
  }
  visit_control_flow_change_before_codegen();
  end_ret(emit_);
}

void Generator::end_fragment_with_iret() {
  // IRET can be used purely in userspace, but it's poorly documented in the SDM.
  // The stack layout immediately prior to the iret is:
  // <RSP>:    The address to be returned to.
  // <RSP+8>:  The value to be loaded into CS.
  // <RSP+10>: The value to be loaded into EFLAGS.
  // <RSP+18>: The value to be loaded into RSP.
  // <RSP+20>: The value to be loaded into SS.
  //
  // A pure userspace iret isn't allowed to do anything interesting to the segment
  // registers (e.g. change privilege levels) of course, so we will just ignore them.
  // Anything that actually does change the segment registers is going to break here,
  // but loading a new value into CS would require actually executing an IRET which
  // is more complicated.
  //
  // From our perspective IRET is a combined POPFQ, POP %RSP, RET.

  emit_spill_scratch_registers();
  emit_.pop(R10());
  emit_.pop(R11()); // Ignore the CS register.
  emit_popf();
  emit_.pop(R11()); // R11 now contains the new RSP
  // Ignore the SS register.

  emit_.mov(R11(), RSP());
  // The new stack pointer is present, we can note the control flow change.
  visit_control_flow_change_before_codegen();
  // And jump.
  end_ret(emit_);
}

void Generator::emit_sync_signal_stop() {
  emit_.mov(start_pc, R8());
  emit_.jmp_long(sync_signal_stop_stub);
}

void Generator::maybe_emit_rcb_update(const AnalysisBase& analysis,
                                      int last_instruction_with_dead_flags) {
  if (last_instruction_with_dead_flags >= 0 &&
      instruction_index != last_instruction_with_dead_flags) {
    // We'll try to place the INC instruction as late as possible on the theory
    // that it's almost certainly not on any critical path, and we should
    // prioritize critical-path instructions over non-critical-path
    // instructions.
    return;
  }
  if (need_to_update_rcb && !(analysis.arith_flags_live & INC_flags())) {
    emit_.inc(IPRel64(&remix_rcb));
    need_to_update_rcb = false;
  }
}

void Generator::end_fragment_with_conditional_branch(app_pc end_pc,
                                                     int offset_size) {
  emit_spill_scratch_registers();

  if (need_to_update_rcb) {
    // Couldn't find a place to do it earlier with a single flag-clobbering
    // instruction, so increment rcb counter here without affecting flags
    emit_.mov(IPRel64(&remix_rcb), R8());
    emit_.lea(RegMem64(R8()), 1, R8());
    emit_.mov(R8(), IPRel64(&remix_rcb));
  }

  conditional_branch_start = emit_.next();

  // Avoid DynamoRio cti_short hackery. We don't need it.
  app_pc pc = instr_get_raw_bits(&current_instruction());
  size_t len = end_pc - pc;
  if (offset_size == 1) {
    int op = instr_get_opcode(&current_instruction());
    bool regular_branch = (op >= OP_jo_short && op <= OP_jnle_short) ||
                          (op >= OP_jo && op <= OP_jnle);
    if (regular_branch) {
      // chop off unnecessary prefixes. This will simplify things later.
      // Ignoring prediction-hint prefixes is OK because apparently modern
      // hardware does anyway. BND prefixes are ignored, but that's OK because
      // we don't support MPX right now and to support it, we just need to
      // ensure all MPX instructions are translated to noops; any #BR faults
      // will be emulated by replay anyway.
      emit_.imm(pc[len - 2]);
    } else {
      // This might be a multibyte instruction because JCXZ and LOOP* may have
      // an address-size prefix. So emit the instruction part, and then our
      // offset.
      emit_.imm(pc, len - 1);
    }
    emit_.imm(5); // size of a generic jmp instruction
  } else {
    // Far conditional branch. Convert to 2-byte form since we're just
    // going to jump forwards by 5 bytes. This also simplifies the completion
    // logic below since we only have short conditional branches as input.
    emit_.imm(pc[len - 5] - 0x10, 5);
  }
  conditional_branch_len = emit_.next() - conditional_branch_start;

  pc = end_pc;
  emit_.jmp_long(new_conditional_branch_not_taken_stub);
  emit_.jmp_long(new_conditional_branch_taken_stub);
  run_immediately_ = true;
  // After this, before any more code is emitted, we'll run the fragment,
  // land in one of the new_conditional_branch_* stubs, and complete_fragment()
  // will be called, which will rewrite the ending with the actual code.
  // OR we'll hit a stop before we reach the end, but in that
  // case this fragment will be invalidated so we're fine.
}

enum BranchState { BRANCH_UNTRANSLATED, BRANCH_FALL_THROUGH, BRANCH_JUMP };
enum BranchType { BRANCH_TAKEN, BRANCH_NOT_TAKEN };
struct BranchInfo {
  BranchState state;
  app_pc pc;
  GeneratedCode* addr;
  GeneratedCode* emit_stub(GeneratedCode* jmp_offset) {
    return emit_untranslated_branch_stub(pc, jmp_offset);
  }
};

static BranchInfo lookup_branch(app_pc pc) {
  BranchInfo info;
  info.pc = pc;
  info.addr = Translation::lookup(pc);
  info.state = info.addr ? BRANCH_JUMP : BRANCH_UNTRANSLATED;
  return info;
}

static GeneratedCode* convert_short_conditional_branch_to_near(
    GeneratedCode* start, GeneratedCode* dest, bool regular_branch) {
  if (!regular_branch) {
    // JCXZ or LOOP*. Turn it into
    //       jcxz/loop fwd
    //       jmp fwd2
    // fwd:  jmp dest
    // fwd2:
    // ... Suboptimal, but these are extremely rare. They simply do not occur
    // in Firefox libxul.so for example. (And if the destination address is
    // already translated and the translation is in range, we won't even have
    // to do this.)
    start[1].v = 2;
    start[2].v = 0xeb;
    start[3].v = 5;
    start[4].v = 0xe9;
    return Assembler::write(start + 5, (int32_t)(dest - (start + 9)));
  }
  start[1].v = start[0].v + 0x10;
  start[0].v = 0x0f;
  return Assembler::write(start + 2, (int32_t)(dest - (start + 6)));
}

void Generator::complete_fragment(GeneratedFragment* generated) {
  // Currently only conditional branches use this
  remix_assert(conditional_branch_start != nullptr);
  remix_assert(conditional_branch_len >= 2);

  // We don't need to do anything here to support singlestepping.
  // We're going to exit to the control loop anyway. Singlestep fragments
  // are always only used once, so it doesn't matter what changes we make here,
  // so we might as well do what we normally do.

  instr_t& instruction = instruction_buf[instruction_count - 1];
  opnd_t operand = instr_get_src(&instruction, 0);
  remix_assert(OPND_IS_NEAR_PC(operand));
  app_pc taken_pc = opnd_get_pc(operand);
  app_pc not_taken_pc = instr_get_raw_bits(&instruction) +
                        instr_length(GLOBAL_DCONTEXT, &instruction);

  BranchInfo branches[] = { lookup_branch(taken_pc),
                            lookup_branch(not_taken_pc) };
  BranchType follow =
      conditional_branch_taken ? BRANCH_TAKEN : BRANCH_NOT_TAKEN;

  // This didn't get set by any stub, so do it now.
  remix_registers.rip = uintptr_t(branches[follow].pc);

  if (branches[follow].state == BRANCH_UNTRANSLATED) {
    branches[follow].state = BRANCH_FALL_THROUGH;
    generated->set_next_pc(branches[follow].pc);
  }

  // All translations are before us in the code buffer.
  bool will_generate_backwards_branch =
      branches[BRANCH_TAKEN].state == BRANCH_JUMP;

  int op = instr_get_opcode(&instruction);
  bool regular_branch = (op >= OP_jo_short && op <= OP_jnle_short) ||
                        (op >= OP_jo && op <= OP_jnle);

  if ((taken_pc < not_taken_pc) != will_generate_backwards_branch &&
      regular_branch) {
    // We need to flip the direction of the branch. Try flipping the
    // branch test so the default prediction matches the original code.
    // Note that earlier we converted non-short branches to short ones.
    // end_fragment_with_conditional_branch already chopped off any prefixes
    // so we know the opcode is in the first byte.
    conditional_branch_start[0].v ^= 1;
    BranchInfo tmp = branches[0];
    branches[0] = branches[1];
    branches[1] = tmp;
    follow = conditional_branch_taken ? BRANCH_NOT_TAKEN : BRANCH_TAKEN;
  }

  // Now emit the actual branch.

  // Temporarily seize control from the Assembler here, since it's simpler to
  // mangle instructions manually.
  GeneratedCode* output = conditional_branch_start;
  switch (branches[BRANCH_TAKEN].state) {
    case BRANCH_JUMP: {
      intptr_t short_branch_offset =
          branches[BRANCH_TAKEN].addr - (output + conditional_branch_len);
      if (short_branch_offset == (int8_t)short_branch_offset) {
        // The short branch will work. Emit it.
        output[conditional_branch_len - 1].v = short_branch_offset;
        output += conditional_branch_len;
      } else {
        output = convert_short_conditional_branch_to_near(
            output + conditional_branch_len - 2,
            branches[BRANCH_TAKEN].addr, regular_branch);
      }
      break;
    }
    case BRANCH_UNTRANSLATED:
      output = convert_short_conditional_branch_to_near(
          output + conditional_branch_len - 2,
          stub_buffer.next(), regular_branch);
      branches[BRANCH_TAKEN].emit_stub(output - 4);
      break;
    case BRANCH_FALL_THROUGH:
      // The conditional will be a short forward jump over the not-taken code.
      // We'll fill it in below.
      output += conditional_branch_len;
      break;
  }
  emit_.reset(output);

  // Now emit the not-taken code.

  switch (branches[BRANCH_NOT_TAKEN].state) {
    case BRANCH_JUMP:
      emit_.jmp(branches[BRANCH_NOT_TAKEN].addr);
      break;
    case BRANCH_UNTRANSLATED:
      // This assumes we'll emit a near (not short) jump, which is true.
      emit_.jmp_long(branches[BRANCH_NOT_TAKEN].emit_stub(output + 1));
      break;
    case BRANCH_FALL_THROUGH:
      break;
  }

  if (branches[BRANCH_TAKEN].state == BRANCH_FALL_THROUGH) {
    conditional_branch_start[conditional_branch_len - 1].v =
        emit_.next() - (conditional_branch_start + conditional_branch_len);
  }
}

void Generator::fixup_rip_relative_operands(const AnalysisBase& analysis) {
  if (!analysis.uses_rip) {
    return;
  }

  instr_t& instruction = current_instruction();

  // A 64-bit move is longer than a RIP-relative LEA (10 vs 7), but that's
  // not a big deal and this may save us having to load a scratch register.
  if (instr_get_opcode(&instruction) == OP_lea) {
    instr_set_opcode(&instruction, OP_mov_imm);
    intptr_t value = intptr_t(opnd_get_addr(instr_get_src(&instruction, 0)));
    opnd_size_t size = opnd_get_size(instr_get_dst(&instruction, 0));
    if (size == OPSZ_4) {
      value = (int32_t)value;
    }
    instr_set_src(&instruction, 0, opnd_create_immed_int(value, size));
    return;
  }

  Reg64 rip_reg = RAX(); // dummy

  intptr_t offset = (app_pc)analysis.rip_address - start_pc;
  if (offset == (int32_t)offset) {
    uint8_t usable_regs_already_holding_pc =
        scratch_regs_hold_rip & ~analysis.scratch_regs_read;
    if (usable_regs_already_holding_pc) {
      rip_reg = find_first_scratch_reg(usable_regs_already_holding_pc, 0);
    } else {
      // Pick a register that won't be overwritten by this instruction. That
      // gives us a better chance of being able to reuse the register later.
      // A RIP-relative-addressing instruction can only read or write one
      // other register, so this can't fail.
      uint8_t usable_regs = ALL_SCRATCH_REGS ^ (analysis.scratch_regs_read |
                                                analysis.scratch_regs_written |
                                                scratch_regs_reserved_);
      rip_reg =
          find_first_scratch_reg(usable_regs, scratch_regs_match_application());
      uint8_t mask = 1 << (rip_reg.id() - DR_REG_R8);
      emit_spill_scratch_register(rip_reg.id());
      emit_.mov(start_pc, rip_reg);
      regs_match_application &= ~(mask << 8);
      scratch_regs_hold_rip |= mask;
    }

    if (analysis.uses_xh) {
      // If we're using XH, we can't take a REX prefix on this instruction.
      // So we need to use one of the lower 8 registers. RDI doesn't have an
      // upper byte register, so steal it.
      using_rdi_to_avoid_rex_register = rip_reg.id();
      emit_.xchg(rip_reg, RDI());
      rip_reg = RDI();
    }
  } else {
    // This shouldn't happen, but it's possible that we can't address the
    // rip-relative value using the fragment start PC as a base (because the
    // displacement address is INT32_MAX or something). Don't implement this
    // until we can write a test for it.
    remix_abort("crazy edge case with PC-rel 32-bit overflow");
  }

  int num_srcs = instr_num_srcs(&instruction);
  for (int i = 0; i < num_srcs; ++i) {
    opnd_t operand = instr_get_src(&instruction, i);
    if (OPND_IS_REL_ADDR(operand)) {
      instr_set_src(&instruction, i,
                    opnd_create_base_disp(rip_reg.id(), DR_REG_NULL, 0,
                                          (int32_t)offset,
                                          opnd_get_size(operand)));
    }
  }
  int num_dsts = instr_num_dsts(&instruction);
  for (int i = 0; i < num_dsts; ++i) {
    opnd_t operand = instr_get_dst(&instruction, i);
    if (OPND_IS_REL_ADDR(operand)) {
      instr_set_dst(&instruction, i,
                    opnd_create_base_disp(rip_reg.id(), DR_REG_NULL, 0,
                                          (int32_t)offset,
                                          opnd_get_size(operand)));
    }
  }
}

void Generator::unfixup_rip_relative_operands(const AnalysisBase& analysis) {
  if (analysis.output_instruction) {
    if (using_rdi_to_avoid_rex_register) {
      emit().xchg(RDI(), Reg64::from_dr(using_rdi_to_avoid_rex_register));
      using_rdi_to_avoid_rex_register = 0;
    }
  }
}

/**
 * Keep in mind that if an instruction returns TERMINATE_BEFORE here,
 * it may not end up being part of the fragment.
 */
uint32_t Generator::analyze_instruction_opcode(instr_t& instruction) {
  switch (instr_get_opcode(&instruction)) {
    case OP_int:
    case OP_into:
    case OP_int1:
    case OP_int3:
    case OP_hlt:
    // Syscalls are often followed by conditional branches, and we often
    // incur a conditional stop before a syscall instruction, in which case
    // the conditional branch fragment end will not be fixed up properly so
    // we'll force-invalidate the fragment. Avoid these invalidations by
    // terminating fragment immediately after the syscall so neither this
    // fragment nor the following conditional-branch fragment need to be
    // invalidated.
    case OP_syscall:
    case OP_cpuid:
    case OP_rdtsc:
    case OP_rdtscp:
    case OP_rdrand:
    // Some instrumentation tools are simpler if repeating string instructions
    // are their own fragment. They're not that common so we may as well
    // always make them their own fragment.
    case OP_rep_movs:
    case OP_rep_stos:
    case OP_rep_lods:
    case OP_rep_cmps:
    case OP_repne_cmps:
    case OP_rep_scas:
    case OP_repne_scas:
    // Some instrumentation tools are simpler if masked moves are always
    // put in their own fragment. These are also not common instructions.
    case OP_maskmovq:
    case OP_maskmovdqu:
    case OP_vmaskmovps:
    case OP_vmaskmovpd:
    case OP_vpmaskmovd:
    case OP_vpmaskmovq:
    case OP_vmaskmovdqu:
      return TERMINATE_AFTER | TERMINATE_BEFORE;

    // These are effectively masked moves if they have opmasks other than K0.
    case OP_vmovdqa32:
    case OP_vmovaps:
    case OP_vmovdqa64:
    case OP_vmovapd:
    case OP_vmovdqu8:
    case OP_vmovdqu16:
    case OP_vmovdqu32:
    case OP_vmovups:
    case OP_vmovdqu64:
    case OP_vmovupd:
      if (has_variable_opmask(&instruction)) {
        return TERMINATE_AFTER | TERMINATE_BEFORE;
      }
      break;

    // Some instrumentation tools are simpler if instructions that access huge
    // amounts of data (>= 512 bytes) are always put in their own fragment.
    // They're not that common. These also need to flush pending FIP changes
    // before this instruction. This ensures that if the FIP gets written to
    // user memory, it has the correct value.
    // Flushing also sets pending_fip to null so if we then restore the FIP
    // from some other state, that won't get overwritten by our pending_fip.
    case OP_fxsave32:
    case OP_fxsave64:
    case OP_fxrstor32:
    case OP_fxrstor64:
    case OP_xsave32:
    case OP_xsave64:
    case OP_xsavec32:
    case OP_xsavec64:
    case OP_xsaveopt32:
    case OP_xsaveopt64:
    case OP_xrstor32:
    case OP_xrstor64:
      return TERMINATE_AFTER | TERMINATE_BEFORE | NEEDS_FLUSH_PENDING_FIP;

    case OP_jmp:
    case OP_jmp_short:
    case OP_jmp_ind:
    case OP_call:
    case OP_call_ind:
    case OP_ret:
    case OP_iret:
      // Don't bother propagating the adjusted RSP here; since this
      // is the last instruction in the fragment, we can't use the
      // updated RSP information.
    case OP_vzeroupper:
      return TERMINATE_AFTER;

    case OP_rsqrtss:
    case OP_rsqrtps:
    case OP_rcpss:
    case OP_rcpps:
    case OP_vrsqrtss:
    case OP_vrsqrtps:
    case OP_vrcpss:
    case OP_vrcpps:
      // If we are emulating, we need to terminate the fragment. Emulation
      // will clobber the scratch registers and we might be using them (e.g.
      // to aggregate writes).
      if (correct_rcp_rsqrt) {
        return TERMINATE_AFTER;
      }
      break;

    case OP_jo_short:
    case OP_jno_short:
    case OP_jb_short:
    case OP_jnb_short:
    case OP_jz_short:
    case OP_jnz_short:
    case OP_jbe_short:
    case OP_jnbe_short:
    case OP_js_short:
    case OP_jns_short:
    case OP_jp_short:
    case OP_jnp_short:
    case OP_jl_short:
    case OP_jnl_short:
    case OP_jle_short:
    case OP_jnle_short:
    case OP_loopne:
    case OP_loope:
    case OP_loop:
    case OP_jecxz:
    case OP_jo:
    case OP_jno:
    case OP_jb:
    case OP_jnb:
    case OP_jz:
    case OP_jnz:
    case OP_jbe:
    case OP_jnbe:
    case OP_js:
    case OP_jns:
    case OP_jp:
    case OP_jnp:
    case OP_jl:
    case OP_jnl:
    case OP_jle:
    case OP_jnle:
      return TERMINATE_AFTER | NEEDS_RCB_UPDATE;

    // OP_fwait:
    // OP_fnclex:
    // OP_fldcw:
    // OP_fnstcw:
    // OP_fnstsw:
    // These x87 instructions DO NOT set FIP. See "x87 FPU Instruction and
    // Data (Operand) Pointers" in the Intel manual.
    case OP_fninit:
    case OP_fnsave:
    case OP_fnstenv:
    case OP_fldenv:
    case OP_frstor:
      // Flush pending FIP changes before this instruction. This ensures that
      // if the FIP gets written to user memory, it has the correct value.
      // Flushing also sets pending_fip to null so if we then restore the FIP
      // from some other state, that won't get overwritten by our pending_fip.
      return NEEDS_FLUSH_PENDING_FIP;

    // Apply register flow effects (conservatively, focusing on common cases)
    case OP_push_imm:
    case OP_push:
      flow_analysis.visit_push(&instruction);
      break;
    case OP_pop:
      flow_analysis.visit_pop(&instruction);
      break;
    case OP_add:
    case OP_sub:
      flow_analysis.visit_add_sub(&instruction);
      break;
    case OP_lea:
      flow_analysis.visit_lea(&instruction);
      break;
    case OP_mov_ld:
    case OP_mov_st:
    case OP_mov_imm:
      flow_analysis.visit_mov(&instruction);
      break;
  }
  return 0;
}

void Generator::optimize_mov(AnalysisBase& analysis, const DataflowTracker& dataflow_tracker) {
  instr_t& instruction = current_instruction();
  opnd_t dst = instr_get_dst(&instruction, 0);
  if (!OPND_IS_REG(dst)) {
    return;
  }
  reg_id_t dst_reg = opnd_get_reg(dst);
  if (dst_reg < DR_REG_RAX || dst_reg > DR_REG_R15D) {
    return;
  }
  GprIndex dst_reg_index = to_64(dst_reg) - DR_REG_RAX;
  if (!(regs_match_application & (1 << dst_reg_index))) {
    return;
  }
  CanonicalValue new_value = dataflow_tracker.gpr_value_at(dst_reg_index, analysis.index + 1);
  if (dataflow_tracker.gpr_value(dst_reg_index) == new_value) {
    // The current value is already correct so do nothing.
    instr_set_opcode(&instruction, OP_nop);
    return;
  }
  opnd_t src = instr_get_src(&instruction, 0);
  if (OPND_IS_REG(src)) {
    // Already a reg->reg move so we can't improve it.
    return;
  }
  // Look for a value already in a register that we can use instead of a load.
  for (GprIndex i = 0; i < NUM_GPRS; ++i) {
    if (!(regs_match_application & (1 << i))) {
      continue;
    }
    if (dataflow_tracker.gpr_value(i) == new_value) {
      instr_set_src(&instruction, 0, opnd_create_reg(match_reg_size(DR_REG_RAX + i, dst_reg)));
      return;
    }
  }
  // Now look for the slightly more complicated situation where the value exists
  // in a register with some offset
  for (GprIndex i = 0; i < NUM_GPRS; ++i) {
    if (!(regs_match_application & (1 << i))) {
      continue;
    }
    CanonicalValue r = dataflow_tracker.gpr_value(i);
    if (r.base_reg != new_value.base_reg ||
        r.defined_at_instruction != new_value.defined_at_instruction) {
      continue;
    }
    uint64_t delta_offset = new_value.offset - r.offset;
    if ((int64_t)delta_offset != (int32_t)delta_offset) {
      continue;
    }
    bool is_64 = dst_reg <= DR_REG_R15;
    if (is_64 && (r.flags & CANONICAL_VALUE_32BITS) &&
        !(new_value.flags & CANONICAL_VALUE_32BITS)) {
      // We can't use this, because the register high 32 bits have been zeroed but we
      // need those bits.
      continue;
    }
    instr_set_opcode(&instruction, OP_lea);
    if ((new_value.flags & CANONICAL_VALUE_32BITS) && is_64) {
      is_64 = false;
      instr_set_dst(&instruction, 0, opnd_create_reg(dst_reg - DR_REG_RAX + DR_REG_EAX));
    }
    opnd_t src_operand = opnd_create_base_disp(
      i + (is_64 ? DR_REG_RAX : DR_REG_EAX), DR_REG_NULL, 1,
      (int32_t)delta_offset, OPSZ_lea);
    instr_set_src(&instruction, 0, src_operand);
    return;
  }
}

void Generator::check_strange_instructions(AnalysisBase& analysis) {
  seen_hle |= instr_get_prefix_flag(analysis.instr, PREFIX_XACQUIRE | PREFIX_XRELEASE);
}

void Generator::output_instruction(AnalysisBase& analysis,
                                   const DataflowTracker& dataflow_tracker, app_pc end_pc,
                                   GeneratedFragment* generated) {
  instr_t& instruction = current_instruction();
  int opcode = instr_get_opcode(&instruction);
  switch (opcode) {
    case OP_syscall:
      emit_syscall();
      generated->set_next_pc(end_pc);
      break;

    case OP_int3:
      // Stop at all int3s (breakpoints).
      emit_spill_scratch_registers();
      emit_.mov(end_pc, R8());
      emit_.jmp_long(breakpoint_stop_stub);
      break;

    case OP_int:
      if (instr_is_syscall(&instruction)) {
        emit_int_syscall();
        generated->set_next_pc(end_pc);
      }
      break;

    case OP_cpuid:
      if (!use_cpuid_faulting) {
        // Never emit an actual CPUID instruction. We always
        // want to use values from a trace event or values from
        // the trace record header via handle_unrecorded_cpuid_fault.
        emit_handle_unrecorded_cpuid_fault();
        generated->set_next_pc(end_pc);
        break;
      }
      // Fall through
    case OP_int1:
    case OP_into:
    case OP_hlt:
    case OP_rdtsc:
    case OP_rdtscp:
      // We always emit a stop after these instructions
      break;

    case OP_rep_movs:
    case OP_rep_stos:
    case OP_rep_lods:
    case OP_rep_cmps:
    case OP_repne_cmps:
    case OP_rep_scas:
    case OP_repne_scas:
      emit_repeating_string_instruction();
      generated->set_next_pc(end_pc);
      break;

    case OP_jmp:
    case OP_jmp_short:
      end_fragment_with_jump(generated);
      break;

    case OP_jmp_ind:
      end_fragment_with_indirect_jump();
      break;

    case OP_call:
      end_fragment_with_call(end_pc, generated);
      break;

    case OP_call_ind:
      end_fragment_with_indirect_call(end_pc);
      break;

    case OP_ret:
      end_fragment_with_ret();
      break;

    case OP_iret:
      end_fragment_with_iret();
      break;

    case OP_pushf:
      emit_pushf(opnd_get_size(instr_get_dst(&instruction, 1)));
      break;
    case OP_popf: {
      opnd_t flags = instr_get_src(&instruction, 1);
      if (opnd_get_size(flags) == OPSZ_2) {
        emit_popf16();
      } else {
        emit_popf();
      }
      break;
    }

    case OP_jo_short:
    case OP_jno_short:
    case OP_jb_short:
    case OP_jnb_short:
    case OP_jz_short:
    case OP_jnz_short:
    case OP_jbe_short:
    case OP_jnbe_short:
    case OP_js_short:
    case OP_jns_short:
    case OP_jp_short:
    case OP_jnp_short:
    case OP_jl_short:
    case OP_jnl_short:
    case OP_jle_short:
    case OP_jnle_short:
    case OP_loopne:
    case OP_loope:
    case OP_loop:
    case OP_jecxz:
      end_fragment_with_conditional_branch(end_pc, 1);
      break;

    case OP_jo:
    case OP_jno:
    case OP_jb:
    case OP_jnb:
    case OP_jz:
    case OP_jnz:
    case OP_jbe:
    case OP_jnbe:
    case OP_js:
    case OP_jns:
    case OP_jp:
    case OP_jnp:
    case OP_jl:
    case OP_jnl:
    case OP_jle:
    case OP_jnle:
      end_fragment_with_conditional_branch(end_pc, 4);
      break;

    case OP_nop:
    case OP_nop_modrm:
      /* These are probably for alignment in the original code. They're not
       * helping that in the generated code, so just remove them.
       */
      break;

    case OP_mov_ld:
    case OP_mov_st:
      optimize_mov(analysis, dataflow_tracker);
      if (instr_get_opcode(&instruction) != OP_nop) {
        emit_.instruction(instruction);
      }
      break;

    case OP_f2xm1:
    case OP_fabs:
    case OP_fadd:
    case OP_faddp:
    case OP_fbld:
    case OP_fbstp:
    case OP_fchs:
    case OP_fcom:
    case OP_fcomp:
    case OP_fcompp:
    case OP_fdecstp:
    case OP_fdiv:
    case OP_fdivp:
    case OP_fdivr:
    case OP_fdivrp:
    case OP_ffree:
    case OP_fiadd:
    case OP_ficom:
    case OP_ficomp:
    case OP_fidiv:
    case OP_fidivr:
    case OP_fild:
    case OP_fimul:
    case OP_fincstp:
    case OP_fist:
    case OP_fistp:
    case OP_fisub:
    case OP_fisubr:
    case OP_fld:
    case OP_fld1:
    case OP_fldl2e:
    case OP_fldl2t:
    case OP_fldlg2:
    case OP_fldln2:
    case OP_fldpi:
    case OP_fldz:
    case OP_fmul:
    case OP_fmulp:
    case OP_fnop:
    case OP_fpatan:
    case OP_fprem:
    case OP_fptan:
    case OP_frndint:
    case OP_fscale:
    case OP_fsqrt:
    case OP_fst:
    case OP_fstp:
    case OP_fsub:
    case OP_fsubp:
    case OP_fsubr:
    case OP_fsubrp:
    case OP_ftst:
    case OP_fxam:
    case OP_fxch:
    case OP_fxtract:
    case OP_fyl2x:
    case OP_fyl2xp1:
    case OP_fcos:
    case OP_fprem1:
    case OP_fsin:
    case OP_fsincos:
    case OP_fucom:
    case OP_fucomp:
    case OP_fucompp:
    case OP_fcmovnbe:
    case OP_fcmovne:
    case OP_fcmovnu:
    case OP_fcmovu:
    case OP_fcomi:
    case OP_fcomip:
    case OP_fucomi:
    case OP_fucomip:
    case OP_fcmovb:
    case OP_fcmovbe:
    case OP_fcmove:
    case OP_fcmovnb:
    case OP_fisttp:
    case OP_ffreep:
      emit_.instruction(current_instruction());
      emit_.mov((int32_t)(long)analysis.pc, IPRel32(&pending_fip));
      emit_.mov((int32_t)((long)analysis.pc >> 32),
                IPRel32((int32_t*)&pending_fip + 1));
      break;

    // Emulate AMD rsqrt/rcp on Intel or vice versa
    case OP_rsqrtss:
      emit_corrected_rcp_rsqrt(generated, end_pc, zen_rsqrt(), correct_single_rcp_rsqrt_stub);
      break;
    case OP_rsqrtps:
      emit_corrected_rcp_rsqrt(generated, end_pc, zen_rsqrt(), correct_packed_rcp_rsqrt_stub);
      break;
    case OP_rcpss:
      emit_corrected_rcp_rsqrt(generated, end_pc, zen_rcp(), correct_single_rcp_rsqrt_stub);
      break;
    case OP_rcpps:
      emit_corrected_rcp_rsqrt(generated, end_pc, zen_rcp(), correct_packed_rcp_rsqrt_stub);
      break;
    case OP_vrsqrtss:
      emit_corrected_rcp_rsqrt(generated, end_pc, zen_rsqrt(), correct_single_vex_rcp_rsqrt_stub);
      break;
    case OP_vrsqrtps:
      emit_corrected_rcp_rsqrt(generated, end_pc, zen_rsqrt(), correct_packed_vex_rcp_rsqrt_stub);
      break;
    case OP_vrcpss:
      emit_corrected_rcp_rsqrt(generated, end_pc, zen_rcp(), correct_single_vex_rcp_rsqrt_stub);
      break;
    case OP_vrcpps:
      emit_corrected_rcp_rsqrt(generated, end_pc, zen_rcp(), correct_packed_vex_rcp_rsqrt_stub);
      break;

    // Emulate lzcnt/tzcnt on unsupported CPUs, or vice versa.
    case OP_lzcnt:
      emit_corrected_lzcnt();
      break;
    case OP_tzcnt:
      emit_corrected_tzcnt();
      break;

    case OP_xgetbv:
      emit_xgetbv();
      break;

    case OP_rdrand:
      emit_rdrand(analysis.pc);
      generated->set_next_pc(end_pc);
      break;

    case OP_fxsave32:
    case OP_fxsave64:
    case OP_fxrstor32:
    case OP_fxrstor64:
    case OP_xsaveopt32:
    case OP_xsaveopt64:
      emit_.instruction(current_instruction());
      generated->set_next_pc(end_pc);
      break;

    case OP_xsave32:
    case OP_xsave64:
    case OP_xsavec32:
    case OP_xsavec64:
    case OP_xrstor32:
    case OP_xrstor64:
      // We also need to mask EDX:EAX to the tracee XCR0 in case our host
      // XCR0 has extra bits that cause extra writes that the tracee
      // didn't see. (If the tracee XCR0 has extra bits over our host,
      // we're doomed, but we'll detect that.)
      // We don't need to do this for XSAVEOPT because it limits what
      // it writes to the XINUSE components (and XINUSE bits of XSTATE_BV),
      // and if components unsupported by our host are in use, we're already dead.
      // We *do* need to do this for XSAVEC because it will set XCOMP_BV
      // bits to RFBM bits (the AND of EDX:EAX and CPU XCR0) even if the
      // corresponding XINUSE bits are zero.
      emit_xsave_wrapper();
      generated->set_next_pc(end_pc);
      break;

    case OP_vzeroupper:
    case OP_maskmovq:
    case OP_maskmovdqu:
    case OP_vmaskmovps:
    case OP_vmaskmovpd:
    case OP_vpmaskmovd:
    case OP_vpmaskmovq:
    case OP_vmaskmovdqu:
      /// These are only special in that they terminate their fragment.
      generated->set_next_pc(end_pc);
      emit_.instruction(current_instruction());
      break;

    case OP_sha1msg1:
    case OP_sha1msg2:
    case OP_sha1nexte:
    case OP_sha1rnds4:
    case OP_sha256msg1:
    case OP_sha256msg2:
    case OP_sha256rnds2:
      if (!cpu_has_sha()) {
        instruction_unsupported_on_this_cpu(analysis.pc, opcode, "sha");
      }
      emit_.instruction(current_instruction());
      break;

    case OP_xtest: {
      // This is 100% safe to execute if and only if we've never seen an HLE instruction.
      if (seen_hle) {
        instruction_unsupported_for_replay(analysis.pc, opcode);
      }

      emit_.instruction(current_instruction());
      break;
    }

    case OP_wrfsbase: {
      // We have to update remix_registers.fs_base too.
      reg_id_t src_reg = OPND_GET_REG(instr_get_src(&current_instruction(), 0));
      emit_.mov(Reg64::from_dr(src_reg), IPRel64(&remix_registers.fs_base));
      emit_.instruction(current_instruction());
      break;
    }

    case OP_wrgsbase: {
      // We have to update remix_registers.gs_base too.
      reg_id_t src_reg = OPND_GET_REG(instr_get_src(&current_instruction(), 0));
      emit_.mov(Reg64::from_dr(src_reg), IPRel64(&remix_registers.gs_base));
      emit_.instruction(current_instruction());
      break;
    }

    case OP_mov_seg:
      // Only movs with segment registers as a source are supported.
      if (opnd_is_reg(instr_get_src(&current_instruction(), 0)) &&
          reg_is_segment(opnd_get_reg(instr_get_src(&current_instruction(), 0)))) {
        // default handling
        emit_.instruction(current_instruction());
        break;
      }
      RR_FALLTHROUGH;

    // We would need special handling for this so that when used as a cheap
    // hack to get the current CPU core number, it returns the right result ---
    // since remix doesn't bind tracees to a particular CPU.
    case OP_lsl:

    /** Many more privileged instructions arguably should be listed here */
    case OP_arpl:
    case OP_bndcl:
    case OP_bndcn:
    case OP_bndcu:
    case OP_bndldx:
    case OP_bndmk:
    case OP_bndmov:
    case OP_bndstx:
    case OP_call_far:
    case OP_call_far_ind:
    case OP_clts:
    case OP_getsec:
    case OP_in:
    case OP_ins:
    case OP_outs:
    case OP_jmp_far:
    case OP_jmp_far_ind:
    case OP_lgdt:
    case OP_lidt:
    case OP_lldt:
    case OP_lmsw:
    case OP_ltr:
    case OP_movdir64b:
    case OP_mov_priv:
    case OP_rdmsr:
    case OP_rdpmc:
    case OP_rep_ins:
    case OP_rep_outs:
    case OP_ret_far:
    case OP_rsm:
    case OP_sgdt:
    case OP_sidt:
    case OP_skinit:
    case OP_sldt:
    case OP_smsw:
    case OP_str:
    case OP_sysenter:
    case OP_sysexit:
    case OP_sysret:
    case OP_verr:
    case OP_verw:
    case OP_vmcall:
    case OP_vmfunc:
    case OP_vmlaunch:
    case OP_vmmcall:
    case OP_vmresume:
    case OP_vmrun:
    case OP_vmxoff:
    case OP_vmxon:
    case OP_xabort:
    case OP_xbegin:
    case OP_xend:
      instruction_unsupported_for_replay(analysis.pc, opcode);
      break;

    case OP_vmovdqa32:
    case OP_vmovaps:
    case OP_vmovdqa64:
    case OP_vmovapd:
    case OP_vmovdqu8:
    case OP_vmovdqu16:
    case OP_vmovdqu32:
    case OP_vmovups:
    case OP_vmovdqu64:
    case OP_vmovupd:
      if (has_variable_opmask(&current_instruction())) {
        /// These are only special in that they terminate their fragment.
        generated->set_next_pc(end_pc);
      }
      RR_FALLTHROUGH;
    default:
      emit_.instruction(current_instruction());
      break;
  }
}

void Generator::output_instruction_skipped(app_pc end_pc,
                                           GeneratedFragment* generated) {
  instr_t& instruction = current_instruction();

  switch (instr_get_opcode(&instruction)) {
    case OP_int1:
    case OP_into:
    case OP_rdtsc:
    case OP_rdtscp:
    case OP_int3:
    case OP_hlt:
    case OP_syscall:
    case OP_rep_movs:
    case OP_rep_stos:
    case OP_rep_lods:
    case OP_rep_cmps:
    case OP_repne_cmps:
    case OP_rep_scas:
    case OP_repne_scas:
    case OP_fxsave32:
    case OP_fxsave64:
    case OP_fxrstor32:
    case OP_fxrstor64:
    case OP_xsave32:
    case OP_xsave64:
    case OP_xsavec32:
    case OP_xsavec64:
    case OP_xsaveopt32:
    case OP_xsaveopt64:
    case OP_xrstor32:
    case OP_xrstor64:
      generated->set_next_pc(end_pc);
      break;
    case OP_cpuid:
      if (use_cpuid_faulting) {
        generated->set_next_pc(end_pc);
      }
      break;

    case OP_int:
      if (instr_is_syscall(&instruction)) {
        generated->set_next_pc(end_pc);
      }
      break;

    default:
      break;
  }
}

void Generator::fix_fragment_size() {
  // Invalid fragments are patched with a near jmp so we need to be at least
  // that long.
  const int min_fragment_size = 5;
  if (emit_.next() < code_buffer.next() + min_fragment_size) {
    emit_.nops(code_buffer.next() + min_fragment_size - emit_.next());
  }
}

uint8_t* Generator::log_disassemble(uint8_t* pc) {
  if (!(remix_log_modules & REMIX_LOG_GEN)) {
    return nullptr;
  }
  char buf[1024];
  int out_chars;
  app_pc ret = disassemble_to_buffer(GLOBAL_DCONTEXT, pc, pc, false, false, buf,
                                     sizeof(buf), &out_chars);
  // Chop off trailing newline
  buf[out_chars - 1] = 0;
  remix_log(REMIX_LOG_GEN, "  %p: %s", pc, buf);
  return ret;
}

void Generator::log_disassemble_fragment() {
  if (!(remix_log_modules & REMIX_LOG_GEN)) {
    return;
  }
  for (GeneratedCode* b = code_buffer.next(); b < emit_.next();) {
    auto* bb = reinterpret_cast<uint8_t*>(b);
    uint8_t* next = log_disassemble(bb);
    if (!next) {
      break;
    }
    b += next - bb;
  }
}

void remix_apply_quirk(RemixQuirk quirk, void* arg2, void* arg3, void* arg4, void* arg5) {
  AutoSaveRestoreState save_state;

  if (quirk == RemixQuirk::XSAVE_COMPONENT_DATA) {
    note_trace_cpuid_data_for_component((intptr_t)arg2, (uintptr_t)arg3, (uintptr_t)arg4, (uintptr_t)arg5);
    return;
  }

  if (quirk == RemixQuirk::ALLOW_RDRAND) {
    Generator::allow_rdrand_start = (app_pc)arg2;
    Generator::allow_rdrand_end = (app_pc)arg3;
    return;
  }

  remix_abort("Unknown quirk %d %x %x", quirk, arg2, arg3);
}

REMIX_TARGET_END
