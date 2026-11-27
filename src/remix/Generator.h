/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_GENERATOR_H_
#define RR_GENERATOR_H_

#include <stddef.h>
#include <sys/mman.h>

#include "Assembler.h"
#include "DataflowAnalysis.h"
#include "ToolHooks.h"
#include "engine.h"
#include "generator_utils.h"
#include "remix.h"
#include "remix_util.h"
#include "string.h"

REMIX_TARGET_BEGIN

/**
 * Per-instruction analysis results
 */
struct AnalysisBase {
  // Analysis results generated during the first pass:

  app_pc pc;

  instr_t* instr;

  // Absolute address that is targeted by the rip-relative operand. Only
  // meaningful if uses_rip is set.
  void* rip_address;

  // Number of the instruction within the fragment
  int index;

  // Arithmetic flags read by this instruction (some subset of
  // EFLAGS_READ_ARITH)
  uint16_t arith_flags_read;
  // Arithmetic flags written by this instruction (some subset of
  // EFLAGS_READ_ARITH). If a flag is conditionally written then we
  // add it to arith_flags_read as well.
  uint16_t arith_flags_written;

  // Which scratch registers are read.
  uint8_t scratch_regs_read;
  // Which scratch registers are written. If a register is partially or
  // conditionally written we add that register to the read mask as well.
  uint8_t scratch_regs_written;

  // True if the instruction uses rip-relative memory addressing (in which
  // case we have to rewrite that operand).
  bool uses_rip;

  // True if the instruction has an output memory operand.
  bool has_write_memory_operand;

  // True if the instruction uses AH, BH, CH, DH.
  // These registers are incompatible with REX prefixes.
  bool uses_xh;

  // True if the instruction counts as a "tick".
  bool is_tick;

  // True if this instruction requires us to flush_pending_fip().
  bool flush_pending_fip;

  // WRITEABLE BY TOOLS
  // Set this to skip output_instruction. The tool will be responsible for
  // generating its own code for this instruction.
  bool output_instruction;

  // Analysis results generated during the second pass:

  // Arithmetic flags live at the start of this instruction.
  uint16_t arith_flags_live;
  // Arithmetic flags live at the end of this instruction.
  uint16_t arith_flags_live_at_end;

  template <typename A> A& other(int i) {
    return static_cast<A*>(this)[i - index];
  }
};

struct FragmentAnalysis {
  // Index of last instruction where all arithmetic flags are dead before it.
  // -1 if there is no such instruction.
  int last_instruction_with_dead_flags;
};

struct RcpRsqrtEmulationTable {
  int values[22];
  char deltas[1 << 21];
};

/**
 * Class controlling code generation for a fragment.
 * Contains state that gets set as we generate instrumented code,
 * including the current state of each scratch register.
 */
class Generator {
public:
  typedef Assembler::Reg512 Reg512;
  typedef Assembler::Reg256 Reg256;
  typedef Assembler::Reg128 Reg128;
  typedef Assembler::Reg64 Reg64;
  typedef Assembler::Reg32 Reg32;
  typedef Assembler::Reg8 Reg8;
  typedef Assembler::IPRel256 IPRel256;
  typedef Assembler::IPRel64 IPRel64;
  typedef Assembler::IPRel32 IPRel32;
  typedef Assembler::IPRel16 IPRel16;
  typedef Assembler::RegMem512 RegMem512;
  typedef Assembler::RegMem256 RegMem256;
  typedef Assembler::RegMem128 RegMem128;
  typedef Assembler::RegMem64 RegMem64;
  typedef Assembler::RegMem32 RegMem32;
  typedef Assembler::RegMem16 RegMem16;
  typedef Assembler::RegMem8 RegMem8;

  Generator(app_pc pc)
      : start_pc(pc),
        emit_(code_buffer.next()),
        instruction_count(0),
        instruction_index(0),
        conditional_branch_start(nullptr),
        need_to_update_rcb(false),
        conditional_branch_len(0),
        regs_match_application(0xF0FF),
        scratch_regs_dirty(0),
        scratch_regs_hold_rip(0),
        scratch_regs_reserved_(0),
        run_immediately_(false),
        using_rdi_to_avoid_rex_register(0) {}
  GeneratedFragment generate_fragment(Fragment first_fragment);
  virtual ~Generator() {
    remix_assert(!scratch_regs_dirty);
    code_buffer.mark_allocated(emit_.next());
  }

  instr_t& init_tmp_instruction() {
    instr_reuse(GLOBAL_DCONTEXT, &tmp_instruction);
    return tmp_instruction;
  }
  instr_t& current_instruction() { return instruction_buf[instruction_index]; }

  bool run_immediately() { return run_immediately_; }

  /**
   * Saves RAX to rax_scratch and copies arith flags to AL/AH
   */
  void emit_save_flags(reg_id_t rax_scratch = DR_REG_R11);
  /**
   * Restores arith flags from AL/AH and restores RAX from rax_scratch
   */
  void emit_restore_flags(reg_id_t rax_scratch = DR_REG_R11);

  void emit_store_constant_bytes(int size, uint8_t* bytes, Reg64 reg,
                                 int offset);
  void emit_copy_bytes(Reg64 src, int src_offset, int size, Reg64 dst,
                       int dst_offset, Reg64 tmp);

  /* Analyzes instruction operands. */
  void analyze_instruction_operands(AnalysisBase& result);

  /* Finds a free scratch register and emits code to load PC into it --- unless
   * we already have it in a scratch register.
   * Modifies |instruction|'s operands to use that register.
   */
  void fixup_rip_relative_operands(const AnalysisBase& analysis);

  void unfixup_rip_relative_operands(const AnalysisBase& analysis);

  enum {
    /**
     * Terminate fragment before this instruction, if not before the first
     * instruction.
     */
    TERMINATE_BEFORE = 0x01,
    /**
     * Instructions that return TERMINATE_AFTER are required to ensure that
     * the fragment does end, either by calling GeneratedFragment::set_next_pc
     * and falling through, or by jumping somewhere else.
     */
    TERMINATE_AFTER = 0x02,
    /**
     * Set if this is a conditional branch that should update the RCB counter
     */
    NEEDS_RCB_UPDATE = 0x04,
    /**
     * Set if this instruction needs a preceeding flush_pending_fip call.
     */
    NEEDS_FLUSH_PENDING_FIP = 0x08
  };
  /**
   * Do opcode-specific processing during the first pass.
   */
  uint32_t analyze_instruction_opcode(instr_t& instruction);

  /**
   * Handle string instructions, control transfer instructions,
   * syscall instructions specially, or just encode the instruction.
   * Sets generated->(have_)next_pc to the instruction to we wish to fall
   * through to.
   */
  void output_instruction(AnalysisBase& analysis,
                          const DataflowTracker& dataflow_tracker, app_pc end_pc,
                          GeneratedFragment* generated);
  /**
   * Like output_instruction but doesn't actually output the instruction, just
   * sets generated->(have_)next_pc if necessary.
   */
  void output_instruction_skipped(app_pc end_pc, GeneratedFragment* generated);

  GeneratedFragment process_instructions();

  void emit_unconditional_stop();
  void emit_conditional_stop();
  void emit_conditional_breakpoint_fault_stop();
  void emit_conditional_syscall_stop();
  void emit_monitor_before_syscall(uint8_t is_32bit);
  void emit_monitor_after_syscall(uint8_t is_32bit);
  void emit_syscall();
  void emit_int_syscall();
  void emit_handle_unrecorded_cpuid_fault();
  void emit_flush_pending_fip();
  void emit_corrected_rcp_rsqrt(GeneratedFragment* generated, app_pc end_pc,
                                const RcpRsqrtEmulationTable* table, AsmStub stub);
  void emit_corrected_lzcnt();
  void emit_corrected_tzcnt();
  /* Trashes R11 */
  void emit_popf();
  /* Trashes R11 */
  void emit_popf16();
  void emit_pushf(opnd_size_t operand_size);
  void emit_xgetbv();
  void emit_rdrand(app_pc pc);
  void emit_xsave_wrapper();
  /* Trashes all of R8-R11 */
  void emit_repeating_string_instruction();
  void emit_directed_return(app_pc next_pc);
  void emit_patchable_directed_return(app_pc next_pc);
  void end_fragment_with_jump(GeneratedFragment* generated);
  void end_fragment_with_indirect_jump();
  void end_fragment_with_call(app_pc end_pc, GeneratedFragment* generated);
  void end_fragment_with_indirect_call(app_pc end_pc);
  void end_fragment_with_ret();
  void end_fragment_with_iret();
  void maybe_emit_rcb_update(const AnalysisBase& analysis,
                             int last_instruction_with_dead_flags);
  void end_fragment_with_conditional_branch(app_pc end_pc, int offset_size);
  void emit_sync_signal_stop();

  void emit_load_indirect_pc_to_r10();
  /**
   * Leaves the return address in R8, an allocated scratch register.
   */
  void emit_push_return_address(app_pc end_pc);

  // |dest| must be 64-bit. |mask| should have just one bit set; that
  // scratch reg is loaded into |dest|.
  void emit_load_scratch_register_to_other_reg(uint8_t mask, reg_id_t dest);
  // Load subset of scratch regsters with their application values.
  // All 'scratch masks' are bit 0 = R8, bit 1 = R9, bit 2 = R10, bit 3 = R11
  void emit_load_scratch_registers(uint8_t mask = 0xff);
  // Spill scratch registers holding dirty application values to remix_registers
  // storage.
  void emit_spill_scratch_registers(uint8_t mask = 0xff);
  // Spill the given scratch registers as necessary and mark them as "in use" by
  // instrumentation code.
  // Call this before using the register, unless you call
  // emit_spill_scratch_register yourself and take care not to reuse the register.
  void take_scratch_registers(uint8_t mask = 0xff);
  // Mark registers as "not in use" by instrumentation code.
  void release_scratch_registers(uint8_t mask = 0xff);

  // Convenience wrapper for emit_load_scratch_registers for a single register.
  void emit_load_scratch_register(reg_id_t reg) {
    emit_load_scratch_registers(dr_reg_to_scratch_mask(reg));
  }
  // Convenience wrapper for emit_spill_scratch_registers for a single register.
  void emit_spill_scratch_register(reg_id_t reg) {
    emit_spill_scratch_registers(dr_reg_to_scratch_mask(reg));
  }
  // Convenience wrapper for take_scratch_registers for a single register.
  void take_scratch_register(reg_id_t reg) {
    take_scratch_registers(dr_reg_to_scratch_mask(reg));
  }
  // Convenience wrapper for release_scratch_registers for a single register.
  void release_scratch_register(reg_id_t reg) {
    release_scratch_registers(dr_reg_to_scratch_mask(reg));
  }

  // Find the first available scratch register in `mask`. Try to avoid
  // using the registers in `try_to_avoid_regs`, but fall back to using
  // them if necessary.
  static Assembler::Reg64 find_first_scratch_reg(uint8_t mask,
                                                 uint8_t try_to_avoid_regs);
  uint8_t scratch_regs_holding_rip() { return scratch_regs_hold_rip; }

  /**
   * Emit padding to ensure the fragment is big enough to be patched
   * if it becomes invalid. Must be idempotent, since we may call it twice
   * if we need the fragment ending address early.
   */
  void fix_fragment_size();

  void complete_fragment(GeneratedFragment* generated);

  void log_disassemble_fragment();
  static uint8_t* log_disassemble(uint8_t* pc);

  Assembler& emit() { return emit_; }

  static void init();

  enum { SCRATCH_COUNT = 4, ALL_SCRATCH_REGS = (1 << SCRATCH_COUNT) - 1 };

  static Reg64 scratch_reg(int index) {
    return Reg64::from_dr(DR_REG_R8 + index);
  }

  static const int scratch_user_regs_struct_offsets[4];

  static uint8_t dr_reg_to_scratch_mask(reg_id_t reg) {
    if (reg >= DR_REG_R8 && reg <= DR_REG_R11) {
      return 1 << (reg - DR_REG_R8);
    }
    if (reg >= DR_REG_R8D && reg <= DR_REG_R11D) {
      return 1 << (reg - DR_REG_R8D);
    }
    if (reg >= DR_REG_R8W && reg <= DR_REG_R11W) {
      return 1 << (reg - DR_REG_R8W);
    }
    if (reg >= DR_REG_R8L && reg <= DR_REG_R11L) {
      return 1 << (reg - DR_REG_R8L);
    }
    return 0;
  }
  static uint8_t dr_regs_to_scratch_mask(reg_id_t reg1, reg_id_t reg2) {
    return dr_reg_to_scratch_mask(reg1) | dr_reg_to_scratch_mask(reg2);
  }
  static uint8_t dr_regs_to_scratch_mask(reg_id_t reg1, reg_id_t reg2,
                                         reg_id_t reg3) {
    return dr_reg_to_scratch_mask(reg1) | dr_reg_to_scratch_mask(reg2) |
           dr_reg_to_scratch_mask(reg3);
  }
  static uint8_t dr_regs_to_scratch_mask(reg_id_t reg1, reg_id_t reg2,
                                         reg_id_t reg3, reg_id_t reg4) {
    return dr_reg_to_scratch_mask(reg1) | dr_reg_to_scratch_mask(reg2) |
           dr_reg_to_scratch_mask(reg3) | dr_reg_to_scratch_mask(reg4);
  }

  uint8_t scratch_regs_match_application() {
    return (regs_match_application >> 8) & 0xF;
  }
  void set_scratch_regs_match_application(uint8_t mask) {
    regs_match_application = (regs_match_application & 0xF0FF) | (mask << 8);
  }
  void set_reg_matches_application(reg_id_t reg, bool matches) {
    remix_assert(DR_REG_RAX <= reg && reg <= DR_REG_R15);
    uint16_t mask = 1 << (reg - DR_REG_RAX);
    if (matches) {
      regs_match_application |= mask;
    } else {
      regs_match_application &= ~mask;
    }
  }

  uint8_t scratch_regs_in_use() {
    return scratch_regs_match_application() | scratch_regs_hold_rip |
           scratch_regs_reserved_;
  }
  uint8_t scratch_regs_reserved() { return scratch_regs_reserved_; }

  static GeneratedCode* code_for_direct_jump(app_pc pc);

protected:
  void optimize_mov(AnalysisBase& analysis, const DataflowTracker& dataflow_tracker);
  void check_strange_instructions(AnalysisBase& analysis);

  virtual void visit_interrupted_instruction_codegen() = 0;
  /**
   * Instrumentation must preserve R8.
   * For indirect call/jump/ret instructions, destination must be in R10, which must be preserved.
   * For other instructions, R10 may be trashed.
   * R9/R11 may be trashed.
   * RSP must be after any push (for a call) and after any ret.
   */
  virtual void visit_control_flow_change_before_codegen() = 0;

  // PC of the start of the fragment
  app_pc start_pc;
  Assembler emit_;
  int instruction_count;
  int instruction_index;

  // Conditional-branch state
  GeneratedCode* conditional_branch_start;
  // Set during first pass
  bool need_to_update_rcb;
  uint8_t conditional_branch_len;

  /* Bit set when the GP register holds the application's value. */
  uint16_t regs_match_application;

  /* Bit set when the scratch register holds the application's value and
   * needs to be written back to remix_registers */
  uint8_t scratch_regs_dirty;
  /* Bit set when the scratch register holds the PC of the fragment start */
  uint8_t scratch_regs_hold_rip;
  /* Bit set when the scratch register has been reserved for some other
   * purpose */
  uint8_t scratch_regs_reserved_;

  // When set, after generating the fragment, run it immediately and then
  // call complete_fragment() (unless a stop occurred before the end, in which
  // case the fragment will be invalidated).
  bool run_immediately_;

  // When set, RDI has been swapped with this register so that we can avoid
  // triggering a REX prefix.
  reg_id_t using_rdi_to_avoid_rex_register;

  DataflowAnalysis flow_analysis;

  static instr_t instruction_buf[MAX_BYTES_PER_FRAGMENT + 1];
  static instr_t tmp_instruction;
  static void* analysis_buf;
  static app_pc allow_rdrand_start;
  static app_pc allow_rdrand_end;
  static const uintptr_t rdrand_return_value;
  // True if XACQUIRE/XRELEASE have ever been seen.
  static bool seen_hle;

  friend void remix_apply_quirk(RemixQuirk, void*, void*, void*, void*);
};

class ToolBase {
public:
  typedef AnalysisBase Analysis;
  typedef Assembler::Reg512 Reg512;
  typedef Assembler::Reg256 Reg256;
  typedef Assembler::Reg128 Reg128;
  typedef Assembler::Reg64 Reg64;
  typedef Assembler::Reg32 Reg32;
  typedef Assembler::Reg16 Reg16;
  typedef Assembler::Reg8 Reg8;
  typedef Assembler::IPRel256 IPRel256;
  typedef Assembler::IPRel128 IPRel128;
  typedef Assembler::IPRel64 IPRel64;
  typedef Assembler::IPRel32 IPRel32;
  typedef Assembler::IPRel16 IPRel16;
  typedef Assembler::IPRelConst IPRelConst;
  typedef Assembler::AbsMem64 AbsMem64;
  typedef Assembler::RegMem512 RegMem512;
  typedef Assembler::RegMem256 RegMem256;
  typedef Assembler::RegMem128 RegMem128;
  typedef Assembler::RegMem64 RegMem64;
  typedef Assembler::RegMem32 RegMem32;
  typedef Assembler::RegMem16 RegMem16;
  typedef Assembler::RegMem8 RegMem8;

  // Forward analysis pass
  void begin_forward_analysis_pass(app_pc) {}
  void begin_analyzing_instruction(Analysis& analysis) {
    if (stop_mode == STOP_AT_IP_EMULATE && analysis.pc == stop_pc) {
      analysis.output_instruction = false;
    }
  }
  void visit_src_operand(const opnd_t&, Analysis&) {}
  void visit_dst_operand(const opnd_t&, Analysis&, DataflowAnalysis&) {}
  void end_analyzing_instruction(Analysis&) {}
  bool stop_after_instruction(Analysis&) { return false; }

  void begin_backward_analysis_pass() {}
  void visit_instruction_for_backward_analysis(Analysis&) {}

  // Codegen pass
  void begin_codegen_pass() {}
  void visit_instruction_before_codegen(Analysis&, Generator&,
                                        FragmentAnalysis&) {}
  // Called immediately before generating an instruction that changes the
  // control flow (JMP/CALL/RET).
  void visit_control_flow_change_before_codegen(Analysis&, Generator&) {}
  // Code emitted here runs after a repeated string instruction is interrupted
  // (by a singlestep or an async signal).
  // Code generated here will be executed, and the instruction will (probably)
  // be later resumed; then the before-codegen code will run again.
  void visit_interrupted_instruction_codegen(Analysis&, Generator&) {}
  void visit_instruction_after_codegen(Analysis& analysis, Generator& gen,
                                       FragmentAnalysis&, const DataflowTracker&) {
    gen.unfixup_rip_relative_operands(analysis);
  }
  // Called after all instructions have been codegen'ed; return true to
  // invalidate the fragment we just built. It will never be executed.
  // did_fragment will not be called.
  bool immediately_invalidate() { return false; }

  void did_fragment(uint8_t /*instruction_bytes*/,
                    uint16_t /*translated_length*/) {}
};

template <typename Tool> class ToolGenerator final : public Generator {
public:
  typedef typename Tool::Analysis Analysis;

  ToolGenerator(app_pc pc) : Generator(pc) {}

  virtual void visit_interrupted_instruction_codegen() override {
    tool.visit_interrupted_instruction_codegen(analysis_for(instruction_index),
                                               *this);
  }

  virtual void visit_control_flow_change_before_codegen() override {
    tool.visit_control_flow_change_before_codegen(
        analysis_for(instruction_index), *this);
  }

  Analysis& analysis_for(int index) {
    return static_cast<Analysis*>(analysis_buf)[index];
  }

  static void init() {
    Generator::init();
    analysis_buf = new typename Tool::Analysis[MAX_BYTES_PER_FRAGMENT];
  }

  void analyze_instruction_operands(Analysis& analysis) {
    instr_t& instruction = current_instruction();
    auto opcode = instr_get_opcode(&instruction);

    analysis.scratch_regs_read = 0;
    analysis.scratch_regs_written = 0;
    analysis.uses_rip = false;
    analysis.has_write_memory_operand = false;
    analysis.uses_xh = false;
    analysis.is_tick = false;
    analysis.flush_pending_fip = false;
    // We could call instr_reads_from_reg/instr_writes_to_reg four times each
    // but we can do quite a bit better.
    int num_srcs = instr_num_srcs(&instruction);
    for (int i = 0; i < num_srcs; ++i) {
      opnd_t operand = instr_get_src(&instruction, i);
      if (OPND_IS_REG(operand)) {
        reg_id_t reg = opnd_get_reg(operand);
        uint8_t mask = dr_reg_to_scratch_mask(reg);
        if (mask) {
          // xor reg,reg does not really use its operands ... providing it's
          // a 32-bit or 64-bit xor.
          if (i == 0 && opcode == OP_xor &&
              reg >= DR_REG_RAX && reg <= DR_REG_R15D) {
            remix_assert(num_srcs == 2);
            opnd_t op2 = instr_get_src(&instruction, 1);
            if (OPND_IS_REG(op2) && opnd_get_reg(op2) == reg) {
              break;
            }
          }
          analysis.scratch_regs_read |= mask;
        }
        if (DR_REG_AH <= reg && reg <= DR_REG_BH) {
          analysis.uses_xh = true;
        }
      } else if (OPND_IS_BASE_DISP(operand)) {
        analysis.scratch_regs_read |=
            dr_reg_to_scratch_mask(opnd_get_base(operand)) |
            dr_reg_to_scratch_mask(opnd_get_index(operand));
      } else if (OPND_IS_REL_ADDR(operand)) {
        // At most 1 unique rip-relative address per instruction
        void* addr = opnd_get_addr(operand);
        remix_assert(!analysis.uses_rip || addr == analysis.rip_address);
        analysis.uses_rip = true;
        analysis.rip_address = addr;
      }
      tool.visit_src_operand(operand, analysis);
    }
    int num_dsts = instr_num_dsts(&instruction);
    for (int i = 0; i < num_dsts; ++i) {
      opnd_t operand = instr_get_dst(&instruction, i);
      if (OPND_IS_REG(operand)) {
        reg_id_t reg = opnd_get_reg(operand);
        uint8_t mask = dr_reg_to_scratch_mask(reg);
        analysis.scratch_regs_written |= mask;
        if ((reg >= DR_REG_R8W && reg <= DR_REG_R11W) ||
            (reg >= DR_REG_R8L && reg <= DR_REG_R11L)) {
          // These writes are only partial. Therefore the instruction requires
          // these registers as inputs too.
          analysis.scratch_regs_read |= mask;
        } else if (opcode == OP_bsf || opcode == OP_bsr ||
            (correct_tzcnt && opcode == OP_tzcnt) ||
            (correct_lzcnt && opcode == OP_lzcnt)) {
          // The bsf/bsr instructions can leave the destination unchanged.
          analysis.scratch_regs_read |= mask;
        }
        if (DR_REG_AH <= reg && reg <= DR_REG_BH) {
          analysis.uses_xh = true;
        }
      } else if (OPND_IS_BASE_DISP(operand)) {
        analysis.has_write_memory_operand = true;
        analysis.scratch_regs_read |=
            dr_reg_to_scratch_mask(opnd_get_base(operand)) |
            dr_reg_to_scratch_mask(opnd_get_index(operand));
      } else if (OPND_IS_REL_ADDR(operand)) {
        // At most 1 unique rip-relative address per instruction
        void* addr = opnd_get_addr(operand);
        remix_assert(!analysis.uses_rip || addr == analysis.rip_address);
        analysis.uses_rip = true;
        analysis.has_write_memory_operand = true;
        analysis.rip_address = addr;
      }
      flow_analysis.visit_dst_operand(instruction_index, i, operand);
      tool.visit_dst_operand(operand, analysis, flow_analysis);
    }

    uint32_t flag_effects =
        instr_get_arith_flags(&instruction, DR_QUERY_INCLUDE_ALL);
    analysis.arith_flags_read = flag_effects & EFLAGS_READ_ARITH;
    analysis.arith_flags_written =
        EFLAGS_WRITE_TO_READ(flag_effects & EFLAGS_WRITE_ARITH);

    if (instr_is_predicated(&instruction)) {
      // Since the instruction only happens conditionally, any output scratch
      // registers are also implicitly read.
      analysis.scratch_regs_read |= analysis.scratch_regs_written;
      // And any written flags depend on their input values.
      analysis.arith_flags_read |= analysis.arith_flags_written;
    } else if (instr_get_opcode(&instruction) == OP_syscall) {
      // Clear this, it's handled specially in code generation.
      uint8_t r11_mask = dr_reg_to_scratch_mask(DR_REG_R11);
      analysis.scratch_regs_written &= ~r11_mask;
    }
  }

  GeneratedFragment process_instructions() {
    GeneratedCode* final_translation = nullptr;
    GeneratedFragment result;

    uint8_t page_prot = Translation::get_prot(start_pc);
    uint8_t next_page_prot;
    app_pc start_pc_page = floor_page_size(start_pc);
    if (floor_page_size(start_pc + MAX_BYTES_PER_FRAGMENT - 1) != start_pc_page) {
      next_page_prot = Translation::get_prot(start_pc + MAX_BYTES_PER_FRAGMENT - 1);
    } else {
      next_page_prot = page_prot;
    }

    // FIRST PASS:
    flow_analysis.begin_forward_analysis_pass();
    tool.begin_forward_analysis_pass(start_pc);
    // Decode and analyze each instruction, find fragment end.
    // Grab all the instructions and figure out where the fragment will end,
    // before we emit any code.
    app_pc pc = start_pc;
    bool seen_write_instruction = false;
    while (true) {
      instr_reuse(GLOBAL_DCONTEXT, &current_instruction());
      app_pc next_pc = decode(GLOBAL_DCONTEXT, pc, &current_instruction());
      if (!next_pc) {
        // Decoding failed. If the tracee actually executed an invalid
        // instruction
        // we wouldn't reach here (we'd stop earlier with a signal). So this
        // must be an instruction that was executed but DR doesn't know about.
        remix_abort(
            "Unknown instruction at %p: "
            "%02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x "
            "%02x %02x %02x",
            pc, pc[0], pc[1], pc[2], pc[3], pc[4], pc[5], pc[6], pc[7], pc[8],
            pc[9], pc[10], pc[11], pc[12], pc[13], pc[14]);
      }
      // Bound fragment length, or things can get pathological (e.g. multiple
      // entries to a long instruction sequence could generate O(N)
      // fragments each of length O(N))
      if (next_pc - start_pc > MAX_BYTES_PER_FRAGMENT) {
        result.set_next_pc(pc);
        break;
      }
      flow_analysis.begin_analyzing_instruction();
      // This can alter the instruction, optimizing it to a simpler form.
      uint32_t opflags = analyze_instruction_opcode(current_instruction());
      // If we've already processed at least one instruction then reject this
      // next instruction if:
      // * It's TERMINATE_BEORE
      // * We need to trigger a visited callback
      // * We started in a PROT_WRITE page and we have seen a write instruction
      // * The instruction extends into the next page and that page is PROT_WRITE and
      // we have seen a write instruction.
      // In PROT_WRITE pages fragments can't have any instructions following a write
      // instruction since that write might invalidate following instructions in the
      // fragment.
      // XXX a "rep stos/movs" might overwrite itself; we don't handle that properly
      // because all iterations are folded into a single fragment.
      if (pc > start_pc &&
          ((opflags & TERMINATE_BEFORE) || is_visited_pc(pc) ||
           (seen_write_instruction &&
            ((page_prot & PROT_WRITE) ||
             (floor_page_size(next_pc - 1) != start_pc_page &&
              (next_page_prot & PROT_WRITE)))))) {
        result.set_next_pc(pc);
        break;
      }

      // Now we're committed to including this instruction in this fragment
      Analysis& analysis = analysis_for(instruction_index);
      analysis.pc = pc;
      analysis.instr = &current_instruction();
      analysis.index = instruction_index;
      analysis.output_instruction = true;
      check_strange_instructions(analysis);
      tool.begin_analyzing_instruction(analysis);
      log_disassemble(pc);
      analyze_instruction_operands(analysis);
      if (opflags & NEEDS_RCB_UPDATE) {
        analysis.is_tick = true;
        if (!Translation::translation_mode()) {
          need_to_update_rcb = true;
        }
      }
      if (opflags & NEEDS_FLUSH_PENDING_FIP) {
        analysis.flush_pending_fip = true;
      }
      tool.end_analyzing_instruction(analysis);
      flow_analysis.end_analyzing_instruction();
      pc = next_pc;
      ++instruction_index;
      seen_write_instruction |= analysis.has_write_memory_operand;

      // If we're supposed to stop after this instruction, don't bother
      // handling more than one instruction. But always cover one instruction
      // so that invalidation works properly.
      if ((opflags & TERMINATE_AFTER) ||
          tool.stop_after_instruction(analysis) ||
          (start_pc == stop_pc &&
           (stop_mode == STOP_AT_IP || stop_mode == STOP_AT_IP_EMULATE) &&
           !Translation::translation_mode())) {
        break;
      }
      if (singlestep_mode) {
        result.set_next_pc(pc);
        break;
      }
      final_translation = Translation::lookup(pc);
      if (final_translation) {
        if (is_visited_pc(pc)) {
          final_translation = nullptr;
          result.set_next_pc(pc);
        }
        break;
      }
      if (pc == stop_pc) {
        result.set_next_pc(pc);
        break;
      }
    }
    instruction_count = instruction_index;

    // SECOND PASS:
    // Propagate some analysis information backwards.
    tool.begin_backward_analysis_pass();
    uint16_t arith_flags_live = EFLAGS_READ_ARITH;
    FragmentAnalysis fragment_analysis = { -1 };
    for (int index = instruction_count - 1; index >= 0; --index) {
      Analysis& analysis = analysis_for(index);
      analysis.arith_flags_live_at_end = arith_flags_live;
      arith_flags_live = analysis.arith_flags_live =
          (arith_flags_live & ~analysis.arith_flags_written) |
          analysis.arith_flags_read;
      if (!arith_flags_live &&
          fragment_analysis.last_instruction_with_dead_flags < 0) {
        fragment_analysis.last_instruction_with_dead_flags = index;
      }
      tool.visit_instruction_for_backward_analysis(analysis);
    }

    // Verify that no code was produced during the analysis phase
    remix_assert(emit_.next() == code_buffer.next());

    // Emit stops that happen before the instruction executes
    if (!Translation::translation_mode()) {
      if (start_pc == stop_pc) {
        if (stop_mode == STOP_AT_IP) {
          emit_unconditional_stop();
        } else if (stop_mode == STOP_AT_TARGET) {
          emit_conditional_stop();
        } else if (stop_mode == STOP_AT_BREAKPOINT_FAULT) {
          emit_conditional_breakpoint_fault_stop();
        } else if (stop_mode == STOP_AT_IP_EMULATE) {
          // We should have forced this fragment to have a single
          // instruction.
          remix_assert(instruction_count == 1);
        }
      }

      switch (instr_get_opcode(&instruction_buf[0])) {
        case OP_syscall:
          emit_conditional_syscall_stop();
          break;
        case OP_int:
          if (instr_is_syscall(&instruction_buf[0])) {
            emit_conditional_syscall_stop();
          }
          break;
        case OP_xor:
          // NB: For RR_PAGE_SYSCALL_UNTRACED_RECORDING_ONLY "syscalls", we need
          // to emit a syscall stop here if we're singlestepping. This is the only
          // thing that allows us to stop here if we're doing
          // `rerun -x --singlestep=...`.
          if (stop_mode == STOP_AT_SYSCALL &&
              instruction_count == 1 &&
              start_pc == (void*)0x7000000c) {
            emit_conditional_syscall_stop();
          }
          break;
      }
    }

    // THIRD PASS:
    // Instrumentation and code generation
    tool.begin_codegen_pass();
    app_pc end_pc = pc;
    DataflowTracker dataflow_tracker(flow_analysis);
    for (instruction_index = 0; instruction_index < instruction_count;
         ++instruction_index) {
      Analysis& analysis = analysis_for(instruction_index);
      dataflow_tracker.process_up_to(instruction_index);
      if (analysis.has_write_memory_operand &&
          ((page_prot | next_page_prot) & PROT_WRITE)) {
        // Ensure there's space to patch the start of this fragment
        // without affecting this instruction, since it may need to
        // be invalidated and then restarted.
        const int invalidation_jump_size = 5;
        if (emit_.next() < code_buffer.next() + invalidation_jump_size) {
          emit_.nops(code_buffer.next() + invalidation_jump_size - emit_.next());
        }
      }
      tool.visit_instruction_before_codegen(analysis, *this, fragment_analysis);
      maybe_emit_rcb_update(analysis,
                            fragment_analysis.last_instruction_with_dead_flags);

      if (analysis.output_instruction) {
        // Do this before loading scratch registers, because this will clobber
        // scratch registers.
        if (analysis.flush_pending_fip) {
          emit_flush_pending_fip();
        }
        emit_load_scratch_registers(analysis.scratch_regs_read);
        fixup_rip_relative_operands(analysis);
        output_instruction(analysis, dataflow_tracker, end_pc, &result);
        regs_match_application |= analysis.scratch_regs_written << 8;
        scratch_regs_dirty |= analysis.scratch_regs_written;
        scratch_regs_hold_rip &= ~analysis.scratch_regs_written;
      } else {
        output_instruction_skipped(end_pc, &result);
      }

      tool.visit_instruction_after_codegen(analysis, *this, fragment_analysis, dataflow_tracker);
    }

    result.translation =
        Translation::insert(start_pc, end_pc - start_pc, code_buffer.next());
    emit_spill_scratch_registers();

    // Emit stops that happen after the instruction executes
    if (!Translation::translation_mode()) {
      if (start_pc == stop_pc) {
        if (stop_mode == STOP_AT_IP_EMULATE) {
          emit_unconditional_stop();
        }
      }

      switch (instr_get_opcode(&instruction_buf[0])) {
        case OP_int:
          if (!instr_is_syscall(&instruction_buf[0])) {
            emit_sync_signal_stop();
          }
          break;
        case OP_int1:
        case OP_into:
        case OP_hlt:
        case OP_rdtsc:
        case OP_rdtscp:
          emit_sync_signal_stop();
          break;
        case OP_cpuid:
          if (use_cpuid_faulting) {
            emit_sync_signal_stop();
          }
          break;
      }
    }

    if (final_translation) {
      // Already translated. Don't extend this fragment, just emit a jump to the
      // translation.
      remix_assert(!result.have_next_pc);
      emit_.jmp(final_translation);
    } else if (result.have_next_pc) {
      GeneratedCode* b = Generator::code_for_direct_jump(result.next_pc);
      if (b) {
        // Already translated so just jump to the translation ... which could be
        // this fragment itself.
        emit_.jmp(b);
        result.have_next_pc = false;
      }
    }
    return result;
  }

  GeneratedFragment generate_fragment(Fragment first_fragment) {
    bool invalidate = false;

    remix_log(REMIX_LOG_GEN,
              "Generating fragment for pc=%p at %p (mode %d); input:", start_pc,
              code_buffer.next(), Translation::translation_mode());

    GeneratedFragment result = process_instructions();

    if (tool.immediately_invalidate()) {
      invalidate = true;
    } else if (run_immediately()) {
      remix_log(REMIX_LOG_EXEC,
                "Executing immediately pc=%p at %p, rcb=%lld (mode %d)",
                (app_pc)remix_registers.rip,
                first_fragment, (long long)remix_rcb,
                Translation::translation_mode());
      run_fragment(first_fragment);
      result.did_run = true;
      if (patch_callback) {
        remix_assert(patch_callback == patch_invalid_fragment_stub);
        // Invalidation was triggered on some fragment along the path to this
        // fragment --- possibly this fragment itself.
        // We aren't going to run this.
        patch_callback = nullptr;
        // We stopped before reaching the end of our just-generated fragment,
        // so we can't complete the fragment. Invalidate it. If it has already
        // been invalidated, `invalidate_code` will be a no-op so that's fine.
        invalidate = true;
      } else if (stop_flag) {
        // We stopped before reaching the end of our just-generated fragment,
        // so we can't complete the fragment. Invalidate it.
        invalidate = true;
      } else {
        // We reached the end of our fragment.
        // Complete the fragment using information gathered from this run.
        complete_fragment(&result);
      }
    }
    if (result.have_next_pc &&
        (singlestep_mode || is_visited_pc(result.next_pc))) {
      // The fragment is trying to fall through. We need to generate a stub
      // that will return from run_fragment so the main loop gets to run.
      // stop_pc may be untranslateable and we might be in the target state,
      // and we need to stop before we try to translate it.
      emit_directed_return(result.next_pc);
      result.have_next_pc = false;
    }
    if (result.have_next_pc && result.next_pc == stop_pc) {
      // We may not be able to generate a fragment for stop_pc if it's an
      // invalid address. If it is invalid, then we must be doing a
      // STOP_AT_TARGET
      // or STOP_AT_IP to reach the state where the signal is generated. So,
      // after running the fragment, return to the main loop where we can test
      // that state. If the stop_pc *is* valid and we're not in the target
      // state, make sure this fragment gets patched with a direct jump to the stop_pc.
      // (This fragment could be part of a hot loop and we don't want to exit to
      // the main loop on each iteration.)
      emit_patchable_directed_return(result.next_pc);
      result.have_next_pc = false;
    }
    if (result.have_next_pc && start_pc == stop_pc) {
      // Don't generate fragments past stop_pc yet. There's no guarantee that we
      // ever execute that code, so it may not even be valid.
      emit_patchable_directed_return(result.next_pc);
      result.have_next_pc = false;
    }
    // Make sure fragment is big enough to be invalidated before we might need
    // to invalidate it.
    fix_fragment_size();
    tool.did_fragment(result.translation->pc_length(),
                      emit().next() - code_buffer.next());
    remix_log(REMIX_LOG_GEN,
              "Fall-through pc=%p, output fragment:", result.next_pc);
    log_disassemble_fragment();
    if (invalidate) {
      invalidate_code(start_pc, start_pc + 1);
    }
    // Ensure that any scratch registers temporarily reserved by a tool have
    // been released.
    remix_assert(!scratch_regs_reserved());
    return result;
  }

  static GeneratedFragment generate_one_fragment(app_pc start_pc,
                                                 Fragment first_fragment) {
    ToolGenerator<Tool> gen(start_pc);
    return gen.generate_fragment(first_fragment);
  }

  Tool tool;
};

template <typename Tool> class ToolHooksImpl : public ToolHooks {
public:
  ToolHooksImpl() { ToolGenerator<Tool>::init(); }

  virtual GeneratedFragment generate_one_fragment(app_pc pc,
                                                  Fragment first_fragment) {
    return ToolGenerator<Tool>::generate_one_fragment(pc, first_fragment);
  }
};

inline uint32_t INC_flags() {
  return EFLAGS_READ_PF | EFLAGS_READ_AF | EFLAGS_READ_OF | EFLAGS_READ_ZF |
         EFLAGS_READ_SF;
}

void report_instruction_error(app_pc pc, int opcode, RemixErrorCode code);

REMIX_TARGET_END

#endif /* RR_GENERATOR_H_ */
