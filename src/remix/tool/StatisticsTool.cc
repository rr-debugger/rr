/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include <errno.h>
#include <stdio.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

#include <algorithm>
#include <functional>

#include "../Generator.h"
#include "../Hashtable.h"
#include "../generator_utils.h"
#include "../../core.h"

REMIX_TARGET_BEGIN

using namespace std;

struct StatsRecord {
  uint64_t effective_address_low_byte_frequences[256];

  uint64_t fragments_translated;
  uint64_t instructions_translated;
  uint64_t fragments_invalidated;
  uint64_t full_resets;

  uint64_t fragment_instruction_count_frequencies[256];
  uint64_t fragment_byte_count_frequencies[256];
  uint64_t fragment_translated_byte_count_frequencies[8192];

  uint64_t instructions_executed;
  uint64_t instructions_executed_using_reg[96];

  uint64_t bytes_written_excluding_repeating_string;
  uint64_t bytes_written_using_rip;
  uint64_t bytes_written_using_repeating_string;
  uint64_t bytes_written_using_reg[16];
  uint64_t avx512_masked_memory_writes;
  uint64_t avx512_gather_scatter_instructions;

  uint64_t ticks;

  uint64_t translated_instruction_execution_count_frequencies[1000];
  app_pc translated_instruction_execution_count_example[1000];

  uint64_t xinuse_reads;
};

extern "C" {
extern AsmStub before_xgetbv_stub;
extern AsmStub mem_operand_stub;

void before_xgetbv(void);

StatsRecord* stats_record;
}

struct FragmentStats {
  void* operator new(size_t count) { return malloc(count); }
  void operator delete(void* ptr) { free(ptr); }

  FragmentStats* next;
  uint64_t* fragment_execution_counter;
  app_pc pc;
  uint16_t bytes_written;
  uint16_t bytes_written_using_rip;
  uint16_t bytes_written_using_reg[16];
  uint8_t instruction_count;
  uint8_t instruction_count_using_reg[96];
  uint8_t instruction_boundary_bits[32];
  uint8_t avx512_masked_memory_writes;
  uint8_t avx512_gather_scatter_instructions;
  bool ends_with_tick;
};

static uint64_t translated_instruction_execution_count_frequency_max[1000];
static FragmentStats* fragment_stats;

static const bool count_string_instruction_repetitions = false;

static void init_bucket_sizes() {
  uint64_t size = 0;
  for (int i = 0; i < 1000; ++i) {
    translated_instruction_execution_count_frequency_max[i] = size;
    size = max(size + 1, (size * 9) / 8);
  }
}

struct PCFreq {
  PCFreq(app_pc pc, uint64_t freq = 0) : pc(pc), freq(freq) {}
  app_pc pc;
  uint64_t freq;
  bool operator==(const PCFreq& other) const { return other.pc == pc; }
};
template <> size_t hash(const PCFreq& p) { return std::hash<app_pc>()(p.pc); }

static void write_back_process_stats() {
  FragmentStats* next;
  Hashtable<PCFreq> freqs;
  for (FragmentStats* f = fragment_stats; f; f = next) {
    next = f->next;
    uint64_t exec_count = *f->fragment_execution_counter;
    stats_record->instructions_executed += exec_count * f->instruction_count;
    for (size_t i = 0; i < sizeof(f->instruction_count_using_reg)/sizeof(f->instruction_count_using_reg[0]); ++i) {
      stats_record->instructions_executed_using_reg[i] +=
          f->instruction_count_using_reg[i] * exec_count;
    }
    stats_record->bytes_written_excluding_repeating_string += exec_count * f->bytes_written;
    stats_record->bytes_written_using_rip += exec_count * f->bytes_written_using_rip;
    if (f->ends_with_tick) {
      stats_record->ticks += exec_count;
    }
    stats_record->avx512_masked_memory_writes += exec_count * f->avx512_masked_memory_writes;
    stats_record->avx512_gather_scatter_instructions += exec_count * f->avx512_gather_scatter_instructions;
    for (int i = 0; i < 16; ++i) {
      stats_record->bytes_written_using_reg[i] +=
          f->bytes_written_using_reg[i] * exec_count;
    }
    for (int i = 0; i < 32; ++i) {
      if (f->instruction_boundary_bits[i]) {
        for (int j = 0; j < 8; ++j) {
          if (f->instruction_boundary_bits[i] & (1 << j)) {
            app_pc addr = f->pc + i * 8 + j;
            PCFreq* val = freqs.lookup(PCFreq(addr));
            if (val) {
              val->freq += exec_count;
            } else {
              freqs.insert(PCFreq(addr, exec_count));
            }
          }
        }
      }
    }
    delete f;
  }

  for (auto& p : freqs) {
    uint64_t exec_count = p.freq;
    for (int i = 0; i < 1000; ++i) {
      if (exec_count <=
          translated_instruction_execution_count_frequency_max[i]) {
        ++stats_record->translated_instruction_execution_count_frequencies[i];
        stats_record->translated_instruction_execution_count_example[i] = p.pc;
        break;
      }
    }
  }

  fragment_stats = nullptr;
}

void before_xgetbv() {
  /* Because we're called via prepare_enter_cpp_fast,
     we will ONLY see correct GP-register state in
     remix_registers for %rsp,%eflags,%rax,%rcx,%rdx,%rsi,%rdi.
     We are NOT allowed to use MM or x87 registers since they are not
     being saved/restored.
   */
  if ((uint32_t)remix_registers.rcx == 1) {
    ++stats_record->xinuse_reads;
  }
}

static const char* gp_regs[] = { "RAX", "RCX", "RDX", "RBX",
                                 "RSP", "RBP", "RSI", "RDI",
                                 "R8", "R9", "R10", "R11",
                                 "R12", "R13", "R14", "R15" };

static int find_last_index(uint64_t* values, int len) {
  for (int i = len - 1; i >= 0; --i) {
    if (values[i]) {
      return i;
    }
  }
  return 0;
}

static void output_final_stats() {
  printf("===== RESULTS =====\n");
  printf("Fragments translated:\t%lld\n",
         (long long)stats_record->fragments_translated);
  printf("Fragments invalidated:\t%lld\n",
         (long long)stats_record->fragments_invalidated);
  printf("Full resets:\t%lld\n", (long long)stats_record->full_resets);
  printf("Instructions translated:\t%lld\n",
         (long long)stats_record->instructions_translated);

  printf("Fragment instruction count frequencies:");
  int last_index = find_last_index(
      stats_record->fragment_instruction_count_frequencies, 256);
  for (int i = 1; i <= last_index; ++i) {
    printf("\t%lld",
           (long long)stats_record->fragment_instruction_count_frequencies[i]);
  }
  printf("\n");

  printf("Fragment byte count frequencies:");
  last_index =
      find_last_index(stats_record->fragment_byte_count_frequencies, 256);
  for (int i = 1; i <= last_index; ++i) {
    printf("\t%lld",
           (long long)stats_record->fragment_byte_count_frequencies[i]);
  }
  printf("\n");

  printf("Fragment translated byte count frequencies:");
  last_index = find_last_index(
      stats_record->fragment_translated_byte_count_frequencies, 8192);
  for (int i = 1; i <= last_index; ++i) {
    printf(
        "\t%lld",
        (long long)stats_record->fragment_translated_byte_count_frequencies[i]);
  }
  printf("\n");

  printf("Instructions executed:\t%lld\n",
         (long long)stats_record->instructions_executed);
  printf("Ticks:\t%lld\n", (long long)stats_record->ticks);

  printf("Instructions executed using register:\n");
  for (int i = 0; i < 16; ++i) {
    printf("%s\t%lld\n", gp_regs[i],
           (long long)stats_record->instructions_executed_using_reg[i]);
  }
  for (int i = 0; i < 32; ++i) {
    printf("XMM%d\t%lld\n", i,
           (long long)stats_record->instructions_executed_using_reg[i + 16]);
  }
  for (int i = 0; i < 32; ++i) {
    printf("ZMM%d\t%lld\n", i,
           (long long)stats_record->instructions_executed_using_reg[i + 48]);
  }
  printf("... as a dst ...\n");
  for (int i = 0; i <= 7; ++i) {
    printf("K%d\t%lld\n", i,
           (long long)stats_record->instructions_executed_using_reg[i + 80]);
  }
  printf("... as a src ...\n");
  for (int i = 0; i <= 7; ++i) {
    printf("K%d\t%lld\n", i,
           (long long)stats_record->instructions_executed_using_reg[i + 88]);
  }

  printf("Bytes written:\t%lld\n", stats_record->bytes_written_excluding_repeating_string + stats_record->bytes_written_using_repeating_string);
  printf("Bytes written using base register:\n");
  for (int i = 0; i < 16; ++i) {
    printf("%s\t%lld\n", gp_regs[i],
           (long long)stats_record->bytes_written_using_reg[i]);
  }
  printf("RIP:\t%lld\n", stats_record->bytes_written_using_rip);
  printf("Strings:\t%lld\n", stats_record->bytes_written_using_repeating_string);
  printf("AVX-512 masked memory writes:\t%lld\n", (long long)stats_record->avx512_masked_memory_writes);
  printf("AVX-512 gather/scatter instructions:\t%lld\n", (long long)stats_record->avx512_gather_scatter_instructions);

  printf("Fragment execution count distribution:\n");
  last_index = find_last_index(
      stats_record->translated_instruction_execution_count_frequencies, 1000);
  for (int i = 0; i <= last_index; ++i) {
    printf("%lld\t%lld\t%p\n",
           (long long)translated_instruction_execution_count_frequency_max[i],
           (long long)stats_record
               ->translated_instruction_execution_count_frequencies[i],
           stats_record->translated_instruction_execution_count_example[i]);
  }

  printf("Frequencies of the low byte of effective addresses:\n");
  for (int i = 0; i < 256; ++i) {
    printf("%d\t%lld\n",
           i,
           (long long)stats_record->effective_address_low_byte_frequences[i]);
  }

  printf("XINUSE reads: %lld\n", (long long)stats_record->xinuse_reads);
}

class StatisticsTool : public ToolBase {
public:
  enum SpecialType { NORMAL, REPEATING_STRING, XGETBV };
  struct Analysis : public AnalysisBase {
    opnd_t load_operand;
    opnd_t store_operand;
    SpecialType special_type;

    bool has_load_operand;
    bool has_store_operand;
    bool has_variable_opmask;
  };

  void begin_forward_analysis_pass(app_pc start_pc) {
    stats = new FragmentStats();
    stats->pc = start_pc;
    stats->fragment_execution_counter = static_cast<uint64_t*>(
        data_buffer.allocate(sizeof(*stats->fragment_execution_counter)));
    *stats->fragment_execution_counter = 0;
    stats->bytes_written = 0;
    stats->bytes_written_using_rip = 0;
    stats->ends_with_tick = false;
    memset(stats->bytes_written_using_reg, 0,
           sizeof(stats->bytes_written_using_reg));
    memset(stats->instruction_count_using_reg, 0,
           sizeof(stats->instruction_count_using_reg));
    memset(stats->instruction_boundary_bits, 0,
           sizeof(stats->instruction_boundary_bits));
    stats->avx512_masked_memory_writes = 0;
    stats->avx512_gather_scatter_instructions = 0;
    need_to_update_exec_count = true;
    instruction_count = 0;
  }
  void begin_analyzing_instruction(Analysis& analysis) {
    ToolBase::begin_analyzing_instruction(analysis);

    analysis.has_load_operand = false;
    analysis.has_store_operand = false;
    analysis.has_variable_opmask = false;

    int offset = instr_get_raw_bits(analysis.instr) - stats->pc;
    stats->instruction_boundary_bits[offset >> 3] |= 1 << (offset & 7);
    regs_used_by_current_instruction = 0;
    ++instruction_count;

    switch (instr_get_opcode(analysis.instr)) {
      case OP_rep_movs:
      case OP_rep_stos:
      case OP_rep_lods:
      case OP_rep_cmps:
      case OP_repne_cmps:
      case OP_rep_scas:
      case OP_repne_scas: {
        analysis.special_type = REPEATING_STRING;
        break;
      }

      case OP_xgetbv: {
        analysis.special_type = XGETBV;
        break;
      }

      case OP_vpgatherdd:
      case OP_vpgatherdq:
      case OP_vpgatherqd:
      case OP_vpgatherqq:
      case OP_vgatherdps:
      case OP_vgatherdpd:
      case OP_vgatherqps:
      case OP_vgatherqpd:
      case OP_vpscatterdd:
      case OP_vpscatterdq:
      case OP_vpscatterqd:
      case OP_vpscatterqq:
      case OP_vscatterdpd:
      case OP_vscatterdps:
      case OP_vscatterqpd:
      case OP_vscatterqps:
        ++stats->avx512_gather_scatter_instructions;
        RR_FALLTHROUGH;

      default:
        analysis.special_type = NORMAL;
        break;
    }
  }
  void visit_src_operand(const opnd_t& operand, Analysis& analysis) {
    visit_operand(operand, analysis, false);
  }
  void visit_dst_operand(const opnd_t& operand, Analysis& analysis, DataflowAnalysis&) {
    visit_operand(operand, analysis, true);
  }
  void end_analyzing_instruction(Analysis& analysis) {
    if (analysis.has_store_operand && analysis.special_type == NORMAL) {
      uint32_t size = opnd_size_in_bytes(opnd_get_size(analysis.store_operand));
      stats->bytes_written += size;
      // size will be zero for some very rare instructions. Just ignore those.
      if (OPND_IS_BASE_DISP(analysis.store_operand)) {
        reg_id_t base_reg = to_64(opnd_get_base(analysis.store_operand));
        if (base_reg >= DR_REG_RAX && base_reg <= DR_REG_R15) {
          stats->bytes_written_using_reg[base_reg - DR_REG_RAX] += size;
        }
      } else if (OPND_IS_REL_ADDR(analysis.store_operand)) {
        stats->bytes_written_using_rip += size;
      }
      if (analysis.has_variable_opmask) {
        ++stats->avx512_masked_memory_writes;
      }
    }
    if (analysis.is_tick) {
      remix_assert(!stats->ends_with_tick);
      stats->ends_with_tick = true;
    }
  }

  // Codegen pass
  void visit_instruction_before_codegen(Analysis& analysis, Generator& gen,
                                        FragmentAnalysis& fragment_analysis) {
    // x86 instructions can have at most one load operand and one store operand.
    // For instructions with both, the operands are usually the same,
    // but sometimes (e.g. string instructions, `push (mem)`, `pop (mem)`)
    // they aren't.
    if (analysis.has_load_operand) {
      emit_operand_instrumentation(analysis.load_operand, gen);
    }
    if (analysis.has_store_operand) {
      emit_operand_instrumentation(analysis.store_operand, gen);
    }

    switch (analysis.special_type) {
      case REPEATING_STRING: {
        gen.emit().mov(RCX(), IPRel64(&remix_registers.rcx));
        return;
      }

      case XGETBV: {
        // For demo purposes we'll log executions of xgetbv in C++ code.
        // Start by taking all scratch registers since C++ will trash them all.
        gen.take_scratch_registers(
          Generator::dr_regs_to_scratch_mask(DR_REG_R8, DR_REG_R9, DR_REG_R10, DR_REG_R11));
        Assembler::ForwardIPRel<int32_t> label;
        // Store return address in R11.
        gen.emit().lea(label, R11());
        gen.emit().jmp_long(before_xgetbv_stub);
        gen.emit().label(label);
        gen.release_scratch_registers(Generator::dr_regs_to_scratch_mask(
          DR_REG_R8, DR_REG_R9, DR_REG_R10, DR_REG_R11));
        break;
      }

      default:
        break;
    }

    if (fragment_analysis.last_instruction_with_dead_flags >= 0 &&
        analysis.index != fragment_analysis.last_instruction_with_dead_flags) {
      // We'll try to place the INC instruction as late as possible on the
      // theory that it's almost certainly not on any critical path, and we
      // should prioritize critical-path instructions over non-critical-path
      // instructions.
      // We can't have a string instruction here since string instructions always
      // occur alone in a fragment.
      return;
    }

    if (need_to_update_exec_count &&
        !(analysis.arith_flags_live & INC_flags())) {
      gen.emit().inc(IPRel64(stats->fragment_execution_counter));
      need_to_update_exec_count = false;
    }

    if (need_to_update_exec_count &&
        analysis.index == instruction_count - 1) {
      // Couldn't find a place to do it earlier with a single
      // flag-clobbering
      // instruction, so increment counter here without affecting flags.
      // This should be rare.
      gen.take_scratch_register(DR_REG_R11);
      gen.emit().mov(IPRel64(stats->fragment_execution_counter), R11());
      gen.emit().lea(RegMem64(R11()), 1, R11());
      gen.emit().mov(R11(), IPRel64(stats->fragment_execution_counter));
      gen.release_scratch_register(DR_REG_R11);
    }
  }

  void visit_interrupted_instruction_codegen(Analysis& analysis,
                                             Generator& gen) {
    remix_assert(analysis.special_type == REPEATING_STRING);
    count_string_instruction_iterations(analysis, gen);
  }

  void visit_instruction_after_codegen(Analysis& analysis, Generator& gen,
                                       FragmentAnalysis& fragment_analysis,
                                       const DataflowTracker& dataflow_tracker) {
    ToolBase::visit_instruction_after_codegen(analysis, gen,
                                              fragment_analysis, dataflow_tracker);

    if (analysis.special_type == REPEATING_STRING) {
      count_string_instruction_iterations(analysis, gen);
    }
  }

  void did_fragment(uint8_t instruction_bytes, uint16_t translated_length) {
    stats->next = fragment_stats;
    stats->instruction_count = instruction_count;
    stats_record->instructions_translated += instruction_count;
    fragment_stats = stats;

    ++stats_record->fragments_translated;
    ++stats_record->fragment_instruction_count_frequencies[instruction_count];
    ++stats_record->fragment_byte_count_frequencies[instruction_bytes];
    remix_assert(translated_length < 8192);
    ++stats_record
          ->fragment_translated_byte_count_frequencies[translated_length];
  }

private:
  static void emit_load_base_disp_address(const opnd_t& operand,
                                          Generator& gen, reg_id_t reg) {
    reg_id_t base = opnd_get_base(operand);
    reg_id_t index = opnd_get_index(operand);
    gen.emit_load_scratch_registers(Generator::dr_reg_to_scratch_mask(base) |
                                    Generator::dr_reg_to_scratch_mask(index));

    instr_t& tmp_instruction = gen.init_tmp_instruction();
    // XXX Will this work for VSIB etc?
    instr_set_opcode(&tmp_instruction, OP_lea);
    instr_set_num_opnds(GLOBAL_DCONTEXT, &tmp_instruction, 1, 1);
    opnd_t tmp_operand = opnd_create_base_disp(
        base, index, opnd_get_scale(operand),
        opnd_get_disp(operand), OPSZ_lea);
    instr_set_src(&tmp_instruction, 0, tmp_operand);
    instr_set_dst(&tmp_instruction, 0,
                  opnd_create_reg(match_reg_size(reg, base)));
    gen.emit().instruction(tmp_instruction);
  }

  static void generate_effective_address(
      const opnd_t& operand, Generator& gen, reg_id_t out_addr_reg) {
    if (OPND_IS_BASE_DISP(operand)) {
      reg_id_t addr_reg =
          Generator::find_first_scratch_reg(
              Generator::ALL_SCRATCH_REGS,
              Generator::ALL_SCRATCH_REGS ^
                  Generator::dr_reg_to_scratch_mask(out_addr_reg))
              .id();
      gen.emit_spill_scratch_register(addr_reg);
      emit_load_base_disp_address(operand, gen, addr_reg);
      if (out_addr_reg != addr_reg) {
        gen.emit_spill_scratch_register(out_addr_reg);
        gen.emit().mov(Reg64::from_dr(addr_reg), Reg64::from_dr(out_addr_reg));
      }
    } else {
      uintptr_t addr = uintptr_t(opnd_get_addr(operand));
      gen.emit_spill_scratch_register(out_addr_reg);
      gen.emit().mov(addr, Reg64::from_dr(out_addr_reg));
    }
    gen.take_scratch_register(out_addr_reg);

    void* seg_base;
    switch (opnd_get_segment(operand)) {
      // Seems that by default DR just returns DR_REG_NULL
      case DR_REG_NULL:
      case DR_SEG_CS:
      case DR_SEG_DS:
      case DR_SEG_ES:
      case DR_SEG_SS:
        // On Linux these are all the same
        return;
      case DR_SEG_FS:
        seg_base = &remix_registers.fs_base;
        break;
      case DR_SEG_GS:
        seg_base = &remix_registers.gs_base;
        break;
      default:
        remix_abort("Unsupported segment %d",
                    opnd_get_segment(operand));
        return;
    }

    reg_id_t seg_base_reg =
        Generator::find_first_scratch_reg(
            Generator::ALL_SCRATCH_REGS ^
                Generator::dr_reg_to_scratch_mask(out_addr_reg),
            gen.scratch_regs_in_use())
            .id();
    // Experiments suggest that when the segment base is added to a 32-bit
    // effective address, the effective address is treated as unsigned. So
    // that's what we do.
    gen.take_scratch_register(seg_base_reg);
    gen.emit().mov(IPRel64(seg_base), Reg64::from_dr(seg_base_reg));
    gen.emit().lea(RegMem64(Reg64::from_dr(out_addr_reg)),
                   Reg64::from_dr(seg_base_reg), Reg64::from_dr(out_addr_reg));
    gen.release_scratch_register(seg_base_reg);
  }

  void emit_operand_instrumentation(const opnd_t& operand, Generator& gen) {
    if (OPND_IS_BASE_DISP(operand)) {
      reg_id_t index = opnd_get_index(operand);
      if (index == DR_REG_NULL || !reg_is_gpr(index)) {
        // Ignore VSIB operands to VPGATHER ... these are weird
        return;
      }
    }
    generate_effective_address(operand, gen, DR_REG_R8);
    gen.take_scratch_registers(
      Generator::dr_regs_to_scratch_mask(DR_REG_R9, DR_REG_R10, DR_REG_R11));
    Assembler::ForwardIPRel<int32_t> label;
    // Store return address in R11.
    gen.emit().lea(label, R11());
    gen.emit().jmp_long(mem_operand_stub);
    gen.emit().label(label);
    gen.release_scratch_registers(Generator::dr_regs_to_scratch_mask(
      DR_REG_R8, DR_REG_R9, DR_REG_R10, DR_REG_R11));
  }

  void count_string_instruction_iterations(Analysis& analysis, Generator& gen) {
    opnd_t cx =
        instr_get_dst(analysis.instr, instr_num_dsts(analysis.instr) - 1);
    remix_assert(OPND_IS_REG(cx));
    reg_id_t cx_reg = OPND_GET_REG(cx);
    remix_assert(cx_reg == DR_REG_RCX || cx_reg == DR_REG_ECX);

    gen.emit_save_flags(DR_REG_R10);
    gen.emit().mov(IPRel64(&remix_registers.rcx), R11());
    if (cx_reg == DR_REG_RCX) {
      gen.emit().sub(RCX(), R11());
    } else {
      Assembler::ForwardIPRel<int8_t> nonzero;
      gen.emit().sub(ECX(), R11D());
      gen.emit().jcc(DR_PRED_NB, nonzero);
      gen.emit().mov(0x100000000, R9());
      gen.emit().add(R9(), R11());
      gen.emit().label(nonzero);
    }
    if (count_string_instruction_repetitions) {
      gen.emit().add(R11(), IPRel64(stats->fragment_execution_counter));
    } else {
      gen.emit().inc(IPRel64(stats->fragment_execution_counter));
    }
    if (analysis.has_store_operand) {
      switch (opnd_get_size(analysis.store_operand)) {
        case OPSZ_2:
          gen.emit().shl(1, R11());
          break;
        case OPSZ_4:
          gen.emit().shl(2, R11());
          break;
        case OPSZ_8:
          gen.emit().shl(3, R11());
          break;
      }
      gen.emit().mov((uint64_t)&stats_record->bytes_written_using_repeating_string, R9());
      gen.emit().add(R11(), RegMem64(R9()));
    }
    gen.emit_restore_flags(DR_REG_R10);
  }

  void visit_operand(const opnd_t& operand, Analysis& analysis, bool dst) {
    auto has_mem_operand = dst ? &Analysis::has_store_operand : &Analysis::has_load_operand;
    auto mem_operand = dst ? &Analysis::store_operand : &Analysis::load_operand;

    if (OPND_IS_REG(operand)) {
      visit_operand_reg(opnd_get_reg(operand), analysis, dst);
    } else if (OPND_IS_BASE_DISP(operand)) {
      visit_operand_reg(opnd_get_base(operand), analysis, dst);
      visit_operand_reg(opnd_get_index(operand), analysis, dst);
      (analysis.*has_mem_operand) = true;
      (analysis.*mem_operand) = operand;
    } else if (OPND_IS_REL_ADDR(operand) || opnd_is_abs_addr(operand)) {
      (analysis.*has_mem_operand) = true;
      (analysis.*mem_operand) = operand;
    }
  }
  void visit_operand_reg(reg_id_t reg, Analysis& analysis, bool dst) {
    int index;
    if (reg >= DR_REG_RAX && reg <= DR_REG_R15) {
      index = reg - DR_REG_RAX;
    } else if (reg >= DR_REG_EAX && reg <= DR_REG_R15D) {
      index = reg - DR_REG_EAX;
    } else if (reg >= DR_REG_AX && reg <= DR_REG_R15W) {
      index = reg - DR_REG_AX;
    } else if (reg >= DR_REG_AH && reg <= DR_REG_BH) {
      index = reg - DR_REG_AH;
    } else if (reg >= DR_REG_AL && reg <= DR_REG_BL) {
      index = reg - DR_REG_AL;
    } else if (reg >= DR_REG_R8L && reg <= DR_REG_R15L) {
      index = reg - DR_REG_R8L + 8;
    } else if (reg >= DR_REG_SPL && reg <= DR_REG_DIL) {
      index = reg - DR_REG_SPL + 4;
    } else if (reg >= DR_REG_XMM0 && reg <= DR_REG_XMM31) {
      index = reg - DR_REG_XMM0 + 16;
    } else if (reg >= DR_REG_YMM0 && reg <= DR_REG_YMM31) {
      index = reg - DR_REG_YMM0 + 16;
    } else if (reg >= DR_REG_START_ZMM && reg <= DR_REG_STOP_ZMM) {
      index = reg - DR_REG_START_ZMM + 48;
    } else if (reg >= DR_REG_K0 && reg <= DR_REG_K7) {
      if (dst) {
        index = reg - DR_REG_K0 + 80;
      } else {
        if (!instr_is_opmask(analysis.instr)) {
          // We only care about K0 if it's used in an opmask instruction.
          // K0 as a mask operand to an instruction is not interesting.
          if (reg == DR_REG_K0) {
            return;
          }
          // If this is a mask operand (i.e. this is not an opmask instruction)
          // note that we have a non-K0 mask. We'll need that to count masked
          // memory writes.
          analysis.has_variable_opmask = true;
        }
        index = reg - DR_REG_K0 + 88;
      }
    } else {
      return;
    }
    __uint128_t mask = (__uint128_t)1 << index;
    if (!(regs_used_by_current_instruction & mask)) {
      regs_used_by_current_instruction |= mask;
      ++stats->instruction_count_using_reg[index];
    }
  }

  FragmentStats* stats;
  __uint128_t regs_used_by_current_instruction;
  int instruction_count;
  bool need_to_update_exec_count;
};

class StatisticsToolHooks : public ToolHooksImpl<StatisticsTool> {
public:
  virtual void did_fork_child(pid_t, uint32_t, TraceFrameTime) override {
    // Our current stats will be recorded by the parent, so clear them out now
    // so they don't get double-recorded.
    for (FragmentStats* f = fragment_stats; f; f = f->next) {
      *f->fragment_execution_counter = 0;
    }
  }
  virtual void notify_will_full_reset() override {
    ++stats_record->full_resets;
    write_back_process_stats();
  }
  virtual void did_invalidate() override {
    ++stats_record->fragments_invalidated;
  }
  virtual void notify_will_exec(TraceFrameTime) override {
    write_back_process_stats();
  }
  virtual void notify_will_exit(pid_t, uint32_t, TraceFrameTime,
                                uint32_t flags) override {
    if (flags & (REMIX_EXIT_LAST_THREAD | REMIX_EXIT_SYNTHETIC)) {
      write_back_process_stats();
      if (flags & (REMIX_EXIT_LAST_PROCESS | REMIX_EXIT_SYNTHETIC)) {
        output_final_stats();
      }
    }
  }
};

ToolHooks* tool_init(intptr_t* init_cookie) {
  init_bucket_sizes();

  int fd;
  if (*init_cookie == -1) {
    fd = syscall(SYS_memfd_create, "statistics_record", 0);
    if (fd < 0) {
      remix_abort("memfd_create failed, errno=%d", errno);
    }
    *init_cookie = fd;
    int ret = ftruncate(fd, sizeof(StatsRecord));
    if (ret < 0) {
      remix_abort("ftruncate failed");
    }
  } else {
    fd = *init_cookie;
  }

  stats_record = static_cast<StatsRecord*>(mmap(
      nullptr, sizeof(StatsRecord), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0));
  if (stats_record == MAP_FAILED) {
    remix_abort("mmap failed");
  }

  return new StatisticsToolHooks();
}

REMIX_TARGET_END
