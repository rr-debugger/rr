/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_DATAFLOWANALYSIS_H_
#define RR_DATAFLOWANALYSIS_H_

#include <stdint.h>

#include "engine.h"
#include "generator_utils.h"
#include "Vector.h"

const uint8_t REG_ZERO = 0xff;

// Set to indicate that the output value must be
// truncated to 32 bits (high 32 bits set to zero).
const uint8_t CANONICAL_VALUE_32BITS = 0x01;

const int NUM_GPRS = 16;

// Don't add more memory facts than this. This could go
// up to 255 but we'll cap it at 16 to avoid slow instrumentation
// for pathological fragments. Normally we won't find this many
// definitely-not-aliased memory writes at once.
const int MAX_MEMORY_VALUES = 16;

typedef uint8_t GprIndex;

/**
 * Represents a "canonical" value that we can use to track simple
 * relationships between registers.
 * The value is equal to the value of `base_reg` (which must be 64-bit),
 * at the *start of* the instruction `defined_at_instruction` within the
 * fragment, plus `offset`.
 * If `base_reg` is REG_ZERO then the value is just `offset`.
 * If CANONICAL_VALUE_32BITS is set in `flags` then the result after adding
 * `offset` then has the high 32 bits zeroed.
 */
struct CanonicalValue {
  CanonicalValue() = default;
  CanonicalValue(const CanonicalValue& other) = default;
  CanonicalValue(GprIndex base_reg, uint16_t defined_at_instruction, uint8_t flags, uint64_t offset)
    : offset(offset)
    , defined_at_instruction(defined_at_instruction)
    , base_reg(base_reg)
    , flags(flags) {
  }
  bool operator==(const CanonicalValue& other) const {
    return base_reg == other.base_reg &&
        defined_at_instruction == other.defined_at_instruction &&
        flags == other.flags &&
        offset == other.offset;
  }
  bool operator!=(const CanonicalValue& other) const {
    return !(*this == other);
  }
  bool equal_except_offset(const CanonicalValue& other) const {
    return base_reg == other.base_reg && flags == other.flags &&
           defined_at_instruction == other.defined_at_instruction;
  }
  bool is_constant(uint64_t* out) const {
    if (base_reg != REG_ZERO) {
      return false;
    }
    if (flags & CANONICAL_VALUE_32BITS) {
      *out = (uint32_t)offset;
    } else {
      *out = offset;
    }
    return true;
  }

  uint64_t offset;
  uint16_t defined_at_instruction; // Always zero for REG_ZERO
  GprIndex base_reg; // 0..16 or REG_ZERO
  uint8_t flags;
};

/**
 * The `size` bytes at address 'address' have the value `value'.
 * We remember a set of these facts as we process a fragment.
 */
struct MemoryValue {
  CanonicalValue address;
  CanonicalValue value;
  // Length in bytes. Uses low bits of `value`.
  uint8_t size;
};

typedef uint16_t CanonicalValueUpdateIndex;

/**
 * Indicates that at the start of `instruction_index` the value
 * of `gpr` changes to `value`.
 */
struct CanonicalValueUpdate {
  CanonicalValueUpdate(GprIndex reg, uint16_t instruction_index, CanonicalValue value)
    : value(value)
    , reg(reg)
    , instruction_index(instruction_index) {
  }
  CanonicalValue value;
  GprIndex reg;
  uint16_t instruction_index;
};

/**
 * Tracks dataflow through registers and memory. Mantains a CanonicalValue for each GPR
 * and also a set of MemoryValues describing what we know about the contents of memory.
 *
 * The dataflow analysis runs during the first forward pass through the fragment.
 * CanonicalValues for each register at the start and end of each instruction are
 * available once the analysis has finished.
 *
 * These values can be used by tools to optimize their instrumentation. They can
 * also be used by the code generation pass to optimize the generated code.
 */
struct DataflowAnalysis {
  static const int NUM_GPRS = 16;

  Vector<CanonicalValueUpdate> canonical_value_updates;
  // Bits corresponding to operand indices that we have set values for
  uint8_t preserve_dest_operands;
  // Number of valid elements in `memory`
  uint8_t num_memory_values;
  uint16_t current_instruction_index;
  CanonicalValueUpdateIndex processed_updates;
  CanonicalValueUpdateIndex gpr_values[NUM_GPRS];
  // This keeps track of what we know about values in memory.
  MemoryValue memory[MAX_MEMORY_VALUES];

  DataflowAnalysis() {
    for (GprIndex i = 0; i < NUM_GPRS; ++i) {
      CanonicalValue v(i, 0, 0, 0);
      canonical_value_updates.push_back(CanonicalValueUpdate(i, 0, v));
    }
  }

  void begin_forward_analysis_pass() {
    num_memory_values = 0;
    current_instruction_index = 0;
    processed_updates = NUM_GPRS;
    for (GprIndex i = 0; i < NUM_GPRS; ++i) {
      gpr_values[i] = i;
    }
    while (canonical_value_updates.size() > NUM_GPRS) {
      canonical_value_updates.pop_back();
    }
  }
  void begin_analyzing_instruction() {
    preserve_dest_operands = 0;
  }

  // OP_push, OP_push_imm
  void visit_push(instr_t* instruction) {
    if (opnd_get_size(instr_get_src(instruction, 0)) == OPSZ_8) {
      set_dst_reg(0, DR_REG_RSP, DR_REG_RSP, -8);
    }
    // XXX we could set a MemoryValue here but it probably isn't that
    // helpful. That value would probably not be loaded by a load
    // instruction, but only by a matching pop instruction, and the
    // pushed register has probably been overwritten without being
    // available elsewhere, so we can't avoid the reload.
  }
  // OP_pop
  void visit_pop(instr_t* instruction) {
    if (opnd_get_size(instr_get_src(instruction, 1)) == OPSZ_8) {
      set_dst_reg(1, DR_REG_RSP, DR_REG_RSP, 8);
      // Force %rsp's canonical value to be updated immediately,
      // so that an %rsp-relative memory destination will be
      // canonicalized accordingly (those are relative to the
      // modified %rsp).
      gpr_values[DR_REG_RSP - DR_REG_RAX] = processed_updates;
    }
    // XXX we could look for a MemoryValue here but it isn't that
    // helpful. See above.
  }
  // OP_add, OP_sub
  void visit_add_sub(instr_t* instruction) {
    opnd_t operand1 = instr_get_src(instruction, 0);
    if (OPND_IS_IMMED_INT(operand1)) {
      int64_t immediate = opnd_get_immed_int(operand1);
      if (instr_get_opcode(instruction) == OP_sub) {
        immediate = -immediate;
      }
      set_dst(instruction, 0, 1, immediate);
    }
    // XXX we could update a MemoryValue here but it probably isn't
    // that helpful.
  }
  // OP_lea
  void visit_lea(instr_t* instruction) {
    opnd_t src_operand = instr_get_src(instruction, 0);
    if (OPND_IS_BASE_DISP(src_operand) && opnd_get_index(src_operand) == DR_REG_NULL) {
      opnd_t dst_operand = instr_get_dst(instruction, 0);
      remix_assert(OPND_IS_REG(dst_operand));
      set_dst_reg(0, opnd_get_reg(dst_operand),
                  opnd_get_base(src_operand), opnd_get_disp(src_operand));
    }
    // XXX we could generate a constant value for RIP-relative LEAs
  }
  // OP_mov_ld, OP_mov_st, OP_mov_imm
  void visit_mov(instr_t* instruction) {
    opnd_t src_operand = instr_get_src(instruction, 0);
    opnd_t dst_operand = instr_get_dst(instruction, 0);
    if (OPND_IS_REG(dst_operand)) {
      reg_id_t dst_reg = opnd_get_reg(dst_operand);
      if (dst_reg < DR_REG_RAX || dst_reg > DR_REG_R15D) {
        // No special handling
        return;
      }
      GprIndex dst_reg_index = to_64(dst_reg) - DR_REG_RAX;
      bool is_64 = dst_reg <= DR_REG_R15;

      if (OPND_IS_REG(src_operand)) {
        // Register->register move
        reg_id_t src_reg = opnd_get_reg(src_operand);
        CanonicalValue v;
        if (get_canonical_value_for_reg(src_reg, &v)) {
          preserve_dest_operands |= 1;
          push_update(dst_reg_index, v);
        }
        return;
      }

      if (OPND_IS_IMMED_INT(src_operand)) {
        // Immediate->register move
        CanonicalValue v;
        if (get_canonical_value_for_operand(src_operand, &v, is_64)) {
          preserve_dest_operands |= 1;
          push_update(dst_reg_index, v);
        }
        return;
      }

      // Memory->register move
      CanonicalValue addr;
      uint32_t size;
      if (get_canonical_value_and_size_for_mem_address(src_operand, &addr, &size)) {
        for (int i = 0; i < num_memory_values; ++i) {
          // XXX we could handle partial reads in some cases, but it's easier not to
          // and not known to be useful.
          if (memory[i].address == addr && memory[i].size == size) {
            preserve_dest_operands |= 1;
            CanonicalValue v = memory[i].value;
            if (!is_64) {
              v.flags |= CANONICAL_VALUE_32BITS;
            }
            push_update(dst_reg_index, v);
            return;
          }
        }
        // OK we don't know what's in that memory location so can't optimize the instruction. We can however
        // update the memory value based on what we've loaded, so if it gets loaded again,
        // we might be able to reuse the value in an existing register.
        if (num_memory_values < MAX_MEMORY_VALUES) {
          memory[num_memory_values].address = addr;
          memory[num_memory_values].value = CanonicalValue(dst_reg_index, current_instruction_index + 1, 0, 0);
          memory[num_memory_values].size = size;
          ++num_memory_values;
        }
      }
      return;
    }

    // Store to memory. Invalidate may-aliased memory values and
    // possibly write a new one to record what we stored.
    preserve_dest_operands |= 1;
    CanonicalValue addr;
    uint32_t size;
    // DO NOT optimize stores to locations that we know already have the right
    // value! That could break semantics for tools that depend on knowing exactly when
    // memory locations are written, even if written idempotently.
    if (get_canonical_value_and_size_for_mem_address(dst_operand, &addr, &size)) {
      invalidate_may_alias_canonical_value_address(addr, size);
      if ((size == 8 || size == 4) && num_memory_values < MAX_MEMORY_VALUES) {
        CanonicalValue v;
        if (get_canonical_value_for_operand(src_operand, &v, size == 8)) {
          memory[num_memory_values].address = addr;
          memory[num_memory_values].value = v;
          memory[num_memory_values].size = size;
          ++num_memory_values;
        }
      }
    } else {
      // Forget everything
      num_memory_values = 0;
    }
  }

  void visit_dst_operand(int instr_index, int operand_index, opnd_t operand) {
    if (preserve_dest_operands & (1 << operand_index)) {
      return;
    }
    if (OPND_IS_REG(operand)) {
      // Unknown value.
      reg_id_t reg = opnd_get_reg(operand);
      GprIndex r = to_64(reg) - DR_REG_RAX;
      push_update(r, CanonicalValue(r, instr_index + 1, 0, 0));
      return;
    }
    invalidate_may_alias_values(operand);
  }

  void end_analyzing_instruction() {
    ++current_instruction_index;
    while (processed_updates < canonical_value_updates.size()) {
      CanonicalValueUpdate& u = canonical_value_updates[processed_updates];
      gpr_values[u.reg] = processed_updates;
      ++processed_updates;
    }
  }

  const CanonicalValue& gpr_value(GprIndex reg) {
    return canonical_value_updates[gpr_values[reg]].value;
  }

  bool get_canonical_value_for_mem_address(opnd_t operand, CanonicalValue* out) {
    if (is_special_segment(operand)) {
      return false;
    }
    if (OPND_IS_BASE_DISP(operand)) {
      if (opnd_get_index(operand) == DR_REG_NULL) {
        reg_id_t base_reg = opnd_get_base(operand);
        if (base_reg == DR_REG_NULL) {
          *out = CanonicalValue(REG_ZERO, 0, 0, 0);
        } else {
          bool ok = get_canonical_value_for_reg(base_reg, out);
          remix_assert(ok);
        }
        out->offset += (int64_t)opnd_get_disp(operand);
        return true;
      }
    } else if (OPND_IS_REL_ADDR(operand) || opnd_is_abs_addr(operand)) {
      *out = CanonicalValue(REG_ZERO, 0, 0, (uint64_t)opnd_get_addr(operand));
      return true;
    }
    return false;
  }
  bool get_canonical_value_and_size_for_mem_address(opnd_t operand, CanonicalValue* out, uint32_t* size_out) {
    if (!get_canonical_value_for_mem_address(operand, out)) {
      return false;
    }
    *size_out = opnd_size_in_bytes(opnd_get_size(operand));
    return *size_out > 0;
  }

private:
  void push_update(GprIndex reg, CanonicalValue v) {
    CanonicalValueUpdate u(reg, current_instruction_index + 1, v);
    canonical_value_updates.push_back(u);
  }
  // `dest` register has been set to input `src` register plus some offset.
  // We ignore this if dest and src aren't 64-bit.
  bool get_canonical_value_for_reg(reg_id_t reg, CanonicalValue* out) {
    if (reg >= DR_REG_RAX && reg <= DR_REG_R15) {
      *out = gpr_value(reg - DR_REG_RAX);
      return true;
    }
    if (reg >= DR_REG_EAX && reg <= DR_REG_R15D) {
      *out = gpr_value(reg - DR_REG_EAX);
      out->flags |= CANONICAL_VALUE_32BITS;
      return true;
    }
    return false;
  }
  bool get_canonical_value_for_operand(opnd_t operand, CanonicalValue* out, bool is_64) {
    if (OPND_IS_REG(operand)) {
      return get_canonical_value_for_reg(opnd_get_reg(operand), out);
    }
    if (OPND_IS_IMMED_INT(operand)) {
      int64_t immediate = opnd_is_immed_int64(operand) ?
        opnd_get_immed_int64(operand) : opnd_get_immed_int(operand);
      *out = CanonicalValue(REG_ZERO, 0, 0, is_64 ? (int64_t)immediate : (uint32_t)immediate);
      return true;
    }
    return false;
  }
  void set_dst_reg(int dest_operand_index, reg_id_t dest, reg_id_t src, int64_t offset) {
    CanonicalValue v;
    if (dest >= DR_REG_RAX && dest <= DR_REG_R15D &&
        get_canonical_value_for_reg(src, &v)) {
      if (offset && (v.flags & CANONICAL_VALUE_32BITS) && src <= DR_REG_R15) {
        // The expression works out to ((uint32_t)reg_base + offset) which we
        // can't represent.
        return;
      }
      preserve_dest_operands |= 1 << dest_operand_index;
      v.offset += offset;
      if (dest >= DR_REG_EAX) {
        v.flags |= CANONICAL_VALUE_32BITS;
      }
      push_update(to_64(dest) - DR_REG_RAX, v);
    }
  }
  void set_dst(instr_t* instruction, int dest_operand_index, int src_operand_index, int64_t offset) {
    opnd_t dest_operand = instr_get_dst(instruction, dest_operand_index);
    if (OPND_IS_REG(dest_operand)) {
      opnd_t src_operand = instr_get_src(instruction, src_operand_index);
      if (OPND_IS_REG(src_operand)) {
        set_dst_reg(dest_operand_index, opnd_get_reg(dest_operand), opnd_get_reg(src_operand), offset);
      }
    }
  }
  bool is_special_segment(opnd_t operand) {
    switch (opnd_get_segment(operand)) {
      case DR_SEG_FS:
      case DR_SEG_GS:
        return true;
      default:
        return false;
    }
  }
  static bool range_overlap(uint64_t p1, uint32_t size1, uint64_t p2, uint32_t size2, uint8_t flags) {
    if (!(flags & CANONICAL_VALUE_32BITS)) {
      return p2 - p1 < size1 || p1 - p2 < size2;
    }
    return (uint32_t)p2 - (uint32_t)p1 < size1 || (uint32_t)p1 - (uint32_t)p2 < size2;
  }
  void invalidate_may_alias_values(opnd_t operand) {
    CanonicalValue addr;
    uint32_t size;
    if (get_canonical_value_and_size_for_mem_address(operand, &addr, &size)) {
      invalidate_may_alias_canonical_value_address(addr, size);
    } else if (!OPND_IS_REG(operand)) {
      // Forget everything
      num_memory_values = 0;
    }
  }
  void invalidate_may_alias_canonical_value_address(CanonicalValue addr, uint32_t size) {
    uint8_t out_index = 0;
    for (uint8_t i = 0; i < num_memory_values; ++i) {
      const MemoryValue& mem = memory[i];
      if (mem.address.equal_except_offset(addr) &&
          !range_overlap(mem.address.offset, mem.size, addr.offset, size, addr.flags)) {
        memory[out_index] = mem;
        ++out_index;
      }
    }
    num_memory_values = out_index;
  }
};

struct DataflowTracker {
  DataflowTracker(DataflowAnalysis& analysis)
    : updates(analysis.canonical_value_updates)
    , processed_updates(0) {
    process_up_to(0);
  }
  DataflowTracker(const DataflowTracker& other) = default;
  void process_up_to(uint16_t instruction_index) {
    CanonicalValueUpdateIndex size = updates.size();
    while (processed_updates < size) {
      CanonicalValueUpdate& u = updates[processed_updates];
      if (u.instruction_index > instruction_index) {
        break;
      }
      gpr_values[u.reg] = processed_updates;
      ++processed_updates;
    }
  }
  const CanonicalValue& gpr_value(GprIndex reg) const {
    return updates[gpr_values[reg]].value;
  }
  const CanonicalValue& gpr_value_at(GprIndex reg, uint16_t instruction_index) const {
    CanonicalValueUpdateIndex size = updates.size();
    CanonicalValueUpdateIndex current = processed_updates;
    CanonicalValueUpdateIndex ret = gpr_values[reg];
    while (current < size) {
      CanonicalValueUpdate& u = updates[current];
      if (u.instruction_index > instruction_index) {
        break;
      }
      if (u.reg == reg) {
        ret = current;
      }
      ++current;
    }
    return updates[ret].value;
  }

private:
  Vector<CanonicalValueUpdate>& updates;
  CanonicalValueUpdateIndex processed_updates;
  CanonicalValueUpdateIndex gpr_values[NUM_GPRS];
};

#endif /* RR_DATAFLOWANALYSIS_H_ */
