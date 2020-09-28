/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "fast_forward.h"

#include "core.h"
#include "log.h"

using namespace std;

namespace rr {

struct InstructionBuf {
  SupportedArch arch;
  uint8_t code_buf[32];
  int code_buf_len;
};

static InstructionBuf read_instruction(Task* t, remote_code_ptr ip) {
  InstructionBuf result;
  result.arch = t->arch();
  result.code_buf_len = (int)t->read_bytes_fallible(
      ip.to_data_ptr<uint8_t>(), sizeof(result.code_buf), result.code_buf);
  return result;
}

struct DecodedInstruction {
  int operand_size;
  int address_size;
  int length;
  bool modifies_flags;
  bool uses_si;
  bool is_repne;
};

/**
 * This can be conservative: for weird prefix combinations that make valid
 * string instructions, but aren't ever used in practice, we can return false.
 */
static bool decode_x86_string_instruction(const InstructionBuf& code,
                                          DecodedInstruction* decoded) {
  bool found_operand_prefix = false;
  bool found_address_prefix = false;
  bool found_REP_prefix = false;
  bool found_REXW_prefix = false;

  decoded->modifies_flags = false;
  decoded->uses_si = false;
  decoded->is_repne = false;

  int i;
  bool done = false;
  for (i = 0; i < code.code_buf_len; ++i) {
    switch (code.code_buf[i]) {
      case 0x66:
        found_operand_prefix = true;
        break;
      case 0x67:
        found_address_prefix = true;
        break;
      case 0x48:
        if (code.arch == x86_64) {
          found_REXW_prefix = true;
          break;
        }
        return false;
      case 0xF2:
        decoded->is_repne = true;
        RR_FALLTHROUGH;
      case 0xF3:
        found_REP_prefix = true;
        break;
      case 0xA4: // MOVSB
      case 0xA5: // MOVSW
        decoded->uses_si = true;
        done = true;
        break;
      case 0xAA: // STOSB
      case 0xAB: // STOSW
      case 0xAC: // LODSB
      case 0xAD: // LODSW
        done = true;
        break;
      case 0xA6: // CMPSB
      case 0xA7: // CMPSW
        decoded->modifies_flags = true;
        decoded->uses_si = true;
        done = true;
        break;
      case 0xAE: // SCASB
      case 0xAF: // SCASW
        decoded->modifies_flags = true;
        done = true;
        break;
      default:
        return false;
    }
    if (done) {
      break;
    }
  }

  if (!found_REP_prefix) {
    return false;
  }

  decoded->length = i + 1;
  if (code.code_buf[i] & 1) {
    decoded->operand_size =
        found_REXW_prefix ? 8 : (found_operand_prefix ? 2 : 4);
  } else {
    decoded->operand_size = 1;
  }
  decoded->address_size = found_address_prefix ? 4 : 8;
  return true;
}

static bool mem_intersect(remote_ptr<void> a1, int s1, remote_ptr<void> a2,
                          int s2) {
  DEBUG_ASSERT(a1 + s1 > a1);
  DEBUG_ASSERT(a2 + s2 > a2);
  return max(a1, a2) < min(a1 + s1, a2 + s2);
}

static void bound_iterations_for_watchpoint(Task* t, remote_ptr<void> reg,
                                            const DecodedInstruction& decoded,
                                            const WatchConfig& watch,
                                            uintptr_t* iterations) {
  if (watch.num_bytes == 0) {
    // Ignore zero-sized watch. It can't ever trigger.
    return;
  }

  // Compute how many iterations it will take before we hit the watchpoint.
  // 0 means the first iteration will hit the watchpoint.
  int size = decoded.operand_size;
  int direction = t->regs().df_flag() ? -1 : 1;

  if (mem_intersect(reg, size, watch.addr, watch.num_bytes)) {
    *iterations = 0;
    return;
  }

  // Number of iterations we can perform without triggering the watchpoint
  uintptr_t steps;
  if (direction > 0) {
    if (watch.addr < reg) {
      // We're assuming wraparound can't happpen!
      return;
    }
    // We'll hit the first byte of the watchpoint moving forward.
    steps = (watch.addr - reg) / size;
  } else {
    if (watch.addr > reg) {
      // We're assuming wraparound can't happpen!
      return;
    }
    // We'll hit the last byte of the watchpoint moving backward.
    steps = (reg - (watch.addr + watch.num_bytes)) / size + 1;
  }

  *iterations = min(*iterations, steps);
}

FastForwardStatus fast_forward_through_instruction(Task* t, ResumeRequest how,
                                                   const vector<const Registers*>& states) {
  DEBUG_ASSERT(how == RESUME_SINGLESTEP || how == RESUME_SYSEMU_SINGLESTEP);
  FastForwardStatus result;

  remote_code_ptr ip = t->ip();

  t->resume_execution(how, RESUME_WAIT, RESUME_UNLIMITED_TICKS);
  if (t->stop_sig() != SIGTRAP) {
    // we might have stepped into a system call...
    return result;
  }

  if (t->ip() != ip) {
    return result;
  }
  if (t->vm()->get_breakpoint_type_at_addr(ip) != BKPT_NONE) {
    // breakpoint must have fired
    return result;
  }
  if (t->compute_trap_reasons().watchpoint) { 
    // watchpoint fired
    return result;
  }
  for (auto& state : states) {
    if (state->matches(t->regs())) {
      return result;
    }
  }
  if (!is_x86ish(t->arch())) {
    return result;
  }

  InstructionBuf instruction_buf = read_instruction(t, ip);
  DecodedInstruction decoded;
  if (!decode_x86_string_instruction(instruction_buf, &decoded)) {
    return result;
  }
  if (decoded.address_size != 8) {
    ASSERT(t, false) << "Address-size prefix on string instructions unsupported";
  }

  remote_code_ptr limit_ip = ip + decoded.length;

  // At this point we can be sure the instruction didn't trigger a syscall,
  // so we no longer care about the value of |how|.

  Registers extra_state_to_avoid;
  vector<const Registers*> states_copy;
  auto using_states = &states;

  while (true) {
    // This string instruction should execute until CX reaches 0 and
    // we move to the next instruction, or we hit one of the states in
    // |states|, or the ZF flag changes so that the REP stops, or we hit
    // a watchpoint. (We can't hit a breakpoint during the loop since we
    // already verified there isn't one set here.)

    // We'll compute an upper bound on the number of string instruction
    // iterations to execute, and execute just that many iterations by
    // modifying CX, setting a breakpoint after the string instruction to catch it
    // ending.
    // Keep in mind that it's possible that states in |states| might
    // belong to multiple independent loops of this string instruction, with
    // registers reset in between the loops.

    uintptr_t cur_cx = t->regs().cx();
    if (cur_cx == 0) {
      // Fake singlestep status for trap diagnosis
      t->set_x86_debug_status(DS_SINGLESTEP);
      // This instruction will be skipped entirely.
      return result;
    }
    // There is at least one more iteration to go.
    result.incomplete_fast_forward = true;

    // Don't execute the last iteration of the string instruction. That
    // simplifies code below that tries to emulate the register effects
    // of singlestepping to predict if the next singlestep would result in a
    // mark_vector state.
    uintptr_t iterations = cur_cx - 1;

    // Bound |iterations| to ensure we stop before reaching any |states|.
    for (auto& state : *using_states) {
      if (state->ip() == ip) {
        uintptr_t dest_cx = state->cx();
        if (dest_cx == 0) {
          // This state represents entering the string instruction with CX==0,
          // so we can't reach this state in the current loop.
          continue;
        }
        if (dest_cx >= cur_cx) {
          // This can't be reached in the current loop.
          continue;
        }
        iterations = min(iterations, cur_cx - dest_cx - 1);
      } else if (state->ip() == limit_ip) {
        uintptr_t dest_cx = state->cx();
        if (dest_cx >= cur_cx) {
          // This can't be reached in the current loop.
          continue;
        }
        iterations = min(iterations, cur_cx - dest_cx - 1);
      }
    }

    // To stop before the ZF changes and we exit the loop, we don't bound
    // the iterations here. Instead we run the loop, observe the ZF change,
    // and then rerun the loop with the loop-exit state added to the |states|
    // list. See below.

    // A code watchpoint would already be hit if we're going to hit it.
    // Check for data watchpoints that we might hit when reading/writing
    // memory.
    // Make conservative assumptions about the watchpoint type. Applying
    // unnecessary watchpoints here will only result in a few more singlesteps.
    // We do have to ignore SI if the instruction doesn't use it; otherwise
    // a watchpoint which happens to match SI will appear to be hit on every
    // iteration of the string instruction, which would be devastating.
    for (auto& watch : t->vm()->all_watchpoints()) {
      if (decoded.uses_si) {
        bound_iterations_for_watchpoint(t, t->regs().si(), decoded, watch,
                                        &iterations);
      }
      bound_iterations_for_watchpoint(t, t->regs().di(), decoded, watch,
                                      &iterations);
    }

    if (iterations == 0) {
      // Fake singlestep status for trap diagnosis
      t->set_x86_debug_status(DS_SINGLESTEP);
      return result;
    }

    LOG(debug) << "x86-string fast-forward: " << iterations
               << " iterations required (ip==" << t->ip() << ")";

    Registers r = t->regs();

    Registers tmp = r;
    tmp.set_cx(iterations);
    t->set_regs(tmp);
    bool ok = t->vm()->add_breakpoint(limit_ip, BKPT_INTERNAL);
    ASSERT(t, ok) << "Failed to add breakpoint";
    // Watchpoints can fire spuriously because configure_watch_registers
    // can increase the size of the watched area to conserve watch registers.
    // So, disable watchpoints temporarily.
    t->vm()->save_watchpoints();
    t->vm()->remove_all_watchpoints();
    t->resume_execution(RESUME_CONT, RESUME_WAIT, RESUME_UNLIMITED_TICKS);
    t->vm()->restore_watchpoints();
    t->vm()->remove_breakpoint(limit_ip, BKPT_INTERNAL);
    result.did_fast_forward = true;
    // We should have reached the breakpoint
    ASSERT(t, t->stop_sig() == SIGTRAP);
    ASSERT(t, t->ip() == limit_ip.increment_by_bkpt_insn_length(t->arch()));
    uintptr_t iterations_performed = iterations - t->regs().cx();
    tmp = t->regs();
    // Undo our change to CX value
    tmp.set_cx(tmp.cx() + cur_cx - iterations);
    if (decoded.modifies_flags &&
        (t->regs().cx() > 0 ||
         (decoded.is_repne && t->regs().zf_flag()) ||
         (!decoded.is_repne && !t->regs().zf_flag()))) {
      // String instructions that modify flags don't have non-register side
      // effects, so we can reset registers to effectively unwind the loop.
      // Then we try rerunning the loop again, adding this state as one to
      // avoid stepping into. We shouldn't need to do this more than once!
      ASSERT(t, states_copy.empty());
      tmp.set_ip(limit_ip);
      extra_state_to_avoid = tmp;
      states_copy = states;
      states_copy.push_back(&extra_state_to_avoid);
      using_states = &states_copy;
      t->set_regs(r);
      continue;
    }
    // instructions that don't modify flags should not terminate too early.
    ASSERT(t, t->regs().cx() == 0);
    ASSERT(t, iterations_performed == iterations);
    // We always end with at least one iteration to go in the string instruction,
    // so we must have the IP of the string instruction.
    tmp.set_ip(r.ip());
    t->set_regs(tmp);

    LOG(debug) << "x86-string fast-forward done; ip()==" << t->ip();
    // Fake singlestep status for trap diagnosis
    t->set_x86_debug_status(DS_SINGLESTEP);
    return result;
  }
}

static bool is_ignorable_prefix(Task* t, uint8_t byte) {
  if (byte >= 0x40 && byte <= 0x4f) {
    // REX prefix
    return t->arch() == x86_64;
  }
  switch (byte) {
    case 0x26: // ES override
    case 0x2E: // CS override
    case 0x36: // SS override
    case 0x3E: // DS override
    case 0x64: // FS override
    case 0x65: // GS override
    case 0x66: // operand-size override
    case 0x67: // address-size override
    case 0xF0: // LOCK
      return true;
    default:
      return false;
  }
}

static bool is_rep_prefix(uint8_t byte) { return byte == 0xF2 || byte == 0xF3; }

static bool is_string_instruction(uint8_t byte) {
  switch (byte) {
    case 0xA4: // MOVSB
    case 0xA5: // MOVSW
    case 0xA6: // CMPSB
    case 0xA7: // CMPSW
    case 0xAA: // STOSB
    case 0xAB: // STOSW
    case 0xAC: // LODSB
    case 0xAD: // LODSW
    case 0xAE: // SCASB
    case 0xAF: // SCASW
      return true;
    default:
      return false;
  }
}

static int fallible_read_byte(Task* t, remote_ptr<uint8_t> ip) {
  uint8_t byte;
  if (t->read_bytes_fallible(ip, 1, &byte) == 0) {
    return -1;
  }
  return byte;
}

bool is_string_instruction_at(Task* t, remote_code_ptr ip) {
  bool found_rep = false;
  remote_ptr<uint8_t> bare_ip = ip.to_data_ptr<uint8_t>();
  while (true) {
    int byte = fallible_read_byte(t, bare_ip);
    if (byte < 0) {
      return false;
    } else if (is_rep_prefix(byte)) {
      found_rep = true;
    } else if (is_string_instruction(byte)) {
      return found_rep;
    } else if (!is_ignorable_prefix(t, byte)) {
      return false;
    }
    ++bare_ip;
  }
}

static bool is_string_instruction_before(Task* t, remote_code_ptr ip) {
  remote_ptr<uint8_t> bare_ip = ip.to_data_ptr<uint8_t>();
  --bare_ip;
  int byte = fallible_read_byte(t, bare_ip);
  if (byte < 0 || !is_string_instruction(byte)) {
    return false;
  }
  while (true) {
    --bare_ip;
    int byte = fallible_read_byte(t, bare_ip);
    if (byte < 0) {
      return false;
    } else if (is_rep_prefix(byte)) {
      return true;
    } else if (!is_ignorable_prefix(t, byte)) {
      return false;
    }
  }
}

bool maybe_at_or_after_x86_string_instruction(Task* t) {
  if (!is_x86ish(t->arch())) {
    return false;
  }

  return is_string_instruction_at(t, t->ip()) ||
         is_string_instruction_before(t, t->ip());
}

bool at_x86_string_instruction(Task* t) {
  if (!is_x86ish(t->arch())) {
    return false;
  }

  return is_string_instruction_at(t, t->ip());
}

} // namespace rr
