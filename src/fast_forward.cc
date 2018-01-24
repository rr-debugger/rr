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
  int length;
  bool modifies_flags;
  bool uses_si;
};

/**
 * This can be conservative: for weird prefix combinations that make valid
 * string instructions, but aren't ever used in practice, we can return false.
 */
static bool decode_x86_string_instruction(const InstructionBuf& code,
                                          DecodedInstruction* decoded) {
  bool found_operand_prefix = false;
  bool found_REP_prefix = false;
  bool found_REXW_prefix = false;

  decoded->modifies_flags = false;
  decoded->uses_si = false;

  int i;
  bool done = false;
  for (i = 0; i < code.code_buf_len; ++i) {
    switch (code.code_buf[i]) {
      case 0x66:
        found_operand_prefix = true;
        break;
      case 0x48:
        if (code.arch == x86_64) {
          found_REXW_prefix = true;
          break;
        }
        return false;
      case 0xF2:
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

static bool is_x86ish(Task* t) {
  return t->arch() == x86 || t->arch() == x86_64;
}

bool fast_forward_through_instruction(Task* t, ResumeRequest how,
                                      const vector<const Registers*>& states) {
  DEBUG_ASSERT(how == RESUME_SINGLESTEP || how == RESUME_SYSEMU_SINGLESTEP);

  remote_code_ptr ip = t->ip();

  t->resume_execution(how, RESUME_WAIT, RESUME_UNLIMITED_TICKS);
  if (t->stop_sig() != SIGTRAP) {
    // we might have stepped into a system call...
    return false;
  }

  if (t->ip() != ip) {
    return false;
  }
  if (t->vm()->get_breakpoint_type_at_addr(ip) != BKPT_NONE) {
    // breakpoint must have fired
    return false;
  }
  if (t->vm()->notify_watchpoint_fired(t->debug_status(),
          t->last_execution_resume())) {
    // watchpoint fired
    return false;
  }
  for (auto& state : states) {
    if (state->matches(t->regs())) {
      return false;
    }
  }
  if (!is_x86ish(t)) {
    return false;
  }

  InstructionBuf instruction_buf = read_instruction(t, ip);
  DecodedInstruction decoded;
  if (!decode_x86_string_instruction(instruction_buf, &decoded)) {
    return false;
  }

  remote_code_ptr limit_ip = ip + decoded.length;

  // At this point we can be sure the instruction didn't trigger a syscall,
  // so we no longer care about the value of |how|.

  Registers extra_state_to_avoid;
  vector<const Registers*> states_copy;
  auto using_states = &states;

  bool did_execute = false;
  while (true) {
    // This string instruction should execute until CX reaches 0 and
    // we move to the next instruction, or we hit one of the states in
    // |states|, or the ZF flag changes so that the REP stops, or we hit
    // a watchpoint. (We can't hit a breakpoint during the loop since we
    // already verified there isn't one set here.)

    // We'll compute an upper bound on the number of string instruction
    // iterations to execute, and set a watchpoint on the memory location
    // accessed through DI in the iteration we want to stop at. We'll also
    // set a breakpoint after the string instruction to catch cases where it
    // ends due to a ZF change.
    // Keep in mind that it's possible that states in |states| might
    // belong to multiple independent loops of this string instruction, with
    // registers reset in between the loops.

    uintptr_t cur_cx = t->regs().cx();
    if (cur_cx == 0) {
      // Fake singlestep status for trap diagnosis
      t->set_debug_status(DS_SINGLESTEP);
      // This instruction will be skipped entirely.
      return did_execute;
    }

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
      t->set_debug_status(DS_SINGLESTEP);
      return did_execute;
    }

    LOG(debug) << "x86-string fast-forward: " << iterations
               << " iterations required (ip==" << t->ip() << ")";

    Registers r = t->regs();

    int direction = t->regs().df_flag() ? -1 : 1;
    // Figure out the address to set a watchpoint at. This address must
    // be accessed at or before the last iteration we want to perform.
    // We have to account for a CPU quirk: Intel CPUs may coalesce iterations
    // to write up to 64 bytes at a time (observed for "rep stosb" on Ivy
    // Bridge). Assume 128 bytes to be safe.
    static const unsigned BYTES_COALESCED = 128;
    uintptr_t watch_offset = decoded.operand_size * (iterations - 1);
    if (watch_offset > BYTES_COALESCED) {
      watch_offset -= BYTES_COALESCED;
      t->vm()->save_watchpoints();
      t->vm()->remove_all_watchpoints();
      remote_ptr<void> watch_di = t->regs().di() + direction * watch_offset;
      LOG(debug) << "Set x86-string fast-forward watchpoint at " << watch_di;
      bool ok = t->vm()->add_watchpoint(watch_di, 1, WATCH_READWRITE);
      ASSERT(t, ok) << "Can't even handle one watchpoint???";
      ok = t->vm()->add_breakpoint(limit_ip, BKPT_INTERNAL);
      ASSERT(t, ok) << "Failed to add breakpoint";

      t->resume_execution(RESUME_CONT, RESUME_WAIT, RESUME_UNLIMITED_TICKS);
      did_execute = true;
      ASSERT(t, t->stop_sig() == SIGTRAP);
      // Grab debug_status before restoring watchpoints, since the latter
      // clears the debug status
      bool triggered_watchpoint =
          t->vm()->notify_watchpoint_fired(t->debug_status(),
              t->last_execution_resume());
      t->vm()->remove_breakpoint(limit_ip, BKPT_INTERNAL);
      t->vm()->restore_watchpoints();

      ASSERT(t, cur_cx > t->regs().cx());
      uintptr_t iterations_performed = cur_cx - t->regs().cx();
      // we shoudn't execute more iterations than we asked for.
      // In Ubuntu-14 4.2.0-27-generic in a KVM guest we have seen watchpoints
      // failing to fire during string_instructions_replay. We plow through
      // and hit the backup breakpoint. triggered_watchpoint is true because
      // the memory has changed. This assertion should catch such errors.
      ASSERT(t, iterations >= iterations_performed);
      iterations -= iterations_performed;
      // instructions that don't modify flags should not terminate too early.
      // We can terminate prematurely when the watchpoint we set relative
      // to DI is triggered by a read via SI.
      ASSERT(t,
             decoded.modifies_flags || iterations <= BYTES_COALESCED ||
                 triggered_watchpoint);

      if (!triggered_watchpoint) {
        // watchpoint didn't fire. We must have exited the loop early and
        // hit the breakpoint. IP will be after the breakpoint instruction.
        ASSERT(t,
               t->ip() == limit_ip.increment_by_bkpt_insn_length(t->arch()) &&
                   decoded.modifies_flags);
        // Undo the execution of the breakpoint instruction.
        Registers tmp = t->regs();
        tmp.set_ip(limit_ip);
        t->set_regs(tmp);
      } else {
        ASSERT(t, t->ip() == limit_ip || t->ip() == ip);
        watch_offset = decoded.operand_size * (iterations - 1);
        if (watch_offset > BYTES_COALESCED) {
          // Fake singlestep status for trap diagnosis
          t->set_debug_status(DS_SINGLESTEP);
          // We fired the watchpoint too early, perhaps because reads through SI
          // triggered it. Let's just bail out now; better for the caller to
          // retry fast_forward_through_instruction than for us to try
          // singlestepping all the rest of the way.
          LOG(debug) << "x86-string fast-forward: " << iterations
                     << " iterations to go, but watchpoint hit early; aborted";
          return did_execute;
        }
      }
    }

    LOG(debug) << "x86-string fast-forward: " << iterations
               << " iterations to go";

    // Singlestep through the remaining iterations.
    while (iterations > 0 && t->ip() == ip) {
      // Don't count ticks here. Reactivating the performance counter can be
      // expensive and since we know we're just executing the string instruction
      // we shouldn't miss any ticks here.
      t->resume_execution(RESUME_SINGLESTEP, RESUME_WAIT, RESUME_NO_TICKS);
      did_execute = true;
      ASSERT(t, t->stop_sig() == SIGTRAP);
      // Watchpoints can fire spuriously because configure_watch_registers
      // can increase the size of the watched area to conserve watch registers.
      --iterations;
    }

    if (t->ip() != ip) {
      // We exited the loop early due to flags being modified.
      ASSERT(t, t->ip() == limit_ip && decoded.modifies_flags);
      // String instructions that modify flags don't have non-register side
      // effects, so we can reset registers to effectively unwind the loop.
      // Then we try rerunning the loop again, adding this state as one to
      // avoid stepping into. We shouldn't need to do this more than once!
      ASSERT(t, states_copy.empty());
      extra_state_to_avoid = t->regs();
      states_copy = states;
      states_copy.push_back(&extra_state_to_avoid);
      using_states = &states_copy;
      t->set_regs(r);
    } else {
      LOG(debug) << "x86-string fast-forward done; ip()==" << t->ip();
      // Fake singlestep status for trap diagnosis
      t->set_debug_status(DS_SINGLESTEP);
      return did_execute;
    }
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
  if (!is_x86ish(t)) {
    return false;
  }

  return is_string_instruction_at(t, t->ip()) ||
         is_string_instruction_before(t, t->ip());
}

bool at_x86_string_instruction(Task* t) {
  if (!is_x86ish(t)) {
    return false;
  }

  return is_string_instruction_at(t, t->ip());
}

} // namespace rr
