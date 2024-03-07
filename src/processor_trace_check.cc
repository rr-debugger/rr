/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "processor_trace_check.h"

#include <ostream>
#include <sstream>
#include <string>
#include <vector>

#include "PerfCounters.h"
#include "ProcessorTraceDecoder.h"
#include "ReplaySession.h"
#include "ReplayTask.h"
#include "remote_code_ptr.h"

using namespace std;

namespace rr {

static bool get_next_instruction(ReplayTask* t, ProcessorTraceDecoder& decoder,
                                 ProcessorTraceDecoder::Instruction* out,
                                 remote_code_ptr instruction_to_ignore = remote_code_ptr()) {
  while (true) {
    bool result = decoder.next_instruction(out);
    if (!result) {
      return false;
    }
    if (out->address == t->vm()->do_breakpoint_fault_addr() ||
        out->address == instruction_to_ignore) {
      continue;
    }
    return true;
  }
}

static string intel_pt_context(ReplayTask* t, const vector<uint8_t>& record_pt_data,
    const vector<uint8_t>& replay_pt_data, int instruction_count,
    remote_ptr<void> patch_addr,
    const vector<uint8_t>& patch_data,
    remote_code_ptr record_instruction_to_ignore) {
  stringstream out;
  unordered_map<remote_code_ptr, int> execution_counts;
  ProcessorTraceDecoder record_pt_decoder(t, record_pt_data,
      ProcessorTraceDecoder::IS_RECORDING);
  record_pt_decoder.set_patch(patch_addr, patch_data);
  ProcessorTraceDecoder replay_pt_decoder(t, replay_pt_data,
      ProcessorTraceDecoder::IS_REPLAY);
  replay_pt_decoder.set_patch(patch_addr, patch_data);
  int start_at = max(0, instruction_count - 100);
  out << "\nrecord and replay (" << start_at << " instructions skipped)";
  for (int i = 0; i < instruction_count; ++i) {
    ProcessorTraceDecoder::Instruction tmp;
    get_next_instruction(t, record_pt_decoder, &tmp, record_instruction_to_ignore);
    get_next_instruction(t, replay_pt_decoder, &tmp);
    ++execution_counts[tmp.address];
    if (i >= start_at) {
      out << "\n" << tmp.address << " (execution "
          << execution_counts[tmp.address] << ")";
    }
  }
  out << "\nrecord";
  for (int i = 0; i < 10; ++i) {
    ProcessorTraceDecoder::Instruction tmp;
    if (get_next_instruction(t, record_pt_decoder, &tmp, record_instruction_to_ignore)) {
      out << "\n" << tmp.address;
    } else {
      break;
    }
  }
  out << "\nreplay";
  for (int i = 0; i < 10; ++i) {
    ProcessorTraceDecoder::Instruction tmp;
    if (get_next_instruction(t, replay_pt_decoder, &tmp)) {
      out << "\n" << tmp.address;
    } else {
      break;
    }
  }
  return out.str();
}

static vector<uint8_t> flatten_vector(const vector<vector<uint8_t>>& data) {
  vector<uint8_t> ret;
  size_t total_size = 0;
  for (const auto& d : data) {
    total_size += d.size();
  }
  ret.resize(total_size);
  if (total_size) {
    size_t offset = 0;
    for (const auto& d : data) {
      memcpy(ret.data() + offset, d.data(), d.size());
      offset += d.size();
    }
  }
  return ret;
}

static bool check_intel_pt_internal(ReplayTask* t,
    const PTData& replay_pt_data, ostream& stream) {
  remote_ptr<void> patch_addr;
  vector<uint8_t> patch_data;
  remote_code_ptr record_instruction_to_ignore;

  const Event& ev = t->session().current_trace_frame().event();
  switch (ev.type()) {
    case EV_PATCH_SYSCALL:
      // The task now has the syscallbuf patch applied.
      // But when we executed this code, there was a syscall
      // there.
      patch_addr = t->ip().to_data_ptr<void>();
      patch_data = syscall_instruction(t->arch());
      break;
    case EV_SYSCALL:
      // This instruction may not be executed due to the breakpoint
      // optimization we do during replay.
      record_instruction_to_ignore =
        t->session().current_trace_frame().regs().ip().decrement_by_syscall_insn_length(
          t->arch());
      break;
    default:
      break;
  }

  vector<uint8_t> replay_data = flatten_vector(replay_pt_data.data);

  FrameTime recorded_pt_data_time = t->current_frame_time();
  if (ev.has_ticks_slop()) {
    // This is for an emergency debugging dump. Look for PT data
    // associated with the next event instead since that will have
    // accumulated the data for this event.
    ++recorded_pt_data_time;
  }
  vector<uint8_t> record_pt_data = read_pt_data(t, recorded_pt_data_time);
  ProcessorTraceDecoder record_pt_decoder(t, record_pt_data,
      ProcessorTraceDecoder::IS_RECORDING);
  record_pt_decoder.set_patch(patch_addr, patch_data);
  ProcessorTraceDecoder replay_pt_decoder(t, replay_data,
      ProcessorTraceDecoder::IS_REPLAY);
  replay_pt_decoder.set_patch(patch_addr, patch_data);

  int instruction_count = 0;
  while (true) {
    ProcessorTraceDecoder::Instruction record_instruction;
    bool got_record_instruction =
        get_next_instruction(t, record_pt_decoder, &record_instruction,
            record_instruction_to_ignore);
    ProcessorTraceDecoder::Instruction replay_instruction;
    bool got_replay_instruction =
        get_next_instruction(t, replay_pt_decoder, &replay_instruction);
    if (got_record_instruction != got_replay_instruction) {
      stream << "Instruction sequence ended early: got_record_instruction "
          << got_record_instruction << " got_replay_instruction "
          << got_replay_instruction
          << intel_pt_context(t, record_pt_data, replay_data, instruction_count,
                              patch_addr, patch_data, record_instruction_to_ignore) << "\n";
      return false;
    }
    if (!got_record_instruction) {
      break;
    }
    if (record_instruction.address != replay_instruction.address) {
      stream << "Control flow diverged"
          << intel_pt_context(t, record_pt_data, replay_data, instruction_count,
                              patch_addr, patch_data, record_instruction_to_ignore) << "\n";
      return false;
    }
    ++instruction_count;
  }
  if (instruction_count) {
    LOG(debug) << "check_intel_pt verified " << instruction_count << " instructions";
  }
  return true;
}

void check_intel_pt_if_enabled(ReplayTask* t) {
  const Event& ev = t->session().current_trace_frame().event();
  if (ev.has_ticks_slop()) {
    // Only check PT data at events whose timing is exactly
    // the same between record and replay.
    return;
  }

  // Always extract PT data if there is any, and throw it
  // away if we don't want to check it.
  PTData replay_pt_data = t->hpc.extract_intel_pt_data();

  FrameTime start_checking_event =
    t->session().flags().intel_pt_start_checking_event;
  if (start_checking_event < 0) {
    return;
  }
  FrameTime current_time = t->current_frame_time();
  if (start_checking_event > current_time ||
      !t->session().done_initial_exec()) {
    return;
  }
  stringstream stream;
  bool ok = check_intel_pt_internal(t, replay_pt_data, stream);
  ASSERT(t, ok) << "Intel PT detected control flow divergence: "
      << stream.str();
}

void emergency_check_intel_pt(ReplayTask* t, ostream& stream) {
  PTData replay_pt_data = t->hpc.extract_intel_pt_data();
  if (!replay_pt_data.data.empty()) {
    check_intel_pt_internal(t, replay_pt_data, stream);
  }
}

} // namespace rr
