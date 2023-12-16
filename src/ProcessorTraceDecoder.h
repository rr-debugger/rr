/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_PROCESSOR_TRACE_DECODER_H_
#define RR_PROCESSOR_TRACE_DECODER_H_

#include <stdint.h>

#include <vector>

#include "log.h"
#include "Task.h"
#include "remote_code_ptr.h"

struct pt_insn_decoder;

namespace rr {

/**
 * Decodes Intel PT data to produce a control flow trace as a sequence
 * of executed instructions.
 *
 * If intel_pt_decoding was not explicitly set to TRUE via `cmake -Dintel_pt_decoding=TRUE`,
 * then libipt is not linked in and this always returns no instructions.
 */
class ProcessorTraceDecoder {
public:
  enum Mode {
    IS_RECORDING,
    IS_REPLAY
  };

  struct Instruction {
    remote_code_ptr address;
  };

  ProcessorTraceDecoder(Task* t, const std::vector<uint8_t>& trace_data, Mode mode)
    : task(t), decoder(nullptr), mode(mode), need_sync(false) {
    init(trace_data);
  }
#ifdef INTEL_PT_DECODING
  ~ProcessorTraceDecoder();
  bool next_instruction(Instruction* out, int* pt_status = nullptr);
#else
  bool next_instruction(Instruction*, int* = nullptr)
  {
    FATAL() << "Intel PT support not built";
    return false;
  }
#endif

  // Override a memory range with specific data to be seen by libipt.
  // This is needed when memory (other than the rr page) is different between
  // when the PT data was gathered and its current contents.
  void set_patch(remote_ptr<void> addr, const std::vector<uint8_t>& data) {
    patch_addr = addr;
    patch_data = data;
  }
  int read_mem(uint64_t ip, uint8_t *buffer, size_t size);

private:
#ifdef INTEL_PT_DECODING
  void init(const std::vector<uint8_t>& trace_data);
#else
  void init(const std::vector<uint8_t>&)
  {
    FATAL() << "Intel PT decoding support not built; run CMake with -Dintel_pt_decoding=TRUE";
  }
#endif
  void init_decoder();

  void dump_full_trace_data_to_file();

  void maybe_process_events(int status);
  std::string internal_error_context_string();

  Task* const task;
  std::vector<uint8_t> full_trace_data;
  pt_insn_decoder* decoder;
  remote_ptr<void> patch_addr;
  std::vector<uint8_t> patch_data;
  Mode mode;
  bool need_sync;
};

} // namespace rr

#endif /* RR_PROCESSOR_TRACE_DECODER_H_ */
