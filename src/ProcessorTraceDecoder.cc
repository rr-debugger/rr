/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include <intel-pt.h>

#include <ostream>
#include <sstream>
#include <vector>

#include "AddressSpace.h"
#include "ProcessorTraceDecoder.h"
#include "Session.h"
#include "log.h"
#include "preload/preload_interface.h"
#include "util.h"

using namespace std;

namespace rr {

static string pt_err(int status) {
  char buf[1024];
  sprintf(buf, "%s (%d)", pt_errstr(pt_errcode(status)), status);
  return buf;
}

ProcessorTraceDecoder::~ProcessorTraceDecoder() {
  if (decoder) {
    pt_insn_free_decoder(decoder);
  }
}

int read_mem_callback(uint8_t *buffer, size_t size,
                      const pt_asid *,
                      uint64_t ip, void *context) {
  return static_cast<ProcessorTraceDecoder*>(context)->
      read_mem(ip, buffer, size);
}

static constexpr uint8_t injected_header_packets[] =
    { /*PSB*/ 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82,
              0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82,
      /*CBR 31*/ 0x02, 0x03, 0x1f, 0x00,
      /*PSBEND*/ 0x02, 0x23 };
static constexpr size_t PSB_LEN = 16;

void ProcessorTraceDecoder::init(const vector<uint8_t>& trace_data) {
  if (trace_data.empty()) {
    return;
  }

  if (trace_data.size() < PSB_LEN ||
      memcmp(injected_header_packets, trace_data.data(), PSB_LEN)) {
    full_trace_data.reserve(sizeof(injected_header_packets) + trace_data.size());
    full_trace_data.insert(full_trace_data.end(), injected_header_packets,
                           injected_header_packets + sizeof(injected_header_packets));
  }
  full_trace_data.insert(full_trace_data.end(), trace_data.begin(),
                         trace_data.end());

  init_decoder();
}

void ProcessorTraceDecoder::dump_full_trace_data_to_file() {
  ScopedFd out("/tmp/ptdata", O_WRONLY | O_CREAT | O_TRUNC, 0700);
  write_all(out, full_trace_data.data(), full_trace_data.size());
}

void ProcessorTraceDecoder::init_decoder() {
  pt_config config;
  memset(&config, 0, sizeof(config));
  config.size = sizeof(config);
  config.begin = const_cast<uint8_t*>(full_trace_data.data());
  config.end = const_cast<uint8_t*>(full_trace_data.data() + full_trace_data.size());

  decoder = pt_insn_alloc_decoder(&config);
  if (!decoder) {
    FATAL() << "Cannot create PT decoder";
  }

  pt_image* image = pt_insn_get_image(decoder);
  int status = pt_image_set_callback(image, read_mem_callback, this);
  if (status < 0) {
    FATAL() << "Can't set PT mem callback: " << pt_errstr(pt_errcode(status));
  }

  need_sync = true;
}

static vector<uint8_t>* cached_rr_page_for_recording[2];

static const vector<uint8_t>& rr_page_for_recording(SupportedArch arch) {
  if (arch != x86 && arch != x86_64) {
    FATAL() << "Unsupported arch " << arch_name(arch);
  }
  int index = arch == x86_64;
  vector<uint8_t>* page = cached_rr_page_for_recording[index];
  if (page) {
    return *page;
  }
  page = new vector<uint8_t>();
  *page = AddressSpace::read_rr_page_for_recording(arch);
  cached_rr_page_for_recording[index] = page;
  return *page;
}

int ProcessorTraceDecoder::read_mem(uint64_t ip, uint8_t *buffer, size_t size) {
  ssize_t ret = task->read_bytes_fallible(ip, size, buffer);
  if (ret <= 0) {
    return ret;
  }
  if (mode == IS_RECORDING) {
    // The rr page instructions differ between recording and replay. The
    // task's rr page contains the replay values; if we're analyzing
    // PT data from the recording, make sure to use the rr page instructions
    // from the recording.
    const vector<uint8_t>& rr_page_data = rr_page_for_recording(task->arch());
    remote_ptr<void> rr_page_addr(RR_PAGE_ADDR);
    remote_ptr<void> ip_addr(ip);
    replace_in_buffer(MemoryRange(rr_page_addr, rr_page_data.size()),
                      rr_page_data.data(), MemoryRange(ip, ret), buffer);
  }
  replace_in_buffer(MemoryRange(patch_addr, patch_data.size()),
                    patch_data.data(), MemoryRange(ip, ret), buffer);
  return ret;
}

void ProcessorTraceDecoder::maybe_process_events(int status) {
  while (status & pts_event_pending) {
    pt_event event;
    status = pt_insn_event(decoder, &event, sizeof(event));
    if (status < 0) {
      FATAL() << "Cannot get PT event: " << pt_err(status);
    }
    switch (event.type) {
      case ptev_enabled:
      case ptev_disabled:
      case ptev_async_disabled:
      case ptev_exec_mode:
      case ptev_cbr:
      case ptev_tsx:
      case ptev_async_vmcs:
        break;
      case ptev_overflow:
        FATAL() << "Detected ptev_overflow";
        break;
      default:
        FATAL() << "Unhandled event type: " << event.type;
        break;
    }
  }
}

string ProcessorTraceDecoder::internal_error_context_string() {
  ProcessorTraceDecoder helper(task, full_trace_data, mode);
  vector<Instruction> instructions;
  while (true) {
    int pt_status = 0;
    Instruction instruction;
    if (helper.next_instruction(&instruction, &pt_status)) {
      instructions.push_back(instruction);
    } else {
      break;
    }
  }
  size_t start_index = 0;
  stringstream out;
  if (instructions.size() > 10000) {
    start_index = instructions.size() - 10000;
    out << "\n... skipped " << start_index << " instructions";
  }
  for (size_t i = start_index; i < instructions.size(); ++i) {
    out << "\n" << instructions[i].address;
  }
  return out.str();
}

bool ProcessorTraceDecoder::next_instruction(Instruction* out, int* pt_status) {
  if (!decoder) {
    return false;
  }

  while (true) {
    if (need_sync) {
      int status = pt_insn_sync_forward(decoder);
      if (pt_errcode(status) == pte_eos) {
        return false;
      }
      if (status < 0) {
        if (pt_status) {
          *pt_status = status;
          return false;
        }
        FATAL() << "Can't sync forward: " << pt_err(status)
            << internal_error_context_string();
      }
      need_sync = false;
      maybe_process_events(status);
    }

    pt_insn insn;
    int status = pt_insn_next(decoder, &insn, sizeof(insn));
    if (pt_errcode(status) == pte_eos) {
      need_sync = true;
      continue;
    }
    if (status < 0) {
      if (pt_status) {
        *pt_status = status;
        return false;
      }
      FATAL() << "Can't read next instruction: " << pt_err(status)
          << internal_error_context_string();
    }
    maybe_process_events(status);
    out->address = insn.ip;
    return true;
  }
}

}
