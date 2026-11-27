/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include <algorithm>

#include "dr_api.h"

#include "engine.h"
#include "remix_util.h"
#include "xsave_utils.h"

#include "remix.h"

#include "../core.h"

REMIX_TARGET_BEGIN

using namespace std;

const int XSAVEC_FEATURE_FLAG = 1 << 1;
const int XGETBV_XINUSE_FEATURE_FLAG = 1 << 2;
const int OSXSAVE_FEATURE_FLAG = 1 << 27;

static bool host_has_xsavec = false;
static bool host_has_xgetbv_xinuse = false;
extern uint64_t host_xcr0;

uint64_t rbfm() {
  uint64_t instruction_mask =
      (remix_registers.rdx << 32) | uint32_t(remix_registers.rax);
  return tracee_xcr0 & instruction_mask;
}

struct CPUIDXSaveComponentData {
  uint32_t area_size;
  uint32_t standard_area_offset;
  uint32_t flags;
};

static CPUIDXSaveComponentData host_cpuid_data_for_component(int component) {
  static CPUIDXSaveComponentData cached_data[64];

  if (cached_data[component].area_size > 0) {
    return cached_data[component];
  }

  auto cpuid_result = cpuid(0x0d, component);
  cached_data[component] = { cpuid_result.eax, cpuid_result.ebx, cpuid_result.ecx };
  return cached_data[component];
}

static CPUIDXSaveComponentData trace_xsave_component_data[64];

void note_trace_cpuid_data_for_component(int component, uint32_t eax, uint32_t ebx, uint32_t ecx) {
  remix_assert(component < 64);
  trace_xsave_component_data[component] = { eax, ebx, ecx };
}

static CPUIDXSaveComponentData trace_cpuid_data_for_component(int component) {
  return trace_xsave_component_data[component];
}

static uint64_t standard_xsave_area_size(uint64_t xstate_bv) {
  xstate_bv >>= 2;
  int component = 2;
  uint64_t end = 576;
  while (xstate_bv) {
    if (xstate_bv & 1) {
      CPUIDXSaveComponentData data = trace_cpuid_data_for_component(component);
      end = max<uint64_t>(end, data.standard_area_offset + data.area_size);
    }
    xstate_bv >>= 1;
    ++component;
  }
  return end;
}

static uint64_t compacted_xsave_area_size(uint64_t xstate_bv,
                                          uint64_t xcomp_bv) {
  xstate_bv >>= 2;
  xcomp_bv >>= 2;
  int component = 2;
  uint64_t end = 576;
  // The components must be in order so we just return the end of the last
  // component in xstate_bv.
  while (xstate_bv) {
    if (xcomp_bv & 1) {
      CPUIDXSaveComponentData data = trace_cpuid_data_for_component(component);
      if (data.flags & 2) {
        // Need to align
        end = (end + 63) & ~uint64_t(63);
      }
      end += data.area_size;
    }
    xstate_bv >>= 1;
    xcomp_bv >>= 1;
    ++component;
  }
  return end;
}

XSaveAnalysis analyze_xsave(int opcode, void* xsave_area) {
  remix_assert(xmm_regs_saved());

  XSaveAnalysis analysis;
  bool supports_compact = false;
  bool honors_XINUSE = false;
  switch (opcode) {
    case OP_fxsave32:
    case OP_fxsave64:
      return { 3, 3, 512, IS_SAVE };
    case OP_fxrstor32:
    case OP_fxrstor64:
      return { 3, 3, 512, IS_RESTORE };
    case OP_xsaveopt32:
    case OP_xsaveopt64:
      // Intel says to not use XSAVEOPT in user space. However, if it does get
      // used, it's OK for us to ignore the "modified optimization" and return
      // conservative results.
      honors_XINUSE = true;
      RR_FALLTHROUGH;
    case OP_xsave32:
    case OP_xsave64:
      analysis.save_restore = IS_SAVE;
      break;
    case OP_xsavec32:
    case OP_xsavec64:
      supports_compact = true;
      honors_XINUSE = true;
      analysis.save_restore = IS_SAVE;
      break;
    case OP_xrstor32:
    case OP_xrstor64:
      supports_compact = true;
      analysis.save_restore = IS_RESTORE;
      break;
    default:
      return { 0, 0, 0, IS_SAVE };
  }

  uint64_t* xstate_bv = (uint64_t*)((char*)xsave_area + 512);
  analysis.register_components = rbfm();
  if (honors_XINUSE) {
    analysis.memory_components = *xstate_bv & analysis.register_components;
  } else {
    analysis.memory_components = analysis.register_components;
  }

  // Now determine the length of the xsave memory area.
  uint64_t* xcomp_bv = xstate_bv + 1;
  if (supports_compact && (*xcomp_bv >> 63)) {
    analysis.mem_size = compacted_xsave_area_size(analysis.memory_components, *xcomp_bv);
  } else {
    analysis.mem_size = standard_xsave_area_size(analysis.memory_components);
  }
  return analysis;
}

void* memcpy_no_simd(void* dst, const void* src, size_t len) {
  asm volatile ("rep movsb"
                : "=D" (dst),
                  "=S" (src),
                  "=c" (len)
                : "0" (dst),
                  "1" (src),
                  "2" (len)
                : "memory");
  return dst;
}

void convert_host_trace_xsave_region(int opcode, char* input_xsave_area, char* output_xsave_area) {
  bool honors_XINUSE = false;
  bool supports_compact = false;
  bool input_is_host_layout = true;

  switch (opcode) {
    case OP_xsaveopt32:
    case OP_xsaveopt64:
      // Intel says to not use XSAVEOPT in user space. However, if it does get
      // used, it's OK for us to ignore the "modified optimization" and return
      // conservative results.
      honors_XINUSE = true;
      RR_FALLTHROUGH;
    case OP_xsave32:
    case OP_xsave64:
      break;
    case OP_xsavec32:
    case OP_xsavec64:
      supports_compact = true;
      honors_XINUSE = true;
      break;
    case OP_xrstor32:
    case OP_xrstor64:
      supports_compact = true;
      input_is_host_layout = false;
      break;
    default:
      remix_abort("Unknown opcode %d", opcode);
  }

  uint64_t register_components = rbfm();
  uint64_t* xstate_bv = (uint64_t*)(input_xsave_area + 512);
  uint64_t memory_components;
  if (honors_XINUSE) {
    memory_components = *xstate_bv & register_components;
  } else {
    memory_components = register_components;
  }

  uint64_t xcomp_bv = *(xstate_bv + 1);

  // Copy the legacy region.
  memcpy_no_simd(output_xsave_area, input_xsave_area, 416);
  // Copy the header.
  memcpy_no_simd(output_xsave_area + 512, input_xsave_area + 512, 64);

  if (supports_compact && (xcomp_bv >> 63)) {
    memory_components >>= 2;
    xcomp_bv >>= 2;
    int component = 2;
    uint64_t end = 576;
    // The components must be in order so we just return the end of the last
    // component in xstate_bv.
    while (memory_components) {
      if (xcomp_bv & 1) {
        CPUIDXSaveComponentData trace_data = trace_cpuid_data_for_component(component);
        CPUIDXSaveComponentData host_data = host_cpuid_data_for_component(component);
        remix_assert((trace_data.flags & 2) == (host_data.flags & 2));
        remix_assert(trace_data.area_size == host_data.area_size);
        if (trace_data.flags & 2) {
          // Need to align
          end = (end + 63) & ~uint64_t(63);
        }
        memcpy_no_simd(output_xsave_area + end, input_xsave_area + end, trace_data.area_size);
        end += trace_data.area_size;
      }
      memory_components >>= 1;
      xcomp_bv >>= 1;
      ++component;
    }
  } else {
    memory_components >>= 2;
    int component = 2;
    while (memory_components) {
      if (memory_components & 1) {
        CPUIDXSaveComponentData trace_data = trace_cpuid_data_for_component(component);
        CPUIDXSaveComponentData host_data = host_cpuid_data_for_component(component);
        remix_assert(trace_data.area_size == host_data.area_size);
        if (input_is_host_layout) {
          memcpy_no_simd(output_xsave_area + trace_data.standard_area_offset,
                         input_xsave_area + host_data.standard_area_offset,
                         trace_data.area_size);
        } else {
          memcpy_no_simd(output_xsave_area + host_data.standard_area_offset,
                         input_xsave_area + trace_data.standard_area_offset,
                         trace_data.area_size);
        }
      }
      memory_components >>= 1;
      ++component;
    }
  }
}

uint32_t before_xsave_max_area_size(int opcode) {
  switch (opcode) {
    case OP_fxsave32:
    case OP_fxsave64:
      return 512;
    case OP_xsaveopt32:
    case OP_xsaveopt64:
    case OP_xsave32:
    case OP_xsave64:
      return standard_xsave_area_size(rbfm());
    case OP_xsavec32:
    case OP_xsavec64:
      return compacted_xsave_area_size(rbfm(), 0xffffffff);
    default:
      return 0;
  }
}

uint64_t xinuse() {
  if (host_has_xgetbv_xinuse) {
    uint32_t edx, eax;
    asm("xgetbv" : "=a"(eax), "=d"(edx) : "c"(1));
    uint64_t xinuse = (uint64_t(edx) << 32) | eax;
    return xinuse;
  } else if (host_has_xsavec) {
    // Theoretically this can happen, but it's not clear it happens on an
    // actual processor. Unimplemented for now. We could reconstruct
    // XINUSE from the output of an XSAVEC.
    remix_assert(false);
    return -1;
  } else {
    // If we don't have XSAVEC the XINUSE bits are not observable, so pretend
    // all components enabled in the host XCR0 are in use. (Callers rely on
    // XINUSE bits only being set for components the host supports.)
    return host_xcr0;
  }
}

static uint64_t xcr0(void) {
  uint32_t eax, edx;
  asm volatile("xgetbv"
               : "=a"(eax), "=d"(edx)
               : "c"(0));
  return (uint64_t(edx) << 32) | eax;
}

void xsave_init() {
  auto cpuid_result = cpuid(1, 0);
  remix_assert((cpuid_result.ecx & OSXSAVE_FEATURE_FLAG) != 0);
  cpuid_result = cpuid(0x0d, 0);
  remix_assert(cpuid_result.ecx <= XSAVE_REGION_MAXIMUM_SIZE);
  cpuid_result = cpuid(0x0d, 1);
  host_has_xsavec = !!(cpuid_result.eax & XSAVEC_FEATURE_FLAG);
  host_has_xgetbv_xinuse = !!(cpuid_result.eax & XGETBV_XINUSE_FEATURE_FLAG);
  host_xcr0 = xcr0();
}

REMIX_TARGET_END
