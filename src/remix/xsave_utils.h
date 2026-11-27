/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_REMIX_XSAVE_UTILS_H_
#define RR_REMIX_XSAVE_UTILS_H_

#include <stdint.h>

#define XINUSE_AVX (1 << 2)
#define XINUSE_BNDREGS (1 << 3)
#define XINUSE_BNDCSR (1 << 4)
#define XINUSE_MPX (XINUSE_BNDREGS | XINUSE_BNDCSR)
#define XINUSE_OPMASK (1 << 5)
#define XINUSE_ZMM_HI256 (1 << 6)
#define XINUSE_HI16_ZMM (1 << 7)
#define XSAVE_REGION_MAXIMUM_SIZE 11008

// NB: All functions in this file operate on trace layout XSAVE regions except
// convert_host_trace_xsave_region.

void note_trace_cpuid_data_for_component(int component, uint32_t eax, uint32_t ebx, uint32_t ecx);

enum SaveRestore { IS_SAVE, IS_RESTORE };
// For now we'll assume at most 32 state commponents and at most a 32-bit size
// bound on the xsave area. That should be enough for all time!
// If the layout of this struct changes, check all stubs.S files!
struct XSaveAnalysis {
  // Bitmask of the register components read/written. In some cases the exact
  // components maybe not be identifiable, in which case this is conservative.
  // Whether MXCSR is saved/restored is not indicated; even if bit 1 (SSE state)
  // is zero, MXCSR might still be saved/restored.
  uint32_t register_components;
  // Bitmask of the memory components read/written.
  uint32_t memory_components;
  // Size of the XSAVE/XRSTOR memory area read/written. Not all bytes in this
  // area are read/written; this is conservative.
  uint32_t mem_size;
  // A SaveRestore enum value
  uint32_t save_restore;
};
// Call this immediately after the instruction executed, so 'xsave_area' is
// the area that was just saved or restored. Reads remix_registers.
// This can use XMM regs so make sure they've been saved/restored.
XSaveAnalysis analyze_xsave(int opcode, void* xsave_area);

// Return maximum possible size of xsave data based on state known before
// xsave instruction. Reads remix_registers so isn't constant.
uint32_t before_xsave_max_area_size(int opcode);

uint64_t xinuse(void);

uint64_t rbfm(void);

void xsave_init();

void* memcpy_no_simd(void* dst, const void* src, size_t len);

void convert_host_trace_xsave_region(int opcode, char* input_xsave_area, char* output_xsave_area);

#endif
