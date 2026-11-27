/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_ENGINE_H_
#define RR_ENGINE_H_

#include <stdlib.h>

#include "dr_api.h"

#include "Assembler.h"
#include "Translation.h"

const int MAX_BYTES_PER_FRAGMENT = 255;
void engine_init(void* nearzone_start, size_t nearzone_size,
                 uint32_t flags, uint64_t tracee_xcr0);

// Called when we're exiting the address space
void engine_exit();

struct InvalidateTranslatedCodeParam;

extern "C" {
// While running fragments we keep the original stack pointer here. Sometimes
// we switch back to it to run C helper code.
extern void* saved_rsp;

/**
 * If non-null, then the IP of the last x87 instruction executed.
 * Our translated x87 instructions update this and we update the CPU with it
 * whenever the FIP becomes observable.
 * This can only be non-null while we're in remix_execute. At all other timmes
 * it must be null and therefore the CPU's FIP must be correct.
 */
extern app_pc pending_fip;
extern uint64_t extra_rflags;

extern uint8_t saved_mm_regs[16 * 16];
extern uint32_t saved_mxcsr;

extern uint8_t stop_mode;
extern uint8_t singlestep_mode;
extern bool stop_flag;
// Generate STOPPED_SYNC_SIGNAL on CPUID executions
extern bool use_cpuid_faulting;
extern bool correct_rcp_rsqrt;
extern bool correct_lzcnt;
extern bool correct_tzcnt;
extern bool correct_xsave_region_format;
extern app_pc stop_pc;
extern uint64_t tracee_xcr0;
extern uint8_t rcp_rsqrt_input_operand[16];

extern bool conditional_branch_taken;

/**
 * True when we are executing generated code.
 */
extern bool in_generated_code;

/**
 * A PatchCallback is called after a stub has caused a return from run_fragment.
 * At that point, a fragment is about to be generated for remix_registers.rip
 * at code_buffer.next(), so we can patch the just-exited fragment with that
 * knowledge.
 */
typedef void (*PatchCallback)(void);
extern PatchCallback patch_callback;

/**
 * Declare non-C-callable assembly stubs as AsmStub.
 */
typedef uint8_t AsmStub[1];

// Functions defined in assembly code.
void run_fragment(Fragment fragment);
void save_xmm_state();
void restore_xmm_state();

// Functions exported from C to assembly code
int match_registers(void);
void patch_invalid_fragment_stub(void);
void patch_refill_indirect_jump_cache(void);
void patch_untranslated_branch(void);
void before_monitored_syscall(uint8_t is_32bit, uintptr_t return_address);
uintptr_t monitored_syscall(uint8_t is_32bit);
void wx_sighandler_internal(void);
// If pending_fip is non-null, copy it back to our CPU's FIP.
void flush_pending_fip(void);
void handle_xsave(int opcode, void* tracee_xsave_region);
}

const uint64_t RFLAG_TF = 0x100;
const uint64_t RFLAG_AC = 0x40000;

inline bool xmm_regs_saved() {
  return saved_mxcsr != 0;
}

struct AutoSaveRestoreState {
  AutoSaveRestoreState() {
    remix_assert(!xmm_regs_saved());
    save_xmm_state();
  }
  ~AutoSaveRestoreState() { restore_xmm_state(); }
};

// These can be called by tools only when it's safe to "change engine state"

// Force recompilation of all code in range.
void invalidate_code(app_pc start, app_pc end);
// Force full reset of all generated code.
void full_reset();
// Every time the given PC is visited, call ToolHooks::notify_visit_pc.
// Since this forces a switch from generated code to remix (and back), there is
// some overhead. If you don't need to get into a "safe to change engine state"
// state, you might be better off generating custom instrumentation for this pc
// instead (possibly involving an assembler stub that calls into C using
// prepare_enter_cpp_fast/prepare_exit_cpp_fast).
// String instructions are only visited before the first iteration and
// before each restart of an interrupted instruction.
void add_visit_pc(app_pc pc);
// Entries are not refcounted, i.e. multiple adds followed by one remove will
// remove the entry from the set.
void remove_visit_pc(app_pc pc);

// Called by Translation.cc
void invalidate_translated_code(Translation* t, InvalidateTranslatedCodeParam* param);

template <typename T> class LinearAllocator {
public:
  void init(void* start, void* end) {
    current = this->start_ = static_cast<T*>(start);
    this->end = static_cast<T*>(end);
  }
  void* allocate(size_t size) {
    void* p = current;
    current += size;
    return p;
  }
  T* start() { return start_; }
  T* next() { return current; }
  size_t remaining() { return end - current; }
  void mark_allocated(T* output) { current = output; }
  void reset() { current = start_; }

private:
  T* start_;
  T* current;
  T* end;
};

/*
 * Code buffer allocation manager.
 * All allocations guaranteed to be within 2GB after the start of the
 * remix module.
 * The code buffer is intended for unaligned translated code that will fill
 * the instruction cache (i.e. may be hot).
 */
extern LinearAllocator<GeneratedCode> code_buffer;

/*
 * Stub buffer allocation manager.
 * All allocations guaranteed to be within 2GB after the start of the
 * remix module.
 * The stub buffer is intended for unaligned translated code that should not
 * pollute the instruction cache (i.e. is not hot).
 */
extern LinearAllocator<GeneratedCode> stub_buffer;

/*
 * Data buffer allocation manager.
 * All allocations guaranteed to be within 2GB after the start of the
 * remix module.
 * The data buffer is intended for aligned non-executable data that could be
 * hot.
 */
extern LinearAllocator<uint8_t> data_buffer;

// Called by Generator during codegen.
bool is_visited_pc(app_pc pc);

#endif /* RR_ENGINE_H_ */
