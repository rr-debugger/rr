/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "engine.h"

#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <algorithm>
#include <functional>

#include "dr_api.h"

#include "Assembler.h"
#include "Generator.h"
#include "Hashtable.h"
#include "Translation.h"
#include "Vector.h"
#include "fragment_stubs.h"
#include "remix.h"
#include "remix_util.h"
#include "xsave_utils.h"

REMIX_TARGET_BEGIN

using namespace std;

// Variables we want to access from assembly code need to be extern "C" for
// sanity.
extern "C" {

// These are used to save and restore XMM registers while in our tool code.
// We assume that tool code never uses the YMM upper halves, so those are never
// saved/restored.
// 64-byte alignment because these get used to save zmm scratch regs in some
// cases.
uint8_t saved_mm_regs[16 * 16] __attribute__((aligned(64)));

uint8_t rcp_rsqrt_input_operand[16] __attribute__((aligned(16)));

struct user_regs_struct remix_registers;
uint64_t remix_rcb;
app_pc pending_fip;
// Extra bits (just TF/AC for now) to be added into remix_registers.eflags
uint64_t extra_rflags;
struct user_regs_struct remix_target_registers;
uint64_t remix_target_rcb;
uint8_t remix_enable_stack_extension;
RemixSighandlerState remix_sighandler_state;
void* remix_crash_handler;
uintptr_t remix_range_start;
uintptr_t remix_range_end;
uint64_t sighandler_saved_rsp;
uint64_t tracee_xcr0;
uint64_t host_xcr0;

// While running fragments we keep the original stack pointer here. Sometimes
// we switch back to it to run C helper code.
// The value saved here has the same low 4 bits (alignment) as the value
// on entry (i.e. after the 'call') to "run_fragment". You need to subtract 8
// if you're going to make a call to a C function.
void* saved_rsp;

app_pc stop_pc;
GeneratedCode* untranslated_branch_offset;
PatchCallback patch_callback;

uint32_t saved_mxcsr;
uint32_t reference_mxcsr = 0x1f80;

uint8_t stop_mode;
uint8_t singlestep_mode;
bool match_ignore_gp_regs;
bool stop_flag;
bool use_cpuid_faulting;
bool correct_rcp_rsqrt;
bool correct_lzcnt;
bool correct_tzcnt;
bool correct_xsave_region_layout;
bool breakpoint_flag;
bool sync_signal_flag;

bool conditional_branch_taken;
bool in_generated_code;
}

LinearAllocator<GeneratedCode> code_buffer;
LinearAllocator<GeneratedCode> stub_buffer;
LinearAllocator<uint8_t> data_buffer;

static TraceFrameTime current_event;

template <> size_t hash(const app_pc& p) { return std::hash<app_pc>()(p); }

struct SavedInvalidFragment {
  app_pc pc;
  Fragment translation;
  uint8_t leading_bytes[5];
  uint8_t pc_len;
  bool resurrectable;
};

static Hashtable<app_pc>* visit_pc_hash;
static Vector<SavedInvalidFragment>* saved_invalid_fragments;

void engine_init(void* nz_start, size_t nz_size, uint32_t flags,
                 uint64_t tracee_xcr0) {
  size_t code_buffer_size = floor_page_size(nz_size / 2);
  size_t stub_buffer_size = floor_page_size(nz_size / 4);
  size_t data_buffer_size = floor_page_size(nz_size / 4);

  // Use guard pages
  auto p = (uint8_t*)nz_start;
  code_buffer.init(p, p + code_buffer_size - PAGE_SIZE);
  p += code_buffer_size;
  stub_buffer.init(p, p + stub_buffer_size - PAGE_SIZE);
  p += stub_buffer_size;
  data_buffer.init(p, p + data_buffer_size - PAGE_SIZE);

  p = (uint8_t*)syscall(SYS_mmap, code_buffer.next(), code_buffer.remaining(),
                        PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  if (p != (uint8_t*)code_buffer.next()) {
    remix_abort("Can't map code buffer");
  }

  p = (uint8_t*)syscall(SYS_mmap, stub_buffer.next(), stub_buffer.remaining(),
                        PROT_READ | PROT_WRITE | PROT_EXEC,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  if (p != (uint8_t*)stub_buffer.next()) {
    remix_abort("Can't map stub buffer");
  }

  p = (uint8_t*)syscall(SYS_mmap, data_buffer.next(), data_buffer.remaining(),
                        PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  if (p != (uint8_t*)data_buffer.next()) {
    remix_abort("Can't map data buffer");
  }

  ::use_cpuid_faulting = (flags & REMIX_INIT_CPUID_FAULTING) != 0;
  ::correct_rcp_rsqrt = (flags & REMIX_INIT_CORRECT_RCP_RSQRT) != 0;
  if (::correct_rcp_rsqrt) {
    remix_log(REMIX_LOG, "RCP/RSQRT correction enabled");
  }
  ::correct_lzcnt = (flags & REMIX_INIT_CORRECT_LZCNT) != 0;
  if (::correct_lzcnt) {
    remix_log(REMIX_LOG, "LZCNT correction enabled");
  }
  ::correct_tzcnt = (flags & REMIX_INIT_CORRECT_TZCNT) != 0;
  if (::correct_tzcnt) {
    remix_log(REMIX_LOG, "TZCNT correction enabled");
  }
  ::correct_xsave_region_layout = (flags & REMIX_INIT_CORRECT_XSAVE_REGION_LAYOUT) != 0;
  if (::correct_xsave_region_layout) {
    remix_log(REMIX_LOG, "XSAVE region layout correction enabled");
  }
  ::tracee_xcr0 = tracee_xcr0;
  Translation::init();
  saved_invalid_fragments = new Vector<SavedInvalidFragment>();
}

void add_visit_pc(app_pc pc) {
  if (!visit_pc_hash) {
    visit_pc_hash = new Hashtable<app_pc>();
  }
  if (!visit_pc_hash->lookup(pc)) {
    invalidate_code(pc, pc + 1);
    visit_pc_hash->insert(pc);
  }
}

void remove_visit_pc(app_pc pc) {
  if (visit_pc_hash->lookup(pc)) {
    invalidate_code(pc, pc + 1);
    visit_pc_hash->remove(pc);
  }
}

bool is_visited_pc(app_pc pc) {
  return visit_pc_hash && visit_pc_hash->lookup(pc);
}

static bool is_visited_or_stop_pc(app_pc pc) {
  return stop_pc == pc || is_visited_pc(pc);
}

void flush_pending_fip() {
  if (!pending_fip) {
    return;
  }

  struct user_fpregs_struct fxregs __attribute__((aligned(16)));
  asm("fxsave64 %0" : "=m"(fxregs));
  fxregs.rip = uintptr_t(pending_fip);
  asm("fxrstor64 %0" : : "m"(fxregs));

  pending_fip = nullptr;
}

// MPX was removed from later Intel processors. Even though remix doesn't support
// actually using MPX, its presence or absence is visible in XCOMP_BV after XSAVEC
// if the RBFM contained the right bits. Fix things up here to avoid a divergence.
void maybe_correct_xsavec_xcomp_bv_for_mpx(void* tracee_xsave_region) {
  uint64_t requested = rbfm();
  uint64_t requested_mpx_features = requested & XINUSE_MPX;
  if (!requested_mpx_features) {
    return;
  }

  uint64_t present_mpx_features = tracee_xcr0 & requested_mpx_features;
  uint64_t host_mpx_features = host_xcr0 & requested_mpx_features;
  if (present_mpx_features == host_mpx_features) {
    return;
  }

  uint64_t* tracee_xcomp_bv = (uint64_t*)((char*)tracee_xsave_region + 512) + 1;
  *tracee_xcomp_bv &= ~requested_mpx_features;
  *tracee_xcomp_bv |= present_mpx_features;
}

struct AutoRestorePreviousXcompBv {
  ~AutoRestorePreviousXcompBv() {
    if (xcomp_bv_address) {
      *xcomp_bv_address = xcomp_bv_value;
    }
  }
  uint64_t* xcomp_bv_address;
  uint64_t xcomp_bv_value;
};

// Likewise, we may need to remove bits from XCOMP_BV for an XRSTOR. Take care
// not to let that be visible to the tracee.
AutoRestorePreviousXcompBv maybe_correct_xrstor_xcomp_bv_for_mpx(void* host_xsave_region) {
  AutoRestorePreviousXcompBv restore = { 0, 0 };

  uint64_t present_mpx_features = tracee_xcr0 & XINUSE_MPX;
  uint64_t host_mpx_features = host_xcr0 & XINUSE_MPX;
  if (present_mpx_features == host_mpx_features) {
    return restore;
  }

  uint64_t* host_xcomp_bv = (uint64_t*)((char*)host_xsave_region + 512) + 1;
  if (!(*host_xcomp_bv & (1UL << 63))) {
    // Not compressed.
    return restore;
  }

  restore.xcomp_bv_address = host_xcomp_bv;
  restore.xcomp_bv_value = *host_xcomp_bv;
  *host_xcomp_bv &= ~XINUSE_MPX;
  *host_xcomp_bv |= host_mpx_features;
  return restore;
}

void handle_xsave(int opcode, void* tracee_xsave_region) {
  static uint8_t scratch_xsave_region[XSAVE_REGION_MAXIMUM_SIZE] __attribute__ ((aligned (64)));

  // Unpack EDX:EAX
  uint64_t requested = rbfm();
  uint32_t eax = requested;
  uint32_t edx = requested >> 32;

  if (!correct_xsave_region_layout) {
    switch (opcode) {
      case OP_xsavec32:
        asm volatile("xsavec (%0)" : : "r"(tracee_xsave_region), "a"(eax), "d"(edx) : "memory");
        maybe_correct_xsavec_xcomp_bv_for_mpx(tracee_xsave_region);
        break;
      case OP_xsavec64:
        asm volatile("xsavec64 (%0)" : : "r"(tracee_xsave_region), "a"(eax), "d"(edx) : "memory");
        maybe_correct_xsavec_xcomp_bv_for_mpx(tracee_xsave_region);
        break;
      case OP_xsave32:
        asm volatile("xsave (%0)" : : "r"(tracee_xsave_region), "a"(eax), "d"(edx) : "memory");
        break;
      case OP_xsave64:
        asm volatile("xsave64 (%0)" : : "r"(tracee_xsave_region), "a"(eax), "d"(edx) : "memory");
        break;
      case OP_xrstor32: {
        auto _restore = maybe_correct_xrstor_xcomp_bv_for_mpx(tracee_xsave_region);
        asm volatile("xrstor (%0)" : : "r"(tracee_xsave_region), "a"(eax), "d"(edx) : "memory");
        break;
      }
      case OP_xrstor64: {
        auto _restore = maybe_correct_xrstor_xcomp_bv_for_mpx(tracee_xsave_region);
        asm volatile("xrstor64 (%0)" : : "r"(tracee_xsave_region), "a"(eax), "d"(edx) : "memory");
        break;
      }
      default:
        remix_abort("Unexpected opcode %d", opcode);
    }
    return;
  }

  switch (opcode) {
    case OP_xsavec32:
      memcpy_no_simd(scratch_xsave_region, tracee_xsave_region, 576);
      asm volatile("xsavec (%0)" : : "r"(scratch_xsave_region), "a"(eax), "d"(edx) : "memory");
      convert_host_trace_xsave_region(opcode, (char*)scratch_xsave_region, (char*)tracee_xsave_region);
      maybe_correct_xsavec_xcomp_bv_for_mpx(tracee_xsave_region);
      break;
    case OP_xsavec64:
      memcpy_no_simd(scratch_xsave_region, tracee_xsave_region, 576);
      asm volatile("xsavec64 (%0)" : : "r"(scratch_xsave_region), "a"(eax), "d"(edx) : "memory");
      convert_host_trace_xsave_region(opcode, (char*)scratch_xsave_region, (char*)tracee_xsave_region);
      maybe_correct_xsavec_xcomp_bv_for_mpx(tracee_xsave_region);
      break;
    case OP_xsave32:
      memcpy_no_simd(scratch_xsave_region, tracee_xsave_region, 576);
      asm volatile("xsave (%0)" : : "r"(scratch_xsave_region), "a"(eax), "d"(edx) : "memory");
      convert_host_trace_xsave_region(opcode, (char*)scratch_xsave_region, (char*)tracee_xsave_region);
      break;
    case OP_xsave64:
      memcpy_no_simd(scratch_xsave_region, tracee_xsave_region, 576);
      asm volatile("xsave64 (%0)" : : "r"(scratch_xsave_region), "a"(eax), "d"(edx) : "memory");
      convert_host_trace_xsave_region(opcode, (char*)scratch_xsave_region, (char*)tracee_xsave_region);
      break;
    case OP_xrstor32: {
      convert_host_trace_xsave_region(opcode, (char*)tracee_xsave_region, (char*)scratch_xsave_region);
      auto _restore = maybe_correct_xrstor_xcomp_bv_for_mpx(scratch_xsave_region);
      asm volatile("xrstor (%0)" : : "r"(scratch_xsave_region), "a"(eax), "d"(edx) : "memory");
      break;
    }
    case OP_xrstor64: {
      convert_host_trace_xsave_region(opcode, (char*)tracee_xsave_region, (char*)scratch_xsave_region);
      auto _restore = maybe_correct_xrstor_xcomp_bv_for_mpx(scratch_xsave_region);
      asm volatile("xrstor64 (%0)" : : "r"(scratch_xsave_region), "a"(eax), "d"(edx) : "memory");
      break;
    }
    default:
      remix_abort("Unexpected opcode %d", opcode);
  }
}

void patch_refill_indirect_jump_cache() {
  app_pc pc = (app_pc)remix_registers.rip;
  // We just got here because the indirect jump stub couldn't find a
  // Translation
#ifdef DEBUG
  remix_assert(!Translation::lookup(pc));
#endif
  if (is_visited_or_stop_pc(pc)) {
    remix_log(REMIX_LOG_EXEC,
              "Bailing out in patch_refill_indirect_jump_cache");
    // Bail out. We may not be generating code for this pc yet; we will return
    // to rr or tool code which might change our state to something quite
    // different.
    return;
  }
  Translation::refill_indirect_jump_cache(pc, code_buffer.next());
}

void patch_untranslated_branch() {
  app_pc pc = (app_pc)remix_registers.rip;
  GeneratedCode* b = Translation::lookup(pc);
  if (!b) {
    if (is_visited_or_stop_pc(pc)) {
      remix_log(REMIX_LOG_EXEC, "Bailing out in patch_untranslated_branch");
      // Bail out. We may not be generating code for this pc yet; we will return
      // to rr or tool code which might change our state to something quite
      // different.
      return;
    }
    // The code will be emitted here next.
    b = code_buffer.next();
  }
  // Patch the branch that entered untranslated_branch_stub so that it jumps
  // directly to the translation of |pc| instead.
  Assembler::write(untranslated_branch_offset,
                   (int32_t)(b - (untranslated_branch_offset + 4)));
}

struct FirstInvalidFragmentForPC {
  app_pc pc;
  GeneratedCode* first_invalid_fragment;
  FirstInvalidFragmentForPC* next;
  uint8_t translation_mode;
};
static const int first_invalid_fragment_hash_size = 1 << 16;
static FirstInvalidFragmentForPC*
    first_invalid_fragment_hash[first_invalid_fragment_hash_size];

static uint32_t hash_first_invalid_fragment(app_pc pc) {
  return ((uintptr_t(pc) * PC_HASH_MULTIPLICAND) >> PC_HASH_SHIFT) &
         (first_invalid_fragment_hash_size - 1);
}

static GeneratedCode* first_invalid_fragment_lookup(app_pc pc,
                                                    uint8_t translation_mode) {
  FirstInvalidFragmentForPC* f =
      first_invalid_fragment_hash[hash_first_invalid_fragment(pc)];
  while (f) {
    if (f->pc == pc && f->translation_mode == translation_mode) {
      return f->first_invalid_fragment;
    }
    f = f->next;
  }
  return nullptr;
}

static void first_invalid_fragment_insert(app_pc pc, uint8_t translation_mode,
                                          GeneratedCode* fragment) {
  FirstInvalidFragmentForPC** ptr =
      &first_invalid_fragment_hash[hash_first_invalid_fragment(pc)];
  auto p = new FirstInvalidFragmentForPC();
  p->pc = pc;
  p->first_invalid_fragment = fragment;
  p->next = *ptr;
  p->translation_mode = translation_mode;
  *ptr = p;
}

static void first_invalid_fragment_reset() {
  for (size_t i = 0; i < first_invalid_fragment_hash_size; ++i) {
    FirstInvalidFragmentForPC** f = &first_invalid_fragment_hash[i];
    if (*f) {
      FirstInvalidFragmentForPC* next;
      for (auto ff = *f; ff; ff = next) {
        next = ff->next;
        delete ff;
      }
      *f = nullptr;
    }
  }
}

extern AsmStub fixup_invalid_fragment_stub;

void patch_invalid_fragment_stub() {
  app_pc pc = (app_pc)remix_registers.rip;
  // Some fragment jumped to the first invalid fragment for |pc|, which has
  // not been patched to point to a valid fragment. Fix that.
  GeneratedCode* valid_fragment = Translation::lookup(pc);
  // If we don't already have a translation, it may be emitted next.
  if (!valid_fragment) {
    if (is_visited_or_stop_pc(pc)) {
      remix_log(REMIX_LOG_EXEC, "Bailing out in patch_invalid_fragment_stub");
      // Bail out. We may not be generating code for this pc yet; we will return
      // to rr or tool code which might change our state to something quite
      // different.
      return;
    }
    valid_fragment = code_buffer.next();
  }
  Assembler emit(
      first_invalid_fragment_lookup(pc, Translation::translation_mode()));
  emit.jmp_long(valid_fragment);
}

static const uint32_t INVALIDATION_STUB_SIZE = 15;

struct InvalidateTranslatedCodeParam {
  bool save_invalidated_fragments;
};

/**
 * See "Fragment Invalidation" in the design doc.
 * The first invalid fragment for a pc is the one that gets patched when
 * a valid fragment is created and the invalid fragment gets executed. All
 * other invalid fragments just jump to the first one. This means we only
 * have to patch one site to point to a new valid fragment, while control flow
 * through any invalid fragment will reach the valid fragment after at most
 * two jumps.
 *
 * This can be called while a fragment is interrupted by a SIGSEGV signal
 * due to it writing to a PROT_WRITE_PROTECTED page --- so be careful.
 *
 * We ensure this can't OOM by ensuring there's always enough stub buffer space
 * to invalidate all extant Translations.
 */
void invalidate_translated_code(Translation* t, InvalidateTranslatedCodeParam* param) {
  app_pc pc = t->pc_start();
  remix_log(REMIX_LOG_EXEC, "Invalidating translation pc=%p at %p", pc,
            t->translation);

  if (param->save_invalidated_fragments && !t->mode) {
    auto dont_save = false;

    for (auto& f : *saved_invalid_fragments) {
      if (f.pc == pc) {
        // Prefer the longer fragment.
        if (f.pc_len >= t->pc_len) {
          dont_save = true;
          break;
        } else {
          f.resurrectable = false;
        }
      }
    }

    if (!dont_save) {
      SavedInvalidFragment frag;
      frag.pc = pc;
      frag.translation = t->translation;
      memcpy(frag.leading_bytes, frag.translation, sizeof(frag.leading_bytes));
      frag.pc_len = t->pc_len;
      frag.resurrectable = true;
      saved_invalid_fragments->push_back(frag);
    }
  }

  GeneratedCode* first_invalid_fragment =
      first_invalid_fragment_lookup(pc, t->mode);
  GeneratedCode* this_invalid_fragment = t->translation_start();
  if (first_invalid_fragment) {
    Assembler emit(this_invalid_fragment);
    emit.jmp_long(first_invalid_fragment);
  } else {
    first_invalid_fragment_insert(pc, t->mode, this_invalid_fragment);
    first_invalid_fragment = this_invalid_fragment;
  }

  // Generate a dynamic stub for "mov $pc,%r8; jmp fixup_invalid_fragment_stub"
  // and jump to it from the fragment. That means we only need 5 bytes in
  // the fragment, reducing the minimum fragment size.
  Assembler emit(first_invalid_fragment);
  emit.jmp_long(stub_buffer.next());

  Assembler dynamic_stub_emit(stub_buffer.next());
  dynamic_stub_emit.mov(pc, Assembler::Reg64::R8());
  dynamic_stub_emit.jmp_long(fixup_invalid_fragment_stub);
  remix_assert(dynamic_stub_emit.next() <= stub_buffer.next() + INVALIDATION_STUB_SIZE);
  stub_buffer.mark_allocated(dynamic_stub_emit.next());

  tool_hooks->did_invalidate();
}

static void reset_and_clear(LinearAllocator<GeneratedCode>* buffer) {
  /* Fill buffer with HLT instructions to catch any attempt to execute
     the old code. */
  memset(buffer->start(), 0xF4, buffer->next() - buffer->start());
  buffer->reset();
}

void full_reset() {
  remix_log(REMIX_LOG_EXEC, "Performing full reset");
  tool_hooks->notify_will_full_reset();
  Translation::delete_all();
  reset_and_clear(&code_buffer);
  reset_and_clear(&stub_buffer);
  data_buffer.reset();
  first_invalid_fragment_reset();
  saved_invalid_fragments->clear();
  tool_hooks->did_full_reset();
}

static void invalidate_translations(app_pc start, app_pc end) {
  InvalidateTranslatedCodeParam param = { false };
  Translation::delete_overlapping(start, end, &param);
}

void mark_unresurrectable(app_pc start, app_pc end) {
  for (auto& f : *saved_invalid_fragments) {
    if (max(f.pc, start) < min(f.pc + f.pc_len, end)) {
      f.resurrectable = false;
    }
  }
}

void invalidate_code(app_pc start, app_pc end) {
  mark_unresurrectable(start, end);
  invalidate_translations(start, end);
}

void invalidate_and_save_code(app_pc start, app_pc end) {
  remix_assert(!Translation::translation_mode());
  InvalidateTranslatedCodeParam param = { true };
  Translation::delete_overlapping(start, end, &param);
}

void resurrect_saved_fragments() {
  remix_assert(!Translation::translation_mode());
  // Delete any other fragments already translating the code we're going to resurrect.
  // Note that their start_pcs will be patched with jumps back to the
  // first invalid fragment for that pc, which will typically be the fragment(s) we're
  // about to resurrect!
  for (auto& f : *saved_invalid_fragments) {
    if (f.resurrectable) {
      invalidate_translations(f.pc, f.pc + f.pc_len);
    }
  }
  // We may be resurrecting fragments which are jumped to by other invalid fragments.
  // (See above.) That's OK because we are valid.
  for (auto& f : *saved_invalid_fragments) {
    if (f.resurrectable) {
      remix_log(REMIX_LOG_EXEC, "Resurrecting fragment %p at %p", f.pc, f.translation);
      memcpy(f.translation, f.leading_bytes, sizeof(f.leading_bytes));
      Translation::insert(f.pc, f.pc_len, f.translation);
    } else {
      remix_log(REMIX_LOG_EXEC, "Declining to resurrect fragment %p at %p", f.pc, f.translation);
    }
  }
  saved_invalid_fragments->clear();
}

RRPageSyscall remix_rr_page_syscalls[REMIX_MAX_RR_PAGE_SYSCALLS];

int match_registers() {
  remix_assert(remix_rcb == remix_target_rcb);

  auto& r1 = remix_registers;
  auto& r2 = remix_target_registers;
#define MATCH(reg)                                                             \
  if (r1.reg != r2.reg) {                                                      \
    remix_log(REMIX_LOG_EXEC, "match_registers mismatched " #reg ": %p vs %p", \
              (void*)r1.reg, (void*)r2.reg);                                   \
    return 0;                                                                  \
  }
  MATCH(rip);
  if (!match_ignore_gp_regs) {
    MATCH(rax);
    MATCH(rbx);
    MATCH(rcx);
    MATCH(rdx);
    MATCH(rsi);
    MATCH(rdi);
    MATCH(rbp);
    MATCH(rsp);
    MATCH(r8);
    MATCH(r9);
    MATCH(r10);
    MATCH(r11);
    MATCH(r12);
    MATCH(r13);
    MATCH(r14);
    MATCH(r15);
    MATCH(cs);
    MATCH(ds);
    MATCH(es);
    MATCH(fs);
    MATCH(gs);
    MATCH(ss);
    MATCH(fs_base);
    MATCH(gs_base);
    if ((intptr_t)r1.orig_rax >= 0 && (intptr_t)r2.orig_rax >= 0 &&
        r1.orig_rax != r2.orig_rax) {
      remix_log(REMIX_LOG_EXEC, "match_registers mismatched orig_rax: %p vs %p",
                (void*)r1.orig_rax, (void*)r2.orig_rax);
      return 0;
    }
  }
#undef MATCH
  // Don't match the flags register. Flags can be undefined after certain
  // instructions (e.g. DIV) and ambiguity that requires the flags to resolve
  // it probably won't happen.
  remix_log(REMIX_LOG_EXEC, "match_registers matched");
  return 1;
}

static void notify_modified_ranges_for_event(ModifiedRangeAndProt* ranges,
                                             int num_ranges) {
  // Apply all non-write changes first so that our prot data is accurate.
  // We'll need this to manipulate the write data correctly.
  for (int i = 0; i < num_ranges; ++i) {
    MemChangeType change_type = ranges[i].change_type;
    if (change_type == MEM_WRITE) {
      continue;
    }
    app_pc start = (app_pc)ranges[i].start;
    app_pc end = (app_pc)ranges[i].end;
    int prot = ranges[i].prot;
    remix_log(REMIX_LOG_EXEC, "remix_execute memory modified %p-%p %d type %d",
              start, end, prot, (int)change_type);

    if (change_type == MEM_MAP || change_type == MEM_UNMAP ||
        change_type == MEM_WRITE_BREAKPOINT) {
      invalidate_code(start, end);
    }
    if (prot >= 0) {
      InvalidateTranslatedCodeParam param = { false };
      Translation::notify_prot(start, end, prot, &param);
    }
    tool_hooks->notify_modified_range(ranges[i]);
  }

  // All ranges should either have saved_before_write_data or not. We check.
  HaveOriginalData have_original_data = HAVE_NEW_DATA;
  bool need_will_write_notifications = false;
  if (tool_hooks->needs_notify_will_write_range()) {
    for (int i = 0; i < num_ranges; ++i) {
      if (ranges[i].change_type == MEM_WRITE) {
        // saved_before_write_data can be zero if there's no previous value,
        // only
        // the new values (e.g. for writes performed during execve).
        HaveOriginalData have_data = ranges[i].saved_before_write_data
                                         ? HAVE_ORIGINAL_DATA
                                         : HAVE_NEW_DATA;
        if (need_will_write_notifications) {
          remix_assert(have_data == have_original_data);
        } else {
          need_will_write_notifications = true;
          have_original_data = have_data;
        }
      }
    }

    if (have_original_data == HAVE_ORIGINAL_DATA) {
      // Restore original memory values. All map operations have already
      // occurred so it's safe to do this.
      for (int i = num_ranges - 1; i >= 0; --i) {
        if (ranges[i].change_type == MEM_WRITE) {
          app_pc start = (app_pc)ranges[i].start;
          app_pc end = (app_pc)ranges[i].end;
          // Swap this data with the current data so that the data in memory
          // is the original data and saved_before_write_data points to the new
          // values.
          swap_app_bytes(start, (app_pc)ranges[i].saved_before_write_data,
                         end - start);
        }
      }
    }
  }

  for (int i = 0; i < num_ranges; ++i) {
    if (ranges[i].change_type != MEM_WRITE) {
      continue;
    }
    app_pc start = (app_pc)ranges[i].start;
    app_pc end = (app_pc)ranges[i].end;
    int prot = ranges[i].prot;
    remix_log(REMIX_LOG_EXEC, "remix_execute memory modified %p-%p %d type %d",
              start, end, prot, (int)MEM_WRITE);

    invalidate_code(start, end);
    if (need_will_write_notifications) {
      tool_hooks->notify_will_modify_range(ranges[i].start, end - start,
                                           have_original_data);
      app_pc start = (app_pc)ranges[i].start;
      app_pc end = (app_pc)ranges[i].end;
      if (have_original_data == HAVE_ORIGINAL_DATA) {
        // Copy the new values back.
        memcpy_to_app(start, (app_pc)ranges[i].saved_before_write_data,
                      end - start);
      }
    }
    tool_hooks->notify_modified_range(ranges[i]);
  }
}

static void notify_modified_ranges(ModifiedRangeAndProt* ranges,
                                   int num_ranges) {
  while (num_ranges > 0) {
    int range_count = 1;
    while (range_count < num_ranges &&
           ranges[range_count].event == ranges[0].event) {
      ++range_count;
    }
    notify_modified_ranges_for_event(ranges, range_count);
    ranges += range_count;
    num_ranges -= range_count;
  }
}

static uintptr_t madv_dontneed_original_start;
static uintptr_t madv_dontneed_original_end;
static uintptr_t madv_dontneed_restart_point;

void before_monitored_syscall(uint8_t is_32bit, uintptr_t return_address) {
  // On entry, all syscall parameters are set in remix_registers, and the
  // syscall number is in remix_registers.orig_rax. The syscall result is in
  // remix_registers.rax.
  // Only syscalls not incurring a stop are reported here.
  if (is_32bit) {
    remix_abort("32bit syscalls not handled yet");
  }
  switch (remix_registers.orig_rax) {
    case SYS_madvise: {
      int advice = remix_registers.rdx;
      switch (advice) {
        // If another MADV_* is ever added here, and that madvise is not a no-op
        // on pages that are not writable, write-recorder's assumptions will
        // break.
        case MADV_DONTNEED:
        case MADV_REMOVE: {
          auto start = floor_page_size(remix_registers.rdi);
          auto end = ceil_page_size(remix_registers.rdi + remix_registers.rsi);
          if (remix_range_end >= start && remix_range_start < end) {
            // There is some overlap.
            madv_dontneed_original_start = start;
            madv_dontneed_original_end = end;
            madv_dontneed_restart_point = return_address;

            // First see if the requested range is entirely within the remix range.
            if (start >= remix_range_start && end <= remix_range_end) {
              // It is. Cut the length here to 0 and break.
              remix_registers.rsi = 0;
              break;
            }

            if (start < remix_range_start) {
              // There is a left side. Do that first.
              remix_registers.rsi = remix_range_start - start;
            } else {
              remix_assert(remix_range_end < end);
              // Do the right side.
              remix_registers.rdi = remix_range_end;
              remix_registers.rsi = end - remix_range_end;
            }
          } else {
            madv_dontneed_original_start = 0;
            madv_dontneed_original_end = 0;
            madv_dontneed_restart_point = 0;
          }
          tool_hooks->notify_will_modify_range(start, end - start,
                                               HAVE_ORIGINAL_DATA);
          break;
        }
      }
      break;
    }

    default:
      break;
  }
}

uintptr_t monitored_syscall(uint8_t is_32bit) {
  // On entry, all syscall parameters are set in remix_registers, and the
  // syscall number is in remix_registers.orig_rax. The syscall result is in
  // remix_registers.rax.
  // Only syscalls not incurring a stop are reported here.
  // Take care; this could invalidate the current fragment.
  if (is_32bit) {
    remix_abort("32bit syscalls not handled yet");
  }
  switch (remix_registers.orig_rax) {
    case SYS_mprotect: {
      app_pc start = floor_page_size((app_pc)remix_registers.rdi);
      app_pc end =
          ceil_page_size((app_pc)(remix_registers.rdi + remix_registers.rsi));
      int prot = remix_registers.rdx & (PROT_READ | PROT_WRITE | PROT_EXEC);
      InvalidateTranslatedCodeParam param = { false };
      Translation::notify_prot(start, end, prot, &param);
      break;
    }

    case SYS_madvise: {
      int advice = remix_registers.rdx;
      switch (advice) {
        case MADV_DONTNEED:
        case MADV_REMOVE: {
          ModifiedRangeAndProt range;
          range.start = floor_page_size(remix_registers.rdi);
          range.end = ceil_page_size(remix_registers.rdi + remix_registers.rsi);
          range.prot = -1;
          range.event = current_event;
          range.saved_before_write_data = 0;
          range.change_type = MEM_WRITE;
          if (madv_dontneed_original_start && madv_dontneed_original_end) {
            // The requested MADV_DONTNEED range overlaps the remix range.
            if (remix_registers.rsi == 0) {
              // The requested range entirely fits inside the remix range, so we
              // ignored the syscall. Skip notify_modified_ranges.
              remix_registers.rdi = madv_dontneed_original_start;
              remix_registers.rsi = madv_dontneed_original_end - madv_dontneed_original_start;
              break;
            }

            if (remix_registers.rdi + remix_registers.rsi == remix_range_start) {
              // This is the left side. There might also be a right side we need to do.
              if (remix_range_end < madv_dontneed_original_end) {
                remix_registers.rdi = remix_range_end;
                remix_registers.rsi = madv_dontneed_original_end - remix_range_end;
                return madv_dontneed_restart_point;
              }
            }
          }
          notify_modified_ranges(&range, 1);
          if (madv_dontneed_original_start && madv_dontneed_original_end) {
            remix_registers.rdi = madv_dontneed_original_start;
            remix_registers.rsi = madv_dontneed_original_end - madv_dontneed_original_start;
          }
          break;
        }
      }
      break;
    }

    default:
      break;
  }
  return 0;
}

static const char* stop_mode_str() {
#define CASE(s)                                                                \
  case s:                                                                      \
    return #s
  switch (stop_mode) {
    CASE(STOP_AT_IP);
    CASE(STOP_AT_IP_EMULATE);
    CASE(STOP_AT_SYSCALL);
    CASE(STOP_AT_TARGET);
    CASE(STOP_AT_BREAKPOINT_FAULT);
    default:
      return "???";
  }
#undef CASE
}

static const char* singlestep_mode_str() {
#define CASE(s)                                                                \
  case s:                                                                      \
    return #s
  switch (singlestep_mode) {
    CASE(STOP_SINGLESTEP_NONE);
    CASE(STOP_SINGLESTEP);
    CASE(STOP_SINGLESTEP_FAST_FORWARD);
    default:
      return "???";
  }
#undef CASE
}

static const char* stop_reason_str(StopReason reason) {
#define CASE(s)                                                                \
  case s:                                                                      \
    return #s
  switch (reason) {
    CASE(STOPPED_NULL);
    CASE(STOPPED_NORMALLY);
    CASE(STOPPED_BREAKPOINT);
    CASE(STOPPED_SINGLESTEP);
    CASE(STOPPED_SYNC_SIGNAL);
    default:
      return "???";
  }
#undef CASE
}

static bool reached_target() {
  // Only translations in mode 0 represent normal replay
  if (Translation::translation_mode()) {
    return false;
  }
  if (stop_mode == STOP_AT_BREAKPOINT_FAULT &&
      stop_pc == (void*)remix_registers.rip && intptr_t(remix_registers.rsi) < 0) {
    return true;
  }
  if (stop_mode != STOP_AT_TARGET || remix_rcb < remix_target_rcb ||
      !match_registers()) {
    return false;
  }
  // When a singlestep SIGTRAP fires, we record this as an event
  // leading to a SIGTRAP signal which clears TF and is replayed
  // via STOP_AT_TARGET. So update TF here.
  extra_rflags = remix_target_registers.eflags;
  return true;
}

static StopReason finish_execute(StopReason reason) {
  remix_assert(!patch_callback);
  remix_log(REMIX_LOG_EXEC, "remix_execute %s pc=%p", stop_reason_str(reason),
            (void*)remix_registers.rip);
  flush_pending_fip();
  if (stop_pc) {
    invalidate_translations(stop_pc, stop_pc + 1);
    resurrect_saved_fragments();
    stop_pc = nullptr;
  }
  tool_hooks->notify_did_execute();
  remix_registers.eflags |= extra_rflags & (RFLAG_AC | RFLAG_TF);

  return reason;
}

void remix_notify_modified_ranges(ModifiedRangeAndProt* ranges,
                                  int num_ranges) {
  AutoSaveRestoreState save_state;
  notify_modified_ranges(ranges, num_ranges);
}

StopReason remix_execute(uint32_t flags, ModifiedRangeAndProt* ranges,
                         int num_ranges, pid_t rec_tid, uint32_t rec_tid_serial,
                         TraceFrameTime event) {
  AutoSaveRestoreState save_state;

  remix_assert(!pending_fip);
  extra_rflags = remix_registers.eflags;
  remix_registers.eflags &= ~(RFLAG_AC | RFLAG_TF);

  notify_modified_ranges(ranges, num_ranges);

  tool_hooks->notify_will_execute(rec_tid, rec_tid_serial, event);
  current_event = event;

  stop_mode = flags & STOP_AT_MASK;
  singlestep_mode = flags & STOP_SINGLESTEP_MASK;
  match_ignore_gp_regs = (flags & STOP_MATCH_IGNORE_GP_REGS) != 0;
  stop_flag = false;
  breakpoint_flag = false;
  sync_signal_flag = false;

  remix_log(REMIX_LOG_EXEC, "remix_execute pc=%p stop=%s singlestep=%s",
            (void*)remix_registers.rip, stop_mode_str(), singlestep_mode_str());

  if (stop_mode == STOP_AT_IP || stop_mode == STOP_AT_IP_EMULATE ||
      stop_mode == STOP_AT_TARGET || stop_mode == STOP_AT_BREAKPOINT_FAULT) {
    stop_pc = (app_pc)remix_target_registers.rip;
    remix_log(REMIX_LOG_EXEC, "stop_pc=%p", stop_pc);
    invalidate_and_save_code(stop_pc, stop_pc + 1);
  }
  if (singlestep_mode) {
    app_pc pc = (app_pc)remix_registers.rip;
    // Build a new trace here, because we need to build a trace of just one
    // instruction.
    invalidate_code(pc, pc + 1);
  }

  while (true) {
    app_pc pc = (app_pc)remix_registers.rip;

    if (is_visited_pc(pc)) {
      tool_hooks->notify_visit_pc(pc);
      pc = (app_pc)remix_registers.rip;
    }

    Fragment fragment = Translation::lookup(pc);
    bool already_run = false;

    if (fragment) {
      // The generated fragment is responsible for checking reached_target() so
      // we don't need to here.
      // We're going to run something. Clear orig_rax as the kernel would.
      remix_registers.orig_rax = -1;
    } else {
      // See if we've reached our target now. When the application crashes
      // with invalid PC, we'll reach this and we need to stop before we try
      // to translate it.
      if (reached_target()) {
        return finish_execute(STOPPED_NORMALLY);
      }

      // We're going to run something. Clear orig_rax as the kernel would.
      remix_registers.orig_rax = -1;

      Fragment first_fragment = fragment = code_buffer.next();
      bool reset_after_out_of_memory = false;
      while (true) {
        // 64K is pretty generous since a fragment can only translate up to
        // 255 bytes of application code.
        // Make sure that we have enough stub space to allocate an invalidation
        // stub for every current Translation.
        if (code_buffer.remaining() < 64 * 1024 ||
            stub_buffer.remaining() < 64 * 1024 +
                Translation::translations_count() * INVALIDATION_STUB_SIZE ||
            data_buffer.remaining() < 64 * 1024) {
          if (reset_after_out_of_memory) {
            remix_abort(
                "Not enough space in code buffer to translate anything");
          }
          // Reset everything
          reset_after_out_of_memory = true;
          full_reset();
          first_fragment = fragment = code_buffer.next();
          pc = (app_pc)remix_registers.rip;
          continue;
        }

        auto generated = tool_hooks->generate_one_fragment(pc, first_fragment);
        if (singlestep_mode) {
          remix_assert(!generated.have_next_pc);
        }
        if (!generated.have_next_pc) {
          already_run = generated.did_run;
          break;
        }
        if (generated.did_run && !stop_flag) {
          // Keep generating code, but start execution at the new fragment.
          first_fragment = fragment = code_buffer.next();
          // We made progress, so we can try again after OOM
          reset_after_out_of_memory = false;
          if (reached_target()) {
            return finish_execute(STOPPED_NORMALLY);
          }
        }
        pc = generated.next_pc;
#ifdef DEBUG
        // Fragments should end at visited-PCs without generating a next-pc.
        remix_assert(!is_visited_pc(pc));
#endif
      }
    }

    if (!already_run) {
      remix_log(REMIX_LOG_EXEC,
                "Executing pc=%p at %p, rcb=%lld, event=%d (mode %d)",
                (app_pc)remix_registers.rip,
                fragment, (long long)remix_rcb, event,
                Translation::translation_mode());
      run_fragment(fragment);
    }

    if (singlestep_mode) {
      // Now that we've run the fragment, invalidate it because it may
      // depend on being in singlestep mode.
      invalidate_code(pc, pc + 1);
    }
    if (patch_callback) {
      patch_callback();
      patch_callback = nullptr;
    }
    if (stop_flag) {
      if (breakpoint_flag) {
        if (singlestep_mode) {
          return finish_execute(STOPPED_SINGLESTEP);
        }
        return finish_execute(STOPPED_BREAKPOINT);
      }
      if (sync_signal_flag) {
        return finish_execute(STOPPED_SYNC_SIGNAL);
      }
      return finish_execute(STOPPED_NORMALLY);
    }
    if (singlestep_mode) {
      return finish_execute(STOPPED_SINGLESTEP);
    }
    remix_log(REMIX_LOG_EXEC, "Continuing with pc=%p, rcb=%lld (mode %d)",
              (void*)remix_registers.rip, (long long)remix_rcb,
              Translation::translation_mode());
  }
}

/* Called for SIGSEGVs that faulted on a PROT_WRITE | PROT_EXEC page. */
void wx_sighandler_internal() {
  AutoSaveRestoreState save_state;
  InvalidateTranslatedCodeParam param = { false };
  auto invalidated_range = Translation::remove_write_protection((app_pc)remix_sighandler_state.fault_address, &param);
  mark_unresurrectable(invalidated_range.start, invalidated_range.end);
}

void engine_exit() {
  Translation::dump_translation_chain_lengths();
}

REMIX_TARGET_END
