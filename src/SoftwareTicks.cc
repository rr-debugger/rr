/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "SoftwareTicks.h"

#include <string.h>

#include <algorithm>

#include "AddressSpace.h"
#include "ElfReader.h"
#include "Task.h"
#include "log.h"
#include "preload/preload_interface.h"

namespace rr {

static bool software_ticks_mode_;

bool software_ticks_mode() { return software_ticks_mode_; }

void set_software_ticks_mode(bool on) { software_ticks_mode_ = on; }

remote_ptr<uint64_t> software_ticks_countdown_address() {
  return remote_ptr<uint64_t>(SOFTWARE_TICKS_COUNTDOWN_ADDR);
}

uint32_t read_software_ticks_note(ElfFileReader& reader) {
  if (!reader.ok()) {
    return 0;
  }
  SectionOffsets offsets =
      reader.find_section_file_offsets(RR_SOFTWARE_TICKS_NOTE_SECTION);
  if (!offsets.start) {
    return 0;
  }
  uint64_t off = offsets.start;
  while (off + 12 <= offsets.end) {
    auto hdr = reader.read<uint32_t>(off, 3);
    if (!hdr) {
      return 0;
    }
    uint32_t namesz = hdr[0];
    uint32_t descsz = hdr[1];
    uint32_t type = hdr[2];
    uint64_t name_off = off + 12;
    uint64_t desc_off = name_off + ((uint64_t(namesz) + 3) & ~uint64_t(3));
    uint64_t next = desc_off + ((uint64_t(descsz) + 3) & ~uint64_t(3));
    if (next > offsets.end) {
      return 0;
    }
    if (namesz == 3 && descsz == 4 && type == SOFTWARE_TICKS_NOTE_TYPE) {
      auto name = reader.read<char>(name_off, 3);
      if (name && !memcmp(name, "rr", 3)) {
        auto desc = reader.read<uint32_t>(desc_off);
        return desc ? *desc : 0;
      }
    }
    off = next;
  }
  return 0;
}

// Whether t's address space has a countdown we may use: the
// preload_thread_locals mapping rr created (not one the tracee mapped over it,
// nor one a task inherited before its first exec, e.g. from a parent that is
// itself a tracee of an outer rr), still writable. Otherwise nothing is armed
// or read: writing to some other mapping would change the tracee's memory, and
// writing through a mapping that is not writable (safe_pwrite64) makes remote
// mprotect calls, which clobber the registers that resume_execution has
// already flushed when it starts the counter. The tracee mapping over the page
// is recorded, so replay decides the same way.
static bool software_ticks_slot_usable(Task* t) {
  remote_ptr<void> start = AddressSpace::preload_thread_locals_start();
  if (!t->vm()->has_mapping(start)) {
    return false;
  }
  const AddressSpace::Mapping& m = t->vm()->mapping_of(start);
  return (m.flags & AddressSpace::Mapping::IS_THREAD_LOCALS) &&
         (m.map.prot() & PROT_WRITE) &&
         software_ticks_countdown_address().as_int() + sizeof(uint64_t) <=
             m.map.end().as_int();
}

bool read_software_ticks_slot(Task* t, uint64_t* value) {
  if (!software_ticks_slot_usable(t)) {
    return false;
  }
  return t->read_bytes_fallible(software_ticks_countdown_address(),
                                sizeof(*value), value) == sizeof(*value);
}

bool write_software_ticks_slot(Task* t, uint64_t value) {
  if (!software_ticks_slot_usable(t)) {
    return false;
  }
  bool ok = true;
  t->write_bytes_helper_no_notifications(software_ticks_countdown_address(),
                                         sizeof(value), &value, &ok);
  return ok;
}

void init_software_ticks_slot(Task* t) {
  write_software_ticks_slot(t, SOFTWARE_TICKS_PARKED);
  t->vm()->set_software_ticks_owner(TaskUid());
}

// The tick sequences (include/rr/softticks.h), with their offsets. Each
// first tests the countdown's top bit (the guard) and skips the tick while it
// is set (the countdown is disarmed).
static const uint8_t tick_x64[] = {
  0xf6, 0x04, 0x25, 0x07, 0x18, 0x00, 0x70, 0x80, // 0: testb $0x80, 0x70001807
  0x75, 0x0b,                                     // 8: jnz 1f
  0x48, 0xff, 0x0c, 0x25, 0x00, 0x18, 0x00, 0x70, // 10: decq 0x70001800
  0x75, 0x01,                                     // 18: jnz 1f
  0xcc                                            // 20: int3
};
static const uint8_t tick_x86[] = {
  0xf6, 0x05, 0x07, 0x18, 0x00, 0x70, 0x80, // 0: testb $0x80, 0x70001807
  0x75, 0x13,                               // 7: jnz 1f
  0x83, 0x2d, 0x00, 0x18, 0x00, 0x70, 0x01, // 9: subl $1, 0x70001800
  0x75, 0x0a,                               // 16: jnz 1f
  0x83, 0x2d, 0x04, 0x18, 0x00, 0x70, 0x01, // 18: subl $1, 0x70001804
  0x73, 0x01,                               // 25: jae 1f (no borrow)
  0xcc                                      // 27: int3
};
static const uint8_t tick_arm64[] = {
  0x30, 0x00, 0xae, 0xd2, // 0: movz x16, #0x7001, lsl #16
  0x11, 0x02, 0x44, 0xf9, // 4: ldr x17, [x16, #0x800]
  0xb1, 0x00, 0xf8, 0xb7, // 8: tbnz x17, #63, 1f
  0x31, 0x06, 0x00, 0xd1, // 12: sub x17, x17, #1
  0x11, 0x02, 0x04, 0xf9, // 16: str x17, [x16, #0x800]
  0x51, 0x00, 0x00, 0xb5, // 20: cbnz x17, 1f
  0x80, 0x6a, 0x2a, 0xd4, // 24: brk #0x5354
  0xf1, 0x03, 0x1f, 0xaa  // 28: 1: mov x17, xzr
};
// The longest of them, for buffers.
static const size_t TICK_MAX_SIZE = sizeof(tick_arm64);
static_assert(sizeof(tick_x64) <= TICK_MAX_SIZE &&
                  sizeof(tick_x86) <= TICK_MAX_SIZE,
              "tick buffers too small");

// Whether an aarch64 tick stopped at |offset| in its sequence, with |x17|, is
// yet to commit, and will: from the tbnz to the str (the commit), except at
// the tbnz when the ldr loaded a disarmed countdown (x17's top bit set), where
// the guard skips the tick and stores nothing.
static bool arm64_commit_ahead(size_t offset, uint64_t x17) {
  return offset >= 8 && offset < 20 && !(offset == 8 && (x17 >> 63));
}

// Read code from t's memory as the program has it: without the int3s of rr's
// breakpoints (a debugger's breakpoint may be inside a tick sequence).
static bool read_code(Task* t, uintptr_t addr, size_t len, uint8_t* buf) {
  if (t->read_bytes_fallible(remote_ptr<void>(addr), len, buf) != (ssize_t)len) {
    return false;
  }
  t->vm()->replace_breakpoints_with_original_values(buf, len,
                                                    remote_ptr<uint8_t>(addr));
  return true;
}

bool is_software_tick_trap(Task* t, const siginfo_t& si) {
  // Only our countdown's traps are ours. Where the page at the countdown's
  // address is not the one we created (software_ticks_slot_usable), we never
  // arm a countdown, so a tick trap there comes from a countdown that someone
  // else programs, e.g. an rr that is our tracee recording or replaying its
  // own tracee: it is an ordinary SIGTRAP for the tracee (or its ptracer).
  if (!software_ticks_slot_usable(t)) {
    return false;
  }
  const uint8_t* seq;
  size_t len;
  // The trap instruction's offset in the sequence.
  size_t trap_offset;
  switch (t->arch()) {
    case x86_64:
      seq = tick_x64;
      len = sizeof(tick_x64);
      trap_offset = 20;
      break;
    case x86:
      seq = tick_x86;
      len = sizeof(tick_x86);
      trap_offset = 27;
      break;
    case aarch64:
      seq = tick_arm64;
      len = sizeof(tick_arm64);
      trap_offset = 24;
      break;
    default:
      return false;
  }
  if (is_x86ish(t->arch()) ? si.si_code != SI_KERNEL
                           : si.si_code != TRAP_BRKPT) {
    return false;
  }
  // The trap instruction's address: on x86 the pc is after the int3.
  uintptr_t trap = t->ip().register_value() - (is_x86ish(t->arch()) ? 1 : 0);
  if (t->vm()->get_breakpoint_type_at_addr(remote_code_ptr(trap)) !=
      BKPT_NONE) {
    return false;
  }
  uint8_t buf[TICK_MAX_SIZE];
  if (!read_code(t, trap - trap_offset, len, buf)) {
    return false;
  }
  return !memcmp(buf, seq, len);
}

Ticks complete_software_tick_sequence(Task* t) {
  // Without our countdown (see is_software_tick_trap), the trap that the rest
  // of the sequence may execute is not ours to drop.
  if (!software_ticks_slot_usable(t)) {
    return 0;
  }
  // The offsets of the instructions after the commit (the decrement): jnz and
  // int3 (x86-64); jnz, the borrow's subl, jae and int3 (i386). Before the
  // commit the x86 flags come from the guard's testb of the countdown's top
  // bit, which is clear while the task runs, in recording and replay alike. On
  // aarch64 x17 holds the countdown from the ldr until the mov at the end
  // clears it, so also the instructions before the commit (the str): tbnz, sub
  // and str, then cbnz, brk and mov (which the tbnz jumps to when the guard
  // skips the tick).
  static const size_t x64_offsets[] = { 18, 20 };
  static const size_t x86_offsets[] = { 16, 18, 25, 27 };
  static const size_t arm64_offsets[] = { 8, 12, 16, 20, 24, 28 };
  const uint8_t* seq;
  size_t len;
  const size_t* offsets;
  size_t noffsets;
  switch (t->arch()) {
    case x86_64:
      seq = tick_x64;
      len = sizeof(tick_x64);
      offsets = x64_offsets;
      noffsets = sizeof(x64_offsets) / sizeof(x64_offsets[0]);
      break;
    case x86:
      seq = tick_x86;
      len = sizeof(tick_x86);
      offsets = x86_offsets;
      noffsets = sizeof(x86_offsets) / sizeof(x86_offsets[0]);
      break;
    case aarch64:
      seq = tick_arm64;
      len = sizeof(tick_arm64);
      offsets = arm64_offsets;
      noffsets = sizeof(arm64_offsets) / sizeof(arm64_offsets[0]);
      break;
    default:
      return 0;
  }
  uintptr_t pc = t->ip().register_value();
  uint8_t buf[TICK_MAX_SIZE];
  for (size_t i = 0; i < noffsets; ++i) {
    uintptr_t start = pc - offsets[i];
    if (!read_code(t, start, len, buf) || memcmp(buf, seq, len)) {
      continue;
    }
    // Before the commit (only on aarch64) the counters have not counted the
    // tick (the countdown still holds what the ldr loaded): completing commits
    // it, if the tick would commit at all.
    Ticks committed = 0;
    if (t->arch() == aarch64 &&
        arm64_commit_ahead(offsets[i], t->regs().x(17))) {
      committed = 1;
    }
    LOG(debug) << "  stopped inside a tick sequence at " << t->ip()
               << "; completing it" << (committed ? " and its tick" : "");
    Registers r = t->regs();
    r.set_ip(remote_code_ptr(start + len));
    if (t->arch() == aarch64) {
      // What the mov at the end does.
      r.set_x(17, 0);
    }
    t->set_regs(r);
    return committed;
  }
  return 0;
}

// Whether t, an i386 task, is stopped between a tick's two subl instructions:
// after the low word reached 0 (ZF set) and before the borrow from the high
// word, i.e. at the jnz (offset 16) or at the second subl (18). Or just after
// an int3 that rr put there for a breakpoint: the pc is then 1 byte into the
// instruction (which no jump targets), before rr moves it back.
static bool x86_borrow_pending(Task* t) {
  // A task whose stop we have not processed has no registers to look at. (A
  // task blocked in the kernel is not inside a tick sequence.)
  if (!t->stopped_or_unexpected_exit()) {
    return false;
  }
  const Registers& r = t->regs();
  if (!r.zf_flag()) {
    return false;
  }
  uintptr_t pc = r.ip().register_value();
  uint8_t buf[sizeof(tick_x86)];
  for (size_t offset : { 16, 18, 17, 19 }) {
    if (read_code(t, pc - offset, sizeof(buf), buf) &&
        !memcmp(buf, tick_x86, sizeof(buf))) {
      LOG(debug) << "  stopped at " << r.ip()
                 << " before a tick's borrow from the high word";
      return true;
    }
  }
  return false;
}

// Whether t, an aarch64 task, is stopped between a tick's ldr and its str
// (the commit), with the commit ahead (arm64_commit_ahead), where x17 holds
// what the str will store: the countdown the ldr loaded, less 1 once the sub
// has run. Returns the offset in the sequence (8: at the tbnz; 12: at the sub;
// 16: at the str), else 0. (On aarch64 rr's breakpoints do not move the pc.)
static size_t arm64_commit_pending(Task* t) {
  // As in x86_borrow_pending.
  if (!t->stopped_or_unexpected_exit()) {
    return 0;
  }
  const Registers& r = t->regs();
  // Cheap test first: from the movz on, x16 holds the countdown's page.
  if (r.x(16) != PRELOAD_THREAD_LOCALS_ADDR) {
    return 0;
  }
  uintptr_t pc = r.ip().register_value();
  // Then the instruction at the pc (tbnz, sub or str), before the whole
  // sequence.
  uint8_t insn[4];
  if (!read_code(t, pc, sizeof(insn), insn)) {
    return 0;
  }
  size_t offset = 0;
  for (size_t o : { 8, 12, 16 }) {
    if (!memcmp(insn, tick_arm64 + o, sizeof(insn))) {
      offset = o;
      break;
    }
  }
  if (!arm64_commit_ahead(offset, r.x(17))) {
    return 0;
  }
  uint8_t buf[sizeof(tick_arm64)];
  if (!read_code(t, pc - offset, sizeof(buf), buf) ||
      memcmp(buf, tick_arm64, sizeof(buf))) {
    return 0;
  }
  LOG(debug) << "  stopped at " << r.ip()
             << " before a tick's store to the countdown";
  return offset;
}

void rebase_pending_software_tick(Task* t, uint64_t slot) {
  if (t->arch() != aarch64) {
    return;
  }
  size_t offset = arm64_commit_pending(t);
  if (!offset) {
    return;
  }
  // As if the ldr had loaded the countdown just armed (top bit clear, so a
  // stop at the tbnz still commits): the str then commits one tick against it,
  // and the trap comes when that runs out.
  Registers r = t->regs();
  r.set_x(17, offset == 16 ? slot - 1 : slot);
  t->set_regs(r);
  // resume_execution has flushed the registers when it starts the counter.
  t->flush_regs();
}

static const uint64_t X86_LOW_WORD = uint64_t(1) << 32;

uint64_t software_ticks_remaining(Task* t, uint64_t slot) {
  if (t->arch() != x86) {
    return slot;
  }
  uint64_t ret = slot;
  if (uint32_t(slot) == 0) {
    ret += X86_LOW_WORD;
  }
  if (x86_borrow_pending(t)) {
    ret -= X86_LOW_WORD;
  }
  return ret;
}

uint64_t software_ticks_slot_for(Task* t, uint64_t remaining) {
  if (t->arch() != x86) {
    return remaining;
  }
  uint64_t ret = remaining;
  if (uint32_t(remaining) == 0) {
    ret -= X86_LOW_WORD;
  }
  if (x86_borrow_pending(t)) {
    // The pending borrow takes it back off.
    ret += X86_LOW_WORD;
  }
  return ret;
}

size_t software_ticks_thread_locals_size() {
  return std::max<size_t>(PRELOAD_THREAD_LOCALS_SIZE,
                          SOFTWARE_TICKS_COUNTDOWN_ADDR -
                              PRELOAD_THREAD_LOCALS_ADDR + sizeof(uint64_t));
}

void normalize_software_ticks_slot(uint8_t* page, size_t size) {
  size_t off = SOFTWARE_TICKS_COUNTDOWN_ADDR - PRELOAD_THREAD_LOCALS_ADDR;
  if (size >= off + sizeof(uint64_t)) {
    memset(page + off, 0, sizeof(uint64_t));
  }
}

} // namespace rr
