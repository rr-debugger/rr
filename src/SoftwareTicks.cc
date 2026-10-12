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

// The tick sequences up to and including their trap instruction
// (include/rr/softticks.h).
static const uint8_t tick_x64[] = {
  0x48, 0xff, 0x0c, 0x25, 0x00, 0x18, 0x00, 0x70, // decq 0x70001800
  0x75, 0x01,                                     // jnz 1f
  0xcc                                            // int3
};
static const uint8_t tick_x86[] = {
  0x83, 0x2d, 0x00, 0x18, 0x00, 0x70, 0x01, // subl $1, 0x70001800
  0x75, 0x0a,                               // jnz 1f
  0x83, 0x2d, 0x04, 0x18, 0x00, 0x70, 0x01, // subl $1, 0x70001804
  0x73, 0x01,                               // jae 1f (no borrow)
  0xcc                                      // int3
};
static const uint8_t tick_arm64[] = {
  0x30, 0x00, 0xae, 0xd2, // movz x16, #0x7001, lsl #16
  0x11, 0x02, 0x44, 0xf9, // ldr x17, [x16, #0x800]
  0x31, 0x06, 0x00, 0xd1, // sub x17, x17, #1
  0x11, 0x02, 0x04, 0xf9, // str x17, [x16, #0x800]
  0x51, 0x00, 0x00, 0xb5, // cbnz x17, 1f
  0x80, 0x6a, 0x2a, 0xd4  // brk #0x5354
};

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

bool is_software_tick_trap(Task* t) {
  const uint8_t* seq;
  size_t len;
  size_t trap_len;
  const siginfo_t& si = t->get_siginfo();
  switch (t->arch()) {
    case x86_64:
      seq = tick_x64;
      len = sizeof(tick_x64);
      trap_len = 1;
      break;
    case x86:
      seq = tick_x86;
      len = sizeof(tick_x86);
      trap_len = 1;
      break;
    case aarch64:
      seq = tick_arm64;
      len = sizeof(tick_arm64);
      trap_len = 4;
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
  uint8_t buf[sizeof(tick_arm64)];
  if (!read_code(t, trap + trap_len - len, len, buf)) {
    return false;
  }
  return !memcmp(buf, seq, len);
}

bool complete_software_tick_sequence(Task* t) {
  // The offsets of the instructions after the commit (the decrement): jnz and
  // int3 (x86-64); jnz, the borrow's subl, jae and int3 (i386); cbnz and brk
  // (aarch64).
  static const size_t x64_after_commit[] = { 8, 10 };
  static const size_t x86_after_commit[] = { 7, 9, 16, 18 };
  static const size_t arm64_after_commit[] = { 16, 20 };
  const uint8_t* seq;
  size_t len;
  size_t seq_end;
  const size_t* offsets;
  size_t noffsets;
  switch (t->arch()) {
    case x86_64:
      seq = tick_x64;
      len = sizeof(tick_x64);
      seq_end = len;
      offsets = x64_after_commit;
      noffsets = 2;
      break;
    case x86:
      seq = tick_x86;
      len = sizeof(tick_x86);
      seq_end = len;
      offsets = x86_after_commit;
      noffsets = 4;
      break;
    case aarch64:
      seq = tick_arm64;
      len = sizeof(tick_arm64);
      seq_end = len + 4;
      offsets = arm64_after_commit;
      noffsets = 2;
      break;
    default:
      return false;
  }
  uintptr_t pc = t->ip().register_value();
  uint8_t buf[sizeof(tick_arm64)];
  for (size_t i = 0; i < noffsets; ++i) {
    uintptr_t start = pc - offsets[i];
    if (!read_code(t, start, len, buf) || memcmp(buf, seq, len)) {
      continue;
    }
    LOG(debug) << "  stopped inside a tick sequence at " << t->ip()
               << "; completing it";
    Registers r = t->regs();
    r.set_ip(remote_code_ptr(start + seq_end));
    t->set_regs(r);
    return true;
  }
  return false;
}

// Whether t, an i386 task, is stopped between a tick's two subl instructions:
// after the low word reached 0 (ZF set) and before the borrow from the high
// word, i.e. at the jnz or at the second subl. Or just after an int3 that rr
// put there for a breakpoint: the pc is then 1 byte into the instruction
// (which no jump targets), before rr moves it back.
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
  for (size_t offset : { 7, 9, 8, 10 }) {
    if (read_code(t, pc - offset, sizeof(buf), buf) &&
        !memcmp(buf, tick_x86, sizeof(buf))) {
      LOG(debug) << "  stopped at " << r.ip()
                 << " before a tick's borrow from the high word";
      return true;
    }
  }
  return false;
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
