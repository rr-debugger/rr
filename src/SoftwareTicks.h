/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_SOFTWARE_TICKS_H_
#define RR_SOFTWARE_TICKS_H_

#include <stdint.h>
#include <stddef.h>

#include "remote_ptr.h"

/**
 * Software ticks (TICKS_SOFTWARE). A program built with a software-ticks
 * compiler pass counts its own ticks: the pass places a tick so that no
 * instrumented instruction executes twice in the same stack frame without a
 * tick in between (at function entries, loop headers and after returns_twice
 * calls). A tick decrements a countdown at SOFTWARE_TICKS_COUNTDOWN_ADDR, in
 * the preload thread-locals page, and traps when it reaches 0
 * (include/rr/softticks.h is the tracee ABI). With TICKS_SOFTWARE,
 * PerfCounters programs that countdown instead of the PMU, and
 * Task::did_waitpid turns a tick trap into the TIME_SLICE_SIGNAL stop the PMU
 * would have caused, so the rest of the recorder and the replayer work
 * unchanged. Such a program carries the note RR_SOFTWARE_TICKS_NOTE_SECTION;
 * rr records it with software ticks when it is the program rr starts.
 *
 * The countdown is per address space, not per task: rr runs one task at a
 * time, and PerfCounters::start takes it over for the task it resumes, first
 * counting the ticks of the task that had it.
 */

namespace rr {

class ElfFileReader;
class Task;

/* The tracee ABI version rr implements (Header.softwareTicks.abiVersion and
 * the descriptor of the .note.rrsoftticks note). */
const uint32_t SOFTWARE_TICKS_ABI_VERSION = 1;

#define RR_SOFTWARE_TICKS_NOTE_SECTION ".note.rrsoftticks"
const uint32_t SOFTWARE_TICKS_NOTE_TYPE = 1;

/* The slot's value while no task's countdown is armed (2^64 - 1 ticks to go,
 * on every architecture). rr writes it when it creates the preload
 * thread-locals page (the page's creator must disarm the countdown) and when
 * a task stops. */
const uint64_t SOFTWARE_TICKS_PARKED = 0xFFFFFFFFFFFFFFFFULL;

/* The countdown rr arms when it wants no interrupt (as for the PMU). */
const uint64_t SOFTWARE_TICKS_UNLIMITED = uint64_t(1) << 60;

remote_ptr<uint64_t> software_ticks_countdown_address();

/* Whether this recording or replay counts software ticks. Set before the
 * session is created, so that PerfCounters::default_ticks_semantics() never
 * touches the PMU. */
bool software_ticks_mode();
void set_software_ticks_mode(bool on);

/* The ABI version of the file's .note.rrsoftticks note, or 0 if it has none. */
uint32_t read_software_ticks_note(ElfFileReader& reader);

/* Called after rr creates a preload thread-locals page: park the countdown. */
void init_software_ticks_slot(Task* t);

/* Whether t's current SIGTRAP stop is a tick trap: the trap instruction of a
 * tick sequence (x86: the pc is after the int3; aarch64: at the brk), not one
 * of rr's breakpoints. It need not have found the countdown at 0: a tick whose
 * trap was pending at an earlier stop traps when the task resumes, and is
 * treated the same way. */
bool is_software_tick_trap(Task* t);

/* When recording, move a task stopped between a tick's decrement and the end
 * of its sequence to the end of the sequence. What lies in between (the
 * branch on the result; on i386 the borrow from the high word and a second
 * branch; the trap) only affects the countdown and whether the trap runs,
 * which depend on the countdown's value, which replay programs differently: a
 * recorded event there could not be found again. The task's counters have
 * already been stopped, which counted the tick and parked the countdown, and
 * they are re-armed before it runs again, so completing the sequence only
 * drops a pending tick trap, i.e. a time-slice interrupt that the stop has
 * made moot (and on i386 a borrow that no longer applies to anything).
 * Returns whether the pc moved. */
bool complete_software_tick_sequence(Task* t);

/* Zero the countdown's slot in a copy of a preload thread-locals page (for
 * memory checksums: recording and replay program different values there). */
void normalize_software_ticks_slot(uint8_t* page, size_t size);

/* The size of the preload_thread_locals segment: PRELOAD_THREAD_LOCALS_SIZE
 * would end the shared file before the countdown, and the kernel does not
 * keep what is written to a shared mapping's page beyond the end of the file,
 * so the segment covers the countdown too. */
size_t software_ticks_thread_locals_size();

/* Read and write the slot through t's memory. */
bool read_software_ticks_slot(Task* t, uint64_t* value);
bool write_software_ticks_slot(Task* t, uint64_t value);

/* The number of ticks t executes before its tick traps (0: the trap is due),
 * given the slot's value. On x86-64 and aarch64 that is the slot's value. On
 * i386 the countdown is 64 bits but decremented one 32-bit word at a time:
 * when a tick takes the low word to 0 it borrows from the high word in a
 * second instruction, and traps if the high word was 0. With lo and hi the
 * two words, it is hi * 2^32 + lo, where a low word of 0 counts as 2^32 (the
 * borrow has been taken), less 2^32 while t is stopped between the two
 * instructions (the borrow is still to come), modulo 2^64. So it depends on
 * where t is stopped, and is unchanged by the borrow itself. */
uint64_t software_ticks_remaining(Task* t, uint64_t slot);

/* The slot value that makes software_ticks_remaining(t, slot) == remaining
 * (1 <= remaining < 2^63). */
uint64_t software_ticks_slot_for(Task* t, uint64_t remaining);

} // namespace rr

#endif /* RR_SOFTWARE_TICKS_H_ */
