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

/* The slot's value while no task's countdown is armed: on i386 its high word
 * is the "disarmed" word, nonzero, so 32-bit code never traps; as a 64-bit
 * countdown it never reaches 0 either. rr writes it when it creates the
 * preload thread-locals page (the page's creator must disarm the countdown)
 * and when a task stops. */
const uint64_t SOFTWARE_TICKS_PARKED = 0xFFFFFFFF00000000ULL;

/* The largest countdown rr arms. The i386 countdown has 32 bits, and keeping
 * the 64-bit one in the same range lets one 8-byte write arm either (low
 * word: the countdown, high word: 0, which on i386 means armed). A longer
 * request traps early, like a stray PMU interrupt. */
const uint32_t SOFTWARE_TICKS_MAX_PERIOD = 0xFFFFFFFF;

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
 * branch on the result, the trap) has no effect but the trap, and whether it
 * runs depends on the countdown's value, which replay programs differently: a
 * recorded event there could not be found again. Completing the sequence
 * only drops a pending tick trap, i.e. a time-slice interrupt that the stop
 * has made moot. Returns whether the pc moved. */
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

} // namespace rr

#endif /* RR_SOFTWARE_TICKS_H_ */
