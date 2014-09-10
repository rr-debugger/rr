/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_TYPES_H_
#define RR_TYPES_H_

#include <linux/limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <string>

/**
 * command line arguments for rr
 */

#define DUMP_ON_ALL 10000
#define DUMP_ON_NONE -DUMP_ON_ALL

#define DUMP_AT_NONE -1

#define CHECKSUM_NONE -3
#define CHECKSUM_SYSCALL -2
#define CHECKSUM_ALL -1

// We let users specify which process should be "created" before
// starting a debug session for it.  Problem is, "process" in this
// context is ambiguous.  It could mean the "thread group", which is
// created at fork().  Or it could mean the "address space", which is
// created at exec() (after the fork).
//
// We force choosers to specify which they mean, and default to the
// much more useful (and probably common) exec() definition.
enum {
  CREATED_DEFAULT = 0,
  CREATED_EXEC,
  CREATED_FORK
};

struct Flags {
  /* Max counter value before the scheduler interrupts a tracee. */
  int max_rbc;
  /* Max number of trace events before the scheduler
   * de-schedules a tracee. */
  int max_events;
  /* Whenever |ignore_sig| is pending for a tracee, decline to
   * deliver it. */
  int ignore_sig;
  bool redirect;
  bool use_syscall_buffer;
  std::string syscall_buffer_lib_path;
  int dump_on; // event
  int dump_at; // global time
  int checksum;
  /* IP port to listen on for debug connections. */
  int dbgport;
  /* Number of seconds to wait after startup, before starting
   * "real work". */
  int wait_secs;
  /* True when not-absolutely-urgently-critical messages will be
   * logged. */
  bool verbose;
  /* True when tracee processes in record and replay are allowed
   * to run on any logical CPU. */
  bool cpu_unbound;
  // Force rr to do some things that it otherwise wouldn't, for
  // example launching an emergency debugger when the output
  // doesn't seem to be a tty.
  bool force_things;
  /* Mark the trace global time along with tracee writes to
   * stdio. */
  bool mark_stdio;
  // Check that cached mmaps match /proc/maps after each event.
  bool check_cached_mmaps;
  // Suppress warnings related to environmental features outside rr's
  // control.
  bool suppress_environment_warnings;
  // Any warning or error that would be printed is treated as fatal
  bool fatal_errors_and_warnings;
  // Start a debug server for the task scheduled at the first
  // event at which reached this event AND target_process has
  // been "created".
  uint32_t goto_event;
  pid_t target_process;
  int process_created_how;
  // Dump trace frames in a more easily machine-parseable
  // format.
  bool raw_dump;
  // Dump statistics about the trace
  bool dump_statistics;
  // Dump syscallbuf contents
  bool dump_syscallbuf;
  // Only open a debug socket, don't launch the debugger too.
  bool dont_launch_debugger;
  // Pass this file name to debugger with -x
  std::string gdb_command_file_path;
  // User override for architecture detection, e.g. when running
  // under valgrind.
  std::string forced_uarch;

  Flags()
      : max_rbc(0),
        max_events(0),
        ignore_sig(0),
        redirect(false),
        use_syscall_buffer(false),
        syscall_buffer_lib_path(""),
        dump_on(0),
        dump_at(0),
        checksum(0),
        dbgport(0),
        wait_secs(0),
        verbose(false),
        cpu_unbound(false),
        force_things(false),
        mark_stdio(false),
        check_cached_mmaps(false),
        goto_event(0),
        target_process(0),
        process_created_how(0),
        raw_dump(false),
        dump_statistics(false),
        dump_syscallbuf(false),
        dont_launch_debugger(false) {}
};

#endif /* RR_TYPES_H_ */
