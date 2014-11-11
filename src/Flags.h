/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_FLAGS_H_
#define RR_FLAGS_H_

#include <stdint.h>
#include <unistd.h>

#include <string>

#include "Ticks.h"
#include "TraceFrame.h"

/**
 * Command line arguments for rr
 */
struct Flags {
  /* Max counter value before the scheduler interrupts a tracee. */
  Ticks max_ticks;

  /* Max number of trace events before the scheduler
   * de-schedules a tracee. */
  TraceFrame::Time max_events;

  /**
   * The following parameters define the default scheduling parameters.
   * The recorder scheduler basically works as follows
   *
   *  0. Find a task A with a pending event.
   *  1. If A was the last task scheduled, decrease its "max-event"
   *     counter.
   *  2. Program an HPC interrupt for A that will fire after "max-ticks"
   *     retired conditional branches (or so, it may not be precise).
   *  3. Resume the execution of A.
   *
   * The next thing that will occur is another scheduling event, after
   * which one of two things happens
   *
   *  0. Task A triggers a trace event in rr, which could be a signal,
   *     syscall entry/exit, HPC interrupt, ...
   *  1. Some other task triggers an event.
   *
   * And then we make another scheduling decision.
   *
   * Like in most task schedulers, there are conflicting goals to
   * balance.  Lower max-ticks / max-events generally makes the
   * application more "interactive", generally speaking lower latency.
   * (And wrt catching bugs, this setting generally creates more
   * opportunity for bugs to arise in multi-threaded/process
   * applications.)  This comes at the cost of more overhead from
   * scheduling and context switching.  Higher max-ticks / max-events
   * generally gives the application higher throughput.
   *
   * The rr scheduler is relatively dumb compared to modern OS
   * schedulers, but the default parameters are configured to achieve
   *
   *  o IO-heavy tasks are relatively quickly switched, in the hope this
   *    improves latency.
   *  o CPU-heavy tasks are given an O(10ms) timeslice before being
   *    switched.
   *  o Keep max number of HPC interrupts small to avoid overhead.
   *
   * In addition to all the aforementioned deficiencies, using retired
   * conditional branches to compute timeslices is quite crude, since
   * they don't correspond to any unit of time in general.  Hopefully
   * that can be improved, but empirical data from Firefox demonstrate,
   * surprisingly consistently, a distribution of insns/rcb massed
   * around 10.  Somewhat arbitrarily guessing ~4cycles/insn on average
   * (fair amount of pointer chasing), that implies
   *
   *  10ms = .01s = x rcb * (10insn / rcb) * (4cycle / insn) * (1s / 2e9cycle)
   *  x = 500000rcb / 10ms
   *
   * We'll arbitrarily decide to allow 10 max successive events for
   * latency reasons.  To try to keep overhead lower (since trace traps
   * are heavyweight), we'll give each task a relatively large 50ms
   * timeslice.  This works out to
   *
   *   50ms * (500000rcb / 10ms) / 10event = 250000 rcb / event
   */
  enum {
    DEFAULT_MAX_TICKS = 250000
  };
  enum {
    DEFAULT_MAX_EVENTS = 10
  };

  /* Whenever |ignore_sig| is pending for a tracee, decline to
   * deliver it. */
  int ignore_sig;

  /* When true, echo tracee stdout/stderr writes to console. */
  bool redirect;

  /* When true, use syscall buffering optimization during recording. */
  bool use_syscall_buffer;

  /* Path to librrpreload library. */
  std::string syscall_buffer_lib_path;

  enum {
    DUMP_ON_ALL = 10000,
    DUMP_ON_NONE = -DUMP_ON_ALL
  };
  /* event(s) to create memory dumps for */
  TraceFrame::Time dump_on; // event

  enum {
    DUMP_AT_NONE = -1
  };
  /* time at which to create memory dump */
  int dump_at; // global time

  enum {
    CHECKSUM_NONE = -3,
    CHECKSUM_SYSCALL = -2,
    CHECKSUM_ALL = -1
  };
  /* When to generate or check memory checksums. One of CHECKSUM_NONE,
   * CHECKSUM_SYSCALL or CHECKSUM_ALL, or a positive integer representing the
   * event time at which to start checksumming.
   */
  int checksum;

  /* IP port to listen on for debug connections. */
  int dbgport;

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
  TraceFrame::Time goto_event;

  pid_t target_process;

  // We let users specify which process should be "created" before
  // starting a debug session for it.  Problem is, "process" in this
  // context is ambiguous.  It could mean the "thread group", which is
  // created at fork().  Or it could mean the "address space", which is
  // created at exec() (after the fork).
  //
  // We force choosers to specify which they mean.
  enum {
    CREATED_NONE,
    CREATED_EXEC,
    CREATED_FORK
  } process_created_how;

  // Let the 'dump' command dump trace frames in a more easily machine-parseable
  // format.
  bool raw_dump;

  // Let the 'dump' command dump statistics about the trace
  bool dump_statistics;

  // Let the 'dump' command dump syscallbuf contents
  bool dump_syscallbuf;

  // Only open a debug socket, don't launch the debugger too.
  bool dont_launch_debugger;

  // Pass this file name to debugger with -x
  std::string gdb_command_file_path;

  // User override for architecture detection, e.g. when running
  // under valgrind.
  std::string forced_uarch;

  Flags()
      : max_ticks(0),
        max_events(0),
        ignore_sig(0),
        redirect(false),
        use_syscall_buffer(false),
        syscall_buffer_lib_path(""),
        dump_on(0),
        dump_at(0),
        checksum(0),
        dbgport(0),
        verbose(false),
        cpu_unbound(false),
        force_things(false),
        mark_stdio(false),
        check_cached_mmaps(false),
        goto_event(0),
        target_process(0),
        process_created_how(CREATED_NONE),
        raw_dump(false),
        dump_statistics(false),
        dump_syscallbuf(false),
        dont_launch_debugger(false) {}

  static const Flags& get() { return singleton; }

  /**
   * Get a reference that can be used to initialize the global Flags.
   * Can only be called once.
   */
  static Flags& get_for_init();

private:
  static Flags singleton;
};

#endif /* RR_FLAGS_H_ */
