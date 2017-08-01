/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_FLAGS_H_
#define RR_FLAGS_H_

#include <stdint.h>
#include <unistd.h>

#include <string>

#include "Ticks.h"
#include "TraceFrame.h"

namespace rr {

/**
 * Command line arguments for rr
 */
struct Flags {
  enum { CHECKSUM_NONE = -3, CHECKSUM_SYSCALL = -2, CHECKSUM_ALL = -1 };
  /* When to generate or check memory checksums. One of CHECKSUM_NONE,
   * CHECKSUM_SYSCALL or CHECKSUM_ALL, or a positive integer representing the
   * event time at which to start checksumming.
   */
  FrameTime checksum;

  enum {
    DUMP_ON_ALL = 10000,
    DUMP_ON_RDTSC = 10001,
    DUMP_ON_NONE = -DUMP_ON_ALL
  };
  int dump_on;

  enum { DUMP_AT_NONE = -1 };
  /* time at which to create memory dump */
  FrameTime dump_at; // global time

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

  // Pretend CPUID faulting support doesn't exist
  bool disable_cpuid_faulting;

  // User override for architecture detection, e.g. when running
  // under valgrind.
  std::string forced_uarch;

  Flags()
      : checksum(CHECKSUM_NONE),
        dump_on(DUMP_ON_NONE),
        dump_at(DUMP_AT_NONE),
        force_things(false),
        mark_stdio(false),
        check_cached_mmaps(false),
        suppress_environment_warnings(false),
        fatal_errors_and_warnings(false),
        disable_cpuid_faulting(false) {}

  static const Flags& get() { return singleton; }

  /**
   * Get a reference that can be used to initialize the global Flags.
   * Can only be called once.
   */
  static Flags& get_for_init();

private:
  static Flags singleton;
};

} // namespace rr

#endif /* RR_FLAGS_H_ */
