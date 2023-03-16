/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_TRACEE_ATTENTION_SET_H_
#define RR_TRACEE_ATTENTION_SET_H_

#include <signal.h>
#include <sys/wait.h>

#include <unordered_set>

namespace rr {

// This class creates a thread that continuously observes SIGCHLD signals
// and adds their pids to an "attention set". This attention set can be
// read from any thread (which clears the set).
// In general multiple SIGCHLD signals can arrive between observations,
// in which case all but the first one will effectively dropped, so this
// is not a reliable record of which pids SICHLD has been triggered for.
// These values are only usable as hints.
class TraceeAttentionSet {
public:
  // Call this early, before any other threads have been spawned.
  static void initialize();

  static std::unordered_set<pid_t> read();

  // Return original sigmask (before initialize() was called, if it was)
  static void get_original_sigmask(sigset_t* out);
};

}

#endif // RR_TRACEE_ATTENTION_SET_H_
