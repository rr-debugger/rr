/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

//#define DEBUGTAG "Recorder"

#include "recorder.h"

#include <assert.h>
#include <sysexits.h>

#include <string>
#include <vector>

#include "Flags.h"
#include "kernel_metadata.h"
#include "log.h"
#include "RecordSession.h"

using namespace rr;
using namespace std;

static bool term_request;

static void terminate_recording(RecordSession& session, int status = 0) {
  session.terminate_recording();
  LOG(info) << "  exiting, goodbye.";
  exit(status);
}

/**
 * A terminating signal was received.  Set the |term_request| bit to
 * terminate the trace at the next convenient point.
 *
 * If there's already a term request pending, then assume rr is wedged
 * and abort().
 */
static void handle_termsig(int sig) {
  if (term_request) {
    FATAL() << "Received termsig while an earlier one was pending.  We're "
               "probably wedged.";
  }
  LOG(info) << "Received termsig " << signal_name(sig)
            << ", requesting shutdown ...\n";
  term_request = true;
}

static void install_termsig_handlers(void) {
  int termsigs[] = { SIGINT, SIGTERM };
  for (size_t i = 0; i < array_length(termsigs); ++i) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_termsig;
    sigaction(termsigs[i], &sa, nullptr);
  }
}

/** If |term_request| is set, then terminate_recording(). */
static void maybe_process_term_request(RecordSession& session) {
  if (term_request) {
    terminate_recording(session);
  }
}

int record(const vector<string>& args, char** envp) {
  LOG(info) << "Start recording...";

  vector<string> env;
  for (; *envp; ++envp) {
    env.push_back(*envp);
  }

  char cwd[PATH_MAX] = "";
  getcwd(cwd, sizeof(cwd));

  install_termsig_handlers();

  auto session = RecordSession::create(args, env, cwd);

  RecordSession::RecordResult step_result;
  while ((step_result = session->record_step()).status ==
         RecordSession::STEP_CONTINUE) {
    maybe_process_term_request(*session);
  }

  if (step_result.status == RecordSession::STEP_EXEC_FAILED) {
    fprintf(stderr,
            "\n"
            "rr: error:\n"
            "  Unexpected `write()' call from first tracee process.\n"
            "  Most likely, the executable image `%s' is 64-bit, doesn't "
            "exist, or\n"
            "  isn't in your $PATH.  Terminating recording.\n"
            "\n",
            session->trace_writer().initial_exe().c_str());
    terminate_recording(*session);
  }

  if (step_result.status == RecordSession::STEP_PERF_COUNTERS_UNAVAILABLE) {
    fprintf(stderr, "\n"
                    "rr: internal recorder error:\n"
                    "  Performance counter doesn't seem to be working.  Are "
                    "you perhaps\n"
                    "  running rr in a VM but didn't enable perf-counter "
                    "virtualization?\n");
    terminate_recording(*session, EX_UNAVAILABLE);
  }

  assert(step_result.status == RecordSession::STEP_EXITED);
  LOG(info) << "Done recording -- cleaning up";
  return step_result.exit_code;
}
