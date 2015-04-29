/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "RecordCommand.h"

#include <assert.h>
#include <sysexits.h>

#include "preload/preload_interface.h"

#include "Flags.h"
#include "kernel_metadata.h"
#include "log.h"
#include "main.h"
#include "RecordSession.h"
#include "util.h"

using namespace std;

RecordCommand RecordCommand::singleton(
    "record",
    " rr record [OPTION]... <exe> [exe-args]...\n"
    "  -b, --force-syscall-buffer force the syscall buffer preload library\n"
    "                             to be used, even if that's probably a bad\n"
    "                             idea\n"
    "  -c, --num-cpu-ticks=<NUM>  maximum number of 'CPU ticks' (currently \n"
    "                             retired conditional branches) to allow a \n"
    "                             task to run before interrupting it\n"
    "  -e, --num-events=<NUM>     maximum number of events (syscall \n"
    "                             enter/exit, signal, CPU interrupt, ...) \n"
    "                             to allow a task before descheduling it\n"
    "  -i, --ignore-signal=<SIG>  block <SIG> from being delivered to "
    "tracees.\n"
    "                             Probably only useful for unit tests.\n"
    "  -n, --no-syscall-buffer    disable the syscall buffer preload "
    "library\n"
    "                             even if it would otherwise be used\n"
    "  -u, --cpu-unbound          allow tracees to run on any virtual CPU.\n"
    "                             Default is to bind to CPU 0.  This option\n"
    "                             can cause replay divergence: use with\n"
    "                             caution.\n"
    "  -v, --env=NAME=VALUE       value to add to the environment of the\n"
    "                             tracee. There can be any number of these.\n");

struct RecordFlags {
  vector<string> extra_env;

  /* Max counter value before the scheduler interrupts a tracee. */
  Ticks max_ticks;

  /* Max number of trace events before the scheduler
   * de-schedules a tracee. */
  TraceFrame::Time max_events;

  /* Whenever |ignore_sig| is pending for a tracee, decline to
   * deliver it. */
  int ignore_sig;

  /* When true, use syscall buffering optimization during recording. */
  bool use_syscall_buffer;

  /* True when tracee processes in record and replay are allowed
   * to run on any logical CPU. */
  bool cpu_unbound;

  RecordFlags()
      : max_ticks(Scheduler::DEFAULT_MAX_TICKS),
        max_events(Scheduler::DEFAULT_MAX_EVENTS),
        ignore_sig(0),
        use_syscall_buffer(true),
        cpu_unbound(false) {}
};

static bool parse_record_arg(std::vector<std::string>& args,
                             RecordFlags& flags) {
  if (parse_global_option(args)) {
    return true;
  }

  static const OptionSpec options[] = {
    { 'b', "force-syscall-buffer", NO_PARAMETER },
    { 'i', "ignore-signal", HAS_PARAMETER },
    { 'c', "num-cpu-ticks", HAS_PARAMETER },
    { 'e', "num-events", HAS_PARAMETER },
    { 'n', "no-syscall-buffer", NO_PARAMETER },
    { 'u', "cpu-unbound", NO_PARAMETER },
    { 'v', "env", HAS_PARAMETER }
  };
  ParsedOption opt;
  auto args_copy = args;
  if (!Command::parse_option(args_copy, options, &opt)) {
    return false;
  }

  switch (opt.short_name) {
    case 'b':
      flags.use_syscall_buffer = true;
      break;
    case 'c':
      if (!opt.verify_valid_int(1, INT64_MAX)) {
        return false;
      }
      flags.max_ticks = opt.int_value;
      break;
    case 'e':
      if (!opt.verify_valid_int(1, UINT32_MAX)) {
        return false;
      }
      flags.max_events = opt.int_value;
      ;
      break;
    case 'i':
      if (!opt.verify_valid_int(1, _NSIG - 1)) {
        return false;
      }
      flags.ignore_sig = opt.int_value;
      break;
    case 'n':
      flags.use_syscall_buffer = false;
      break;
    case 'u':
      flags.cpu_unbound = true;
      break;
    case 'v':
      flags.extra_env.push_back(opt.value);
      break;
    default:
      assert(0 && "Unknown option");
  }

  args = args_copy;
  return true;
}

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

static void setup_session_from_flags(RecordSession& session,
                                     const RecordFlags& flags) {
  session.scheduler().set_max_ticks(flags.max_ticks);
  session.scheduler().set_max_events(flags.max_events);
  session.set_ignore_sig(flags.ignore_sig);
}

static int record(const vector<string>& args, const RecordFlags& flags) {
  LOG(info) << "Start recording...";

  install_termsig_handlers();

  auto session = RecordSession::create(
      args,
      (flags.cpu_unbound ? RecordSession::CPU_UNBOUND : 0) |
          (flags.use_syscall_buffer ? 0 : RecordSession::DISABLE_SYSCALL_BUF),
       flags.extra_env);
  setup_session_from_flags(*session, flags);

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

int RecordCommand::run(std::vector<std::string>& args) {
  RecordFlags flags;
  while (parse_record_arg(args, flags)) {
  }

  if (!verify_not_option(args) || args.size() == 0) {
    print_help(stderr);
    return 1;
  }

  assert_prerequisites(flags.use_syscall_buffer);
  check_performance_settings();

  return record(args, flags);
}
