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
    "  -h, --chaos                randomize scheduling decisions to try to \n"
    "                             reproduce bugs\n"
    "  -i, --ignore-signal=<SIG>  block <SIG> from being delivered to \n"
    "                             tracees. Probably only useful for unit \n"
    "                             tests.\n"
    "  -n, --no-syscall-buffer    disable the syscall buffer preload \n"
    "                             library even if it would otherwise be used\n"
    "  -s, --always-switch        tryto context switch at every rr event\n"
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

  /* Whenever |ignore_sig| is pending for a tracee, decline to
   * deliver it. */
  int ignore_sig;

  /* Whether to use syscall buffering optimization during recording. */
  RecordSession::SyscallBuffering use_syscall_buffer;

  /* Whether tracee processes in record and replay are allowed
   * to run on any logical CPU. */
  RecordSession::BindCPU bind_cpu;

  /* True if we should context switch after every rr event */
  bool always_switch;

  /* Whether to enable chaos mode in the scheduler */
  RecordSession::Chaos chaos;

  RecordFlags()
      : max_ticks(Scheduler::DEFAULT_MAX_TICKS),
        ignore_sig(0),
        use_syscall_buffer(RecordSession::ENABLE_SYSCALL_BUF),
        bind_cpu(RecordSession::BIND_CPU),
        always_switch(false),
        chaos(RecordSession::DISABLE_CHAOS) {}
};

static bool parse_record_arg(std::vector<std::string>& args,
                             RecordFlags& flags) {
  if (parse_global_option(args)) {
    return true;
  }

  static const OptionSpec options[] = {
    { 'b', "force-syscall-buffer", NO_PARAMETER },
    { 'c', "num-cpu-ticks", HAS_PARAMETER },
    { 'h', "chaos", NO_PARAMETER },
    { 'i', "ignore-signal", HAS_PARAMETER },
    { 'n', "no-syscall-buffer", NO_PARAMETER },
    { 's', "always-switch", NO_PARAMETER },
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
      flags.use_syscall_buffer = RecordSession::ENABLE_SYSCALL_BUF;
      break;
    case 'c':
      if (!opt.verify_valid_int(1, INT64_MAX)) {
        return false;
      }
      flags.max_ticks = opt.int_value;
      break;
    case 'h':
      flags.chaos = RecordSession::ENABLE_CHAOS;
      break;
    case 'i':
      if (!opt.verify_valid_int(1, _NSIG - 1)) {
        return false;
      }
      flags.ignore_sig = opt.int_value;
      break;
    case 'n':
      flags.use_syscall_buffer = RecordSession::DISABLE_SYSCALL_BUF;
      break;
    case 's':
      flags.always_switch = true;
      break;
    case 'u':
      flags.bind_cpu = RecordSession::UNBOUND_CPU;
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

/**
 * A terminating signal was received.  Set the |term_request| bit to
 * terminate the trace at the next convenient point.
 *
 * If there's already a term request pending, then assume rr is wedged
 * and abort().
 */
static void handle_SIGTERM(int sig) {
  if (term_request) {
    FATAL() << "Received termsig while an earlier one was pending.  We're "
               "probably wedged.";
  }
  LOG(info) << "Received termsig " << signal_name(sig)
            << ", requesting shutdown ...\n";
  term_request = true;
}

static void install_signal_handlers(void) {
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = handle_SIGTERM;
  sigaction(SIGTERM, &sa, nullptr);

  sa.sa_handler = SIG_IGN;
  sigaction(SIGINT, &sa, nullptr);
}

static void setup_session_from_flags(RecordSession& session,
                                     const RecordFlags& flags) {
  session.scheduler().set_max_ticks(flags.max_ticks);
  session.scheduler().set_always_switch(flags.always_switch);
  session.set_ignore_sig(flags.ignore_sig);
}

static int record(const vector<string>& args, const RecordFlags& flags) {
  LOG(info) << "Start recording...";

  auto session =
      RecordSession::create(args, flags.extra_env, flags.use_syscall_buffer,
                            flags.bind_cpu, flags.chaos);
  setup_session_from_flags(*session, flags);

  // Install signal handlers after creating the session, to ensure they're not
  // inherited by the tracee.
  install_signal_handlers();

  RecordSession::RecordResult step_result;
  do {
    step_result = session->record_step();
  } while (step_result.status == RecordSession::STEP_CONTINUE && !term_request);

  session->terminate_recording();

  switch (step_result.status) {
    case RecordSession::STEP_CONTINUE:
      // SIGINT or something like that interrupted us.
      return 0x80 | SIGINT;

    case RecordSession::STEP_EXITED:
      return step_result.exit_code;

    case RecordSession::STEP_EXEC_FAILED:
      fprintf(stderr,
              "\n"
              "rr: error:\n"
              "  Unexpected `write()' call from first tracee process.\n"
              "  Most likely, the executable image `%s' is 64-bit, doesn't "
              "exist, or\n"
              "  isn't in your $PATH.  Terminating recording.\n"
              "\n",
              session->trace_writer().initial_exe().c_str());
      return EX_NOINPUT;

    case RecordSession::STEP_PERF_COUNTERS_UNAVAILABLE:
      fprintf(stderr, "\n"
                      "rr: internal recorder error:\n"
                      "  Performance counter doesn't seem to be working.  Are "
                      "you perhaps\n"
                      "  running rr in a VM but didn't enable perf-counter "
                      "virtualization?\n");
      return EX_UNAVAILABLE;

    default:
      assert(0 && "Unknown exit status");
      return -1;
  }
}

int RecordCommand::run(std::vector<std::string>& args) {
  if (getenv("RUNNING_UNDER_RR")) {
    fprintf(stderr, "rr: cannot run rr recording under rr. Exiting.\n");
    return 1;
  }

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
