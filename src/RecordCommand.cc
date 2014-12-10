/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "RecordCommand.h"

#include <assert.h>
#include <sysexits.h>

#include "preload/preload_interface.h"

#include "Flags.h"
#include "kernel_metadata.h"
#include "log.h"
#include "RecordSession.h"
#include "util.h"

using namespace std;

extern char** environ;

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
    "                             even if it would otherwise be used\n");

static bool parse_record_arg(std::vector<std::string>& args) {
  if (parse_global_option(args)) {
    return true;
  }

  static const OptionSpec options[] = {
    { 'b', "force-syscall-buffer", NO_PARAMETER },
    { 'i', "ignore-signal", HAS_PARAMETER },
    { 'c', "num-cpu-ticks", HAS_PARAMETER },
    { 'e', "num-events", HAS_PARAMETER },
    { 'n', "no-syscall-buffer", NO_PARAMETER }
  };
  ParsedOption opt;
  if (!Command::parse_option(args, options, &opt)) {
    return false;
  }

  Flags& flags = Flags::get_for_init();
  switch (opt.short_name) {
    case 'b':
      flags.use_syscall_buffer = true;
      break;
    case 'c':
      flags.max_ticks = max(1, atoi(optarg));
      break;
    case 'e':
      flags.max_events = max(1, atoi(optarg));
      break;
    case 'i':
      flags.ignore_sig = min(_NSIG - 1, max(1, atoi(optarg)));
      break;
    case 'n':
      flags.use_syscall_buffer = false;
      break;
    default:
      assert(0 && "Unknown option");
  }
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

static int record(const vector<string>& args, char** envp) {
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

static string find_syscall_buffer_library() {
  char* exe_path = realpath("/proc/self/exe", nullptr);
  string lib_path = exe_path;
  free(exe_path);

  int end = lib_path.length();
  // Chop off the filename
  while (end > 0 && lib_path[end - 1] != '/') {
    --end;
  }
  lib_path.erase(end);
  lib_path += "../lib/";
  string file_name = lib_path + SYSCALLBUF_LIB_FILENAME;
  if (access(file_name.c_str(), F_OK) != 0) {
    // File does not exist. Assume install put it in LD_LIBRARY_PATH.
    lib_path = "";
  }
  return lib_path;
}

int RecordCommand::run(std::vector<std::string>& args) {
  while (parse_record_arg(args)) {
  }

  if (!verify_not_option(args)) {
    return 1;
  }

  if (args.size() == 0) {
    print_help(stderr);
    return 1;
  }

  // The syscallbuf library interposes some critical
  // external symbols like XShmQueryExtension(), so we
  // preload it whether or not syscallbuf is enabled.
  if (Flags::get().use_syscall_buffer) {
    setenv(SYSCALLBUF_ENABLED_ENV_VAR, "1", 1);
  } else {
    unsetenv(SYSCALLBUF_ENABLED_ENV_VAR);
  }
  Flags::get_for_init().syscall_buffer_lib_path = find_syscall_buffer_library();

  return record(args, environ);
}
