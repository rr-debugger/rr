/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

//#define DEBUGTAG "ReplayCommand"

#include <assert.h>
#include <sys/wait.h>
#include <unistd.h>

#include <limits>

#include "Command.h"
#include "Flags.h"
#include "GdbServer.h"
#include "kernel_metadata.h"
#include "log.h"
#include "main.h"
#include "ReplaySession.h"
#include "ScopedFd.h"

using namespace std;

class ReplayCommand : public Command {
public:
  virtual int run(std::vector<std::string>& args);

protected:
  ReplayCommand(const char* name, const char* help) : Command(name, help) {}

  static ReplayCommand singleton;
};

ReplayCommand ReplayCommand::singleton(
    "replay",
    " rr replay [OPTION]... [<trace-dir>]\n"
    "  -a, --autopilot            replay without debugger server\n"
    "  -f, --onfork=<PID>         start a debug server when <PID> has been\n"
    "                             fork()d, AND the target event has been\n"
    "                             reached.\n"
    "  -g, --goto=<EVENT-NUM>     start a debug server on reaching "
    "<EVENT-NUM>\n"
    "                             in the trace.  See -m above.\n"
    "  -p, --onprocess=<PID>      start a debug server when <PID> has been\n"
    "                             exec()d, AND the target event has been\n"
    "                             reached.\n"
    "  -q, --no-redirect-output   don't replay writes to stdout/stderr\n"
    "  -s, --dbgport=<PORT>       only start a debug server on <PORT>;\n"
    "                             don't automatically launch the debugger\n"
    "                             client too.\n"
    "  -x, --gdb-x=<FILE>         execute gdb commands from <FILE>\n");

static bool parse_replay_arg(std::vector<std::string>& args) {
  if (parse_global_option(args)) {
    return true;
  }

  static const OptionSpec options[] = { { 'a', "autopilot", NO_PARAMETER },
                                        { 's', "dbgport", HAS_PARAMETER },
                                        { 'g', "goto", HAS_PARAMETER },
                                        { 'q', "no-redirect-output",
                                          NO_PARAMETER },
                                        { 'f', "onfork", HAS_PARAMETER },
                                        { 'p', "onprocess", HAS_PARAMETER },
                                        { 'x', "gdb-x", HAS_PARAMETER } };
  ParsedOption opt;
  if (!Command::parse_option(args, options, &opt)) {
    return false;
  }

  Flags& flags = Flags::get_for_init();
  switch (opt.short_name) {
    case 'a':
      flags.goto_event = numeric_limits<decltype(flags.goto_event)>::max();
      flags.dont_launch_debugger = true;
      break;
    case 'f':
      flags.target_process = atoi(optarg);
      flags.process_created_how = Flags::CREATED_FORK;
      break;
    case 'g':
      flags.goto_event = atoi(optarg);
      break;
    case 'p':
      flags.target_process = atoi(optarg);
      flags.process_created_how = Flags::CREATED_EXEC;
      break;
    case 'q':
      flags.redirect = false;
      break;
    case 's':
      flags.dbgport = atoi(optarg);
      flags.dont_launch_debugger = true;
      break;
    case 'x':
      flags.gdb_command_file_path = optarg;
      break;
    default:
      assert(0 && "Unknown option");
  }
  return true;
}

// The parent process waits until the server, |waiting_for_child|, creates a
// debug socket. Then the parent exec()s the debugger over itself. While it's
// waiting for the child, this is the child's pid.
// This needs to be global because it's used by a signal handler.
static pid_t waiting_for_child;

/**
 * Set the blocked-ness of |sig| to |blockedness|.
 */
static void set_sig_blockedness(int sig, int blockedness) {
  sigset_t sset;
  sigemptyset(&sset);
  sigaddset(&sset, sig);
  if (sigprocmask(blockedness, &sset, nullptr)) {
    FATAL() << "Didn't change sigmask.";
  }
}

static void serve_replay_no_debugger(const string& trace_dir) {
  ReplaySession::shr_ptr replay_session = ReplaySession::create(trace_dir);

  while (true) {
    auto result = replay_session->replay_step(ReplaySession::RUN_CONTINUE);

    if (result.status == ReplaySession::REPLAY_EXITED) {
      break;
    }
    assert(result.status == ReplaySession::REPLAY_CONTINUE);
    assert(result.break_status.reason == Session::BREAK_NONE ||
           result.break_status.reason == Session::BREAK_SIGNAL);
  }

  LOG(info) << ("Replayer successfully finished.");
}

static void handle_signal(int sig) {
  switch (sig) {
    case SIGINT:
      // Translate the SIGINT into SIGTERM for the debugger
      // server, because it's blocking SIGINT.  We don't use
      // SIGINT for anything, so all it's meant to do is
      // kill us, and SIGTERM works just as well for that.
      if (waiting_for_child > 0) {
        kill(waiting_for_child, SIGTERM);
      }
      break;
    default:
      FATAL() << "Unhandled signal " << signal_name(sig);
  }
}

static int replay(const string& trace_dir) {
  GdbServer::Target target;
  switch (Flags::get().process_created_how) {
    case Flags::CREATED_EXEC:
      target.pid = Flags::get().target_process;
      target.require_exec = true;
      break;
    case Flags::CREATED_FORK:
      target.pid = Flags::get().target_process;
      target.require_exec = false;
      break;
    case Flags::CREATED_NONE:
      break;
  }
  target.event = Flags::get().goto_event;

  // If we're not going to autolaunch the debugger, don't go
  // through the rigamarole to set that up.  All it does is
  // complicate the process tree and confuse users.
  if (Flags::get().dont_launch_debugger) {
    if (target.event == numeric_limits<decltype(target.event)>::max()) {
      serve_replay_no_debugger(trace_dir);
    } else {
      GdbServer::serve(trace_dir, target);
    }
    return 0;
  }

  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = handle_signal;
  if (sigaction(SIGINT, &sa, nullptr)) {
    FATAL() << "Couldn't set sigaction for SIGINT.";
  }

  int debugger_params_pipe[2];
  if (pipe2(debugger_params_pipe, O_CLOEXEC)) {
    FATAL() << "Couldn't open debugger params pipe.";
  }
  if (0 == (waiting_for_child = fork())) {
    // Ensure only the parent has the read end of the pipe open. Then if
    // the parent dies, our writes to the pipe will error out.
    close(debugger_params_pipe[0]);
    ScopedFd debugger_params_write_pipe(debugger_params_pipe[1]);
    // The parent process (gdb) must be able to receive
    // SIGINT's to interrupt non-stopped tracees.  But the
    // debugger server isn't set up to handle SIGINT.  So
    // block it.
    set_sig_blockedness(SIGINT, SIG_BLOCK);
    GdbServer::serve(trace_dir, target, &debugger_params_write_pipe);
    return 0;
  }
  // Ensure only the child has the write end of the pipe open. Then if
  // the child dies, our reads from the pipe will return EOF.
  close(debugger_params_pipe[1]);
  LOG(debug) << getpid() << ": forked debugger server " << waiting_for_child;

  {
    ScopedFd params_pipe_read_fd(debugger_params_pipe[0]);
    GdbServer::launch_gdb(params_pipe_read_fd);
  }

  // Child must have died before we were able to get debugger parameters
  // and exec gdb. Exit with the exit status of the child.
  while (true) {
    int status;
    int ret = waitpid(waiting_for_child, &status, 0);
    int err = errno;
    LOG(debug) << getpid() << ": waitpid(" << waiting_for_child << ") returned "
               << strerror(err) << "(" << err << "); status:" << HEX(status);
    if (waiting_for_child != ret) {
      if (EINTR == err) {
        continue;
      }
      FATAL() << getpid() << ": waitpid(" << waiting_for_child << ") failed";
    }
    if (WIFEXITED(status) || WIFSIGNALED(status)) {
      LOG(info) << ("Debugger server died.  Exiting.");
      exit(WIFEXITED(status) ? WEXITSTATUS(status) : 1);
    }
  }

  return 0;
}

int ReplayCommand::run(std::vector<std::string>& args) {
  while (parse_replay_arg(args)) {
  }

  string trace_dir;
  if (!parse_optional_trace_dir(args, &trace_dir)) {
    return 1;
  }

  assert_prerequisites();
  check_performance_settings();

  return replay(trace_dir);
}
