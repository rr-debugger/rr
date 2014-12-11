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

struct ReplayFlags {
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

  // Only open a debug socket, don't launch the debugger too.
  bool dont_launch_debugger;

  // IP port to listen on for debug connections.
  int dbg_port;

  // Pass this file name to debugger with -x
  string gdb_command_file_path;

  /* When true, echo tracee stdout/stderr writes to console. */
  bool redirect;

  ReplayFlags()
      : goto_event(0),
        target_process(0),
        process_created_how(CREATED_NONE),
        dont_launch_debugger(false),
        dbg_port(-1),
        redirect(true) {}
};

static bool parse_replay_arg(std::vector<std::string>& args,
                             ReplayFlags& flags) {
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

  switch (opt.short_name) {
    case 'a':
      flags.goto_event = numeric_limits<decltype(flags.goto_event)>::max();
      flags.dont_launch_debugger = true;
      break;
    case 'f':
      flags.target_process = atoi(optarg);
      flags.process_created_how = ReplayFlags::CREATED_FORK;
      break;
    case 'g':
      flags.goto_event = atoi(optarg);
      break;
    case 'p':
      flags.target_process = atoi(optarg);
      flags.process_created_how = ReplayFlags::CREATED_EXEC;
      break;
    case 'q':
      flags.redirect = false;
      break;
    case 's':
      flags.dbg_port = atoi(optarg);
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

static void setup_session_from_flags(ReplaySession& session,
                                     const ReplayFlags& flags) {
  session.set_redirect_stdio(flags.redirect);
}

static void serve_replay_no_debugger(const string& trace_dir,
                                     const ReplayFlags& flags) {
  ReplaySession::shr_ptr replay_session = ReplaySession::create(trace_dir);
  setup_session_from_flags(*replay_session, flags);

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

static int replay(const string& trace_dir, const ReplayFlags& flags) {
  GdbServer::Target target;
  switch (flags.process_created_how) {
    case ReplayFlags::CREATED_EXEC:
      target.pid = flags.target_process;
      target.require_exec = true;
      break;
    case ReplayFlags::CREATED_FORK:
      target.pid = flags.target_process;
      target.require_exec = false;
      break;
    case ReplayFlags::CREATED_NONE:
      break;
  }
  target.event = flags.goto_event;

  // If we're not going to autolaunch the debugger, don't go
  // through the rigamarole to set that up.  All it does is
  // complicate the process tree and confuse users.
  if (flags.dont_launch_debugger) {
    if (target.event == numeric_limits<decltype(target.event)>::max()) {
      serve_replay_no_debugger(trace_dir, flags);
    } else {
      auto session = ReplaySession::create(trace_dir);
      setup_session_from_flags(*session, flags);
      GdbServer::ConnectionFlags conn_flags;
      conn_flags.dbg_port = flags.dbg_port;
      GdbServer::serve(session, target, conn_flags);
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
    auto session = ReplaySession::create(trace_dir);
    setup_session_from_flags(*session, flags);
    GdbServer::ConnectionFlags conn_flags;
    conn_flags.dbg_port = flags.dbg_port;
    conn_flags.debugger_params_write_pipe = &debugger_params_write_pipe;
    GdbServer::serve(session, target, conn_flags);
    return 0;
  }
  // Ensure only the child has the write end of the pipe open. Then if
  // the child dies, our reads from the pipe will return EOF.
  close(debugger_params_pipe[1]);
  LOG(debug) << getpid() << ": forked debugger server " << waiting_for_child;

  {
    ScopedFd params_pipe_read_fd(debugger_params_pipe[0]);
    GdbServer::launch_gdb(params_pipe_read_fd, flags.gdb_command_file_path);
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
  ReplayFlags flags;
  while (parse_replay_arg(args, flags)) {
  }

  string trace_dir;
  if (!parse_optional_trace_dir(args, &trace_dir)) {
    return 1;
  }

  assert_prerequisites();
  check_performance_settings();

  return replay(trace_dir, flags);
}
