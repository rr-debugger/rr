/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "ReplayCommand.h"

#include <sys/prctl.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

#include <limits>

#include "Command.h"
#include "Flags.h"
#include "GdbServer.h"
#include "ReplaySession.h"
#include "ScopedFd.h"
#include "core.h"
#include "kernel_metadata.h"
#include "log.h"
#include "main.h"

using namespace std;

namespace rr {

static int DUMP_STATS_PERIOD = 0;

ReplayCommand ReplayCommand::singleton(
    "replay",
    " rr replay [OPTION]... [<trace-dir>] [-- <debugger-options>]\n"
    "  -a, --autopilot            replay without debugger server\n"
    "  -f, --onfork=<PID>         start a debug server when <PID> has been\n"
    "                             fork()d, AND the target event has been\n"
    "                             reached.\n"
    "  -g, --goto=<EVENT-NUM>     start a debug server on reaching "
    "<EVENT-NUM>\n"
    "                             in the trace.  See -M in the general "
    "options.\n"
    "  -o, --debugger-option=<OPTION>\n"
    "                             pass <OPTION> to debugger\n"
    "  -p, --onprocess=<PID>|<COMMAND>\n"
    "                             start a debug server when <PID> or "
    "<COMMAND>\n"
    "                             has been exec()d, AND the target event has "
    "been\n"
    "                             reached.\n"
    "  --fullname\n"
    "  -i=<X>\n"
    "  --interpreter=<X>          These are passed directly to gdb. They are\n"
    "                             here for convenience to support 'gdb -i=mi'\n"
    "                             and 'gdb --fullname' as suggested by GNU "
    "Emacs\n"
    "  -d, --debugger=<FILE>      use <FILE> as the gdb command\n"
    "  -q, --no-redirect-output   don't replay writes to stdout/stderr\n"
    "  -h, --dbghost=<HOST>       listen address for the debug server.\n"
    "                             default listen address is set to localhost.\n"
    "  -s, --dbgport=<PORT>       only start a debug server on <PORT>,\n"
    "                             don't automatically launch the debugger\n"
    "                             client; set PORT to 0 to automatically\n"
    "                             probe a port\n"
    "  -k, --keep-listening       keep listening after detaching when using \n"
    "                             --dbgport (-s) mode\n"
    "  -t, --trace=<EVENT>        singlestep instructions and dump register\n"
    "                             states when replaying towards <EVENT> or\n"
    "                             later\n"
    "  -x, --gdb-x=<FILE>         execute gdb commands from <FILE>\n");

struct ReplayFlags {
  // Start a debug server for the task scheduled at the first
  // event at which reached this event AND target_process has
  // been "created".
  FrameTime goto_event;

  FrameTime singlestep_to_event;

  pid_t target_process;

  string target_command;

  // We let users specify which process should be "created" before
  // starting a debug session for it.  Problem is, "process" in this
  // context is ambiguous.  It could mean the "thread group", which is
  // created at fork().  Or it could mean the "address space", which is
  // created at exec() (after the fork).
  //
  // We force choosers to specify which they mean.
  enum { CREATED_NONE, CREATED_EXEC, CREATED_FORK } process_created_how;

  // Only open a debug socket, don't launch the debugger too.
  bool dont_launch_debugger;

  // IP port to listen on for debug connections.
  int dbg_port;

  // IP host to listen on for debug connections.
  string dbg_host;

  // Whether to keep listening with a new server after the existing server
  // detaches
  bool keep_listening;

  // Pass these options to gdb
  vector<string> gdb_options;

  // Specify a custom gdb binary with -d
  string gdb_binary_file_path;

  /* When true, echo tracee stdout/stderr writes to console. */
  bool redirect;

  // When true make all private mappings shared with the tracee by default
  // to test the corresponding code.
  bool share_private_mappings;

  ReplayFlags()
      : goto_event(0),
        singlestep_to_event(0),
        target_process(0),
        process_created_how(CREATED_NONE),
        dont_launch_debugger(false),
        dbg_port(-1),
        dbg_host(localhost_addr),
        keep_listening(false),
        gdb_binary_file_path("gdb"),
        redirect(true),
        share_private_mappings(false) {}
};

static bool parse_replay_arg(vector<string>& args, ReplayFlags& flags) {
  if (parse_global_option(args)) {
    return true;
  }

  static const OptionSpec options[] = {
    { 'a', "autopilot", NO_PARAMETER },
    { 'd', "debugger", HAS_PARAMETER },
    { 'k', "keep-listening", NO_PARAMETER },
    { 'f', "onfork", HAS_PARAMETER },
    { 'g', "goto", HAS_PARAMETER },
    { 'o', "debugger-option", HAS_PARAMETER },
    { 'p', "onprocess", HAS_PARAMETER },
    { 'q', "no-redirect-output", NO_PARAMETER },
    { 'h', "dbghost", HAS_PARAMETER },
    { 's', "dbgport", HAS_PARAMETER },
    { 't', "trace", HAS_PARAMETER },
    { 'x', "gdb-x", HAS_PARAMETER },
    { 0, "share-private-mappings", NO_PARAMETER },
    { 1, "fullname", NO_PARAMETER },
    { 'i', "interpreter", HAS_PARAMETER }
  };
  ParsedOption opt;
  if (!Command::parse_option(args, options, &opt)) {
    return false;
  }

  switch (opt.short_name) {
    case 'a':
      flags.goto_event = numeric_limits<decltype(flags.goto_event)>::max();
      flags.dont_launch_debugger = true;
      break;
    case 'd':
      flags.gdb_binary_file_path = opt.value;
      break;
    case 'f':
      if (!opt.verify_valid_int(1, INT32_MAX)) {
        return false;
      }
      flags.target_process = opt.int_value;
      flags.process_created_how = ReplayFlags::CREATED_FORK;
      break;
    case 'g':
      if (!opt.verify_valid_int(1, UINT32_MAX)) {
        return false;
      }
      flags.goto_event = opt.int_value;
      break;
    case 'k':
      flags.keep_listening = true;
      break;
    case 'o':
      flags.gdb_options.push_back(opt.value);
      break;
    case 'p':
      if (opt.int_value > 0) {
        if (!opt.verify_valid_int(1, INT32_MAX)) {
          return false;
        }
        flags.target_process = opt.int_value;
      } else {
        flags.target_command = opt.value;
      }
      flags.process_created_how = ReplayFlags::CREATED_EXEC;
      break;
    case 'q':
      flags.redirect = false;
      break;
    case 'h':
      flags.dbg_host = opt.value;
      flags.dont_launch_debugger = true;
      break;
    case 's':
      if (!opt.verify_valid_int(0, INT32_MAX)) {
        return false;
      }
      flags.dbg_port = opt.int_value;
      flags.dont_launch_debugger = true;
      break;
    case 't':
      if (!opt.verify_valid_int(1, INT32_MAX)) {
        return false;
      }
      flags.singlestep_to_event = opt.int_value;
      break;
    case 'x':
      flags.gdb_options.push_back("-x");
      flags.gdb_options.push_back(opt.value);
      break;
    case 0:
      flags.share_private_mappings = true;
      break;
    case 1:
      flags.gdb_options.push_back("--fullname");
      break;
    case 'i':
      flags.gdb_options.push_back("-i");
      flags.gdb_options.push_back(opt.value);
      break;
    default:
      DEBUG_ASSERT(0 && "Unknown option");
  }
  return true;
}

static int find_pid_for_command(const string& trace_dir,
                                const string& command) {
  TraceReader trace(trace_dir);

  while (true) {
    TraceTaskEvent e = trace.read_task_event();
    if (e.type() == TraceTaskEvent::NONE) {
      return -1;
    }
    if (e.type() != TraceTaskEvent::EXEC) {
      continue;
    }
    if (e.cmd_line().empty()) {
      continue;
    }
    auto& cmd = e.cmd_line()[0];
    if (cmd == command ||
        (cmd.size() > command.size() &&
         cmd.substr(cmd.size() - command.size() - 1) == ('/' + command))) {
      return e.tid();
    }
  }
}

static bool pid_exists(const string& trace_dir, pid_t pid) {
  TraceReader trace(trace_dir);

  while (true) {
    auto e = trace.read_task_event();
    if (e.type() == TraceTaskEvent::NONE) {
      return false;
    }
    if (e.tid() == pid) {
      return true;
    }
  }
}

static bool pid_execs(const string& trace_dir, pid_t pid) {
  TraceReader trace(trace_dir);

  while (true) {
    auto e = trace.read_task_event();
    if (e.type() == TraceTaskEvent::NONE) {
      return false;
    }
    if (e.tid() == pid && e.type() == TraceTaskEvent::EXEC) {
      return true;
    }
  }
}

// The parent process waits until the server, |waiting_for_child|, creates a
// debug socket. Then the parent exec()s the debugger over itself. While it's
// waiting for the child, this is the child's pid.
// This needs to be global because it's used by a signal handler.
static pid_t waiting_for_child;

static ReplaySession::Flags session_flags(const ReplayFlags& flags) {
  ReplaySession::Flags result;
  result.redirect_stdio = flags.redirect;
  result.share_private_mappings = flags.share_private_mappings;
  return result;
}

static uint64_t to_microseconds(const struct timeval& tv) {
  return (uint64_t)tv.tv_sec * 1000000 + tv.tv_usec;
}

static void serve_replay_no_debugger(const string& trace_dir,
                                     const ReplayFlags& flags) {
  ReplaySession::shr_ptr replay_session = ReplaySession::create(trace_dir);
  replay_session->set_flags(session_flags(flags));
  uint32_t step_count = 0;
  struct timeval last_dump_time;
  Session::Statistics last_stats;
  gettimeofday(&last_dump_time, NULL);

  while (true) {
    RunCommand cmd = RUN_CONTINUE;
    if (flags.singlestep_to_event > 0 &&
        replay_session->trace_reader().time() >= flags.singlestep_to_event) {
      cmd = RUN_SINGLESTEP;
      fputs("Stepping from: ", stderr);
      Task* t = replay_session->current_task();
      t->regs().print_register_file_compact(stderr);
      fputc(' ', stderr);
      t->extra_regs().print_register_file_compact(stderr);
      fprintf(stderr, " ticks:%" PRId64 "\n", t->tick_count());
    }

    FrameTime before_time = replay_session->trace_reader().time();
    auto result = replay_session->replay_step(cmd);
    FrameTime after_time = replay_session->trace_reader().time();
    DEBUG_ASSERT(after_time >= before_time && after_time <= before_time + 1);

    ++step_count;
    if (DUMP_STATS_PERIOD > 0 && step_count % DUMP_STATS_PERIOD == 0) {
      struct timeval now;
      gettimeofday(&now, NULL);
      Session::Statistics stats = replay_session->statistics();
      printf(
          "[ReplayStatistics] ticks %lld syscalls %lld bytes_written %lld "
          "microseconds %lld\n",
          (long long)(stats.ticks_processed - last_stats.ticks_processed),
          (long long)(stats.syscalls_performed - last_stats.syscalls_performed),
          (long long)(stats.bytes_written - last_stats.bytes_written),
          (long long)(to_microseconds(now) - to_microseconds(last_dump_time)));
      last_dump_time = now;
      last_stats = stats;
    }

    if (result.status == REPLAY_EXITED) {
      break;
    }
    DEBUG_ASSERT(result.status == REPLAY_CONTINUE);
    DEBUG_ASSERT(result.break_status.watchpoints_hit.empty());
    DEBUG_ASSERT(!result.break_status.breakpoint_hit);
    DEBUG_ASSERT(cmd == RUN_SINGLESTEP ||
                 !result.break_status.singlestep_complete);
  }

  LOG(info) << "Replayer successfully finished";
}

/* Handling ctrl-C during replay:
 * We want the entire group of processes to remain a single process group
 * since that allows shell job control to work best.
 * We want ctrl-C to not reach tracees, because that would disturb replay.
 * That's taken care of by Task::set_up_process.
 * We allow terminal SIGINT to go directly to the parent and the child (rr).
 * rr's SIGINT handler |handle_SIGINT_in_child| just interrupts the replay
 * if we're in the process of replaying to a target event, otherwise it
 * does nothing.
 * Before the parent execs gdb, its SIGINT handler does nothing. After exec,
 * the signal handler is reset to default so gdb behaves as normal (which is
 * why we use a signal handler instead of SIG_IGN).
 */
static void handle_SIGINT_in_parent(int sig) {
  DEBUG_ASSERT(sig == SIGINT);
  // Just ignore it.
}

static GdbServer* server_ptr = nullptr;

static void handle_SIGINT_in_child(int sig) {
  DEBUG_ASSERT(sig == SIGINT);
  if (server_ptr) {
    server_ptr->interrupt_replay_to_target();
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
      GdbServer::ConnectionFlags conn_flags;
      conn_flags.dbg_port = flags.dbg_port;
      conn_flags.dbg_host = flags.dbg_host;
      conn_flags.debugger_name = flags.gdb_binary_file_path;
      conn_flags.keep_listening = flags.keep_listening;
      GdbServer(session, session_flags(flags), target).serve_replay(conn_flags);
    }

    // Everything should have been cleaned up by now.
    check_for_leaks();
    return 0;
  }

  int debugger_params_pipe[2];
  if (pipe2(debugger_params_pipe, O_CLOEXEC)) {
    FATAL() << "Couldn't open debugger params pipe.";
  }
  if (0 == (waiting_for_child = fork())) {
    // Ensure only the parent has the read end of the pipe open. Then if
    // the parent dies, our writes to the pipe will error out.
    close(debugger_params_pipe[0]);

    {
      prctl(PR_SET_PDEATHSIG, SIGTERM, 0, 0, 0);

      ScopedFd debugger_params_write_pipe(debugger_params_pipe[1]);
      auto session = ReplaySession::create(trace_dir);
      GdbServer::ConnectionFlags conn_flags;
      conn_flags.dbg_port = flags.dbg_port;
      conn_flags.dbg_host = flags.dbg_host;
      conn_flags.debugger_params_write_pipe = &debugger_params_write_pipe;
      GdbServer server(session, session_flags(flags), target);

      server_ptr = &server;
      struct sigaction sa;
      memset(&sa, 0, sizeof(sa));
      sa.sa_flags = SA_RESTART;
      sa.sa_handler = handle_SIGINT_in_child;
      if (sigaction(SIGINT, &sa, nullptr)) {
        FATAL() << "Couldn't set sigaction for SIGINT.";
      }

      server.serve_replay(conn_flags);
    }
    // Everything should have been cleaned up by now.
    check_for_leaks();
    return 0;
  }
  // Ensure only the child has the write end of the pipe open. Then if
  // the child dies, our reads from the pipe will return EOF.
  close(debugger_params_pipe[1]);
  LOG(debug) << getpid() << ": forked debugger server " << waiting_for_child;

  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_flags = SA_RESTART;
  sa.sa_handler = handle_SIGINT_in_parent;
  if (sigaction(SIGINT, &sa, nullptr)) {
    FATAL() << "Couldn't set sigaction for SIGINT.";
  }

  {
    ScopedFd params_pipe_read_fd(debugger_params_pipe[0]);
    GdbServer::launch_gdb(params_pipe_read_fd, flags.gdb_binary_file_path,
                          flags.gdb_options);
  }

  // Child must have died before we were able to get debugger parameters
  // and exec gdb. Exit with the exit status of the child.
  while (true) {
    int status;
    int ret = waitpid(waiting_for_child, &status, 0);
    int err = errno;
    LOG(debug) << getpid() << ": waitpid(" << waiting_for_child << ") returned "
               << errno_name(err) << "(" << err << "); status:" << HEX(status);
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

int ReplayCommand::run(vector<string>& args) {
  bool found_dir = false;
  string trace_dir;
  ReplayFlags flags;

  while (!args.empty()) {
    if (parse_replay_arg(args, flags)) {
      continue;
    }
    if (parse_literal(args, "--")) {
      flags.gdb_options.insert(flags.gdb_options.end(), args.begin(),
                               args.end());
      break;
    }
    if (!found_dir && parse_optional_trace_dir(args, &trace_dir)) {
      found_dir = true;
      continue;
    }
    print_help(stderr);
    return 1;
  }

  if (!flags.target_command.empty()) {
    flags.target_process =
        find_pid_for_command(trace_dir, flags.target_command);
    if (flags.target_process <= 0) {
      fprintf(stderr, "No process '%s' found. Try 'rr ps'.\n",
              flags.target_command.c_str());
      return 2;
    }
  }
  if (flags.process_created_how != ReplayFlags::CREATED_NONE) {
    if (!pid_exists(trace_dir, flags.target_process)) {
      fprintf(stderr, "No process %d found in trace. Try 'rr ps'.\n",
              flags.target_process);
      return 2;
    }
    if (flags.process_created_how == ReplayFlags::CREATED_EXEC &&
        !pid_execs(trace_dir, flags.target_process)) {
      fprintf(stderr, "Process %d never exec()ed. Try 'rr ps', or use "
                      "'-f'.\n",
              flags.target_process);
      return 2;
    }
  }

  assert_prerequisites();

  if (running_under_rr()) {
    if (!Flags::get().suppress_environment_warnings) {
      fprintf(stderr, "rr: rr pid %d running under parent %d. Good luck.\n",
              getpid(), getppid());
    }
    if (trace_dir.empty()) {
      fprintf(stderr,
              "rr: No trace-dir supplied. You'll try to replay the "
              "recording of this rr and have a bad time. Bailing out.\n");
      return 3;
    }
  }

  if (flags.keep_listening && flags.dbg_port == -1) {
    fprintf(stderr,
            "Cannot use --keep-listening (-k) without --dbgport (-s).\n");
    return 4;
  }

  return replay(trace_dir, flags);
}

} // namespace rr
