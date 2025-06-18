/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/syscall.h>

#include <limits.h>
#include <memory>
#include <sstream>
#include <string>

#include "launch_debugger.h"

#include "DebuggerExtensionCommandHandler.h"
#include "GdbServer.h"
#include "GdbServerConnection.h"
#include "kernel_supplement.h"
#include "log.h"
#include "StringVectorToCharArray.h"
#include "util.h"

using namespace std;

namespace rr {

// Special-sauce macros defined by rr when launching the gdb client,
// which implement functionality outside of the gdb remote protocol.
// (Don't stare at them too long or you'll go blind ;).)
static string gdb_rr_macros(const string* file_to_delete) {
  stringstream ss;
  ss << DebuggerExtensionCommandHandler::gdb_macros()
     // gdb warns about redefining inbuilt commands, silence that by
     // wrapping it in python code
     << "python gdb.execute('define jump\\nrr-denied jump\\nend')\n"
     << "python gdb.execute('define restart\\nrun c$arg0\\nend')\n"
     << "document restart\n"
     << "restart at checkpoint N\n"
     << "checkpoints are created with the 'checkpoint' command\n"
     << "end\n"
     << "define seek-ticks\n"
     << "  run t$arg0\n"
     << "end\n"
     << "document seek-ticks\n"
     << "restart at given ticks value\n"
     << "end\n"
     // In gdb version "Fedora 7.8.1-30.fc21", a raw "run" command
     // issued before any user-generated resume-execution command
     // results in gdb hanging just after the inferior hits an internal
     // gdb breakpoint.  This happens outside of rr, with gdb
     // controlling gdbserver, as well.  We work around that by
     // ensuring *some* resume-execution command has been issued before
     // restarting the session.  But, only if the inferior hasn't
     // already finished execution ($_thread != 0).  If it has and we
     // issue the "stepi" command, then gdb refuses to restart
     // execution.
     << "define hook-run\n"
     << "  rr-hook-run\n"
     << "end\n"
     << "define hookpost-continue\n"
     << "  rr-set-suppress-run-hook 1\n"
     << "end\n"
     << "define hookpost-step\n"
     << "  rr-set-suppress-run-hook 1\n"
     << "end\n"
     << "define hookpost-stepi\n"
     << "  rr-set-suppress-run-hook 1\n"
     << "end\n"
     << "define hookpost-next\n"
     << "  rr-set-suppress-run-hook 1\n"
     << "end\n"
     << "define hookpost-nexti\n"
     << "  rr-set-suppress-run-hook 1\n"
     << "end\n"
     << "define hookpost-finish\n"
     << "  rr-set-suppress-run-hook 1\n"
     << "end\n"
     << "define hookpost-reverse-continue\n"
     << "  rr-set-suppress-run-hook 1\n"
     << "end\n"
     << "define hookpost-reverse-step\n"
     << "  rr-set-suppress-run-hook 1\n"
     << "end\n"
     << "define hookpost-reverse-stepi\n"
     << "  rr-set-suppress-run-hook 1\n"
     << "end\n"
     << "define hookpost-reverse-finish\n"
     << "  rr-set-suppress-run-hook 1\n"
     << "end\n"
     << "define hookpost-run\n"
     << "  rr-set-suppress-run-hook 0\n"
     << "end\n"
     << "set unwindonsignal on\n"
     << "set non-stop off\n"
     << "handle SIGURG stop\n"
     << "set prompt (rr) \n"
     // Try both "set target-async" and "maint set target-async" since
     // that changed recently.
     << "python\n"
     << "import re\n"
     << "import os\n"
     << "m = re.compile(r"
     << "'[^0-9]*([0-9]+)\\.([0-9]+)(\\.([0-9]+))?'"
     << ").match(gdb.VERSION)\n"
     << "ver = int(m.group(1))*10000 + int(m.group(2))*100\n"
     << "if m.group(4):\n"
     << "    ver = ver + int(m.group(4))\n"
     << "\n"
     << "if ver == 71100:\n"
     << "    gdb.write("
     << "'This version of gdb (7.11.0) has known bugs that break rr. "
     << "Install 7.11.1 or later.\\n', gdb.STDERR)\n"
     << "\n"
     << "if ver < 71101:\n"
     << "    gdb.execute('set target-async 0')\n"
     << "    gdb.execute('maint set target-async 0')\n";
  if (file_to_delete) {
    ss << "os.unlink('" << *file_to_delete << "')\n";
  }
  ss << "end\n";
  return ss.str();
}

static const string& lldb_python_rr_macros(
    const string* file_to_delete, const string* module_name) {
  static string s;

  if (s.empty()) {
    auto cmds = DebuggerExtensionCommandHandler::lldb_python_macros(
        module_name);
    stringstream ss;
    ss << cmds.toplevel_definitions
       << "import os\n"
       << "def  __lldb_init_module(debugger, internal_dict):\n"
       << cmds.run_on_startup
       << "    debugger.HandleCommand('set set prompt \"(rr) \"')\n";
    if (file_to_delete) {
      ss << "    os.unlink('" << *file_to_delete << "')\n";
    }
    ss << "\n";
    s = ss.str();
  }
  return s;
}

static void push_default_gdb_options(vector<string>& vec, bool serve_files) {
  // The gdb protocol uses the "vRun" packet to reload
  // remote targets.  The packet is specified to be like
  // "vCont", in which gdb waits infinitely long for a
  // stop reply packet.  But in practice, gdb client
  // expects the vRun to complete within the remote-reply
  // timeout, after which it issues vCont.  The timeout
  // causes gdb<-->rr communication to go haywire.
  //
  // rr can take a very long time indeed to send the
  // stop-reply to gdb after restarting replay; the time
  // to reach a specified execution target is
  // theoretically unbounded.  Timing out on vRun is
  // technically a gdb bug, but because the rr replay and
  // the gdb reload models don't quite match up, we'll
  // work around it on the rr side by disabling the
  // remote-reply timeout.
  vec.push_back("-l");
  vec.push_back("10000");
  if (!serve_files) {
    // For now, avoid requesting binary files through vFile. That is slow and
    // hard to make work correctly, because gdb requests files based on the
    // names it sees in memory and in ELF, and those names may be symlinks to
    // the filenames in the trace, so it's hard to match those names to files in
    // the trace.
    vec.push_back("-ex");
    vec.push_back("set sysroot /");
  }
}

static void push_gdb_target_remote_cmd(vector<string>& vec, int socket_domain,
                                       const string& host,
                                       unsigned short port) {
  vec.push_back("-ex");
  stringstream ss;
  switch (socket_domain) {
    case AF_INET:
      // If we omit the address, then gdb can try to resolve "localhost" which
      // in some broken environments may not actually resolve to the local host
      ss << "target extended-remote " << host << ":" << port;
      break;
    case AF_INET6:
      ss << "target extended-remote tcp6:[" << host << "]:" << port;
      break;
    default:
      FATAL() << "Unknown socket domain " << socket_domain;
      break;
  }
  vec.push_back(ss.str());
}

static void push_lldb_target_remote_cmd(vector<string>& vec, int socket_domain,
                                        const string& host,
                                        unsigned short port) {
  vec.push_back("-o");
  stringstream ss;
  switch (socket_domain) {
    case AF_INET:
    case AF_INET6:
      ss << "gdb-remote [" << host << "]:" << port;
      break;
    default:
      FATAL() << "Unknown socket domain " << socket_domain;
      break;
  }
  vec.push_back(ss.str());
}

string saved_debugger_launch_command;

vector<string> debugger_launch_command(Task* t, int socket_domain,
                                       const string& host,
                                       unsigned short port,
                                       bool serve_files,
                                       const string& debugger_name,
                                       DebuggerType debugger_type) {
  vector<string> cmd;
  cmd.push_back(debugger_name);
  switch (debugger_type) {
    case DebuggerType::GDB:
      push_default_gdb_options(cmd, serve_files);
      push_gdb_target_remote_cmd(cmd, socket_domain, host, port);
      break;
    case DebuggerType::LLDB:
      cmd.push_back("--source-quietly");
      push_lldb_target_remote_cmd(cmd, socket_domain, host, port);
      break;
    default:
      FATAL() << "Unknown debugger type";
      break;
  }
  cmd.push_back(t->vm()->exe_image());
  saved_debugger_launch_command = to_shell_string(cmd);
  return cmd;
}

string to_shell_string(const vector<string>& args) {
  stringstream ss;
  for (auto& a : args) {
    ss << "'" << a << "' ";
  }
  return ss.str();
}

static bool needs_target(const string& option) {
  return !strncmp(option.c_str(), "continue", option.size());
}

/**
 * Exec the debuger using the params that were written to
 * `params_pipe_fd`.
 */
void launch_debugger(ScopedFd& params_pipe_fd,
                     const string& debugger_file_path,
                     DebuggerType debugger_type,
                     const vector<string>& options,
                     bool serve_files) {
  DebuggerParams params;
  ssize_t nread;
  while (true) {
    nread = read(params_pipe_fd, &params, sizeof(params));
    if (nread == 0) {
      // pipe was closed. Probably rr failed/died.
      return;
    }
    if (nread != -1 || errno != EINTR) {
      break;
    }
  }
  DEBUG_ASSERT(nread == sizeof(params));

  const string& host(params.host);
  int socket_domain(params.socket_domain);
  uint16_t port(params.port);

  vector<string> cmd;
  cmd.push_back(debugger_file_path);
  vector<string> env = current_env();

  // LLDB 'command script import' requires the filename to be a valid Python
  // identifier.
  TempFile file = create_temporary_file("rr_debugger_commands_XXXXXX");
  switch (debugger_type) {
    case DebuggerType::GDB: {
      push_default_gdb_options(cmd, serve_files);
      string script = gdb_rr_macros(&file.name);
      write_all(file.fd, script.data(), script.size());
      cmd.push_back("-x");
      cmd.push_back(file.name);

      bool did_set_remote = false;
      for (size_t i = 0; i < options.size(); ++i) {
        if (!did_set_remote && options[i] == "-ex" &&
            i + 1 < options.size() && needs_target(options[i + 1])) {
          push_gdb_target_remote_cmd(cmd, socket_domain, host, port);
          did_set_remote = true;
        }
        cmd.push_back(options[i]);
      }
      if (!did_set_remote) {
        push_gdb_target_remote_cmd(cmd, socket_domain, host, port);
      }

      env.push_back("GDB_UNDER_RR=1");
      break;
    }
    case DebuggerType::LLDB: {
      cmd.push_back("--source-quietly");
      cmd.insert(cmd.end(), options.begin(), options.end());
      push_lldb_target_remote_cmd(cmd, socket_domain, host, port);
      // LLDB 'command script import' requires the file to end in '.py'.
      string new_name = file.name + ".py";
      if (::syscall(SYS_renameat2, AT_FDCWD, file.name.c_str(), AT_FDCWD, new_name.c_str(),
                    RENAME_NOREPLACE)) {
        FATAL() << "Can't fix temp file name";
      }
      string module_name(basename(file.name.c_str()));
      string script = lldb_python_rr_macros(&new_name, &module_name);
      write_all(file.fd, script.data(), script.size());
      cmd.push_back("-o");
      cmd.push_back("command script import " + new_name);
      env.push_back("LLDB_UNDER_RR=1");
      break;
    }
    default:
      FATAL() << "Unknown debugger type";
      break;
  }

  cmd.push_back(params.exe_image);

  LOG(debug) << "launching " << to_shell_string(cmd);

  StringVectorToCharArray c_args(cmd);
  StringVectorToCharArray c_env(env);
  execvpe(debugger_file_path.c_str(), c_args.get(), c_env.get());
  CLEAN_FATAL() << "Failed to exec " << debugger_file_path << ".";
}

void emergency_debug(Task* t) {
  // See the comment in |guard_overshoot()| explaining why we do
  // this.  Unlike in that context though, we don't know if |t|
  // overshot an internal breakpoint.  If it did, cover that
  // breakpoint up.
  if (t->vm()) {
    t->vm()->remove_all_breakpoints();
  }

  // Don't launch a debugger on fatal errors; the user is most
  // likely already in a debugger, and wouldn't be able to
  // control another session. Instead, launch a new GdbServer and wait for
  // the user to connect from another window.
  GdbServerConnection::Features features;
  // Don't advertise reverse_execution to gdb because a) it won't work and
  // b) some gdb versions will fail if the user doesn't turn off async
  // mode (and we don't want to require users to do that)
  features.reverse_execution = false;
  OpenedSocket listen_socket = open_socket(string(), t->tid, PROBE_PORT);

  {
    ScopedFd fd(STDERR_FILENO);
    dump_rr_stack(fd);
    fd.extract();
  }

  char* test_monitor_pid = getenv("RUNNING_UNDER_TEST_MONITOR");
  if (test_monitor_pid) {
    pid_t pid = atoi(test_monitor_pid);
    // Tell test-monitor to wake up and take a snapshot. It will also
    // connect the emergency debugger so let that happen.
    FILE* gdb_cmd = fopen("gdb_cmd", "w");
    if (gdb_cmd) {
      fputs(to_shell_string(
          debugger_launch_command(t, listen_socket.domain,
              listen_socket.host, listen_socket.port, false, "gdb",
              DebuggerType::GDB)).c_str(), gdb_cmd);
      fclose(gdb_cmd);
    }
    kill(pid, SIGURG);
  } else {
    vector<string> cmd = debugger_launch_command(t,
        listen_socket.domain, listen_socket.host, listen_socket.port,
        false, "gdb", DebuggerType::GDB);
    fprintf(stderr, "Launch debugger with\n  %s\n", to_shell_string(cmd).c_str());
  }
  unique_ptr<GdbServerConnection> dbg =
      GdbServerConnection::await_connection(t, listen_socket.fd, DebuggerType::GDB, features);
  GdbServer::serve_emergency_debugger(std::move(dbg), t);
}

string gdb_init_script() { return gdb_rr_macros(nullptr); }

string lldb_init_script() { return lldb_python_rr_macros(nullptr, nullptr); }

} // namespace rr
