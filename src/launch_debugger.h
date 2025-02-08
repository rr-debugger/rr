/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_LAUNCH_DEBUGGER_H_
#define RR_LAUNCH_DEBUGGER_H_

#include <limits.h>

#include <string>
#include <vector>

#include "ScopedFd.h"
#include "Task.h"

namespace rr {

// Controls the command-line arguments and command syntax we'll use
// to control the debugger.
enum class DebuggerType {
  // GDB and compatible debuggers
  GDB,
  // LLDB and compatible debuggers
  LLDB,
};

struct DebuggerParams {
  char exe_image[PATH_MAX];
  int socket_domain;
  char host[128];
  short port;
};

/**
 * exec()'s the debuger using parameters read from params_pipe_fd.
 */
void launch_debugger(ScopedFd& params_pipe_fd, const std::string& debugger_file_path,
                     DebuggerType debugger_type, const std::vector<std::string>& options,
                     bool serve_files);

/**
 * Produces the command line needed to launch the debugger.
 */
std::vector<std::string> debugger_launch_command(Task* t, int socket_domain,
                                                 const std::string& host,
                                                 unsigned short port,
                                                 bool serve_files,
                                                 const std::string& debugger_name,
                                                 DebuggerType debugger_type);

/**
 * Convert the command line to a string containing quoted parameters.
 */
std::string to_shell_string(const std::vector<std::string>& args);

/**
 * Start a debugging connection for |t| and return when there are no
 * more requests to process (usually because the debugger detaches).
 *
 * This helper doesn't attempt to determine whether blocking rr on a
 * debugger connection might be a bad idea.  It will always open the debug
 * socket and block awaiting a connection.
 */
void emergency_debug(Task* t);

/**
 * A string containing the default gdbinit script that we load into gdb.
 */
std::string gdb_init_script();

/**
 * A string containing the default lldbinit script that we load into lldb.
 */
std::string lldb_init_script();

} // namespace rr

#endif /* RR_LAUNCH_DEBUGGER_H_ */
