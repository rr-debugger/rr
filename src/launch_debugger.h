/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_LAUNCH_DEBUGGER_H_
#define RR_LAUNCH_DEBUGGER_H_

#include <string>
#include <vector>

#include "ScopedFd.h"
#include "Task.h"

namespace rr {

/**
 * exec()'s the debuger using parameters read from params_pipe_fd.
 */
void launch_debugger(ScopedFd& params_pipe_fd, const std::string& debugger_file_path,
                     const std::vector<std::string>& options, bool serve_files);

/**
 * Produces the command line needed to launch the debugger.
 */
std::vector<std::string> debugger_launch_command(Task* t, const std::string& host,
                                                 unsigned short port,
                                                 bool serve_files,
                                                 const std::string& debugger_name);

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

} // namespace rr

#endif /* RR_LAUNCH_DEBUGGER_H_ */
