/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_EXPORT_IMPORT_CHECKPOINTS_H_
#define RR_EXPORT_IMPORT_CHECKPOINTS_H_

#include "ReplaySession.h"

#include <string>
#include <vector>

namespace rr {

bool parse_export_checkpoints(const std::string& arg, FrameTime& export_checkpoints_event,
                              int& export_checkpoints_count, std::string& export_checkpoints_socket);

/* Bind the socket so clients can try to connect to it and block. */
ScopedFd bind_export_checkpoints_socket(int count, const std::string& socket_file_name);

/* A command to run on the checkpoint */
struct CommandForCheckpoint {
  std::vector<std::string> args;
  std::vector<ScopedFd> fds;
  ReplaySession::shr_ptr session;
  ScopedFd exit_notification_fd;
};

/* Export checkpoints from the given session.
   This function will return `count` + 1 times; the first `count` times in a forked child
   with a valid CommandForCheckpoint with a nonnull `session`; the last time with a null
   `session` when all forked children have exited and been reaped.
   For the child returns, stdin/stdout/stderr will have been rebound to fds passed in over
   the socket.
*/
CommandForCheckpoint export_checkpoints(ReplaySession::shr_ptr session, int count, ScopedFd& sock,
    const std::string& socket_file_name);

/* After performing the CommandForCheckpoint, notify that we have exited normally. */
void notify_normal_exit(ScopedFd& exit_notification_fd);

/* Invoke a command on a checkpoint. stdin/stdout/stderr and the args and fds
   are passed to the exporter process, then we wait for it to complete and exit, and return
   an appropriate exit code.
*/
int invoke_checkpoint_command(const std::string& socket_file_name,
    std::vector<std::string> args, std::vector<ScopedFd> fds = std::vector<ScopedFd>());

} // namespace rr

#endif /* RR_EXPORT_IMPORT_CHECKPOINTS_H_ */
