/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "ExportImportCheckpoints.h"

#include <fcntl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>

#include <sstream>

#include "log.h"
#include "main.h"

using namespace std;

/* Clients connect to the checkpoints socket and may send a one-byte command.
   Currently the only valid command value is 0: create a checkpoint.
*/

namespace rr {

bool parse_export_checkpoints(const string& arg, FrameTime& export_checkpoints_event,
                              int& export_checkpoints_count, string& export_checkpoints_socket) {
  size_t first_comma = arg.find(',');
  if (first_comma == string::npos) {
    fprintf(stderr, "Missing <NUM> parameter for --export-checkpoints");
    return false;
  }
  size_t second_comma = arg.find(',', first_comma + 1);
  if (second_comma == string::npos) {
    fprintf(stderr, "Missing <FILE> parameter for --export-checkpoints");
    return false;
  }
  char* endptr;
  string event_str = arg.substr(0, first_comma);
  export_checkpoints_event = strtoul(event_str.c_str(), &endptr, 0);
  if (*endptr) {
    fprintf(stderr, "Invalid <EVENT> for --export-checkpoints: %s\n", event_str.c_str());
    return false;
  }
  string num_str = arg.substr(first_comma + 1, second_comma - (first_comma + 1));
  export_checkpoints_count = strtoul(num_str.c_str(), &endptr, 0);
  if (*endptr) {
    fprintf(stderr, "Invalid <NUM> for --export-checkpoints: %s\n", num_str.c_str());
    return false;
  }
  export_checkpoints_socket = arg.substr(second_comma + 1);
  return true;
}

ScopedFd bind_export_checkpoints_socket(int count, const string& socket_file_name) {
  unlink(socket_file_name.c_str());

  ScopedFd sock = ScopedFd(socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0));
  if (!sock.is_open()) {
    FATAL() << "Can't create Unix socket " << socket_file_name;
  }
  if (socket_file_name.size() + 1 > sizeof(sockaddr_un::sun_path)) {
    FATAL() << "Socket file name " << socket_file_name << " too long";
  }
  int reuse = 1;
  int ret = setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
  if (ret < 0) {
    FATAL() << "Failed to set SO_REUSEADDR";
  }
  sockaddr_un addr;
  addr.sun_family = AF_UNIX;
  strcpy(addr.sun_path, socket_file_name.c_str());
  ret = ::bind(sock, (const sockaddr*)&addr, sizeof(addr));
  if (ret < 0) {
    FATAL() << "Can't bind Unix socket " << socket_file_name;
  }
  ret = listen(sock, count);
  if (ret < 0) {
    FATAL() << "Can't listen on Unix socket " << socket_file_name;
  }
  return sock;
}

static void send_all(ScopedFd& sock, const void* vbuf, size_t count) {
  const char* buf = static_cast<const char*>(vbuf);
  while (count > 0) {
    ssize_t ret = send(sock, buf, count, 0);
    if (ret <= 0) {
      FATAL() << "Failed to send complete message";
    }
    count -= ret;
    buf += ret;
  }
}

static void recv_all(ScopedFd& sock, void* vbuf, size_t count) {
  char* buf = static_cast<char*>(vbuf);
  while (count > 0) {
    ssize_t ret = recv(sock, buf, count, 0);
    if (ret <= 0) {
      FATAL() << "Failed to recv complete message";
    }
    count -= ret;
    buf += ret;
  }
}

static void setup_child_fds(vector<int> fds, CommandForCheckpoint& command_for_checkpoint) {
  command_for_checkpoint.exit_notification_fd = ScopedFd(fds[0]);
  for (int our_fd = 0; our_fd < 3; ++our_fd) {
    // We deliberately don't set CLOEXEC here since we might want these
    // to be inherited.
    int ret = dup2(fds[our_fd + 1], our_fd);
    if (ret < 0) {
      FATAL() << "Can't dup over stdin/stdout/stderr";
    }
    close(fds[our_fd + 1]);
  }

  for (size_t i = 4; i < fds.size(); ++i) {
    command_for_checkpoint.fds.push_back(ScopedFd(fds[i]));
  }
}

static void set_title(const vector<string>& args) {
  string line = "rr:";
  for (auto& a : args) {
    line += ' ';
    line += a;
  }

  char* arg0 = saved_argv0();
  size_t space = saved_argv0_space() - 1;
  if (space < 3) {
    return;
  }
  // To simplify things, instead of moving the environment around when the new command is too long,
  // we just truncate it.
  if (line.size() > space) {
    line[space - 3] = line[space - 2] = line[space - 1] = '.';
    line.resize(space);
  }
  memcpy(arg0, line.data(), line.size());
  memset(arg0 + line.size(), 0, space - line.size());
}

CommandForCheckpoint export_checkpoints(ReplaySession::shr_ptr session, int count, ScopedFd& sock,
    const std::string&) {
  if (!session->can_clone()) {
    FATAL() << "Can't create checkpoints at this time, aborting: " << session->current_frame_time();
  }

  CommandForCheckpoint command_for_checkpoint;

  vector<pid_t> children;
  for (int i = 0; i < count; ++i) {
    ScopedFd client = ScopedFd(accept4(sock, nullptr, nullptr, SOCK_CLOEXEC));
    if (!client.is_open()) {
      FATAL() << "Failed to accept client connection";
    }

    ssize_t priority;
    recv_all(client, &priority, sizeof(priority));
    ssize_t ret = setpriority(PRIO_PROCESS, 0, priority);
    if (ret < 0) {
      if (errno == EACCES) {
        LOG(warn) << "Failed to increase priority";
      } else {
        FATAL() << "Failed setpriority";
      }
    }

    size_t fds_size;
    recv_all(client, &fds_size, sizeof(fds_size));

    // Do the SCM_RIGHTS dance to receive file descriptors
    msghdr msg;
    memset(&msg, 0, sizeof(msg));
    char dummy_buf;
    iovec iov = { &dummy_buf, 1 };
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    vector<uint8_t> cbuf;
    size_t data_len = sizeof(int)*fds_size;
    cbuf.resize(CMSG_SPACE(data_len));
    msg.msg_control = cbuf.data();
    msg.msg_controllen = cbuf.size();
    ret = recvmsg(client, &msg, MSG_CMSG_CLOEXEC);
    if (ret != 1) {
      FATAL() << "Failed to read fds";
    }
    cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
    if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS || cmsg->cmsg_len != CMSG_LEN(data_len)) {
      FATAL() << "Invalid cmsg metadata";
    }
    vector<int> fds_data;
    fds_data.resize(fds_size);
    memcpy(fds_data.data(), CMSG_DATA(cmsg), data_len);

    size_t arg_count;
    recv_all(client, &arg_count, sizeof(arg_count));
    vector<string> args;
    for (size_t i = 0; i < arg_count; ++i) {
      size_t arg_size;
      recv_all(client, &arg_size, sizeof(arg_size));
      vector<char> arg;
      arg.resize(arg_size);
      recv_all(client, arg.data(), arg_size);
      args.push_back(string(arg.data(), arg.size()));
    }

    ReplaySession::shr_ptr checkpoint = session->clone();
    int parent_to_child_fds[2];
    ret = pipe(parent_to_child_fds);
    if (ret < 0) {
      FATAL() << "Can't pipe";
    }
    ScopedFd parent_to_child_read(parent_to_child_fds[0]);
    ScopedFd parent_to_child_write(parent_to_child_fds[1]);

    checkpoint->prepare_to_detach_tasks();

    // We need to create a new control socket for the child, we can't use the shared control socket
    // safely in multiple processes.
    int sockets[2];
    ret = socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sockets);
    if (ret < 0) {
      FATAL() << "socketpair failed";
    }
    ScopedFd new_tracee_socket(sockets[0]);
    ScopedFd new_tracee_socket_receiver(sockets[1]);

    pid_t child = fork();
    if (!child) {
      set_title(args);
      session->forget_tasks();
      command_for_checkpoint.args = move(args);
      command_for_checkpoint.session = move(checkpoint);
      setup_child_fds(fds_data, command_for_checkpoint);
      char ch;
      ret = read(parent_to_child_read, &ch, 1);
      if (ret != 1) {
        FATAL() << "Failed to read parent notification";
      }
      command_for_checkpoint.session->reattach_tasks(move(new_tracee_socket),
        move(new_tracee_socket_receiver));
      return command_for_checkpoint;
    }
    children.push_back(child);

    checkpoint->detach_tasks(child, new_tracee_socket_receiver);
    ret = write(parent_to_child_write, "x", 1);
    if (ret != 1) {
      FATAL() << "Failed to write parent notification";
    }
    for (auto d : fds_data) {
      close(d);
    }
  }

  // Wait for and reap all children
  for (size_t i = 0; i < children.size(); ++i) {
    int status;
    int ret = waitpid(children[i], &status, 0);
    if (ret < 0) {
      FATAL() << "Failed to wait for child " << children[i];
    }
  }

  return command_for_checkpoint;
}

void notify_normal_exit(ScopedFd& exit_notification_fd) {
  ssize_t ret = write(exit_notification_fd, "", 1);
  if (ret != 1) {
    FATAL() << "Can't send exit notification";
  }
}

int invoke_checkpoint_command(const string& socket_file_name,
    vector<string> args, vector<ScopedFd> fds) {
  ScopedFd sock = ScopedFd(socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0));
  if (!sock.is_open()) {
    FATAL() << "Can't create Unix socket " << socket_file_name;
  }
  if (socket_file_name.size() + 1 > sizeof(sockaddr_un::sun_path)) {
    FATAL() << "Socket file name " << socket_file_name << " too long";
  }
  sockaddr_un addr;
  addr.sun_family = AF_UNIX;
  strcpy(addr.sun_path, socket_file_name.c_str());
  while (true) {
    ssize_t ret = connect(sock, (const sockaddr*)&addr, sizeof(addr));
    if (ret < 0) {
      // We might try to connect between the socket being bound and listen()ed on
      if (errno == ENOENT || errno == ECONNREFUSED) {
        sleep(1);
        continue;
      }
      FATAL() << "Can't connect socket " << socket_file_name;
    }
    break;
  }

  ssize_t ret = getpriority(PRIO_PROCESS, 0);
  if (ret < 0) {
    FATAL() << "Failed getpriority";
  }
  send_all(sock, &ret, sizeof(ret));

  size_t total_fds = 4 + fds.size();
  send_all(sock, &total_fds, sizeof(total_fds));

  int exit_notification_pipe_fds[2];
  ret = pipe(exit_notification_pipe_fds);
  if (ret < 0) {
    FATAL() << "Failed pipe";
  }

  // Do the SCM_RIGHTS dance to send file descriptors.
  msghdr msg;
  memset(&msg, 0, sizeof(msg));
  char ch = 'x';
  iovec iov = { &ch, 1 };
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  vector<uint8_t> cbuf;
  size_t data_len = sizeof(int)*total_fds;
  cbuf.resize(CMSG_SPACE(data_len));
  msg.msg_control = cbuf.data();
  msg.msg_controllen = cbuf.size();
  cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
  cmsg->cmsg_level = SOL_SOCKET;
  cmsg->cmsg_type = SCM_RIGHTS;
  cmsg->cmsg_len = CMSG_LEN(data_len);
  char* cmsg_data = (char*)CMSG_DATA(cmsg);
  vector<int> int_fds;
  int_fds.push_back(exit_notification_pipe_fds[1]);
  int_fds.push_back(0);
  int_fds.push_back(1);
  int_fds.push_back(2);
  for (auto& fd : fds) {
    int_fds.push_back(fd);
  }
  memcpy(cmsg_data, int_fds.data(), sizeof(int)*int_fds.size());
  ret = sendmsg(sock, &msg, 0);
  if (ret != 1) {
    FATAL() << "Can't send file descriptors";
  }
  close(exit_notification_pipe_fds[1]);
  // Close stdin but keep stdout/stderr open in case we need to print something ourselves.
  close(0);

  size_t arg_count = args.size();
  send_all(sock, &arg_count, sizeof(arg_count));
  for (auto& arg : args) {
    size_t arg_size = arg.size();
    send_all(sock, &arg_size, sizeof(arg_size));
    send_all(sock, arg.data(), arg_size);
  }

  ret = read(exit_notification_pipe_fds[0], &ch, 1);
  if (ret < 0) {
    FATAL() << "Can't read from notification pipe";
  }
  if (ret == 0) {
    // abnormal termination
    return 1;
  }
  return 0;
}

} // namespace rr
