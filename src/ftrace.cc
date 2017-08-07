/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "ftrace.h"

#include <limits.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>

#include <sstream>

#include "ScopedFd.h"
#include "Session.h"
#include "Task.h"
#include "core.h"
#include "log.h"

using namespace std;

namespace rr {
namespace ftrace {

static ScopedFd control_fd;
static ScopedFd marker_fd;
static bool tracing = false;

static void open_socket() {
  string s = string(getenv("HOME")) + "/.local/share/rr/ftrace";
  control_fd = socket(AF_UNIX, SOCK_STREAM, 0);
  if (control_fd < 0) {
    FATAL() << "Cannot create socket";
  }
  DEBUG_ASSERT(control_fd >= 0);
  struct sockaddr_un addr;
  addr.sun_family = AF_UNIX;
  if (s.size() + 1 > sizeof(addr.sun_path)) {
    FATAL() << "Pathname '" << s << "' too long";
  }
  strcpy(addr.sun_path, s.c_str());
  int ret = connect(control_fd, (struct sockaddr*)&addr, sizeof(addr));
  if (ret < 0 && (errno == ENOENT || errno == ECONNREFUSED)) {
    FATAL() << "ftrace-helper not running. Run ftrace-helper first.";
  }
  if (ret < 0) {
    FATAL() << "Can't connect to socket " << s;
  }
}

static void write_control_message(const string& s) {
  ssize_t ret = ::write(control_fd, s.c_str(), s.size());
  if (ret != (ssize_t)s.size()) {
    FATAL() << "Can't write line to socket " << s;
  }
}

static void wait_for_reply() {
  char ch;
  if (read(control_fd, &ch, 1) != 1) {
    FATAL() << "Can't read reply from socket";
  }
}

static void receive_marker_fd() {
  char received_data;
  struct iovec msgdata;
  msgdata.iov_base = &received_data;
  msgdata.iov_len = 1;

  char cmsgbuf[CMSG_SPACE(sizeof(int))];
  struct msghdr msg;
  memset(&msg, 0, sizeof(msg));
  msg.msg_control = cmsgbuf;
  msg.msg_controllen = sizeof(cmsgbuf);
  msg.msg_iov = &msgdata;
  msg.msg_iovlen = 1;

  if (0 > recvmsg(control_fd, &msg, 0)) {
    FATAL() << "Failed to receive fd";
  }
  DEBUG_ASSERT(received_data == 'F');

  struct cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
  DEBUG_ASSERT(cmsg && cmsg->cmsg_level == SOL_SOCKET &&
               cmsg->cmsg_type == SCM_RIGHTS);
  marker_fd = ScopedFd(*(int*)CMSG_DATA(cmsg));
  DEBUG_ASSERT(marker_fd.is_open());
}

void start_function_graph(const Session& session, const TraceStream& trace) {
  if (tracing) {
    return;
  }

  if (!control_fd.is_open()) {
    open_socket();
  }

  stringstream ss;
  ss << trace.bound_to_cpu() << "\n";

  ss << getpid() << "\n";
  for (auto& it : session.tasks()) {
    ss << it.second->tid << "\n";
  }
  ss << "\n";

  write_control_message(ss.str());

  receive_marker_fd();

  wait_for_reply();
  tracing = true;
}

void write(const string& str) {
  if (!marker_fd.is_open()) {
    return;
  }
  size_t last_start = 0;
  for (size_t i = 0; i < str.size(); ++i) {
    if (str[i] == '\n') {
      if (i > last_start) {
        string s = str.substr(last_start, i + 1 - last_start);
        ssize_t ret = ::write(marker_fd, s.c_str(), s.size());
        if (ret != (ssize_t)s.size()) {
          FATAL() << "Can't write line to socket " << s;
        }
      }
      last_start = i + 1;
    }
  }
}

void stop() {
  if (tracing) {
    marker_fd.close();
    write_control_message("end\n");
    wait_for_reply();
    tracing = false;
  }
}
}
}
