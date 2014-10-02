/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_SCOPED_FD_H_
#define RR_SCOPED_FD_H_

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

/**
 * RAII helper to open a file and then close the fd when the helper
 * goes out of scope.
 */
class ScopedFd {
public:
  ScopedFd(int fd) : fd(fd) {}
  ScopedFd(const char* pathname, int flags, mode_t mode = 0)
      : fd(open(pathname, flags, mode)) {}
  ~ScopedFd() { close(fd); }

  operator int() const { return get(); }
  int get() const { return fd; }

private:
  int fd;
};

#endif // RR_SCOPED_FD_H
