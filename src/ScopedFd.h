/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_SCOPED_FD_H_
#define RR_SCOPED_FD_H_

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "log.h"

namespace rr {

/**
 * RAII helper to open a file and then close the fd when the helper
 * goes out of scope.
 */
class ScopedFd {
public:
  ScopedFd() : fd(-1) {}
  explicit ScopedFd(int fd) : fd(fd) {}
  ScopedFd(const char* pathname, int flags, mode_t mode = 0)
      : fd(open(pathname, flags, mode)) {}
  ScopedFd(ScopedFd&& other) : fd(other.fd) { other.fd = -1; }
  ~ScopedFd() { close(); }

  ScopedFd& operator=(ScopedFd&& other) {
    close();
    fd = other.fd;
    other.fd = -1;
    return *this;
  }

  operator int() const { return get(); }
  int get() const { return fd; }
  int extract() {
    int result = fd;
    fd = -1;
    return result;
  }

  bool is_open() const { return fd >= 0; }
  void close() {
    if (fd >= 0) {
      int err = ::close(fd);
      // With EINTR/EIO, it is unspecified whether fd will be
      // closed, but on Linux, it is always removed from the FD
      // table, so the close was successful for our purposes.
      if (err != 0 && err != -EINTR && err != -EIO) {
        FATAL() << "Unexpected error while closing fd " << fd;
      }
    }
    fd = -1;
  }

  static ScopedFd openat(const ScopedFd &dir, const char* pathname,
                         int flags, mode_t mode = 0) {
    return ScopedFd(::openat(dir.get(), pathname, flags, mode));
  }

private:
  int fd;
};

} // namespace rr

#endif // RR_SCOPED_FD_H
