/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

#define FILENAME "foo.txt"

#ifndef F_OFD_GETLK     /* In case we are on a system with glibc version
                           earlier than 2.20 */
#define F_OFD_GETLK     36
#define F_OFD_SETLK     37
#define F_OFD_SETLKW    38
#endif

int main(void) {
  ssize_t pagesize = sysconf(_SC_PAGESIZE);
  int fd;
  int fd2;
  size_t i;
  int err;
  pid_t parent_pid = getpid();
  pid_t pid;
  int status;

  fd = open(FILENAME, O_CREAT | O_EXCL | O_RDWR, 0600);
  fd2 = open(FILENAME, O_RDWR);
  test_assert(fd >= 0 && fd2 >= 0);

  unlink(FILENAME);

  atomic_printf("parent pid is %d\n", parent_pid);

  /* Write a page's worth of data. */
  for (i = 0; i < pagesize / sizeof(i); ++i) {
    ssize_t nwritten = write(fd, &i, sizeof(i));
    test_assert(nwritten == sizeof(i));
  }

  {
    struct flock64 lock = {
      .l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = pagesize, .l_pid = 0
    };

    atomic_printf("sizeof(flock64) = %zu\n", sizeof(lock));
    err = fcntl(fd, F_OFD_GETLK, &lock);
    if (err == -1 && errno == EINVAL)
    {
      // should we succeed when OFD locks are not supported?
      atomic_puts("EXIT-SUCCESS");
      return 0;
    }

    test_assert(0 == err);

    atomic_printf("before lock: type: %d, pid: %d\n", lock.l_type, lock.l_pid);
    test_assert(F_UNLCK == lock.l_type);

    lock.l_type = F_WRLCK;
    fcntl(fd, F_OFD_SETLK, &lock);
    test_assert(0 == err);

    /* Make sure our lock "took". */
    if (0 == (pid = fork())) {
      lock.l_type = F_RDLCK;
      err = fcntl(fd2, F_OFD_GETLK, &lock);
      test_assert(0 == err);

      atomic_printf("  after GETLK: type: %d, pid: %d\n", lock.l_type,
                    lock.l_pid);
      test_assert(F_WRLCK == lock.l_type && 0 == lock.l_start &&
                  pagesize == lock.l_len && -1 == lock.l_pid);

      lock.l_type = F_RDLCK;
      lock.l_pid = 0;
      err = fcntl(fd2, F_OFD_SETLKW, &lock);
      test_assert(0 == err);

      atomic_printf("  after SETLKW: type: %d, pid: %d\n", lock.l_type,
                    lock.l_pid);
      test_assert(F_RDLCK == lock.l_type && 0 == lock.l_start &&
                  pagesize == lock.l_len && 0 == lock.l_pid);

      atomic_puts("  releasing lock ...");
      lock.l_type = F_UNLCK;
      fcntl(fd2, F_OFD_SETLK, &lock);
      test_assert(0 == err);
      return 0;
    }

    atomic_puts("P: forcing child to block on LK, sleeping ...");
    usleep(500000);
    atomic_puts("P: ... awake, releasing lock");
    lock.l_type = F_UNLCK;
    fcntl(fd, F_OFD_SETLK, &lock);
    test_assert(0 == err);

    waitpid(pid, &status, 0);
    test_assert(WIFEXITED(status) && 0 == WEXITSTATUS(status));
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
