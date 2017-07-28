/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define FILENAME "foo.txt"

static void verify_lock(int fd, struct flock64* lock) {
  ssize_t pagesize = sysconf(_SC_PAGESIZE);
  lock->l_type = F_WRLCK;
  test_assert(0 == fcntl(fd, F_OFD_GETLK, lock));

  test_assert(F_RDLCK == lock->l_type && pagesize / 2 == lock->l_start &&
              pagesize / 2 == lock->l_len);
}

int main(void) {
  ssize_t pagesize = sysconf(_SC_PAGESIZE);
  int fd, fd2;
  size_t i;
  int err;
  pid_t pid;
  int status;

  fd = open(FILENAME, O_CREAT | O_EXCL | O_RDWR, 0600);
  fd2 = open(FILENAME, O_EXCL | O_RDWR, 0600);
  test_assert(fd >= 0 && fd2 >= 0);

  unlink(FILENAME);

  /* Write a page's worth of data. */
  for (i = 0; i < pagesize / sizeof(i); ++i) {
    ssize_t nwritten = write(fd, &i, sizeof(i));
    test_assert(nwritten == sizeof(i));
  }

  struct flock64 lock = {.l_type = F_RDLCK,
                         .l_whence = SEEK_SET,
                         .l_start = pagesize,
                         .l_len = -pagesize / 2 };

  /* It should currently be unlocked. */
  err = fcntl(fd2, F_OFD_GETLK, &lock);
  if (err < 0 && errno == EINVAL) {
    atomic_puts("F_OFD_GETLK not supported");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }
  test_assert(0 == err);

  test_assert(F_UNLCK == lock.l_type);

  if (0 == (pid = fork())) {
    lock.l_type = F_RDLCK;
    fcntl(fd, F_OFD_SETLK, &lock);
    test_assert(0 == err);

    /* Close a dup of the file descriptor. This should not release the lock */
    test_assert(0 == close(dup(fd)));

    /* Make sure our lock "took". */
    if (0 == (pid = fork())) {
      verify_lock(fd2, &lock);
      exit(0);
    }

    waitpid(pid, &status, 0);
    test_assert(WIFEXITED(status) && 0 == WEXITSTATUS(status));
    return 0;
  }

  waitpid(pid, &status, 0);
  test_assert(WIFEXITED(status) && 0 == WEXITSTATUS(status));

  /* Should still be locked, since the lock is associated with the file
     descriptor, not the process */
  verify_lock(fd2, &lock);

  /* This should release the lock */
  close(fd);

  lock.l_type = F_RDLCK;
  lock.l_whence = SEEK_SET;
  lock.l_start = pagesize;
  lock.l_len = -pagesize / 2;
  lock.l_pid = 0;
  test_assert(0 == fcntl(fd2, F_OFD_GETLK, &lock));
  test_assert(F_UNLCK == lock.l_type);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
