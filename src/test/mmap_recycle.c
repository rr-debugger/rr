/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "nsutils.h"
#include "util.h"

#define PREFIX "./"

static int child_to_parent_pipe[2];

static void do_child(void) {
  struct stat st;
  unlink("foobar");
  int fd = open(PREFIX "foobar", O_CREAT | O_RDWR, 0700);
  test_assert(fd >= 0);
  int ret = unlink(PREFIX "foobar");
  test_assert(ret == 0);
  ret = write(fd, "x", 1);
  test_assert(ret == 1);
  ret = fstat(fd, &st);
  test_assert(ret == 0);
  void* p = mmap(NULL, 1, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
  test_assert(p != MAP_FAILED);
  ret = write(child_to_parent_pipe[1], &st.st_ino, sizeof(st.st_ino));
  test_assert(ret == sizeof(st.st_ino));
  kill(getpid(), SIGSTOP);
}

int main(void) {
  int ret = pipe(child_to_parent_pipe);
  pid_t child;
  ino_t child_inode;
  struct timespec ts = { 0, 1000000 };
  test_assert(ret == 0);

  for (int i = 0; i < 10; ++i) {
    char buf[100];
    sprintf(buf, PREFIX "foobar%d", i);
    unlink(buf);
  }

  child = fork();
  if (!child) {
    do_child();
    return 0;
  }
  ret = read(child_to_parent_pipe[0], &child_inode, sizeof(child_inode));
  test_assert(ret == sizeof(child_inode));
  ret = kill(child, SIGKILL);
  nanosleep(&ts, NULL);
  test_assert(ret == 0);
  /* now try to reuse the dev/ino */
  for (int i = 0; i < 10; ++i) {
    char buf[100];
    struct stat st;
    sprintf(buf, PREFIX "foobar%d", i);
    unlink(buf);
    int fd = open(buf, O_CREAT | O_RDWR, 0700);
    test_assert(fd >= 0);
    ret = fstat(fd, &st);
    test_assert(ret >= 0);
    if (st.st_ino == child_inode) {
      atomic_puts("EXIT-SUCCESS");
      return 0;
    }
    ret = close(fd);
    test_assert(ret >= 0);
  }
  atomic_puts("Skipping test because inode was not recycled; try running the test with the working directory in ext4");
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
