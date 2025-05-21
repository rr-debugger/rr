/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"
#include "ptrace_util.h"

static void* do_thread(void* arg) {
  int pipe_fd = *(int*)arg;
  uint32_t tid = sys_gettid();

  write(pipe_fd, &tid, 4);
  /* Sleep long enough that it will be noticed if it's not interrupted. */
  sleep(1000);

  return NULL;
}

int main(void) {
  pid_t child, grandchild;
  int sock_fds[2];

  test_assert(0 == socketpair(AF_LOCAL, SOCK_STREAM, 0, sock_fds));

  if (0 == (child = fork())) {
    uint32_t tid;
    int pipe_fds[2];
    test_assert(0 == pipe(pipe_fds));

    if (0 == (grandchild = fork())) {
      pthread_t t;

      pthread_create(&t, NULL, do_thread, &pipe_fds[1]);
      pthread_join(t, NULL);

      return 77;
    }

    test_assert(4 == read(pipe_fds[0], &tid, 4));

    close(pipe_fds[0]);
    sched_yield();

    test_assert(sizeof(grandchild) == send(sock_fds[1], &grandchild, sizeof(grandchild), 0));
    /* Nothing is ever sent the other way so this just blocks. */
    recv(sock_fds[1], &grandchild, sizeof(grandchild), 0);

    return 66;
  }

  /* Get the grandchild pid. */
  recv(sock_fds[0], &grandchild, sizeof(grandchild), 0);

  /* Hit the entire process group with a SIGSTOP. */
  tgkill(grandchild, grandchild, SIGSTOP);

  /* Force the rr scheduler to run. */
  sched_yield();

  kill(SIGKILL, grandchild);
  kill(SIGKILL, child);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
