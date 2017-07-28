/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static int pipe_fds[2];

static void install_filter(void) {
  struct sock_filter filter[] = { /* Allow all system calls */
                                  BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW)
  };
  struct sock_fprog prog = {
    .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
    .filter = filter,
  };
  int ret;

  ret = syscall(RR_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC,
                &prog);
  if (ret == -1 && errno == ENOSYS) {
    atomic_puts("seccomp syscall not supported");
    atomic_puts("EXIT-SUCCESS");
    exit(0);
  }
  test_assert(ret == 0);
}

static void* waiting_thread(__attribute__((unused)) void* p) {
  char buf;
  test_assert(1 == read(pipe_fds[0], &buf, 1));
  /* Check this thread *was* affected by SECCOMP_FILTER_FLAG_TSYNC */
  test_assert(2 == prctl(PR_GET_SECCOMP));
  return NULL;
}

int main(void) {
  pthread_t w_thread;

  test_assert(0 == pipe(pipe_fds));

  pthread_create(&w_thread, NULL, waiting_thread, NULL);

  /* Prepare syscallbuf patch path. Need to do this after
     pthread_create since when we have more than one
     thread we take a different syscall path... */
  test_assert(0 == prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
  install_filter();
  test_assert(2 == prctl(PR_GET_SECCOMP));

  test_assert(1 == write(pipe_fds[1], "c", 1));
  pthread_join(w_thread, NULL);

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
