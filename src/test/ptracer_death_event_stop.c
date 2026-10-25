/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* A ptracer exits while its tracee is in a PTRACE_EVENT_CLONE, _FORK,
   _VFORK or _EXEC stop: in the first round with its whole process, in the
   second as the main thread of its process while another thread keeps
   running. The tracee should resume when the ptracer thread exits and
   finish its clone, fork, vfork or execve. */

static const int events[] = { PTRACE_EVENT_CLONE, PTRACE_EVENT_FORK,
                              PTRACE_EVENT_VFORK, PTRACE_EVENT_EXEC };

static char* exe;
static int status_pipe[2];

static void* do_thread(__attribute__((unused)) void* p) { return NULL; }

static void report_done(int fd) {
  char ok = 'K';
  test_assert(1 == write(fd, &ok, 1));
}

static void wait_for_report(void) {
  char ch = 0;
  test_assert(1 == read(status_pipe[0], &ch, 1));
  test_assert(ch == 'K');
}

static void run_tracee(int event, int ready_fd) {
  char ch = 0;
  int status;
  pthread_t thread;
  pid_t pid;
  char fd_str[20];

  test_assert(1 == read(ready_fd, &ch, 1));
  test_assert(ch == 'R');
  switch (event) {
    case PTRACE_EVENT_CLONE:
      test_assert(0 == pthread_create(&thread, NULL, do_thread, NULL));
      test_assert(0 == pthread_join(thread, NULL));
      break;
    case PTRACE_EVENT_FORK:
    case PTRACE_EVENT_VFORK:
      pid = event == PTRACE_EVENT_FORK ? fork() : vfork();
      if (!pid) {
        _exit(0);
      }
      test_assert(pid > 0);
      test_assert(pid == waitpid(pid, &status, 0));
      test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 0);
      break;
    case PTRACE_EVENT_EXEC:
      sprintf(fd_str, "%d", status_pipe[1]);
      execl(exe, exe, fd_str, NULL);
      test_assert(0);
      break;
  }
  report_done(status_pipe[1]);
}

static void* wait_for_tracee(__attribute__((unused)) void* p) {
  wait_for_report();
  exit(44);
  return NULL;
}

static void run_ptracer(int event, int main_thread_only) {
  pid_t child;
  int status;
  int ready_pipe[2];
  char ready = 'R';
  pthread_t thread;

  test_assert(0 == pipe(ready_pipe));

  if (0 == (child = fork())) {
    run_tracee(event, ready_pipe[0]);
    exit(77);
  }
  test_assert(child > 0);

  test_assert(0 == ptrace(PTRACE_SEIZE, child, NULL,
                          (void*)(PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK |
                                  PTRACE_O_TRACEVFORK | PTRACE_O_TRACEEXEC)));
  test_assert(1 == write(ready_pipe[1], &ready, 1));
  test_assert(child == waitpid(child, &status, 0));
  test_assert(status == ((event << 16) | (SIGTRAP << 8) | 0x7f));

  if (main_thread_only) {
    test_assert(0 == pthread_create(&thread, NULL, wait_for_tracee, NULL));
    /* Exit this thread only. The tracee should resume. */
    syscall(SYS_exit, 0);
    test_assert(0);
  }
  /* Exit the process, and the tracee should resume. */
  exit(44);
}

int main(int argc, char* argv[]) {
  pid_t ptracer;
  int status;
  int main_thread_only;
  size_t i;

  if (argc == 2) {
    /* We were exec'ed by a tracee. */
    report_done(atoi(argv[1]));
    return 77;
  }
  exe = argv[0];

  test_assert(0 == pipe(status_pipe));

  for (main_thread_only = 0; main_thread_only < 2; ++main_thread_only) {
    for (i = 0; i < sizeof(events) / sizeof(events[0]); ++i) {
      if (0 == (ptracer = fork())) {
        run_ptracer(events[i], main_thread_only);
      }
      test_assert(ptracer > 0);

      test_assert(ptracer == waitpid(ptracer, &status, 0));
      test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 44);
      if (!main_thread_only) {
        wait_for_report();
      }
    }
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
