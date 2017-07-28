#include "util.h"

int handler_pipe_fd;

static void fault_handler(int sig, __attribute__((unused)) siginfo_t* si,
                          __attribute__((unused)) void* context) {
  sigset_t oldset;
  sigprocmask(0, NULL, &oldset);
  test_assert(sigismember(&oldset, SIGSEGV) &&
              "SIGSEGV should be blocked here");
  write(handler_pipe_fd, &sig, sizeof(int));
  *((int*)1) = 0;
  // raise(SIGSEGV);
  test_assert(0 && "Should not reach here");
}

static void* do_thread(__attribute__((unused)) void* p) {
  raise(SIGSEGV);
  test_assert(0 && "Should not reach here!");
  return NULL;
}

int main(void) {
  pid_t child;
  int status;
  pthread_t thread;
  int pipe_fds[2];
  pipe(pipe_fds);
  handler_pipe_fd = pipe_fds[1];

  if ((child = fork()) == 0) {
    struct sigaction act;
    act.sa_sigaction = fault_handler;
    act.sa_flags = SA_ONSTACK | SA_SIGINFO;
    sigemptyset(&act.sa_mask);
    sigaction(SIGSEGV, &act, NULL);

    pthread_create(&thread, NULL, do_thread, NULL);
    test_assert(0 == sched_yield());
    sleep(1000);
    test_assert(0 && "Should not reach here");
    return 0;
  }

  int handler_sig;

  test_assert(read(pipe_fds[0], &handler_sig, sizeof(int)) == sizeof(int));
  test_assert(handler_sig == SIGSEGV);
  test_assert(child == wait(&status));
  test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
