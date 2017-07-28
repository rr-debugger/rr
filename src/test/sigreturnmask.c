#include "util.h"

static void segv_handler(__attribute__((unused)) int sig,
                         __attribute__((unused)) siginfo_t* si,
                         __attribute__((unused)) void* context) {
  test_assert(0 && "Should not reach here");
}

static void usr1_handler(__attribute__((unused)) int sig,
                         __attribute__((unused)) siginfo_t* si,
                         __attribute__((unused)) void* context) {
  ucontext_t* ctx = (ucontext_t*)context;
  sigaddset(&ctx->uc_sigmask, SIGSEGV);
  return;
}

static void* do_thread(__attribute__((unused)) void* p) {
  raise(SIGUSR1); // just a strange way to spell sigprocmask
  // Generate SIGSEGV. Can't use raise, because that will be blocked
  (*(int*)1) = 0;
  test_assert(0 && "Should not reach here!");
  return NULL;
}

int main(void) {
  pid_t child;
  int status;
  pthread_t thread;

  if ((child = fork()) == 0) {
    struct sigaction act;
    act.sa_sigaction = segv_handler;
    act.sa_flags = SA_ONSTACK | SA_SIGINFO;
    sigemptyset(&act.sa_mask);
    sigaction(SIGSEGV, &act, NULL);

    act.sa_sigaction = usr1_handler;
    sigaction(SIGUSR1, &act, NULL);

    pthread_create(&thread, NULL, do_thread, NULL);
    test_assert(0 == sched_yield());
    sleep(1000);
    test_assert(0 && "Should not reach here");
    return 0;
  }

  test_assert(child == wait(&status));
  test_assert(WIFSIGNALED(status) && WTERMSIG(status) == SIGSEGV);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
