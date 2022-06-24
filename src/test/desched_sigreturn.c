/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

pid_t main_thread_tid = 0;
int fds[2];
char zeros[8192];

void sigproc_and_hang(void)
{
  sigset_t sigs;
  sigfillset(&sigs);
  sigdelset(&sigs, SIGUSR2);
  sigprocmask(SIG_SETMASK, &sigs, NULL);
  write(fds[1], &zeros, 8192);
  write(fds[1], &zeros, 8192);
  test_assert(0);
}

void print_and_exit(void)
{
  atomic_printf("EXIT-SUCCESS\n");
  exit(0);
}

volatile int counter = 0;
void usr2_handler(__attribute__((unused)) int signum,
             __attribute__((unused)) siginfo_t* siginfo_ptr,
             void* ucontext_ptr) {
  uintptr_t target = counter == 0 ? (uintptr_t)&sigproc_and_hang : (uintptr_t)&print_and_exit;
  counter += 1;
#if defined(__i386__)
  ucontext_t* ctx = (ucontext_t*)ucontext_ptr;
  ctx->uc_mcontext.gregs[REG_EIP] = (uint32_t)target;
#elif defined(__x86_64__)
  ucontext_t* ctx = (ucontext_t*)ucontext_ptr;
  ctx->uc_mcontext.gregs[REG_RIP] = (long long)target;
#elif defined(__aarch64__)
  ucontext_t* ctx = (ucontext_t*)ucontext_ptr;
  ctx->uc_mcontext.pc = (long)target;
#else
  #error "Unsupported architecture"
#endif
}

static void* signaler_thread(__attribute__((unused)) void* p) {
  for (int i = 0; i < 10; ++i)
    sched_yield();
  syscall(SYS_tgkill, getpid(), main_thread_tid, SIGUSR2);
  // Technically should use atomics, but volatile is good enough for this test,
  // since we're doing a syscall in the loop.
  while (counter == 0)
    sched_yield();
  for (int i = 0; i < 10; ++i)
    sched_yield();
  syscall(SYS_tgkill, getpid(), main_thread_tid, SIGUSR2);
  return NULL;
}

int main(void) {
  int err = pipe(fds);
  test_assert(err == 0);

  err = fcntl(fds[1], F_SETPIPE_SZ, 4096);
  test_assert(err > 0);

  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_sigaction = usr2_handler;
  sa.sa_flags = SA_ONSTACK | SA_SIGINFO | SA_RESTART;
  err = sigaction(SIGUSR2, &sa, NULL);
  test_assert(err == 0);

  main_thread_tid = sys_gettid();

  pthread_t thread;
  pthread_create(&thread, NULL, signaler_thread, NULL);

  // Block on pipe read.
  int ch = 0;
  err = read(fds[0], &ch, sizeof(int));
  test_assert(0);

  return 0;
}
