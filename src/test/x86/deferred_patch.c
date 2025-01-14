/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"
#include "rrcalls.h"

/*
 * When we see a syscall patch region in which the syscall is the last instruction,
 * we defer patching until we exit the corresponding syscall
 * (since we can't assume that we can jump to the top of the patch and re-execute
 * the preceeding instructions). This test tests a few corner cases:
 *
 * 1. When a syscall that had such a deferred patch is interrupted by a signal and the
 *    signal handler itself makes a syscall, we need to be sure that we don't accidentally
 *    try to patch that syscall.
 *
 * 2. If another thread is in the middle of the same syscall we need to make sure that we
 *    don't accidentally patch it (but do patch it on the exit of the second syscall).
 *
 * 3. If the signal handler rewrites the signal context to resume execution elsewhere, we still
 *    want to try patching the original syscall.
 */

#ifdef __x86_64__
static __attribute__((noinline)) uintptr_t deferred_patch_syscall(
    uintptr_t syscall, uintptr_t arg1, uintptr_t arg2,
    uintptr_t arg3, uintptr_t arg4) {
  uintptr_t ret;
  register uintptr_t r10 __asm__("r10") = arg4;
  register long r8 __asm__("r8") = 0;
  register long r9 __asm__("r9") = 0;
  __asm__ volatile(
                   /* Use a syscall sequence for which we have a PATCH_SYSCALL_INSTRUCTION_IS_LAST */
                   ".byte 0x0f, 0x1f, 0x44, 0x00, 0x00\n\t"
                   "syscall\n\t"
                   /* Make sure we don't accidentally match any hook pattern with the instructions after */
                   "cmp $0x77,%%rax\n\t"
                   : "=a"(ret)
                   : "a"(syscall), "D"(arg1), "S"(arg2), "d"(arg3), "r"(r10), "r"(r8), "r"(r9)
                   : "flags");
  return ret;
}

static __attribute__((noinline)) uintptr_t deferred_patch_syscall2(
    uintptr_t syscall, uintptr_t arg1, uintptr_t arg2,
    uintptr_t arg3, uintptr_t arg4) {
  uintptr_t ret;
  register uintptr_t r10 __asm__("r10") = arg4;
  register long r8 __asm__("r8") = 0;
  register long r9 __asm__("r9") = 0;
  __asm__ volatile(
                   ".byte 0x0f, 0x1f, 0x44, 0x00, 0x00\n\t"
                   "syscall\n\t"
                   "cmp $0x77,%%rax\n\t"
                   : "=a"(ret)
                   : "a"(syscall), "D"(arg1), "S"(arg2), "d"(arg3), "r"(r10), "r"(r8), "r"(r9)
                   : "flags");
  return ret;
}

int pipefds[2];
int pipefds2[2];
uint8_t byte = 0x1;
volatile uint32_t futex = 0;

static void handle_alrm(__attribute__((unused)) int sig,
                         __attribute__((unused)) siginfo_t* si, void* user) {
  ucontext_t* ctx = (ucontext_t*)user;
  // Skip the syscall and cmp after and have it return 0
  ctx->uc_mcontext.gregs[REG_RIP] += 4;
  ctx->uc_mcontext.gregs[REG_RAX] = 0;
  futex = 1;
  return;
}

static void handle_usr1(__attribute__((unused)) int sig) {
  // Wake up child
  test_assert(1 == write(pipefds2[1], &byte, 1));
  // We need this read to desched, so that rr sees a syscall inside the rr page.
  // We want to make sure that rr doesn't acccidentally try patching that syscall
  // rather than the futex one that we interrupted.
  test_assert(1 == read(pipefds[0], &byte, 1));
  futex = 2;
  test_assert(1 == write(pipefds2[1], &byte, 1));
  return;
}

static void handle_usr2(__attribute__((unused)) int sig) {
  futex = 3;
  return;
}

static void futex_wait(uintptr_t val)
{
  test_assert((uintptr_t)-EAGAIN == deferred_patch_syscall(SYS_futex, (uintptr_t)&futex, FUTEX_WAIT, val, (uintptr_t)NULL));
}

pid_t parent;

static void *do_thread(__attribute__((unused)) void*) {
  test_assert(1 == read(pipefds2[0], &byte, 1));
  sched_yield();
  syscall(SYS_tkill, parent, SIGALRM);
  test_assert(1 == read(pipefds2[0], &byte, 1));
  sched_yield();
  syscall(SYS_tkill, parent, SIGUSR1);
  test_assert(1 == read(pipefds2[0], &byte, 1));
  test_assert(1 == write(pipefds[1], &byte, 1));
  test_assert(1 == read(pipefds2[0], &byte, 1));
  futex_wait(2);
  test_assert(futex == 3);
  return NULL;
}

int main(void) {
  test_assert(0 == pipe(pipefds));
  test_assert(0 == pipe(pipefds2));

  parent = sys_gettid();

  pthread_t t;

  // Setup signal handlers
  struct sigaction sa;
  sa.sa_sigaction = handle_alrm;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_SIGINFO;
  test_assert(0 == sigaction(SIGALRM, &sa, NULL));
  test_assert(0 == signal(SIGUSR1, handle_usr1));
  test_assert(0 == signal(SIGUSR2, handle_usr2));

  // Kick off driver thread
  pthread_create(&t, NULL, do_thread, NULL);

  // Wait for SIGALARM
  test_assert(1 == write(pipefds2[1], &byte, 1));
  test_assert(0 == deferred_patch_syscall2(SYS_futex, (uintptr_t)&futex, FUTEX_WAIT, 0, (uintptr_t)NULL));
  test_assert(futex == 1);

  // Wait for SIGUSR1
  test_assert(1 == write(pipefds2[1], &byte, 1));
  futex_wait(1);

  // Issue SIGUSR2 in thread to let it out of the futex (and let it patch the syscall)
  sched_yield(); sched_yield();
  pthread_kill(t, SIGUSR2);
  pthread_join(t, NULL);

  // Make sure that the patching actually happened (if the syscallbuf is enabled)
  uintptr_t ret = deferred_patch_syscall(SYS_rrcall_check_presence, RRCALL_CHECK_SYSCALLBUF_USED_OR_DISABLED, 0, 0, 0);
  test_assert(ret == (uintptr_t)-ENOSYS || ret == 0);

  ret = deferred_patch_syscall2(SYS_rrcall_check_presence, RRCALL_CHECK_SYSCALLBUF_USED_OR_DISABLED, 0, 0, 0);
  test_assert(ret == (uintptr_t)-ENOSYS || ret == 0);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
#else
int main(void) {
  atomic_puts("This test can only be run on x86_64. Skipping...");
  atomic_puts("EXIT-SUCCESS");
  return 77;
}
#endif
