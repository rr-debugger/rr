/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

extern int perform_redzone_integrity_test(void);

#if defined(__x86_64__)
__asm__(".text\n"
        ".global perform_redzone_integrity_test\n"
        ".type perform_redzone_integrity_test, @function\n"
        "perform_redzone_integrity_test:\n"
        "  leaq -128(%rsp), %rdi\n"
        "  movq $128, %rcx \n"
        "  movq $0xde, %rax # Arbitrary byte pattern we will verify after\n"
        "  rep stosb\n"
        /* Note: This should be a patchable syscall */
        "  movq $186, %rax\n"
        "  syscall\n"
        "  nop\n"
        "  nop\n"
        "  nop\n"
        "  leaq    -128(%rsp), %rdi\n"
        "  leaq    128(%rdi), %rax\n"
        "  jmp exit_cond\n"
        "loop_start:\n"
        "  addq    $1, %rdi\n"
        "  cmpq    %rax, %rdi\n"
        "  je  exit_success\n"
        "exit_cond:\n"
        "  cmpb    $0xde, (%rdi)\n"
        "  je  loop_start\n"
        "exit_fail:\n"
        "  movq    $1, %rax\n"
        "  retq\n"
        "exit_success:\n"
        "  xorq %rax, %rax\n"
        "  retq\n"
        ".previous\n");
#else
// x86-64 is the only architecture we currently support that mandates a redzone
int perform_redzone_integrity_test(void) { return 0; }
#endif

static int did_sighandler_test = 0;
void catcher(int __attribute__((unused)) signum,
             __attribute__((unused)) siginfo_t* siginfo_ptr,
             __attribute__((unused)) void* ucontext_ptr) {
  test_assert(0 == perform_redzone_integrity_test());
  did_sighandler_test = 1;
}

int main(void) {
  test_assert(0 == perform_redzone_integrity_test());

  if (0 == fork()) {
    // Just a child to prevent waitpid failing with fork
    sleep(1000);
    test_assert(0 && "Should not reach here");
  }

  // Test redzone integrity in a singal handler during an interrupted blocking
  // syscall.
  struct sigaction sact;
  sigemptyset(&sact.sa_mask);
  sact.sa_flags = SA_SIGINFO;
  sact.sa_sigaction = catcher;
  sigaction(SIGALRM, &sact, NULL);
  alarm(1);

  int status;
  wait(&status);

  test_assert(did_sighandler_test);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
