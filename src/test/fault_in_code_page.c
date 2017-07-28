/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

typedef int (*fn_type)(void);
static fn_type fn = NULL;
static const uint8_t fn_insns[] = {
  0xb8, 0x2a, 0x00, 0x00, 0x00, /* movl $42, %eax */
  0xc3,                         /* ret */
};

static uint8_t* code_page;
static size_t page_size;

static int fault_count;
static void fault_in_code_page(int sig, siginfo_t* si,
                               __attribute__((unused)) void* context) {
  atomic_printf("FAULT: signal %d: code %d for addr %p\n", sig, si->si_code,
                si->si_addr);
  test_assert(SIGSEGV == sig);
  test_assert(SEGV_ACCERR == si->si_code);
  test_assert(code_page == si->si_addr);
  test_assert(1 == ++fault_count);

  atomic_puts("  populating page...");
  test_assert(0 == mprotect(code_page, page_size, PROT_READ | PROT_WRITE));
  test_assert(sizeof(fn_insns) < page_size);
  memcpy(code_page, fn_insns, sizeof(fn_insns));

  test_assert(0 == mprotect(code_page, page_size, PROT_READ | PROT_EXEC));
  atomic_puts("  ... and protected it. sigreturn'ing");
}

static uint64_t sigsegv_blocked_rdtsc(void) {
  sigset_t s, old;

  sigemptyset(&s);
  sigaddset(&s, SIGSEGV);

  sigprocmask(SIG_BLOCK, &s, &old);
  uint64_t tsc = rdtsc();
  sys_gettid();
  sigprocmask(SIG_SETMASK, &old, NULL);

  return tsc;
}

int main(void) {
  struct sigaction act;

  page_size = sysconf(_SC_PAGESIZE);

  act.sa_sigaction = fault_in_code_page;
  act.sa_flags = SA_SIGINFO;
  sigemptyset(&act.sa_mask);
  sigaction(SIGSEGV, &act, NULL);

  atomic_printf("current tsc: %" PRIu64 "\n", sigsegv_blocked_rdtsc());

  atomic_printf("    and now: %" PRIu64 "\n", sigsegv_blocked_rdtsc());

  code_page =
      mmap(NULL, page_size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

  atomic_printf("(%d) mapped code page to %p\n", errno, code_page);
  test_assert(code_page != (void*)-1);
  fn = (fn_type)code_page;

  atomic_printf("calling fn(), faulting ...\n");
  int ret = fn();

  atomic_printf("fn() returned %d\n", ret);
  test_assert(42 == ret);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
