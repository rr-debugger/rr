/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

/* A software-ticks program that runs a ticking loop in writable memory (as a
 * JIT would) while a CPU-time timer interrupts it. Replay reaches a signal in
 * the loop with a hardware breakpoint at its pc (an int3 there could be
 * overwritten), which must be disabled once replay has stopped there: the
 * loop runs the same pc again after the handler returns. */

#include "util.h"

#include <rr/softticks.h>

__asm__(RR_SOFTTICKS_INIT_ASM);

#define TICK() RR_SOFTTICK()

#define ITERATIONS 100000000

#if defined(__x86_64__) || defined(__i386__)
static volatile int sigs;

static void handler(__attribute__((unused)) int sig) {
  TICK();
  ++sigs;
}

/* long loop(long n): tick n times. */
#if defined(__x86_64__)
static const uint8_t loop_code[] = {
  0x31, 0xc0,                                     /* xor %eax,%eax */
  /* 1: */
  0x48, 0xff, 0x0c, 0x25, 0x00, 0x18, 0x00, 0x70, /* decq 0x70001800 */
  0x75, 0x01,                                     /* jnz 2f */
  0xcc,                                           /* int3 */
  /* 2: */
  0x48, 0xff, 0xc0,                               /* inc %rax */
  0x48, 0x39, 0xf8,                               /* cmp %rdi,%rax */
  0x75, 0xed,                                     /* jne 1b */
  0xc3,                                           /* ret */
};
#elif defined(__i386__)
static const uint8_t loop_code[] = {
  0x31, 0xc0,                                     /* xor %eax,%eax */
  /* 1: */
  0x83, 0x2d, 0x00, 0x18, 0x00, 0x70, 0x01,       /* subl $1,0x70001800 */
  0x75, 0x0a,                                     /* jnz 2f */
  0x83, 0x2d, 0x04, 0x18, 0x00, 0x70, 0x01,       /* subl $1,0x70001804 */
  0x73, 0x01,                                     /* jae 2f */
  0xcc,                                           /* int3 */
  /* 2: */
  0x40,                                           /* inc %eax */
  0x3b, 0x44, 0x24, 0x04,                         /* cmp 4(%esp),%eax */
  0x75, 0xe6,                                     /* jne 1b */
  0xc3,                                           /* ret */
};
#endif
#endif

int main(void) {
#if defined(__x86_64__) || defined(__i386__)
  struct itimerval timer = { { 0, 1000 }, { 0, 1000 } };
  struct itimerval off = { { 0, 0 }, { 0, 0 } };
  long (*loop)(long);
  void* p;

  TICK();
  p = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  test_assert(p != MAP_FAILED);
  memcpy(p, loop_code, sizeof(loop_code));
  loop = (long (*)(long))p;

  signal(SIGPROF, handler);
  setitimer(ITIMER_PROF, &timer, NULL);
  test_assert(loop(ITERATIONS) == ITERATIONS);
  setitimer(ITIMER_PROF, &off, NULL);
  atomic_printf("signals: %d\n", sigs > 0);
#endif
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
