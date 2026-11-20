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

/* long loop(long n): tick n times. Assembled here from the ABI's tick
 * sequence, and copied to writable memory to run. */
#if defined(__x86_64__)
#define LOOP_STEP "inc %rax\n\tcmp %rdi, %rax\n\t"
#else
#define LOOP_STEP "inc %eax\n\tcmp 4(%esp), %eax\n\t"
#endif
__asm__(".pushsection .rodata\n"
        "loop_code:\n\t"
        "xor %eax, %eax\n"
        "2:\n\t" RR_SOFTTICKS_TICK_ASM "\n\t"
        LOOP_STEP
        "jne 2b\n\t"
        "ret\n"
        "loop_code_end:\n\t"
        ".popsection");
extern const uint8_t loop_code[], loop_code_end[];
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
  memcpy(p, loop_code, loop_code_end - loop_code);
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
