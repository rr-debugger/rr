/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#ifdef __x86_64__

static long gettimeofday_vsyscall(struct timeval* tv, struct timezone* tz)
{
  long ret;
  __asm__ __volatile(
    "movq $0xffffffffff600000, %%rax\n\t"
    "callq *%%rax\n\t" : "=a"(ret) : "D"(tv), "S"(tz) : "cc", "memory");
  return ret;
}

static time_t time_vsyscall(time_t* t)
{
  time_t ret;
  __asm__ __volatile(
    "movq $0xffffffffff600400, %%rax\n\t"
    "callq *%%rax\n\t" : "=a"(ret) : "D"(t) : "cc", "memory");
  return ret;
}

static long getcpu_vsyscall(unsigned* cpu, unsigned* node, void* tcache)
{
  long ret;
  __asm__ __volatile(
    "movq $0xffffffffff600800, %%rax\n\t"
    "callq *%%rax\n\t" : "=a"(ret) : "D"(cpu), "S"(node), "d"(tcache) : "cc", "memory");
  return ret;
}
#endif

int main(void) {
  // x86_64 only
#ifdef __x86_64__
  // gettimeofday
  struct timeval tv = { 0, 0 };
  test_assert(gettimeofday_vsyscall(&tv, NULL) == 0);
  test_assert(tv.tv_sec != 0);

  // time
  time_t tim;
  time_t ret = (time_t)time_vsyscall(&tim);
  test_assert(ret == tim);

  // getcpu
  unsigned* cpu;
  unsigned* node;
  ALLOCATE_GUARD(cpu, -1);
  ALLOCATE_GUARD(node, -1);
  test_assert(0 == getcpu_vsyscall(cpu, node, NULL));
  test_assert(*cpu <= 0xffffff);
  test_assert(*node <= 0xffffff);
  VERIFY_GUARD(cpu);
  VERIFY_GUARD(node);
#endif
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
