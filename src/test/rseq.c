/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

struct rseq {
  uint32_t cpu_id_start;
  uint32_t cpu_id;
  uint64_t rseq_cs;
  uint32_t flags;
} __attribute__((aligned(32)));

struct rseq_cs {
  uint32_t version;
  uint32_t flags;
  uint64_t start_ip;
  uint64_t post_commit_offset;
  uint64_t abort_ip;
} __attribute__((aligned(32)));

static struct rseq rs;
static struct rseq_cs rs_cs;

static const uint32_t RSEQ_SIG = 0x12345678;

extern char start_ip;
extern char end_ip;
extern char abort_ip;

static uint64_t aborts;
static uint64_t jump_aborts;

static volatile uint32_t dummy;

static void do_section(void) {
  int did_abort = 0;
  rs.rseq_cs = (uint64_t)(uintptr_t)&rs_cs;
#if defined(__x86_64__) || defined(__i386__)
  __asm__ __volatile__ (
    "start_ip:\n\t"
    "movl $1234,%0\n\t"
    "movl $1234,%0\n\t"
    "movl $1234,%0\n\t"
    "movl $1234,%0\n\t"
    "jmp 1f\n\t"
    "end_ip:\n\t"
    ".int 0x12345678\n\t"
    "abort_ip:\n\t"
    "movb $1,%1\n\t"
    "1:\n\t"
    : : "m"(dummy), "m"(did_abort));
#endif
  if (did_abort) {
    ++jump_aborts;
    test_assert(!rs.rseq_cs);
  }
  if (!rs.rseq_cs) {
    ++aborts;
  }
  rs.rseq_cs = 0;
}

int main(void) {
  rs.cpu_id_start = 10000000;
  rs.cpu_id = 10000001;
  int ret = syscall(RR_rseq, &rs, sizeof(rs), 0, RSEQ_SIG);
  int i;
  int status;
  pid_t child;
  if (ret == -1 && errno == ENOSYS) {
    atomic_puts("rseq not supported; ignoring test");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }
  test_assert(ret == 0);
  test_assert(rs.cpu_id_start < 10000000);
  test_assert(rs.cpu_id < 10000000);

#if defined(__x86_64__) || defined(__i386__)
  rs_cs.start_ip = (uint64_t)(uintptr_t)&start_ip;
  rs_cs.post_commit_offset = (uint64_t)(uintptr_t)&end_ip - rs_cs.start_ip;
  rs_cs.abort_ip = (uint64_t)(uintptr_t)&abort_ip;
#endif

  child = fork();
  if (!child) {
    for (i = 0; i < 300000000; ++i) {
      do_section();
    }

    atomic_printf("Detected %lld aborts, %lld jump aborts\n",
                  (long long)aborts, (long long)jump_aborts);
    return 77;
  }
  atomic_printf("child %d\n", child);
  for (i = 0; i < 1000; ++i) {
    sched_yield();
  }
  ret = waitpid(child, &status, 0);
  test_assert(ret == child);
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
