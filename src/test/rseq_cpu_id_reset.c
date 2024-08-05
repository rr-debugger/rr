/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

static const uint32_t RSEQ_SIG = 0x12345678;

static int to_main_fds[2];
static int from_main_fds[2];

static const int PING_PONG_ITERATIONS = 5;

static const uint32_t CPU_INVALID = 10000000;

static int main_child(void) {
  struct rseq* rs_ptr =
      (struct rseq*)mmap(NULL, sizeof(struct rseq), PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  test_assert(rs_ptr != MAP_FAILED);
  rs_ptr->cpu_id_start = CPU_INVALID;
  rs_ptr->cpu_id = CPU_INVALID;

  int ret = syscall(RR_rseq, rs_ptr, sizeof(*rs_ptr), 0, RSEQ_SIG);
  if (ret == -1 && errno == ENOSYS) {
    atomic_puts("rseq not supported; ignoring test");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }
  test_assert(ret == 0);
  test_assert(rs_ptr->cpu_id_start < CPU_INVALID);
  test_assert(rs_ptr->cpu_id < CPU_INVALID);

  for (int i = 0; i < PING_PONG_ITERATIONS; ++i) {
    char ch;
    rs_ptr->cpu_id_start = CPU_INVALID;
    rs_ptr->cpu_id = CPU_INVALID;
    test_assert(1 == write(to_main_fds[1], "y", 1));
    // Under rr (or taskset to a single core) there must be a
    // context switch here. Some code exists that expects
    // rseq::cpu_id(_start) to be reset to the current core index
    // every time a task is scheduled onto a core.
    test_assert(1 == read(from_main_fds[0], &ch, 1));
    test_assert(rs_ptr->cpu_id_start < CPU_INVALID);
    test_assert(rs_ptr->cpu_id < CPU_INVALID);
  }

  return 0;
}

static int main_child_wrapper(__attribute__((unused)) void* arg) {
  atomic_puts("EXIT-SUCCESS");
  exit(main_child());
}

int main(void) {
  test_assert(0 == pipe(to_main_fds));
  test_assert(0 == pipe(from_main_fds));

  const size_t stack_size = 1 << 20;
  void* stack = mmap(NULL, stack_size, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  test_assert(stack != MAP_FAILED);

  /* Do the real work in a thread that doesn't have glibc's rseq setup installed */
  clone(main_child_wrapper, stack + stack_size,
        CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_THREAD | CLONE_SIGHAND,
        NULL, NULL, NULL, NULL);

  for (int i = 0; i < PING_PONG_ITERATIONS; ++i) {
    char ch;
    test_assert(1 == read(to_main_fds[0], &ch, 1));
    test_assert(1 == write(from_main_fds[1], "x", 1));
  }

  pause();
  return 0;
}
