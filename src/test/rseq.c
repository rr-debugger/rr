/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

struct rseq {
  uint32_t cpu_id_start;
  uint32_t cpu_id;
  uint64_t rseq_cs;
  uint32_t flags;
};

int main(void) {
  struct rseq rs;
  int ret = syscall(RR_rseq, &rs, sizeof(rs), 0, 0);
  test_assert(ret == -1 && errno == ENOSYS);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
