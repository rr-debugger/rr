/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

struct io_sqring_offsets {
  uint32_t head;
  uint32_t tail;
  uint32_t ring_mask;
  uint32_t ring_entries;
  uint32_t flags;
  uint32_t dropped;
  uint32_t array;
  uint32_t resv[3];
};

struct io_cqring_offsets {
  uint32_t head;
  uint32_t tail;
  uint32_t ring_mask;
  uint32_t ring_entries;
  uint32_t overflow;
  uint32_t cqes;
  uint32_t flags;
  uint32_t resv[3];
};

struct io_uring_params {
  uint32_t sq_entries;
  uint32_t cq_entries;
  uint32_t flags;
  uint32_t sq_thread_idle;
  uint32_t features;
  uint32_t resv[4];
  struct io_sqring_offsets sq_off;
  struct io_cqring_offsets cq_off;
};

int main(void) {
  struct io_uring_params params;
  int ret = syscall(RR_io_uring_setup, 32, &params);
  test_assert(ret == -1 && errno == ENOSYS);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
