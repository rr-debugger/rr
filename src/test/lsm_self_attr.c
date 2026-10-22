/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define LSM_ATTR_CURRENT 100
#define LSM_FLAG_SINGLE 1

struct lsm_ctx {
  uint64_t id;
  uint64_t flags;
  uint64_t len;
  uint64_t ctx_len;
  uint8_t ctx[];
};

static void test_list_modules(void) {
  uint32_t* size;
  uint64_t* ids;
  void* small;
  uint32_t required;
  uint32_t i;
  int ret;

  ALLOCATE_GUARD(size, 0);
  *size = 0;
  ret = syscall(RR_lsm_list_modules, NULL, size, 0);
  test_assert(ret == -1 && errno == E2BIG);
  test_assert(*size > 0 && *size % sizeof(uint64_t) == 0);
  VERIFY_GUARD(size);

  required = *size;
  /* A buffer that's too small gets nothing written to it, but *size is
     set to the required size. */
  small = allocate_guard(required - 1, 'x');
  *size = required - 1;
  ret = syscall(RR_lsm_list_modules, small, size, 0);
  test_assert(ret == -1 && errno == E2BIG);
  test_assert(*size == required);
  for (i = 0; i < required - 1; ++i) {
    test_assert(((char*)small)[i] == 'x');
  }
  free_guard(required - 1, small);

  ids = allocate_guard(*size, 'x');
  ret = syscall(RR_lsm_list_modules, ids, size, 0);
  test_assert(ret > 0);
  test_assert(*size == ret * sizeof(uint64_t));
  verify_guard(*size, ids);
  for (i = 0; i < (uint32_t)ret; ++i) {
    atomic_printf("LSM module %llu\n", (unsigned long long)ids[i]);
  }
  free_guard(*size, ids);
}

static void print_ctxs(struct lsm_ctx* ctx, int count) {
  int i;
  for (i = 0; i < count; ++i) {
    atomic_printf("LSM %llu ctx_len %llu\n", (unsigned long long)ctx->id,
                  (unsigned long long)ctx->ctx_len);
    test_assert(ctx->len >= sizeof(*ctx) + ctx->ctx_len);
    ctx = (struct lsm_ctx*)((char*)ctx + ctx->len);
  }
}

static void test_self_attr(void) {
  uint32_t* size;
  struct lsm_ctx* ctx;
  struct lsm_ctx* single;
  void* small;
  uint32_t buf_size;
  uint32_t checksum = 0;
  uint32_t i;
  int ret;

  ALLOCATE_GUARD(size, 0);
  *size = 0;
  ret = syscall(RR_lsm_get_self_attr, LSM_ATTR_CURRENT, NULL, size, 0);
  VERIFY_GUARD(size);
  if (ret == 0 || (ret == -1 && errno == EOPNOTSUPP)) {
    atomic_puts("No LSM provides the current attribute");
    return;
  }
  test_assert(ret == -1 && errno == E2BIG);
  test_assert(*size > 0);

  buf_size = *size;

  /* With a buffer that's too small, *size is set to the required size, but
     entries for LSMs that fit may have been written. Print a checksum of the
     buffer so replay is checked against what the kernel wrote. */
  small = allocate_guard(buf_size - 1, 'x');
  *size = buf_size - 1;
  ret = syscall(RR_lsm_get_self_attr, LSM_ATTR_CURRENT, small, size, 0);
  test_assert(ret == -1 && errno == E2BIG);
  test_assert(*size == buf_size);
  for (i = 0; i < buf_size - 1; ++i) {
    checksum = checksum * 31 + ((unsigned char*)small)[i];
  }
  atomic_printf("Too-small buffer checksum %u\n", checksum);
  free_guard(buf_size - 1, small);

  ctx = allocate_guard(buf_size, 'x');
  ret = syscall(RR_lsm_get_self_attr, LSM_ATTR_CURRENT, ctx, size, 0);
  test_assert(ret > 0);
  test_assert(*size <= buf_size);
  verify_guard(buf_size, ctx);
  print_ctxs(ctx, ret);

  /* Fetch just the first LSM's attribute. ctx->id is an input here. */
  single = allocate_guard(buf_size, 'y');
  single->id = ctx->id;
  *size = buf_size;
  ret = syscall(RR_lsm_get_self_attr, LSM_ATTR_CURRENT, single, size,
                LSM_FLAG_SINGLE);
  test_assert(ret == 1);
  test_assert(single->id == ctx->id);
  test_assert(single->ctx_len == ctx->ctx_len);
  test_assert(memcmp(single->ctx, ctx->ctx, ctx->ctx_len) == 0);
  verify_guard(buf_size, single);

  /* Setting our current attribute to its existing value may or may not
     be permitted; either way rr should handle it. */
  ret = syscall(RR_lsm_set_self_attr, LSM_ATTR_CURRENT, single,
                (uint32_t)single->len, 0);
  atomic_printf("lsm_set_self_attr returned %d\n", ret == 0 ? 0 : errno);

  /* Invalid flags must be rejected. */
  ret = syscall(RR_lsm_set_self_attr, LSM_ATTR_CURRENT, single,
                (uint32_t)single->len, 0xff);
  test_assert(ret == -1 && errno == EINVAL);

  free_guard(buf_size, single);
  free_guard(buf_size, ctx);
}

int main(void) {
  uint32_t size = 0;
  int ret = syscall(RR_lsm_list_modules, NULL, &size, 0);
  if (ret < 0 && errno == ENOSYS) {
    atomic_puts("LSM syscalls not supported, skipping test");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  test_list_modules();
  test_self_attr();

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
