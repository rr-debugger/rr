/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#ifndef ARCH_GET_XCOMP_SUPP
#define ARCH_GET_XCOMP_SUPP 0x1021
#endif
#ifndef ARCH_GET_XCOMP_PERM
#define ARCH_GET_XCOMP_PERM 0x1022
#endif
#ifndef ARCH_REQ_XCOMP_PERM
#define ARCH_REQ_XCOMP_PERM 0x1023
#endif
#ifndef ARCH_XCOMP_TILEDATA
#define ARCH_XCOMP_TILEDATA 18
#endif

int main(void) {
  uint64_t* features;
  ALLOCATE_GUARD(features, 'a');
  int ret = syscall(SYS_arch_prctl, ARCH_GET_XCOMP_SUPP, features);
  if (ret < 0 && errno == EINVAL) {
    atomic_puts("XSTATE features not supported, skipping test");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }
  test_assert(0 == ret);
  VERIFY_GUARD(features);
  atomic_printf("XSTATE features: %llx\n", (long long)*features);

  uint64_t* features_perm;
  ALLOCATE_GUARD(features_perm, 'b');
  ret = syscall(SYS_arch_prctl, ARCH_GET_XCOMP_PERM, features_perm);
  test_assert(0 == ret);
  VERIFY_GUARD(features_perm);
  atomic_printf("XSTATE features permitted: %llx\n", (long long)*features_perm);

  ret = syscall(SYS_arch_prctl, ARCH_REQ_XCOMP_PERM, ARCH_XCOMP_TILEDATA);
  if ((1 << ARCH_XCOMP_TILEDATA) & *features_perm) {
    test_assert(0 == ret);
  } else {
    test_assert(-1 == ret && errno == EOPNOTSUPP);
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
