/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* We use this structure to verify that, on architectures supporting UID16
 * syscalls, rr properly records and replays only 16-bit values.
 */
union legacy_id {
  uint16_t u16[2];
  uint32_t u32;
};

#define UID_COOKIE 0xd05e

static void initialize_legacy_ids(size_t n, union legacy_id* ids) {
  size_t i;

  for (i = 0; i < n; ++i) {
    ids[i].u16[0] = 0;
    ids[i].u16[1] = UID_COOKIE;
  }
};

static void verify_results(size_t n, union legacy_id* ids) {
  size_t i;

  for (i = 0; i < n; ++i) {
#if defined(__i386__)
    // For UID16 syscall-supporting archs, the cookie should be intact.
    test_assert(ids[i].u16[1] == UID_COOKIE);
#elif defined(__x86_64__)
    // For UID32 archs, assume that the user doesn't have a UID with the
    // upper bits equivalent to our cookie.  This is not a great assumption,
    // but we don't really have anything better.
    test_assert(ids[i].u16[1] != UID_COOKIE);
#else
#error unknown architecture
#endif
  }
}

int main(void) {
  union legacy_id resuid_results[3];
  union legacy_id resgid_results[3];

  initialize_legacy_ids(ALEN(resuid_results), resuid_results);
  test_assert(0 == syscall(SYS_getresuid, &resuid_results[0],
                           &resuid_results[1], &resuid_results[2]));
  verify_results(ALEN(resuid_results), resuid_results);

  initialize_legacy_ids(ALEN(resgid_results), resgid_results);
  test_assert(0 == syscall(SYS_getresgid, &resgid_results[0],
                           &resgid_results[1], &resgid_results[2]));
  verify_results(ALEN(resgid_results), resgid_results);

  atomic_puts("EXIT-SUCCESS");

  return 0;
}
