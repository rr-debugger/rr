/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"
#include <linux/keyctl.h>

typedef uint32_t key_serial_t;

int main(void) {
  char buffer[500];

  char* data = "Test Data";
  key_serial_t key = syscall(SYS_add_key, "user", "RR Test key", data,
                             strlen(data) + 1, KEY_SPEC_PROCESS_KEYRING);
  test_assert(0 == syscall(SYS_keyctl, KEYCTL_SETPERM, key, 0x3f3f0000));
  long result =
      syscall(SYS_keyctl, KEYCTL_DESCRIBE, key, buffer, sizeof(buffer));
  test_assert(-1 != result);
  check_data(buffer, result);
  result = syscall(SYS_keyctl, KEYCTL_READ, key, buffer, sizeof(buffer));
  test_assert(-1 != result);
  check_data(buffer, result);
  test_assert(0 == memcmp(buffer, data, strlen(data) + 1));
  result =
      syscall(SYS_keyctl, KEYCTL_GET_SECURITY, key, buffer, sizeof(buffer));
  test_assert(-1 != result);
  check_data(buffer, result);

  test_assert(0 == syscall(SYS_keyctl, KEYCTL_INVALIDATE, key));

#ifdef KEYCTL_DH_COMPUTE
  char base[] = "Hi!";
  uint64_t prime = ((uint64_t)0) - 59; // 2^64-59
  uint8_t private = 1;                 // The world's worst private key

  key_serial_t base_key = syscall(SYS_add_key, "user", "base", base,
                                  strlen(base) + 1, KEY_SPEC_PROCESS_KEYRING);
  key_serial_t prime_key = syscall(SYS_add_key, "user", "prime", &prime,
                                   sizeof(prime), KEY_SPEC_PROCESS_KEYRING);
  key_serial_t private_key = syscall(SYS_add_key, "user", "private", &private,
                                     sizeof(private), KEY_SPEC_PROCESS_KEYRING);

  struct keyctl_dh_params params = {.private = private_key,
                                    .prime = prime_key,
                                    .base = base_key };

  result = syscall(SYS_keyctl, KEYCTL_DH_COMPUTE, &params, buffer,
                   sizeof(buffer), NULL);
  if (-1 == result) {
    // This one's rather new. May not be supported.
    test_assert(errno == EOPNOTSUPP);
  } else {
    check_data(buffer, result);
    test_assert(0 == memcmp(buffer, base, strlen(base) + 1));
  }
#endif

  atomic_printf("EXIT-SUCCESS");
  return 0;
}
