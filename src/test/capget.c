/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

extern int capget(cap_user_header_t header, const cap_user_data_t data);

int main(int argc, char* argv[]) {
  struct __user_cap_header_struct hdr;
  struct __user_cap_data_struct data[2];

  memset(&hdr, 0, sizeof(hdr));
  hdr.version = _LINUX_CAPABILITY_VERSION_3;

  test_assert(0 == capget(&hdr, &data[0]));
  test_assert(0 == data[0].effective);
  test_assert(0 == data[0].permitted);
  test_assert(0 == data[0].inheritable);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
