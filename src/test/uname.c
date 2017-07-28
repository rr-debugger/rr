/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  struct utsname* buf;

  ALLOCATE_GUARD(buf, 0);
  test_assert(0 == uname(buf));
  test_assert(buf->sysname[0] != 0);
  test_assert(buf->nodename[0] != 0);
  test_assert(buf->release[0] != 0);
  test_assert(buf->version[0] != 0);
  test_assert(buf->machine[0] != 0);
  VERIFY_GUARD(buf);

  atomic_printf("{ sysname: '%s', nodename: '%s', release: '%s',\n"
                "  version: '%s', machine: '%s', domainname: '%s' }\n",
                buf->sysname, buf->nodename, buf->release, buf->version,
                buf->machine, buf->domainname);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
