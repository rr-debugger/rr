/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

int main(int argc, char* argv[]) {
  struct utsname buf;

  uname(&buf);
  atomic_printf("{ sysname: '%s', nodename: '%s', release: '%s',\n"
                "  version: '%s', machine: '%s', domainname: '%s' }\n",
                buf.sysname, buf.nodename, buf.release, buf.version,
                buf.machine, buf.domainname);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
