/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define TEST_MEMFD "foo"

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001
#define MFD_ALLOW_SEALING 0x0002
#endif

#ifndef F_ADD_SEALS
#define F_ADD_SEALS 0x409
#endif

#ifndef F_SEAL_SEAL
#define F_SEAL_SEAL 0x0001
#define F_SEAL_SHRINK 0x0002
#define F_SEAL_GROW 0x0004
#define F_SEAL_WRITE 0x0008
#endif

int main(void) {
  int fd;

  /* There's no libc helper for this syscall. */
  fd = syscall(RR_memfd_create, TEST_MEMFD, MFD_ALLOW_SEALING);
  if (-1 == fd && ENOSYS == errno) {
    atomic_puts("SYS_memfd_create not supported on this kernel");
  } else if (-1 == fd && EINVAL == errno) {
    atomic_puts("MFD_ALLOW_SEALING not supported on this kernel");
  } else {
    test_assert(fd >= 0);
    test_assert(
        fcntl(fd, F_ADD_SEALS, F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW) == 0);
    /* Seal after F_SEAL_SEAL should fail */
    test_assert(fcntl(fd, F_ADD_SEALS,
                      F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW) == -1);
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
