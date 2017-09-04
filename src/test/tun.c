/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "nsutils.h"
#include "util.h"

static void test_tun(void) {
  struct ifreq* ifr;
  int* features;
  int* sndbuf;
  int* hdrsz;
  int fd = open("/dev/net/tun", O_RDWR);

  if (fd < 0) {
    atomic_puts("Can't open /dev/net/tun --- not supported?");
    atomic_puts("EXIT-SUCCESS");
    exit(0);
  }

  ALLOCATE_GUARD(features, 0);
  test_assert(ioctl(fd, TUNGETFEATURES, (void*)features) == 0);
  VERIFY_GUARD(features);
  test_assert((*features & IFF_TAP) != 0);

  ALLOCATE_GUARD(ifr, 'a');
  memset(ifr, 0, sizeof(*ifr));
  ifr->ifr_flags = IFF_TAP;
  test_assert(ioctl(fd, TUNSETIFF, (void*)ifr) == 0);
  VERIFY_GUARD(ifr);
  test_assert(ifr->ifr_name[0] != 0);
  atomic_printf("ifname: %s\n", ifr->ifr_name);

  ALLOCATE_GUARD(ifr, 0);
  test_assert(ioctl(fd, TUNGETIFF, (void*)ifr) == 0);
  VERIFY_GUARD(ifr);
  atomic_printf("flags: 0x%x\n", ifr->ifr_flags);
  test_assert((ifr->ifr_flags & IFF_TAP) != 0);
  test_assert(ifr->ifr_name[0] != 0);

  ALLOCATE_GUARD(sndbuf, 0);
  test_assert(ioctl(fd, TUNGETSNDBUF, (void*)sndbuf) == 0);
  VERIFY_GUARD(sndbuf);
  test_assert(*sndbuf > 0);

  ALLOCATE_GUARD(hdrsz, 0);
  test_assert(ioctl(fd, TUNGETVNETHDRSZ, (void*)hdrsz) == 0);
  VERIFY_GUARD(hdrsz);
  test_assert(*hdrsz > 0);

#ifdef __x86_64__
  /* TUNDETACHFILTER/TUNGETFILTER (and probably TUNATTACHFILTER) are
     incorrectly implemented (as of 4.12 at least). The ioctl values are
     defined with a size field of 8 bytes (struct sock_fprog) on x86-32,
     but an x86-64 kernel expects the x86-64 size (16 bytes) and the
     64-bit sock_fprog layout. */
  /* The actual ioctl numbers will depend on whether the kernel is 32-bit
     or 64-bit so testing this on 32-bit is not worth the hassle. */
  test_assert(ioctl(fd, TUNDETACHFILTER, NULL) == 0);

  /* The actual results will depend on whether we're running on a 32-bit
     or 64-bit kernel, which we don't want to try to detect, so only run
     this test on 64-bit kernels. */
  struct sock_fprog* fprog;
  ALLOCATE_GUARD(fprog, 'x');
  test_assert(ioctl(fd, TUNGETFILTER, (void*)fprog) == 0);
  VERIFY_GUARD(fprog);
  test_assert(fprog->len == 0);
#endif
}

int main(void) {
  if (-1 == try_setup_ns(CLONE_NEWNET)) {
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  test_tun();

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
