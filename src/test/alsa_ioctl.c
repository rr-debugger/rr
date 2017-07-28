/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#ifndef ALSA_DEVICE_DIRECTORY
#define ALSA_DEVICE_DIRECTORY "/dev/snd/"
#endif

int main(void) {
  int fd = open(ALSA_DEVICE_DIRECTORY "control0", O_NONBLOCK | O_RDONLY);
  if (fd < 0) {
    test_assert(errno == EACCES || errno == ENOENT);
  } else {
    int* pversion;
    struct snd_ctl_card_info* info;

    ALLOCATE_GUARD(pversion, 'x');
    *pversion = -1;
    test_assert(0 == ioctl(fd, SNDRV_CTL_IOCTL_PVERSION, pversion));
    VERIFY_GUARD(pversion);
    test_assert(*pversion >= 0);

    ALLOCATE_GUARD(info, 1);
    test_assert(0 == ioctl(fd, SNDRV_CTL_IOCTL_CARD_INFO, info));
    VERIFY_GUARD(info);
    test_assert(info->id[0] > 1);
    test_assert(info->driver[0] > 1);
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
