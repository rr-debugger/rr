/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  int fd;
  struct fb_fix_screeninfo finfo;
  struct fb_var_screeninfo vinfo;

  fd = open("/dev/fb0", O_RDWR);
  if (fd < 0) {
    atomic_puts("Can't open framebuffer, aborting test");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  test_assert(0 == ioctl(fd, FBIOGET_FSCREENINFO, &finfo));
  atomic_printf("FBIOGET_FSCREENINFO returned id=%s capabilities=%d\n", finfo.id, finfo.capabilities);

  test_assert(0 == ioctl(fd, FBIOGET_VSCREENINFO, &vinfo));
  atomic_printf("FBIOGET_VSCREENINFO returned xres=%d yres=%d colorspace=%d\n", vinfo.xres, vinfo.yres, vinfo.colorspace);

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
