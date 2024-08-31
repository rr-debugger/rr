/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include <linux/hidraw.h>
#include "util.h"

inline static int atomic_warn(int cond, const char *str,
                              const char *file, const int line) {
  if (!cond) {
    atomic_printf("FAILED at %s:%d: !(%s) errno:%d (%s)\n", file, line, str,
                  errno, strerror(errno));
  }
  return 1;
}

#define test_warn(cond) atomic_warn(cond, #cond, __FILE__, __LINE__)

#define BUF_SIZE 256

void test(int fd) {
  char *buf = allocate_guard(BUF_SIZE, 0xFF);;
  int size;
  struct hidraw_report_descriptor *rpt_desc;

  test_warn(0 <= ioctl(fd, HIDIOCGRAWNAME(256), buf));
  atomic_printf(" Device name: %s\n", buf);
  verify_guard(BUF_SIZE, buf);

  test_warn(0 == ioctl(fd, HIDIOCGRDESCSIZE, &size));
  atomic_printf(" Report Descriptor Size = %d bytes\n", size);

  ALLOCATE_GUARD(rpt_desc, 0x00);
  rpt_desc->size = size;
  test_warn(0 == ioctl(fd, HIDIOCGRDESC, rpt_desc));
  atomic_printf(" Report Descriptor:");
  for (unsigned int i = 0; i < rpt_desc->size; i++) {
    if (i % 16 == 0) {
      atomic_printf("\n ");
    }
    atomic_printf("0x%02hhX ", rpt_desc->value[i]);
  }
  atomic_puts("");
  FREE_GUARD(rpt_desc);
}

int main(void) {
  int fd;

  chdir("/dev");
  DIR* dev = opendir(".");
  if (dev < 0) {
    atomic_puts("Can't open dev directory, aborting test");
    atomic_puts("EXIT-SUCCESS");
    return 0;
  }

  struct dirent* e;
  while ((e = readdir(dev))) {
    if (0 != strncmp("hidraw", e->d_name, 6)) {
      continue;
    }

    fd = open(e->d_name, O_RDWR|O_NONBLOCK);
    if (fd < 0) {
      atomic_printf("Can’t open device /dev/%s; skipping\n", e->d_name);
      continue;
    }
    atomic_printf("Poking device /dev/%s\n", e->d_name);
    test(fd);
    close(fd);
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
