/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  long ncpus = sysconf(_SC_NPROCESSORS_CONF);
  unsigned cpu;
  int ret = getcpu(&cpu, NULL);
  test_assert(ret == 0);
  atomic_printf("sysconf says %ld processors are configured, getcpu()=%d\n", ncpus, cpu);

  if (cpu >= (unsigned)ncpus) {
    if (ncpus == 1 && access("/sys/devices/system/cpu", X_OK) < 0) {
      atomic_puts("Can't access /sys/devices/system/cpu; _SC_NPROCESSORS_CONF is probably broken, skipping test");
      atomic_puts("EXIT-SUCCESS");
      return 0;
    }
    system("ls /sys/devices/system/cpu");
    atomic_puts("present:");
    system("cat /sys/devices/system/cpu/present");
    atomic_puts("possible:");
    system("cat /sys/devices/system/cpu/possible");
    abort();
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
