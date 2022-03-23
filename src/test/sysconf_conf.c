/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  long ncpus = sysconf(_SC_NPROCESSORS_CONF);
  unsigned cpu;
  int ret = getcpu(&cpu, NULL);
  test_assert(ret == 0);
  atomic_printf("sysconf says %ld processors are configured, getcpu()=%d\n", ncpus, cpu);

  if (cpu >= (unsigned)ncpus) {
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
