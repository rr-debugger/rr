/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

void callback(uint64_t env, char *name, __attribute__((unused)) map_properties_t* props) {
  const char search[] = "librrpreload.so";
  if (strlen(name) > strlen(search)) {
    if (sizeof(void*) == 4 &&
        strcmp(name + strlen(name) - strlen(search), search) == 0)
    {
      int* rr_is_32bit = (int*)(uintptr_t)env;
      *rr_is_32bit = 1;
    }
  }
}

static void skip_if_rr_32_bit_under_kernel_64_bit(void) {
  FILE* maps_file = fopen("/proc/self/maps", "r");
  int rr_is_32bit = 0;
  iterate_maps((uintptr_t)&rr_is_32bit, callback, maps_file);

  struct utsname buf;
  if (uname(&buf) != 0)
    return;

  if (rr_is_32bit && // we are inside a 32bit rr process
      strcmp(buf.machine, "x86_64") == 0) // running at a 64bit kernel
  {
    atomic_puts("NOTE: Skipping 32-bit test because of 32-bit rr with 64-bit kernel.");
    atomic_puts("EXIT-SUCCESS");
    exit(0);
  }
}

int main(void) {

  skip_if_rr_32_bit_under_kernel_64_bit();

  /* Fork-and-exec 'echo'.
     The exec may fail if 'bash' is 64-bit and rr doesn't support
     64-bit processes. That's fine; the test should still pass. We're
     testing that rr doesn't abort.
   */
  FILE* f = popen("echo -n", "r");
  while (1) {
    int ch = fgetc(f);
    if (ch < 0) {
      break;
    }
    putchar(ch);
  }
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
