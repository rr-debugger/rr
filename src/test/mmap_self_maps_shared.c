/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

void callback(uint64_t env, char* name, map_properties_t* props) {
  (void)env;
  if (name[0] != '/') {
    return;
  }
  int fd = open(name, O_RDONLY);
  void* addr =
      mmap(NULL, props->end - props->start, PROT_READ, MAP_SHARED, fd, 0);
  munmap(addr, props->end - props->start);
  close(fd);
}

int main(void) {
  FILE* maps_file = fopen("/proc/self/maps", "r");
  iterate_maps(0, callback, maps_file);
  atomic_puts("EXIT-SUCCESS");
  return 0;
}
