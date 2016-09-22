/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"
#include <ctype.h>

static char* trim_leading_blanks(char* str) {
  char* trimmed = str;
  while (isblank(*trimmed)) {
    ++trimmed;
  }
  return trimmed;
}

int main(void) {
  FILE* maps_file = fopen("/proc/self/maps", "r");

  while (!feof(maps_file)) {
    char line[PATH_MAX * 2];
    if (!fgets(line, sizeof(line), maps_file)) {
      break;
    }

    uint64_t start, end, offset, inode;
    int dev_major, dev_minor;
    char flags[32];
    int chars_scanned;
    int nparsed = sscanf(line, "%" SCNx64 "-%" SCNx64 " %31s %" SCNx64
                               " %x:%x %" SCNu64 " %n",
                         &start, &end, flags, &offset, &dev_major, &dev_minor,
                         &inode, &chars_scanned);
    assert(8 /*number of info fields*/ == nparsed ||
           7 /*num fields if name is blank*/ == nparsed);

    // trim trailing newline, if any
    int last_char = strlen(line) - 1;
    if (line[last_char] == '\n') {
      line[last_char] = 0;
    }

    char* name = trim_leading_blanks(line + chars_scanned);
    if (name[0] != '/')
      continue;
    int fd = open(name, O_RDONLY);
    void* addr = mmap(NULL, end - start, PROT_READ, MAP_SHARED, fd, 0);
    munmap(addr, end - start);
    close(fd);
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
