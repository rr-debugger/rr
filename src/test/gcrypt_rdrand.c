/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

int main(void) {
  FILE* file = fopen("/etc/gcrypt/hwf.deny", "r");

  test_assert(file != NULL);
  while (1) {
    char* buf = NULL;
    size_t len = 0;
    ssize_t bytes = getline(&buf, &len, file);
    test_assert(bytes >= 0);
    if (strcmp(buf, "intel-rdrand\n") == 0) {
      atomic_puts("EXIT-SUCCESS");
      return 0;
    }
    free(buf);
  }
}
