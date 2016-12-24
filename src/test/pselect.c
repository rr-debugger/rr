/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "rrutil.h"

int main(void) {
  pselect(0, NULL, NULL, NULL, NULL, NULL);
  return 0;
}
