/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "FdTable.h"

using namespace std;

void FdTable::dup(int from, int to) {
  if (fds.count(from)) {
    fds[to] = fds[from];
  } else {
    fds.erase(to);
  }
}

void FdTable::close(int fd) { fds.erase(fd); }
