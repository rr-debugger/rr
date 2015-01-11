/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_FD_TABLE_H_
#define RR_FD_TABLE_H_

#include <unordered_map>
#include <memory>

#include "FileMonitor.h"

class FdTable {
public:
  typedef std::shared_ptr<FdTable> shr_ptr;

  void dup(int from, int to);
  void close(int fd);

private:
  std::unordered_map<int, FileMonitor::shr_ptr> fds;
};

#endif /* RR_FD_TABLE_H_ */
