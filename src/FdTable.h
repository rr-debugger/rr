/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_FD_TABLE_H_
#define RR_FD_TABLE_H_

#include <unordered_map>
#include <memory>

#include "AddressSpace.h"
#include "FileMonitor.h"

class FdTable : public HasTaskSet {
public:
  typedef std::shared_ptr<FdTable> shr_ptr;

  void dup(int from, int to);
  void close(int fd);

  shr_ptr clone(Task* t) {
    shr_ptr fds(new FdTable(*this));
    fds->insert_task(t);
    return fds;
  }
  static shr_ptr create(Task* t) {
    shr_ptr fds(new FdTable());
    fds->insert_task(t);
    return fds;
  }

private:
  FdTable() {}
  FdTable(const FdTable& other) : fds(other.fds) {}

  std::unordered_map<int, FileMonitor::shr_ptr> fds;
};

#endif /* RR_FD_TABLE_H_ */
