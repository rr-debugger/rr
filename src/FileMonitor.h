/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_FILE_MONITOR_H_
#define RR_FILE_MONITOR_H_

class Task;

#include <stdint.h>
#include <stdlib.h>

#include <memory>

class FileMonitor {
public:
  typedef std::shared_ptr<FileMonitor> shr_ptr;

  virtual ~FileMonitor() {}
};

#endif /* RR_FILE_MONITOR_H_ */
