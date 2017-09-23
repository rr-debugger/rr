/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_TASKISH_UID_H_
#define RR_TASKISH_UID_H_

#include <inttypes.h>
#include <unistd.h>

namespace rr {

class AddressSpace;
class Task;
class ThreadGroup;

/**
 * An ID that's unique within a Session (but consistent across
 * multiple ReplaySessions for the same trace), used by Tasks, ThreadGroups
 * and AddressSpaces.
 * This is needed because tids can be recycled during a long-running session.
 */
template <class T> class TaskishUid {
public:
  TaskishUid() : tid_(0), serial_(0) {}
  TaskishUid(pid_t tid, uint32_t serial) : tid_(tid), serial_(serial) {}
  TaskishUid(const TaskishUid<T>& other) = default;
  bool operator==(const TaskishUid<T>& other) const {
    return tid_ == other.tid_ && serial_ == other.serial_;
  }
  bool operator!=(const TaskishUid<T>& other) const {
    return !(*this == other);
  }
  bool operator<(const TaskishUid<T>& other) const {
    if (tid_ < other.tid_) {
      return true;
    }
    if (tid_ > other.tid_) {
      return false;
    }
    return serial_ < other.serial_;
  }
  pid_t tid() const { return tid_; }
  uint32_t serial() const { return serial_; }

private:
  pid_t tid_;
  uint32_t serial_;
};

typedef TaskishUid<Task> TaskUid;
typedef TaskishUid<ThreadGroup> ThreadGroupUid;

class AddressSpaceUid : public TaskishUid<AddressSpace> {
public:
  AddressSpaceUid() : exec_count_(0) {}
  AddressSpaceUid(pid_t tid, uint32_t serial, uint32_t exec_count)
      : TaskishUid<AddressSpace>(tid, serial), exec_count_(exec_count) {}
  AddressSpaceUid(const AddressSpaceUid& other) = default;
  bool operator==(const AddressSpaceUid& other) const {
    return TaskishUid<AddressSpace>::operator==(other) &&
           exec_count_ == other.exec_count_;
  }
  bool operator<(const AddressSpaceUid& other) const {
    if (TaskishUid<AddressSpace>::operator<(other)) {
      return true;
    }
    if (other.TaskishUid<AddressSpace>::operator<(*this)) {
      return false;
    }
    return exec_count_ < other.exec_count_;
  }
  uint32_t exec_count() const { return exec_count_; }

private:
  uint32_t exec_count_;
};

} // namespace rr

#endif // RR_TASKISH_UID_H_
