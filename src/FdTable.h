/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_FD_TABLE_H_
#define RR_FD_TABLE_H_

#include <memory>
#include <unordered_map>
#include <vector>

#include "FileMonitor.h"
#include "HasTaskSet.h"
#include "rr_pcp.capnp.h"

namespace rr {

class AddressSpace;
class RecordTask;
class ReplayTask;
class Task;

class FdTable final : public HasTaskSet {
public:
  typedef std::shared_ptr<FdTable> shr_ptr;

  void add_monitor(Task* t, int fd, FileMonitor* monitor);
  void replace_monitor(Task* t, int fd, FileMonitor* monitor);
  bool emulate_ioctl(int fd, RecordTask* t, uint64_t* result);
  bool emulate_fcntl(int fd, RecordTask* t, uint64_t* result);
  bool emulate_read(int fd, RecordTask* t,
                    const std::vector<FileMonitor::Range>& ranges,
                    FileMonitor::LazyOffset& offset, uint64_t* result);
  void filter_getdents(int fd, RecordTask* t);
  bool is_rr_fd(int fd);
  Switchable will_write(Task* t, int fd);
  void did_write(Task* t, int fd, const std::vector<FileMonitor::Range>& ranges,
                 FileMonitor::LazyOffset& offset);
  void did_dup(int from, int to) {
    did_dup(this, from, to);
  }
  void did_dup(FdTable* table, int from, int to);
  void did_close(int fd);

  shr_ptr clone() const {
    return shr_ptr(new FdTable(*this));
  }

  static shr_ptr create(Task* t);

  bool is_monitoring(int fd) const { return fds.count(fd) > 0; }
  uint32_t count_beyond_limit() const { return fd_count_beyond_limit; }

  FileMonitor* get_monitor(int fd);

  /**
   * Regenerate syscallbuf_fds_disabled in task |t|.
   * Called during initialization of the preload library.
   */
  void init_syscallbuf_fds_disabled(Task* t);

  /**
   * Get list of fds that have been closed after |t| has done an execve.
   * Rather than tracking CLOEXEC flags (which would be complicated), we just
   * scan /proc/<pid>/fd during recording and note any monitored fds that have
   * been closed.
   * This also updates our table to match reality.
   */
  std::vector<int> fds_to_close_after_exec(RecordTask* t);

  /**
   * Close fds in list after an exec.
   */
  void close_after_exec(ReplayTask* t, const std::vector<int>& fds_to_close);

  // Used to optimize ReplayTask's find_free_file_descriptor
  int last_free_fd() const { return last_free_fd_; }
  void set_last_free_fd(int last_free_fd) { last_free_fd_ = last_free_fd; }

  void serialize(pcp::ProcessSpace::Builder& leader_builder) const;
  void deserialize(Task* leader,
                   const pcp::ProcessSpace::Reader& leader_reader);

  void insert_task(Task* t) override;
  void erase_task(Task* t) override;

private:
  explicit FdTable(uint32_t syscallbuf_fds_disabled_size)
    : syscallbuf_fds_disabled_size(syscallbuf_fds_disabled_size),
      fd_count_beyond_limit(0), last_free_fd_(0) {}
  // Does not call the base-class copy constructor because
  // we don't want to copy the task set; the new FdTable will
  // be for new tasks.
  FdTable(const FdTable& other) : fds(other.fds),
    syscallbuf_fds_disabled_size(other.syscallbuf_fds_disabled_size),
    fd_count_beyond_limit(other.fd_count_beyond_limit),
    last_free_fd_(other.last_free_fd_) {}

  void update_syscallbuf_fds_disabled(int fd);

  std::unordered_map<int, FileMonitor::shr_ptr> fds;
  std::unordered_map<AddressSpace*, int> vms;
  // Currently this is only used during recording, so we could use
  // SYSCALLBUF_FDS_DISABLED_SIZE directly and not bother tracking it in
  // the trace header, but to make things less fragile in case we ever need to
  // know it during replay, we track it here.
  int syscallbuf_fds_disabled_size;
  // Number of elements of `fds` that are >= syscallbuf_fds_disabled_size.
  // Only used during recording.
  uint32_t fd_count_beyond_limit;
  // Only used during recording.
  int last_free_fd_;
};

} // namespace rr

#endif /* RR_FD_TABLE_H_ */
