/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "MmappedFileMonitor.h"

#include "RecordSession.h"
#include "RecordTask.h"
#include "ReplayTask.h"
#include "log.h"

using namespace std;

namespace rr {

MmappedFileMonitor::MmappedFileMonitor(Task* t, int fd) {
  ASSERT(t, !t->session().is_replaying());
  dead_ = false;
  auto stat = t->stat_fd(fd);
  device_ = stat.st_dev;
  inode_ = stat.st_ino;
}

MmappedFileMonitor::MmappedFileMonitor(Task* t, EmuFile::shr_ptr f) {
  ASSERT(t, t->session().is_replaying());

  dead_ = false;
  device_ = f->device();
  inode_ = f->inode();
}

void MmappedFileMonitor::did_write(Task* t, const std::vector<Range>& ranges,
                                   LazyOffset& offset) {
  // If there are no remaining mappings that we care about, those can't reappear
  // without going through mmap again, at which point this will be reset to
  // false.
  if (dead_) {
    return;
  }

  if (ranges.empty()) {
    return;
  }

  // Dead until proven otherwise
  dead_ = true;
  int64_t realized_offset = 0;

  bool is_replay = t->session().is_replaying();
  for (auto v : t->session().vms()) {
    for (const auto& m : v->maps()) {
      auto km = m.map;

      if (is_replay) {
        if (!m.emu_file || m.emu_file->device() != device_ ||
            m.emu_file->inode() != inode_) {
          continue;
        }
      } else {
        if (km.device() != device_ || km.inode() != inode_) {
          continue;
        }
        // If the mapping is MAP_PRIVATE then this write is dangerous
        // because it's unpredictable what will be seen in the mapping.
        // However, it could be OK if the application doesn't read from
        // this part of the mapping. Just optimistically assume this mapping
        // is not affected.
        if (!(km.flags() & MAP_SHARED)) {
          LOG(warn) << "MAP_PRIVATE mapping affected by write";
          continue;
        }
      }

      // We're discovering a mapping we care about
      if (dead_) {
        dead_ = false;
        realized_offset = offset.retrieve(true);
      }

      // stat matches.
      uint64_t mapping_offset = km.file_offset_bytes();
      int64_t local_offset = realized_offset;
      for (auto r : ranges) {
        remote_ptr<void> start = km.start() + local_offset - mapping_offset;
        MemoryRange mr(start, r.length);
        if (km.intersects(mr)) {
          if (is_replay) {
            // If we're writing beyond the EmuFile's end, resize it.
            m.emu_file->ensure_size(local_offset + r.length);
          } else {
            ASSERT(t, !v->task_set().empty());
            // We will record multiple writes if the file is mapped multiple
            // times. This is inefficient --- one is sufficient --- but not
            // wrong.
            // Make sure we use a task for this address space. `t` might have
            // a different address space.
            for (auto tt : v->task_set()) {
              // If the task here has execed, we may not be able to record its
              // memory any longer, so loop through all tasks in this address
              // space in turn in case any *didn't* exec.
              if (static_cast<RecordTask*>(tt)->record_remote_fallible(km.intersect(mr)) > 0) {
                break;
              }
            }
          }
        }
        local_offset += r.length;
      }
    }
  }
}

} // namespace rr
