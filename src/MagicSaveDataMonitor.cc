/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "MagicSaveDataMonitor.h"

#include <limits.h>

#include <rr/rr.h>

#include "RecordTask.h"
#include "ReplayTask.h"
#include "Session.h"
#include "log.h"
#include "util.h"

namespace rr {

static void dump_path_data(Task* t, FrameTime global_time, const char* tag,
                           char* filename, size_t filename_size,
                           const void* buf, size_t buf_len,
                           remote_ptr<void> addr) {
  format_dump_filename(t, global_time, tag, filename, filename_size);
  dump_binary_data(filename, tag, (const uint32_t*)buf, buf_len / 4, addr);
}

static void notify_save_data_error(ReplayTask* t, remote_ptr<void> addr,
                                   const void* rec_buf, size_t rec_buf_len,
                                   const void* rep_buf, size_t rep_buf_len) {
  char rec_dump[PATH_MAX];
  char rep_dump[PATH_MAX];
  FrameTime global_time = t->current_trace_frame().time();

  dump_path_data(t, global_time, "rec_save_data", rec_dump, sizeof(rec_dump),
                 rec_buf, rec_buf_len, addr);
  dump_path_data(t, global_time, "rep_save_data", rep_dump, sizeof(rep_dump),
                 rep_buf, rep_buf_len, addr);

  ASSERT(t,
         (rec_buf_len == rep_buf_len && !memcmp(rec_buf, rep_buf, rec_buf_len)))
      << "Divergence in contents of 'tracee-save buffer'.  Recording executed\n"
         "\n"
         "  write("
      << RR_MAGIC_SAVE_DATA_FD << ", " << addr << ", " << rec_buf_len
      << ")\n"
         "\n"
         "and replay executed\n"
         "\n"
         "  write("
      << RR_MAGIC_SAVE_DATA_FD << ", " << addr << ", " << rep_buf_len
      << ")\n"
         "\n"
         "The contents of the tracee-save buffers have been dumped to disk.\n"
         "Compare them by using the following command\n"
         "\n"
         "$ diff -u "
      << rec_dump << " " << rep_dump << " >save-data-diverge.diff\n";
}

void MagicSaveDataMonitor::did_write(Task* t, const std::vector<Range>& ranges,
                                     LazyOffset&) {
  for (auto& r : ranges) {
    if (t->session().is_recording()) {
      static_cast<RecordTask*>(t)->record_remote(r.data.cast<uint8_t>(),
                                                 r.length);
    } else if (t->session().is_replaying()) {
      auto rt = static_cast<ReplayTask*>(t);
      auto bytes = rt->read_mem(r.data.cast<uint8_t>(), r.length);
      auto rec = rt->trace_reader().read_raw_data();
      if (rec.data != bytes) {
        notify_save_data_error(rt, rec.addr, rec.data.data(), rec.data.size(),
                               bytes.data(), bytes.size());
      }
    }
  }
}

} // namespace rr
