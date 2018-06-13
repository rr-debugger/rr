/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_DUMP_COMMAND_H_
#define RR_DUMP_COMMAND_H_

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif

#include <stdio.h>

#include <memory>
#include <string>
#include <vector>

namespace rr {

struct DumpFlags {
  bool dump_syscallbuf;
  bool dump_recorded_data_metadata;
  bool dump_mmaps;
  bool dump_task_events;
  bool raw_dump;
  bool dump_statistics;
  int only_tid;

  DumpFlags()
      : dump_syscallbuf(false),
        dump_recorded_data_metadata(false),
        dump_mmaps(false),
        dump_task_events(false),
        raw_dump(false),
        dump_statistics(false),
        only_tid(0) {}
};

void dump(const std::string& trace_dir, const DumpFlags& flags,
          const std::vector<std::string>& specs, FILE* out);

} // namespace rr

#endif // RR_DUMP_COMMAND_H_
