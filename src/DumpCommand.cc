/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include <assert.h>
#include <inttypes.h>

#include <limits>

#include "preload/preload_interface.h"

#include "AddressSpace.h"
#include "Command.h"
#include "kernel_metadata.h"
#include "main.h"
#include "TraceStream.h"
#include "util.h"

using namespace std;

namespace rr {

class DumpCommand : public Command {
public:
  virtual int run(std::vector<std::string>& args);

protected:
  DumpCommand(const char* name, const char* help) : Command(name, help) {}

  static DumpCommand singleton;
};

DumpCommand DumpCommand::singleton(
    "dump",
    " rr dump [OPTIONS] [<trace_dir>] [<event-spec>...]\n"
    "  Event specs can be either an event number like `127', or a range\n"
    "  like `1000-5000'.  By default, all events are dumped.\n"
    "  -b, --syscallbuf           dump syscallbuf contents\n"
    " --g, --generic              dump generic data\n"
    "  -m, --recorded-metadata    dump recorded data metadata\n"
    "  -p, --mmaps                dump mmap data\n"
    "  -r, --raw                  dump trace frames in a more easily\n"
    "                             machine-parseable format instead of the\n"
    "                             default human-readable format\n"
    "  -s, --statistics           dump statistics about the trace\n");

struct DumpFlags {
  bool dump_syscallbuf;
  bool dump_generic;
  bool dump_recorded_data_metadata;
  bool dump_mmaps;
  bool raw_dump;
  bool dump_statistics;

  DumpFlags()
      : dump_syscallbuf(false),
        dump_generic(false),
        dump_recorded_data_metadata(false),
        dump_mmaps(false),
        raw_dump(false),
        dump_statistics(false) {}
};

static bool parse_dump_arg(std::vector<std::string>& args, DumpFlags& flags) {
  if (parse_global_option(args)) {
    return true;
  }

  static const OptionSpec options[] = {
    { 'b', "syscallbuf", NO_PARAMETER },
    { 'g', "generic", NO_PARAMETER },
    { 'm', "recorded-metadata", NO_PARAMETER },
    { 'p', "mmaps", NO_PARAMETER },
    { 'r', "raw", NO_PARAMETER },
    { 's', "statistics", NO_PARAMETER }
  };
  ParsedOption opt;
  if (!Command::parse_option(args, options, &opt)) {
    return false;
  }

  switch (opt.short_name) {
    case 'b':
      flags.dump_syscallbuf = true;
      break;
    case 'g':
      flags.dump_generic = true;
      break;
    case 'm':
      flags.dump_recorded_data_metadata = true;
      break;
    case 'p':
      flags.dump_mmaps = true;
      break;
    case 'r':
      flags.raw_dump = true;
      break;
    case 's':
      flags.dump_statistics = true;
      break;
    default:
      assert(0 && "Unknown option");
  }
  return true;
}

static void dump_syscallbuf_data(TraceReader& trace, FILE* out,
                                 const TraceFrame& frame) {
  if (frame.event().type() != EV_SYSCALLBUF_FLUSH) {
    return;
  }
  auto buf = trace.read_raw_data();
  size_t bytes_remaining = buf.data.size() - sizeof(struct syscallbuf_hdr);
  auto flush_hdr = reinterpret_cast<const syscallbuf_hdr*>(buf.data.data());
  if (flush_hdr->num_rec_bytes > bytes_remaining) {
    fprintf(stderr, "Malformed trace file (bad recorded-bytes count)\n");
    abort();
  }
  bytes_remaining = flush_hdr->num_rec_bytes;

  auto record_ptr = reinterpret_cast<const uint8_t*>(flush_hdr + 1);
  auto end_ptr = record_ptr + bytes_remaining;
  while (record_ptr < end_ptr) {
    auto record = reinterpret_cast<const struct syscallbuf_record*>(record_ptr);
    fprintf(out, "  { syscall:'%s', ret:0x%lx, size:0x%lx }\n",
            syscall_name(record->syscallno, frame.event().arch()).c_str(),
            (long)record->ret, (long)record->size);
    if (record->size < sizeof(*record)) {
      fprintf(stderr, "Malformed trace file (bad record size)\n");
      abort();
    }
    record_ptr += stored_record_size(record->size);
  }
}

/**
 * Dump all events from the current to trace that match |spec| to
 * |out|.  |spec| has the following syntax: /\d+(-\d+)?/, expressing
 * either a single event number of a range, and may be null to
 * indicate "dump all events".
 *
 * This function is side-effect-y, in that the trace file isn't
 * rewound in between matching each spec.  Therefore specs should be
 * constructed so as to match properly on a serial linear scan; that
 * is, they should comprise disjoint and monotonically increasing
 * event sets.  No attempt is made to enforce this or normalize specs.
 */
static void dump_events_matching(TraceReader& trace, const DumpFlags& flags,
                                 FILE* out, const string* spec) {

  uint32_t start = 0, end = numeric_limits<uint32_t>::max();

  // Try to parse the "range" syntax '[start]-[end]'.
  if (spec && 2 > sscanf(spec->c_str(), "%u-%u", &start, &end)) {
    // Fall back on assuming the spec is a single event
    // number, however it parses out with atoi().
    start = end = atoi(spec->c_str());
  }

  bool process_raw_data =
      flags.dump_syscallbuf || flags.dump_recorded_data_metadata;
  while (!trace.at_end()) {
    auto frame = trace.read_frame();
    if (end < frame.time()) {
      return;
    }
    if (start <= frame.time() && frame.time() <= end) {
      if (flags.raw_dump) {
        frame.dump_raw(out);
      } else {
        frame.dump(out);
      }
      if (flags.dump_syscallbuf) {
        dump_syscallbuf_data(trace, out, frame);
      }

      while (true) {
        TraceReader::MappedData data;
        bool found;
        KernelMapping km =
            trace.read_mapped_region(&data, &found, TraceReader::DONT_VALIDATE);
        if (!found) {
          break;
        }
        if (flags.dump_mmaps) {
          char prot_flags[] = "rwxp";
          if (!(km.prot() & PROT_READ)) {
            prot_flags[0] = '-';
          }
          if (!(km.prot() & PROT_WRITE)) {
            prot_flags[1] = '-';
          }
          if (!(km.prot() & PROT_EXEC)) {
            prot_flags[2] = '-';
          }
          if (km.flags() & MAP_SHARED) {
            prot_flags[3] = 's';
          }
          fprintf(out, "  { map_file:\"%s\", addr:%p, length:%p, "
                       "prot_flags:\"%s\", file_offset:0x%llx, "
                       "data_file:\"%s\", data_offset:0x%llx }\n",
                  km.fsname().c_str(), (void*)km.start().as_int(),
                  (void*)km.size(), prot_flags,
                  (long long)km.file_offset_bytes(), data.file_name.c_str(),
                  (long long)data.file_data_offset_bytes);
        }
      }

      TraceReader::RawData data;
      while (process_raw_data && trace.read_raw_data_for_frame(frame, data)) {
        if (flags.dump_recorded_data_metadata) {
          fprintf(out, "  { addr:%p, length:%p }\n", (void*)data.addr.as_int(),
                  (void*)data.data.size());
        }
      }
      vector<uint8_t> buf;
      while (flags.dump_generic && trace.read_generic_for_frame(frame, buf)) {
        fprintf(out, "  { length:%p }\n", (void*)buf.size());
      }
      if (!flags.raw_dump) {
        fprintf(out, "}\n");
      }
    } else {
      TraceReader::RawData data;
      while (process_raw_data && trace.read_raw_data_for_frame(frame, data)) {
      }
      while (true) {
        TraceReader::MappedData data;
        KernelMapping km = trace.read_mapped_region(&data, nullptr,
                                                    TraceReader::DONT_VALIDATE);
        if (km.size() == 0) {
          break;
        }
      }
    }
  }
}

static void dump_statistics(const TraceReader& trace, FILE* out) {
  uint64_t uncompressed = trace.uncompressed_bytes();
  uint64_t compressed = trace.compressed_bytes();
  fprintf(out, "// Uncompressed bytes %" PRIu64 ", compressed bytes %" PRIu64
               ", ratio %.2fx\n",
          uncompressed, compressed, double(uncompressed) / compressed);
}

static void dump(const string& trace_dir, const DumpFlags& flags,
                 const vector<string>& specs, FILE* out) {
  TraceReader trace(trace_dir);

  if (flags.raw_dump) {
    fprintf(out, "global_time tid reason ticks "
                 "hw_interrupts page_faults instructions "
                 "eax ebx ecx edx esi edi ebp orig_eax esp eip eflags\n");
  }

  if (specs.size() > 0) {
    for (size_t i = 0; i < specs.size(); ++i) {
      dump_events_matching(trace, flags, stdout, &specs[i]);
    }
  } else {
    // No specs => dump all events.
    dump_events_matching(trace, flags, stdout, nullptr /*all events*/);
  }

  if (flags.dump_statistics) {
    dump_statistics(trace, stdout);
  }
}

int DumpCommand::run(std::vector<std::string>& args) {
  DumpFlags flags;

  while (parse_dump_arg(args, flags)) {
  }

  string trace_dir;
  if (!parse_optional_trace_dir(args, &trace_dir)) {
    print_help(stderr);
    return 1;
  }

  dump(trace_dir, flags, args, stdout);
  return 0;
}

} // namespace rr
