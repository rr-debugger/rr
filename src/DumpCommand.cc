/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "Command.h"

#include <assert.h>
#include <inttypes.h>

#include <limits>

#include "preload/preload_interface.h"

#include "Flags.h"
#include "kernel_metadata.h"
#include "TraceStream.h"

using namespace std;

class DumpCommand : public Command {
public:
  virtual int run(std::vector<std::string>& args);

protected:
  DumpCommand(const char* name, const char* help) : Command(name, help) {}

  static DumpCommand singleton;
};

DumpCommand DumpCommand::singleton(
    "dump",
    " rr dump [OPTIONS] <trace_dir> [<event-spec>...]\n"
    "  Event specs can be either an event number like `127', or a range\n"
    "  like `1000-5000'.  By default, all events are dumped.\n"
    "  -r, --raw                  dump trace frames in a more easily\n"
    "                             machine-parseable format instead of the\n"
    "                             default human-readable format\n"
    "  -s, --statistics           dump statistics about the trace\n"
    "  -b, --syscallbuf           dump syscallbuf contents\n");

static void dump_syscallbuf_data(TraceReader& trace, FILE* out,
                                 const TraceFrame& frame) {
  if (frame.event().type != EV_SYSCALLBUF_FLUSH) {
    return;
  }
  auto buf = trace.read_raw_data();
  size_t bytes_remaining = buf.data.size() - sizeof(struct syscallbuf_hdr);
  auto flush_hdr = reinterpret_cast<const syscallbuf_hdr*>(buf.data.data());
  if (flush_hdr->num_rec_bytes != bytes_remaining) {
    fprintf(stderr, "Malformed trace file (bad recorded-bytes count)\n");
    abort();
  }

  auto record_ptr = reinterpret_cast<const uint8_t*>(flush_hdr + 1);
  auto end_ptr = record_ptr + bytes_remaining;
  while (record_ptr < end_ptr) {
    auto record = reinterpret_cast<const struct syscallbuf_record*>(record_ptr);
    fprintf(out, "  { syscall:'%s', ret:0x%lx }\n",
            syscall_name(record->syscallno, frame.event().arch()).c_str(),
            (long)record->ret);
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
static void dump_events_matching(TraceReader& trace, FILE* out,
                                 const string* spec) {

  uint32_t start = 0, end = numeric_limits<uint32_t>::max();

  // Try to parse the "range" syntax '[start]-[end]'.
  if (spec && 2 > sscanf(spec->c_str(), "%u-%u", &start, &end)) {
    // Fall back on assuming the spec is a single event
    // number, however it parses out with atoi().
    start = end = atoi(spec->c_str());
  }

  bool dump_raw_data = Flags::get().dump_syscallbuf;
  while (!trace.at_end()) {
    auto frame = trace.read_frame();
    if (end < frame.time()) {
      return;
    }
    if (start <= frame.time() && frame.time() <= end) {
      if (Flags::get().raw_dump) {
        frame.dump_raw(out);
      } else {
        frame.dump(out);
      }
      if (Flags::get().dump_syscallbuf) {
        dump_syscallbuf_data(trace, out, frame);
      }
      if (!Flags::get().raw_dump) {
        fprintf(out, "}\n");
      }
    }
    TraceReader::RawData data;
    while (dump_raw_data && trace.read_raw_data_for_frame(frame, data)) {
      // Skip raw data for this frame
    }
  }
}

static void dump_statistics(const TraceReader& trace, FILE* out) {
  uint64_t uncompressed = trace.uncompressed_bytes();
  uint64_t compressed = trace.compressed_bytes();
  fprintf(stdout, "// Uncompressed bytes %" PRIu64 ", compressed bytes %" PRIu64
                  ", ratio %.2fx\n",
          uncompressed, compressed, double(uncompressed) / compressed);
}

static void dump(TraceReader& trace, const vector<string>& specs, FILE* out) {
  if (Flags::get().raw_dump) {
    fprintf(out, "global_time tid reason "
                 "hw_interrupts page_faults adapted_ticks instructions "
                 "eax ebx ecx edx esi edi ebp orig_eax esp eip eflags\n");
  }

  if (specs.size() > 0) {
    for (size_t i = 0; i < specs.size(); ++i) {
      dump_events_matching(trace, stdout, &specs[i]);
    }
  } else {
    // No specs => dump all events.
    dump_events_matching(trace, stdout, nullptr /*all events*/);
  }

  if (Flags::get().dump_statistics) {
    dump_statistics(trace, stdout);
  }
}

static bool parse_dump_arg(std::vector<std::string>& args) {
  if (parse_global_option(args)) {
    return true;
  }

  static const OptionSpec options[] = { { 'b', "syscallbuf", NO_PARAMETER },
                                        { 'r', "raw", NO_PARAMETER },
                                        { 's', "statistics", NO_PARAMETER } };
  ParsedOption opt;
  if (!Command::parse_option(args, options, &opt)) {
    return false;
  }

  Flags& flags = Flags::get_for_init();
  switch (opt.short_name) {
    case 'b':
      flags.dump_syscallbuf = true;
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

int DumpCommand::run(std::vector<std::string>& args) {
  while (parse_dump_arg(args)) {
  }

  unique_ptr<TraceReader> trace = parse_optional_trace_dir(args);
  if (!trace) {
    return 1;
  }

  dump(*trace, args, stdout);
  return 0;
}
