/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "DumpCommand.h"

#include <arpa/inet.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <limits>
#include <unordered_map>

#include "preload/preload_interface.h"

#include "AddressSpace.h"
#include "Command.h"
#include "TraceStream.h"
#include "core.h"
#include "kernel_metadata.h"
#include "log.h"
#include "main.h"
#include "util.h"

using namespace std;

namespace rr {

class DumpCommand : public Command {
public:
  virtual int run(vector<string>& args) override;

protected:
  DumpCommand(const char* name, const char* help) : Command(name, help) {}

  static DumpCommand singleton;
};

DumpCommand DumpCommand::singleton(
    "dump",
    " rr dump [OPTIONS] [<trace_dir>] [<event-spec>...]\n"
    "  Event specs can be either an event number like `127', or a range\n"
    "  like `1000-5000', or `end' for the last record in the trace.\n"
    "  By default, all events are dumped.\n"
    "  -b, --syscallbuf           dump syscallbuf contents\n"
    "  -e, --task-events          dump task events\n"
    "  -m, --recorded-metadata    dump recorded data metadata\n"
    "  -p, --mmaps                dump mmap data\n"
    "  -r, --raw                  dump trace frames in a more easily\n"
    "                             machine-parseable format instead of the\n"
    "                             default human-readable format\n"
    "  -s, --statistics           dump statistics about the trace\n"
    "  -t, --tid=<pid>            dump events only for the specified tid\n");

static bool parse_dump_arg(vector<string>& args, DumpFlags& flags) {
  if (parse_global_option(args)) {
    return true;
  }

  static const OptionSpec options[] = {
    { 0, "socket-addresses", NO_PARAMETER },
    { 'b', "syscallbuf", NO_PARAMETER },
    { 'e', "task-events", NO_PARAMETER },
    { 'm', "recorded-metadata", NO_PARAMETER },
    { 'p', "mmaps", NO_PARAMETER },
    { 'r', "raw", NO_PARAMETER },
    { 's', "statistics", NO_PARAMETER },
    { 't', "tid", HAS_PARAMETER },
  };
  ParsedOption opt;
  if (!Command::parse_option(args, options, &opt)) {
    return false;
  }

  switch (opt.short_name) {
    case 'b':
      flags.dump_syscallbuf = true;
      break;
    case 'e':
      flags.dump_task_events = true;
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
    case 't':
      if (!opt.verify_valid_int(1, INT32_MAX)) {
        return false;
      }
      flags.only_tid = opt.int_value;
      break;
    case 0:
      flags.dump_socket_addrs = true;
      break;
    default:
      DEBUG_ASSERT(0 && "Unknown option");
  }
  return true;
}

static void dump_syscallbuf_data(TraceReader& trace, FILE* out,
                                 const TraceFrame& frame,
                                 bool dump_raw) {
  if (frame.event().type() != EV_SYSCALLBUF_FLUSH) {
    return;
  }
  auto buf = trace.read_raw_data();
  size_t bytes_remaining = buf.data.size() - sizeof(struct syscallbuf_hdr);
  auto flush_hdr = reinterpret_cast<const syscallbuf_hdr*>(buf.data.data());
  if (flush_hdr->num_rec_bytes > bytes_remaining) {
    fprintf(stderr, "Malformed trace file (bad recorded-bytes count)\n");
    notifying_abort();
  }
  bytes_remaining = flush_hdr->num_rec_bytes;

  auto record_ptr = reinterpret_cast<const uint8_t*>(flush_hdr + 1);
  auto end_ptr = record_ptr + bytes_remaining;
  while (record_ptr < end_ptr) {
    auto record = reinterpret_cast<const struct syscallbuf_record*>(record_ptr);
    // Buffered syscalls always use the task arch
    fprintf(out, "  { syscall:'%s', ret:0x%lx, size:0x%lx%s%s }\n",
            syscall_name(record->syscallno, frame.regs().arch()).c_str(),
            (long)record->ret, (long)record->size,
            record->desched ? ", desched:1" : "",
            record->replay_assist ? ", replay_assist:1" : "");
    if (dump_raw) {
      fprintf(out, "  ");
      for (unsigned long i = 0; i < record->size; ++i) {
        fprintf(out, "%2.2x", *(record_ptr + (uintptr_t)i));
      }
      fprintf(out, "\n");
    }
    if (record->size < sizeof(*record)) {
      fprintf(stderr, "Malformed trace file (bad record size)\n");
      notifying_abort();
    }
    record_ptr += stored_record_size(record->size);
  }
}

static void print_socket_addr(FILE* out, const struct NativeArch::sockaddr_storage& sa) {
  char buf[256];
  auto sockaddr = reinterpret_cast<const struct sockaddr_storage*>(&sa);
  switch (sockaddr->ss_family) {
    case AF_INET: {
      auto sockaddr_in = reinterpret_cast<const struct sockaddr_in*>(sockaddr);
      if (inet_ntop(AF_INET, &sockaddr_in->sin_addr, buf, sizeof(buf) - 1)) {
        fprintf(out, "%s:%d", buf, sockaddr_in->sin_port);
      } else {
        FATAL();
      }
      break;
    }
    case AF_INET6: {
      auto sockaddr_in6 = reinterpret_cast<const struct sockaddr_in6*>(sockaddr);
      if (inet_ntop(AF_INET6, &sockaddr_in6->sin6_addr, buf, sizeof(buf) - 1)) {
        fprintf(out, "%s:%d", buf, sockaddr_in6->sin6_port);
      } else {
        FATAL();
      }
      break;
    }
    default:
      fputs("<Unknown socket family>", out);
      break;
  }
}

static void dump_socket_addrs(FILE* out, const TraceFrame& frame) {
  if (frame.event().type() != EV_SYSCALL) {
    return;
  }

  auto syscall = frame.event().Syscall();
  if (syscall.socket_addrs) {
    fputs("  Local socket address '", out);
    print_socket_addr(out, (*syscall.socket_addrs.get())[0]);
    fputs("' Remote socket address '", out);
    print_socket_addr(out, (*syscall.socket_addrs.get())[1]);
    fputs("'\n", out);
  }
}

static void dump_task_event(FILE* out, const TraceTaskEvent& event) {
  switch (event.type()) {
    case TraceTaskEvent::CLONE:
      fprintf(out, "  TraceTaskEvent::CLONE tid=%d parent=%d clone_flags=0x%x\n",
          event.tid(), event.parent_tid(), event.clone_flags());
      break;
    case TraceTaskEvent::EXEC:
      fprintf(out, "  TraceTaskEvent::EXEC tid=%d file=%s\n", event.tid(),
          event.file_name().c_str());
      break;
    case TraceTaskEvent::EXIT:
      fprintf(out, "  TraceTaskEvent::EXIT tid=%d status=%d\n", event.tid(),
          event.exit_status().get());
      break;
    case TraceTaskEvent::DETACH:
      fprintf(out, "  TraceTaskEvent::DETACH tid=%d\n", event.tid());
      break;
    default:
      FATAL() << "Unknown TraceTaskEvent";
      break;
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
                                 FILE* out, const string* spec,
                                 const unordered_map<FrameTime, TraceTaskEvent>& task_events) {

  uint32_t start = 0, end = numeric_limits<uint32_t>::max();
  bool only_end = false;

  if (spec && *spec == "end") {
    only_end = true;
  } else {
    // Try to parse the "range" syntax '[start]-[end]'.
    if (spec && 2 > sscanf(spec->c_str(), "%u-%u", &start, &end)) {
      // Fall back on assuming the spec is a single event
      // number, however it parses out with atoi().
      start = end = atoi(spec->c_str());
    }
  }

  bool process_raw_data =
      flags.dump_syscallbuf || flags.dump_recorded_data_metadata;
  while (!trace.at_end()) {
    auto frame = trace.read_frame();
    if (end < frame.time()) {
      return;
    }
    if (only_end ? trace.at_end() :
         (start <= frame.time() && frame.time() <= end &&
           (!flags.only_tid || flags.only_tid == frame.tid()))) {
      if (flags.raw_dump) {
        frame.dump_raw(out);
      } else {
        frame.dump(out);
      }
      if (flags.dump_syscallbuf) {
        dump_syscallbuf_data(trace, out, frame, flags.raw_dump);
      }
      if (flags.dump_task_events) {
        auto it = task_events.find(frame.time());
        if (it != task_events.end()) {
          dump_task_event(out, it->second);
        }
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
          const char* fsname = km.fsname().c_str();
          if (data.source == TraceReader::SOURCE_ZERO) {
            static const char source_zero[] = "<ZERO>";
            fsname = source_zero;
          }
          fprintf(out, "  { map_file:\"%s\", addr:%p, length:%p, "
                       "prot_flags:\"%s\", file_offset:0x%llx, "
                       "device:%lld, inode:%lld, "
                       "data_file:\"%s\", data_offset:0x%llx, "
                       "file_size:0x%llx }\n",
                  fsname, (void*)km.start().as_int(), (void*)km.size(),
                  prot_flags, (long long)km.file_offset_bytes(),
                  (long long)km.device(), (long long)km.inode(),
                  data.file_name.c_str(), (long long)data.data_offset_bytes,
                  (long long)data.file_size_bytes);
        }
      }

      TraceReader::RawDataMetadata data;
      while (process_raw_data && trace.read_raw_data_metadata_for_frame(data)) {
        if (flags.dump_recorded_data_metadata) {
          fprintf(out, "  { tid:%d, addr:%p, length:%p", data.rec_tid,
                  (void*)data.addr.as_int(), (void*)data.size);
          if (!data.holes.empty()) {
            fputs(", holes:[", out);
            bool first = true;
            for (auto& h : data.holes) {
              if (!first) {
                fputs(", ", out);
              }
              fprintf(out, "%p-%p", (void*)h.offset, (void*)(h.offset + h.size));
            }
            fputs("]", out);
          }
          fputs(" }\n", out);
        }
      }
      if (flags.dump_socket_addrs) {
        dump_socket_addrs(out, frame);
      }
      if (!flags.raw_dump) {
        fprintf(out, "}\n");
      }
    } else {
      while (true) {
        TraceReader::MappedData data;
        KernelMapping km = trace.read_mapped_region(&data, nullptr,
                                                    TraceReader::DONT_VALIDATE);
        if (km.size() == 0) {
          break;
        }
      }
      TraceReader::RawDataMetadata data;
      while (process_raw_data && trace.read_raw_data_metadata_for_frame(data)) {
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

void dump(const string& trace_dir, const DumpFlags& flags,
          const vector<string>& specs, FILE* out) {
  TraceReader trace(trace_dir);

  if (flags.raw_dump) {
    fprintf(out, "global_time tid reason ticks "
                 "hw_interrupts page_faults instructions "
                 "eax ebx ecx edx esi edi ebp orig_eax esp eip eflags\n");
  }

  unordered_map<FrameTime, TraceTaskEvent> task_events;
  FrameTime last_time = 0;
  while (true) {
    FrameTime time;
    TraceTaskEvent r = trace.read_task_event(&time);
    if (time < last_time) {
      FATAL() << "TraceTaskEvent times non-monotonic";
    }
    if (r.type() == TraceTaskEvent::NONE) {
      break;
    }
    task_events.insert(make_pair(time, r));
    last_time = time;
  }

  if (specs.size() > 0) {
    for (size_t i = 0; i < specs.size(); ++i) {
      dump_events_matching(trace, flags, out, &specs[i], task_events);
    }
  } else {
    // No specs => dump all events.
    dump_events_matching(trace, flags, out, nullptr /*all events*/, task_events);
  }

  if (flags.dump_statistics) {
    dump_statistics(trace, out);
  }
}

int DumpCommand::run(vector<string>& args) {
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
