/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "DumpCommand.h"

#include <arpa/inet.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <limits>
#include <unordered_map>

#include "Event.h"
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

struct JsonArrayAtKeyWriter {
  public:
  bool key_written = false;
  bool write_comma = false;

  void ensure_key(FILE *out, const char *key) {
    if (!key_written) {
      key_written = true;
      fprintf(out, ", \"%s\": [", key);
    }
  };

  void maybe_comma(FILE *out) {
    if (!write_comma) {
      write_comma = true;
    } else {
      fprintf(out, ", ");
    }
  };
};

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
    "  -R, --no-regs              skip dumping register values\n"
    "  -r, --raw                  dump trace frames in a more easily\n"
    "                             machine-parseable format instead of the\n"
    "                             default human-readable format\n"
    "  -j, --json                 dump trace frames in jsonl, i.e. one\n"
    "                             json object per line\n"
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
    { 'R', "no-regs", NO_PARAMETER },
    { 'r', "raw", NO_PARAMETER },
    { 'j', "json", NO_PARAMETER },
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
    case 'R':
      flags.dump_no_regs = true;
      break;
    case 'r':
      flags.raw_dump = true;
      break;
    case 'j':
      flags.json_dump = true;
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
                                 const DumpFlags& flags) {
  if (frame.event().type() != EV_SYSCALLBUF_FLUSH) {
    return;
  }
  TraceReader::RawData buf;
  bool ok = trace.read_raw_data_for_frame(buf);
  if (!ok) {
    FATAL() << "Can't read raw-data record for syscallbuf";
  }
  size_t bytes_remaining = buf.data.size() - trace.syscallbuf_hdr_size();
  auto flush_hdr = reinterpret_cast<const syscallbuf_hdr*>(buf.data.data());
  if (flush_hdr->num_rec_bytes > bytes_remaining) {
    CLEAN_FATAL() << "Malformed trace file (bad recorded-bytes count)";
  }
  if (flags.raw_dump) {
    char hdr_out[sizeof(syscallbuf_hdr) * 2 + 1];
    write_hex_string(buf.data.data(), sizeof(syscallbuf_hdr), hdr_out, sizeof(hdr_out));
    if (flags.json_dump) {
      fprintf(out, ", \"syscallbuf_flush_raw\": \"%s\"", hdr_out);
    } else {
      fprintf(out, "  %s\n", hdr_out);
    }
  }
  bytes_remaining = flush_hdr->num_rec_bytes;

  JsonArrayAtKeyWriter key_writer = {};

  auto record_ptr = reinterpret_cast<const uint8_t*>(flush_hdr) + trace.syscallbuf_hdr_size();
  auto end_ptr = record_ptr + bytes_remaining;
  while (record_ptr < end_ptr) {
    auto record = reinterpret_cast<const struct syscallbuf_record*>(record_ptr);
    // Buffered syscalls always use the task arch
    if (flags.json_dump) {
      key_writer.ensure_key(out, "syscalls");
      key_writer.maybe_comma(out);
      fprintf(out, "{ \"syscall\":\"%s\", \"ret\":%ld, \"size\":%ld%s%s ",
              syscall_name(record->syscallno, frame.regs().arch()).c_str(),
              (long)record->ret, (long)record->size,
              record->desched ? ", \"desched\":1" : "",
              record->replay_assist ? ", \"replay_assist\":1" : "");
    } else {
      fprintf(out, "  { syscall:'%s', ret:0x%lx, size:0x%lx%s%s }\n",
              syscall_name(record->syscallno, frame.regs().arch()).c_str(),
              (long)record->ret, (long)record->size,
              record->desched ? ", desched:1" : "",
              record->replay_assist ? ", replay_assist:1" : "");
    }
    if (flags.raw_dump) {
      auto record_out = std::vector<char>();
      record_out.resize(record->size * 2 + 1);
      write_hex_string(record_ptr, record->size, record_out.data(), record_out.size());
      if (flags.json_dump) {
        fprintf(out, ", \"raw\": \"%s\"", record_out.data());
      } else {
        fprintf(out, "  %s\n", record_out.data());
      }
    }
    if (flags.json_dump) {
      fprintf(out, "}");
    }
    if (record->size < sizeof(*record)) {
      CLEAN_FATAL() << "Malformed trace file (bad record size)";
    }
    record_ptr += stored_record_size(record->size);
  }
  if (key_writer.key_written) {
    fprintf(out, "]");
  }
  if (flags.dump_mmaps) {
    JsonArrayAtKeyWriter mmaps_key = {};
    for (auto& record : frame.event().SyscallbufFlush().mprotect_records) {
      if (flags.json_dump) {
        mmaps_key.ensure_key(out, "mmaps");
        mmaps_key.maybe_comma(out);
        fprintf(out, "{ \"start\":%ld, \"size\":%" PRIx64 ", \"prot\":\"%s\"",
                record.start, record.size, prot_flags_string(record.prot).c_str());
      } else {
        fprintf(out, "  { start:%p, size:%" PRIx64 ", prot:'%s' }\n",
                (void*)record.start, record.size, prot_flags_string(record.prot).c_str());
      }
      if (flags.raw_dump) {
        char rec_out[sizeof(record) * 2 + 1];
        write_hex_string(reinterpret_cast<const uint8_t*>(&record), sizeof(record), rec_out, sizeof(rec_out));
        if (flags.json_dump) {
          fprintf(out, ", \"raw\": \"%s\"", rec_out);
        } else {
          fprintf(out, "  %s\n", rec_out);
        }
      }
      fprintf(out, "}");
    }
    if (mmaps_key.key_written) {
      fprintf(out, "]");
    }
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

static void dump_frame_json(FILE *out, const TraceFrame &frame, const DumpFlags &flags) {
  fprintf(out, "{ \"real_time\":%f, \"global_time\":%lld, \"tid\":%d, \"event\":\"%s\", \"ticks\": %ld",
          frame.monotonic_time(), (long long)frame.time(),
          frame.tid(), frame.event().str().c_str(),
          frame.ticks());
  if (frame.event().is_syscall_event()) {
    fprintf(out, ", \"state\": \"%s\"",
            state_name(frame.event().Syscall().state));
  }
  if (!flags.dump_no_regs && frame.event().record_regs()) {
    fprintf(out, ", ");
    frame.regs().print_register_file_json(out);
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

static void dump_task_event_json(FILE* out, const TraceTaskEvent& event) {
  switch (event.type()) {
    case TraceTaskEvent::CLONE:
      fprintf(out, "{ \"event\":\"CLONE\", \"tid\":%d, \"parent\":%d, \"clone_flags\":%d }",
          event.tid(), event.parent_tid(), event.clone_flags());
      break;
    case TraceTaskEvent::EXEC:
      fprintf(out, "{ \"event\":\"EXEC\", \"tid\":%d, \"file\":\"%s\" }",
          event.tid(), json_escape(event.file_name()).c_str());
      break;
    case TraceTaskEvent::EXIT:
      fprintf(out, "{ \"event\":\"EXIT\", \"tid\":%d, \"status\":%d }",
          event.tid(), event.exit_status().get());
      break;
    case TraceTaskEvent::DETACH:
      fprintf(out, "{ \"event\":\"DETACH\", \"tid\":%d }",
          event.tid());
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
                                 const unordered_multimap<FrameTime, TraceTaskEvent>& task_events) {

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
    auto frame = trace.read_frame(start);
    if (end < frame.time()) {
      return;
    }
    if (only_end ? trace.at_end() :
         (start <= frame.time() && frame.time() <= end &&
           (!flags.only_tid || flags.only_tid == frame.tid()))) {
      if (flags.json_dump) {
        JsonArrayAtKeyWriter task_event_key_writer = {};
        dump_frame_json(out, frame, flags);

        if (flags.dump_syscallbuf) {
          dump_syscallbuf_data(trace, out, frame, flags);
        }
        if (flags.dump_task_events) {
          auto range = task_events.equal_range(frame.time());
          for (auto it = range.first; it != range.second; ++it) {
            task_event_key_writer.ensure_key(out, "task_events");
            task_event_key_writer.maybe_comma(out);
            dump_task_event_json(out, it->second);
          }
          if (task_event_key_writer.key_written) {
            fprintf(out, "]");
          }
        }
      } else {
        if (flags.raw_dump) {
          frame.dump_raw(out, !flags.dump_no_regs);
        } else {
          frame.dump(out, !flags.dump_no_regs);
        }
        if (flags.dump_syscallbuf) {
          dump_syscallbuf_data(trace, out, frame, flags);
        }
        if (flags.dump_task_events) {
          auto range = task_events.equal_range(frame.time());
          for (auto it = range.first; it != range.second; ++it) {
            dump_task_event(out, it->second);
          }
        }
      }

      JsonArrayAtKeyWriter key_writer = {};
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
          std::string fsname;
          if (data.source == TraceReader::SOURCE_ZERO) {
            fsname = "<ZERO>";
          }
          else {
            fsname = km.fsname();
          }

          if (flags.json_dump) {
            key_writer.ensure_key(out, "maps");
            key_writer.maybe_comma(out);
            fprintf(out, "{ \"map_file\":\"%s\", \"addr\": %lu, "
                         "\"length\": %lu, \"prot_flags\": \"%s\", "
                         "\"file_offset\": %lld, \"device\": %lld, "
                         "\"inode\": %lld, \"data_file\": \"%s\", "
                         "\"data_offset\": %lld, \"file_size\": %lld }",
                    json_escape(fsname).c_str(), km.start().as_int(), km.size(),
                    prot_flags, (long long)km.file_offset_bytes(),
                    (long long)km.device(), (long long)km.inode(),
                    json_escape(data.file_name).c_str(),
                    (long long)data.data_offset_bytes,
                    (long long)data.file_size_bytes);
          } else {
            fprintf(out, "  { map_file:\"%s\", addr:%p, length:%p, "
                         "prot_flags:\"%s\", file_offset:0x%llx, "
                         "device:%lld, inode:%lld, "
                         "data_file:\"%s\", data_offset:0x%llx, "
                         "file_size:0x%llx }\n",
                    fsname.c_str(), (void*)km.start().as_int(), (void*)km.size(),
                    prot_flags, (long long)km.file_offset_bytes(),
                    (long long)km.device(), (long long)km.inode(),
                    data.file_name.c_str(), (long long)data.data_offset_bytes,
                    (long long)data.file_size_bytes);
          }
        }
      }
      if (flags.json_dump && key_writer.key_written) {
        fprintf(out, " ]");
      }

      TraceReader::RawDataMetadata data;
      while (process_raw_data && trace.read_raw_data_metadata_for_frame(data)) {
        if (flags.dump_recorded_data_metadata) {
          if (flags.json_dump) {
            fprintf(out, ", \"metadata\": { \"tid\":%d, \"addr\":%ld, \"length\":%ld",
                    data.rec_tid, data.addr.as_int(), data.size);
          } else {
            fprintf(out, " { tid:%d, addr:%p, length:%p", data.rec_tid,
                    (void*)data.addr.as_int(), (void*)data.size);
          }
          if (!data.holes.empty()) {
            if (flags.json_dump) {
              fputs(", \"holes\":[", out);
            } else {
              fputs(", holes:[", out);
            }
            bool first = true;
            for (auto& h : data.holes) {
              if (!first) {
                fputs(", ", out);
              }
              first = false;
              if (flags.json_dump) {
                fprintf(out, "\"%p-%p\"", (void*)h.offset, (void*)(h.offset + h.size));
              } else {
                fprintf(out, "%p-%p", (void*)h.offset, (void*)(h.offset + h.size));
              }
            }
            fputs("]", out);
          }
          if (flags.json_dump) {
            fputs(" }", out);
          } else {
            fputs(" }\n", out);
          }
        }
      }
      if (flags.dump_socket_addrs) {
        dump_socket_addrs(out, frame);
      }
      if (!flags.raw_dump || flags.json_dump) {
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

  if (flags.raw_dump && !flags.json_dump) {
    fprintf(out, "global_time tid reason ticks "
                 "hw_interrupts page_faults instructions "
                 "eax ebx ecx edx esi edi ebp orig_eax esp eip eflags\n");
  }

  unordered_multimap<FrameTime, TraceTaskEvent> task_events;
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
