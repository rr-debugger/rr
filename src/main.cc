/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include <assert.h>
#include <dlfcn.h>
#include <getopt.h>
#include <inttypes.h>
#include <linux/version.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sysexits.h>
#include <sys/prctl.h>
#include <sys/utsname.h>
#include <sys/wait.h>

#include <limits>
#include <sstream>

#include "preload/syscall_buffer.h"

#include "log.h"
#include "recorder.h"
#include "recorder_sched.h"
#include "replayer.h"
#include "syscalls.h"
#include "task.h"
#include "trace.h"
#include "util.h"

using namespace std;

extern char** environ;

static void dump_syscallbuf_data(TraceReader& trace, FILE* out,
                                 const TraceFrame& frame) {
  if (frame.event().type != EV_SYSCALLBUF_FLUSH) {
    return;
  }
  auto buf = trace.read_raw_data();
  size_t bytes_remaining =
      buf.data.size() - sizeof(sizeof(struct syscallbuf_hdr));
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
            syscall_name(record->syscallno, frame.event().arch()), record->ret);
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
                                 const char* spec) {

  uint32_t start = 0, end = numeric_limits<uint32_t>::max();

  // Try to parse the "range" syntax '[start]-[end]'.
  if (spec && 2 > sscanf(spec, "%u-%u", &start, &end)) {
    // Fall back on assuming the spec is a single event
    // number, however it parses out with atoi().
    start = end = atoi(spec);
  }

  bool dump_raw_data = Flags::get().dump_syscallbuf;
  while (!trace.at_end()) {
    TraceFrame frame;
    trace >> frame;
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

static int dump(int argc, char* argv[], char** envp) {
  FILE* out = stdout;
  TraceReader trace(argc > 0 ? argv[0] : "");

  if (Flags::get().raw_dump) {
    fprintf(out, "global_time tid reason "
                 "hw_interrupts page_faults adapted_rbc instructions "
                 "eax ebx ecx edx esi edi ebp orig_eax esp eip eflags\n");
  }

  if (1 == argc) {
    // No specs => dump all events.
    dump_events_matching(trace, stdout, nullptr /*all events*/);
  } else {
    for (int i = 1; i < argc; ++i) {
      dump_events_matching(trace, stdout, argv[i]);
    }
  }

  if (Flags::get().dump_statistics) {
    dump_statistics(trace, stdout);
  }

  return 0;
}

static void assert_prerequisites(Flags* flags) {
  struct utsname uname_buf;
  memset(&uname_buf, 0, sizeof(uname_buf));
  if (!uname(&uname_buf)) {
    unsigned int major, minor;
    char dot;
    stringstream stream(uname_buf.release);
    stream >> major >> dot >> minor;
    if (KERNEL_VERSION(major, minor, 0) < KERNEL_VERSION(3, 4, 0)) {
      FATAL() << "Kernel doesn't support necessary ptrace "
              << "functionality; need 3.4.0 or better.";
    }

    if (flags->use_syscall_buffer &&
        KERNEL_VERSION(major, minor, 0) < KERNEL_VERSION(3, 5, 0)) {
      FATAL() << "Your kernel does not support syscall "
              << "filtering; please use the -n option";
    }
  }
}

static void check_performance_settings() {
  // NB: we hard-code "cpu0" here because rr pins itself and all
  // tracees to cpu 0.  We don't care about the other CPUs.
  int fd =
      open("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor", O_RDONLY);
  if (0 > fd) {
    // If the file doesn't exist, the system probably
    // doesn't have the ability to frequency-scale, for
    // example a VM.
    LOG(info) << "Unable to check CPU-frequency governor.";
    return;
  }
  char governor[PATH_MAX];
  ssize_t nread = read(fd, governor, sizeof(governor) - 1);
  if (0 > nread) {
    FATAL() << "Unable to read cpu0's frequency governor.";
  }
  governor[nread] = '\0';
  ssize_t len = strlen(governor);
  if (len > 0) {
    // Eat the '\n'.
    governor[len - 1] = '\0';
  }
  LOG(info) << "cpu0's frequency governor is '" << governor << "'";
  if (strcmp("performance", governor)) {
    fprintf(stderr,
            "\n"
            "rr: Warning: Your CPU frequency governor is '%s'.  rr strongly\n"
            "    recommends that you use the 'performance' governor.  Not "
            "using the\n"
            "    'performance' governor can cause rr to be at least 2x slower\n"
            "    on laptops.\n"
            "\n"
            "    On Fedora-based systems, you can enable the 'performance' "
            "governor\n"
            "    by running the following commands:\n"
            "\n"
            "    $ sudo yum install kernel-tools\n"
            "    $ sudo cpupower frequency-set -g performance\n"
            "\n",
            governor);
    // TODO: It would be nice to bail here or do something
    // clever to enable the 'performance' just for rr, but
    // that seems too hard at the moment.
  }
  close(fd);
}

static void print_usage(void) {
  fputs(
      "Usage: rr [OPTION] (record|replay|dump) [OPTION]... [ARG]...\n"
      "\n"
      "Common options\n"
      "  -a, --microarch=<NAME>     force rr to assume it's running on a CPU\n"
      "                             with microarch NAME even if runtime "
      "detection\n"
      "                             says otherwise.  NAME should be a string "
      "like\n"
      "                             'Ivy Bridge'.\n"
      "  -c, --checksum={on-syscalls,on-all-events}|FROM_TIME\n"
      "                             compute and store (during recording) or\n"
      "                             read and verify (during replay) checksums\n"
      "                             of each of a tracee's memory mappings "
      "either\n"
      "                             at the end of all syscalls "
      "(`on-syscalls'),\n"
      "                             at all events (`on-all-events'), or \n"
      "                             starting from a global timepoint "
      "FROM_TIME\n"
      "  -d, --dump-on=<SYSCALL_NUM|-SIGNAL_NUM>\n"
      "                             dump memory at SYSCALL or SIGNAL to the\n"
      "                             file "
      "`[trace_dir]/[tid].[time]_{rec,rep}':\n"
      "                             `_rec' for dumps during recording, `_rep'\n"
      "                             for dumps during replay\n"
      "  -f, --force-things\n       force rr to do some things that don't "
      "seem\n"
      "                             like good ideas, for example launching an\n"
      "                             interactive emergency debugger if stderr\n"
      "                             isn't a tty.\n"
      "  -k, --check-cached-mmaps   verify that cached task mmaps match "
      "/proc/maps\n"
      "  -e, --fatal-errors         any warning or error that is printed is\n"
      "                             treated as fatal\n"
      "  -m, --mark-stdio           mark stdio writes with [rr.<EVENT-NO>],\n"
      "                             where EVENT-NO is the global trace time "
      "at\n"
      "                             which the write occures.\n"
      "  -s, --suppress-environment-warnings\n"
      "                             suppress warnings about issues in the\n"
      "                             environment that rr has no control over\n"
      "  -t, --dump-at=TIME         dump memory at global timepoint TIME\n"
      "  -u, --cpu-unbound          allow tracees to run on any virtual CPU.\n"
      "                             Default is to bind to CPU 0.  This option\n"
      "                             can cause replay divergence: use with\n"
      "                             caution.\n"
      "  -v, --verbose              log messages that may not be urgently \n"
      "                             critical to the user\n"
      "  -w, --wait-secs=<NUM_SECS> wait NUM_SECS seconds just after startup,\n"
      "                             before initiating recording or replaying\n"
      "\n"
      "Syntax for `record'\n"
      " rr record [OPTION]... <exe> [exe-args]...\n"
      "  -b, --force-syscall-buffer force the syscall buffer preload library\n"
      "                             to be used, even if that's probably a bad\n"
      "                             idea\n"
      "  -c, --num-cpu-ticks=<NUM>  maximum number of 'CPU ticks' (currently \n"
      "                             retired conditional branches) to allow a \n"
      "                             task to run before interrupting it\n"
      "  -e, --num-events=<NUM>     maximum number of events (syscall \n"
      "                             enter/exit, signal, CPU interrupt, ...) \n"
      "                             to allow a task before descheduling it\n"
      "  -i, --ignore-signal=<SIG>  block <SIG> from being delivered to "
      "tracees.\n"
      "                             Probably only useful for unit tests.\n"
      "  -n, --no-syscall-buffer    disable the syscall buffer preload "
      "library\n"
      "                             even if it would otherwise be used\n"
      "\n"
      "Syntax for `replay'\n"
      " rr replay [OPTION]... [<trace-dir>]\n"
      "  -a, --autopilot            replay without debugger server\n"
      "  -f, --onfork=<PID>         start a debug server when <PID> has been\n"
      "                             fork()d, AND the target event has been\n"
      "                             reached.\n"
      "  -g, --goto=<EVENT-NUM>     start a debug server on reaching "
      "<EVENT-NUM>\n"
      "                             in the trace.  See -m above.\n"
      "  -p, --onprocess=<PID>      start a debug server when <PID> has been\n"
      "                             exec()d, AND the target event has been\n"
      "                             reached.\n"
      "  -q, --no-redirect-output   don't replay writes to stdout/stderr\n"
      "  -s, --dbgport=<PORT>       only start a debug server on <PORT>;\n"
      "                             don't automatically launch the debugger\n"
      "                             client too.\n"
      "  -x, --gdb-x=<FILE>         execute gdb commands from <FILE>\n"
      "\n"
      "Syntax for `dump`\n"
      " rr dump [OPTIONS] <trace_dir> [<event-spec>...]\n"
      "  Event specs can be either an event number like `127', or a range\n"
      "  like `1000-5000'.  By default, all events are dumped.\n"
      "  -r, --raw                  dump trace frames in a more easily\n"
      "                             machine-parseable format instead of the\n"
      "                             default human-readable format\n"
      "  -s, --statistics           dump statistics about the trace\n"
      "  -b, --syscallbuf           dump syscallbuf contents\n"
      "\n"
      "A command line like `rr (-h|--help|help)...' will print this message.\n",
      stderr);
}

static int parse_record_args(int cmdi, int argc, char** argv, Flags* flags) {
  struct option opts[] = { { "force-syscall-buffer", no_argument, NULL, 'b' },
                           { "ignore-signal", required_argument, NULL, 'i' },
                           { "num-cpu-ticks", required_argument, NULL, 'c' },
                           { "num-events", required_argument, NULL, 'e' },
                           { "no-syscall-buffer", no_argument, NULL, 'n' },
                           { 0 } };
  optind = cmdi;
  while (1) {
    int i = 0;
    switch (getopt_long(argc, argv, "+c:be:i:n", opts, &i)) {
      case -1:
        return optind;
      case 'b':
        flags->use_syscall_buffer = true;
        break;
      case 'c':
        flags->max_rbc = MAX(1, atoi(optarg));
        break;
      case 'e':
        flags->max_events = MAX(1, atoi(optarg));
        break;
      case 'i':
        flags->ignore_sig = MIN(_NSIG - 1, MAX(1, atoi(optarg)));
        break;
      case 'n':
        flags->use_syscall_buffer = false;
        break;
      default:
        return -1;
    }
  }
}

static int parse_replay_args(int cmdi, int argc, char** argv, Flags* flags) {
  struct option opts[] = { { "autopilot", no_argument, NULL, 'a' },
                           { "dbgport", required_argument, NULL, 's' },
                           { "goto", required_argument, NULL, 'g' },
                           { "no-redirect-output", no_argument, NULL, 'q' },
                           { "onfork", required_argument, NULL, 'f' },
                           { "onprocess", required_argument, NULL, 'p' },
                           { "gdb-x", required_argument, NULL, 'x' },
                           { 0 } };
  optind = cmdi;
  while (1) {
    int i = 0;
    switch (getopt_long(argc, argv, "+af:g:p:qs:x:", opts, &i)) {
      case -1:
        return optind;
      case 'a':
        flags->goto_event = numeric_limits<decltype(flags->goto_event)>::max();
        flags->dont_launch_debugger = true;
        break;
      case 'f':
        flags->target_process = atoi(optarg);
        flags->process_created_how = Flags::CREATED_FORK;
        break;
      case 'g':
        flags->goto_event = atoi(optarg);
        break;
      case 'p':
        flags->target_process = atoi(optarg);
        flags->process_created_how = Flags::CREATED_EXEC;
        break;
      case 'q':
        flags->redirect = false;
        break;
      case 's':
        flags->dbgport = atoi(optarg);
        flags->dont_launch_debugger = true;
        break;
      case 'x':
        flags->gdb_command_file_path = optarg;
        break;
      default:
        return -1;
    }
  }
}

static int parse_dump_args(int cmdi, int argc, char** argv, Flags* flags) {
  struct option opts[] = { { "syscallbuf", no_argument, NULL, 'b' },
                           { "raw", no_argument, NULL, 'r' },
                           { "statistics", no_argument, NULL, 's' },
                           { 0 } };
  optind = cmdi;
  while (1) {
    int i = 0;
    switch (getopt_long(argc, argv, "brs", opts, &i)) {
      case -1:
        return optind;
      case 'b':
        flags->dump_syscallbuf = true;
        break;
      case 'r':
        flags->raw_dump = true;
        break;
      case 's':
        flags->dump_statistics = true;
        break;
      default:
        return -1;
    }
  }
}

static int parse_common_args(int argc, char** argv, Flags* flags) {
  struct option opts[] = { { "checksum", required_argument, NULL, 'c' },
                           { "check-cached-mmaps", no_argument, NULL, 'k' },
                           { "cpu-unbound", no_argument, NULL, 'u' },
                           { "dump-at", required_argument, NULL, 't' },
                           { "dump-on", required_argument, NULL, 'd' },
                           { "force-things", no_argument, NULL, 'f' },
                           { "force-microarch", required_argument, NULL, 'a' },
                           { "mark-stdio", no_argument, NULL, 'm' },
                           { "suppress-environment-warnings", no_argument,
                             NULL,                            's' },
                           { "fatal-errors", no_argument, NULL, 'e' },
                           { "verbose", no_argument, NULL, 'v' },
                           { "wait-secs", required_argument, NULL, 'w' },
                           { 0 } };
  while (1) {
    int i = 0;
    switch (getopt_long(argc, argv, "+a:c:d:fkmst:uvw:", opts, &i)) {
      case -1:
        return optind;
      case 'a':
        flags->forced_uarch = optarg;
        break;
      case 'c':
        if (!strcmp("on-syscalls", optarg)) {
          LOG(info) << "checksumming on syscall exit";
          flags->checksum = Flags::CHECKSUM_SYSCALL;
        } else if (!strcmp("on-all-events", optarg)) {
          LOG(info) << "checksumming on all events";
          flags->checksum = Flags::CHECKSUM_ALL;
        } else {
          flags->checksum = atoi(optarg);
          LOG(info) << "checksumming on at event " << flags->checksum;
        }
        break;
      case 'd':
        flags->dump_on = atoi(optarg);
        break;
      case 'e':
        flags->fatal_errors_and_warnings = true;
        break;
      case 'f':
        flags->force_things = true;
        break;
      case 'k':
        flags->check_cached_mmaps = true;
        break;
      case 'm':
        flags->mark_stdio = true;
        break;
      case 's':
        flags->suppress_environment_warnings = true;
        break;
      case 't':
        flags->dump_at = atoi(optarg);
        break;
      case 'u':
        flags->cpu_unbound = true;
        break;
      case 'v':
        flags->verbose = true;
        break;
      case 'w':
        flags->wait_secs = atoi(optarg);
        break;
      default:
        return -1;
    }
  }
}

enum Command {
  RECORD,
  REPLAY,
  DUMP_EVENTS
};

static int parse_args(int argc, char** argv, Flags* flags, Command* command) {
  const char* exe = argv[0];
  const char* cmd;
  int cmdi;

  flags->max_rbc = Flags::DEFAULT_MAX_RBC;
  flags->max_events = Flags::DEFAULT_MAX_EVENTS;
  flags->checksum = Flags::CHECKSUM_NONE;
  flags->dbgport = -1;
  flags->dump_at = Flags::DUMP_AT_NONE;
  flags->dump_on = Flags::DUMP_ON_NONE;
  flags->redirect = true;
  flags->use_syscall_buffer = true;
  flags->suppress_environment_warnings = false;

  if (0 > (cmdi = parse_common_args(argc, argv, flags))) {
    return -1;
  }
  if (0 == cmdi || cmdi >= argc) {
    fprintf(stderr, "%s: must specify a command\n", exe);
    return -1;
  }

  cmd = argv[cmdi];
  if (!strcmp("record", cmd)) {
    *command = RECORD;
    return parse_record_args(cmdi + 1, argc, argv, flags);
  }
  if (!strcmp("replay", cmd)) {
    *command = REPLAY;
    return parse_replay_args(cmdi + 1, argc, argv, flags);
  }
  if (!strcmp("dump", cmd)) {
    *command = DUMP_EVENTS;
    return parse_dump_args(cmdi + 1, argc, argv, flags);
  }
  if (!strcmp("help", cmd) || !strcmp("-h", cmd) || !strcmp("--help", cmd)) {
    return -1;
  }
  *command = RECORD;
  return parse_record_args(cmdi, argc, argv, flags);
}

static string find_syscall_buffer_library() {
  char* exe_path = realpath("/proc/self/exe", NULL);
  string lib_path = exe_path;
  free(exe_path);

  int end = lib_path.length();
  // Chop off the filename
  while (end > 0 && lib_path[end - 1] != '/') {
    --end;
  }
  lib_path.erase(end);
  lib_path += "../lib/" SYSCALLBUF_LIB_FILENAME;
  if (access(lib_path.c_str(), F_OK) != 0) {
    // File does not exist. Assume install put it in LD_LIBRARY_PATH.
    lib_path = SYSCALLBUF_LIB_FILENAME;
  }
  return lib_path;
}

static void init_random() {
  // Not very good, but good enough for our non-security-sensitive needs.
  srandom(time(NULL) ^ getpid());
}

int main(int argc, char* argv[]) {
  int argi; /* index of first positional argument */
  Flags* flags = &Flags::get_for_init();

  init_random();

  if (argc >= 2 && !strcmp("check-preload-lib", argv[1])) {
    // If we reach here and we were checking the preload
    // lib, then it didn't load --- its __constructor__
    // function didn't run.
    _exit(EX_CONFIG);
  }

  Command command;
  if (0 > (argi = parse_args(argc, argv, flags, &command)) || argc < argi ||
      // |rr replay| is allowed to have no arguments to replay
      // the most recently saved trace.
      (REPLAY != command && argc <= argi)) {
    print_usage();
    return 1;
  }

  assert_prerequisites(flags);
  if (!flags->suppress_environment_warnings) {
    check_performance_settings();
  }

  int wait_secs = flags->wait_secs;
  if (wait_secs > 0) {
    struct timespec ts;
    ts.tv_sec = wait_secs;
    ts.tv_nsec = 0;
    LOG(info) << "Waiting " << wait_secs << " seconds before continuing ...";
    if (nanosleep_nointr(&ts)) {
      FATAL() << "Failed to wait requested duration";
    }
    LOG(info) << "... continuing.";
  }

  if (RECORD == command) {
    LOG(info) << "Scheduler using max_events=" << flags->max_events
              << ", max_rbc=" << flags->max_rbc;

    // The syscallbuf library interposes some critical
    // external symbols like XShmQueryExtension(), so we
    // preload it whether or not syscallbuf is enabled.
    if (flags->use_syscall_buffer) {
      setenv(SYSCALLBUF_ENABLED_ENV_VAR, "1", 1);
    } else {
      LOG(info) << "Syscall buffer disabled by flag";
      unsetenv(SYSCALLBUF_ENABLED_ENV_VAR);
    }
    flags->syscall_buffer_lib_path = find_syscall_buffer_library();
  }

  const char* rr_exe = argv[0];
  argc -= argi;
  argv += argi;

  switch (command) {
    case RECORD:
      return record(rr_exe, argc, argv, environ);
    case REPLAY:
      return replay(argc, argv, environ);
    case DUMP_EVENTS:
      return dump(argc, argv, environ);
    default:
      FATAL() << "Unknown option " << command;
      return 0; // unreached
  }
}
