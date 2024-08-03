/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "RecordCommand.h"

#include <linux/capability.h>
#include <spawn.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <sysexits.h>
#include <time.h>

#include "preload/preload_interface.h"

#include "Flags.h"
#include "RecordSession.h"
#include "StringVectorToCharArray.h"
#include "WaitManager.h"
#include "WaitStatus.h"
#include "core.h"
#include "git_revision.h"
#include "kernel_metadata.h"
#include "log.h"
#include "main.h"
#include "util.h"

using namespace std;

namespace rr {

RecordCommand RecordCommand::singleton(
    "record",
    " rr record [OPTION]... <exe> [exe-args]...\n"
    "  -c, --num-cpu-ticks=<NUM>  maximum number of 'CPU ticks' (currently \n"
    "                             retired conditional branches) to allow a \n"
    "                             task to run before interrupting it\n"
    "  --disable-avx-512          Masks out the CPUID bits for AVX512\n"
    "                             This can improve trace portability\n"
    "  --disable-cpuid-features <CCC>[,<DDD>]\n"
    "                             Mask out CPUID EAX=1 feature bits\n"
    "                             <CCC>: Bitmask of bits to clear from ECX\n"
    "                             <DDD>: Bitmask of bits to clear from EDX\n"
    "  --disable-cpuid-features-ext <BBB>[,<CCC>[,<DDD>]]\n"
    "                             Mask out CPUID EAX=7,ECX=0 feature bits\n"
    "                             <BBB>: Bitmask of bits to clear from EBX\n"
    "                             <CCC>: Bitmask of bits to clear from ECX\n"
    "                             <DDD>: Bitmask of bits to clear from EDX\n"
    "  --disable-cpuid-features-xsave <AAA>\n"
    "                             Mask out CPUID EAX=0xD,ECX=1 feature bits\n"
    "                             <AAA>: Bitmask of bits to clear from EAX\n"
    "  -h, --chaos                randomize scheduling decisions to try to \n"
    "                             reproduce bugs\n"
    "  -n, --no-syscall-buffer    disable the syscall buffer preload \n"
    "                             library even if it would otherwise be used\n"
    "  --no-file-cloning          disable file cloning for mmapped files\n"
    "  --no-read-cloning          disable file-block cloning for syscallbuf\n"
    "                             reads\n"
    "  --num-cores=N              pretend to have N cores (rr will still\n"
    "                             only run on a single core). Overrides\n"
    "                             random setting from --chaos.\n"
    "  -o, --output-trace-dir<DIR> set the output trace directory.\n"
    "                             _RR_TRACE_DIR gets ignored.\n"
    "                             Directory name is given name, not the\n"
    "                             application name.\n"
    "  --save-as=<NAME>           Name of the new recording's directory. If\n"
    "                             a recording with that name already exists, normal\n"
    "                             number appending is applied."
    "  -p --print-trace-dir=<NUM> print trace directory followed by a newline\n"
    "                             to given file descriptor\n"
    "  --syscall-buffer-sig=<NUM> the signal used for communication with the\n"
    "                             syscall buffer. SIGPWR by default, unused\n"
    "                             if --no-syscall-buffer is passed\n"
    "  -s, --always-switch        Context-switch after every rr event\n"
    "                             (mainly for testing)\n"
    "  -t, --continue-through-signal=<SIG>\n"
    "                             Unhandled <SIG> signals will be ignored\n"
    "                             instead of terminating the program. The\n"
    "                             signal will still be delivered for user\n"
    "                             handlers and debugging.\n"
    "  --intel-pt                 Enable PT collection of control flow\n"
    "                             (for debugging rr)\n"
    "  -u, --cpu-unbound          allow tracees to run on any virtual CPU.\n"
    "                             Default is to bind to a random CPU.  This "
    "option\n"
    "                             can cause replay divergence: use with\n"
    "                             caution.\n"
    "  --bind-to-cpu=<NUM>        Bind to a particular CPU\n"
    "                             instead of a randomly chosen one.\n"
    "  -v, --env=NAME=VALUE       value to add to the environment of the\n"
    "                             tracee. There can be any number of these.\n"
    "  -w, --wait                 Wait for all child processes to exit, not\n"
    "                             just the initial process.\n"
    "  --nested=<value>           Control behavior when run inside an outer\n"
    "                             rr recording. Default: exit with error\n"
    "  --nested=ignore            Directly start child process so it's part\n"
    "                             of the outer recording\n"
    "  --nested=detach            Start a separate recording session.\n"
    "                             Must not share memory with the outer.\n"
    "  --nested=release           Run the child without recording it.\n"
    "                             Must not share memory with the outer.\n"
    "  --setuid-sudo              If running under sudo, pretend to be the\n"
    "                             user that ran sudo rather than root. This\n"
    "                             allows recording setuid/setcap binaries.\n"
    "  --trace-id                 Sets the trace id to the specified id.\n"
    "  --copy-preload-src         Copy preload sources to trace dir\n"
    "  --stap-sdt                 Enables the use of SystemTap statically-\n"
    "                             defined tracepoints\n"
    "  --asan                     Override heuristics and always enable ASAN\n"
    "                             compatibility.\n"
    "  --tsan                     Override heuristics and always enable TSAN\n"
    "                             compatibility.\n");

struct RecordFlags {
  vector<string> extra_env;

  /* Max counter value before the scheduler interrupts a tracee. */
  Ticks max_ticks;

  /* Whenever |ignore_sig| is pending for a tracee, decline to
   * deliver it. */
  int ignore_sig;
  /* Whenever |continue_through_sig| is delivered to a tracee, if there is no
   * user handler and the signal would terminate the program, just ignore it. */
  int continue_through_sig;

  /* Whether to use syscall buffering optimization during recording. */
  RecordSession::SyscallBuffering use_syscall_buffer;

  /* If nonzero, the desired syscall buffer size. Must be a multiple of the page
   * size.
   */
  size_t syscall_buffer_size;

  /* CPUID features to disable */
  DisableCPUIDFeatures disable_cpuid_features;

  int print_trace_dir;

  TraceOutputPath path;

  /* Whether to use file-cloning optimization during recording. */
  bool use_file_cloning;

  /* Whether to use read-cloning optimization during recording. */
  bool use_read_cloning;

  /* Whether tracee processes in record and replay are allowed
   * to run on any logical CPU. */
  BindCPU bind_cpu;

  /* True if we should context switch after every rr event */
  bool always_switch;

  /* Whether to enable chaos mode in the scheduler */
  bool chaos;

  /* Controls number of cores reported to recorded process. */
  int num_cores;

  /* True if we should wait for all processes to exit before finishing
   * recording. */
  bool wait_for_all;

  /* Start child process directly if run under nested rr recording */
  NestedBehavior nested;

  bool scarce_fds;

  bool setuid_sudo;

  unique_ptr<TraceUuid> trace_id;

  /* Copy preload sources to trace dir */
  bool copy_preload_src;

  /* The signal to use for syscallbuf desched events */
  int syscallbuf_desched_sig;

  /* True if we should load the audit library for SystemTap SDT support. */
  bool stap_sdt;

  /* True if we should unmap the vdso */
  bool unmap_vdso;

  /* True if we should always enable ASAN compatibility. */
  bool asan;

  /* True if we should always enable TSAN compatibility. */
  bool tsan;

  /* True if we should enable collection of control flow
     with PT. */
  bool intel_pt;

  RecordFlags()
      : max_ticks(Scheduler::DEFAULT_MAX_TICKS),
        ignore_sig(0),
        continue_through_sig(0),
        use_syscall_buffer(RecordSession::ENABLE_SYSCALL_BUF),
        syscall_buffer_size(0),
        print_trace_dir(-1),
        path{"", "", false, false},
        use_file_cloning(true),
        use_read_cloning(true),
        bind_cpu(BIND_CPU),
        always_switch(false),
        chaos(false),
        num_cores(0),
        wait_for_all(false),
        nested(NESTED_ERROR),
        scarce_fds(false),
        setuid_sudo(false),
        copy_preload_src(false),
        syscallbuf_desched_sig(SYSCALLBUF_DEFAULT_DESCHED_SIGNAL),
        stap_sdt(false),
        unmap_vdso(false),
        asan(false),
        tsan(false),
        intel_pt(false) {}
};

static void parse_signal_name(ParsedOption& opt) {
  if (opt.int_value != INT64_MIN) {
    return;
  }

  for (int i = 1; i < _NSIG; i++) {
    std::string signame = signal_name(i);
    if (signame == opt.value) {
      opt.int_value = i;
      return;
    }
    DEBUG_ASSERT(signame[0] == 'S' && signame[1] == 'I' && signame[2] == 'G');
    if (signame.substr(3) == opt.value) {
      opt.int_value = i;
      return;
    }
  }
}

static vector<uint32_t> parse_feature_bits(ParsedOption& opt) {
  vector<uint32_t> ret;
  const char* p = opt.value.c_str();
  while (*p) {
    char* endptr;
    unsigned long long v = strtoull(p, &endptr, 0);
    if (v > UINT32_MAX || (*endptr && *endptr != ',')) {
      return vector<uint32_t>();
    }
    ret.push_back(v);
    p = *endptr == ',' ? endptr + 1 : endptr;
  }
  return ret;
}

static bool parse_record_arg(vector<string>& args, RecordFlags& flags) {
  if (parse_global_option(args)) {
    return true;
  }

  static const OptionSpec options[] = {
    { 0, "no-read-cloning", NO_PARAMETER },
    { 1, "no-file-cloning", NO_PARAMETER },
    { 2, "syscall-buffer-size", HAS_PARAMETER },
    { 3, "nested", HAS_PARAMETER },
    { 4, "scarce-fds", NO_PARAMETER },
    { 5, "setuid-sudo", NO_PARAMETER },
    { 6, "bind-to-cpu", HAS_PARAMETER },
    { 7, "disable-cpuid-features", HAS_PARAMETER },
    { 8, "disable-cpuid-features-ext", HAS_PARAMETER },
    { 9, "disable-cpuid-features-xsave", HAS_PARAMETER },
    { 10, "num-cores", HAS_PARAMETER },
    { 11, "trace-id", HAS_PARAMETER },
    { 12, "copy-preload-src", NO_PARAMETER },
    { 13, "syscall-buffer-sig", HAS_PARAMETER },
    { 14, "stap-sdt", NO_PARAMETER },
    { 15, "unmap-vdso", NO_PARAMETER },
    { 16, "disable-avx-512", NO_PARAMETER },
    { 17, "asan", NO_PARAMETER },
    { 18, "tsan", NO_PARAMETER },
    { 19, "intel-pt", NO_PARAMETER },
    { 20, "save-as", HAS_PARAMETER },
    { 'c', "num-cpu-ticks", HAS_PARAMETER },
    { 'h', "chaos", NO_PARAMETER },
    { 'i', "ignore-signal", HAS_PARAMETER },
    { 'n', "no-syscall-buffer", NO_PARAMETER },
    { 'p', "print-trace-dir", HAS_PARAMETER },
    { 'o', "output-trace-dir", HAS_PARAMETER },
    { 's', "always-switch", NO_PARAMETER },
    { 't', "continue-through-signal", HAS_PARAMETER },
    { 'u', "cpu-unbound", NO_PARAMETER },
    { 'v', "env", HAS_PARAMETER },
    { 'w', "wait", NO_PARAMETER }};

  ParsedOption opt;
  auto args_copy = args;
  if (!Command::parse_option(args_copy, options, &opt)) {
    return false;
  }

  switch (opt.short_name) {
    case 'c':
      if (!opt.verify_valid_int(1, Scheduler::MAX_MAX_TICKS)) {
        return false;
      }
      flags.max_ticks = opt.int_value;
      break;
    case 'h':
      LOG(info) << "Enabled chaos mode";
      flags.chaos = true;
      break;
    case 'i':
      parse_signal_name(opt);
      if (!opt.verify_valid_int(1, _NSIG - 1)) {
        return false;
      }
      flags.ignore_sig = opt.int_value;
      break;
    case 'n':
      flags.use_syscall_buffer = RecordSession::DISABLE_SYSCALL_BUF;
      break;
    case 'p':
      if (!opt.verify_valid_int(0, INT32_MAX)) {
        return false;
      }
      flags.print_trace_dir = opt.int_value;
      break;
    case 'o':
      flags.path.output_trace_dir = opt.value;
      flags.path.usr_provided_outdir = true;
      break;
    case 0:
      flags.use_read_cloning = false;
      break;
    case 1:
      flags.use_file_cloning = false;
      break;
    case 2:
      if (!opt.verify_valid_int(4, 1024 * 1024)) {
        return false;
      }
      flags.syscall_buffer_size = ceil_page_size(opt.int_value * 1024);
      break;
    case 3:
      if (opt.value == "default" || opt.value == "error") {
        flags.nested = NESTED_ERROR;
      } else if (opt.value == "ignore") {
        flags.nested = NESTED_IGNORE;
      } else if (opt.value == "detach") {
        flags.nested = NESTED_DETACH;
      } else if (opt.value == "release") {
        flags.nested = NESTED_RELEASE;
      } else {
        LOG(warn) << "Unknown nesting behavior `" << opt.value << "`";
        flags.nested = NESTED_ERROR;
      }
      break;
    case 4:
      flags.scarce_fds = true;
      break;
    case 5:
      flags.setuid_sudo = true;
      break;
    case 6:
      if (!opt.verify_valid_int(0, INT32_MAX)) {
        return false;
      }
      flags.bind_cpu = BindCPU(opt.int_value);
      break;
    case 7: {
      vector<uint32_t> bits = parse_feature_bits(opt);
      if (bits.empty() || bits.size() > 2) {
        return false;
      }
      flags.disable_cpuid_features.features_ecx = bits[0];
      if (bits.size() > 1) {
        flags.disable_cpuid_features.features_edx = bits[1];
      }
      break;
    }
    case 8: {
      vector<uint32_t> bits = parse_feature_bits(opt);
      if (bits.empty() || bits.size() > 3) {
        return false;
      }
      flags.disable_cpuid_features.extended_features_ebx = bits[0];
      if (bits.size() > 1) {
        flags.disable_cpuid_features.extended_features_ecx = bits[1];
        if (bits.size() > 2) {
          flags.disable_cpuid_features.extended_features_edx = bits[2];
        }
      }
      break;
    }
    case 9: {
      vector<uint32_t> bits = parse_feature_bits(opt);
      if (bits.size() != 1) {
        return false;
      }
      flags.disable_cpuid_features.xsave_features_eax = bits[0];
      break;
    }
    case 10: {
      if (!opt.verify_valid_int(1, 128)) {
        return false;
      }
      flags.num_cores = opt.int_value;
      break;
    }
    case 11: {
      const uint8_t SUM_GROUP_LENS[5] = { 8, 12, 16, 20, 32 };
      /* Parse UUIDs from string form optionally with hyphens */
      uint8_t digit = 0; // This counts only hex digits (i.e. not hyphens)
      uint8_t group = 0;
      uint8_t acc = 0;
      unique_ptr<TraceUuid> buf(new TraceUuid);
      auto it = opt.value.begin();
      while (it < opt.value.end()) {
        auto c = *it;

        if (digit > SUM_GROUP_LENS[4]) {
          return false;
        }

        if (digit % 2 == 0) {
          // First digit of the byte.
          if ('0' <= c && c <= '9') {
            acc = c - '0';
          } else if ('a' <= c && c <= 'f') {
            acc = c - 'a' + 10;
          } else if ('A' <= c && c <= 'F') {
            acc = c - 'A' + 10;
          } else if (c == '-') {
            // Group delimiter.
            if (SUM_GROUP_LENS[group] != digit) {
              return false;
            }
            ++group;
            ++it;
            continue;
          } else {
            return false;
          }
        } else {
          // Second digit of the byte.
          acc <<= 4;
          if ('0' <= c && c <= '9') {
            acc += c - '0';
          } else if ('a' <= c && c <= 'f') {
            acc += c - 'a' + 10;
          } else if ('A' <= c && c <= 'F') {
            acc += c - 'A' + 10;
          } else {
            return false;
          }

          buf->bytes[digit / 2] = acc;
        }

        ++digit;
        ++it;
      }

      if (SUM_GROUP_LENS[4] != digit) {
        return false;
      }

      flags.trace_id.swap(buf);
      break;
    }
    case 12:
      flags.copy_preload_src = true;
      break;
    case 13:
      parse_signal_name(opt);
      if (!opt.verify_valid_int(1, _NSIG - 1)) {
        return false;
      }
      flags.syscallbuf_desched_sig = opt.int_value;
      break;
    case 14:
      flags.stap_sdt = true;
      break;
    case 15:
      flags.unmap_vdso = true;
      break;
    case 16:
      flags.disable_cpuid_features.extended_features_ebx |= 0xdc230000;
      flags.disable_cpuid_features.extended_features_ecx |= 0x00002c42;
      flags.disable_cpuid_features.extended_features_edx |= 0x0000000c;
      break;
    case 17:
      flags.asan = true;
      break;
    case 18:
      flags.tsan = true;
      break;
    case 19:
      flags.intel_pt = true;
      break;
    case 20:
      flags.path.name = opt.value;
      flags.path.usr_provided_name = true;
      break;
    case 's':
      flags.always_switch = true;
      break;
    case 't':
      parse_signal_name(opt);
      if (!opt.verify_valid_int(1, _NSIG - 1)) {
        return false;
      }
      flags.continue_through_sig = opt.int_value;
      break;
    case 'u':
      flags.bind_cpu = UNBOUND_CPU;
      break;
    case 'v':
      flags.extra_env.push_back(opt.value);
      break;
    case 'w':
      flags.wait_for_all = true;
      break;
    default:
      DEBUG_ASSERT(0 && "Unknown option");
  }

  args = args_copy;
  return true;
}

static volatile double term_requested;
static bool did_print_reassurance = false;

static const double TRACEE_SIGTERM_RESPONSE_MAX_TIME = 5;
static const double RR_SIGKILL_GRACE_TIME = 5;

/**
 * A terminating signal was received.
 *
 * First we forward it to the tracee. Then if the tracee is still
 * running after TRACEE_SIGTERM_RESPONSE_MAX_TIME, we kill it with SIGKILL.
 * If a term request remains pending for more than one second,
 * then assume rr is wedged and abort().
 *
 * Note that this is called in a signal handler and could also
 * be called off the main thread.
 */
static void handle_SIGTERM(__attribute__((unused)) int sig) {
  // Don't use LOG() here because we're in a signal handler. If we do anything
  // that could allocate, we could deadlock.
  if (term_requested > 0) {
    double now = monotonic_now_sec();
    if (now - term_requested > 1 + TRACEE_SIGTERM_RESPONSE_MAX_TIME) {
      if (!did_print_reassurance) {
        static const char msg[] =
          "[rr] Tracee failed to exit within 1s after SIGKILL. Recording will forcibly terminate in 4s.\n";
        did_print_reassurance = true;
        write_all(STDERR_FILENO, msg, sizeof(msg) - 1);
      } else if (now - term_requested > RR_SIGKILL_GRACE_TIME + TRACEE_SIGTERM_RESPONSE_MAX_TIME) {
        errno = 0;
        FATAL() << "SIGTERM grace period expired";
      }
    }
  } else {
    term_requested = monotonic_now_sec();
  }
}

/**
 * Something segfaulted - this is probably a bug in rr. Try to at least
 * give a stacktrace.
 */
static void handle_SIGSEGV(__attribute__((unused)) int sig) {
  errno = 0;
  FATAL() << "rr itself crashed (SIGSEGV). This shouldn't happen!";
}

static void install_signal_handlers(void) {
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = handle_SIGTERM;
  sigaction(SIGTERM, &sa, nullptr);

  sa.sa_handler = handle_SIGSEGV;
  sigaction(SIGSEGV, &sa, nullptr);

  sa.sa_handler = SIG_IGN;
  sigaction(SIGHUP, &sa, nullptr);
  sigaction(SIGINT, &sa, nullptr);
  sigaction(SIGABRT, &sa, nullptr);
  sigaction(SIGQUIT, &sa, nullptr);
  sigaction(SIGTRAP, &sa, nullptr);
}

static void setup_session_from_flags(RecordSession& session,
                                     const RecordFlags& flags) {
  session.scheduler().set_max_ticks(flags.max_ticks);
  session.scheduler().set_always_switch(flags.always_switch);
  session.set_enable_chaos(flags.chaos);
  if (flags.num_cores) {
    // Set the number of cores reported, possibly overriding the chaos mode
    // setting.
    session.set_num_cores(flags.num_cores);
  }
  session.set_use_read_cloning(flags.use_read_cloning);
  session.set_use_file_cloning(flags.use_file_cloning);
  session.set_ignore_sig(flags.ignore_sig);
  session.set_continue_through_sig(flags.continue_through_sig);
  session.set_wait_for_all(flags.wait_for_all);
  if (flags.syscall_buffer_size > 0) {
    session.set_syscall_buffer_size(flags.syscall_buffer_size);
  }

  if (flags.scarce_fds) {
    for (int i = 0; i < 950; ++i) {
      open("/dev/null", O_RDONLY);
    }
  }
}

static RecordSession* static_session;

// This can be called during debugging to close the trace so it can be used
// later.
void force_close_record_session() {
  if (static_session) {
    static_session->close_trace_writer(TraceWriter::CLOSE_ERROR);
  }
}

static void copy_preload_sources_to_trace(const string& trace_dir) {
  string files_dir = trace_dir + "/files.rr";
  mkdir(files_dir.c_str(), 0700);
  pid_t pid;
  string dest_path = files_dir + "/librrpreload.zip";
  string src_path = resource_path() + "share/rr/src";
  char zip[] = "zip";
  char r[] = "-r";
  char j[] = "-j";
  char* argv[] = {
    zip, r, j,
    const_cast<char*>(dest_path.c_str()),
    const_cast<char*>(src_path.c_str()),
    NULL
  };
  posix_spawn_file_actions_t actions;
  posix_spawn_file_actions_init(&actions);
  posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO, "/dev/null", O_RDONLY, 0);
  posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_RDONLY, 0);
  int ret = posix_spawnp(&pid, argv[0], &actions, NULL, argv, environ);
  if (ret) {
    FATAL() << "Can't spawn 'zip'";
  }
  posix_spawn_file_actions_destroy(&actions);
  WaitResult result = WaitManager::wait_exit(WaitOptions(pid));
  if (result.code != WAIT_OK) {
    FATAL() << "Wait failed";
  }
  LOG(info) << "Got zip status " << result.status;
}

static void save_rr_git_revision(const string& trace_dir) {
  string files_dir = trace_dir + "/files.rr";
  mkdir(files_dir.c_str(), 0700);
  string dest_path = files_dir + "/rr_git_revision";
  ScopedFd fd(dest_path.c_str(), O_CREAT | O_WRONLY, 0600);
  ssize_t written = write(fd, GIT_REVISION, sizeof(GIT_REVISION) - 1);
  if (written != sizeof(GIT_REVISION) - 1) {
    FATAL() << "Can't write GIT_REVISION";
  }
}

static void* repeat_SIGTERM(__attribute__((unused)) void* p) {
  sleep_time(TRACEE_SIGTERM_RESPONSE_MAX_TIME);
  /* send another SIGTERM so we wake up and SIGKILL our tracees */
  kill(getpid(), SIGTERM);
  sleep_time(RR_SIGKILL_GRACE_TIME);
  /* Ok, now we're really wedged, just repeatedly SIGTERM until we're out */
  while (1) {
    kill(getpid(), SIGTERM);
    sleep_time(0.01);
  }
}

static WaitStatus record(const vector<string>& args, const RecordFlags& flags) {
  LOG(info) << "Start recording...";
  DEBUG_ASSERT(!flags.path.name.empty() && !flags.path.output_trace_dir.empty() && "No output dir or trace dir name set");
  auto session = RecordSession::create(
      args, flags.extra_env, flags.disable_cpuid_features, flags.path,
      flags.use_syscall_buffer, flags.syscallbuf_desched_sig,
      flags.bind_cpu,
      flags.trace_id.get(),
      flags.stap_sdt, flags.unmap_vdso, flags.asan, flags.tsan,
      flags.intel_pt);
  setup_session_from_flags(*session, flags);

  static_session = session.get();

  if (flags.print_trace_dir >= 0) {
    const string& dir = session->trace_writer().dir();
    write_all(flags.print_trace_dir, dir.c_str(), dir.size());
    write_all(flags.print_trace_dir, "\n", 1);
  }

  if (flags.copy_preload_src) {
    const string& dir = session->trace_writer().dir();
    copy_preload_sources_to_trace(dir);
    save_rr_git_revision(dir);
  }

  // Install signal handlers after creating the session, to ensure they're not
  // inherited by the tracee.
  install_signal_handlers();

  RecordSession::RecordResult step_result;
  bool did_forward_SIGTERM = false;
  bool did_term_detached_tasks = false;
  pthread_t term_repeater_thread;
  do {
    bool done_initial_exec = session->done_initial_exec();
    step_result = session->record_step();
    // Only create latest-trace symlink if --output-trace-dir is not being used
    if (!done_initial_exec && session->done_initial_exec() && !flags.path.usr_provided_outdir) {
      session->trace_writer().make_latest_trace();
    }
    if (term_requested) {
      if (monotonic_now_sec() - term_requested > TRACEE_SIGTERM_RESPONSE_MAX_TIME) {
        /* time ran out for the tracee to respond to SIGTERM; kill everything */
        session->terminate_tracees();
      } else if (!did_forward_SIGTERM) {
        session->forward_SIGTERM();
        // Start a thread to send a SIGTERM to ourselves (again)
        // in case the tracee doesn't respond to SIGTERM.
        pthread_create(&term_repeater_thread, NULL, repeat_SIGTERM, NULL);
        did_forward_SIGTERM = true;
      }
      /* Forward SIGTERM to detached tasks immediately */
      if (!did_term_detached_tasks) {
        session->term_detached_tasks();
        did_term_detached_tasks = true;
      }
    }
  } while (step_result.status == RecordSession::STEP_CONTINUE);

  session->close_trace_writer(TraceWriter::CLOSE_OK);
  static_session = nullptr;

  switch (step_result.status) {
    case RecordSession::STEP_CONTINUE:
      // SIGTERM interrupted us.
      return WaitStatus::for_fatal_sig(SIGTERM);

    case RecordSession::STEP_EXITED:
      return step_result.exit_status;

    case RecordSession::STEP_SPAWN_FAILED:
      cerr << "\n" << step_result.failure_message << "\n";
      return WaitStatus::for_exit_code(EX_UNAVAILABLE);

    default:
      DEBUG_ASSERT(0 && "Unknown exit status");
      return WaitStatus();
  }
}

static void exec_child(vector<string>& args) {
  execvp(args[0].c_str(), StringVectorToCharArray(args).get());
  // That failed. Try executing the file directly.
  execv(args[0].c_str(), StringVectorToCharArray(args).get());
  switch (errno) {
    case ENOENT:
      fprintf(stderr, "execv failed: '%s' (or interpreter) not found (%s)",
              args[0].c_str(), errno_name(errno).c_str());
      break;
    default:
      fprintf(stderr, "execv of '%s' failed (%s)", args[0].c_str(),
              errno_name(errno).c_str());
      break;
  }
  _exit(1);
  // Never returns!
}

static void reset_uid_sudo() {
  // Let's change our uids now. We do keep capabilities though, since that's
  // the point of the exercise. The first exec will reset both the keepcaps,
  // and the capabilities in the child
  std::string sudo_uid = getenv("SUDO_UID");
  std::string sudo_gid = getenv("SUDO_GID");
  DEBUG_ASSERT(!sudo_uid.empty() && !sudo_gid.empty());
  uid_t tracee_uid = stoi(sudo_uid);
  gid_t tracee_gid = stoi(sudo_gid);
  // Setuid will drop effective capabilities. Save them now and set them
  // back after
  struct NativeArch::cap_header header = {.version =
                                              _LINUX_CAPABILITY_VERSION_3,
                                          .pid = 0 };
  struct NativeArch::cap_data data[2];
  if (syscall(NativeArch::capget, &header, data) != 0) {
    FATAL() << "FAILED to read capabilities";
  }
  if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0)) {
    FATAL() << "FAILED to set keepcaps";
  }
  if (setgid(tracee_gid) != 0) {
    FATAL() << "FAILED to setgid to sudo group";
  }
  if (setuid(tracee_uid) != 0) {
    FATAL() << "FAILED to setuid to sudo user";
  }
  if (syscall(NativeArch::capset, &header, data) != 0) {
    FATAL() << "FAILED to set capabilities";
  }
  // Just make sure the ambient set is cleared, to avoid polluting the tracee
  prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0);
}

int RecordCommand::run(vector<string>& args) {
  RecordFlags flags;
  while (parse_record_arg(args, flags)) {
  }

  if (running_under_rr()) {
    switch (flags.nested) {
      case NESTED_IGNORE:
        exec_child(args);
        return 1;
      case NESTED_DETACH:
      case NESTED_RELEASE: {
        int ret = syscall(SYS_rrcall_detach_teleport, (uintptr_t)0, (uintptr_t)0,
          (uintptr_t)0, (uintptr_t)0, (uintptr_t)0, (uintptr_t)0);
        if (ret < 0) {
          FATAL() << "Failed to detach from parent rr";
        }
        if (running_under_rr(false)) {
          FATAL() << "Detaching from parent rr did not work";
        }
        if (flags.nested == NESTED_RELEASE) {
          exec_child(args);
          return 1;
        }
        // running_under_rr() changed - respect the log specification from RR_LOG
        // just as if we hadn't been running under rr.
        apply_log_spec_from_env();
        break;
      }
      default:
        fprintf(stderr, "rr: cannot run rr recording under rr. Exiting.\n"
                        "Use `rr record --nested=ignore` to start the child "
                        "process directly.\n");
        return 1;
    }
  }

  if (!verify_not_option(args) || args.size() == 0) {
    print_help(stderr);
    return 1;
  }

  assert_prerequisites(flags.use_syscall_buffer);

  if (flags.setuid_sudo) {
    if (geteuid() != 0 || getenv("SUDO_UID") == NULL) {
      fprintf(stderr, "rr: --setuid-sudo option may only be used under sudo.\n"
                      "Re-run as `sudo -EP --preserve-env=HOME rr record --setuid-sudo` to"
                      "record privileged executables.\n");
      return 1;
    }

    reset_uid_sudo();
  }

  if (flags.chaos) {
    // Add up to one page worth of random padding to the environment to induce
    // a variety of possible stack pointer offsets
    vector<char> chars;
    chars.resize(random() % page_size());
    memset(chars.data(), '0', chars.size());
    chars.push_back(0);
    string padding = string("RR_CHAOS_PADDING=") + chars.data();
    flags.extra_env.push_back(padding);
  }

  if(flags.path.name.empty()) {
    flags.path.name = args[0];
    flags.path.usr_provided_name = false;
  }

  if(flags.path.output_trace_dir.empty()) {
    flags.path.usr_provided_outdir = false;
    flags.path.output_trace_dir = trace_save_dir();
  }

  WaitStatus status = record(args, flags);

  // Everything should have been cleaned up by now.
  check_for_leaks();

  switch (status.type()) {
    case WaitStatus::EXIT:
      return status.exit_code();
    case WaitStatus::FATAL_SIGNAL:
      signal(status.fatal_sig(), SIG_DFL);
      prctl(PR_SET_DUMPABLE, 0);
      kill(getpid(), status.fatal_sig());
      break;
    default:
      FATAL() << "Don't know why we exited: " << status;
      break;
  }
  return 1;
}

} // namespace rr
