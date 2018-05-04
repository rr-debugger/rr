/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "RecordCommand.h"

#include <linux/capability.h>
#include <sys/prctl.h>
#include <sysexits.h>

#include "preload/preload_interface.h"

#include "Flags.h"
#include "RecordSession.h"
#include "StringVectorToCharArray.h"
#include "WaitStatus.h"
#include "core.h"
#include "kernel_metadata.h"
#include "log.h"
#include "main.h"
#include "util.h"

using namespace std;

namespace rr {

RecordCommand RecordCommand::singleton(
    "record",
    " rr record [OPTION]... <exe> [exe-args]...\n"
    "  -b, --force-syscall-buffer force the syscall buffer preload library\n"
    "                             to be used, even if that's probably a bad\n"
    "                             idea\n"
    "  -c, --num-cpu-ticks=<NUM>  maximum number of 'CPU ticks' (currently \n"
    "                             retired conditional branches) to allow a \n"
    "                             task to run before interrupting it\n"
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
    "  -i, --ignore-signal=<SIG>  block <SIG> from being delivered to \n"
    "                             tracees. Probably only useful for unit \n"
    "                             tests.\n"
    "  -n, --no-syscall-buffer    disable the syscall buffer preload \n"
    "                             library even if it would otherwise be used\n"
    "  --no-file-cloning          disable file cloning for mmapped files\n"
    "  --no-read-cloning          disable file-block cloning for syscallbuf\n"
    "                             reads\n"
    "  -p --print-trace-dir=<NUM> print trace directory followed by a newline\n"
    "                             to given file descriptor\n"
    "  --syscall-buffer-size=<NUM> desired size of syscall buffer in kB.\n"
    "                             Mainly for tests\n"
    "  -s, --always-switch        try to context switch at every rr event\n"
    "  -t, --continue-through-signal=<SIG>\n"
    "                             Unhandled <SIG> signals will be ignored\n"
    "                             instead of terminating the program. The\n"
    "                             signal will still be delivered for user\n"
    "                             handlers and debugging.\n"
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
    "  --ignore-nested            Directly start child process when running\n"
    "                             under nested rr recording, instead of\n"
    "                             raising an error.\n"
    "  --scarce-fds               Consume 950 fds before recording\n"
    "                             (for testing purposes)\n"
    "  --setuid-sudo              If running under sudo, pretend to be the\n"
    "                             user that ran sudo rather than root. This\n"
    "                             allows recording setuid/setcap binaries.\n");

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

  /* True if we should wait for all processes to exit before finishing
   * recording. */
  bool wait_for_all;

  /* Start child process directly if run under nested rr recording */
  bool ignore_nested;

  bool scarce_fds;

  bool setuid_sudo;

  RecordFlags()
      : max_ticks(Scheduler::DEFAULT_MAX_TICKS),
        ignore_sig(0),
        continue_through_sig(0),
        use_syscall_buffer(RecordSession::ENABLE_SYSCALL_BUF),
        syscall_buffer_size(0),
        print_trace_dir(-1),
        use_file_cloning(true),
        use_read_cloning(true),
        bind_cpu(BIND_CPU),
        always_switch(false),
        chaos(false),
        wait_for_all(false),
        ignore_nested(false),
        scarce_fds(false),
        setuid_sudo(false) {}
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
    { 3, "ignore-nested", NO_PARAMETER },
    { 4, "scarce-fds", NO_PARAMETER },
    { 5, "setuid-sudo", NO_PARAMETER },
    { 6, "bind-to-cpu", HAS_PARAMETER },
    { 7, "disable-cpuid-features", HAS_PARAMETER },
    { 8, "disable-cpuid-features-ext", HAS_PARAMETER },
    { 9, "disable-cpuid-features-xsave", HAS_PARAMETER },
    { 'b', "force-syscall-buffer", NO_PARAMETER },
    { 'c', "num-cpu-ticks", HAS_PARAMETER },
    { 'h', "chaos", NO_PARAMETER },
    { 'i', "ignore-signal", HAS_PARAMETER },
    { 'n', "no-syscall-buffer", NO_PARAMETER },
    { 'p', "print-trace-dir", HAS_PARAMETER },
    { 's', "always-switch", NO_PARAMETER },
    { 't', "continue-through-signal", HAS_PARAMETER },
    { 'u', "cpu-unbound", NO_PARAMETER },
    { 'v', "env", HAS_PARAMETER },
    { 'w', "wait", NO_PARAMETER }
  };
  ParsedOption opt;
  auto args_copy = args;
  if (!Command::parse_option(args_copy, options, &opt)) {
    return false;
  }

  switch (opt.short_name) {
    case 'b':
      flags.use_syscall_buffer = RecordSession::ENABLE_SYSCALL_BUF;
      break;
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
    case 0:
      flags.use_read_cloning = false;
      break;
    case 1:
      flags.use_file_cloning = false;
      break;
    case 2:
      if (!opt.verify_valid_int(4, 1024 * 1024) ||
          (opt.int_value & (page_size() / 1024 - 1))) {
        return false;
      }
      flags.syscall_buffer_size = opt.int_value * 1024;
      break;
    case 3:
      flags.ignore_nested = true;
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

static volatile bool term_request;

/**
 * A terminating signal was received.  Set the |term_request| bit to
 * terminate the trace at the next convenient point.
 *
 * If there's already a term request pending, then assume rr is wedged
 * and abort().
 *
 * Note that this is not only called in a signal handler but it could
 * be called off the main thread.
 */
static void handle_SIGTERM(__attribute__((unused)) int sig) {
  // Don't use LOG() here because we're in a signal handler. If we do anything
  // that could allocate, we could deadlock.
  if (term_request) {
    static const char msg[] =
        "Received SIGTERM while an earlier one was pending.  We're "
        "probably wedged.\n";
    write_all(STDERR_FILENO, msg, sizeof(msg) - 1);
    notifying_abort();
  }
  term_request = true;
}

static void install_signal_handlers(void) {
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = handle_SIGTERM;
  sigaction(SIGTERM, &sa, nullptr);

  sa.sa_handler = SIG_IGN;
  sigaction(SIGINT, &sa, nullptr);
}

static void setup_session_from_flags(RecordSession& session,
                                     const RecordFlags& flags) {
  session.scheduler().set_max_ticks(flags.max_ticks);
  session.scheduler().set_always_switch(flags.always_switch);
  session.set_enable_chaos(flags.chaos);
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
    static_session->terminate_recording();
  }
}

static WaitStatus record(const vector<string>& args, const RecordFlags& flags) {
  LOG(info) << "Start recording...";

  auto session = RecordSession::create(
      args, flags.extra_env, flags.disable_cpuid_features,
      flags.use_syscall_buffer, flags.bind_cpu);
  setup_session_from_flags(*session, flags);

  static_session = session.get();

  if (flags.print_trace_dir >= 0) {
    const string& dir = session->trace_writer().dir();
    write_all(flags.print_trace_dir, dir.c_str(), dir.size());
    write_all(flags.print_trace_dir, "\n", 1);
  }

  // Install signal handlers after creating the session, to ensure they're not
  // inherited by the tracee.
  install_signal_handlers();

  RecordSession::RecordResult step_result;
  do {
    bool done_initial_exec = session->done_initial_exec();
    step_result = session->record_step();
    if (!done_initial_exec && session->done_initial_exec()) {
      session->trace_writer().make_latest_trace();
    }
  } while (step_result.status == RecordSession::STEP_CONTINUE && !term_request);

  session->terminate_recording();
  static_session = nullptr;

  switch (step_result.status) {
    case RecordSession::STEP_CONTINUE:
      // SIGINT or something like that interrupted us.
      return WaitStatus::for_fatal_sig(SIGINT);

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
    if (flags.ignore_nested) {
      exec_child(args);
    }
    fprintf(stderr, "rr: cannot run rr recording under rr. Exiting.\n"
                    "Use `rr record --ignore-nested` to start the child "
                    "process directly.\n");
    return 1;
  }

  if (!verify_not_option(args) || args.size() == 0) {
    print_help(stderr);
    return 1;
  }

  assert_prerequisites(flags.use_syscall_buffer);

  if (flags.setuid_sudo) {
    if (geteuid() != 0 || getenv("SUDO_UID") == NULL) {
      fprintf(stderr, "rr: --setuid-sudo option may only be used under sudo.\n"
                      "Re-run as `sudo -EP rr record --setuid-sudo` to"
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
