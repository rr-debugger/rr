/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "main.h"

#include <limits.h>
#include <linux/version.h>
#include <stdio.h>
#include <string.h>
#include <sys/utsname.h>

#include <sstream>

#include "Command.h"
#include "Flags.h"
#include "RecordCommand.h"
#include "log.h"

using namespace std;

namespace rr {

// Show version and quit.
static bool show_version = false;

void assert_prerequisites(bool use_syscall_buffer) {
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

    if (use_syscall_buffer &&
        KERNEL_VERSION(major, minor, 0) < KERNEL_VERSION(3, 5, 0)) {
      FATAL() << "Your kernel does not support syscall "
              << "filtering; please use the -n option";
    }
  }
}

void check_performance_settings() {
  if (Flags::get().suppress_environment_warnings) {
    return;
  }

  // NB: we hard-code "cpu0" here because rr pins itself and all
  // tracees to cpu 0.  We don't care about the other CPUs.
  ScopedFd fd("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor",
              O_RDONLY);
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
            "    $ sudo dnf install kernel-tools\n"
            "    $ sudo cpupower frequency-set -g performance\n"
            "\n",
            governor);
    // TODO: It would be nice to bail here or do something
    // clever to enable the 'performance' just for rr, but
    // that seems too hard at the moment.
  }
}

void print_version(FILE* out) { fprintf(out, "rr version %s\n", RR_VERSION); }

void print_usage(FILE* out) {
  print_version(out);
  fputs("Usage:\n", out);
  Command::print_help_all(out);
  fputs(
      "\n"
      "Common options:\n"
      "  -A, --microarch=<NAME>     force rr to assume it's running on a CPU\n"
      "                             with microarch NAME even if runtime "
      "detection\n"
      "                             says otherwise.  NAME should be a string "
      "like\n"
      "                             'Ivy Bridge'. Note that rr will not work "
      "with\n"
      "                             Intel Merom or Penryn microarchitectures.\n"
      "  -C, --checksum={on-syscalls,on-all-events}|FROM_TIME\n"
      "                             compute and store (during recording) or\n"
      "                             read and verify (during replay) checksums\n"
      "                             of each of a tracee's memory mappings "
      "either\n"
      "                             at the end of all syscalls "
      "(`on-syscalls'),\n"
      "                             at all events (`on-all-events'), or \n"
      "                             starting from a global timepoint "
      "FROM_TIME\n"
      "  -D, --dump-on=<SYSCALL_NUM|-SIGNAL_NUM>\n"
      "                             dump memory at SYSCALL or SIGNAL to the\n"
      "                             file "
      "`[trace_dir]/[tid].[time]_{rec,rep}':\n"
      "                             `_rec' for dumps during recording, `_rep'\n"
      "                             for dumps during replay\n"
      "  -F, --force-things         force rr to do some things that don't "
      "seem\n"
      "                             like good ideas, for example launching an\n"
      "                             interactive emergency debugger if stderr\n"
      "                             isn't a tty.\n"
      "  -K, --check-cached-mmaps   verify that cached task mmaps match "
      "/proc/maps\n"
      "  -E, --fatal-errors         any warning or error that is printed is\n"
      "                             treated as fatal\n"
      "  -M, --mark-stdio           mark stdio writes with [rr <PID> <EV>]\n"
      "                             where EV is the global trace time at\n"
      "                             which the write occurs and PID is the pid\n"
      "                             of the process it occurs in.\n"
      "  -N, --version              print the version number and exit\n"
      "  -S, --suppress-environment-warnings\n"
      "                             suppress warnings about issues in the\n"
      "                             environment that rr has no control over\n"
      "  -T, --dump-at=TIME         dump memory at global timepoint TIME\n"
      "  -V, --verbose              log messages that may not be urgently \n"
      "                             critical to the user\n"
      "  -W, --wait-secs=<NUM_SECS> wait NUM_SECS seconds just after startup,\n"
      "                             before initiating recording or replaying\n"
      "\n"
      "Use RR_LOG to control logging; e.g. RR_LOG=all:warn,Task:debug\n",
      out);
}

static void init_random() {
  // Not very good, but good enough for our non-security-sensitive needs.
  int key = time(nullptr) ^ getpid();
  srandom(key);
  srand(key);
}

bool parse_global_option(std::vector<std::string>& args) {
  static const OptionSpec options[] = {
    { 'C', "checksum", HAS_PARAMETER },
    { 'K', "check-cached-mmaps", NO_PARAMETER },
    { 'U', "cpu-unbound", NO_PARAMETER },
    { 'T', "dump-at", HAS_PARAMETER },
    { 'D', "dump-on", HAS_PARAMETER },
    { 'F', "force-things", NO_PARAMETER },
    { 'A', "microarch", HAS_PARAMETER },
    { 'M', "mark-stdio", NO_PARAMETER },
    { 'S', "suppress-environment-warnings", NO_PARAMETER },
    { 'E', "fatal-errors", NO_PARAMETER },
    { 'V', "verbose", NO_PARAMETER },
    { 'N', "version", NO_PARAMETER }
  };

  ParsedOption opt;
  if (!Command::parse_option(args, options, &opt)) {
    return false;
  }

  Flags& flags = Flags::get_for_init();
  switch (opt.short_name) {
    case 'A':
      flags.forced_uarch = opt.value;
      break;
    case 'C':
      if (opt.value == "on-syscalls") {
        LOG(info) << "checksumming on syscall exit";
        flags.checksum = Flags::CHECKSUM_SYSCALL;
      } else if (opt.value == "on-all-events") {
        LOG(info) << "checksumming on all events";
        flags.checksum = Flags::CHECKSUM_ALL;
      } else {
        flags.checksum = atoi(opt.value.c_str());
        LOG(info) << "checksumming on at event " << flags.checksum;
      }
      break;
    case 'D':
      if (opt.value == "RDTSC") {
        flags.dump_on = Flags::DUMP_ON_RDTSC;
      } else {
        flags.dump_on = atoi(opt.value.c_str());
      }
      break;
    case 'E':
      flags.fatal_errors_and_warnings = true;
      break;
    case 'F':
      flags.force_things = true;
      break;
    case 'K':
      flags.check_cached_mmaps = true;
      break;
    case 'M':
      flags.mark_stdio = true;
      break;
    case 'S':
      flags.suppress_environment_warnings = true;
      break;
    case 'T':
      flags.dump_at = atoi(opt.value.c_str());
      break;
    case 'N':
      show_version = true;
      break;
    default:
      assert(0 && "Invalid flag");
  }
  return true;
}

} // namespace rr

using namespace rr;

int main(int argc, char* argv[]) {
  init_random();

  vector<string> args;
  for (int i = 1; i < argc; ++i) {
    args.push_back(argv[i]);
  }

  while (parse_global_option(args)) {
  }

  if (show_version) {
    print_version(stdout);
    return 0;
  }

  if (args.size() == 0) {
    print_usage(stderr);
    return 1;
  }

  auto command = Command::command_for_name(args[0]);
  if (command) {
    args.erase(args.begin());
  } else {
    if (!Command::verify_not_option(args)) {
      print_usage(stderr);
      return 1;
    }
    command = RecordCommand::get();
  }

  return command->run(args);
}
