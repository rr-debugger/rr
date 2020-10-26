/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "main.h"

#include <limits.h>
#include <linux/version.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>

#include <sstream>

#include "Command.h"
#include "Flags.h"
#include "RecordCommand.h"
#include "ReplayCommand.h"
#include "core.h"
#include "log.h"
#include "util.h"

using namespace std;

namespace rr {

// Show version and quit.
static bool show_version = false;
static bool show_cmd_list = false;

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

void print_version(FILE* out) { fprintf(out, "rr version %s\n", RR_VERSION); }

void print_global_options(FILE* out) {
  fputs(
      "Global options:\n"
      "  --disable-cpuid-faulting   disable use of CPUID faulting\n"
      "  --disable-ptrace-exit_events disable use of PTRACE_EVENT_EXIT\n"
      "  --resource-path=PATH       specify the paths that rr should use to "
      "find\n"
      "                             files such as rr_page_*.  These files "
      "should\n"
      "                             be located in PATH/bin, PATH/lib[64], and\n"
      "                             PATH/share as appropriate.\n"
      "  -A, --microarch=<NAME>     force rr to assume it's running on a CPU\n"
      "                             with microarch NAME even if runtime "
      "detection\n"
      "                             says otherwise.  NAME should be a string "
      "like\n"
      "                             'Ivy Bridge'. Note that rr will not work "
      "with\n"
      "                             Intel Merom or Penryn microarchitectures.\n"
      "  -F, --force-things         force rr to do some things that don't "
      "seem\n"
      "                             like good ideas, for example launching an\n"
      "                             interactive emergency debugger if stderr\n"
      "                             isn't a tty.\n"
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
      "\n"
      "Use RR_LOG to control logging; e.g. RR_LOG=all:warn,Task:debug\n",
      out);
}

void list_commands(FILE* out) {
  Command::print_help_all(out);
}

void print_usage(FILE* out) {
  print_version(out);
  fputs("\nUsage:\n", out);
  list_commands(out);
  fputs("\nIf no subcommand is provided, we check if the first non-option\n"
        "argument is a directory. If it is, we assume the 'replay' subcommand\n"
        "otherwise we assume the 'record' subcommand.\n\n",
        out);
  print_global_options(out);
}

static void init_random() {
  // Not very good, but good enough for our non-security-sensitive needs.
  int key;
  good_random(&key, sizeof(key));
  srandom(key);
  srand(key);
}

bool parse_global_option(std::vector<std::string>& args) {
  static const OptionSpec options[] = {
    { 0, "disable-cpuid-faulting", NO_PARAMETER },
    { 1, "disable-ptrace-exit-events", NO_PARAMETER },
    { 2, "resource-path", HAS_PARAMETER },
    { 'A', "microarch", HAS_PARAMETER },
    { 'C', "checksum", HAS_PARAMETER },
    { 'D', "dump-on", HAS_PARAMETER },
    { 'E', "fatal-errors", NO_PARAMETER },
    { 'F', "force-things", NO_PARAMETER },
    { 'K', "check-cached-mmaps", NO_PARAMETER },
    { 'L', "list-commands", NO_PARAMETER },
    { 'M', "mark-stdio", NO_PARAMETER },
    { 'N', "version", NO_PARAMETER },
    { 'S', "suppress-environment-warnings", NO_PARAMETER },
    { 'T', "dump-at", HAS_PARAMETER },
  };

  ParsedOption opt;
  if (!Command::parse_option(args, options, &opt)) {
    return false;
  }

  Flags& flags = Flags::get_for_init();
  switch (opt.short_name) {
    case 0:
      flags.disable_cpuid_faulting = true;
      break;
    case 1:
      flags.disable_ptrace_exit_events = true;
      break;
    case 2:
      flags.resource_path = opt.value;
      if (flags.resource_path.back() != '/') {
        flags.resource_path.append("/");
      }
      break;
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
        flags.checksum = strtoll(opt.value.c_str(), NULL, 10);
        LOG(info) << "checksumming on at event " << flags.checksum;
      }
      break;
    case 'D':
      if (opt.value == "RDTSC") {
        flags.dump_on = Flags::DUMP_ON_RDTSC;
      } else {
        flags.dump_on = strtoll(opt.value.c_str(), NULL, 10);
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
      flags.dump_at = strtoll(opt.value.c_str(), NULL, 10);
      break;
    case 'N':
      show_version = true;
      break;
    case 'L':
      show_cmd_list = true;
      break;
    default:
      DEBUG_ASSERT(0 && "Invalid flag");
  }
  return true;
}

} // namespace rr

using namespace rr;

int main(int argc, char* argv[]) {
  init_random();
  raise_resource_limits();

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
  if (show_cmd_list) {
    list_commands(stdout);
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
    if (is_directory(args[0].c_str())) {
      command = ReplayCommand::get();
    } else {
      command = RecordCommand::get();
    }
  }

  return command->run(args);
}
