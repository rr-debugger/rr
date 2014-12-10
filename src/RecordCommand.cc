/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "RecordCommand.h"

#include <assert.h>

#include "preload/preload_interface.h"

#include "Flags.h"
#include "recorder.h"

using namespace std;

extern char** environ;

RecordCommand RecordCommand::singleton(
    "record",
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
    "                             even if it would otherwise be used\n");

static bool parse_record_arg(std::vector<std::string>& args) {
  if (parse_global_option(args)) {
    return true;
  }

  static const OptionSpec options[] = {
    { 'b', "force-syscall-buffer", NO_PARAMETER },
    { 'i', "ignore-signal", HAS_PARAMETER },
    { 'c', "num-cpu-ticks", HAS_PARAMETER },
    { 'e', "num-events", HAS_PARAMETER },
    { 'n', "no-syscall-buffer", NO_PARAMETER }
  };
  ParsedOption opt;
  if (!Command::parse_option(args, options, &opt)) {
    return false;
  }

  Flags& flags = Flags::get_for_init();
  switch (opt.short_name) {
    case 'b':
      flags.use_syscall_buffer = true;
      break;
    case 'c':
      flags.max_ticks = max(1, atoi(optarg));
      break;
    case 'e':
      flags.max_events = max(1, atoi(optarg));
      break;
    case 'i':
      flags.ignore_sig = min(_NSIG - 1, max(1, atoi(optarg)));
      break;
    case 'n':
      flags.use_syscall_buffer = false;
      break;
    default:
      assert(0 && "Unknown option");
  }
  return true;
}

static string find_syscall_buffer_library() {
  char* exe_path = realpath("/proc/self/exe", nullptr);
  string lib_path = exe_path;
  free(exe_path);

  int end = lib_path.length();
  // Chop off the filename
  while (end > 0 && lib_path[end - 1] != '/') {
    --end;
  }
  lib_path.erase(end);
  lib_path += "../lib/";
  string file_name = lib_path + SYSCALLBUF_LIB_FILENAME;
  if (access(file_name.c_str(), F_OK) != 0) {
    // File does not exist. Assume install put it in LD_LIBRARY_PATH.
    lib_path = "";
  }
  return lib_path;
}

int RecordCommand::run(std::vector<std::string>& args) {
  while (parse_record_arg(args)) {
  }

  if (args.size() == 0) {
    print_help(stderr);
    return 1;
  }

  // The syscallbuf library interposes some critical
  // external symbols like XShmQueryExtension(), so we
  // preload it whether or not syscallbuf is enabled.
  if (Flags::get().use_syscall_buffer) {
    setenv(SYSCALLBUF_ENABLED_ENV_VAR, "1", 1);
  } else {
    unsetenv(SYSCALLBUF_ENABLED_ENV_VAR);
  }
  Flags::get_for_init().syscall_buffer_lib_path = find_syscall_buffer_library();

  return record(args, environ);
}
