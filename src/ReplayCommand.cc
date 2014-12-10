/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "Command.h"

#include <assert.h>

#include <limits>

#include "Flags.h"
#include "replayer.h"

using namespace std;

class ReplayCommand : public Command {
public:
  virtual int run(std::vector<std::string>& args);

protected:
  ReplayCommand(const char* name, const char* help) : Command(name, help) {}

  static ReplayCommand singleton;
};

ReplayCommand ReplayCommand::singleton(
    "replay",
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
    "  -x, --gdb-x=<FILE>         execute gdb commands from <FILE>\n");

static bool parse_replay_arg(std::vector<std::string>& args) {
  if (parse_global_option(args)) {
    return true;
  }

  static const OptionSpec options[] = { { 'a', "autopilot", NO_PARAMETER },
                                        { 's', "dbgport", HAS_PARAMETER },
                                        { 'g', "goto", HAS_PARAMETER },
                                        { 'q', "no-redirect-output",
                                          NO_PARAMETER },
                                        { 'f', "onfork", HAS_PARAMETER },
                                        { 'p', "onprocess", HAS_PARAMETER },
                                        { 'x', "gdb-x", HAS_PARAMETER } };
  ParsedOption opt;
  if (!Command::parse_option(args, options, &opt)) {
    return false;
  }

  Flags& flags = Flags::get_for_init();
  switch (opt.short_name) {
    case 'a':
      flags.goto_event = numeric_limits<decltype(flags.goto_event)>::max();
      flags.dont_launch_debugger = true;
      break;
    case 'f':
      flags.target_process = atoi(optarg);
      flags.process_created_how = Flags::CREATED_FORK;
      break;
    case 'g':
      flags.goto_event = atoi(optarg);
      break;
    case 'p':
      flags.target_process = atoi(optarg);
      flags.process_created_how = Flags::CREATED_EXEC;
      break;
    case 'q':
      flags.redirect = false;
      break;
    case 's':
      flags.dbgport = atoi(optarg);
      flags.dont_launch_debugger = true;
      break;
    case 'x':
      flags.gdb_command_file_path = optarg;
      break;
    default:
      assert(0 && "Unknown option");
  }
  return true;
}

int ReplayCommand::run(std::vector<std::string>& args) {
  while (parse_replay_arg(args)) {
  }

  return replay(args);
}
