/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include <ftw.h>
#include <stdio.h>

#include <vector>

#include "Command.h"
#include "TraceStream.h"
#include "main.h"
#include "util.h"

using namespace std;

namespace rr {

class RmCommand : public Command {
public:
  virtual int run(vector<string>& args);

protected:
  RmCommand(const char* name, const char* help) : Command(name, help) {}

  static RmCommand singleton;
};

RmCommand RmCommand::singleton(
    "rm", " rr rm <trace> [OPTION]...\n"
          "  -f, --force, remove folder even if not identifiable as trace.\n");

struct RmFlags {
  bool force;
  RmFlags() : force(false) {}
};

static bool parse_rm_arg(vector<string>& args, RmFlags& flags) {
  if (parse_global_option(args)) {
    return true;
  }

  static const OptionSpec options[] = { { 'f', "force", NO_PARAMETER } };
  ParsedOption opt;
  if (!Command::parse_option(args, options, &opt)) {
    return false;
  }

  switch (opt.short_name) {
    case 'f':
      flags.force = true;
      break;
    default:
      assert(0 && "Unknown option");
  }

  return true;
}

static int _rm_cb(const char* path, const struct stat*, int, struct FTW*) {
  int ret = remove(path);
  if (ret)
    perror(path);
  return ret;
}

static bool remove_all(const string& path) {
  int ret = nftw(path.c_str(), _rm_cb, 16, FTW_DEPTH | FTW_PHYS);
  if (ret) {
    perror(path.c_str());
    return false;
  }
  return true;
}

static int rm(const string& trace, const RmFlags& flags, FILE* out) {
  if (!is_valid_trace_name(trace, true)) {
    return 1;
  }

  string trace_path = resolve_trace_name(trace);

  if (access(trace_path.c_str(), F_OK) != 0) {
    fprintf(stderr,
            "\n"
            "rr: Cannot remove non-existent / unaccessible trace '%s': errno %d\n"
            "\n",
            trace_path.c_str(),
            errno);
    return 1;
  }

  // resolve symlinks like latest_trace
  trace_path = real_path(trace_path);

  if (!flags.force && !is_trace(trace_path)) {
    fprintf(stderr,
            "\n"
            "rr: Could not idenfity '%s' as a trace, use -f to remove anyway (errno %d).\n"
            "\n",
            trace_path.c_str(),
            errno);
    return 1;
  }

  // remove symlink before removing trace in case the former fails
  // a bad symlink might crash other things later such as rr ls, midas
  if (is_latest_trace(trace_path)) {
    if (!remove_latest_trace_symlink()) {
      return 1;
    }
  }

  if (!remove_all(trace_path)) {
    fprintf(stderr,
            "\n"
            "rr: Could not remove trace '%s'\n"
            "\n",
            trace_path.c_str());
    return 1;
  } else {
    fprintf(out, "rr: Removed trace '%s'\n", trace_path.c_str());
    return 0;
  }
}

int RmCommand::run(vector<string>& args) {
  bool found_trace = false;
  string trace;
  RmFlags flags;

  while (!args.empty()) {
    if (parse_rm_arg(args, flags)) {
      continue;
    }
    // use parse_optional_trace_dir to parse trace name
    if (!found_trace && parse_optional_trace_dir(args, &trace)) {
      found_trace = true;
      continue;
    }
    print_help(stderr);
    return 1;
  };

  if (!found_trace) {
    print_help(stderr);
    return 1;
  }

  return rm(trace, flags, stdout);
};

} // namespace rr
