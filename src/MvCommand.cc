/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include <stdio.h>

#include <sysexits.h>
#include <vector>

#include "Command.h"
#include "TraceStream.h"
#include "main.h"
#include "util.h"

using namespace std;

namespace rr {

class MvCommand : public Command {
public:
  virtual int run(vector<string>& args);

protected:
  MvCommand(const char* name, const char* help) : Command(name, help) {}

  static MvCommand singleton;
};

MvCommand MvCommand::singleton("mv", " rr mv <trace> <new-trace>\n");

static int mv(const string& from, const string& to, FILE* out) {
  if (!is_valid_trace_name(from, true) || !is_valid_trace_name(to, true)) {
    return 1;
  }

  string from_path = resolve_trace_name(from);

  if (!is_trace(from_path)) {
    fprintf(stderr,
            "\n"
            "rr: Could not access / identify '%s' as a trace (errno %d).\n"
            "\n",
            from_path.c_str(), errno);
    return 1;
  }

  // resolve symlinks like latest_trace and make comparable
  from_path = real_path(from_path);

  string to_path = to;
  // if 'to' is not a path, view it as trace name and move to trace_dir/to
  if (to.find("/") == string::npos) {
    to_path = trace_save_dir() + "/" + to;
  }

  string to_fname = filename(to_path.c_str());
  if (to_fname == "latest-trace") {
    fprintf(stderr, "\nrr: Cannot rename to latest-trace.\n\n");
    return 1;
  }

  if (from_path == to_path) {
    fprintf(stderr,
            "\n"
            "rr: Old and new trace dir cannot be the same ('%s').\n"
            "\n",
            to_path.c_str());
    return 1;
  }

  if (access(to_path.c_str(), F_OK) == 0) {
    fprintf(stderr,
            "\n"
            "rr: New trace '%s' already exists or cannot be accessed.\n"
            "\n",
            to_path.c_str());
    return 1;
  } else if (errno != ENOENT) {
    fprintf(stderr,
            "\n"
            "rr: Cannot access new trace path '%s': errno %d\n"
            "\n",
            to_path.c_str(), errno);
    return 1;
  }

  // remove symlink before removing trace in case the former fails
  // a bad symlink crashes e.g. rr ls and midas
  if (is_latest_trace(from_path)) {
    if (!remove_latest_trace_symlink()) {
      return 1;
    }
  }

  int ret = rename(from_path.c_str(), to_path.c_str());

  if (ret) {
    const string err = strerror(errno);
    fprintf(stderr,
            "\n"
            "rr: Cannot move '%s' to '%s': %s\n"
            "\n",
            from_path.c_str(), to_path.c_str(), err.c_str());
    return 1;
  } else {
    fprintf(out, "rr: Moved '%s' to '%s'\n", from_path.c_str(),
            to_path.c_str());
    return 0;
  }
}

int MvCommand::run(vector<string>& args) {
  if (args.size() == 2 && verify_not_option(args)) {
    string from = args[0];
    args.erase(args.begin());
    if (verify_not_option(args)) {
      string to = args[0];
      return mv(from, to, stdout);
    }
  }

  print_help(stderr);
  return 1;
};

} // namespace rr
