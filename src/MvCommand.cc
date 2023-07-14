/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include <stdio.h>

#include <vector>
#include <experimental/filesystem>

#include "Command.h"
#include "main.h"
#include "TraceStream.h"
#include "util.h"

using namespace std;
namespace fs = std::experimental::filesystem;

namespace rr {

class MvCommand : public Command {
public:
  virtual int run(vector<string>& args);

protected:
  MvCommand(const char* name, const char* help) : Command(name, help) {}

  static MvCommand singleton;
};

MvCommand MvCommand::singleton(
    "mv", " rr mv <trace> <new-trace>\n");

static int mv(const string& from, const string& to, FILE* out) {
  if (!ensure_valid_trace_name(from) ||
      !ensure_valid_trace_name(to)) {
    return 1;
  }
  
  fs::path from_path = resolve_trace_name(from);

  if (!is_trace(from_path)) {
    fprintf(
      stderr,
      "\n"
      "rr: Could not idenfity '%s' as a trace.\n"
      "\n",
      from_path.c_str());
      return 1;
  }

  // canonical will resolve latest_trace
  from_path = fs::canonical(from_path);

  fs::path to_path = to;
  // if 'to' is not a path, view it as trace name and move to trace_dir/to
  if (to.find("/") == string::npos) {
    to_path = fs::path(trace_save_dir()) / to;
  }

  if (to_path.filename() == "latest-trace") {
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

  if (fs::exists(to_path)) {
    fprintf(
      stderr,
      "\n"
      "rr: New trace '%s' already exists.\n"
      "\n",
      to_path.c_str());
      return 1;
  }

  // remove symlink before removing trace in case the former fails
  // a bad symlink crashes e.g. rr ls and midas
  if (is_latest_trace(from_path)) {
    if (!remove_latest_trace_symlink()) {
      return 1;
    }
  }

  error_code ec;
  fs::rename(from_path, to_path, ec);
  
  if (ec) {
    const string msg = ec.message();
    fprintf(
      stderr,
      "\n"
      "rr: Cannot move '%s' to '%s': %s\n"
      "\n",
      from_path.c_str(),
      to_path.c_str(),
      msg.c_str());
    return 1;
  } else {
    fprintf(
      out,
      "rr: Moved '%s' to '%s'\n",
      from_path.c_str(),
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
      try {
        return mv(from, to, stdout);
      } catch (const fs::filesystem_error& e) {
        const string msg = e.what();
        fprintf(
          stderr,
          "\n"
          "rr: Unexpected filesystem error: %s\n"
          "\n",
          msg.c_str()
        );
        return 1;
      }
    }
  }

  print_help(stderr);
  return 1;
};

} // namespace rr
