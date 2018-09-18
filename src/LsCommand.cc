/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include <assert.h>
#include <dirent.h>

#include <algorithm>
#include <iomanip>
#include <memory>
#include <numeric>
#include <sstream>
#include <vector>

#include "Command.h"
#include "main.h"
#include "TraceStream.h"
#include "util.h"

using namespace std;

namespace rr {

class LsCommand : public Command {
public:
  virtual int run(vector<string>& args);

protected:
  LsCommand(const char* name, const char* help) : Command(name, help) {}

  static LsCommand singleton;
};

LsCommand LsCommand::singleton(
    "ls", " rr ls [OPTION]...\n"
          "  -l, --long-listing use a long listing format\n"
          "     (trace name | start time | size | command line)\n"
          "  -t, --sort-by-age, sort from newest to oldest\n"
          "  -r, --reverse, the sort order\n");

struct LsFlags {
  bool reverse;
  bool full_listing;
  bool sort_by_time;
  LsFlags() : reverse(false), full_listing(false), sort_by_time(false) {}
};

static bool parse_ls_arg(vector<string>& args, LsFlags& flags) {
  if (parse_global_option(args)) {
    return true;
  }

  static const OptionSpec options[] = { { 'r', "reverse", NO_PARAMETER },
                                        { 'l', "long-listing", NO_PARAMETER },
                                        { 't', "sort-by-age", NO_PARAMETER } };
  ParsedOption opt;
  if (!Command::parse_option(args, options, &opt)) {
    return false;
  }

  switch (opt.short_name) {
    case 'r':
      flags.reverse = true;
      break;
    case 'l':
      flags.full_listing = true;
      break;
    case 't':
      flags.sort_by_time = true;
      break;
    default:
      assert(0 && "Unknown option");
  }

  return true;
}

typedef pair<string, unique_ptr<TraceReader>> TraceInfo;

static bool compare_by_name(TraceInfo& at, TraceInfo& bt) {
  auto a = at.first;
  auto b = bt.first;
  return lexicographical_compare(begin(a), end(a), begin(b), end(b));
}

static bool get_folder_size(string dir_name, string& size_str) {
  DIR* dir = opendir(dir_name.c_str());
  if (!dir) {
    cerr << "Cannot open " << dir_name << endl;
    return false;
  }

  size_t bytes = 0;
  while (struct dirent* ent = readdir(dir)) {
    string path = dir_name + "/" + ent->d_name;

    struct stat st;
    if (stat(path.c_str(), &st) == -1) {
      cerr << "stat " << path << " failed\n";
      return false;
    }

    bytes += st.st_size;
  }

  static const char suffixes[] = " KMGT";
  double size = bytes;
  size_t suffix_idx = 0;
  while (size >= 1000.0) {
    size /= 1024.0;
    suffix_idx++;
  }
  char suffix = suffixes[suffix_idx];

  ostringstream cvt;

  if (suffix == ' ') {
    cvt << bytes;
  } else if (size >= 10) {
    cvt << int(size) << suffix;
  } else {
    cvt << fixed << setprecision(1) << size << suffix;
  }

  size_str = cvt.str();
  return true;
}

static bool is_valid_trace(const string& entry) {
  if (entry[0] == '.' || entry[0] == '#') {
    return false;
  }
  if (entry[entry.length() - 1] == '~') {
    return false;
  }
  return true;
}

static string get_exec_path(TraceInfo& info) {
  while (true) {
    TraceTaskEvent r = info.second->read_task_event();
    if (r.type() == TraceTaskEvent::NONE) {
      break;
    }
    if (r.type() == TraceTaskEvent::EXEC) {
      return r.cmd_line()[0];
    }
  }
  return string();
}

static int ls(const string& traces_dir, const LsFlags& flags, FILE* out) {
  DIR* dir = opendir(traces_dir.c_str());
  if (!dir) {
    fprintf(stderr, "Cannot open %s", traces_dir.c_str());
    return 1;
  }

  vector<TraceInfo> traces;

  while (struct dirent* trace_dir = readdir(dir)) {
    if (!is_valid_trace(trace_dir->d_name)) {
      continue;
    }
    traces.emplace_back(string(trace_dir->d_name), unique_ptr<TraceReader>());
  }

  if (flags.sort_by_time) {
    auto compare_by_time = [&](TraceInfo& at, TraceInfo& bt) -> bool {
      auto a_version = traces_dir + at.first + "/data";
      auto b_version = traces_dir + bt.first + "/data";
      struct stat a_stat;
      struct stat b_stat;
      stat(a_version.c_str(), &a_stat);
      stat(b_version.c_str(), &b_stat);
      return a_stat.st_ctime < b_stat.st_ctime;
    };
    sort(traces.begin(), traces.end(), compare_by_time);
  } else {
    sort(traces.begin(), traces.end(), compare_by_name);
  }

  if (flags.reverse) {
    reverse(begin(traces), end(traces));
  };

  if (!flags.full_listing) {
    for (TraceInfo& t : traces) {
      cout << t.first << "\n";
    }
    return 0;
  }

  int max_name_size =
    accumulate(traces.begin(), traces.end(), 0, [](int m, TraceInfo& t) {
        return max(m, static_cast<int>(t.first.length()));
    });

  fprintf(out, "%-*s %19s %5s %s\n", max_name_size,
          "NAME", "WHEN", "SIZE", "CMD");

  for (TraceInfo& t : traces) {
    // Record date & runtime estimates
    struct stat st;
    string data_file = traces_dir + "/" + t.first + "/data";
    stat(data_file.c_str(), &st);
    char outstr[200];
    strftime(outstr, sizeof(outstr), "%F %T", localtime(&st.st_ctime));

    string folder_size = "????";
    string exe = "(incomplete)";
    string version_file = traces_dir + "/" + t.first + "/version";
    if (stat(version_file.c_str(), &st) != -1) {
      t.second.reset(new TraceReader(traces_dir + "/" + t.first));
      get_folder_size(t.second->dir(), folder_size);
      exe = get_exec_path(t);
    }

    fprintf(out, "%-*s %s %5s %s\n", max_name_size, t.first.c_str(),
            outstr, folder_size.c_str(), exe.c_str());
  }

  return 0;
}

int LsCommand::run(vector<string>& args) {
  if (getenv("RUNNING_UNDER_RR")) {
    fprintf(stderr, "rr: cannot run rr replay under rr. Exiting.\n");
    return 1;
  }

  bool found_dir = false;
  string trace_dir;
  LsFlags flags;

  while (!args.empty()) {
    if (parse_ls_arg(args, flags)) {
      continue;
    }
    if (!found_dir && parse_optional_trace_dir(args, &trace_dir)) {
      found_dir = true;
      continue;
    }
    print_help(stderr);
    return 1;
  };

  if (!found_dir) {
    trace_dir = trace_save_dir();
  }
  return ls(trace_dir, flags, stdout);
};

} // namespace rr
