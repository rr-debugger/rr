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

struct TraceInfo {
  string name;
  struct timespec ctime;
  string exit;

  TraceInfo(string in_name) : name(in_name) {}
};

static bool compare_by_name(const TraceInfo& at, const TraceInfo& bt) {
  auto a = at.name;
  auto b = bt.name;
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
  closedir(dir);

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

static string get_exec_path(TraceReader& reader) {
  while (true) {
    TraceTaskEvent r = reader.read_task_event();
    if (r.type() == TraceTaskEvent::NONE) {
      break;
    }
    if (r.type() == TraceTaskEvent::EXEC) {
      return r.cmd_line()[0];
    }
  }
  return string();
}

string find_exit_code(pid_t pid, const vector<TraceTaskEvent>& events,
                      size_t current_event,
                      const map<pid_t, pid_t> current_tid_to_pid);

static int ls(const string& traces_dir, const LsFlags& flags, FILE* out) {
  DIR* dir = opendir(traces_dir.c_str());
  if (!dir) {
    fprintf(stderr, "Cannot open %s\n", traces_dir.c_str());
    return 1;
  }

  const string cpu_lock = real_path(get_cpu_lock_file());
  const string full_traces_dir = real_path(traces_dir) + "/";
  vector<TraceInfo> traces;

  while (struct dirent* trace_dir = readdir(dir)) {
    if (full_traces_dir + trace_dir->d_name == cpu_lock) {
      continue;
    }
    if (!is_valid_trace_name(trace_dir->d_name)) {
      continue;
    }
    traces.emplace_back(TraceInfo(string(trace_dir->d_name)));
    if (flags.sort_by_time || flags.full_listing) {
      struct stat st;
      stat((traces_dir + "/" + trace_dir->d_name + "/data").c_str(), &st);
      traces.back().ctime = st.st_ctim;
    }

    if (flags.full_listing) {
      TraceReader trace(traces_dir + "/" + trace_dir->d_name);

      vector<TraceTaskEvent> events;
      while (true) {
        TraceTaskEvent r = trace.read_task_event();
        if (r.type() == TraceTaskEvent::NONE) {
          break;
        }
        events.push_back(r);
      }

      if (events.empty() || events[0].type() != TraceTaskEvent::EXEC) {
        traces.back().exit = "????";
        continue;
      }

      map<pid_t, pid_t> tid_to_pid;
      pid_t initial_tid = events[0].tid();
      tid_to_pid[initial_tid] = initial_tid;
      traces.back().exit = find_exit_code(initial_tid, events, 0, tid_to_pid);
    }
  }
  closedir(dir);

  if (flags.sort_by_time) {
    auto compare_by_time = [&](const TraceInfo& at,
                               const TraceInfo& bt) -> bool {
      if (at.ctime.tv_sec == bt.ctime.tv_sec) {
        return at.ctime.tv_nsec < bt.ctime.tv_nsec;
      }
      return at.ctime.tv_sec < bt.ctime.tv_sec;
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
      cout << t.name << "\n";
    }
    return 0;
  }

  int max_name_size =
    accumulate(traces.begin(), traces.end(), 0, [](int m, TraceInfo& t) {
        return max(m, static_cast<int>(t.name.length()));
    });

  fprintf(out, "%-*s %-19s %5s %6s %s\n", max_name_size,
          "NAME", "WHEN", "SIZE", "EXIT", "CMD");

  for (TraceInfo& t : traces) {
    // Record date & runtime estimates
    string data_file = traces_dir + "/" + t.name + "/data";
    char outstr[200];
    struct tm ctime_tm;
    if (localtime_r(&t.ctime.tv_sec, &ctime_tm)) {
      strftime(outstr, sizeof(outstr), "%F %T", &ctime_tm);
    } else {
      strcpy(outstr, "<error>");
    }

    string folder_size = "????";
    string exe = "(incomplete)";
    string version_file = traces_dir + "/" + t.name + "/version";
    struct stat st;
    if (stat(version_file.c_str(), &st) != -1) {
      TraceReader reader(traces_dir + "/" + t.name);
      get_folder_size(reader.dir(), folder_size);
      exe = get_exec_path(reader);
    }

    fprintf(out, "%-*s %s %5s %6s %s\n", max_name_size, t.name.c_str(),
            outstr, folder_size.c_str(), t.exit.c_str(), exe.c_str());
  }

  return 0;
}

int LsCommand::run(vector<string>& args) {
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
