/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include <map>

#include "Command.h"
#include "TraceStream.h"
#include "TraceTaskEvent.h"
#include "main.h"
#include "util.h"
#include "Flags.h"

using namespace std;

namespace rr {

class PerfCommand : public Command {
public:
  virtual int run(vector<string>& args);

protected:
  PerfCommand(const char* name, const char* help) : Command(name, help) {}

  static PerfCommand singleton;
};

PerfCommand PerfCommand::singleton("perf", " rr perf [<trace_dir>]\n");


static int perf(const string& trace_dir, FILE* out) {
  TraceReader trace(trace_dir);
  
  if (!probably_not_interactive(STDOUT_FILENO) && !Flags::get().force_things) {
    fprintf(stderr, "Cowardly refusing to write binary data to a tty. "
                    "Use -f to overwrite\n");
    return 1;
  }
  
  // Write perf file header

  // Write perf file data
  ssize_t total_bytes_left = trace.total_perf_bytes();
  while (trace.good() && total_bytes_left > 0) {
    size_t to_read = min((ssize_t)0x1000, total_bytes_left);
    auto data = trace.read_perf_records(to_read);
    fwrite(data.data(), 1, data.size(), out);
    total_bytes_left -= to_read;
  }
   
  return 0;
};

int PerfCommand::run(vector<string>& args) {
  while (parse_global_option(args)) {
  }

  string trace_dir;
  if (!parse_optional_trace_dir(args, &trace_dir)) {
    print_help(stderr);
    return 1;
  }

  return perf(trace_dir, stdout);
}

} // namespace rr
