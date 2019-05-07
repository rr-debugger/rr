/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include <map>

#include "Command.h"
#include "RecordSession.h"
#include "TraceStream.h"
#include "core.h"
#include "main.h"

using namespace std;

namespace rr {

class TraceIdCommand : public Command {
public:
  virtual int run(vector<string>& args) override;

protected:
  TraceIdCommand(const char* name, const char* help) : Command(name, help) {}

  static TraceIdCommand singleton;
};

TraceIdCommand TraceIdCommand::singleton("traceid", " rr traceid [<trace_dir>]\n");

static int trace_id(const string& trace_dir) {
  TraceReader trace(trace_dir);
  const TraceUuid& uuid = trace.uuid();

  write_all(STDOUT_FILENO, uuid.bytes, sizeof(uuid.bytes));

  return 0;
}

int TraceIdCommand::run(vector<string>& args) {
  while (parse_global_option(args)) {
  }

  string trace_dir;
  if (!parse_optional_trace_dir(args, &trace_dir)) {
    print_help(stderr);
    return 1;
  }

  return trace_id(trace_dir);
}

} // namespace rr
