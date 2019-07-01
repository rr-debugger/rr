/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "DumpCommand.h"

#include <inttypes.h>

#include <limits>
#include <unordered_map>

#include "preload/preload_interface.h"

#include "AddressSpace.h"
#include "Command.h"
#include "RecordSession.h"
#include "TraceStream.h"
#include "core.h"
#include "kernel_metadata.h"
#include "log.h"
#include "main.h"
#include "util.h"

using namespace std;

namespace rr {

class TraceInfoCommand : public Command {
public:
  virtual int run(vector<string>& args) override;

protected:
  TraceInfoCommand(const char* name, const char* help) : Command(name, help) {}

  static TraceInfoCommand singleton;
};

TraceInfoCommand TraceInfoCommand::singleton(
    "traceinfo",
    " rr traceinfo [<trace_dir>]\n"
    "  Dump trace header in JSON format.\n");

static void dump_trace_info(const string& trace_dir, FILE* out) {
  TraceReader trace(trace_dir);

  fputs("{\n", out);

  const uint8_t* bytes = trace.uuid().bytes;
  fputs("  \"uuid\":[", out);
  for (size_t i = 0; i < sizeof(trace.uuid().bytes); ++i) {
    if (i > 0) {
      fputc(',', out);
    }
    fprintf(out, "%d", bytes[i]);
  }
  fputs("],\n", out);

  fprintf(out, "  \"xcr0\":%llu,\n", (unsigned long long)trace.xcr0());

  fprintf(out, "  \"cpuidFaulting\":%s,\n", trace.uses_cpuid_faulting() ? "true" : "false");

  const char* semantics;
  switch (trace.ticks_semantics()) {
    case TICKS_RETIRED_CONDITIONAL_BRANCHES: semantics = "rcb"; break;
    case TICKS_TAKEN_BRANCHES: semantics = "branches"; break;
    default: semantics = "?"; break;
  }
  fprintf(out, "  \"ticksSemantics\":\"%s\",\n", semantics);

  fputs("  \"cpuidRecords\": [", out);
  auto& records = trace.cpuid_records();
  for (size_t i = 0; i < records.size(); ++i) {
    if (i > 0) {
      fputc(',', out);
    }
    auto& r = records[i];
    fprintf(out, "\n    [%u,%u,%u,%u,%u,%u]", r.eax_in, r.ecx_in,
           r.out.eax, r.out.ebx, r.out.ecx, r.out.edx);
  }
  fputs("\n  ]\n", out);

  fputs("}\n", out);
  return;
}

int TraceInfoCommand::run(vector<string>& args) {
  while (parse_global_option(args)) {
  }

  string trace_dir;
  if (!parse_optional_trace_dir(args, &trace_dir)) {
    print_help(stderr);
    return 1;
  }

  dump_trace_info(trace_dir, stdout);
  return 0;
}

} // namespace rr
