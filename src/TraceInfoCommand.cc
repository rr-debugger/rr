/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "DumpCommand.h"

#include <inttypes.h>

#include <limits>
#include <unordered_map>

#include "preload/preload_interface.h"

#include "AddressSpace.h"
#include "Command.h"
#include "Flags.h"
#include "RecordSession.h"
#include "ReplaySession.h"
#include "ReplayTask.h"
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

static int dump_trace_info(const string& trace_dir, FILE* out) {
  int ret = 0;
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

  fprintf(out, "  \"bindToCpu\":%d,\n", trace.bound_to_cpu());

  fprintf(out, "  \"cpuidFaulting\":%s,\n", trace.uses_cpuid_faulting() ? "true" : "false");

  fprintf(out, "  \"requiredForwardCompatibilityVersion\":%d,\n", trace.required_forward_compatibility_version());

  const char* semantics;
  switch (trace.ticks_semantics()) {
    case TICKS_RETIRED_CONDITIONAL_BRANCHES: semantics = "rcb"; break;
    case TICKS_TAKEN_BRANCHES: semantics = "branches"; break;
    default: semantics = "?"; break;
  }
  fprintf(out, "  \"ticksSemantics\":\"%s\",\n", semantics);

  fputs("  \"cpuidRecords\":[", out);
  auto& records = trace.cpuid_records();
  for (size_t i = 0; i < records.size(); ++i) {
    if (i > 0) {
      fputc(',', out);
    }
    auto& r = records[i];
    fprintf(out, "\n    [%u,%u,%u,%u,%u,%u]", r.eax_in, r.ecx_in,
           r.out.eax, r.out.ebx, r.out.ecx, r.out.edx);
  }
  fputs("\n  ],\n", out);

  bool chaos_mode_known;
  bool chaos_mode = trace.chaos_mode(&chaos_mode_known);
  if (chaos_mode_known) {
    fprintf(out, "  \"chaosMode\":%s,\n", chaos_mode ? "true" : "false");
    if (chaos_mode) {
      MemoryRange exclusion_range = trace.exclusion_range();
      fprintf(out, "  \"exclusionRange\": { \"start\": %llu, \"end\": %llu },\n",
             (unsigned long long)exclusion_range.start().as_int(),
             (unsigned long long)exclusion_range.end().as_int());
    }
  }

  uint8_t max_virtual_address_size = trace.max_virtual_address_size();
  if (max_virtual_address_size > 0) {
    fprintf(out, "  \"maxVirtualAddressSize\":%d,\n", max_virtual_address_size);
  }

  bool cpu_improperly_configured_known;
  bool cpu_improperly_configured = trace.cpu_improperly_configured(&cpu_improperly_configured_known);
  if (cpu_improperly_configured_known) {
    fprintf(out, "  \"cpuImproperlyConfigured\":%s,\n", cpu_improperly_configured ? "true" : "false");
  }

  if (!trace.uname().sysname.empty()) {
    const auto& uname = trace.uname();
    fputs("  \"uname\":{", out);
    fprintf(out, "\n    \"sysname\":\"%s\",", json_escape(uname.sysname).c_str());
    fprintf(out, "\n    \"nodename\":\"%s\",", json_escape(uname.nodename).c_str());
    fprintf(out, "\n    \"release\":\"%s\",", json_escape(uname.release).c_str());
    fprintf(out, "\n    \"version\":\"%s\",", json_escape(uname.version).c_str());
    fprintf(out, "\n    \"machine\":\"%s\",", json_escape(uname.machine).c_str());
    fprintf(out, "\n    \"domainname\":\"%s\"", json_escape(uname.domainname).c_str());
    fputs("\n  },\n", out);
  }

  ReplaySession::Flags flags;
  flags.redirect_stdio = false;
  flags.share_private_mappings = false;
  flags.replay_stops_at_first_execve = true;
  flags.cpu_unbound = true;
  ReplaySession::shr_ptr replay_session = ReplaySession::create(trace_dir, flags);

  while (true) {
    auto result = replay_session->replay_step(RUN_CONTINUE);
    if (replay_session->done_initial_exec()) {
      fputs("  \"environ\":[", out);
      auto environ = read_env(replay_session->current_task());
      for (size_t i = 0; i < environ.size(); ++i) {
        if (i > 0) {
          fputc(',', out);
        }
        fprintf(out, "\n    \"%s\"", json_escape(environ[i]).c_str());
      }
      fputs("\n  ],\n", out);

      fprintf(out, "  \"program\": \"%s\"\n", json_escape(replay_session->vms()[0]->exe_image()).c_str());

      break;
    }
    if (result.status == REPLAY_EXITED) {
      fputs("Replay finished before initial exec!\n", stderr);
      ret = 1;
      break;
    }
  }

  fputs("}\n", out);
  return ret;
}

int TraceInfoCommand::run(vector<string>& args) {
  // Various "cannot replay safely..." warnings cannot affect us since
  // we only replay to the first execve.
  Flags::get_for_init().suppress_environment_warnings = true;

  while (parse_global_option(args)) {
  }

  string trace_dir;
  if (!parse_optional_trace_dir(args, &trace_dir)) {
    print_help(stderr);
    return 1;
  }

  return dump_trace_info(trace_dir, stdout);
}

} // namespace rr
