/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>

#include <limits>

#include "Command.h"
#include "Flags.h"
#include "GdbServer.h"
#include "ReplaySession.h"
#include "ScopedFd.h"
#include "core.h"
#include "kernel_metadata.h"
#include "log.h"
#include "main.h"

using namespace std;

namespace rr {

/**
 * 'rerun' is intended to be a more powerful form of 'rr replay -a'. It does
 * a replay without debugging support, but it provides options for tracing and
 * dumping tracee state. Initially it supports singlestepping through a range
 * of trace events, dumping selected register values after each step.
 */
class RerunCommand : public Command {
public:
  virtual int run(vector<string>& args) override;

protected:
  RerunCommand(const char* name, const char* help) : Command(name, help) {}

  static RerunCommand singleton;
};

RerunCommand RerunCommand::singleton(
    "rerun",
    " rr rerun [OPTION]... [<trace-dir>]\n"
    "  -e, --trace-end=<EVENT>    end tracing at <EVENT>\n"
    "  -f, --function=<ADDR>      when starting tracing, push sentinel return\n"
    "                             address and jump to <ADDR> to fake call\n"
    "  --singlestep=<REGS>        dump <REGS> after each singlestep\n"
    "  -r, --raw                  dump registers in raw format\n"
    "  -s, --trace-start=<EVENT>  start tracing at <EVENT>\n"
    "\n"
    "<REGS> is a comma-separated sequence of 'event','icount','ip','flags',\n"
    "'gp_x16','xmm_x16','ymm_x16'. For the 'x16' cases, we always output 16,\n"
    "values, the latter 8 of which are zero for x86-32. GP registers are in\n"
    "architectural order (AX,CX,DX,BX,SP,BP,SI,DI,R8-R15). All data is output\n"
    "in little-endian binary format; records are separated by \\n. String\n"
    "instruction repetitions are treated as a single instruction if not\n"
    "interrupted. A 'singlestep' includes events such as system-call-exit\n"
    "where tracee state changes without any user-level instructions actually\n"
    "being executed.\n");

enum TraceFieldKind {
  TRACE_EVENT_NUMBER,      // outputs 64-bit value
  TRACE_INSTRUCTION_COUNT, // outputs 64-bit value
  TRACE_IP,                // outputs 64-bit value
  TRACE_FSBASE,            // outputs 64-bit value
  TRACE_GSBASE,            // outputs 64-bit value
  TRACE_FLAGS,             // outputs 64-bit value
  TRACE_ORIG_AX,           // outputs 64-bit value
  TRACE_SEG_REG,           // outputs 64-bit value
  TRACE_XINUSE,            // outputs 64-bit value
  TRACE_GP_REG,            // outputs 64-bit value
  TRACE_XMM_REG,           // outputs 128-bit value
  TRACE_YMM_REG,           // outputs 256-bit value
};
struct TraceField {
  TraceFieldKind kind;
  uint8_t reg_num;
};

struct RerunFlags {
  FrameTime trace_start;
  FrameTime trace_end;
  remote_code_ptr function;
  vector<TraceField> singlestep_trace;
  bool raw;

  RerunFlags()
      : trace_start(0),
        trace_end(numeric_limits<decltype(trace_end)>::max()),
        raw(false) {}
};

#ifdef __x86_64__
static uint8_t user_regs_fields[16] = {
  offsetof(user_regs_struct, rax), offsetof(user_regs_struct, rcx),
  offsetof(user_regs_struct, rdx), offsetof(user_regs_struct, rbx),
  offsetof(user_regs_struct, rsp), offsetof(user_regs_struct, rbp),
  offsetof(user_regs_struct, rsi), offsetof(user_regs_struct, rdi),
  offsetof(user_regs_struct, r8),  offsetof(user_regs_struct, r9),
  offsetof(user_regs_struct, r10), offsetof(user_regs_struct, r11),
  offsetof(user_regs_struct, r12), offsetof(user_regs_struct, r13),
  offsetof(user_regs_struct, r14), offsetof(user_regs_struct, r15),
};
#elif __i386__
static uint8_t user_regs_fields[16] = {
  offsetof(user_regs_struct, eax), offsetof(user_regs_struct, ecx),
  offsetof(user_regs_struct, edx), offsetof(user_regs_struct, ebx),
  offsetof(user_regs_struct, esp), offsetof(user_regs_struct, ebp),
  offsetof(user_regs_struct, esi), offsetof(user_regs_struct, edi),
};
#else
#error Unsupported architecture
#endif

static void print_hex(uint8_t* value, size_t size, FILE* out) {
  bool any_printed = false;
  for (ssize_t i = size - 1; i >= 0; --i) {
    if (value[i] || any_printed || i == 0) {
      fprintf(out, any_printed ? "%02x" : "%x", value[i]);
      any_printed = true;
    }
  }
}

static void print_value(const char* name, void* value, size_t size,
                        const RerunFlags& flags, FILE* out) {
  if (flags.raw) {
    fwrite(value, size, 1, out);
  } else {
    fprintf(out, "%s:0x", name);
    print_hex(static_cast<uint8_t*>(value), size, out);
  }
}

static const char gp_reg_names[16][4] = { "rax", "rcx", "rdx", "rbx",
                                          "rsp", "rbp", "rsi", "rdi",
                                          "r8",  "r9",  "r10", "r11",
                                          "r12", "r13", "r14", "r15" };
static const char gp_reg_names_32[8][4] = { "eax", "ecx", "edx", "ebx",
                                            "esp", "ebp", "esi", "edi" };

static const char seg_reg_names[6][3] = { "es", "cs", "ss", "ds", "fs", "gs" };

static uint64_t seg_reg(const Registers& regs, uint8_t index) {
  switch (index) {
    case 0:
      return regs.es();
    case 1:
      return regs.cs();
    case 2:
      return regs.ss();
    case 3:
      return regs.ds();
    case 4:
      return regs.fs();
    case 5:
      return regs.gs();
    default:
      FATAL() << "Unknown seg reg";
      return 0;
  }
}

static void print_regs(Task* t, FrameTime event, uint64_t instruction_count,
                       const RerunFlags& flags, FILE* out) {
  union {
    struct user_regs_struct gp_regs;
    uintptr_t regs_values[sizeof(struct user_regs_struct) / sizeof(uintptr_t)];
  };
  bool got_gp_regs = false;
  const vector<TraceField>& fields = flags.singlestep_trace;
  bool first = true;

  for (auto& field : fields) {
    if (first) {
      first = false;
    } else if (!flags.raw) {
      fputc(' ', out);
    }
    switch (field.kind) {
      case TRACE_EVENT_NUMBER: {
        uint64_t value = event;
        print_value("event", &value, sizeof(value), flags, out);
        break;
      }
      case TRACE_INSTRUCTION_COUNT:
        print_value("icount", &instruction_count, sizeof(instruction_count),
                    flags, out);
        break;
      case TRACE_IP: {
        uint64_t value = t->regs().ip().register_value();
        print_value(t->arch() == x86 ? "eip" : "rip", &value, sizeof(value),
                    flags, out);
        break;
      }
      case TRACE_FSBASE: {
        uint64_t value = t->regs().fs_base();
        print_value("fsbase", &value, sizeof(value), flags, out);
        break;
      }
      case TRACE_GSBASE: {
        uint64_t value = t->regs().gs_base();
        print_value("gsbase", &value, sizeof(value), flags, out);
        break;
      }
      case TRACE_FLAGS: {
        uint64_t value = t->regs().flags();
        print_value(t->arch() == x86 ? "eflags" : "rflags", &value,
                    sizeof(value), flags, out);
        break;
      }
      case TRACE_ORIG_AX: {
        uint64_t value = t->regs().original_syscallno();
        print_value(t->arch() == x86 ? "orig_eax" : "orig_rax", &value,
                    sizeof(value), flags, out);
        break;
      }
      case TRACE_SEG_REG: {
        uint64_t value = seg_reg(t->regs(), field.reg_num);
        print_value(seg_reg_names[field.reg_num], &value, sizeof(value), flags,
                    out);
        break;
      }
      case TRACE_XINUSE: {
        bool defined;
        uint64_t value = t->extra_regs().read_xinuse(&defined);
        print_value("xinuse", &value, sizeof(value), flags, out);
        break;
      }
      case TRACE_GP_REG: {
        if (!got_gp_regs) {
          gp_regs = t->regs().get_ptrace();
          got_gp_regs = true;
        }
        uint64_t value = field.reg_num < array_length(user_regs_fields)
                             ? regs_values[user_regs_fields[field.reg_num] / 8]
                             : 0;
        if (field.reg_num == 0 && t->arch() == x86) {
          // EAX->RAX is sign-extended, so undo that.
          value = (uint32_t)value;
        }
        const char* name = (t->arch() == x86 && field.reg_num < 8)
                               ? gp_reg_names_32[field.reg_num]
                               : gp_reg_names[field.reg_num];
        print_value(name, &value, sizeof(value), flags, out);
        break;
      }
      case TRACE_XMM_REG: {
        uint8_t value[16];
        bool defined;
        switch (t->arch()) {
          case x86:
            if (field.reg_num < 8) {
              t->extra_regs().read_register(
                  value, GdbRegister(DREG_XMM0 + field.reg_num), &defined);
            } else {
              memset(value, 0, sizeof(value));
            }
            break;
          case x86_64:
            if (field.reg_num < 16) {
              t->extra_regs().read_register(
                  value, GdbRegister(DREG_64_XMM0 + field.reg_num), &defined);
            } else {
              memset(value, 0, sizeof(value));
            }
            break;
        }
        char buf[8];
        sprintf(buf, "xmm%d", field.reg_num);
        print_value(buf, value, sizeof(value), flags, out);
        break;
      }
      case TRACE_YMM_REG: {
        uint8_t value[32];
        bool defined;
        switch (t->arch()) {
          case x86:
            if (field.reg_num < 8) {
              t->extra_regs().read_register(
                  value, GdbRegister(DREG_XMM0 + field.reg_num), &defined);
              t->extra_regs().read_register(
                  value + 16, GdbRegister(DREG_YMM0H + field.reg_num),
                  &defined);
            } else {
              memset(value, 0, sizeof(value));
            }
            break;
          case x86_64:
            if (field.reg_num < 16) {
              t->extra_regs().read_register(
                  value, GdbRegister(DREG_64_XMM0 + field.reg_num), &defined);
              t->extra_regs().read_register(
                  value + 16, GdbRegister(DREG_64_YMM0H + field.reg_num),
                  &defined);
            } else {
              memset(value, 0, sizeof(value));
            }
            break;
        }
        char buf[8];
        sprintf(buf, "ymm%d", field.reg_num);
        print_value(buf, value, sizeof(value), flags, out);
        break;
      }
    }
  }

  fputc('\n', out);
}

static int find_gp_reg(const string& reg) {
  for (int i = 0; i < 16; ++i) {
    if (reg == gp_reg_names[i] || (i < 8 && reg == gp_reg_names_32[i])) {
      return i;
    }
  }
  return -1;
}

static int find_seg_reg(const string& reg) {
  for (int i = 0; i < 6; ++i) {
    if (reg == seg_reg_names[i]) {
      return i;
    }
  }
  return -1;
}

static bool parse_regs(const string& value, vector<TraceField>* out) {
  string s = value;
  if (s.size() == 0) {
    fprintf(stderr, "Empty register list not allowed\n");
    return false;
  }
  do {
    size_t comma = s.find(',');
    string reg;
    if (comma == s.npos) {
      reg = s;
      s = "";
    } else {
      reg = s.substr(0, comma);
      s = s.substr(comma + 1);
    }
    if (reg == "event") {
      out->push_back({ TRACE_EVENT_NUMBER, 0 });
    } else if (reg == "icount") {
      out->push_back({ TRACE_INSTRUCTION_COUNT, 0 });
    } else if (reg == "ip" || reg == "rip") {
      out->push_back({ TRACE_IP, 0 });
    } else if (reg == "fsbase") {
      out->push_back({ TRACE_FSBASE, 0 });
    } else if (reg == "gsbase") {
      out->push_back({ TRACE_GSBASE, 0 });
    } else if (reg == "flags" || reg == "rflags") {
      out->push_back({ TRACE_FLAGS, 0 });
    } else if (reg == "orig_rax" || reg == "orig_eax") {
      out->push_back({ TRACE_ORIG_AX, 0 });
    } else if (reg == "gp_x16") {
      for (uint8_t i = 0; i < 16; ++i) {
        out->push_back({ TRACE_GP_REG, i });
      }
    } else if (reg == "xmm_x16") {
      for (uint8_t i = 0; i < 16; ++i) {
        out->push_back({ TRACE_XMM_REG, i });
      }
    } else if (reg == "ymm_x16") {
      for (uint8_t i = 0; i < 16; ++i) {
        out->push_back({ TRACE_YMM_REG, i });
      }
    } else if (find_gp_reg(reg) >= 0) {
      out->push_back({ TRACE_GP_REG, (uint8_t)find_gp_reg(reg) });
    } else if (find_seg_reg(reg) >= 0) {
      out->push_back({ TRACE_SEG_REG, (uint8_t)find_seg_reg(reg) });
    } else if (reg == "xinuse") {
      out->push_back({ TRACE_XINUSE, 0 });
    } else {
      fprintf(stderr, "Unknown register '%s'\n", reg.c_str());
      return false;
    }
  } while (s.size() > 0);
  return true;
}

static bool parse_rerun_arg(vector<string>& args, RerunFlags& flags) {
  if (parse_global_option(args)) {
    return true;
  }

  static const OptionSpec options[] = {
    { 1, "singlestep", HAS_PARAMETER },    { 'e', "trace-end", HAS_PARAMETER },
    { 'f', "function", HAS_PARAMETER },    { 'r', "raw", NO_PARAMETER },
    { 's', "trace-start", HAS_PARAMETER },
  };
  ParsedOption opt;
  if (!Command::parse_option(args, options, &opt)) {
    return false;
  }

  switch (opt.short_name) {
    case 1:
      if (!parse_regs(opt.value, &flags.singlestep_trace)) {
        return false;
      }
      break;
    case 'e':
      if (!opt.verify_valid_int(1, UINT32_MAX)) {
        return false;
      }
      flags.trace_end = opt.int_value;
      break;
    case 'f': {
      char* endptr;
      flags.function = strtoul(opt.value.c_str(), &endptr, 0);
      if (*endptr) {
        fprintf(stderr, "Invalid function address %s\n", opt.value.c_str());
        return false;
      }
      break;
    }
    case 'r':
      flags.raw = true;
      break;
    case 's':
      if (!opt.verify_valid_int(1, UINT32_MAX)) {
        return false;
      }
      flags.trace_start = opt.int_value;
      break;
    default:
      DEBUG_ASSERT(0 && "Unknown option");
  }
  return true;
}

static bool treat_event_completion_as_singlestep_complete(const Event& ev) {
  switch (ev.type()) {
    case EV_PATCH_SYSCALL:
    case EV_INSTRUCTION_TRAP:
    case EV_SYSCALL:
      return true;
    default:
      return false;
  }
}

/**
 * Return true if the final "event" state change doesn't really change any
 * user-visible state and is therefore not to be considered a singlestep for
 * our purposes.
 */
static bool ignore_singlestep_for_event(const Event& ev) {
  switch (ev.type()) {
    // These don't actually change user-visible state, so we skip them.
    case EV_SIGNAL:
    case EV_SIGNAL_DELIVERY:
      return true;
    default:
      return false;
  }
}

/**
 * In KVM virtual machines (and maybe others), singlestepping over CPUID
 * executes the following instruction as well. Work around that.
 */
static bool maybe_set_breakpoint_after_cpuid(Task* t) {
  if (!t) {
    return false;
  }
  uint8_t bytes[2];
  if (t->read_bytes_fallible(t->ip().to_data_ptr<void>(), 2, bytes) != 2) {
    return false;
  }
  if (bytes[0] != 0x0f || bytes[1] != 0xa2) {
    return false;
  }
  return t->vm()->add_breakpoint(t->ip() + 2, BKPT_USER);
}

static void clear_breakpoint_after_cpuid(Task* t) {
  t->vm()->remove_breakpoint(t->ip(), BKPT_USER);
}

static const uint64_t sentinel_ret_address = 9;

static void run_diversion_function(ReplaySession& replay, Task* task,
                                   const RerunFlags& flags) {
  DiversionSession::shr_ptr diversion_session = replay.clone_diversion();
  Task* t = diversion_session->find_task(task->tuid());
  Registers regs = t->regs();
  // align stack
  auto sp = remote_ptr<uint64_t>(regs.sp().as_int() & ~uintptr_t(0xf)) - 1;
  t->write_mem(sp.cast<uint64_t>(), sentinel_ret_address);
  regs.set_sp(sp);
  regs.set_ip(flags.function);
  regs.set_di(0);
  regs.set_si(0);
  t->set_regs(regs);
  RunCommand cmd =
      flags.singlestep_trace.empty() ? RUN_CONTINUE : RUN_SINGLESTEP;

  while (true) {
    DiversionSession::DiversionResult result =
        diversion_session->diversion_step(t, cmd);
    print_regs(t, 0, 0, flags, stdout);
    if (result.break_status.signal) {
      if (result.break_status.signal->si_signo == SIGSEGV &&
          result.break_status.signal->si_addr == (void*)sentinel_ret_address) {
        return;
      }
      ASSERT(task, false) << "Unexpected signal "
                          << *result.break_status.signal;
    }
  }
}

static int rerun(const string& trace_dir, const RerunFlags& flags) {
  ReplaySession::shr_ptr replay_session = ReplaySession::create(trace_dir);
  uint64_t instruction_count_within_event = 0;
  bool done_first_step = false;

  // Now that we've spawned the replay, raise our resource limits if
  // possible.
  raise_resource_limits();

  while (replay_session->trace_reader().time() < flags.trace_end) {
    RunCommand cmd = RUN_CONTINUE;

    Task* old_task = replay_session->current_task();
    remote_code_ptr old_ip = old_task ? old_task->ip() : remote_code_ptr();
    FrameTime before_time = replay_session->trace_reader().time();
    if (replay_session->done_initial_exec() &&
        before_time >= flags.trace_start) {
      if (!done_first_step) {
        if (!flags.function.is_null()) {
          run_diversion_function(*replay_session, old_task, flags);
          return 0;
        }

        if (!flags.singlestep_trace.empty()) {
          done_first_step = true;
          print_regs(old_task, before_time - 1, instruction_count_within_event,
                     flags, stdout);
        }
      }

      cmd = RUN_SINGLESTEP_FAST_FORWARD;
    }

    Event replayed_event = replay_session->current_trace_frame().event();

    bool set_breakpoint = maybe_set_breakpoint_after_cpuid(old_task);
    auto result = replay_session->replay_step(cmd);
    if (set_breakpoint) {
      clear_breakpoint_after_cpuid(old_task);
      if (result.break_status.breakpoint_hit ||
          result.break_status.singlestep_complete) {
        ASSERT(old_task, old_task->ip() == old_ip + 2);
        result.break_status.breakpoint_hit = false;
        result.break_status.singlestep_complete = true;
      }
    }

    if (result.status == REPLAY_EXITED) {
      break;
    }

    FrameTime after_time = replay_session->trace_reader().time();
    if (cmd != RUN_CONTINUE) {
      remote_code_ptr after_ip = old_task ? old_task->ip() : remote_code_ptr();
      DEBUG_ASSERT(after_time >= before_time && after_time <= before_time + 1);

      DEBUG_ASSERT(result.status == REPLAY_CONTINUE);
      DEBUG_ASSERT(result.break_status.watchpoints_hit.empty());
      DEBUG_ASSERT(!result.break_status.breakpoint_hit);
      DEBUG_ASSERT(cmd == RUN_SINGLESTEP_FAST_FORWARD ||
                   !result.break_status.singlestep_complete);

      // Treat singlesteps that partially executed a string instruction (that
      // was not interrupted) as not really singlestepping.
      bool singlestep_really_complete =
          result.break_status.singlestep_complete &&
          // ignore_singlestep_for_event only matters if we really completed the
          // event
          (!ignore_singlestep_for_event(replayed_event) ||
           before_time == after_time) &&
          (!result.did_fast_forward || old_ip != after_ip ||
           before_time < after_time);
      if (!flags.singlestep_trace.empty() &&
          cmd == RUN_SINGLESTEP_FAST_FORWARD &&
          (singlestep_really_complete ||
           (before_time < after_time &&
            treat_event_completion_as_singlestep_complete(replayed_event)))) {
        print_regs(old_task, before_time, instruction_count_within_event, flags,
                   stdout);
      }

      if (singlestep_really_complete) {
        instruction_count_within_event += 1;
      }
    }
    if (before_time < after_time) {
      LOG(debug) << "Completed event " << before_time
                 << " instruction_count=" << instruction_count_within_event;
      instruction_count_within_event = 1;
    }
  }

  LOG(info) << "Rerun successfully finished";
  return 0;
}

int RerunCommand::run(vector<string>& args) {
  bool found_dir = false;
  string trace_dir;
  RerunFlags flags;

  while (!args.empty()) {
    if (parse_rerun_arg(args, flags)) {
      continue;
    }
    if (!found_dir && parse_optional_trace_dir(args, &trace_dir)) {
      found_dir = true;
      continue;
    }
    print_help(stderr);
    return 1;
  }

  assert_prerequisites();

  if (running_under_rr()) {
    if (!Flags::get().suppress_environment_warnings) {
      fprintf(stderr, "rr: rr pid %d running under parent %d. Good luck.\n",
              getpid(), getppid());
    }
    if (trace_dir.empty()) {
      fprintf(stderr,
              "rr: No trace-dir supplied. You'll try to rerun the "
              "recording of this rr and have a bad time. Bailing out.\n");
      return 3;
    }
  }

  return rerun(trace_dir, flags);
}

} // namespace rr
