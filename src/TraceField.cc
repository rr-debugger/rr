#include <string>

#include "ReplayTask.h"
#include "TraceField.h"

using namespace std;

namespace rr {

namespace {

void print_hex(uint8_t* value, size_t size, FILE* out) {
  bool any_printed = false;
  for (ssize_t i = size - 1; i >= 0; --i) {
    if (value[i] || any_printed || i == 0) {
      fprintf(out, any_printed ? "%02x" : "%x", value[i]);
      any_printed = true;
    }
  }
}

void print_value(const char* name, void* value, size_t size,
                 bool hex, bool raw, FILE* out) {
  if (raw) {
    fwrite(value, size, 1, out);
  } else if (hex) {
    fprintf(out, "%s:0x", name);
    print_hex(static_cast<uint8_t*>(value), size, out);
  } else {
    uint64_t v = 0;
    DEBUG_ASSERT(size <= 8);
    memcpy(&v, value, size);
    fprintf(out, "%s:%lld", name, (long long)v);
  }
}

#ifdef __x86_64__
uint8_t user_regs_fields[16] = {
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
uint8_t user_regs_fields[16] = {
  offsetof(user_regs_struct, eax), offsetof(user_regs_struct, ecx),
  offsetof(user_regs_struct, edx), offsetof(user_regs_struct, ebx),
  offsetof(user_regs_struct, esp), offsetof(user_regs_struct, ebp),
  offsetof(user_regs_struct, esi), offsetof(user_regs_struct, edi),
};
#elif defined(__aarch64__)
#define user_regs_struct NativeArch::user_regs_struct
uint16_t user_regs_fields[34] = {
  offsetof(user_regs_struct, x[0]), offsetof(user_regs_struct, x[1]),
  offsetof(user_regs_struct, x[2]), offsetof(user_regs_struct, x[3]),
  offsetof(user_regs_struct, x[4]), offsetof(user_regs_struct, x[5]),
  offsetof(user_regs_struct, x[6]), offsetof(user_regs_struct, x[7]),
  offsetof(user_regs_struct, x[8]), offsetof(user_regs_struct, x[9]),
  offsetof(user_regs_struct, x[10]), offsetof(user_regs_struct, x[11]),
  offsetof(user_regs_struct, x[12]), offsetof(user_regs_struct, x[13]),
  offsetof(user_regs_struct, x[14]), offsetof(user_regs_struct, x[15]),
  offsetof(user_regs_struct, x[16]), offsetof(user_regs_struct, x[17]),
  offsetof(user_regs_struct, x[18]), offsetof(user_regs_struct, x[19]),
  offsetof(user_regs_struct, x[20]), offsetof(user_regs_struct, x[21]),
  offsetof(user_regs_struct, x[22]), offsetof(user_regs_struct, x[23]),
  offsetof(user_regs_struct, x[24]), offsetof(user_regs_struct, x[25]),
  offsetof(user_regs_struct, x[26]), offsetof(user_regs_struct, x[27]),
  offsetof(user_regs_struct, x[28]), offsetof(user_regs_struct, x[29]),
  offsetof(user_regs_struct, x[30]),
  offsetof(user_regs_struct, sp),
  offsetof(user_regs_struct, pc),
  offsetof(user_regs_struct, pstate)
};
#undef user_regs_struct
#else
#error Unsupported architecture
#endif

const char gp_reg_names[16][4] = { "rax", "rcx", "rdx", "rbx",
                                   "rsp", "rbp", "rsi", "rdi",
                                   "r8",  "r9",  "r10", "r11",
                                   "r12", "r13", "r14", "r15" };
const char gp_reg_names_32[8][4] = { "eax", "ecx", "edx", "ebx",
                                     "esp", "ebp", "esi", "edi" };

const char seg_reg_names[6][3] = { "es", "cs", "ss", "ds", "fs", "gs" };

uint64_t seg_reg(const Registers& regs, uint8_t index) {
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

int find_gp_reg(const string& reg) {
  for (int i = 0; i < 16; ++i) {
    if (reg == gp_reg_names[i] || (i < 8 && reg == gp_reg_names_32[i])) {
      return i;
    }
  }
  return -1;
}

int find_seg_reg(const string& reg) {
  for (int i = 0; i < 6; ++i) {
    if (reg == seg_reg_names[i]) {
      return i;
    }
  }
  return -1;
}

} // anonymous namespace

void print_trace_fields(ReplayTask* t, FrameTime event, uint64_t instruction_count,
                        bool raw, const vector<TraceField>& fields, FILE* out) {
  if (fields.empty()) {
    return;
  }
  union {
    NativeArch::user_regs_struct gp_regs;
    uintptr_t regs_values[sizeof(NativeArch::user_regs_struct) / sizeof(uintptr_t)];
  };
  bool got_gp_regs = false;
  bool first = true;

  for (auto& field : fields) {
    if (first) {
      first = false;
    } else if (!raw) {
      fputc(' ', out);
    }
    switch (field.kind) {
      case TRACE_EVENT_NUMBER: {
        uint64_t value = event;
        print_value("event", &value, sizeof(value), false, raw, out);
        break;
      }
      case TRACE_INSTRUCTION_COUNT:
        print_value("icount", &instruction_count, sizeof(instruction_count),
                    false, raw, out);
        break;
      case TRACE_IP: {
        uint64_t value = t->regs().ip().register_value();
        print_value(t->arch() == x86 ? "eip" : "rip", &value, sizeof(value),
                    true, raw, out);
        break;
      }
      case TRACE_FSBASE: {
        uint64_t value = t->regs().fs_base();
        print_value("fsbase", &value, sizeof(value), true, raw, out);
        break;
      }
      case TRACE_GSBASE: {
        uint64_t value = t->regs().gs_base();
        print_value("gsbase", &value, sizeof(value), true, raw, out);
        break;
      }
      case TRACE_FLAGS: {
        uint64_t value = t->regs().flags();
        print_value(t->arch() == x86 ? "eflags" : "rflags", &value,
                    sizeof(value), true, raw, out);
        break;
      }
      case TRACE_ORIG_AX: {
        uint64_t value = t->regs().original_syscallno();
        print_value(t->arch() == x86 ? "orig_eax" : "orig_rax", &value,
                    sizeof(value), true, raw, out);
        break;
      }
      case TRACE_SEG_REG: {
        uint64_t value = seg_reg(t->regs(), field.reg_num);
        print_value(seg_reg_names[field.reg_num], &value, sizeof(value), true,
                    raw, out);
        break;
      }
      case TRACE_XINUSE: {
        bool defined;
        uint64_t value = t->extra_regs().read_xinuse(&defined);
        print_value("xinuse", &value, sizeof(value), true, raw, out);
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
        print_value(name, &value, sizeof(value), true, raw, out);
        break;
      }
      case TRACE_XMM_REG: {
        uint8_t value[16];
        bool defined;
        switch (t->arch()) {
          case x86:
            if (field.reg_num < 8) {
              t->extra_regs().read_register(
                  value, GdbServerRegister(DREG_XMM0 + field.reg_num), &defined);
            } else {
              memset(value, 0, sizeof(value));
            }
            break;
          case x86_64:
            if (field.reg_num < 16) {
              t->extra_regs().read_register(
                  value, GdbServerRegister(DREG_64_XMM0 + field.reg_num), &defined);
            } else {
              memset(value, 0, sizeof(value));
            }
            break;
          default:
            FATAL() << "Unexpected architecture";
        }
        char buf[8];
        sprintf(buf, "xmm%d", field.reg_num);
        print_value(buf, value, sizeof(value), true, raw, out);
        break;
      }
      case TRACE_YMM_REG: {
        uint8_t value[32];
        bool defined;
        switch (t->arch()) {
          case x86:
            if (field.reg_num < 8) {
              t->extra_regs().read_register(
                  value, GdbServerRegister(DREG_XMM0 + field.reg_num), &defined);
              t->extra_regs().read_register(
                  value + 16, GdbServerRegister(DREG_YMM0H + field.reg_num),
                  &defined);
            } else {
              memset(value, 0, sizeof(value));
            }
            break;
          case x86_64:
            if (field.reg_num < 16) {
              t->extra_regs().read_register(
                  value, GdbServerRegister(DREG_64_XMM0 + field.reg_num), &defined);
              t->extra_regs().read_register(
                  value + 16, GdbServerRegister(DREG_64_YMM0H + field.reg_num),
                  &defined);
            } else {
              memset(value, 0, sizeof(value));
            }
            break;
          default:
            FATAL() << "Unexpected architecture";
        }
        char buf[8];
        sprintf(buf, "ymm%d", field.reg_num);
        print_value(buf, value, sizeof(value), true, raw, out);
        break;
      }
      case TRACE_FIP: {
        bool defined;
        uint64_t value = t->extra_regs().read_fip(&defined);
        print_value("fip", &value, sizeof(value), true, raw, out);
        break;
      }
      case TRACE_FOP: {
        bool defined;
        uint16_t value = t->extra_regs().read_fop(&defined);
        print_value("fop", &value, sizeof(value), true, raw, out);
        break;
      }
      case TRACE_MXCSR: {
        bool defined;
        uint32_t value = t->extra_regs().read_mxcsr(&defined);
        print_value("mxcsr", &value, sizeof(value), true, raw, out);
        break;
      }
      case TRACE_TID:
        print_value("tid", &t->rec_tid, sizeof(t->rec_tid), false, raw, out);
        break;
      case TRACE_TICKS: {
        Ticks ticks = t->tick_count();
        print_value("ticks", &ticks, sizeof(ticks), false, raw, out);
        break;
      }
    }
  }

  fputc('\n', out);
}

bool parse_trace_fields(const string& value, vector<TraceField>* out) {
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
    } else if (reg == "fip") {
      out->push_back({ TRACE_FIP, 0 });
    } else if (reg == "fop") {
      out->push_back({ TRACE_FOP, 0 });
    } else if (reg == "mxcsr") {
      out->push_back({ TRACE_MXCSR, 0});
    } else if (reg == "tid") {
      out->push_back({ TRACE_TID, 0 });
    } else if (reg == "ticks") {
      out->push_back({ TRACE_TICKS, 0 });
    } else {
      fprintf(stderr, "Unknown register '%s'\n", reg.c_str());
      return false;
    }
  } while (s.size() > 0);
  return true;
}

} // namespace rr
