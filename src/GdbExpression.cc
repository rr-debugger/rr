/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "GdbExpression.h"

#include "GdbServer.h"
#include "Task.h"
#include "core.h"

using namespace std;

namespace rr {

#define WORKAROUND_GDB_BUGS

// Extracted from
// https://sourceware.org/gdb/current/onlinedocs/gdb/Bytecode-Descriptions.html
enum Opcode {
  OP_float = 0x01,
  OP_add = 0x02,
  OP_sub = 0x03,
  OP_mul = 0x04,
  OP_div_signed = 0x05,
  OP_div_unsigned = 0x06,
  OP_rem_signed = 0x07,
  OP_rem_unsigned = 0x08,
  OP_lsh = 0x09,
  OP_rsh_signed = 0x0a,
  OP_rsh_unsigned = 0x0b,
  OP_trace = 0x0c,
  OP_trace_quick = 0x0d,
  OP_log_not = 0x0e,
  OP_bit_and = 0x0f,
  OP_bit_or = 0x10,
  OP_bit_xor = 0x11,
  OP_bit_not = 0x12,
  OP_equal = 0x13,
  OP_less_signed = 0x14,
  OP_less_unsigned = 0x15,
  OP_ext = 0x16,
  OP_ref8 = 0x17,
  OP_ref16 = 0x18,
  OP_ref32 = 0x19,
  OP_ref64 = 0x1a,
  OP_ref_float = 0x1b,
  OP_ref_double = 0x1c,
  OP_ref_long_double = 0x1d,
  OP_l_to_d = 0x1e,
  OP_d_to_l = 0x1f,
  OP_if_goto = 0x20,
  OP_goto = 0x21,
  OP_const8 = 0x22,
  OP_const16 = 0x23,
  OP_const32 = 0x24,
  OP_const64 = 0x25,
  OP_reg = 0x26,
  OP_end = 0x27,
  OP_dup = 0x28,
  OP_pop = 0x29,
  OP_zero_ext = 0x2a,
  OP_swap = 0x2b,
  OP_getv = 0x2c,
  OP_setv = 0x2d,
  OP_tracev = 0x2e,
  OP_tracenz = 0x2f,
  OP_trace16 = 0x30,
  OP_pick = 0x32,
  OP_rot = 0x33,
  OP_printf = 0x34,
};

struct ExpressionState {
  typedef GdbExpression::Value Value;

  ExpressionState(const vector<uint8_t>& bytecode)
      : bytecode(bytecode), pc(0), error(false), end(false) {}

  void set_error() { error = true; }

  // Methods set error to true if there's an error and return some sentinel
  // Value.
  Value pop() {
    if (stack.empty()) {
      set_error();
      return Value(-1);
    }
    Value v = stack.back();
    stack.pop_back();
    return v;
  }
  struct BinaryOperands {
    BinaryOperands(int64_t a = 0, int64_t b = 0) : a(a), b(b) {}
    int64_t a;
    int64_t b;
  };
  BinaryOperands pop_a_b() {
    int64_t b = pop().i;
    return BinaryOperands(pop().i, b);
  }
  int64_t nonzero(int64_t v) {
    if (!v) {
      set_error();
      return 1;
    }
    return v;
  }
  int64_t pop_a() { return pop().i; }
  void push(int64_t i) { stack.push_back(Value(i)); }
  template <typename T> T fetch() {
    if (pc + sizeof(T) > bytecode.size()) {
      set_error();
      return T(-1);
    }
    T v = 0;
    for (size_t i = 0; i < sizeof(T); ++i) {
      v = (v << 8) | bytecode[pc + i];
    }
    pc += sizeof(T);
    return v;
  }
  template <typename T> void load(Task* t) {
    uint64_t addr = pop().i;
    if (error) {
      // Don't do unnecessary syscalls if we're already in an error state.
      return;
    }
    bool ok = true;
    T v = t->read_mem(remote_ptr<T>(addr), &ok);
    if (!ok) {
      set_error();
      return;
    }
    push(v);
  }
  void pick(size_t offset) {
    if (offset >= stack.size()) {
      set_error();
      return;
    }
    push(stack[stack.size() - 1 - offset].i);
  }

  void step(Task* t) {
    DEBUG_ASSERT(!error);
    BinaryOperands operands;
    switch (fetch<uint8_t>()) {
      case OP_add:
        operands = pop_a_b();
        return push(operands.a + operands.b);
      case OP_sub:
        operands = pop_a_b();
        return push(operands.a - operands.b);
      case OP_mul:
        operands = pop_a_b();
        return push(operands.a * operands.b);
      case OP_div_signed:
        operands = pop_a_b();
        return push(operands.a / nonzero(operands.b));
      case OP_div_unsigned:
        operands = pop_a_b();
        return push(uint64_t(operands.a) / uint64_t(nonzero(operands.b)));
      case OP_rem_signed:
        operands = pop_a_b();
        return push(operands.a % nonzero(operands.b));
      case OP_rem_unsigned:
        operands = pop_a_b();
        return push(uint64_t(operands.a) % uint64_t(nonzero(operands.b)));
      case OP_lsh:
        operands = pop_a_b();
        return push(operands.a << operands.b);
      case OP_rsh_signed:
        operands = pop_a_b();
        return push(operands.a >> operands.b);
      case OP_rsh_unsigned:
        operands = pop_a_b();
        return push(uint64_t(operands.a) >> operands.b);
      case OP_log_not:
        return push(!pop_a());
      case OP_bit_and:
        operands = pop_a_b();
        return push(operands.a & operands.b);
      case OP_bit_or:
        operands = pop_a_b();
        return push(operands.a | operands.b);
      case OP_bit_xor:
        operands = pop_a_b();
        return push(operands.a ^ operands.b);
      case OP_bit_not:
        return push(~pop_a());
      case OP_equal:
        operands = pop_a_b();
        return push(operands.a == operands.b);
      case OP_less_signed:
        operands = pop_a_b();
        return push(operands.a < operands.b);
      case OP_less_unsigned:
        operands = pop_a_b();
        return push(uint64_t(operands.a) < uint64_t(operands.b));
      case OP_ext: {
        int64_t n = nonzero(fetch<uint8_t>());
        if (n >= 64) {
          return;
        }
        int64_t a = pop_a();
        int64_t n_mask = (int64_t(1) << n) - 1;
        int sign_bit = (a >> (n - 1)) & 1;
        return push((sign_bit * ~n_mask) | (a & n_mask));
      }
      case OP_zero_ext: {
        int64_t n = fetch<uint8_t>();
        if (n >= 64) {
          return;
        }
        int64_t a = pop_a();
        int64_t n_mask = (int64_t(1) << n) - 1;
        return push(a & n_mask);
      }
      case OP_ref8:
        return load<uint8_t>(t);
      case OP_ref16:
        return load<uint16_t>(t);
      case OP_ref32:
        return load<uint32_t>(t);
      case OP_ref64:
        return load<uint64_t>(t);
      case OP_dup:
        return pick(0);
      case OP_swap:
        operands = pop_a_b();
        push(operands.b);
        return push(operands.a);
      case OP_pop:
        pop_a();
        return;
      case OP_pick:
        return pick(fetch<uint8_t>());
      case OP_rot: {
        int64_t c = pop_a();
        int64_t b = pop_a();
        int64_t a = pop_a();
        push(c);
        push(b);
        return push(a);
      }
      case OP_if_goto: {
        uint16_t offset = fetch<uint16_t>();
        if (pop_a()) {
          pc = offset;
        }
        return;
      }
      case OP_goto:
        pc = fetch<uint16_t>();
        return;
      case OP_const8:
        return push(fetch<uint8_t>());
      case OP_const16:
        return push(fetch<uint16_t>());
      case OP_const32:
        return push(fetch<uint32_t>());
      case OP_const64:
        return push(fetch<uint64_t>());
      case OP_reg: {
        GdbRegisterValue v = GdbServer::get_reg(t->regs(), t->extra_regs(),
                                                GdbRegister(fetch<uint16_t>()));
        if (!v.defined) {
          set_error();
          return;
        }
        switch (v.size) {
          case 1:
            return push(v.value1);
          case 2:
            return push(v.value2);
          case 4:
            return push(v.value4);
          case 8:
            return push(v.value8);
        }
        set_error();
        return;
      }
      case OP_end:
        end = true;
        return;
      default:
        set_error();
        return;
    }
  }

  const vector<uint8_t>& bytecode;
  vector<Value> stack;
  size_t pc;
  bool error;
  bool end;
};

#ifdef WORKAROUND_GDB_BUGS
/* https://sourceware.org/bugzilla/show_bug.cgi?id=18617 means that
 * gdb generates incorrect operands for OP_ext and OP_zero_ext.
 * We work around this bug by generating all the alternative programs that gdb
 * maybe should have generated, and evaluating all of them. If they agree on
 * the result, we return that as the correct result, otherwise we return
 * failure.
 */
static int count_variants(int bits) {
  int result = 1;
  if (bits > 8) {
    ++result;
  }
  if (bits > 16) {
    ++result;
  }
  if (bits > 32) {
    ++result;
  }
  return result;
}

template <typename T>
static T fetch(const uint8_t* data, size_t size, size_t pc) {
  if (pc + sizeof(T) > size) {
    return T(-1);
  }
  T v = 0;
  for (size_t i = 0; i < sizeof(T); ++i) {
    v = (v << 8) | data[pc + i];
  }
  return v;
}

GdbExpression::GdbExpression(const uint8_t* data, size_t size) {
  vector<bool> instruction_starts;
  instruction_starts.resize(size);
  fill(instruction_starts.begin(), instruction_starts.end(), false);

  int64_t num_variants = 1;

  vector<size_t> unvisited;
  unvisited.push_back(0);
  while (!unvisited.empty()) {
    size_t pc = unvisited.back();
    unvisited.pop_back();
    if (pc >= instruction_starts.size() || instruction_starts[pc]) {
      continue;
    }
    instruction_starts[pc] = true;
    switch (data[pc]) {
      case OP_ext:
      case OP_zero_ext:
        if (pc + 1 < size) {
          num_variants *= count_variants(data[pc + 1]);
          if (num_variants > 64) {
            // Too many variants, giving up on this expression
            return;
          }
        }
        unvisited.push_back(pc + 2);
        break;
      case OP_pick:
      case OP_const8:
        unvisited.push_back(pc + 2);
        break;
      case OP_if_goto:
        unvisited.push_back(fetch<uint16_t>(data, size, pc + 1));
        unvisited.push_back(pc + 3);
        break;
      case OP_goto:
        unvisited.push_back(fetch<uint16_t>(data, size, pc + 1));
        break;
      case OP_const16:
      case OP_reg:
        unvisited.push_back(pc + 3);
        break;
      case OP_const32:
        unvisited.push_back(pc + 5);
        break;
      case OP_const64:
        unvisited.push_back(pc + 9);
        break;
      case OP_end:
        break;
      default:
        unvisited.push_back(pc + 1);
        break;
    }
  }

  bytecode_variants.push_back(vector<uint8_t>(data, data + size));
  for (size_t i = 0; i < size; ++i) {
    if (!instruction_starts[i]) {
      continue;
    }
    if ((data[i] == OP_ext || data[i] == OP_zero_ext) && i + 1 < size) {
      uint8_t bits = data[i + 1];
      vector<vector<uint8_t>> variants;
      for (auto& b : bytecode_variants) {
        // gdb perhaps should have used a smaller type width here --- 8, 16 or
        // 32 bits.
        if (bits > 8) {
          vector<uint8_t> v = b;
          v[i + 1] = 8;
          variants.push_back(move(v));
        }
        if (bits > 16) {
          vector<uint8_t> v = b;
          v[i + 1] = 16;
          variants.push_back(move(v));
        }
        if (bits > 32) {
          vector<uint8_t> v = b;
          v[i + 1] = 32;
          variants.push_back(move(v));
        }
        variants.push_back(move(b));
      }
      bytecode_variants = move(variants);
    }
  }
}
#else
GdbExpression::GdbExpression(const uint8_t* data, size_t size) {
  bytecode_variants.push_back(vector<uint8_t>(data, data + size));
}
#endif

bool GdbExpression::evaluate(Task* t, Value* result) const {
  if (bytecode_variants.empty()) {
    return false;
  }

  bool first = true;

  for (auto& b : bytecode_variants) {
    ExpressionState state(b);
    for (int steps = 0; !state.end; ++steps) {
      if (steps >= 10000 || state.error) {
        return false;
      }
      state.step(t);
    }
    Value v = state.pop();
    if (state.error) {
      return false;
    }
    if (first) {
      *result = v;
      first = false;
    } else if (*result != v) {
      return false;
    }
  }

  return true;
}

} // namespace rr
