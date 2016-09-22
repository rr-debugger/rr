/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_GDB_EXPRESSION_H_
#define RR_GDB_EXPRESSION_H_

#include <stddef.h>
#include <stdint.h>

#include <vector>

namespace rr {

class Task;

/**
 * gdb has a simple bytecode language for writing expressions to be evaluated
 * in a remote target. This class implements evaluation of such expressions.
 * See https://sourceware.org/gdb/current/onlinedocs/gdb/Agent-Expressions.html
 */
class GdbExpression {
public:
  GdbExpression(const uint8_t* data, size_t size);

  struct Value {
    Value(int64_t i = 0) : i(i) {}
    bool operator==(const Value& v) { return i == v.i; }
    bool operator!=(const Value& v) { return !(*this == v); }
    int64_t i;
  };
  /**
   * If evaluation succeeds, store the final result in *result and return true.
   * Otherwise return false.
   */
  bool evaluate(Task* t, Value* result) const;

private:
  /**
   * To work around gdb bugs, we may generate and evaluate multiple versions of
   * the same expression program.
   */
  std::vector<std::vector<uint8_t>> bytecode_variants;
};

} // namespace rr

#endif // RR_GDB_EXPRESSION_H_
