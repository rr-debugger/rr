/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_COMMAND_H_
#define RR_COMMAND_H_

#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif

#include <stdint.h>
#include <stdio.h>

#include <memory>
#include <string>
#include <vector>

namespace rr {

class TraceReader;

enum OptionParameters { NO_PARAMETER, HAS_PARAMETER };
struct OptionSpec {
  char short_name;
  const char* long_name;
  OptionParameters param;
};
struct ParsedOption {
  char short_name;
  std::string arg;
  std::string value;
  int64_t int_value;
  bool verify_valid_int(int64_t min = INT64_MIN + 1,
                        int64_t max = INT64_MAX) const;
};

/**
 * rr command-line commands. Objects of this class must be static, since
 * they are expected to be immortal.
 */
class Command {
public:
  static Command* command_for_name(const std::string& name);
  static void print_help_all(FILE* out);

  /* Runs the command with the given parameters. Returns an exit code. */
  virtual int run(std::vector<std::string>& args) = 0;
  void print_help(FILE* out);

  static bool verify_not_option(std::vector<std::string>& args);
  static bool parse_optional_trace_dir(std::vector<std::string>& args,
                                       std::string* out);
  static bool parse_option(std::vector<std::string>& args,
                           const OptionSpec* option_specs, size_t count,
                           ParsedOption* out);
  template <size_t N>
  static bool parse_option(std::vector<std::string>& args,
                           const OptionSpec (&option_specs)[N],
                           ParsedOption* out) {
    return parse_option(args, option_specs, N, out);
  }
  static bool parse_literal(std::vector<std::string>& args, const char* lit);

protected:
  Command(const char* name, const char* help);
  virtual ~Command() {}

  static bool less_than_by_name(Command* c1, Command* c2);

  const char* name;
  const char* help;
};

} // namespace rr

#endif // RR_COMMAND_H_
