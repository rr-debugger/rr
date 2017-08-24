/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#define _BSD_SOURCE

#include "Command.h"

#include <stdio.h>
#include <string.h>

#include <algorithm>

#include "TraceStream.h"
#include "core.h"
#include "main.h"

using namespace std;

namespace rr {

bool ParsedOption::verify_valid_int(int64_t min, int64_t max) const {
  if (int_value < min || int_value > max) {
    fprintf(
        stderr,
        "Value %s for parameter %s was not valid (allowed range %lld-%lld)\n",
        value.c_str(), arg.c_str(), (long long)min, (long long)max);
    return false;
  }
  return true;
}

static vector<Command*>* command_list;

Command::Command(const char* name, const char* help) : name(name), help(help) {
  if (!command_list) {
    command_list = new vector<Command*>();
  }
  command_list->push_back(this);
}

Command* Command::command_for_name(const std::string& name) {
  for (auto& it : *command_list) {
    if (strcmp(it->name, name.c_str()) == 0) {
      return it;
    }
  }
  return nullptr;
}

bool Command::less_than_by_name(Command* c1, Command* c2) {
  return strcmp(c1->name, c2->name) < 0;
}

void Command::print_help_all(FILE* out) {
  vector<Command*> cmds;
  for (auto& it : *command_list) {
    if (!it->help) {
      continue;
    }
    cmds.push_back(it);
  }

  sort(cmds.begin(), cmds.end(), less_than_by_name);

  for (auto& it : cmds) {
    const char* c = strchr(it->help, '\n');
    if (c) {
      fprintf(out, "%.*s\n", (int)(c - it->help), it->help);
    } else {
      fputs(it->help, out);
    }
  }
}

void Command::print_help(FILE* out) {
  if (help) {
    fputs(help, out);
    print_global_options(out);
  } else {
    print_usage(out);
  }
}

static bool consume_args(std::vector<std::string>& args, size_t count) {
  args.erase(args.begin(), args.begin() + count);
  return true;
}

static void assign_param(ParsedOption* opt, const char* s) {
  opt->value = s;
  opt->int_value = INT64_MIN;
  if (!opt->value.empty()) {
    char* end;
    int64_t v = strtoll(s, &end, 10);
    if (*end == 0) {
      opt->int_value = v;
    }
  }
}

bool Command::parse_option(std::vector<std::string>& args,
                           const OptionSpec* option_specs, size_t count,
                           ParsedOption* out) {
  if (args.size() == 0 || args[0][0] != '-') {
    return false;
  }

  out->arg = args[0];

  for (size_t i = 0; i < count; ++i) {
    if (args[0][1] == option_specs[i].short_name && args[0][1] >= 32) {
      out->short_name = option_specs[i].short_name;
      switch (option_specs[i].param) {
        case NO_PARAMETER:
          if (args[0][2] == 0) {
            return consume_args(args, 1);
          }
          return false;
        case HAS_PARAMETER:
          if (args[0][2] == '=') {
            assign_param(out, args[0].c_str() + 3);
            return consume_args(args, 1);
          }
          if (args[0][2] != 0) {
            assign_param(out, args[0].c_str() + 2);
            return consume_args(args, 1);
          }
          if (args.size() >= 2) {
            assign_param(out, args[1].c_str());
            return consume_args(args, 2);
          }
          return false;
        default:
          DEBUG_ASSERT(0 && "Unknown parameter type");
      }
    } else if (args[0][1] == '-') {
      size_t equals = args[0].find('=');
      if (strncmp(args[0].c_str() + 2, option_specs[i].long_name,
                  (equals == string::npos ? 9999 : equals) - 2) == 0) {
        out->short_name = option_specs[i].short_name;
        switch (option_specs[i].param) {
          case NO_PARAMETER:
            return consume_args(args, 1);
          case HAS_PARAMETER:
            if (equals == string::npos) {
              if (args.size() >= 2) {
                assign_param(out, args[1].c_str());
                return consume_args(args, 2);
              }
              return false;
            }
            assign_param(out, args[0].c_str() + equals + 1);
            return consume_args(args, 1);
          default:
            DEBUG_ASSERT(0 && "Unknown parameter type");
        }
      }
    }
  }

  return false;
}

bool Command::verify_not_option(std::vector<std::string>& args) {
  if (args.size() > 0 && args[0][0] == '-') {
    fprintf(stderr, "Invalid option %s\n", args[0].c_str());
    return false;
  }
  return true;
}

bool Command::parse_optional_trace_dir(vector<string>& args, string* out) {
  if (!verify_not_option(args)) {
    return false;
  }
  if (args.size() > 0) {
    *out = args[0];
    args.erase(args.begin());
  } else {
    *out = string();
  }
  return true;
}

bool Command::parse_literal(std::vector<std::string>& args, const char* lit) {
  if (args.size() > 0 && args[0] == lit) {
    args.erase(args.begin());
    return true;
  } else {
    return false;
  }
}

} // namespace rr
