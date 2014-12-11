/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#define _BSD_SOURCE

#include "Command.h"

#include <assert.h>
#include <string.h>

#include "TraceStream.h"

using namespace std;

bool ParsedOption::verify_valid_int(int64_t min, int64_t max) const {
  if (int_value < min || int_value > max) {
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

void Command::print_help_all(FILE* out) {
  for (auto& it : *command_list) {
    if (!it->help) {
      continue;
    }
    const char* c = strchr(it->help, '\n');
    if (c) {
      fprintf(out, "%.*s\n", (int)(c - it->help), it->help);
    } else {
      fputs(it->help, out);
    }
  }
}

void Command::print_help(FILE* out) { fputs(help, out); }

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

  for (size_t i = 0; i < count; ++i) {
    if (args[0][1] == option_specs[i].short_name) {
      out->short_name = option_specs[i].short_name;
      switch (option_specs[i].param) {
        case NO_PARAMETER:
          if (args[0][2] == 0) {
            return consume_args(args, 1);
          }
          return false;
        case HAS_PARAMETER:
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
          assert(0 && "Unknown parameter type");
      }
    } else if (args[0][1] == '-' &&
               strcmp(args[0].c_str() + 2, option_specs[i].long_name) == 0) {
      out->short_name = option_specs[i].short_name;
      switch (option_specs[i].param) {
        case NO_PARAMETER:
          return consume_args(args, 1);
        case HAS_PARAMETER:
          if (args.size() >= 2) {
            assign_param(out, args[1].c_str());
            return consume_args(args, 2);
          }
          return false;
        default:
          assert(0 && "Unknown parameter type");
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
