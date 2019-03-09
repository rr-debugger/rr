/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include <iostream>

#include "log.h"
#include "Command.h"
#include "ElfReader.h"
#include "ScopedFd.h"

using namespace std;

namespace rr {

class BuildidCommand : public Command {
public:
  virtual int run(vector<string>& args) override;

protected:
  BuildidCommand(const char* name, const char* help) : Command(name, help) {}

  static BuildidCommand singleton;
};

BuildidCommand BuildidCommand::singleton(
  "buildid",
  " rr buildid\n"
  "  Accepts paths on stdin, prints buildids on stdout. Will terminate when\n"
  "  either an empty line or an invalid path is provided.\n");

int BuildidCommand::run(vector<string>& args) {
  if (!args.empty()) {
    fprintf(stderr, "Unexpected arguments!");
    return 1;
  }

  string input;
  while (getline(cin, input)) {
    if (input.empty()) {
      break;
    }

    ScopedFd fd = ScopedFd(input.c_str(), O_RDONLY, 0);
    if (!fd.is_open()) {
      LOG(error) << "Failed to open `" << input << "`";
      return 1;
    }

    ElfFileReader reader(fd);
    auto buildid = reader.read_buildid();
    fprintf(stdout, "%s\n", buildid.c_str());
  }

  return 0;
}

} // namespace rr
