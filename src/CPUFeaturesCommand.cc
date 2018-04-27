/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "Command.h"
#include "GdbServer.h"
#include "main.h"
#include "util.h"

using namespace std;

namespace rr {

class CPUFeaturesCommand : public Command {
public:
  virtual int run(vector<string>& args) override;

protected:
  CPUFeaturesCommand(const char* name, const char* help) : Command(name, help) {}

  static CPUFeaturesCommand singleton;
};

CPUFeaturesCommand CPUFeaturesCommand::singleton(
    "cpufeatures",
    " rr cpufeatures\n"
    "  Print `rr record` command line options that will limit the tracee\n"
    "  to CPU features this machine supports.\n"
    "  Useful for trace portability: run `rr cpufeatures` on the machine\n"
    "  you plan to replay on, then add those command-line parameters to\n"
    "  `rr record` on the recording machine.\n");

int CPUFeaturesCommand::run(vector<string>& args) {
  while (parse_global_option(args)) {
  }

  CPUIDData features = cpuid(CPUID_GETFEATURES, 0);
  CPUIDData extended_features = cpuid(CPUID_GETEXTENDEDFEATURES, 0);
  CPUIDData features_xsave = cpuid(CPUID_GETXSAVE, 1);
  fprintf(stdout, "--disable-cpuid-features 0x%x,0x%x "
          "--disable-cpuid-features-ext 0x%x,0x%x,0x%x "
          "--disable-cpuid-features-xsave 0x%x\n",
          ~features.ecx, ~features.edx,
          ~extended_features.ebx, ~extended_features.ecx,
          ~extended_features.edx, ~features_xsave.eax);
  return 0;
}

} // namespace rr
