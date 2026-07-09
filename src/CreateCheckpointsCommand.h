#pragma once

#include "Command.h"
#include <cstdint>

namespace rr {

using FrameTime = int64_t;

struct CreateCheckpointsFlags {
  uint64_t events_interval = 0;
  uint64_t start_event = 0;
  uint64_t end_event = UINT64_MAX;
};

class CreateCheckpointsCommand : Command {
public:
  virtual int run(std::vector<std::string>& args) override;

  static CreateCheckpointsCommand* get() { return &singleton; }

protected:
  CreateCheckpointsCommand(const char* name, const char* help)
      : Command(name, help) {}

  static CreateCheckpointsCommand singleton;

private:
  /* Runs the actual replay, creating checkpoints at events
   * `frames_to_checkpoint_at`. */
  int run_main(const std::string& trace_dir,
               const std::vector<FrameTime>& frames_to_checkpoint_at);

  /* Returns events to checkpoint at given an `interval`. If `report_total` as
   * an out parameter, will report total event count of trace. */
  static std::vector<FrameTime> find_events_to_checkpoint(
      const std::string& trace_dir, const CreateCheckpointsFlags& interval);
  bool verify_params_ok(const CreateCheckpointsFlags& cp);
};

} // namespace rr
