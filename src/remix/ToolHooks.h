/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_TOOL_HOOKS_H_
#define RR_TOOL_HOOKS_H_

#include "dr_api.h"

#include "Translation.h"
#include "remix.h"
#include "remix_util.h"

struct GeneratedFragment {
  GeneratedFragment()
      : translation(nullptr),
        next_pc(nullptr),
        have_next_pc(false),
        did_run(false) {}
  void set_next_pc(app_pc pc) {
    remix_assert(!have_next_pc);
    next_pc = pc;
    have_next_pc = true;
  }
  Translation* translation;
  // PC of a fragment that needs to be generated immediately after this one,
  // if |have_next_pc|.
  app_pc next_pc;
  // We need a separate bool for this because null is a valid value for
  // |next_pc|. User code can't really exist there, but it can jump there.
  // Avoid testing application PC values for null!!!
  bool have_next_pc;
  // When this is true, have_next_pc must be false. We ran the fragment
  // (from first_fragment) as well as generating it.
  bool did_run;
};

enum { DID_EXECUTE_FINAL_FRAGMENT_ABORTED = 0x01 };

enum HaveOriginalData {
  HAVE_ORIGINAL_DATA,
  HAVE_NEW_DATA,
};

class ToolHooks {
public:
  virtual ~ToolHooks() {}

  /* General-purpose hooks. It's safe to change engine state during these
   * hooks.
   */

  /* Called before replaying an event that executes code. */
  virtual void notify_will_execute(pid_t /*rec_tid*/,
                                   uint32_t /*rec_tid_serial*/,
                                   TraceFrameTime /*event*/) {}
  virtual bool needs_notify_will_write_range() { return false; }
  /* This is called while the data in memory have their initial values */
  virtual void notify_will_modify_range(
      uintptr_t /*start*/, size_t /*size*/,
      HaveOriginalData /*have_original_data*/) {}
  virtual void notify_modified_range(const ModifiedRangeAndProt&) {}
  /* Called every time we're about to execute code at `pc`. Only happens if
   * add_visit_ip(pc) was called. Note that this can be called even if there is
   * no code to run at `pc`, i.e. an exception is about to be generated instead
   * of actually running code.
   * This hook can modify remix_registers.rip. If it's modified, notify_visit_pc
   * will *not* be called for the new pc. If the tool needs such processing it
   * can do it internally.
   */
  virtual void notify_visit_pc(app_pc /*pc*/) {}
  virtual void notify_did_execute() {}
  /**
   * Called in the child after a successful fork.
   */
  virtual void did_fork_child(pid_t /*rec_tid*/, uint32_t /*rec_tid_serial*/,
                              TraceFrameTime /*event*/) {}
  virtual void notify_will_full_reset() {}
  virtual void did_full_reset() {}
  virtual void did_invalidate() {}
  // The passed-in event number is the event for entry to the execve. So it's
  // not associated with mmaps and writes performed after the exec.
  virtual void notify_will_exec(TraceFrameTime) {}
  /* Called when a thread exits in the trace. This is not called if
   * the replay is terminated via kill_all_tasks (at the end of a shard
   * where the thread outlives the shard).
   */
  virtual void notify_will_exit(pid_t, uint32_t, TraceFrameTime, uint32_t) {}
  /* Called when a thread exits in the trace, before we unmap its scratch/
   * syscallbuf.
   */
  virtual void notify_will_unmap(pid_t, uint32_t, TraceFrameTime) {}

  /* It is *not* safe to change engine state during this hook. */
  virtual GeneratedFragment generate_one_fragment(app_pc pc,
                                                  Fragment first_fragment) = 0;
};

extern ToolHooks* tool_hooks;

ToolHooks* tool_init(intptr_t* init_cookie);

#endif /* RR_TOOL_HOOKS_H_ */
