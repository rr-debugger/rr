/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_REMIX_MODULE_H_
#define RR_REMIX_MODULE_H_

#include <string.h>
#include <sys/mman.h>

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "MemoryRange.h"
#include "Ticks.h"
#include "remote_code_ptr.h"
#include "remote_ptr.h"

#include "remix/remix.h"

namespace rr {

class ElfFileReader;
class Registers;
class RemixModule;
class ReplayTask;

class RemixToolHost {
public:
  virtual ~RemixToolHost() {}
  // Gets called when the module is loaded and initialized. *NOT* called after
  // the module is forked.
  virtual void notify_remix_module_attach(ReplayTask*, RemixModule*) {}
  virtual void notify_remix_module_detach(RemixModule*) {}

  // This is where it's safe to flush changes through the RemixModule
  virtual void will_change_state(ReplayTask*, RemixModule*) {}
  // It is not safe to flush changes to the RemixModule in this function.
  // Buffer the notification and flush it in `will_change_state`.
  virtual void notify_mapped(ReplayTask*, RemixModule*, const MemoryRange&,
                             int /*prot*/) {}
};

struct RemixTestOptions {
  bool force_emulate_amd : 1;
  bool force_emulate_no_lzcnt_tzcnt : 1;
  bool force_emulate_xsave_region_layout_difference : 1;
};

const RemixTestOptions DEFAULT_TEST_OPTIONS = RemixTestOptions { false, false, false };

class RemixModule {
public:
  typedef std::shared_ptr<RemixModule> shr_ptr;

  /**
   * |mem| is the memory range available for the module.
   * |path| is the path to the .so, minus the ".so". We'll append "_32" if
   * |t| is a 32-bit process under 64-bit rr.
   */
  RemixModule(ReplayTask* t, const MemoryRange& mem, const std::string& path,
              std::shared_ptr<RemixToolHost> host = nullptr,
              intptr_t init_cookie = 0, RemixTestOptions test_options = DEFAULT_TEST_OPTIONS);

  /**
   * Clone an existing module (used when cloning a ReplaySession).
   * The associated AddressSpace must be cloned by the caller and the process
   * fork()ed.
   */
  RemixModule(const RemixModule& other);

  ~RemixModule();

  void unload(ReplayTask* t);

  enum SinglestepMode { SINGLESTEP_NONE, SINGLESTEP, SINGLESTEP_FAST_FORWARD };
  enum TargetMatchMode { MATCH_GP_REGS, MATCH_IP_ONLY };
  /**
   * Invoke remix_execute to run |t| until we are about to enter a syscall.
   * Execution stops at the next syscall instruction, before entering the
   * kernel.
   */
  StopReason execute_to_syscall(ReplayTask* t,
                                SinglestepMode step = SINGLESTEP_NONE);
  /**
   * Invoke remix_execute to run |t| until we reach address |ip|.
   */
  StopReason execute_to_ip(ReplayTask* t, remote_code_ptr ip,
                           SinglestepMode step = SINGLESTEP_NONE);
  /**
   * Invoke remix_execute to run |t| until we reach address |ip|.
   */
  StopReason execute_to_breakpoint_fault(ReplayTask* t, remote_code_ptr ip,
                                         SinglestepMode step = SINGLESTEP_NONE);
  /**
   * Invoke remix_execute to run |t| until we reach address |ip| in a way
   * suitable for emulating |ip|.
   */
  StopReason execute_emulate_ip(ReplayTask* t, remote_code_ptr ip,
                                SinglestepMode step = SINGLESTEP_NONE);
  /**
   * Invoke remix_execute to run |t| until we reach registers |regs| and
   * tick count |ticks|.
   */
  StopReason execute_to_target(ReplayTask* t, const Registers& target_regs,
                               Ticks target_ticks,
                               SinglestepMode step = SINGLESTEP_NONE,
                               TargetMatchMode match = MATCH_GP_REGS);

  /**
   * Notify that |t| is about to change state without any instructions having
   * been executed, i.e. a syscall-exit or signal-handler-transition event.
   */
  void will_change_state_without_execution(ReplayTask* t);
  /**
   * Flush all pending state changes so remix module state is up to date.
   */
  void flush_pending_state(ReplayTask* t);
  /**
   * Notify that |t| just completed an execve event that should be processed and
   * was not otherwise notified (because we just loaded the module).
   */
  void did_complete_execve(ReplayTask* t);

  /**
   * Look up a symbol. Only remix_ symbols are included. Returns null if
   * not found.
   */
  remote_ptr<void> find_symbol(const char* symbol) const;
  remote_code_ptr find_code_symbol(const char* symbol) const;

  remote_ptr<void> free_start() const { return module_end; }
  remote_ptr<void> free_end() const { return saved_before_write_start; }
  remote_ptr<void> stack_top() const { return mem_end; }

  /**
   * Transfer control to the module function |ip| and take back control
   * when it returns.
   */
  template <typename... Rest>
  intptr_t call(ReplayTask* t, remote_code_ptr ip, Rest... args) const {
    std::vector<uint8_t> stack_data;
    std::vector<intptr_t> params;
    return call_helper(t, ip, params, stack_data, args...);
  }

  /**
   * The total address space allocated to the module. Not all of this
   * will be mapped, in practice most of it won't be.
   */
  MemoryRange memory_range() const;

  std::string gdb_helpers() const;
  std::string tool_path() const { return tool_path_; }

  /**
   * Notifications sent by AddressSpace. It's not safe to call into the remix
   * module in these notifications, so we buffer the notifications to deliver
   * at the next execute_ (but only if there's been a previous execute_).
   */
  void notify_mapped(ReplayTask* t, const MemoryRange& range, int prot) {
    if (in_call) {
      return;
    }
    if (host) {
      host->notify_mapped(t, this, range, prot);
    }
    notify_memory_change(t, range, prot, MEM_MAP, 0);
  }
  /**
   * These come in pairs. A notify_will_write is always followed by
   * notify_written (after the memory has been written) before any
   * other notify_will_write.
   */
  void notify_will_write(ReplayTask*, const MemoryRange&);
  void notify_written(ReplayTask* t, const MemoryRange& range);
  /**
   * Notify that a breakpoint was added or removed.
   * Tools do not treat this as a memory write but we may need to
   * invalidate translations.
   */
  void notify_breakpoint_changed(ReplayTask* t, const MemoryRange& range) {
    notify_memory_change(t, range, -1, MEM_WRITE_BREAKPOINT, 0);
  }
  /**
   * Notifies of mprotect changes by trapping system calls. Does not notify
   * about mprotect changes caused by syscallbuf syscalls.
   * The remix engine can't just observe mprotect syscalls itself, because
   * it might observe entering an mprotect syscall but the syscall might
   * be cancelled by some ptracer.
   */
  void notify_mprotect(ReplayTask* t, const MemoryRange& range, int new_prot) {
    notify_memory_change(t, range, new_prot, MEM_PROTECT, 0);
  }
  void notify_will_madvise(ReplayTask* t, const MemoryRange& range,
                           int advice) {
    switch (advice) {
      case MADV_DONTNEED:
      case MADV_REMOVE:
        notify_will_write(t, range);
        break;
    }
  }
  void notify_madvise(ReplayTask* t, const MemoryRange& range, int advice) {
    switch (advice) {
      case MADV_DONTNEED:
      case MADV_REMOVE:
        notify_written(t, range);
        break;
    }
  }
  void notify_unmapped(ReplayTask* t, const MemoryRange& range) {
    if (in_call) {
      return;
    }
    notify_memory_change(t, range, 0, MEM_UNMAP, 0);
  }

  void notify_will_exec(ReplayTask* t);
  void notify_will_exit(ReplayTask* t, bool early = false);

  /**
   * Call this before unmapping a memory region. Currently we don't call this
   * before every unmap, instead we rely on execution happening between
   * writes and an unmap, and the execution forces any necessary flushing. But
   * in some cases execution won't happen between writes and an unmap, in which
   * case this must be called. It's always safe to call this.
   */
  void notify_will_unmap(ReplayTask* t);

  void notify_remix_apply_quirk(ReplayTask* t, RemixQuirk quirk, uintptr_t arg2 = 0, uintptr_t arg3 = 0, uintptr_t arg4 = 0, uintptr_t arg5 = 0);

  StopReason last_remix_execute_stop_reason() const { return last_stop_reason; }

  void set_log_modules(ReplayTask* t, uint32_t modules);

  intptr_t init_cookie_returned() const { return init_cookie; }

private:
  void map_segments(ReplayTask* t, const std::string& file_name,
                    ElfFileReader& reader);
  void apply_relocations(ReplayTask* t, ElfFileReader& reader);
  void load_symbols(ElfFileReader& reader);
  void allocate_stack(ReplayTask* t, ElfFileReader& reader);
  void setup_rr_page_syscalls(ReplayTask* t);
  void set_log_modules_from_environment(ReplayTask* t);
  void notify_memory_change(ReplayTask* t, const MemoryRange& range, int prot,
                            MemChangeType change_type,
                            size_t saved_before_write_offset);
  void send_modified_ranges_notifications(ReplayTask* t, remote_code_ptr notify_fn,
                                          std::vector<ModifiedRangeAndProt>& v);
  void apply_saved_before_write_data(ReplayTask* t, std::vector<ModifiedRangeAndProt>& v);

  bool try_handle_segfault(ReplayTask* t,
                           std::vector<MemoryRange>* unmaps) const;
  bool try_handle_crash(ReplayTask* t) const;
  bool try_handle_wx(ReplayTask* t,
                     remote_ptr<void> addr) const;
  bool try_handle_growdown(ReplayTask* t,
                           remote_ptr<void> addr,
                           std::vector<MemoryRange>* unmaps) const;
  intptr_t call_helper(ReplayTask* t, remote_code_ptr ip,
                       const std::vector<intptr_t>& params,
                       std::vector<uint8_t>& stack_data) const;
  template <typename T, typename... Rest>
  intptr_t call_helper(ReplayTask* t, remote_code_ptr ip,
                       std::vector<intptr_t>& params,
                       std::vector<uint8_t>& stack_data, T arg,
                       Rest... args) const {
    push_arg(params, arg, stack_data);
    return call_helper(t, ip, params, stack_data, args...);
  }
  void push_arg(std::vector<intptr_t>& params, remote_ptr<void> ptr,
                std::vector<uint8_t>&) const {
    params.push_back(ptr.as_int());
  }
  void push_arg(std::vector<intptr_t>& params, intptr_t v,
                std::vector<uint8_t>&) const {
    params.push_back(v);
  }
  template <typename T>
  void push_arg(std::vector<intptr_t>& params, const T* ptr,
                std::vector<uint8_t>& stack_data) const {
    insert_data(stack_data, ptr, sizeof(*ptr), 16);
    params.push_back(mem_end.as_int() - stack_data.size());
  }
  template <typename T>
  void push_arg(std::vector<intptr_t>& params, const std::vector<T>& vec,
                std::vector<uint8_t>& stack_data) const {
    insert_data(stack_data, vec.data(), sizeof(vec[0]) * vec.size(), 16);
    params.push_back(mem_end.as_int() - stack_data.size());
  }
  std::vector<uint8_t> sync_reg_state(ReplayTask* t);
  StopReason execute_helper(ReplayTask* t, uint32_t flags,
                            const Registers& target_regs, Ticks target_ticks);
  void flush_other_process_modified_ranges(ReplayTask* t);
  void flush_modified_ranges(ReplayTask* t);
  void handle_structured_remix_error(ReplayTask* t) const;

  static void insert_data(std::vector<uint8_t>& stack_data, const void* p,
                          size_t s, size_t align) {
    size_t size = (s + align - 1) & ~(align - 1);
    size_t current_size = stack_data.size();
    stack_data.resize(size + current_size);
    memmove(stack_data.data() + size, stack_data.data(), current_size);
    memcpy(stack_data.data(), p, s);
    memset(stack_data.data() + s, 0, size - s);
  }

  std::shared_ptr<RemixToolHost> host;

  // Layout of remix module data in tracee virtual memory.

  // Start of remix module area. The remix binary is mapped at this address.
  remote_ptr<void> mem_base;
  // End of remix binary.
  remote_ptr<void> module_end;
  // Everything between module_end and saved_before_write_start is managed by
  // the remix module for its own use.
  // Buffer we use to track memory values before they're overwritten
  remote_ptr<void> saved_before_write_start;
  // Start of remix stack.
  remote_ptr<void> stack_start;
  // End of remix module area.
  remote_ptr<void> mem_end;

  std::unordered_map<std::string, remote_ptr<void>> symbols;
  std::string file_name;
  std::string tool_path_;

  remote_code_ptr execute_fn;
  remote_code_ptr wx_sighandler;
  remote_ptr<uint8_t> remix_registers;
  remote_ptr<uint64_t> remix_rcb;
  remote_ptr<uint8_t> remix_target_registers;
  remote_ptr<uint64_t> remix_target_rcb;
  remote_ptr<RemixSighandlerState> remix_sighandler_state;
  remote_ptr<remote_code_ptr> remix_crash_handler;
  remote_ptr<bool> remix_enable_stack_extension;
  std::vector<ModifiedRangeAndProt> modified_ranges;
  std::vector<uint8_t> saved_before_write_data;
  remote_ptr<void> last_saved_before_write_source;
  uint64_t last_saved_before_write_data;
  size_t last_saved_before_write_data_len;
  uint64_t module_flags;
  intptr_t init_cookie;
  StopReason last_stop_reason;
  bool need_to_call_did_fork_child;
  mutable bool in_call;
};

} // namespace rr

#endif /* RR_REMIX_MODULE_H_ */
