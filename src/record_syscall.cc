/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/auxvec.h>
#include <linux/capability.h>
#include <linux/elf.h>
#include <linux/ethtool.h>
#include <linux/fs.h>
#include <linux/futex.h>
#include <linux/hidraw.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <linux/if_tun.h>
#include <linux/input.h>
#include <linux/ipc.h>
#include <linux/joystick.h>
#include <linux/msdos_fs.h>
#include <linux/msg.h>
#include <linux/net.h>
#include <linux/netlink.h>
#include <linux/perf_event.h>
#include <linux/personality.h>
#include <linux/prctl.h>
#include <linux/seccomp.h>
#include <linux/sem.h>
#include <linux/shm.h>
#include <linux/sockios.h>
#include <linux/videodev2.h>
#include <linux/wireless.h>
#include <poll.h>
#include <sched.h>
#include <scsi/sg.h>
#include <sound/asound.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/quota.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/sysinfo.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/un.h>
#include <sys/utsname.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <termios.h>

#include <limits>
#include <sstream>
#include <utility>
#include <unordered_set>

#include <rr/rr.h>

#include "record_syscall.h"

#include "preload/preload_interface.h"

#include "AutoRemoteSyscalls.h"
#include "DiversionSession.h"
#include "Flags.h"
#include "MmappedFileMonitor.h"
#include "ProcFdDirMonitor.h"
#include "ProcMemMonitor.h"
#include "ProcStatMonitor.h"
#include "RecordSession.h"
#include "RecordTask.h"
#include "Scheduler.h"
#include "StdioMonitor.h"
#include "SysCpuMonitor.h"
#include "TraceStream.h"
#include "VirtualPerfCounterMonitor.h"
#include "ftrace.h"
#include "kernel_abi.h"
#include "kernel_metadata.h"
#include "kernel_supplement.h"
#include "log.h"
#include "util.h"

using namespace std;

namespace rr {

union _semun {
  int val;
  struct semid64_ds* buf;
  unsigned short int* array;
  struct seminfo* __buf;
};

/* We can't include <sys/shm.h> to get shmctl because it clashes with
 * linux/shm.h.
 */
static int _shmctl(int shmid, int cmd, shmid64_ds* buf) {
#ifdef SYS_shmctl
  int ret = syscall(SYS_shmctl, shmid, cmd, buf);
  if (ret >= 0 || errno != ENOSYS) {
    return ret;
  }
#endif
#ifdef SYS_ipc
  if (sizeof(void*) == 4) {
    cmd |= IPC_64;
  }
  return syscall(SYS_ipc, SHMCTL, shmid, cmd, 0, buf);
#else
  return ret;
#endif
}
static int _semctl(int semid, int semnum, int cmd, _semun un_arg) {
#ifdef SYS_semctl
  int ret = syscall(SYS_semctl, semid, semnum, cmd, un_arg);
  if (ret >= 0 || errno != ENOSYS) {
    return ret;
  }
#endif
#ifdef SYS_ipc
  if (sizeof(void*) == 4) {
    cmd |= IPC_64;
  }
  return syscall(SYS_ipc, SEMCTL, semid, semnum, cmd, &un_arg);
#else
  return ret;
#endif
}

/**
 * Modes used to register syscall memory parameter with TaskSyscallState.
 */
enum ArgMode {
  // Syscall memory parameter is an in-parameter only.
  // This is only important when we want to move the buffer to scratch memory
  // so we can modify it without making the modifications potentially visible
  // to user code. Otherwise, such parameters can be ignored.
  IN,
  // Syscall memory parameter is out-parameter only.
  OUT,
  // Syscall memory parameter is an in-out parameter.
  IN_OUT,
  // Syscall memory parameter is an in-out parameter but we must not use
  // scratch (e.g. for futexes, we must use the actual memory word).
  IN_OUT_NO_SCRATCH
};

/**
 * Specifies how to determine the size of a syscall memory
 * parameter. There is usually an incoming size determined before the syscall
 * executes (which we need in order to allocate scratch memory), combined
 * with an optional final size taken from the syscall result or a specific
 * memory location after the syscall has executed. The minimum of the incoming
 * and final sizes is used, if both are present.
 */
struct ParamSize {
  ParamSize() : incoming_size(size_t(-1)), from_syscall(false) {}
  // Clamp incoming_size to INTPTR_MAX. No system call can read more data
  // than that in practice (to a single output parameter).
  ParamSize(size_t incoming_size)
      : incoming_size(min<size_t>(INTPTR_MAX, incoming_size)),
        from_syscall(false) {}
  /**
   * p points to a tracee location that is already initialized with a
   * "maximum buffer size" passed in by the tracee, and which will be filled
   * in with the size of the data by the kernel when the syscall exits.
   */
  template <typename T>
  static ParamSize from_initialized_mem(RecordTask* t, remote_ptr<T> p) {
    ParamSize r(p.is_null() ? size_t(0) : size_t(t->read_mem(p)));
    r.mem_ptr = p;
    r.read_size = sizeof(T);
    return r;
  }
  /**
   * p points to a tracee location which will be filled in with the size of
   * the data by the kernel when the syscall exits, but the location
   * is uninitialized before the syscall.
   */
  template <typename T> static ParamSize from_mem(remote_ptr<T> p) {
    ParamSize r;
    r.mem_ptr = p;
    r.read_size = sizeof(T);
    return r;
  }
  /**
   * When the syscall exits, the syscall result will be of type T and contain
   * the size of the data. 'incoming_size', if present, is a bound on the size
   * of the data.
   */
  template <typename T> static ParamSize from_syscall_result() {
    ParamSize r;
    r.from_syscall = true;
    r.read_size = sizeof(T);
    return r;
  }
  template <typename T>
  static ParamSize from_syscall_result(size_t incoming_size) {
    ParamSize r(incoming_size);
    r.from_syscall = true;
    r.read_size = sizeof(T);
    return r;
  }
  /**
   * Indicate that the size will be at most 'max'.
   */
  ParamSize limit_size(size_t max) const {
    ParamSize r(*this);
    r.incoming_size = min(r.incoming_size, max);
    return r;
  }

  /**
   * Return true if 'other' takes its dynamic size from the same source as
   * this.
   * When multiple syscall memory parameters take their dynamic size from the
   * same source, the source size is distributed among them, with the first
   * registered parameter taking up to its max_size bytes, followed by the next,
   * etc. This lets us efficiently record iovec buffers.
   */
  bool is_same_source(const ParamSize& other) const {
    return ((!mem_ptr.is_null() && other.mem_ptr == mem_ptr) ||
            (from_syscall && other.from_syscall)) &&
           (read_size == other.read_size);
  }
  /**
   * Compute the actual size after the syscall has executed.
   * 'already_consumed' bytes are subtracted from the syscall-result/
   * memory-location part of the size.
   */
  size_t eval(RecordTask* t, size_t already_consumed) const;

  size_t incoming_size;
  /** If non-null, the size is limited by the value at this location after
   *  the syscall. */
  remote_ptr<void> mem_ptr;
  /** Size of the value at mem_ptr or in the syscall result register. */
  size_t read_size;
  /** If true, the size is limited by the value of the syscall result. */
  bool from_syscall;
};

size_t ParamSize::eval(RecordTask* t, size_t already_consumed) const {
  size_t s = incoming_size;
  if (!mem_ptr.is_null()) {
    size_t mem_size;
    switch (read_size) {
      case 4:
        mem_size = t->read_mem(mem_ptr.cast<uint32_t>());
        break;
      case 8:
        mem_size = t->read_mem(mem_ptr.cast<uint64_t>());
        break;
      default:
        ASSERT(t, false) << "Unknown read_size";
        return 0;
    }
    ASSERT(t, already_consumed <= mem_size);
    s = min(s, mem_size - already_consumed);
  }
  if (from_syscall) {
    size_t syscall_size = max<ssize_t>(0, t->regs().syscall_result_signed());
    switch (read_size) {
      case 4:
        syscall_size = uint32_t(syscall_size);
        break;
      case 8:
        syscall_size = uint64_t(syscall_size);
        break;
      default:
        ASSERT(t, false) << "Unknown read_size";
        return 0;
    }
    ASSERT(t, already_consumed <= syscall_size);
    s = min(s, syscall_size - already_consumed);
  }
  ASSERT(t, s < size_t(-1));
  return s;
}

typedef bool (*ArgMutator)(RecordTask*, remote_ptr<void>, void*);

/**
 * When tasks enter syscalls that may block and so must be
 * prepared for a context-switch, and the syscall params
 * include (in)outparams that point to buffers, we need to
 * redirect those arguments to scratch memory.  This allows rr
 * to serialize execution of what may be multiple blocked
 * syscalls completing "simultaneously" (from rr's
 * perspective).  After the syscall exits, we restore the data
 * saved in scratch memory to the original buffers.
 *
 * Then during replay, we simply restore the saved data to the
 * tracee's passed-in buffer args and continue on.
 *
 * This is implemented by having rec_prepare_syscall_arch set up
 * a record in param_list for syscall in-memory  parameter (whether
 * "in" or "out"). Then done_preparing is called, which does the actual
 * scratch setup. process_syscall_results is called when the syscall is
 * done, to write back scratch results to the real parameters and
 * clean everything up.
 *
 * ... a fly in this ointment is may-block buffered syscalls.
 * If a task blocks in one of those, it will look like it just
 * entered a syscall that needs a scratch buffer.  However,
 * it's too late at that point to fudge the syscall args,
 * because processing of the syscall has already begun in the
 * kernel.  But that's OK: the syscallbuf code has already
 * swapped out the original buffer-pointers for pointers into
 * the syscallbuf (which acts as its own scratch memory).  We
 * just have to worry about setting things up properly for
 * replay.
 *
 * The descheduled syscall will "abort" its commit into the
 * syscallbuf, so the outparam data won't actually be saved
 * there (and thus, won't be restored during replay).  During
 * replay, we have to restore them like we restore the
 * non-buffered-syscall scratch data. This is done by recording
 * the relevant syscallbuf record data in rec_process_syscall_arch.
 */
struct TaskSyscallState {
  void init(RecordTask* t) {
    if (preparation_done) {
      return;
    }
    this->t = t;
    scratch = t->scratch_ptr;
  }

  /**
   * Identify a syscall memory parameter whose address is in register 'arg'
   * with type T.
   * Returns a remote_ptr to the data in the child (before scratch relocation)
   * or null if parameters have already been prepared (the syscall is
   * resuming).
   */
  template <typename T>
  remote_ptr<T> reg_parameter(int arg, ArgMode mode = OUT,
                              ArgMutator mutator = nullptr) {
    return reg_parameter(arg, sizeof(T), mode, mutator).cast<T>();
  }
  /**
   * Identify a syscall memory parameter whose address is in register 'arg'
   * with size 'size'.
   * Returns a remote_ptr to the data in the child (before scratch relocation)
   * or null if parameters have already been prepared (the syscall is
   * resuming).
   */
  remote_ptr<void> reg_parameter(int arg, const ParamSize& size,
                                 ArgMode mode = OUT,
                                 ArgMutator mutator = nullptr);
  /**
   * Identify a syscall memory parameter whose address is in memory at
   * location 'addr_of_buf_ptr' with type T.
   * Returns a remote_ptr to the data in the child (before scratch relocation)
   * or null if parameters have already been prepared (the syscall is
   * resuming).
   * addr_of_buf_ptr must be in a buffer identified by some init_..._parameter
   * call.
   */
  template <typename T>
  remote_ptr<T> mem_ptr_parameter(remote_ptr<void> addr_of_buf_ptr,
                                  ArgMode mode = OUT,
                                  ArgMutator mutator = nullptr) {
    return mem_ptr_parameter(addr_of_buf_ptr, sizeof(T), mode, mutator)
        .cast<T>();
  }
  /**
   * Identify a syscall memory parameter whose address is in memory at
   * location 'addr_of_buf_ptr' with type T.
   * Returns a remote_ptr to the data in the child (before scratch relocation)
   * or null if parameters have already been prepared (the syscall is
   * resuming).
   * addr_of_buf_ptr must be in a buffer identified by some init_..._parameter
   * call.
   */
  template <typename Ptr>
  remote_ptr<typename Ptr::Referent> mem_ptr_parameter_inferred(
      remote_ptr<Ptr> addr_of_buf_ptr, ArgMode mode = OUT,
      ArgMutator mutator = nullptr) {
    remote_ptr<void> p =
        mem_ptr_parameter(addr_of_buf_ptr, Ptr::referent_size(), mode, mutator);
    return p.cast<typename Ptr::Referent>();
  }
  /**
   * Identify a syscall memory parameter whose address is in memory at
   * location 'addr_of_buf_ptr' with size 'size'.
   * Returns a remote_ptr to the data in the child (before scratch relocation)
   * or null if parameters have already been prepared (the syscall is
   * resuming).
   * addr_of_buf_ptr must be in a buffer identified by some init_..._parameter
   * call.
   */
  remote_ptr<void> mem_ptr_parameter(remote_ptr<void> addr_of_buf_ptr,
                                     const ParamSize& size, ArgMode mode = OUT,
                                     ArgMutator mutator = nullptr);

  typedef void (*AfterSyscallAction)(RecordTask* t);
  // Register a callback to run when the syscall has completed.
  // This runs after parameters have been restored.
  void after_syscall_action(AfterSyscallAction action) {
    after_syscall_actions.push_back(action);
  }

  void emulate_result(uint64_t result) {
    ASSERT(t, !preparation_done);
    ASSERT(t, !should_emulate_result);
    should_emulate_result = true;
    emulated_result = result;
  }

  /**
   * Internal method that takes 'ptr', an address within some memory parameter,
   * and relocates it to the parameter's location in scratch memory.
   */
  remote_ptr<void> relocate_pointer_to_scratch(remote_ptr<void> ptr);
  /**
   * Internal method that takes the index of a MemoryParam and a vector
   * containing the actual sizes assigned to each param < param_index, and
   * computes the actual size to use for parameter param_index.
   */
  size_t eval_param_size(size_t param_index, vector<size_t>& actual_sizes);
  /**
   * Called when all memory parameters have been identified. If 'sw' is
   * ALLOW_SWITCH, sets up scratch memory and updates registers etc as
   * necessary.
   * If scratch can't be used for some reason, returns PREVENT_SWITCH,
   * otherwise returns 'sw'.
   */
  Switchable done_preparing(Switchable sw);
  Switchable done_preparing_internal(Switchable sw);
  enum WriteBack { WRITE_BACK, NO_WRITE_BACK };
  /**
   * Called when a syscall exits to copy results from scratch memory to their
   * original destinations, update registers, etc.
   */
  void process_syscall_results();
  /**
   * Called when a syscall has been completely aborted to undo any changes we
   * made.
   */
  void abort_syscall_results();

  /**
   * Upon successful syscall completion, each RestoreAndRecordScratch record
   * in param_list consumes num_bytes from the t->scratch_ptr
   * buffer, copying the data to remote_dest and recording the data at
   * remote_dest. If ptr_in_reg is greater than zero, updates the task's
   * ptr_in_reg register with 'remote_dest'. If ptr_in_memory is non-null,
   * updates the ptr_in_memory location with the value 'remote_dest'.
   */
  struct MemoryParam {
    MemoryParam() : ptr_in_reg(0) {}

    remote_ptr<void> dest;
    remote_ptr<void> scratch;
    ParamSize num_bytes;
    remote_ptr<void> ptr_in_memory;
    int ptr_in_reg;
    ArgMode mode;
    ArgMutator mutator;
  };

  RecordTask* t;

  vector<MemoryParam> param_list;
  /** Tracks the position in t's scratch_ptr buffer where we should allocate
   *  the next scratch area.
   */
  remote_ptr<void> scratch;

  vector<AfterSyscallAction> after_syscall_actions;

  std::unique_ptr<TraceTaskEvent> exec_saved_event;

  RecordTask* emulate_wait_for_child;

  /** Saved syscall-entry registers, used by code paths that modify the
   *  registers temporarily.
   */
  Registers syscall_entry_registers;

  /** When nonzero, syscall is expected to return the given errno and we should
   *  die if it does not. This is set when we detect an error condition during
   *  syscall-enter preparation.
   */
  int expect_errno;

  /** When should_emulate_result is true, syscall result should be adjusted to
   *  be emulated_result. */
  bool should_emulate_result;
  uint64_t emulated_result;

  /** Records whether the syscall is switchable. Only valid when
   *  preparation_done is true. */
  Switchable switchable;

  /** Whether we should write back the syscall results from scratch. Only
   *  valid when preparation_done is true. */
  WriteBack write_back;

  /** When true, this syscall has already been prepared and should not
   *  be set up again.
   */
  bool preparation_done;
  /** When true, the scratch area is enabled, otherwise we're letting
   *  syscall outputs be written directly to their destinations.
   *  Only valid when preparation_done is true.
   */
  bool scratch_enabled;

  /** Miscellaneous saved data that can be used by particular syscalls */
  vector<uint8_t> saved_data;

  TaskSyscallState()
      : t(nullptr),
        emulate_wait_for_child(nullptr),
        expect_errno(0),
        should_emulate_result(false),
        preparation_done(false),
        scratch_enabled(false) {}
};

static const Property<TaskSyscallState, RecordTask> syscall_state_property;

template <typename Arch>
static void set_remote_ptr_arch(RecordTask* t, remote_ptr<void> addr,
                                remote_ptr<void> value) {
  auto typed_addr = addr.cast<typename Arch::unsigned_word>();
  t->write_mem(typed_addr, (typename Arch::unsigned_word)value.as_int());
}

static void set_remote_ptr(RecordTask* t, remote_ptr<void> addr,
                           remote_ptr<void> value) {
  RR_ARCH_FUNCTION(set_remote_ptr_arch, t->arch(), t, addr, value);
}

template <typename Arch>
static remote_ptr<void> get_remote_ptr_arch(RecordTask* t,
                                            remote_ptr<void> addr) {
  auto typed_addr = addr.cast<typename Arch::unsigned_word>();
  auto old = t->read_mem(typed_addr);
  return remote_ptr<void>(old);
}

static remote_ptr<void> get_remote_ptr(RecordTask* t, remote_ptr<void> addr) {
  RR_ARCH_FUNCTION(get_remote_ptr_arch, t->arch(), t, addr);
}

static void align_scratch(remote_ptr<void>* scratch, uintptr_t amount = 8) {
  *scratch = (scratch->as_int() + amount - 1) & ~(amount - 1);
}

remote_ptr<void> TaskSyscallState::reg_parameter(int arg, const ParamSize& size,
                                                 ArgMode mode,
                                                 ArgMutator mutator) {
  if (preparation_done) {
    return remote_ptr<void>();
  }

  MemoryParam param;
  param.dest = syscall_entry_registers.arg(arg);
  if (param.dest.is_null()) {
    return remote_ptr<void>();
  }
  param.num_bytes = size;
  param.mode = mode;
  param.mutator = mutator;
  ASSERT(t, !mutator || mode == IN);
  if (mode != IN_OUT_NO_SCRATCH) {
    param.scratch = scratch;
    scratch += param.num_bytes.incoming_size;
    align_scratch(&scratch);
    param.ptr_in_reg = arg;
  }
  param_list.push_back(param);
  return param.dest;
}

remote_ptr<void> TaskSyscallState::mem_ptr_parameter(
    remote_ptr<void> addr_of_buf_ptr, const ParamSize& size, ArgMode mode,
    ArgMutator mutator) {
  if (preparation_done || addr_of_buf_ptr.is_null()) {
    return remote_ptr<void>();
  }

  MemoryParam param;
  param.dest = get_remote_ptr(t, addr_of_buf_ptr);
  if (param.dest.is_null()) {
    return remote_ptr<void>();
  }
  param.num_bytes = size;
  param.mode = mode;
  param.mutator = mutator;
  ASSERT(t, !mutator || mode == IN);
  if (mode != IN_OUT_NO_SCRATCH) {
    param.scratch = scratch;
    scratch += param.num_bytes.incoming_size;
    align_scratch(&scratch);
    param.ptr_in_memory = addr_of_buf_ptr;
  }
  param_list.push_back(param);
  return param.dest;
}

remote_ptr<void> TaskSyscallState::relocate_pointer_to_scratch(
    remote_ptr<void> ptr) {
  int num_relocations = 0;
  remote_ptr<void> result;
  for (auto& param : param_list) {
    if (param.dest <= ptr && ptr < param.dest + param.num_bytes.incoming_size) {
      result = param.scratch + (ptr - param.dest);
      ++num_relocations;
    }
  }
  DEBUG_ASSERT(
      num_relocations > 0 &&
      "Pointer in non-scratch memory being updated to point to scratch?");
  DEBUG_ASSERT(num_relocations <= 1 &&
               "Overlapping buffers containing relocated pointer?");
  return result;
}

Switchable TaskSyscallState::done_preparing_internal(Switchable sw) {
  ASSERT(t, !preparation_done);

  preparation_done = true;
  write_back = WRITE_BACK;
  switchable = sw;

  if (!t->scratch_ptr) {
    return switchable;
  }

  ASSERT(t, scratch >= t->scratch_ptr);

  if (sw == ALLOW_SWITCH &&
      scratch > t->scratch_ptr + t->usable_scratch_size()) {
    LOG(warn)
        << "`" << t->ev().Syscall().syscall_name()
        << "' needed a scratch buffer of size " << scratch - t->scratch_ptr
        << ", but only " << t->usable_scratch_size()
        << " was available.  Disabling context switching: deadlock may follow.";
    switchable = PREVENT_SWITCH;
  }
  if (switchable == PREVENT_SWITCH || param_list.empty()) {
    return switchable;
  }

  scratch_enabled = true;

  // Step 1: Copy all IN/IN_OUT parameters to their scratch areas
  for (auto& param : param_list) {
    ASSERT(t, param.num_bytes.incoming_size < size_t(-1));
    if (param.mode == IN_OUT || param.mode == IN) {
      // Initialize scratch buffer with input data
      std::unique_ptr<uint8_t[]> buf(
          new uint8_t[param.num_bytes.incoming_size]);
      t->read_bytes_helper(param.dest, param.num_bytes.incoming_size,
                           buf.get());
      t->write_bytes_helper(param.scratch, param.num_bytes.incoming_size,
                            buf.get());
    }
  }
  // Step 2: Update pointers in registers/memory to point to scratch areas
  {
    Registers r = t->regs();
    for (auto& param : param_list) {
      if (param.ptr_in_reg) {
        r.set_arg(param.ptr_in_reg, param.scratch.as_int());
      }
      if (!param.ptr_in_memory.is_null()) {
        // Pointers being relocated must themselves be in scratch memory.
        // We don't want to modify non-scratch memory. Find the pointer's
        // location
        // in scratch memory.
        auto p = relocate_pointer_to_scratch(param.ptr_in_memory);
        // Update pointer to point to scratch.
        // Note that this can only happen after step 1 is complete and all
        // parameter data has been copied to scratch memory.
        set_remote_ptr(t, p, param.scratch);
      }
      // If the number of bytes to record is coming from a memory location,
      // update that location to scratch.
      if (!param.num_bytes.mem_ptr.is_null()) {
        param.num_bytes.mem_ptr =
            relocate_pointer_to_scratch(param.num_bytes.mem_ptr);
      }
    }
    t->set_regs(r);
  }
  return switchable;
}

Switchable TaskSyscallState::done_preparing(Switchable sw) {
  if (preparation_done) {
    return switchable;
  }

  sw = done_preparing_internal(sw);
  ASSERT(t, sw == switchable);

  // Step 3: Execute mutators. This must run even if the scratch steps do not.
  for (auto& param : param_list) {
    if (param.mutator) {
      // Mutated parameters must be IN. If we have scratch space, we don't need
      // to save anything.
      void* saved_data_loc = nullptr;
      if (!scratch_enabled) {
        auto prev_size = saved_data.size();
        saved_data.resize(prev_size + param.num_bytes.incoming_size);
        saved_data_loc = saved_data.data() + prev_size;
      }
      if (!(*param.mutator)(t, scratch_enabled ? param.scratch : param.dest,
                            saved_data_loc)) {
        // Nothing was modified, no need to clean up when we unwind.
        param.mutator = nullptr;
        if (!scratch_enabled) {
          saved_data.resize(saved_data.size() - param.num_bytes.incoming_size);
        }
      }
    }
  }
  return switchable;
}

size_t TaskSyscallState::eval_param_size(size_t i,
                                         vector<size_t>& actual_sizes) {
  DEBUG_ASSERT(actual_sizes.size() == i);

  size_t already_consumed = 0;
  for (size_t j = 0; j < i; ++j) {
    if (param_list[j].num_bytes.is_same_source(param_list[i].num_bytes)) {
      already_consumed += actual_sizes[j];
    }
  }
  size_t size = param_list[i].num_bytes.eval(t, already_consumed);
  actual_sizes.push_back(size);
  return size;
}

void TaskSyscallState::process_syscall_results() {
  ASSERT(t, preparation_done);

  // XXX what's the best way to handle failed syscalls? Currently we just
  // record everything as if it succeeded. That handles failed syscalls that
  // wrote partial results, but doesn't handle syscalls that failed with
  // EFAULT.
  vector<size_t> actual_sizes;
  if (scratch_enabled) {
    size_t scratch_num_bytes = scratch - t->scratch_ptr;
    auto data = t->read_mem(t->scratch_ptr.cast<uint8_t>(), scratch_num_bytes);
    Registers r = t->regs();
    // Step 1: compute actual sizes of all buffers and copy outputs
    // from scratch back to their origin
    for (size_t i = 0; i < param_list.size(); ++i) {
      auto& param = param_list[i];
      size_t size = eval_param_size(i, actual_sizes);
      if (write_back == WRITE_BACK &&
          (param.mode == IN_OUT || param.mode == OUT)) {
        const uint8_t* d = data.data() + (param.scratch - t->scratch_ptr);
        t->write_bytes_helper(param.dest, size, d);
      }
    }
    bool memory_cleaned_up = false;
    // Step 2: restore modified in-memory pointers and registers
    for (size_t i = 0; i < param_list.size(); ++i) {
      auto& param = param_list[i];
      if (param.ptr_in_reg) {
        r.set_orig_arg(param.ptr_in_reg, param.dest.as_int());
      }
      if (!param.ptr_in_memory.is_null()) {
        memory_cleaned_up = true;
        set_remote_ptr(t, param.ptr_in_memory, param.dest);
      }
    }
    if (write_back == WRITE_BACK) {
      // Step 3: record all output memory areas
      for (size_t i = 0; i < param_list.size(); ++i) {
        auto& param = param_list[i];
        size_t size = actual_sizes[i];
        if (param.mode == IN_OUT_NO_SCRATCH) {
          t->record_remote(param.dest, size);
        } else if (param.mode == IN_OUT || param.mode == OUT) {
          // If pointers in memory were fixed up in step 2, then record
          // from tracee memory to ensure we record such fixes. Otherwise we
          // can record from our local data.
          // XXX This optimization can be improved if necessary...
          if (memory_cleaned_up) {
            t->record_remote(param.dest, size);
          } else {
            const uint8_t* d = data.data() + (param.scratch - t->scratch_ptr);
            t->record_local(param.dest, size, d);
          }
        }
      }
    }
    t->set_regs(r);
  } else {
    // Step 1: Determine the size of all output memory areas
    for (size_t i = 0; i < param_list.size(); ++i) {
      eval_param_size(i, actual_sizes);
    }
    // Step 2: restore all mutated memory
    for (auto& param : param_list) {
      if (param.mutator) {
        size_t size = param.num_bytes.incoming_size;
        ASSERT(t, saved_data.size() >= size);
        // If this intersects an output region, we need to be careful not to
        // clobber what the kernel gave us.
        for (size_t i = 0; i < param_list.size(); ++i) {
          auto& param2 = param_list[i];
          size_t param2_size = actual_sizes[i];
          if (param2.mode == IN) {
            continue;
          }
          MemoryRange intersection = MemoryRange(param2.dest, param2_size).
            intersect(MemoryRange(param.dest, size));
          if (intersection.size() != 0) {
            // Just update the saved data we already have. We could try
            // splitting the range and only writing what needs to still change,
            // but we'd probably just end up doing the exact same number of
            // syscalls and this is simpler.
            t->read_bytes_helper(intersection.start(), intersection.size(),
              saved_data.data() + (intersection.start() - param.dest));
          }
        }
        t->write_bytes_helper(param.dest, size, saved_data.data());
        saved_data.erase(saved_data.begin(), saved_data.begin() + size);
      }
    }
    ASSERT(t, saved_data.empty());
    // Step 3: record all output memory areas
    for (size_t i = 0; i < param_list.size(); ++i) {
      auto& param = param_list[i];
      size_t size = actual_sizes[i];
      if (param.mode != IN) {
        t->record_remote(param.dest, size);
      }
    }
  }

  if (should_emulate_result) {
    Registers r = t->regs();
    r.set_syscall_result(emulated_result);
    t->set_regs(r);
  }

  for (auto& action : after_syscall_actions) {
    action(t);
  }
}

void TaskSyscallState::abort_syscall_results() {
  ASSERT(t, preparation_done);

  if (scratch_enabled) {
    Registers r = t->regs();
    // restore modified in-memory pointers and registers
    for (size_t i = 0; i < param_list.size(); ++i) {
      auto& param = param_list[i];
      if (param.ptr_in_reg) {
        r.set_arg(param.ptr_in_reg, param.dest.as_int());
      }
      if (!param.ptr_in_memory.is_null()) {
        set_remote_ptr(t, param.ptr_in_memory, param.dest);
      }
    }
    t->set_regs(r);
  } else {
    for (auto& param : param_list) {
      if (param.mutator) {
        size_t size = param.num_bytes.incoming_size;
        ASSERT(t, saved_data.size() >= size);
        t->write_bytes_helper(param.dest, size, saved_data.data());
        saved_data.erase(saved_data.begin(), saved_data.begin() + size);
      }
    }
  }
}

template <typename Arch>
static void prepare_recvmsg(RecordTask* t, TaskSyscallState& syscall_state,
                            remote_ptr<typename Arch::msghdr> msgp,
                            const ParamSize& io_size) {
  auto namelen_ptr = REMOTE_PTR_FIELD(msgp, msg_namelen);
  syscall_state.mem_ptr_parameter(
      REMOTE_PTR_FIELD(msgp, msg_name),
      ParamSize::from_initialized_mem(t, namelen_ptr));

  auto msg = t->read_mem(msgp);
  remote_ptr<void> iovecsp_void = syscall_state.mem_ptr_parameter(
      REMOTE_PTR_FIELD(msgp, msg_iov),
      sizeof(typename Arch::iovec) * msg.msg_iovlen, IN);
  auto iovecsp = iovecsp_void.cast<typename Arch::iovec>();
  auto iovecs = t->read_mem(iovecsp, msg.msg_iovlen);
  for (size_t i = 0; i < msg.msg_iovlen; ++i) {
    syscall_state.mem_ptr_parameter(REMOTE_PTR_FIELD(iovecsp + i, iov_base),
                                    io_size.limit_size(iovecs[i].iov_len));
  }

  auto controllen_ptr = REMOTE_PTR_FIELD(msgp, msg_controllen);
  syscall_state.mem_ptr_parameter(
      REMOTE_PTR_FIELD(msgp, msg_control),
      ParamSize::from_initialized_mem(t, controllen_ptr));
}

template <typename Arch>
static void prepare_recvmmsg(RecordTask* t, TaskSyscallState& syscall_state,
                             remote_ptr<typename Arch::mmsghdr> mmsgp,
                             unsigned int vlen) {
  for (unsigned int i = 0; i < vlen; ++i) {
    auto msgp = mmsgp + i;
    prepare_recvmsg<Arch>(t, syscall_state, REMOTE_PTR_FIELD(msgp, msg_hdr),
                          ParamSize::from_mem(REMOTE_PTR_FIELD(msgp, msg_len)));
  }
}

static bool block_sock_opt(int level, int optname,
                           TaskSyscallState& syscall_state) {
  switch (level) {
    case SOL_PACKET:
      switch (optname) {
        case PACKET_RX_RING:
        case PACKET_TX_RING:
          syscall_state.emulate_result(-ENOPROTOOPT);
          return true;
      }
      break;
    case SOL_NETLINK:
      switch (optname) {
        case NETLINK_RX_RING:
        case NETLINK_TX_RING:
          syscall_state.emulate_result(-ENOPROTOOPT);
          return true;
      }
      break;
  }
  return false;
}

template <typename Arch>
static Switchable prepare_setsockopt(RecordTask* t,
                                     TaskSyscallState& syscall_state,
                                     typename Arch::setsockopt_args& args) {
  if (block_sock_opt(args.level, args.optname, syscall_state)) {
    Registers r = t->regs();
    r.set_arg1(-1);
    t->set_regs(r);
  } else {
    switch (args.level) {
      case IPPROTO_IP:
      case IPPROTO_IPV6:
        switch (args.optname) {
          case SO_SET_REPLACE: {
            if (args.optlen < (ssize_t)sizeof(typename Arch::ipt_replace)) {
              break;
            }
            auto repl_ptr =
                args.optval.rptr().template cast<typename Arch::ipt_replace>();
            syscall_state.mem_ptr_parameter(
                REMOTE_PTR_FIELD(repl_ptr, counters),
                t->read_mem(REMOTE_PTR_FIELD(repl_ptr, num_counters)) *
                    sizeof(typename Arch::xt_counters));
            break;
          }
          default:
            break;
        }
        break;
      default:
        break;
    }
  }
  return PREVENT_SWITCH;
}

template <typename Arch>
static Switchable maybe_blacklist_connect(RecordTask* t,
                                          remote_ptr<void> addr_ptr,
                                          socklen_t addrlen) {
  struct sockaddr_un addr;
  memset(&addr, 0, sizeof(addr));
  t->read_bytes_fallible(addr_ptr, min<socklen_t>(sizeof(addr), addrlen),
                         &addr);
  // Ensure null termination;
  addr.sun_path[sizeof(addr.sun_path) - 1] = 0;
  if (addr.sun_family == AF_UNIX && is_blacklisted_socket(addr.sun_path)) {
    LOG(warn) << "Cowardly refusing to connect to " << addr.sun_path;
    // Hijack the syscall.
    Registers r = t->regs();
    r.set_original_syscallno(Arch::gettid);
    t->set_regs(r);
  }
  return PREVENT_SWITCH;
}

template <typename Arch>
static Switchable prepare_socketcall(RecordTask* t,
                                     TaskSyscallState& syscall_state) {
  /* int socketcall(int call, unsigned long *args) {
   *   long a[6];
   *   copy_from_user(a,args);
   *   sys_recv(a0, (void __user *)a1, a[2], a[3]);
   * }
   *
   *  (from http://lxr.linux.no/#linux+v3.6.3/net/socket.c#L2354)
   */
  switch ((int)t->regs().arg1_signed()) {
    /* int socket(int domain, int type, int protocol); */
    case SYS_SOCKET:
    /* int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen); */
    case SYS_BIND:
    /* int listen(int sockfd, int backlog) */
    case SYS_LISTEN:
    /* int shutdown(int socket, int how) */
    case SYS_SHUTDOWN:
      break;

    /* int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
     */
    case SYS_CONNECT: {
      auto argsp =
          syscall_state.reg_parameter<typename Arch::connect_args>(2, IN);
      auto args = t->read_mem(argsp);
      return maybe_blacklist_connect<Arch>(t, args.addr.rptr(), args.addrlen);
    }

    /* ssize_t send(int sockfd, const void *buf, size_t len, int flags) */
    case SYS_SEND:
    /* ssize_t sendto(int sockfd, const void *buf, size_t len, int flags, const
     * struct sockaddr *dest_addr, socklen_t addrlen); */
    case SYS_SENDTO:
      // These can block when socket buffers are full.
      return ALLOW_SWITCH;

    /* int setsockopt(int sockfd, int level, int optname, const void *optval,
     * socklen_t optlen); */
    case SYS_SETSOCKOPT: {
      auto argsp =
          syscall_state.reg_parameter<typename Arch::setsockopt_args>(2, IN);
      auto args = t->read_mem(argsp);
      return prepare_setsockopt<Arch>(t, syscall_state, args);
    }

    /*  int getsockopt(int sockfd, int level, int optname, const void *optval,
     * socklen_t* optlen);
     */
    case SYS_GETSOCKOPT: {
      auto argsp =
          syscall_state.reg_parameter<typename Arch::getsockopt_args>(2, IN);
      auto optlen_ptr = syscall_state.mem_ptr_parameter_inferred(
          REMOTE_PTR_FIELD(argsp, optlen), IN_OUT);
      syscall_state.mem_ptr_parameter(
          REMOTE_PTR_FIELD(argsp, optval),
          ParamSize::from_initialized_mem(t, optlen_ptr));
      break;
    }

    /* int socketpair(int domain, int type, int protocol, int sv[2]);
     *
     * values returned in sv
     */
    case SYS_SOCKETPAIR: {
      auto argsp =
          syscall_state.reg_parameter<typename Arch::socketpair_args>(2, IN);
      syscall_state.mem_ptr_parameter(REMOTE_PTR_FIELD(argsp, sv),
                                      sizeof(int) * 2);
      break;
    }

    /* int getpeername(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
     */
    case SYS_GETPEERNAME:
    /* int getsockname(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
     */
    case SYS_GETSOCKNAME: {
      auto argsp =
          syscall_state.reg_parameter<typename Arch::getsockname_args>(2, IN);
      auto addrlen_ptr = syscall_state.mem_ptr_parameter_inferred(
          REMOTE_PTR_FIELD(argsp, addrlen), IN_OUT);
      syscall_state.mem_ptr_parameter(
          REMOTE_PTR_FIELD(argsp, addr),
          ParamSize::from_initialized_mem(t, addrlen_ptr));
      break;
    }

    /* ssize_t recv([int sockfd, void *buf, size_t len, int flags]) */
    case SYS_RECV: {
      auto argsp = syscall_state.reg_parameter<typename Arch::recv_args>(2, IN);
      auto args = t->read_mem(argsp);
      syscall_state.mem_ptr_parameter(
          REMOTE_PTR_FIELD(argsp, buf),
          ParamSize::from_syscall_result<typename Arch::ssize_t>(args.len));
      return ALLOW_SWITCH;
    }

    /* int accept([int sockfd, struct sockaddr *addr, socklen_t *addrlen]) */
    case SYS_ACCEPT: {
      auto argsp =
          syscall_state.reg_parameter<typename Arch::accept_args>(2, IN);
      auto addrlen_ptr = syscall_state.mem_ptr_parameter_inferred(
          REMOTE_PTR_FIELD(argsp, addrlen), IN_OUT);
      syscall_state.mem_ptr_parameter(
          REMOTE_PTR_FIELD(argsp, addr),
          ParamSize::from_initialized_mem(t, addrlen_ptr));
      return ALLOW_SWITCH;
    }

    /* int accept4([int sockfd, struct sockaddr *addr, socklen_t *addrlen, int
     * flags]) */
    case SYS_ACCEPT4: {
      auto argsp =
          syscall_state.reg_parameter<typename Arch::accept4_args>(2, IN);
      auto addrlen_ptr = syscall_state.mem_ptr_parameter_inferred(
          REMOTE_PTR_FIELD(argsp, addrlen), IN_OUT);
      syscall_state.mem_ptr_parameter(
          REMOTE_PTR_FIELD(argsp, addr),
          ParamSize::from_initialized_mem(t, addrlen_ptr));
      return ALLOW_SWITCH;
    }

    case SYS_RECVFROM: {
      auto argsp =
          syscall_state.reg_parameter<typename Arch::recvfrom_args>(2, IN);
      auto args = t->read_mem(argsp);
      syscall_state.mem_ptr_parameter(
          REMOTE_PTR_FIELD(argsp, buf),
          ParamSize::from_syscall_result<typename Arch::ssize_t>(args.len));
      auto addrlen_ptr = syscall_state.mem_ptr_parameter_inferred(
          REMOTE_PTR_FIELD(argsp, addrlen), IN_OUT);
      syscall_state.mem_ptr_parameter(
          REMOTE_PTR_FIELD(argsp, src_addr),
          ParamSize::from_initialized_mem(t, addrlen_ptr));
      return ALLOW_SWITCH;
    }

    case SYS_RECVMSG: {
      auto argsp =
          syscall_state.reg_parameter<typename Arch::recvmsg_args>(2, IN);
      auto msgp = syscall_state.mem_ptr_parameter_inferred(
          REMOTE_PTR_FIELD(argsp, msg), IN_OUT);
      prepare_recvmsg<Arch>(
          t, syscall_state, msgp,
          ParamSize::from_syscall_result<typename Arch::ssize_t>());

      auto args = t->read_mem(argsp);
      if (!(args.flags & MSG_DONTWAIT)) {
        return ALLOW_SWITCH;
      }
      break;
    }

    case SYS_RECVMMSG: {
      auto argsp =
          syscall_state.reg_parameter<typename Arch::recvmmsg_args>(2, IN);
      auto args = t->read_mem(argsp);
      remote_ptr<void> mmsgp_void = syscall_state.mem_ptr_parameter(
          REMOTE_PTR_FIELD(argsp, msgvec),
          sizeof(typename Arch::mmsghdr) * args.vlen, IN_OUT);
      auto mmsgp = mmsgp_void.cast<typename Arch::mmsghdr>();
      prepare_recvmmsg<Arch>(t, syscall_state, mmsgp, args.vlen);
      if (!(args.flags & MSG_DONTWAIT)) {
        return ALLOW_SWITCH;
      }
      break;
    }

    /* ssize_t sendmsg(int sockfd, const struct msghdr *msg, int flags) */
    case SYS_SENDMSG: {
      auto argsp = remote_ptr<typename Arch::sendmsg_args>(t->regs().arg2());
      auto args = t->read_mem(argsp);
      if (!(args.flags & MSG_DONTWAIT)) {
        return ALLOW_SWITCH;
      }
      break;
    }

    case SYS_SENDMMSG: {
      auto argsp =
          syscall_state.reg_parameter<typename Arch::sendmmsg_args>(2, IN);
      auto args = t->read_mem(argsp);
      syscall_state.mem_ptr_parameter(
          REMOTE_PTR_FIELD(argsp, msgvec),
          sizeof(typename Arch::mmsghdr) * args.vlen, IN_OUT);
      if (!(args.flags & MSG_DONTWAIT)) {
        return ALLOW_SWITCH;
      }
      break;
    }

    default:
      syscall_state.expect_errno = EINVAL;
      break;
  }
  return PREVENT_SWITCH;
}

template <typename Arch>
static Switchable prepare_msgctl(TaskSyscallState& syscall_state, int cmd,
                                 int ptr_reg) {
  switch (cmd) {
    case IPC_STAT:
    case MSG_STAT:
      syscall_state.reg_parameter<typename Arch::msqid64_ds>(ptr_reg);
      break;
    case IPC_INFO:
    case MSG_INFO:
      syscall_state.reg_parameter<typename Arch::msginfo>(ptr_reg);
      break;

    case IPC_SET:
    case IPC_RMID:
      break;

    default:
      syscall_state.expect_errno = EINVAL;
      break;
  }
  return PREVENT_SWITCH;
}

template <typename Arch>
static Switchable prepare_shmctl(TaskSyscallState& syscall_state, int cmd,
                                 int ptr_reg) {
  switch (cmd) {
    case IPC_SET:
    case IPC_RMID:
    case SHM_LOCK:
    case SHM_UNLOCK:
      break;

    case IPC_STAT:
    case SHM_STAT:
      syscall_state.reg_parameter<typename Arch::shmid64_ds>(ptr_reg);
      break;

    case IPC_INFO:
      syscall_state.reg_parameter<typename Arch::shminfo64>(ptr_reg);
      break;

    case SHM_INFO:
      syscall_state.reg_parameter<typename Arch::shm_info>(ptr_reg);
      break;

    default:
      syscall_state.expect_errno = EINVAL;
      break;
  }
  return PREVENT_SWITCH;
}

enum SemctlDereference { DEREFERENCE, USE_DIRECTLY };

template <typename Arch>
static Switchable prepare_semctl(RecordTask* t, TaskSyscallState& syscall_state,
                                 int semid, int cmd, int ptr_reg,
                                 SemctlDereference deref) {
  switch (cmd) {
    case IPC_SET:
    case IPC_RMID:
    case GETNCNT:
    case GETPID:
    case GETVAL:
    case GETZCNT:
    case SETALL:
    case SETVAL:
      break;

    case IPC_STAT:
    case SEM_STAT:
      if (deref == DEREFERENCE) {
        syscall_state.mem_ptr_parameter<typename Arch::semid64_ds>(
            syscall_state.reg_parameter<typename Arch::unsigned_long>(ptr_reg));
      } else {
        syscall_state.reg_parameter<typename Arch::semid64_ds>(ptr_reg);
      }
      break;

    case IPC_INFO:
    case SEM_INFO:
      if (deref == DEREFERENCE) {
        syscall_state.mem_ptr_parameter<typename Arch::seminfo>(
            syscall_state.reg_parameter<typename Arch::unsigned_long>(ptr_reg));
      } else {
        syscall_state.reg_parameter<typename Arch::seminfo>(ptr_reg);
      }
      break;

    case GETALL: {
      semid64_ds ds;
      _semun un_arg;
      un_arg.buf = &ds;
      int ret = _semctl(semid, 0, IPC_STAT, un_arg);
      msan_unpoison(&ds, sizeof(semid64_ds));
      ASSERT(t, ret == 0);

      ParamSize size = sizeof(unsigned short) * ds.sem_nsems;
      if (deref == DEREFERENCE) {
        syscall_state.mem_ptr_parameter(
            syscall_state.reg_parameter<typename Arch::unsigned_long>(ptr_reg),
            size);
      } else {
        syscall_state.reg_parameter(ptr_reg, size);
      }
      break;
    }

    default:
      syscall_state.expect_errno = EINVAL;
      break;
  }
  return PREVENT_SWITCH;
}

/**
 * A change has been made to file 'fd' in task t. If the file has been mmapped
 * somewhere in t's address space, record the changes.
 * We check for matching files by comparing file names. This may not be
 * reliable but hopefully it's good enough for the cases where we need this.
 * This doesn't currently handle shared mappings very well. A file mapped
 * shared in multiple locations will be recorded once per location.
 * This doesn't handle mappings of the file into other address spaces.
 */
static void record_file_change(RecordTask* t, int fd, uint64_t offset,
                               uint64_t length) {
  string file_name = t->file_name_of_fd(fd);

  for (const auto& m : t->vm()->maps()) {
    if (m.map.fsname() == file_name) {
      uint64_t start = max(offset, uint64_t(m.map.file_offset_bytes()));
      uint64_t end = min(offset + length,
                         uint64_t(m.map.file_offset_bytes()) + m.map.size());
      if (start < end) {
        t->record_remote(m.map.start() + (start - m.map.file_offset_bytes()),
                         end - start);
      }
    }
  };
}

template <typename Arch>
static void record_v4l2_buffer_contents(RecordTask* t) {
  remote_ptr<typename Arch::v4l2_buffer> bufp = t->regs().arg3();
  auto buf = t->read_mem(bufp);

  switch (buf.memory) {
    case V4L2_MEMORY_MMAP:
      record_file_change(t, (int)t->regs().arg1_signed(), buf.m.offset,
                         buf.length);
      return;

    default:
      ASSERT(t, false) << "Unhandled V4L2 memory type " << buf.memory;
      return;
  }
}

template <typename Arch> static void record_usbdevfs_reaped_urb(RecordTask* t) {
  if (t->regs().syscall_failed()) {
    return;
  }

  remote_ptr<typename Arch::unsigned_word> pp = t->regs().arg3();
  remote_ptr<typename Arch::usbdevfs_urb> p = t->read_mem(pp);
  t->record_remote(p);
  auto urb = t->read_mem(p);
  size_t length;
  if (urb.type == USBDEVFS_URB_TYPE_ISO) {
    auto iso_frame_descs_ptr = REMOTE_PTR_FIELD(p, iso_frame_desc[0]);
    auto iso_frame_descs =
        t->read_mem(iso_frame_descs_ptr, urb.number_of_packets);
    length = 0;
    for (auto& f : iso_frame_descs) {
      length += f.length;
    }
    t->record_local(iso_frame_descs_ptr, iso_frame_descs.data(),
                    iso_frame_descs.size());
  } else {
    length = urb.buffer_length;
  }
  // It's tempting to use actual_length here but in some cases the kernel
  // writes back more data than that.
  t->record_remote(urb.buffer, length);
}

static void record_page_below_stack_ptr(RecordTask* t) {
  /* Record.the page above the top of |t|'s stack.  The SIOC* ioctls
   * have been observed to write beyond the end of tracees' stacks, as
   * if they had allocated scratch space for themselves.  All we can do
   * for now is try to record the scratch data.
   */
  t->record_remote(t->regs().sp() - page_size(), page_size());
}

#define IOCTL_MASK_SIZE(v) ((v) & ~(_IOC_SIZEMASK << _IOC_SIZESHIFT))

typedef ethtool_gstrings GStrings;

template <typename Arch> void get_ethtool_gstrings_arch(RecordTask* t) {
  auto& syscall_state = *syscall_state_property.get(*t);
  Registers& regs = syscall_state.syscall_entry_registers;
  bool ok = true;
  auto ifreq = t->read_mem(remote_ptr<typename Arch::ifreq>(regs.arg3()), &ok);
  Registers new_regs = t->regs();
  if (!ok) {
    new_regs.set_syscall_result(-EFAULT);
    t->set_regs(new_regs);
    return;
  }
  remote_ptr<void> p = ifreq.ifr_ifru.ifru_data.rptr();
  auto orig_gstrings = p.cast<ethtool_gstrings>();
  auto et_gstrings = t->read_mem(orig_gstrings, &ok);
  if (!ok) {
    new_regs.set_syscall_result(-EFAULT);
    t->set_regs(new_regs);
    return;
  }
  if (et_gstrings.string_set >= 64) {
    new_regs.set_syscall_result(-EOPNOTSUPP);
    t->set_regs(new_regs);
    return;
  }

  AutoRemoteSyscalls remote(t);

  // Do a ETHTOOL_GSSET_INFO to get the number of strings
  struct SingleStringSet {
    ethtool_sset_info et;
    uint32_t data;
  };
  SingleStringSet sss;
  sss.et.cmd = ETHTOOL_GSSET_INFO;
  sss.et.reserved = 0;
  sss.et.sset_mask = 1 << et_gstrings.string_set;
  AutoRestoreMem sss_mem(remote, &sss, sizeof(sss));

  ifreq.ifr_ifru.ifru_data = sss_mem.get();
  AutoRestoreMem ifr_mem(remote, &ifreq, sizeof(ifreq));

  long ret = remote.syscall(regs.original_syscallno(), regs.arg1(),
      SIOCETHTOOL, ifr_mem.get());
  if (ret < 0) {
    remote.regs().set_syscall_result(ret);
    return;
  }

  sss = t->read_mem(sss_mem.get().cast<SingleStringSet>());

  // Now do the ETHTOOL_GSTRINGS call
  ret = remote.syscall(regs.original_syscallno(), regs.arg1(), SIOCETHTOOL,
      regs.arg3());
  remote.regs().set_syscall_result(ret);
  if (ret < 0) {
    return;
  }
  t->record_remote(orig_gstrings, sizeof(ethtool_gstrings) + ETH_GSTRING_LEN*sss.data);
}

static void get_ethtool_gstrings(RecordTask* t) {
  RR_ARCH_FUNCTION(get_ethtool_gstrings_arch, t->arch(), t);
}

template <typename Arch> void prepare_ethtool_ioctl(RecordTask* t, TaskSyscallState& syscall_state) {
  auto ifrp = syscall_state.reg_parameter<typename Arch::ifreq>(3, IN);
  bool ok = true;
  auto ifreq = t->read_mem(ifrp, &ok);
  if (!ok) {
    syscall_state.expect_errno = EFAULT;
    return;
  }
  remote_ptr<void> payload = REMOTE_PTR_FIELD(ifrp, ifr_ifru.ifru_data);
  remote_ptr<void> buf_ptr = ifreq.ifr_ifru.ifru_data.rptr();
  uint32_t cmd = t->read_mem(buf_ptr.cast<uint32_t>(), &ok);
  if (!ok) {
    syscall_state.expect_errno = EFAULT;
    return;
  }

  switch (cmd) {
    case ETHTOOL_GSET:
      syscall_state.mem_ptr_parameter<ethtool_cmd>(payload, IN_OUT);
      break;
    case ETHTOOL_GDRVINFO:
      syscall_state.mem_ptr_parameter<ethtool_drvinfo>(payload, IN_OUT);
      break;
    case ETHTOOL_GWOL:
      syscall_state.mem_ptr_parameter<ethtool_wolinfo>(payload, IN_OUT);
      break;
    case ETHTOOL_GREGS: {
      auto buf = t->read_mem(buf_ptr.cast<ethtool_regs>(), &ok);
      if (ok) {
        syscall_state.mem_ptr_parameter(payload, ParamSize(sizeof(buf) + buf.len), IN_OUT);
      } else {
        syscall_state.expect_errno = EFAULT;
        return;
      }
      break;
    }
    case ETHTOOL_GMODULEEEPROM:
    case ETHTOOL_GEEPROM: {
      auto buf = t->read_mem(buf_ptr.cast<ethtool_eeprom>(), &ok);
      if (ok) {
        syscall_state.mem_ptr_parameter(payload, ParamSize(sizeof(buf) + buf.len), IN_OUT);
      } else {
        syscall_state.expect_errno = EFAULT;
        return;
      }
      break;
    }
    case ETHTOOL_GEEE:
      syscall_state.mem_ptr_parameter<ethtool_eee>(payload, IN_OUT);
      break;
    case ETHTOOL_GMODULEINFO:
      syscall_state.mem_ptr_parameter<ethtool_modinfo>(payload, IN_OUT);
      break;
    case ETHTOOL_GCOALESCE:
      syscall_state.mem_ptr_parameter<ethtool_coalesce>(payload, IN_OUT);
      break;
    case ETHTOOL_GRINGPARAM:
      syscall_state.mem_ptr_parameter<ethtool_ringparam>(payload, IN_OUT);
      break;
    case ETHTOOL_GCHANNELS:
      syscall_state.mem_ptr_parameter<ethtool_channels>(payload, IN_OUT);
      break;
    case ETHTOOL_GPAUSEPARAM:
      syscall_state.mem_ptr_parameter<ethtool_pauseparam>(payload, IN_OUT);
      break;
    case ETHTOOL_GSSET_INFO: {
      auto buf = t->read_mem(buf_ptr.cast<ethtool_sset_info>(), &ok);
      if (ok) {
        int bits = pop_count(buf.sset_mask);
        syscall_state.mem_ptr_parameter(payload, ParamSize(sizeof(buf) + bits*sizeof(uint32_t)), IN_OUT);
      } else {
        syscall_state.expect_errno = EFAULT;
        return;
      }
      break;
    }
    case ETHTOOL_GSTRINGS: {
      // These are an enormous pain because to know how much data will be written
      // back by the kernel, we have to perform a ETHTOOL_GSSET_INFO first.
      // We can't do that right here because we've already entered the kernel.
      // So, we emulate this.
      Registers r = t->regs();
      r.set_arg1(-1);
      t->set_regs(r);
      syscall_state.after_syscall_action(get_ethtool_gstrings);
      break;
    }
    case ETHTOOL_GFEATURES: {
      auto buf = t->read_mem(buf_ptr.cast<ethtool_gfeatures>(), &ok);
      if (ok) {
        syscall_state.mem_ptr_parameter(payload, ParamSize(sizeof(buf) + buf.size*sizeof(ethtool_get_features_block)), IN_OUT);
      } else {
        syscall_state.expect_errno = EFAULT;
        return;
      }
      break;
    }
    case ETHTOOL_GPERMADDR: {
      auto buf = t->read_mem(buf_ptr.cast<ethtool_perm_addr>(), &ok);
      if (ok) {
        syscall_state.mem_ptr_parameter(payload, ParamSize(sizeof(buf) + buf.size), IN_OUT);
      } else {
        syscall_state.expect_errno = EFAULT;
        return;
      }
      break;
    }
    case ETHTOOL_SSET:
    case ETHTOOL_SWOL:
    case ETHTOOL_SEEPROM:
    case ETHTOOL_SEEE:
    case ETHTOOL_SCOALESCE:
    case ETHTOOL_SRINGPARAM:
    case ETHTOOL_SCHANNELS:
    case ETHTOOL_SPAUSEPARAM:
    case ETHTOOL_SFEATURES:
      break;
    default:
      LOG(debug) << "Unknown ETHTOOL cmd " << cmd;
      syscall_state.expect_errno = EINVAL;
      return;
  }
  syscall_state.after_syscall_action(record_page_below_stack_ptr);
}

template <typename Arch>
static Switchable prepare_ioctl(RecordTask* t,
                                TaskSyscallState& syscall_state) {
  int fd = t->regs().arg1();
  uint64_t result;
  if (t->fd_table()->emulate_ioctl(fd, t, &result)) {
    // Don't perform this syscall.
    Registers r = t->regs();
    r.set_arg1(-1);
    t->set_regs(r);
    syscall_state.emulate_result(result);
    return PREVENT_SWITCH;
  }

  unsigned int request = t->regs().arg2();
  int type = _IOC_TYPE(request);
  int nr = _IOC_NR(request);
  int dir = _IOC_DIR(request);
  int size = _IOC_SIZE(request);

  LOG(debug) << "handling ioctl(" << HEX(request) << "): type:" << HEX(type)
             << " nr:" << HEX(nr) << " dir:" << HEX(dir) << " size:" << size;

  ASSERT(t, !t->is_desched_event_syscall())
      << "Failed to skip past desched ioctl()";

  /* Some ioctl()s are irregular and don't follow the _IOC()
   * conventions.  Special case them here. */
  switch (request) {
    case SIOCETHTOOL: {
      prepare_ethtool_ioctl<Arch>(t, syscall_state);
      return PREVENT_SWITCH;
    }

    case SIOCGIFCONF: {
      auto ifconfp =
          syscall_state.reg_parameter<typename Arch::ifconf>(3, IN_OUT);
      syscall_state.mem_ptr_parameter(
          REMOTE_PTR_FIELD(ifconfp, ifc_ifcu.ifcu_buf),
          ParamSize::from_initialized_mem(t,
                                          REMOTE_PTR_FIELD(ifconfp, ifc_len)));
      syscall_state.after_syscall_action(record_page_below_stack_ptr);
      return PREVENT_SWITCH;
    }

    /* Privileged ioctls */
    case SIOCSIFADDR:
    case SIOCSIFDSTADDR:
    case SIOCSIFBRDADDR:
    case SIOCSIFHWADDR:
    case SIOCSIFFLAGS:
    case SIOCSIFPFLAGS:
    case SIOCSIFTXQLEN:
    case SIOCSIFMTU:
    case SIOCSIFNAME:
    case SIOCSIFNETMASK:
    case SIOCSIFMETRIC:
    case SIOCSIFHWBROADCAST:
    case SIOCSIFMAP:
    case SIOCADDMULTI:
    case SIOCDELMULTI:
    /* Bridge ioctls */
    case SIOCBRADDBR:
    case SIOCBRDELBR:
    case SIOCBRADDIF:
    case SIOCBRDELIF:
    /* Routing table ioctls */
    case SIOCADDRT:
    case SIOCDELRT:
      return PREVENT_SWITCH;

    case SIOCBONDINFOQUERY: {
      auto ifrp = syscall_state.reg_parameter<typename Arch::ifreq>(3, IN);
      syscall_state.mem_ptr_parameter<typename Arch::ifbond>(
          REMOTE_PTR_FIELD(ifrp, ifr_ifru.ifru_data));
      syscall_state.after_syscall_action(record_page_below_stack_ptr);
      return PREVENT_SWITCH;
    }

    case SIOCGIFADDR:
    case SIOCGIFDSTADDR:
    case SIOCGIFBRDADDR:
    case SIOCGIFHWADDR:
    case SIOCGIFFLAGS:
    case SIOCGIFPFLAGS:
    case SIOCGIFTXQLEN:
    case SIOCGIFINDEX:
    case SIOCGIFMTU:
    case SIOCGIFNAME:
    case SIOCGIFNETMASK:
    case SIOCGIFMETRIC:
    case SIOCGIFMAP:
      syscall_state.reg_parameter<typename Arch::ifreq>(3);
      syscall_state.after_syscall_action(record_page_below_stack_ptr);
      return PREVENT_SWITCH;

    // These haven't been observed to write beyond
    // tracees' stacks, but we record a stack page here
    // just in case the behavior is driver-dependent.
    case SIOCGIWFREQ:
    case SIOCGIWMODE:
    case SIOCGIWNAME:
    case SIOCGIWRATE:
    case SIOCGIWSENS:
      syscall_state.reg_parameter<typename Arch::iwreq>(3);
      syscall_state.after_syscall_action(record_page_below_stack_ptr);
      return PREVENT_SWITCH;
    case SIOCGIWESSID: {
      auto argsp = syscall_state.reg_parameter<typename Arch::iwreq>(3, IN_OUT);
      auto args = t->read_mem(argsp);
      syscall_state.mem_ptr_parameter(REMOTE_PTR_FIELD(argsp, u.essid.pointer),
                                      args.u.essid.length);
      syscall_state.after_syscall_action(record_page_below_stack_ptr);
      return PREVENT_SWITCH;
    }

    case SIOCGSTAMP:
      syscall_state.reg_parameter<typename Arch::timeval>(3);
      return PREVENT_SWITCH;

    case SIOCGSTAMPNS:
      syscall_state.reg_parameter<typename Arch::timespec>(3);
      return PREVENT_SWITCH;

    case TCGETS:
    case TIOCGLCKTRMIOS:
      syscall_state.reg_parameter<typename Arch::termios>(3);
      return PREVENT_SWITCH;

    case TCGETA:
      syscall_state.reg_parameter<typename Arch::termio>(3);
      return PREVENT_SWITCH;

    case TIOCINQ:
    case TIOCOUTQ:
    case TIOCGETD:
      syscall_state.reg_parameter<int>(3);
      return PREVENT_SWITCH;

    case TIOCGWINSZ:
      syscall_state.reg_parameter<typename Arch::winsize>(3);
      return PREVENT_SWITCH;

    case TIOCGPGRP:
    case TIOCGSID:
      syscall_state.reg_parameter<typename Arch::pid_t>(3);
      return PREVENT_SWITCH;

    case SNDRV_CTL_IOCTL_PVERSION:
      syscall_state.reg_parameter<int>(3);
      return PREVENT_SWITCH;

    case SNDRV_CTL_IOCTL_CARD_INFO:
      syscall_state.reg_parameter<typename Arch::snd_ctl_card_info>(3);
      return PREVENT_SWITCH;

    case HCIGETDEVINFO:
      syscall_state.reg_parameter<typename Arch::hci_dev_info>(3);
      return PREVENT_SWITCH;

    case HCIGETDEVLIST:
      syscall_state.reg_parameter<typename Arch::hci_dev_list_req>(3);
      return PREVENT_SWITCH;

    case SG_GET_VERSION_NUM:
      syscall_state.reg_parameter<typename Arch::signed_int>(3);
      return PREVENT_SWITCH;

    case SG_IO:
      auto argsp = syscall_state.reg_parameter<typename Arch::sg_io_hdr>(3, IN_OUT);
      auto args = t->read_mem(argsp);
      syscall_state.mem_ptr_parameter(REMOTE_PTR_FIELD(argsp, dxferp), args.dxfer_len);
      //cmdp: The user memory pointed to is only read (not written to).
      syscall_state.mem_ptr_parameter(REMOTE_PTR_FIELD(argsp, sbp), args.mx_sb_len);
      //usr_ptr: This value is not acted upon by the sg driver.
      return PREVENT_SWITCH;
  }

  /* In ioctl language, "_IOC_READ" means "outparam".  Both
   * READ and WRITE can be set for inout params.
   * USBDEVFS ioctls seem to be mostly backwards in their interpretation of the
   * read/write bits :-(.
   */
  if (!(_IOC_READ & dir)) {
    switch (IOCTL_MASK_SIZE(request)) {
      // Order by value
      // Older ioctls don't use IOC macros at all, so don't mask size for them
      case TCSETS:
      case TCSETSW:
      case TCSETSF:
      case TCSETA:
      case TCSETAW:
      case TCSETAF:
      case TIOCSLCKTRMIOS:
      case TCSBRK:
      case TCSBRKP:
      case TIOCSBRK:
      case TIOCCBRK:
      case TCXONC:
      case TCFLSH:
      case TIOCEXCL:
      case TIOCNXCL:
      case TIOCSCTTY:
      case TIOCNOTTY:
      case TIOCSPGRP:
      case TIOCSTI:
      case TIOCSWINSZ:
      // No test for TIOCCONS because if run as root it would do bad things
      case TIOCCONS:
      case TIOCPKT:
      case FIONBIO:
      case FIOASYNC:
      case TIOCSETD:
      case IOCTL_MASK_SIZE(TIOCSPTLCK):
      case IOCTL_MASK_SIZE(TIOCGPTPEER):
      case FIOCLEX:
      case FIONCLEX:
      case IOCTL_MASK_SIZE(BTRFS_IOC_CLONE):
      case IOCTL_MASK_SIZE(BTRFS_IOC_CLONE_RANGE):
      case IOCTL_MASK_SIZE(USBDEVFS_DISCARDURB):
      case IOCTL_MASK_SIZE(USBDEVFS_RESET):
      case IOCTL_MASK_SIZE(TUNSETNOCSUM):
      case IOCTL_MASK_SIZE(TUNSETDEBUG):
      case IOCTL_MASK_SIZE(TUNSETPERSIST):
      case IOCTL_MASK_SIZE(TUNSETOWNER):
      case IOCTL_MASK_SIZE(TUNSETLINK):
      case IOCTL_MASK_SIZE(TUNSETGROUP):
      case IOCTL_MASK_SIZE(TUNSETOFFLOAD):
      case IOCTL_MASK_SIZE(TUNSETTXFILTER):
      case IOCTL_MASK_SIZE(TUNSETSNDBUF):
      case IOCTL_MASK_SIZE(TUNATTACHFILTER):
      case IOCTL_MASK_SIZE(TUNDETACHFILTER):
      case IOCTL_MASK_SIZE(TUNSETVNETHDRSZ):
      case IOCTL_MASK_SIZE(TUNSETQUEUE):
      case IOCTL_MASK_SIZE(TUNSETIFINDEX):
      case IOCTL_MASK_SIZE(TUNSETVNETLE):
      case IOCTL_MASK_SIZE(TUNSETVNETBE):
        return PREVENT_SWITCH;
      case IOCTL_MASK_SIZE(USBDEVFS_GETDRIVER):
        // Reads and writes its parameter despite not having the _IOC_READ bit.
        syscall_state.reg_parameter(3, size);
        return PREVENT_SWITCH;
      case IOCTL_MASK_SIZE(USBDEVFS_REAPURB):
      case IOCTL_MASK_SIZE(USBDEVFS_REAPURBNDELAY):
        syscall_state.reg_parameter(3, size);
        syscall_state.after_syscall_action(record_usbdevfs_reaped_urb<Arch>);
        return ALLOW_SWITCH;
      case IOCTL_MASK_SIZE(TUNSETIFF):
        // Reads and writes its parameter despite not having the _IOC_READ
        // bit...
        // And the parameter is an ifreq, not an int as in the ioctl definition!
        syscall_state.reg_parameter<typename Arch::ifreq>(3);
        return PREVENT_SWITCH;
    }

    switch (type) {
      case 0x54: // TIO*
      case 0x89: // SIO*
      case 0x8B: // SIO* wireless interface ioctls
        // These ioctls are known to be irregular and don't usually have the
        // correct |dir| bits. They must be handled above
        syscall_state.expect_errno = EINVAL;
        return PREVENT_SWITCH;
    }

    /* If the kernel isn't going to write any data back to
     * us, we hope and pray that the result of the ioctl
     * (observable to the tracee) is deterministic.
     * We're also assuming it doesn't block.
     * This is risky! Many ioctls use irregular ioctl codes
     * that do not have the _IOC_READ bit set but actually do write to
     * user-space! */
    LOG(debug) << "  (presumed ignorable ioctl, nothing to do)";
    return PREVENT_SWITCH;
  }

  /* There are lots of ioctl values for EVIOCGBIT */
  if (type == 'E' && nr >= 0x20 && nr <= 0x7f) {
    syscall_state.reg_parameter(3, size);
    return PREVENT_SWITCH;
  }

  /* The following are thought to be "regular" ioctls, the
   * processing of which is only known to (observably) write to
   * the bytes in the structure passed to the kernel.  So all we
   * need is to record |size| bytes.
   * Since the size may vary across architectures we mask it out here to check
   * only the type + number. */
  switch (IOCTL_MASK_SIZE(request)) {
    case IOCTL_MASK_SIZE(VIDIOC_QUERYCAP):
    case IOCTL_MASK_SIZE(VIDIOC_ENUM_FMT):
    case IOCTL_MASK_SIZE(VIDIOC_ENUM_FRAMESIZES):
    case IOCTL_MASK_SIZE(VIDIOC_ENUM_FRAMEINTERVALS):
    case IOCTL_MASK_SIZE(VIDIOC_ENUMINPUT):
    case IOCTL_MASK_SIZE(VIDIOC_G_FMT):
    case IOCTL_MASK_SIZE(VIDIOC_S_FMT):
    case IOCTL_MASK_SIZE(VIDIOC_TRY_FMT):
    case IOCTL_MASK_SIZE(VIDIOC_G_PARM):
    case IOCTL_MASK_SIZE(VIDIOC_S_PARM):
    case IOCTL_MASK_SIZE(VIDIOC_REQBUFS):
    case IOCTL_MASK_SIZE(VIDIOC_QUERYBUF):
    case IOCTL_MASK_SIZE(VIDIOC_QUERYCTRL):
    case IOCTL_MASK_SIZE(VIDIOC_QBUF):
    case IOCTL_MASK_SIZE(VIDIOC_G_CTRL):
    case IOCTL_MASK_SIZE(VIDIOC_G_OUTPUT):
    case IOCTL_MASK_SIZE(VIDIOC_S_CTRL):
    case IOCTL_MASK_SIZE(VFAT_IOCTL_READDIR_BOTH):
      syscall_state.reg_parameter(3, size, IN_OUT);
      return PREVENT_SWITCH;

    case IOCTL_MASK_SIZE(TIOCGPTN):
    case IOCTL_MASK_SIZE(TIOCGPKT):
    case IOCTL_MASK_SIZE(TIOCGPTLCK):
    case IOCTL_MASK_SIZE(TIOCGEXCL):
    case IOCTL_MASK_SIZE(USBDEVFS_GET_CAPABILITIES):
    // FS_IOC_GETVERSION has the same number as VIDIOCGCAP (but different size)
    // but the same treatment works for both.
    case IOCTL_MASK_SIZE(FS_IOC_GETVERSION):
    case IOCTL_MASK_SIZE(FS_IOC_GETFLAGS):
    case IOCTL_MASK_SIZE(TUNGETFEATURES):
    case IOCTL_MASK_SIZE(TUNGETSNDBUF):
    case IOCTL_MASK_SIZE(TUNGETVNETHDRSZ):
    case IOCTL_MASK_SIZE(TUNGETVNETLE):
    case IOCTL_MASK_SIZE(TUNGETVNETBE):
    case IOCTL_MASK_SIZE(EVIOCGVERSION):
    case IOCTL_MASK_SIZE(EVIOCGID):
    case IOCTL_MASK_SIZE(EVIOCGREP):
    case IOCTL_MASK_SIZE(EVIOCGKEYCODE): /* also covers EVIOCGKEYCODE_V2 */
    case IOCTL_MASK_SIZE(EVIOCGNAME(0)):
    case IOCTL_MASK_SIZE(EVIOCGPHYS(0)):
    case IOCTL_MASK_SIZE(EVIOCGUNIQ(0)):
    case IOCTL_MASK_SIZE(EVIOCGPROP(0)):
    case IOCTL_MASK_SIZE(EVIOCGMTSLOTS(0)):
    case IOCTL_MASK_SIZE(EVIOCGKEY(0)):
    case IOCTL_MASK_SIZE(EVIOCGLED(0)):
    case IOCTL_MASK_SIZE(EVIOCGSND(0)):
    case IOCTL_MASK_SIZE(EVIOCGSW(0)):
    case IOCTL_MASK_SIZE(EVIOCGEFFECTS):
    case IOCTL_MASK_SIZE(EVIOCGMASK):
    case IOCTL_MASK_SIZE(JSIOCGVERSION):
    case IOCTL_MASK_SIZE(JSIOCGAXES):
    case IOCTL_MASK_SIZE(JSIOCGBUTTONS):
    // This gets a list of js_corr structures whose length we don't know without
    // querying the device ourselves.
    // case IOCTL_MASK_SIZE(JSIOCGCORR):
    case IOCTL_MASK_SIZE(JSIOCGAXMAP):
    case IOCTL_MASK_SIZE(JSIOCGBTNMAP):
    case IOCTL_MASK_SIZE(JSIOCGNAME(0)):
    case IOCTL_MASK_SIZE(HIDIOCGRAWINFO):
    case IOCTL_MASK_SIZE(HIDIOCGRAWNAME(0)):
      syscall_state.reg_parameter(3, size);
      return PREVENT_SWITCH;

    case IOCTL_MASK_SIZE(USBDEVFS_ALLOC_STREAMS):
    case IOCTL_MASK_SIZE(USBDEVFS_CLAIMINTERFACE):
    case IOCTL_MASK_SIZE(USBDEVFS_CLEAR_HALT):
    case IOCTL_MASK_SIZE(USBDEVFS_DISCONNECT_CLAIM):
    case IOCTL_MASK_SIZE(USBDEVFS_FREE_STREAMS):
    case IOCTL_MASK_SIZE(USBDEVFS_RELEASEINTERFACE):
    case IOCTL_MASK_SIZE(USBDEVFS_SETCONFIGURATION):
    case IOCTL_MASK_SIZE(USBDEVFS_SETINTERFACE):
    case IOCTL_MASK_SIZE(USBDEVFS_SUBMITURB):
      // Doesn't actually seem to write to userspace
      return PREVENT_SWITCH;

    case IOCTL_MASK_SIZE(TUNGETIFF):
      // The ioctl definition says "unsigned int" but it's actually a
      // struct ifreq!
      syscall_state.reg_parameter<typename Arch::ifreq>(3);
      return PREVENT_SWITCH;
    case IOCTL_MASK_SIZE(TUNGETFILTER):
      // The ioctl definition says "struct sock_fprog" but there is no kernel
      // compat code so a 32-bit task on a 64-bit kernel needs to use the
      // 64-bit type.
      if (sizeof(void*) == 8) {
        // 64-bit rr build. We must be on a 64-bit kernel so use the 64-bit
        // sock_fprog type.
        syscall_state.reg_parameter<typename NativeArch::sock_fprog>(3);
      } else {
        FATAL() << "TUNGETFILTER not supported on 32-bit since its behavior "
                   "depends on 32-bit vs 64-bit kernel";
      }
      return PREVENT_SWITCH;

    case IOCTL_MASK_SIZE(USBDEVFS_IOCTL): {
      auto argsp =
          syscall_state.reg_parameter<typename Arch::usbdevfs_ioctl>(3, IN);
      auto args = t->read_mem(argsp);
      syscall_state.mem_ptr_parameter(REMOTE_PTR_FIELD(argsp, data),
                                      _IOC_SIZE(args.ioctl_code));
      return PREVENT_SWITCH;
    }
    case IOCTL_MASK_SIZE(USBDEVFS_CONTROL): {
      auto argsp =
          syscall_state.reg_parameter<typename Arch::usbdevfs_ctrltransfer>(3,
                                                                            IN);
      auto args = t->read_mem(argsp);
      syscall_state.mem_ptr_parameter(REMOTE_PTR_FIELD(argsp, data),
                                      args.wLength);
      return PREVENT_SWITCH;
    }
  }

  /* These ioctls are mostly regular but require additional recording. */
  switch (IOCTL_MASK_SIZE(request)) {
    case IOCTL_MASK_SIZE(VIDIOC_DQBUF): {
      if (size == sizeof(typename Arch::v4l2_buffer)) {
        syscall_state.reg_parameter(3, size, IN_OUT);
        syscall_state.after_syscall_action(record_v4l2_buffer_contents<Arch>);
        // VIDIOC_DQBUF can block. It can't if the fd was opened O_NONBLOCK,
        // but we don't try to determine that.
        // Note that we're exposed to potential race conditions here because
        // VIDIOC_DQBUF (blocking or not) assumes the driver has filled
        // the mmapped data region at some point since the buffer was queued
        // with VIDIOC_QBUF, and we don't/can't know exactly when that
        // happened. Replay could fail if this thread or another thread reads
        // the contents of mmapped contents queued with the driver.
        return ALLOW_SWITCH;
      }
    }
  }

  syscall_state.expect_errno = EINVAL;
  return PREVENT_SWITCH;
}

template <typename Arch>
static Switchable prepare_bpf(RecordTask* t,
                              TaskSyscallState& syscall_state) {
  int cmd = t->regs().arg1();
  switch (cmd) {
    case BPF_MAP_CREATE:
    case BPF_MAP_UPDATE_ELEM:
    case BPF_MAP_DELETE_ELEM:
      return PREVENT_SWITCH;
    case BPF_PROG_LOAD: {
      auto argsp =
          syscall_state.reg_parameter<typename Arch::bpf_attr>(2, IN);
      auto args = t->read_mem(argsp);
      syscall_state.mem_ptr_parameter(REMOTE_PTR_FIELD(argsp, log_buf),
                                      args.log_size);
      return PREVENT_SWITCH;
    }
    // These are hard to support because we have to track the key_size/value_size :-(
    // case BPF_MAP_LOOKUP_ELEM:
    // case BPF_MAP_GET_NEXT_KEY:
    default:
      syscall_state.expect_errno = EINVAL;
      return PREVENT_SWITCH;
  }
}

static bool maybe_emulate_wait(RecordTask* t, TaskSyscallState& syscall_state,
                               int options) {
  for (RecordTask* child : t->emulated_ptrace_tracees) {
    if (t->is_waiting_for_ptrace(child) && child->emulated_stop_pending) {
      syscall_state.emulate_wait_for_child = child;
      return true;
    }
  }
  for (ThreadGroup* child_process : t->thread_group()->children()) {
    for (Task* child : child_process->task_set()) {
      auto rchild = static_cast<RecordTask*>(child);
      if (rchild->emulated_stop_type == NOT_STOPPED) {
        continue;
      }
      if (!(options & WUNTRACED) && rchild->emulated_stop_type != CHILD_STOP) {
        continue;
      }
      if (!rchild->emulated_stop_pending || !t->is_waiting_for(rchild)) {
        continue;
      }
      syscall_state.emulate_wait_for_child = rchild;
      return true;
    }
  }
  return false;
}

static bool maybe_pause_instead_of_waiting(RecordTask* t, int options) {
  if (t->in_wait_type != WAIT_TYPE_PID || (options & WNOHANG)) {
    return false;
  }
  RecordTask* child = t->session().find_task(t->in_wait_pid);
  if (!child || !t->is_waiting_for_ptrace(child) || t->is_waiting_for(child)) {
    return false;
  }
  // OK, t is waiting for a ptrace child by tid, but since t is not really
  // ptracing child, entering a real wait syscall will not actually wait for
  // the child, so the kernel may error out with ECHILD (non-ptracers can't
  // wait on specific threads of another process, or for non-child processes).
  // To avoid this problem, we'll replace the wait syscall with a pause()
  // syscall.
  // It would be nice if we didn't have to do this, but I can't see a better
  // way.
  Registers r = t->regs();
  // pause() would be sufficient here, but we don't have that on all
  // architectures, so use ppoll(NULL, 0, NULL, NULL), which is what
  // glibc uses to implement pause() on architectures where the former
  // doesn't exist
  r.set_original_syscallno(syscall_number_for_ppoll(t->arch()));
  r.set_arg1(0);
  r.set_arg2(0);
  r.set_arg3(0);
  r.set_arg4(0);
  t->set_regs(r);
  return true;
}

static RecordTask* verify_ptrace_target(RecordTask* tracer,
                                        TaskSyscallState& syscall_state,
                                        pid_t pid) {
  RecordTask* tracee = tracer->session().find_task(pid);
  if (!tracee) {
    LOG(debug) << "tracee pid " << pid << " is unknown to rr";
    syscall_state.emulate_result(-ESRCH);
    return nullptr;
  }
  if (tracee->emulated_ptracer != tracer) {
    LOG(debug) << pid << " is not traced by " << tracer->tid;
    syscall_state.emulate_result(-ESRCH);
    return nullptr;
  }
  if (tracee->emulated_stop_type == NOT_STOPPED) {
    LOG(debug) << pid << " is not in a ptrace stop";
    syscall_state.emulate_result(-ESRCH);
    return nullptr;
  }
  return tracee;
}

static void prepare_ptrace_cont(RecordTask* tracee, int sig, int command) {
  if (sig) {
    siginfo_t si = tracee->take_ptrace_signal_siginfo(sig);
    LOG(debug) << "Doing ptrace resume with signal " << signal_name(sig);
    // Treat signal as nondeterministic; it won't happen just by
    // replaying the tracee.
    tracee->push_event(
        Event(EV_SIGNAL, SignalEvent(si, NONDETERMINISTIC_SIG,
                                     tracee->sig_resolved_disposition(
                                         si.si_signo, NONDETERMINISTIC_SIG))));
  }

  tracee->emulated_stop_type = NOT_STOPPED;
  tracee->emulated_stop_pending = false;
  tracee->emulated_stop_code = WaitStatus();
  tracee->emulated_ptrace_cont_command = command;

  if (tracee->ev().is_syscall_event() &&
      PROCESSING_SYSCALL == tracee->ev().Syscall().state) {
    // Continue the task since we didn't in enter_syscall
    tracee->resume_execution(RESUME_SYSCALL, RESUME_NONBLOCKING,
                             RESUME_NO_TICKS);
  }
}

static uint64_t widen_buffer_unsigned(const void* buf, size_t size) {
  switch (size) {
    case 1:
      return *reinterpret_cast<const uint8_t*>(buf);
    case 2:
      return *reinterpret_cast<const uint16_t*>(buf);
    case 4:
      return *reinterpret_cast<const uint32_t*>(buf);
    case 8:
      return *reinterpret_cast<const uint64_t*>(buf);
    default:
      DEBUG_ASSERT(0 && "Unsupported size");
      return 0;
  }
}

static int64_t widen_buffer_signed(const void* buf, size_t size) {
  switch (size) {
    case 1:
      return *reinterpret_cast<const int8_t*>(buf);
    case 2:
      return *reinterpret_cast<const int16_t*>(buf);
    case 4:
      return *reinterpret_cast<const int32_t*>(buf);
    case 8:
      return *reinterpret_cast<const int64_t*>(buf);
    default:
      DEBUG_ASSERT(0 && "Unsupported size");
      return 0;
  }
}

static uint64_t path_inode_number(const char* path) {
  struct stat st;
  int ret = stat(path, &st);
  DEBUG_ASSERT(ret == 0);
  return st.st_ino;
}

static bool is_same_namespace(const char* name, pid_t tid1, pid_t tid2) {
  char path1[PATH_MAX];
  char path2[PATH_MAX];
  sprintf(path1, "/proc/%d/ns/%s", tid1, name);
  sprintf(path2, "/proc/%d/ns/%s", tid2, name);
  return path_inode_number(path1) == path_inode_number(path2);
}

template <typename Arch>
static void ptrace_get_reg_set(RecordTask* t, TaskSyscallState& syscall_state,
                               const vector<uint8_t>& regs) {
  auto piov = syscall_state.reg_parameter<typename Arch::iovec>(4, IN_OUT);
  auto iov = t->read_mem(piov);
  iov.iov_len = min<size_t>(iov.iov_len, regs.size());
  t->write_mem(piov, iov);
  auto data = syscall_state.mem_ptr_parameter(REMOTE_PTR_FIELD(piov, iov_base),
                                              iov.iov_len);
  t->write_bytes_helper(data, iov.iov_len, regs.data());
  syscall_state.emulate_result(0);
}

template <typename Arch>
static void ptrace_verify_set_reg_set(RecordTask* t, size_t min_size,
                                      TaskSyscallState& syscall_state) {
  auto iov = t->read_mem(remote_ptr<typename Arch::iovec>(t->regs().arg4()));
  if (iov.iov_len < min_size) {
    syscall_state.emulate_result(-EIO);
    return;
  }
  syscall_state.emulate_result(0);
}

static bool verify_ptrace_options(RecordTask* t,
                                  TaskSyscallState& syscall_state) {
  // We "support" PTRACE_O_SYSGOOD because we don't support PTRACE_SYSCALL yet
  static const int supported_ptrace_options =
      PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXIT | PTRACE_O_TRACEFORK |
      PTRACE_O_TRACECLONE | PTRACE_O_TRACEVFORK | PTRACE_O_TRACEEXEC;

  if ((int)t->regs().arg4() & ~supported_ptrace_options) {
    LOG(debug) << "Unsupported ptrace options " << HEX(t->regs().arg4());
    syscall_state.emulate_result(-EINVAL);
    return false;
  }
  return true;
}

static bool check_ptracer_compatible(RecordTask* tracer, RecordTask* tracee) {
  // Don't allow a 32-bit process to trace a 64-bit process. That doesn't
  // make much sense (manipulating registers gets crazy), and would be hard to
  // support.
  if (tracee->emulated_ptracer || tracee->tgid() == tracer->tgid() ||
      (tracer->arch() == x86 && tracee->arch() == x86_64)) {
    return false;
  }
  return true;
}

static RecordTask* get_ptrace_partner(RecordTask* t, pid_t pid) {
  // To simplify things, require that a ptracer be in the same pid
  // namespace as rr itself. I.e., tracee tasks sandboxed in a pid
  // namespace can't use ptrace. This is normally a requirement of
  // sandboxes anyway.
  // This could be supported, but would require some work to translate
  // rr's pids to/from the ptracer's pid namespace.
  ASSERT(t, is_same_namespace("pid", t->tid, getpid()));
  RecordTask* partner = t->session().find_task(pid);
  if (!partner) {
    // XXX This prevents a tracee from attaching to a process which isn't
    // under rr's control. We could support this but it would complicate
    // things.
    return nullptr;
  }
  return partner;
}

static RecordTask* prepare_ptrace_attach(RecordTask* t, pid_t pid,
                                         TaskSyscallState& syscall_state) {
  RecordTask* tracee = get_ptrace_partner(t, pid);
  if (!tracee) {
    syscall_state.emulate_result(-ESRCH);
    return nullptr;
  }
  if (!check_ptracer_compatible(t, tracee)) {
    syscall_state.emulate_result(-EPERM);
    return nullptr;
  }
  return tracee;
}

static RecordTask* prepare_ptrace_traceme(RecordTask* t,
                                          TaskSyscallState& syscall_state) {
  RecordTask* tracer = get_ptrace_partner(t, t->get_parent_pid());
  if (!tracer) {
    syscall_state.emulate_result(-ESRCH);
    return nullptr;
  }
  if (!check_ptracer_compatible(tracer, t)) {
    syscall_state.emulate_result(-EPERM);
    return nullptr;
  }
  return tracer;
}

static void ptrace_attach_to_already_stopped_task(RecordTask* t) {
  ASSERT(t, t->emulated_stop_type == GROUP_STOP);
  // tracee is already stopped because of a group-stop signal.
  // Sending a SIGSTOP won't work, but we don't need to.
  t->force_emulate_ptrace_stop(WaitStatus::for_stop_sig(SIGSTOP));
  siginfo_t si;
  memset(&si, 0, sizeof(si));
  si.si_signo = SIGSTOP;
  si.si_code = SI_USER;
  t->save_ptrace_signal_siginfo(si);
}

/**
 * The PTRACE_GETREGS/PTRACE_SETREGS commands, as well various PEEK_* and POKE_*
 * ptrace commands are legacy and not implemented on newer architectures.
 * We split them out here, since these newer platforms
 * will not define the requisite data structure to serve them.
 */
template <typename Arch>
static void prepare_ptrace_legacy(RecordTask* t,
                                  TaskSyscallState& syscall_state)
{
  pid_t pid = (pid_t)t->regs().arg2_signed();
  int command = (int)t->regs().arg1_signed();
  switch (command) {
    case PTRACE_PEEKTEXT:
    case PTRACE_PEEKDATA: {
      RecordTask* tracee = verify_ptrace_target(t, syscall_state, pid);
      if (tracee) {
        // The actual syscall returns the data via the 'data' out-parameter.
        // The behavior of returning the data as the system call result is
        // provided by the glibc wrapper.
        auto datap =
            syscall_state.reg_parameter<typename Arch::unsigned_word>(4);
        remote_ptr<typename Arch::unsigned_word> addr = t->regs().arg3();
        bool ok = true;
        auto v = tracee->read_mem(addr, &ok);
        if (ok) {
          t->write_mem(datap, v);
          syscall_state.emulate_result(0);
        } else {
          syscall_state.emulate_result(-EIO);
        }
      }
      break;
    }
    case PTRACE_POKETEXT:
    case PTRACE_POKEDATA: {
      RecordTask* tracee = verify_ptrace_target(t, syscall_state, pid);
      if (tracee) {
        remote_ptr<typename Arch::unsigned_word> addr = t->regs().arg3();
        typename Arch::unsigned_word data = t->regs().arg4();
        bool ok = true;
        tracee->write_mem(addr, data, &ok);
        if (ok) {
          // Since we're recording data that might not be for |t|, we have to
          // handle this specially during replay.
          tracee->record_local(addr, &data);
          syscall_state.emulate_result(0);
        } else {
          syscall_state.emulate_result(-EIO);
        }
      }
      break;
    }
    case Arch::PTRACE_PEEKUSR: {
      RecordTask* tracee = verify_ptrace_target(t, syscall_state, pid);
      if (tracee) {
        // The actual syscall returns the data via the 'data' out-parameter.
        // The behavior of returning the data as the system call result is
        // provided by the glibc wrapper.
        size_t addr = t->regs().arg3();
        typename Arch::unsigned_word data;
        if ((addr & (sizeof(data) - 1)) ||
            addr >= sizeof(typename Arch::user)) {
          syscall_state.emulate_result(-EIO);
          break;
        }

        auto datap =
            syscall_state.reg_parameter<typename Arch::unsigned_word>(4);
        if (addr < sizeof(typename Arch::user_regs_struct)) {
          uint8_t buf[Registers::MAX_SIZE];
          bool defined;
          size_t size =
              tracee->regs().read_register_by_user_offset(buf, addr, &defined);
          if (defined) {
            // For unclear reasons, all 32-bit user_regs_struct members are
            // signed while all 64-bit user_regs_struct members are unsigned.
            if (Arch::arch() == x86) {
              data = widen_buffer_signed(buf, size);
            } else {
              data = widen_buffer_unsigned(buf, size);
            }
          } else {
            data = 0;
          }
        } else if (addr >= offsetof(typename Arch::user, u_debugreg[0]) &&
                   addr < offsetof(typename Arch::user, u_debugreg[8])) {
          size_t regno = (addr - offsetof(typename Arch::user, u_debugreg[0])) /
                         sizeof(data);
          data = tracee->get_debug_reg(regno);
        } else {
          data = 0;
        }

        t->write_mem(datap, data);
        syscall_state.emulate_result(0);
      }
      break;
    }
    case Arch::PTRACE_POKEUSR: {
      RecordTask* tracee = verify_ptrace_target(t, syscall_state, pid);
      if (tracee) {
        // The actual syscall returns the data via the 'data' out-parameter.
        // The behavior of returning the data as the system call result is
        // provided by the glibc wrapper.
        size_t addr = t->regs().arg3();
        if ((addr & (sizeof(typename Arch::unsigned_word) - 1)) ||
            addr >= sizeof(typename Arch::user)) {
          syscall_state.emulate_result(-EIO);
          break;
        }
        syscall_state.emulate_result(0);
      }
      break;
    }
    case Arch::PTRACE_GETREGS: {
      RecordTask* tracee = verify_ptrace_target(t, syscall_state, pid);
      if (tracee) {
        auto data =
            syscall_state.reg_parameter<typename Arch::user_regs_struct>(4);
        auto regs = tracee->regs().get_ptrace_for_arch(Arch::arch());
        ASSERT(t, regs.size() == data.referent_size());
        t->write_bytes_helper(data, regs.size(), regs.data());
        syscall_state.emulate_result(0);
      }
      break;
    }
    case Arch::PTRACE_GETFPREGS: {
      RecordTask* tracee = verify_ptrace_target(t, syscall_state, pid);
      if (tracee) {
        auto data =
            syscall_state.reg_parameter<typename Arch::user_fpregs_struct>(4);
        auto regs = tracee->extra_regs().get_user_fpregs_struct(Arch::arch());
        ASSERT(t, regs.size() == data.referent_size());
        t->write_bytes_helper(data, regs.size(), regs.data());
        syscall_state.emulate_result(0);
      }
      break;
    }
    case Arch::PTRACE_GETFPXREGS: {
      if (Arch::arch() != x86) {
        // GETFPXREGS is x86-32 only
        syscall_state.expect_errno = EIO;
        break;
      }
      RecordTask* tracee = verify_ptrace_target(t, syscall_state, pid);
      if (tracee) {
        auto data =
            syscall_state.reg_parameter<X86Arch::user_fpxregs_struct>(4);
        auto regs = tracee->extra_regs().get_user_fpxregs_struct();
        t->write_mem(data, regs);
        syscall_state.emulate_result(0);
      }
      break;
    }
    case Arch::PTRACE_SETREGS: {
      RecordTask* tracee = verify_ptrace_target(t, syscall_state, pid);
      if (tracee) {
        // The actual register effects are performed by
        // Task::on_syscall_exit_arch
        syscall_state.emulate_result(0);
      }
      break;
    }
    case Arch::PTRACE_SETFPREGS: {
      RecordTask* tracee = verify_ptrace_target(t, syscall_state, pid);
      if (tracee) {
        // The actual register effects are performed by
        // Task::on_syscall_exit_arch
        syscall_state.emulate_result(0);
      }
      break;
    }
    case Arch::PTRACE_SETFPXREGS: {
      if (Arch::arch() != x86) {
        // SETFPXREGS is x86-32 only
        syscall_state.expect_errno = EIO;
        break;
      }
      RecordTask* tracee = verify_ptrace_target(t, syscall_state, pid);
      if (tracee) {
        // The actual register effects are performed by
        // Task::on_syscall_exit_arch
        syscall_state.emulate_result(0);
      }
      break;
    }
  }
}

template <>
void prepare_ptrace_legacy<ARM64Arch>(RecordTask*, TaskSyscallState&) {
  // Nothing to do - unimplemented on this architecture
}

static int non_negative_command(int command) { return command < 0 ? INT32_MAX : command; }

template <typename Arch>
static Switchable prepare_ptrace(RecordTask* t,
                                 TaskSyscallState& syscall_state) {
  pid_t pid = (pid_t)t->regs().arg2_signed();
  bool emulate = true;
  int command = (int)t->regs().arg1_signed();
  switch (non_negative_command(command)) {
    case PTRACE_ATTACH: {
      RecordTask* tracee = prepare_ptrace_attach(t, pid, syscall_state);
      if (!tracee) {
        break;
      }
      tracee->set_emulated_ptracer(t);
      tracee->emulated_ptrace_seized = false;
      tracee->emulated_ptrace_options = 0;
      syscall_state.emulate_result(0);
      if (tracee->emulated_stop_type == NOT_STOPPED) {
        // Send SIGSTOP to this specific thread. Otherwise the kernel might
        // deliver SIGSTOP to some other thread of the process, and we won't
        // generate any ptrace event if that thread isn't being ptraced.
        tracee->tgkill(SIGSTOP);
      } else {
        ptrace_attach_to_already_stopped_task(tracee);
      }
      break;
    }
    case PTRACE_TRACEME: {
      RecordTask* tracer = prepare_ptrace_traceme(t, syscall_state);
      if (!tracer) {
        break;
      }
      t->set_emulated_ptracer(tracer);
      t->emulated_ptrace_seized = false;
      t->emulated_ptrace_options = 0;
      syscall_state.emulate_result(0);
      break;
    }
    case PTRACE_SEIZE: {
      RecordTask* tracee = prepare_ptrace_attach(t, pid, syscall_state);
      if (!tracee) {
        break;
      }
      if (t->regs().arg3()) {
        syscall_state.emulate_result(-EIO);
        break;
      }
      if (!verify_ptrace_options(t, syscall_state)) {
        break;
      }
      tracee->set_emulated_ptracer(t);
      tracee->emulated_ptrace_seized = true;
      tracee->emulated_ptrace_options = (int)t->regs().arg4();
      if (tracee->emulated_stop_type == GROUP_STOP) {
        ptrace_attach_to_already_stopped_task(tracee);
      }
      syscall_state.emulate_result(0);
      break;
    }
    case Arch::PTRACE_OLDSETOPTIONS:
      RR_FALLTHROUGH;
    case PTRACE_SETOPTIONS: {
      RecordTask* tracee = verify_ptrace_target(t, syscall_state, pid);
      if (tracee) {
        if (!verify_ptrace_options(t, syscall_state)) {
          break;
        }
        tracee->emulated_ptrace_options = (int)t->regs().arg4();
        syscall_state.emulate_result(0);
      }
      break;
    }
    case PTRACE_GETEVENTMSG: {
      RecordTask* tracee = verify_ptrace_target(t, syscall_state, pid);
      if (tracee) {
        auto datap =
            syscall_state.reg_parameter<typename Arch::unsigned_long>(4);
        t->write_mem(
            datap,
            (typename Arch::unsigned_long)tracee->emulated_ptrace_event_msg);
        syscall_state.emulate_result(0);
      }
      break;
    }
    case PTRACE_GETSIGINFO: {
      RecordTask* tracee = verify_ptrace_target(t, syscall_state, pid);
      if (tracee) {
        auto datap = syscall_state.reg_parameter<typename Arch::siginfo_t>(4);
        typename Arch::siginfo_t dest;
        memset(&dest, 0, sizeof(dest));
        set_arch_siginfo(tracee->get_saved_ptrace_siginfo(), Arch::arch(),
                         &dest, sizeof(dest));
        t->write_mem(datap, dest);
        syscall_state.emulate_result(0);
      }
      break;
    }
    case PTRACE_GETREGSET: {
      switch ((int)t->regs().arg3()) {
        case NT_PRSTATUS: {
          RecordTask* tracee = verify_ptrace_target(t, syscall_state, pid);
          if (tracee) {
            auto regs = tracee->regs().get_ptrace_for_arch(tracee->arch());
            ptrace_get_reg_set<Arch>(t, syscall_state, regs);
          }
          break;
        }
        case NT_PRFPREG: {
          RecordTask* tracee = verify_ptrace_target(t, syscall_state, pid);
          if (tracee) {
            auto regs =
                tracee->extra_regs().get_user_fpregs_struct(tracee->arch());
            ptrace_get_reg_set<Arch>(t, syscall_state, regs);
          }
          break;
        }
        case NT_ARM_SYSTEM_CALL: {
          if (Arch::arch() != aarch64) {
            syscall_state.expect_errno = EINVAL;
            emulate = false;
            break;
          }
          RecordTask* tracee = verify_ptrace_target(t, syscall_state, pid);
          if (tracee) {
            int syscallno = tracee->regs().original_syscallno();
            uint8_t *data = (uint8_t*)&syscallno;
            vector<uint8_t> regs(data, data+sizeof(syscallno));
            ptrace_get_reg_set<Arch>(t, syscall_state, regs);
          }
          break;
        }
        case NT_ARM_HW_BREAK:
        case NT_ARM_HW_WATCH: {
          if (Arch::arch() != aarch64) {
            syscall_state.expect_errno = EINVAL;
            emulate = false;
            break;
          }
          RecordTask* tracee = verify_ptrace_target(t, syscall_state, pid);
          if (tracee) {
            ARM64Arch::user_hwdebug_state bps;
            bool ok = tracee->get_aarch64_debug_regs((int)t->regs().arg3(), &bps);
            ASSERT(tracee, ok);
            uint8_t *data = (uint8_t*)&bps;
            vector<uint8_t> regs(data, data+sizeof(bps));
            ptrace_get_reg_set<Arch>(t, syscall_state, regs);
          }
          break;
        }
        case NT_X86_XSTATE: {
          if (!Arch::is_x86ish()) {
            syscall_state.expect_errno = EINVAL;
            emulate = false;
            break;
          }
          RecordTask* tracee = verify_ptrace_target(t, syscall_state, pid);
          if (tracee) {
            switch (tracee->extra_regs().format()) {
              case ExtraRegisters::XSAVE:
                ptrace_get_reg_set<Arch>(t, syscall_state,
                                         tracee->extra_regs().data());
                break;
              default:
                syscall_state.emulate_result(-EINVAL);
                break;
            }
          }
          break;
        }
        default:
          syscall_state.expect_errno = EINVAL;
          emulate = false;
          break;
      }
      break;
    }
    case PTRACE_SETREGSET: {
      // The actual register effects are performed by
      // Task::on_syscall_exit_arch
      switch ((int)t->regs().arg3()) {
        case NT_PRSTATUS: {
          RecordTask* tracee = verify_ptrace_target(t, syscall_state, pid);
          if (tracee) {
            ptrace_verify_set_reg_set<Arch>(
                t, user_regs_struct_size(tracee->arch()), syscall_state);
          }
          break;
        }
        case NT_PRFPREG: {
          RecordTask* tracee = verify_ptrace_target(t, syscall_state, pid);
          if (tracee) {
            ptrace_verify_set_reg_set<Arch>(
                t, user_fpregs_struct_size(tracee->arch()), syscall_state);
          }
          break;
        }
        case NT_ARM_SYSTEM_CALL: {
          if (Arch::arch() != aarch64) {
            syscall_state.expect_errno = EINVAL;
            emulate = false;
            break;
          }
          RecordTask* tracee = verify_ptrace_target(t, syscall_state, pid);
          if (tracee) {
            ptrace_verify_set_reg_set<Arch>(
                t, sizeof(int), syscall_state);
          }
          break;
        }
        case NT_ARM_HW_WATCH:
        case NT_ARM_HW_BREAK: {
          if (Arch::arch() != aarch64) {
            syscall_state.expect_errno = EINVAL;
            emulate = false;
            break;
          }
          RecordTask* tracee = verify_ptrace_target(t, syscall_state, pid);
          if (tracee) {
            ptrace_verify_set_reg_set<Arch>(
                t, offsetof(ARM64Arch::user_hwdebug_state, dbg_regs[0]),
                syscall_state);
          }
          break;
        }
        case NT_X86_XSTATE: {
          if (!Arch::is_x86ish()) {
            syscall_state.expect_errno = EINVAL;
            emulate = false;
            break;
          }
          RecordTask* tracee = verify_ptrace_target(t, syscall_state, pid);
          if (tracee) {
            switch (tracee->extra_regs().format()) {
              case ExtraRegisters::XSAVE:
                ptrace_verify_set_reg_set<Arch>(
                    t, tracee->extra_regs().data_size(), syscall_state);
                break;
              default:
                syscall_state.emulate_result(-EINVAL);
                break;
            }
          }
          break;
        }
        default:
          syscall_state.expect_errno = EINVAL;
          emulate = false;
          break;
      }
      break;
    }
    case PTRACE_SYSCALL:
    case PTRACE_SINGLESTEP:
    case Arch::PTRACE_SYSEMU:
    case Arch::PTRACE_SYSEMU_SINGLESTEP:
    case PTRACE_CONT: {
      RecordTask* tracee = verify_ptrace_target(t, syscall_state, pid);
      // If the tracer wants to observe syscall entries, we can't use the
      // syscallbuf, because the tracer may want to change syscall numbers
      // which the syscallbuf code is not prepared to handle. Aditionally,
      // we also lock the syscallbuf for PTRACE_SINGLESTEP, since we usually
      // try to avoid delivering signals (e.g. PTRACE_SINGLESTEP's SIGTRAP)
      // inside syscallbuf code. However, if the syscallbuf if locked, doing
      // so should be safe.
      if (tracee) {
        if (!((unsigned int)t->regs().arg4() < _NSIG)) {
          // Invalid signals in ptrace resume cause EIO
          syscall_state.emulate_result(-EIO);
          break;
        }
        tracee->set_syscallbuf_locked(command != PTRACE_CONT);
        prepare_ptrace_cont(tracee, t->regs().arg4(), command);
        syscall_state.emulate_result(0);
      }
      break;
    }
    case PTRACE_DETACH: {
      RecordTask* tracee = verify_ptrace_target(t, syscall_state, pid);
      if (tracee) {
        tracee->set_syscallbuf_locked(0);
        tracee->emulated_ptrace_options = 0;
        tracee->emulated_ptrace_cont_command = 0;
        tracee->emulated_stop_pending = false;
        prepare_ptrace_cont(tracee, t->regs().arg4(), 0);
        tracee->set_emulated_ptracer(nullptr);
        syscall_state.emulate_result(0);
      }
      break;
    }
    case PTRACE_KILL: {
      RecordTask* tracee = verify_ptrace_target(t, syscall_state, pid);
      if (tracee) {
        // The tracee could already be dead, in which case sending it a signal
        // would move it out of the exit stop, preventing us from doing our
        // clean up work.
        tracee->try_wait();
        tracee->kill_if_alive();
        syscall_state.emulate_result(0);
      }
      break;
    }
    case Arch::PTRACE_GET_THREAD_AREA:
    case Arch::PTRACE_SET_THREAD_AREA: {
      RecordTask* tracee = verify_ptrace_target(t, syscall_state, pid);
      if (tracee) {
        if (tracee->arch() != SupportedArch::x86) {
          // This syscall should fail if the tracee is not x86
          syscall_state.expect_errno = EIO;
          emulate = false;
          break;
        }
        remote_ptr<X86Arch::user_desc> remote_addr(t->regs().arg4());
        bool ok = true;
        struct X86Arch::user_desc desc;
        memset(&desc, 0, sizeof(struct X86Arch::user_desc));
        // Do the ptrace request ourselves
        if (command == Arch::PTRACE_GET_THREAD_AREA) {
          int ret = -tracee->emulate_get_thread_area(t->regs().arg3(), desc);
          if (ret == 0) {
            t->write_mem(remote_addr, desc, &ok);
            if (!ok) {
              syscall_state.emulate_result(-EFAULT);
              break;
            }
            t->record_local(remote_addr, &desc);
          }
          syscall_state.emulate_result(ret);
        } else {
          desc = t->read_mem(remote_addr, &ok);
          if (!ok) {
            syscall_state.emulate_result(-EFAULT);
            break;
          }
          syscall_state.emulate_result(
              -tracee->emulate_set_thread_area((int)t->regs().arg3(), desc));
        }
      }
      break;
    }
    case Arch::PTRACE_ARCH_PRCTL: {
      RecordTask* tracee = verify_ptrace_target(t, syscall_state, pid);
      if (tracee) {
        if (tracee->arch() != SupportedArch::x86_64) {
          // This syscall should fail if the tracee is not
          // x86_64
          syscall_state.expect_errno = EIO;
          emulate = false;
          break;
        }
        int code = (int)t->regs().arg4();
        switch (code) {
          case ARCH_GET_FS:
          case ARCH_GET_GS: {
            bool ok = true;
            remote_ptr<uint64_t> addr(t->regs().arg3());
            uint64_t data = code == ARCH_GET_FS ?
                            tracee->regs().fs_base() : tracee->regs().gs_base();
            t->write_mem(addr, data, &ok);
            if (ok) {
              t->record_local(addr, &data);
              syscall_state.emulate_result(0);
            } else {
              syscall_state.emulate_result(-EIO);
            }
            break;
          }
          case ARCH_SET_FS:
          case ARCH_SET_GS:
            syscall_state.emulate_result(0);
            break;
          default:
            syscall_state.emulate_result(-EINVAL);
            break;
        }
      }
      break;
    }
    case Arch::PTRACE_PEEKTEXT:
    case Arch::PTRACE_PEEKDATA:
    case Arch::PTRACE_POKETEXT:
    case Arch::PTRACE_POKEDATA:
    case Arch::PTRACE_PEEKUSR:
    case Arch::PTRACE_POKEUSR:
    case Arch::PTRACE_GETREGS:
    case Arch::PTRACE_GETFPREGS:
    case Arch::PTRACE_GETFPXREGS:
    case Arch::PTRACE_SETREGS:
    case Arch::PTRACE_SETFPREGS:
    case Arch::PTRACE_SETFPXREGS:
      prepare_ptrace_legacy<Arch>(t, syscall_state);
      break;
    default:
      syscall_state.expect_errno = EIO;
      emulate = false;
      break;
  }
  if (emulate) {
    Registers r = t->regs();
    r.set_arg1((intptr_t)-1);
    t->set_regs(r);
  }
  return PREVENT_SWITCH;
}

static void check_signals_while_exiting(RecordTask* t) {
  const RecordTask::StashedSignal* s = t->peek_stashed_sig_to_deliver();
  if (s) {
    // An unblockable signal (SIGKILL, SIGSTOP) might be received
    // and stashed. Since these signals are unblockable they take
    // effect no matter what and we don't need to deliver them to an exiting
    // thread.
    int sig = s->siginfo.si_signo;
    ASSERT(t, sig == SIGKILL || sig == SIGSTOP)
        << "Got unexpected signal " << s->siginfo
        << " (should have been blocked)";
  }
}

static bool send_signal_during_init_buffers() {
  static bool send = getenv("RR_INIT_BUFFERS_SEND_SIGNAL") != nullptr;
  return send;
}

/**
 * At thread exit time, undo the work that init_buffers() did.
 *
 * Call this when the tracee has already entered SYS_exit/SYS_exit_group. The
 * tracee will be returned at a state in which it has entered (or
 * re-entered) SYS_exit/SYS_exit_group.
 */
static void prepare_exit(RecordTask* t) {
  // RecordSession is responsible for ensuring we don't get here with
  // pending signals.
  ASSERT(t, !t->has_stashed_sig());

  t->stable_exit = true;
  t->session().scheduler().in_stable_exit(t);

  Registers r = t->regs();
  Registers exit_regs = r;
  ASSERT(t,
         is_exit_syscall(exit_regs.original_syscallno(),
                         t->ev().Syscall().arch()) ||
             is_exit_group_syscall(exit_regs.original_syscallno(),
                                   t->ev().Syscall().arch()))
      << "Tracee should have been at exit/exit_group, but instead at "
      << t->ev().Syscall().syscall_name();

  // The first thing we need to do is to block all signals to prevent
  // a signal being delivered to the thread (since it's going to exit and
  // won't be able to handle any more signals).
  //
  // The tracee is at the entry to SYS_exit/SYS_exit_group, but hasn't started
  // the call yet.  We can't directly start injecting syscalls
  // because the tracee is still in the kernel.  And obviously,
  // if we finish the SYS_exit/SYS_exit_group syscall, the tracee isn't around
  // anymore.
  //
  // So hijack this SYS_exit call and rewrite it into a SYS_rt_sigprocmask.
  r.set_original_syscallno(syscall_number_for_rt_sigprocmask(t->arch()));
  r.set_arg1(SIG_BLOCK);
  r.set_arg2(AddressSpace::rr_page_ff_bytes());
  r.set_arg3(0);
  r.set_arg4(sizeof(sig_set_t));
  t->set_regs(r);
  // This exits the SYS_rt_sigprocmask.  Now the tracee is ready to do our
  // bidding.
  t->exit_syscall();
  check_signals_while_exiting(t);

  // Do the actual buffer and fd cleanup.
  t->destroy_buffers();

  check_signals_while_exiting(t);

  // Restore these regs to what they would have been just before
  // the tracee trapped at SYS_exit/SYS_exit_group.  When we've finished
  // cleanup, we'll restart the call.
  exit_regs.set_syscallno(exit_regs.original_syscallno());
  exit_regs.set_original_syscallno(-1);
  exit_regs.set_ip(exit_regs.ip() - syscall_instruction_length(t->arch()));
  ASSERT(t, is_at_syscall_instruction(t, exit_regs.ip()))
      << "Tracee should have entered through int $0x80.";
  // Restart the SYS_exit call.
  t->set_regs(exit_regs);
  t->enter_syscall();
  check_signals_while_exiting(t);

  if (t->emulated_ptrace_options & PTRACE_O_TRACEEXIT) {
    t->emulate_ptrace_stop(WaitStatus::for_ptrace_event(PTRACE_EVENT_EXIT));
  }
}

static void prepare_mmap_register_params(RecordTask* t) {
  Registers r = t->regs();
  intptr_t mask_flag = MAP_FIXED;
#ifdef MAP_32BIT
  mask_flag |= MAP_32BIT;
#endif
  if (t->session().enable_chaos() &&
      !(r.arg4_signed() & mask_flag) && r.arg1() == 0) {
    // No address hint was provided. Randomize the allocation address.
    size_t len = r.arg2();
    if (r.arg4_signed() & MAP_GROWSDOWN) {
      // Ensure stacks can grow to the minimum size we choose
      len = max<size_t>(AddressSpace::chaos_mode_min_stack_size(), len);
    }
    remote_ptr<void> addr = t->vm()->chaos_mode_find_free_memory(t, len);
    if (!addr.is_null()) {
      r.set_arg1(addr + len - r.arg2());
      // Note that we don't set MAP_FIXED here. If anything goes wrong (e.g.
      // we pick a hint address that actually can't be used on this system), the
      // kernel will pick a valid address instead.
    }
  }
  r.set_arg4(r.arg4_signed() & ~MAP_GROWSDOWN);
  t->set_regs(r);
}

enum ScratchAddrType { FIXED_ADDRESS, DYNAMIC_ADDRESS };
/* Pointer used when running RR in WINE. Memory below this address is
   unmapped by WINE immediately after exec, so start the scratch buffer
   here. */
static const uintptr_t FIXED_SCRATCH_PTR = 0x68000000;

static void init_scratch_memory(RecordTask* t,
                                ScratchAddrType addr_type = DYNAMIC_ADDRESS) {
  const int scratch_size = 512 * page_size();
  size_t sz = scratch_size;
  // The PROT_EXEC looks scary, and it is, but it's to prevent
  // this region from being coalesced with another anonymous
  // segment mapped just after this one.  If we named this
  // segment, we could remove this hack.
  int prot = PROT_READ | PROT_WRITE | PROT_EXEC;
  int flags = MAP_PRIVATE | MAP_ANONYMOUS;
  {
    /* initialize the scratchpad for blocking system calls */
    AutoRemoteSyscalls remote(t);

    if (addr_type == DYNAMIC_ADDRESS) {
      t->scratch_ptr = remote.infallible_mmap_syscall(remote_ptr<void>(), sz,
                                                      prot, flags, -1, 0);
    } else {
      t->scratch_ptr =
          remote.infallible_mmap_syscall(remote_ptr<void>(FIXED_SCRATCH_PTR),
                                         sz, prot, flags | MAP_FIXED, -1, 0);
    }
    t->scratch_size = scratch_size;
  }

  t->setup_preload_thread_locals();

  // record this mmap for the replay
  Registers r = t->regs();
  uintptr_t saved_result = r.syscall_result();
  r.set_syscall_result(t->scratch_ptr);
  t->set_regs(r);

  KernelMapping km =
      t->vm()->map(t, t->scratch_ptr, sz, prot, flags, 0, string());
  struct stat stat;
  memset(&stat, 0, sizeof(stat));
  auto record_in_trace = t->trace_writer().write_mapped_region(t,
    km, stat, km.fsname(), vector<TraceRemoteFd>());
  ASSERT(t, record_in_trace == TraceWriter::DONT_RECORD_IN_TRACE);

  r.set_syscall_result(saved_result);
  t->set_regs(r);
}

static int ptrace_option_for_event(int ptrace_event) {
  switch (ptrace_event) {
    case PTRACE_EVENT_FORK:
      return PTRACE_O_TRACEFORK;
    case PTRACE_EVENT_CLONE:
      return PTRACE_O_TRACECLONE;
    case PTRACE_EVENT_VFORK:
      return PTRACE_O_TRACEVFORK;
    default:
      FATAL() << "Unsupported ptrace event";
      return 0;
  }
}

template <typename Arch>
static void prepare_clone(RecordTask* t, TaskSyscallState& syscall_state) {
  uintptr_t flags;
  CloneParameters params;
  Registers r = t->regs();
  int original_syscall = r.original_syscallno();
  int ptrace_event;
  int termination_signal = SIGCHLD;

  if (is_clone_syscall(original_syscall, r.arch())) {
    params = extract_clone_parameters(t);
    flags = r.arg1();
    r.set_arg1(flags & ~uintptr_t(CLONE_UNTRACED));
    t->set_regs(r);
    termination_signal = flags & 0xff;
    if (flags & CLONE_VFORK) {
      ptrace_event = PTRACE_EVENT_VFORK;
    } else if (termination_signal == SIGCHLD) {
      ptrace_event = PTRACE_EVENT_FORK;
    } else {
      ptrace_event = PTRACE_EVENT_CLONE;
    }
  } else if (is_vfork_syscall(original_syscall, r.arch())) {
    ptrace_event = PTRACE_EVENT_VFORK;
    flags = CLONE_VM | CLONE_VFORK | SIGCHLD;
  } else {
    ptrace_event = PTRACE_EVENT_FORK;
    flags = SIGCHLD;
  }

  while (true) {
    t->resume_execution(RESUME_SYSCALL, RESUME_WAIT, RESUME_NO_TICKS);
    // XXX handle stray signals?
    if (t->ptrace_event()) {
      break;
    }
    ASSERT(t, !t->stop_sig());
    ASSERT(t, t->regs().syscall_result_signed() < 0);
    if (!t->regs().syscall_may_restart()) {
      LOG(debug) << "clone failed, returning "
                 << errno_name(-t->regs().syscall_result_signed());
      syscall_state.emulate_result(t->regs().syscall_result());
      // clone failed and we're existing the syscall with an error. Reenter
      // the syscall so that we're in the same state as the normal execution
      // path.
      t->ev().Syscall().failed_during_preparation = true;
      // Restore register we might have changed
      r.set_arg1(syscall_state.syscall_entry_registers.arg1());
      r.set_syscallno(Arch::gettid);
      r.set_ip(r.ip().decrement_by_syscall_insn_length(r.arch()));
      t->set_regs(r);
      t->enter_syscall();
      r.set_ip(t->regs().ip());
      r.set_syscallno(original_syscall);
      r.set_original_syscallno(original_syscall);
      t->set_regs(r);
      t->canonicalize_regs(t->arch());
      return;
    }
    // Reenter the syscall. If we try to return an ERESTART* error using the
    // code path above, our set_syscallno(SYS_gettid) fails to take effect and
    // we actually do the clone, and things get horribly confused.
    r.set_syscallno(r.original_syscallno());
    r.set_ip(r.ip().decrement_by_syscall_insn_length(r.arch()));
    t->set_regs(r);
    t->enter_syscall();
  }

  ASSERT(t, t->ptrace_event() == ptrace_event);

  // Ideally we'd just use t->get_ptrace_eventmsg_pid() here, but
  // kernels failed to translate that value from other pid namespaces to
  // our pid namespace until June 2014:
  // https://github.com/torvalds/linux/commit/4e52365f279564cef0ddd41db5237f0471381093
  pid_t new_tid;
  if (flags & CLONE_THREAD) {
    new_tid = t->find_newborn_thread();
  } else {
    new_tid = t->find_newborn_process(flags & CLONE_PARENT ? t->get_parent_pid()
                                                           : t->real_tgid());
  }
  RecordTask* new_task = static_cast<RecordTask*>(
      t->session().clone(t, clone_flags_to_task_flags(flags), params.stack,
                         params.tls, params.ctid, new_tid));

  // Restore modified registers in cloned task
  Registers new_r = new_task->regs();
  new_r.set_original_syscallno(
      syscall_state.syscall_entry_registers.original_syscallno());
  new_r.set_orig_arg1(syscall_state.syscall_entry_registers.arg1());
  new_task->set_regs(new_r);
  new_task->canonicalize_regs(new_task->arch());
  new_task->set_termination_signal(termination_signal);

  /* record child id here */
  if (is_clone_syscall(original_syscall, r.arch())) {
    CloneParameters child_params = extract_clone_parameters(new_task);
    t->record_remote_even_if_null(params.ptid);

    if (Arch::clone_tls_type == Arch::UserDescPointer) {
      t->record_remote_even_if_null(
          params.tls.cast<typename Arch::user_desc>());
      new_task->record_remote_even_if_null(
          child_params.tls.cast<typename Arch::user_desc>());
    } else {
      DEBUG_ASSERT(Arch::clone_tls_type == Arch::PthreadStructurePointer);
    }
    new_task->record_remote_even_if_null(child_params.ptid);
    new_task->record_remote_even_if_null(child_params.ctid);
  }
  t->session().trace_writer().write_task_event(TraceTaskEvent::for_clone(
      new_task->tid, t->tid, new_task->own_namespace_rec_tid, flags));

  init_scratch_memory(new_task);

  if ((t->emulated_ptrace_options & ptrace_option_for_event(ptrace_event)) &&
      !(flags & CLONE_UNTRACED)) {
    new_task->set_emulated_ptracer(t->emulated_ptracer);
    new_task->emulated_ptrace_seized = t->emulated_ptrace_seized;
    new_task->emulated_ptrace_options = t->emulated_ptrace_options;
    t->emulated_ptrace_event_msg = new_task->rec_tid;
    t->emulate_ptrace_stop(WaitStatus::for_ptrace_event(ptrace_event));
    // ptrace(2) man page says that SIGSTOP is used here, but it's really
    // SIGTRAP (in 4.4.4-301.fc23.x86_64 anyway).
    new_task->apply_group_stop(SIGTRAP);
  }

  // Restore our register modifications now, so that the emulated ptracer will
  // see the original registers without our modifications if it inspects them
  // in the ptrace event.
  r = t->regs();
  r.set_orig_arg1(syscall_state.syscall_entry_registers.arg1());
  r.set_original_syscallno(
      syscall_state.syscall_entry_registers.original_syscallno());
  t->set_regs(r);
  t->canonicalize_regs(t->arch());

  // We're in a PTRACE_EVENT_FORK/VFORK/CLONE so the next PTRACE_SYSCALL for
  // |t| will go to the exit of the syscall, as expected.
}

static bool protect_rr_sigs(RecordTask* t, remote_ptr<void> p, void* save) {
  remote_ptr<sig_set_t> setp = p.cast<sig_set_t>();
  if (setp.is_null()) {
    return false;
  }

  auto sig_set = t->read_mem(setp);
  auto new_sig_set = sig_set;
  new_sig_set &= ~t->session().rr_signal_mask();
  if (sig_set == new_sig_set) {
    return false;
  }

  t->write_mem(setp, new_sig_set);
  if (save) {
    memcpy(save, &sig_set, sizeof(sig_set));
  }

  return true;
}

template <typename Arch>
static bool protect_rr_sigs_sa_mask_arch(RecordTask* t, remote_ptr<void> p,
                                         void* save) {
  remote_ptr<typename Arch::kernel_sigaction> sap =
      p.cast<typename Arch::kernel_sigaction>();
  if (sap.is_null()) {
    return false;
  }

  auto sa = t->read_mem(sap);
  auto new_sig_set = sa.sa_mask;
  // Don't let the tracee block TIME_SLICE_SIGNAL or
  // SYSCALLBUF_DESCHED_SIGNAL.
  new_sig_set.__val[0] &= ~t->session().rr_signal_mask();

  if (!memcmp(&sa.sa_mask, &new_sig_set, sizeof(new_sig_set))) {
    return false;
  }

  if (save) {
    memcpy(save, &sa, sizeof(sa));
  }
  sa.sa_mask = new_sig_set;
  t->write_mem(sap, sa);

  return true;
}

static bool protect_rr_sigs_sa_mask(RecordTask* t, remote_ptr<void> p,
                                    void* save) {
  RR_ARCH_FUNCTION(protect_rr_sigs_sa_mask_arch, t->arch(), t, p, save);
}

static void record_ranges(RecordTask* t,
                          const vector<FileMonitor::Range>& ranges,
                          size_t size) {
  size_t s = size;
  for (auto& r : ranges) {
    size_t bytes = min(s, r.length);
    if (bytes > 0) {
      t->record_remote(r.data, bytes);
      s -= bytes;
    }
  }
}

static pid_t do_detach_teleport(RecordTask *t)
{
  DiversionSession session;
  std::string exe_path(find_exec_stub(t->arch()));
  std::vector<std::string> argv, env;
  ScopedFd error_fd;
  int tracee_fd_number = t->session().tracee_fd_number();
  Task *new_t = Task::spawn(session, error_fd, &session.tracee_socket_fd(),
                  &session.tracee_socket_receiver_fd(),
                  &tracee_fd_number,
                  exe_path, argv, env,
                  -1);
  pid_t new_tid = new_t->tid;
  LOG(debug) << "Detached task with tid " << new_tid;
  session.on_create(new_t);
  session.set_tracee_fd_number(tracee_fd_number);
  new_t->os_exec_stub(t->arch());
  session.post_exec();
  new_t->post_exec(exe_path);
  new_t->post_exec_syscall();
  new_t->dup_from(t);
  // Emulate the success of the syscall in the new task
  Registers regs = new_t->regs();
  regs.set_arg1(0);
  new_t->set_regs(regs);
  // Disable syscall buffering. XXX: We could also try to unpatch syscalls here
  new_t->hpc.stop();
  new_t->set_in_diversion(true);
  // Just clean up some additional state
  new_t->reenable_cpuid_tsc();
  {
    AutoRemoteSyscalls remote(new_t, AutoRemoteSyscalls::DISABLE_MEMORY_PARAMS);
    remote.syscall(syscall_number_for_close(new_t->arch()), tracee_fd_number);
  }
  new_t->detach();
  new_t->did_kill();
  delete new_t;
  return new_tid;
}

template <typename Arch>
static Switchable did_emulate_read(int syscallno, RecordTask* t,
                                   const std::vector<FileMonitor::Range>& ranges,
                                   uint64_t result,
                                   TaskSyscallState& syscall_state)
{
  syscall_state.emulate_result(result);
  record_ranges(t, ranges, result);
  if (syscallno == Arch::pread64 || syscallno == Arch::preadv || result <= 0) {
    // Don't perform this syscall.
    Registers r = t->regs();
    r.set_arg1(-1);
    t->set_regs(r);
  } else {
    // Turn this into an lseek to emulate the advance of the fd ptr
    Registers r = t->regs();
    r.set_original_syscallno(Arch::lseek);
    r.set_arg2(result);
    r.set_arg3(SEEK_CUR);
    t->set_regs(r);
  }
  return PREVENT_SWITCH;
}

template <typename Arch>
static Switchable rec_prepare_syscall_arch(RecordTask* t,
                                           TaskSyscallState& syscall_state,
                                           const Registers& regs) {
  int syscallno = t->ev().Syscall().number;

  if (t->regs().original_syscallno() == SECCOMP_MAGIC_SKIP_ORIGINAL_SYSCALLNO) {
    // rr vetoed this syscall. Don't do any pre-processing.
    return PREVENT_SWITCH;
  }

  syscall_state.syscall_entry_registers = regs;

  if (t->desched_rec()) {
    /* |t| was descheduled while in a buffered syscall.  We normally don't
     * use scratch memory for the call, because the syscallbuf itself
     * is serving that purpose. More importantly, we *can't* set up
     * scratch for |t|, because it's already in the syscall. Instead, we will
     * record the syscallbuf memory in rec_process_syscall_arch.
     *
     * However there is one case where we use scratch memory: when
     * sys_read's block-cloning path is interrupted. In that case, record
     * the scratch memory.
     */
    if (syscallno == Arch::read &&
        remote_ptr<void>(regs.arg2()) == t->scratch_ptr) {
      syscall_state.reg_parameter(
          2, ParamSize::from_syscall_result<typename Arch::ssize_t>(
                 (size_t)regs.arg3()),
          IN_OUT_NO_SCRATCH);
    }
    return ALLOW_SWITCH;
  }

  if (syscallno < 0) {
    // Invalid syscall. Don't let it accidentally match a
    // syscall number below that's for an undefined syscall.
    if (!Arch::is_x86ish()) {
      // On architectures where arg1 is shared with the return value, the kernel
      // may not set -ENOSYS for us. There, it instead copies the arg1 to the return
      // value (frankly this is probably a bug, but likely nothing we can do
      // about it).
      Registers new_regs = regs;
      new_regs.set_syscall_result(-ENOSYS);
      t->set_regs(new_regs);
    }
    syscall_state.expect_errno = ENOSYS;
    return PREVENT_SWITCH;
  }

  switch (syscallno) {
// All the regular syscalls are handled here.
#include "SyscallRecordCase.generated"

    case Arch::splice: {
      syscall_state.reg_parameter<loff_t>(2, IN_OUT);
      syscall_state.reg_parameter<loff_t>(4, IN_OUT);
      return ALLOW_SWITCH;
    }

    case Arch::sendfile: {
      syscall_state.reg_parameter<typename Arch::off_t>(3, IN_OUT);
      return ALLOW_SWITCH;
    }
    case Arch::sendfile64: {
      syscall_state.reg_parameter<typename Arch::off64_t>(3, IN_OUT);
      return ALLOW_SWITCH;
    }

    case Arch::capget: {
      auto hdr = t->read_mem(
          syscall_state.reg_parameter<typename Arch::__user_cap_header_struct>(
              1, IN_OUT));
      int struct_count;
      switch (hdr.version) {
        case _LINUX_CAPABILITY_VERSION_1:
          struct_count = _LINUX_CAPABILITY_U32S_1;
          break;
        case _LINUX_CAPABILITY_VERSION_2:
          struct_count = _LINUX_CAPABILITY_U32S_2;
          break;
        case _LINUX_CAPABILITY_VERSION_3:
          struct_count = _LINUX_CAPABILITY_U32S_3;
          break;
        default:
          struct_count = 0;
          break;
      }
      if (struct_count > 0) {
        syscall_state.reg_parameter(
            2, sizeof(typename Arch::__user_cap_data_struct) * struct_count,
            OUT);
      }
      return PREVENT_SWITCH;
    }

    case Arch::fork:
    case Arch::vfork:
    case Arch::clone:
      prepare_clone<Arch>(t, syscall_state);
      return ALLOW_SWITCH;

    case Arch::exit:
      prepare_exit(t);
      return ALLOW_SWITCH;

    case Arch::exit_group:
      if (t->thread_group()->task_set().size() == 1) {
        prepare_exit(t);
        return ALLOW_SWITCH;
      }
      return PREVENT_SWITCH;

    case Arch::execve: {
      t->session().scheduler().did_enter_execve(t);
      vector<string> cmd_line;
      remote_ptr<typename Arch::unsigned_word> argv = regs.arg2();
      bool ok = true;
      while (true) {
        auto p = t->read_mem(argv, &ok);
        if (!ok) {
          syscall_state.expect_errno = EFAULT;
          return ALLOW_SWITCH;
        }
        if (!p) {
          break;
        }
        cmd_line.push_back(t->read_c_str(p, &ok));
        if (!ok) {
          syscall_state.expect_errno = EFAULT;
          return ALLOW_SWITCH;
        }
        argv++;
      }

      // Save the event. We can't record it here because the exec might fail.
      string raw_filename = t->read_c_str(regs.arg1(), &ok);
      if (!ok) {
        syscall_state.expect_errno = EFAULT;
        return ALLOW_SWITCH;
      }
      syscall_state.exec_saved_event =
          unique_ptr<TraceTaskEvent>(new TraceTaskEvent(
              TraceTaskEvent::for_exec(t->tid, raw_filename, cmd_line)));

      // This can trigger exits of non-main threads, so we have to
      // allow them to be handled.
      return ALLOW_SWITCH;
    }

    case Arch::fcntl:
    case Arch::fcntl64: {
      int fd = regs.arg1();
      uint64_t result;
      if (t->fd_table()->emulate_fcntl(fd, t, &result)) {
        // Don't perform this syscall.
        Registers r = regs;
        r.set_arg1(-1);
        t->set_regs(r);
        syscall_state.emulate_result(result);
        return PREVENT_SWITCH;
      }
      switch ((int)regs.arg2_signed()) {
        case Arch::DUPFD:
        case Arch::DUPFD_CLOEXEC:
        case Arch::GETFD:
        case Arch::GETFL:
        case Arch::SETFL:
        case Arch::SETLK:
        case Arch::SETLK64:
        case Arch::OFD_SETLK:
        case Arch::SETOWN:
        case Arch::SETOWN_EX:
        case Arch::GETSIG:
        case Arch::SETSIG:
        case Arch::SETPIPE_SZ:
        case Arch::GETPIPE_SZ:
        case Arch::ADD_SEALS:
        case Arch::GET_SEALS:
        case Arch::SET_RW_HINT:
        case Arch::SET_FILE_RW_HINT:
          break;

        case Arch::SETFD:
          if (t->fd_table()->is_rr_fd(fd)) {
            // Don't let tracee set FD_CLOEXEC on this fd. Disable the syscall,
            // but emulate a successful return.
            Registers r = regs;
            r.set_arg1(-1);
            t->set_regs(r);
            syscall_state.emulate_result(0);
          }
          break;

        case Arch::GETLK:
          syscall_state.reg_parameter<typename Arch::_flock>(3, IN_OUT);
          break;

        case Arch::OFD_GETLK:
        case Arch::GETLK64:
          // flock and flock64 better be different on 32-bit architectures,
          // but on 64-bit architectures, it's OK if they're the same.
          static_assert(
              sizeof(typename Arch::_flock) < sizeof(typename Arch::flock64) ||
                  Arch::elfclass == ELFCLASS64,
              "struct flock64 not declared differently from struct flock");
          syscall_state.reg_parameter<typename Arch::flock64>(3, IN_OUT);
          break;

        case Arch::GETOWN_EX:
          syscall_state.reg_parameter<typename Arch::f_owner_ex>(3);
          break;

        case Arch::SETLKW:
        case Arch::SETLKW64:
        case Arch::OFD_SETLKW:
          // SETLKW blocks, but doesn't write any
          // outparam data to the |struct flock|
          // argument, so no need for scratch.
          return ALLOW_SWITCH;

        case Arch::GET_RW_HINT:
        case Arch::GET_FILE_RW_HINT:
          syscall_state.reg_parameter<int64_t>(3);
          break;

        default:
          // Unknown command should trigger EINVAL.
          syscall_state.expect_errno = EINVAL;
          break;
      }
      return PREVENT_SWITCH;
    }

    /* futex parameters are in-out but they can't be moved to scratch
     * addresses. */
    case Arch::futex_time64:
    case Arch::futex: {
      int op = regs.arg2_signed();
      switch (op & FUTEX_CMD_MASK) {
        case FUTEX_WAIT:
        case FUTEX_WAIT_BITSET:
          return ALLOW_SWITCH;

        case FUTEX_REQUEUE:
        case FUTEX_CMP_REQUEUE:
        case FUTEX_WAKE_OP:
          syscall_state.reg_parameter<int>(5, IN_OUT_NO_SCRATCH);
          break;

        case FUTEX_WAKE:
        case FUTEX_WAKE_BITSET:
          break;

        case FUTEX_LOCK_PI:
        case FUTEX_UNLOCK_PI:
        case FUTEX_TRYLOCK_PI:
        case FUTEX_CMP_REQUEUE_PI:
        case FUTEX_WAIT_REQUEUE_PI: {
          Registers r = regs;
          r.set_arg2(-1);
          t->set_regs(r);
          syscall_state.emulate_result(-ENOSYS);
          break;
        }

        default:
          syscall_state.expect_errno = EINVAL;
          break;
      }
      return PREVENT_SWITCH;
    }

    case Arch::getrandom:
      syscall_state.reg_parameter(
          1, ParamSize::from_syscall_result<int>((size_t)regs.arg2()));
      return (GRND_NONBLOCK & regs.arg3()) ? PREVENT_SWITCH : ALLOW_SWITCH;

    case Arch::get_thread_area:
    case Arch::set_thread_area:
      syscall_state.reg_parameter<typename Arch::user_desc>(1, IN_OUT);
      return PREVENT_SWITCH;

    case Arch::ipc:
      switch ((int)regs.arg1_signed()) {
        case MSGGET:
        case SHMDT:
        case SHMGET:
        case SEMGET:
          break;

        case MSGCTL: {
          int cmd = (int)regs.arg3_signed() & ~IPC_64;
          return prepare_msgctl<Arch>(syscall_state, cmd, 5);
        }

        case MSGSND:
        case SEMOP:
        case SEMTIMEDOP:
          return ALLOW_SWITCH;

        case MSGRCV: {
          size_t msgsize = regs.arg3();
          auto kluge_args =
              syscall_state.reg_parameter<typename Arch::ipc_kludge_args>(5,
                                                                          IN);
          syscall_state.mem_ptr_parameter(REMOTE_PTR_FIELD(kluge_args, msgbuf),
                                          sizeof(typename Arch::signed_long) +
                                              msgsize);
          return ALLOW_SWITCH;
        }

        case SHMAT: {
          // Insane legacy feature: ipc SHMAT returns its pointer via an
          // in-memory out parameter.
          syscall_state.reg_parameter<typename Arch::unsigned_long>(4);
          return PREVENT_SWITCH;
        }

        case SHMCTL: {
          int cmd = (int)regs.arg3_signed() & ~IPC_64;
          return prepare_shmctl<Arch>(syscall_state, cmd, 5);
        }

        case SEMCTL: {
          int cmd = (int)regs.arg4_signed() & ~IPC_64;
          return prepare_semctl<Arch>(t, syscall_state, (int)regs.arg2_signed(),
                                      cmd, 5, DEREFERENCE);
        }

        default:
          syscall_state.expect_errno = EINVAL;
          break;
      }
      return PREVENT_SWITCH;

    case Arch::msgctl:
      return prepare_msgctl<Arch>(syscall_state, (int)regs.arg2_signed(), 3);

    case Arch::msgrcv: {
      size_t msgsize = regs.arg3();
      syscall_state.reg_parameter(2,
                                  sizeof(typename Arch::signed_long) + msgsize);
      return ALLOW_SWITCH;
    }

    // Various syscalls that can block but don't otherwise have behavior we need
    // to record.
    case Arch::fdatasync:
    case Arch::fsync:
    case Arch::msgsnd:
    case Arch::msync:
    case Arch::open:
    case Arch::openat:
    case Arch::semop:
    case Arch::semtimedop_time64:
    case Arch::semtimedop:
    case Arch::sync:
    case Arch::sync_file_range:
    case Arch::syncfs:
      return ALLOW_SWITCH;

    case Arch::sysfs: {
      int option = regs.arg1();
      switch (option) {
        case 1:
        case 3:
          break;
        case 2: {
          remote_ptr<char> buf(regs.arg3());
          // Assume no filesystem type name is more than 1K
          char tmp[1024];
          ssize_t bytes = t->read_bytes_fallible(buf, sizeof(tmp), tmp);
          if (bytes > 0) {
            syscall_state.reg_parameter(3, bytes);
          }
          break;
        }
        default:
          syscall_state.expect_errno = EINVAL;
          break;
      }
      return PREVENT_SWITCH;
    }

    case Arch::socketcall:
      return prepare_socketcall<Arch>(t, syscall_state);

    case Arch::select:
    case Arch::_newselect:
      if (syscallno == Arch::select &&
          Arch::select_semantics == Arch::SelectStructArguments) {
        auto argsp =
            syscall_state.reg_parameter<typename Arch::select_args>(1, IN);
        syscall_state.mem_ptr_parameter_inferred(
            REMOTE_PTR_FIELD(argsp, read_fds), IN_OUT);
        syscall_state.mem_ptr_parameter_inferred(
            REMOTE_PTR_FIELD(argsp, write_fds), IN_OUT);
        syscall_state.mem_ptr_parameter_inferred(
            REMOTE_PTR_FIELD(argsp, except_fds), IN_OUT);
        syscall_state.mem_ptr_parameter_inferred(
            REMOTE_PTR_FIELD(argsp, timeout), IN_OUT);
      } else {
        syscall_state.reg_parameter<typename Arch::fd_set>(2, IN_OUT);
        syscall_state.reg_parameter<typename Arch::fd_set>(3, IN_OUT);
        syscall_state.reg_parameter<typename Arch::fd_set>(4, IN_OUT);
        syscall_state.reg_parameter<typename Arch::timeval>(5, IN_OUT);
      }
      return ALLOW_SWITCH;

    case Arch::pselect6_time64:
    case Arch::pselect6: {
      syscall_state.reg_parameter<typename Arch::fd_set>(2, IN_OUT);
      syscall_state.reg_parameter<typename Arch::fd_set>(3, IN_OUT);
      syscall_state.reg_parameter<typename Arch::fd_set>(4, IN_OUT);
      if (syscallno == Arch::pselect6) {
        syscall_state.reg_parameter<typename Arch::timespec>(5, IN_OUT);
      } else {
        syscall_state.reg_parameter<typename Arch::Arch64::timespec>(5, IN_OUT);
      }
      auto arg6p =
          syscall_state.reg_parameter<typename Arch::pselect6_arg6>(6, IN);
      syscall_state.mem_ptr_parameter_inferred(REMOTE_PTR_FIELD(arg6p, ss), IN,
                                               protect_rr_sigs);
      t->invalidate_sigmask();
      return ALLOW_SWITCH;
    }

    case Arch::recvfrom: {
      syscall_state.reg_parameter(
          2,
          ParamSize::from_syscall_result<typename Arch::ssize_t>(regs.arg3()));
      auto addrlen_ptr =
          syscall_state.reg_parameter<typename Arch::socklen_t>(6, IN_OUT);
      syscall_state.reg_parameter(
          5, ParamSize::from_initialized_mem(t, addrlen_ptr));
      return ALLOW_SWITCH;
    }

    case Arch::recvmsg: {
      auto msgp = syscall_state.reg_parameter<typename Arch::msghdr>(2, IN_OUT);
      prepare_recvmsg<Arch>(
          t, syscall_state, msgp,
          ParamSize::from_syscall_result<typename Arch::ssize_t>());
      if (!((int)regs.arg3() & MSG_DONTWAIT)) {
        return ALLOW_SWITCH;
      }
      return PREVENT_SWITCH;
    }

    case Arch::recvmmsg_time64:
    case Arch::recvmmsg: {
      auto vlen = (unsigned int)regs.arg3();
      auto mmsgp =
          syscall_state
              .reg_parameter(2, sizeof(typename Arch::mmsghdr) * vlen, IN_OUT)
              .cast<typename Arch::mmsghdr>();
      prepare_recvmmsg<Arch>(t, syscall_state, mmsgp, vlen);
      if (!((unsigned int)regs.arg4() & MSG_DONTWAIT)) {
        return ALLOW_SWITCH;
      }
      return PREVENT_SWITCH;
    }

    case Arch::sendto:
      if (!((unsigned int)regs.arg4() & MSG_DONTWAIT)) {
        return ALLOW_SWITCH;
      }
      return PREVENT_SWITCH;

    case Arch::sendmsg:
      if (!((unsigned int)regs.arg3() & MSG_DONTWAIT)) {
        return ALLOW_SWITCH;
      }
      return PREVENT_SWITCH;

    case Arch::sendmmsg: {
      auto vlen = (unsigned int)regs.arg3();
      syscall_state.reg_parameter(2, sizeof(typename Arch::mmsghdr) * vlen,
                                  IN_OUT);
      if (!((unsigned int)regs.arg4() & MSG_DONTWAIT)) {
        return ALLOW_SWITCH;
      }
      return PREVENT_SWITCH;
    }

    case Arch::getsockname:
    case Arch::getpeername: {
      auto addrlen_ptr =
          syscall_state.reg_parameter<typename Arch::socklen_t>(3, IN_OUT);
      syscall_state.reg_parameter(
          2, ParamSize::from_initialized_mem(t, addrlen_ptr));
      return PREVENT_SWITCH;
    }

    case Arch::setsockopt: {
      typename Arch::setsockopt_args args;
      args.sockfd = regs.arg1();
      args.level = regs.arg2();
      args.optname = regs.arg3();
      args.optval = remote_ptr<void>(regs.arg4());
      args.optlen = regs.arg5();
      return prepare_setsockopt<Arch>(t, syscall_state, args);
    }

    case Arch::getsockopt: {
      auto optlen_ptr =
          syscall_state.reg_parameter<typename Arch::socklen_t>(5, IN_OUT);
      syscall_state.reg_parameter(
          4, ParamSize::from_initialized_mem(t, optlen_ptr));
      return PREVENT_SWITCH;
    }

    case Arch::pread64:
    /* ssize_t read(int fd, void *buf, size_t count); */
    case Arch::read: {
      int fd = regs.arg1();
      uint64_t result;
      vector<FileMonitor::Range> ranges;
      ranges.push_back(FileMonitor::Range(regs.arg2(), regs.arg3()));
      FileMonitor::LazyOffset offset(t, regs, syscallno);
      if (t->fd_table()->emulate_read(fd, t, ranges, offset, &result)) {
        return did_emulate_read<Arch>(syscallno, t, ranges, result, syscall_state);
      }
      syscall_state.reg_parameter(
          2, ParamSize::from_syscall_result<typename Arch::ssize_t>(
                 (size_t)regs.arg3()));
      return ALLOW_SWITCH;
    }

    case Arch::accept:
    case Arch::accept4: {
      auto addrlen_ptr =
          syscall_state.reg_parameter<typename Arch::socklen_t>(3, IN_OUT);
      syscall_state.reg_parameter(
          2, ParamSize::from_initialized_mem(t, addrlen_ptr));
      return ALLOW_SWITCH;
    }

    case Arch::getcwd:
      syscall_state.reg_parameter(
          1, ParamSize::from_syscall_result<typename Arch::ssize_t>(
                 (size_t)regs.arg2()));
      return PREVENT_SWITCH;

    case Arch::getdents:
    case Arch::getdents64:
      syscall_state.reg_parameter(
          2, ParamSize::from_syscall_result<int>((unsigned int)regs.arg3()));
      return PREVENT_SWITCH;

    case Arch::readlink:
      syscall_state.reg_parameter(
          2, ParamSize::from_syscall_result<typename Arch::ssize_t>(
                 (size_t)regs.arg3()));
      return PREVENT_SWITCH;

    case Arch::readlinkat:
      syscall_state.reg_parameter(
          3, ParamSize::from_syscall_result<typename Arch::ssize_t>(
                 (size_t)regs.arg4()));
      return PREVENT_SWITCH;

    case Arch::io_setup: {
      // Prevent the io_setup from running and fake an ENOSYS return. We want
      // to discourage applications from using this API because the async
      // reads are writes by the kernel that can race with userspace execution.
      Registers r = regs;
      r.set_arg2(0);
      t->set_regs(r);
      syscall_state.emulate_result(-ENOSYS);
      return PREVENT_SWITCH;
    }

    case Arch::memfd_create: {
      string name = t->read_c_str(remote_ptr<char>(regs.arg1()));
      if (is_blacklisted_memfd(name.c_str())) {
        LOG(warn) << "Cowardly refusing to memfd_create " << name;
        Registers r = regs;
        r.set_arg1(0);
        t->set_regs(r);
        syscall_state.emulate_result(-ENOSYS);
      }
      return PREVENT_SWITCH;
    }

    case Arch::getgroups:
      // We could record a little less data by restricting the recorded data
      // to the syscall result * sizeof(Arch::legacy_gid_t), but that would
      // require more infrastructure and it's not worth worrying about.
      syscall_state.reg_parameter(
          2, (int)regs.arg1_signed() * sizeof(typename Arch::legacy_gid_t));
      return PREVENT_SWITCH;

    case Arch::getgroups32:
      // We could record a little less data by restricting the recorded data
      // to the syscall result * sizeof(Arch::gid_t), but that would
      // require more infrastructure and it's not worth worrying about.
      syscall_state.reg_parameter(
          2, (int)regs.arg1_signed() * sizeof(typename Arch::gid_t));
      return PREVENT_SWITCH;

    case Arch::write:
    case Arch::writev: {
      int fd = (int)regs.arg1_signed();
      return t->fd_table()->will_write(t, fd);
    }

    case Arch::copy_file_range: {
      syscall_state.reg_parameter<typename Arch::loff_t>(2, IN_OUT);
      syscall_state.reg_parameter<typename Arch::loff_t>(4, IN_OUT);
      int in_fd = (int)regs.arg1_signed();
      int out_fd = (int)regs.arg3_signed();
      ASSERT(t, !t->fd_table()->is_monitoring(in_fd) &&
             !t->fd_table()->is_monitoring(out_fd))
             << "copy_file_range for monitored fds not supported yet";
      return ALLOW_SWITCH;
    }

    /* ssize_t readv(int fd, const struct iovec *iov, int iovcnt); */
    case Arch::readv:
    /* ssize_t preadv(int fd, const struct iovec *iov, int iovcnt,
                      off_t offset); */
    case Arch::preadv: {
      int fd = (int)regs.arg1_signed();
      int iovcnt = (int)regs.arg3_signed();
      remote_ptr<void> iovecsp_void = syscall_state.reg_parameter(
          2, sizeof(typename Arch::iovec) * iovcnt, IN);
      auto iovecsp = iovecsp_void.cast<typename Arch::iovec>();
      auto iovecs = t->read_mem(iovecsp, iovcnt);
      uint64_t result;
      vector<FileMonitor::Range> ranges;
      ranges.reserve(iovcnt);
      for (int i = 0; i < iovcnt; ++i) {
        ranges.push_back(
            FileMonitor::Range(iovecs[i].iov_base, iovecs[i].iov_len));
      }
      FileMonitor::LazyOffset offset(t, regs, syscallno);
      if (t->fd_table()->emulate_read(fd, t, ranges, offset, &result)) {
        return did_emulate_read<Arch>(syscallno, t, ranges, result, syscall_state);
      }
      ParamSize io_size =
          ParamSize::from_syscall_result<typename Arch::ssize_t>();
      for (int i = 0; i < iovcnt; ++i) {
        syscall_state.mem_ptr_parameter(REMOTE_PTR_FIELD(iovecsp + i, iov_base),
                                        io_size.limit_size(iovecs[i].iov_len));
      }
      return ALLOW_SWITCH;
    }

    /* pid_t waitpid(pid_t pid, int *status, int options); */
    /* pid_t wait4(pid_t pid, int *status, int options, struct rusage
     * *rusage);
     */
    case Arch::waitpid:
    case Arch::wait4: {
      Switchable should_switch = ALLOW_SWITCH;
      pid_t pid = (pid_t)regs.arg1_signed();
      if (pid < -1) {
        t->in_wait_type = WAIT_TYPE_PGID;
        t->in_wait_pid = -pid;
      } else if (pid == -1) {
        t->in_wait_type = WAIT_TYPE_ANY;
      } else if (pid == 0) {
        t->in_wait_type = WAIT_TYPE_SAME_PGID;
      } else {
        t->in_wait_type = WAIT_TYPE_PID;
        t->in_wait_pid = pid;
      }
      int options = (int)regs.arg3();
      bool pausing = false;
      if (maybe_emulate_wait(t, syscall_state, options)) {
        Registers r = regs;
        // Set options to an invalid value to force syscall to fail
        r.set_arg3(0xffffffff);
        t->set_regs(r);
        should_switch = PREVENT_SWITCH;
      } else if (maybe_pause_instead_of_waiting(t, options)) {
        pausing = true;
      }
      // When pausing, we've modified the registers and will emulate the
      // memory changes on syscall exit. We avoid modifying these registers
      // with pointers to scratch memory, so mark them _NO_SCRATCH if we're
      // pausing.
      syscall_state.reg_parameter<int>(2, pausing ? IN_OUT_NO_SCRATCH : IN_OUT);
      if (syscallno == Arch::wait4) {
        syscall_state.reg_parameter<typename Arch::rusage>(4,
          pausing ? IN_OUT_NO_SCRATCH : OUT);
      }
      return should_switch;
    }

    case Arch::waitid: {
      id_t wait_pid = (id_t)regs.arg2();
      switch ((uint32_t)regs.arg1()) {
        case P_ALL:
          t->in_wait_type = WAIT_TYPE_ANY;
          break;
        case P_PID:
          t->in_wait_type = WAIT_TYPE_PID;
          break;
        case P_PGID:
          t->in_wait_type = WAIT_TYPE_PGID;
          break;
        case P_PIDFD:
          wait_pid = t->pid_of_pidfd(regs.arg2());
          if (!t->session().find_task(wait_pid)) {
            // Waiting on a non-tracee; just let it happen as normal
            // We also take this path if pid_of_pidfd returns -1
            // because the fd is not a pidfd.
            syscall_state.reg_parameter<typename Arch::siginfo_t>(3);
            return ALLOW_SWITCH;
          }
          t->in_wait_type = WAIT_TYPE_PID;
          break;
        default:
          syscall_state.expect_errno = EINVAL;
          break;
      }
      Switchable should_switch = ALLOW_SWITCH;
      t->in_wait_pid = wait_pid;
      int options = (int)regs.arg4();
      bool pausing = false;
      if (maybe_emulate_wait(t, syscall_state, options)) {
        Registers r = regs;
        // Set options to an invalid value to force syscall to fail
        r.set_arg4(0xffffffff);
        t->set_regs(r);
        should_switch = PREVENT_SWITCH;
      } else {
        pausing = maybe_pause_instead_of_waiting(t, options);
      }
      syscall_state.reg_parameter<typename Arch::siginfo_t>(3,
        pausing ? IN_OUT_NO_SCRATCH : IN_OUT);
      return should_switch;
    }

    case Arch::setpriority:
      // The syscall might fail due to insufficient
      // permissions (e.g. while trying to decrease the nice value
      // while not root).
      // We'll choose to honor the new value anyway since we'd like
      // to be able to test configurations where a child thread
      // has a lower nice value than its parent, which requires
      // lowering the child's nice value.
      if ((int)regs.arg1_signed() == PRIO_PROCESS) {
        RecordTask* target =
            (int)regs.arg2_signed()
                ? t->session().find_task((int)regs.arg2_signed())
                : t;
        if (target) {
          LOG(debug) << "Setting nice value for tid " << t->tid << " to "
                     << regs.arg3();
          target->session().scheduler().update_task_priority(
              target, (int)regs.arg3_signed());
        }
      }
      return PREVENT_SWITCH;

    case Arch::pause:
      return ALLOW_SWITCH;

    case Arch::ppoll_time64:
    case Arch::ppoll:
      /* The raw syscall modifies this with the time remaining. The libc
         does not expose this functionality however */
      if (syscallno == Arch::ppoll) {
        syscall_state.reg_parameter<typename Arch::timespec>(3, IN_OUT);
      } else {
        syscall_state.reg_parameter<typename Arch::Arch64::timespec>(3, IN_OUT);
      }
      syscall_state.reg_parameter<typename Arch::kernel_sigset_t>(
          4, IN, protect_rr_sigs);
      t->invalidate_sigmask();
      RR_FALLTHROUGH;
    case Arch::poll: {
      auto nfds = (nfds_t)regs.arg2();
      syscall_state.reg_parameter(1, sizeof(typename Arch::pollfd) * nfds,
                                  IN_OUT);
      return ALLOW_SWITCH;
    }

    case Arch::perf_event_open: {
      RecordTask* target = t->session().find_task((pid_t)regs.arg2_signed());
      int cpu = regs.arg3_signed();
      unsigned long flags = regs.arg5();
      int allowed_perf_flags = PERF_FLAG_FD_CLOEXEC;
      if (target && cpu == -1 && !(flags & ~allowed_perf_flags)) {
        auto attr =
            t->read_mem(remote_ptr<struct perf_event_attr>(regs.arg1()));
        if (VirtualPerfCounterMonitor::should_virtualize(attr)) {
          Registers r = regs;
          // Turn this into an inotify_init() syscall. This just gives us an
          // allocated fd. Syscalls using this fd will be emulated (except for
          // close()).
          r.set_original_syscallno(Arch::inotify_init1);
          int in_flags = (flags & PERF_FLAG_FD_CLOEXEC) ? O_CLOEXEC : 0;
          r.set_arg1(in_flags);
          t->set_regs(r);
        }
      }
      return PREVENT_SWITCH;
    }

    case Arch::connect:
      return maybe_blacklist_connect<Arch>(t, regs.arg2(), regs.arg3());

    case Arch::close:
      if (t->fd_table()->is_rr_fd((int)regs.arg1())) {
        // Don't let processes close this fd. Abort with EBADF by setting
        // oldfd to -1, as if the fd is already closed.
        Registers r = regs;
        r.set_arg1(intptr_t(-1));
        t->set_regs(r);
      }
      return PREVENT_SWITCH;

    case Arch::dup2:
    case Arch::dup3:
      if (t->fd_table()->is_rr_fd((int)regs.arg2())) {
        // Don't let processes dup over this fd. Abort with EBADF by setting
        // oldfd to -1.
        Registers r = regs;
        r.set_arg1(intptr_t(-1));
        t->set_regs(r);
      }
      return PREVENT_SWITCH;

    /* int prctl(int option, unsigned long arg2, unsigned long arg3, unsigned
     * long arg4, unsigned long arg5); */
    case Arch::prctl:
      switch ((int)regs.arg1_signed()) {
        case PR_GET_CHILD_SUBREAPER:
        case PR_GET_ENDIAN:
        case PR_GET_FPEMU:
        case PR_GET_FPEXC:
        case PR_GET_PDEATHSIG:
        case PR_GET_UNALIGN:
          syscall_state.reg_parameter<int>(2);
          break;

        case PR_GET_KEEPCAPS:
        case PR_GET_NO_NEW_PRIVS:
        case PR_GET_TIMERSLACK:
        case PR_MCE_KILL:
        case PR_MCE_KILL_GET:
        case PR_SET_CHILD_SUBREAPER:
        case PR_SET_KEEPCAPS:
        case PR_SET_NAME:
        case PR_SET_PDEATHSIG:
        case PR_SET_TIMERSLACK:
        case PR_CAP_AMBIENT:
        case PR_CAPBSET_DROP:
        case PR_CAPBSET_READ:
        case PR_GET_SPECULATION_CTRL:
        case PR_SET_SPECULATION_CTRL:
        case PR_GET_THP_DISABLE:
        case PR_SET_THP_DISABLE:
        case PR_SET_SECUREBITS:
        case PR_GET_SECUREBITS:
          break;

        case PR_SET_DUMPABLE:
          if (regs.arg2() == 0) {
            // Don't let processes make themselves undumpable. If a process
            // becomes undumpable, calling perf_event_open on it fails.
            Registers r = regs;
            r.set_arg1(intptr_t(-1));
            t->set_regs(r);
            syscall_state.emulate_result(0);
            t->thread_group()->dumpable = false;
          } else if (regs.arg2() == 1) {
            t->thread_group()->dumpable = true;
          }
          break;

        case PR_GET_DUMPABLE:
          syscall_state.emulate_result(t->thread_group()->dumpable);
          break;

        case PR_GET_SECCOMP:
          syscall_state.emulate_result(t->prctl_seccomp_status);
          break;

        case PR_GET_TSC: {
          // Prevent the actual GET_TSC call and return our emulated state.
          Registers r = regs;
          r.set_arg1(intptr_t(-1));
          t->set_regs(r);
          syscall_state.emulate_result(0);
          t->write_mem(syscall_state.reg_parameter<int>(2, IN_OUT_NO_SCRATCH),
                       t->tsc_mode);
          break;
        }

        case PR_SET_TSC: {
          // Prevent the actual SET_TSC call.
          Registers r = regs;
          r.set_arg1(intptr_t(-1));
          t->set_regs(r);
          int val = (int)regs.arg2();
          if (val != PR_TSC_ENABLE && val != PR_TSC_SIGSEGV) {
            syscall_state.emulate_result(-EINVAL);
          } else {
            syscall_state.emulate_result(0);
            t->tsc_mode = val;
          }
          break;
        }

        case PR_GET_NAME:
          syscall_state.reg_parameter(2, 16);
          break;

        case PR_SET_NO_NEW_PRIVS:
          if ((unsigned long)regs.arg2() != 1) {
            syscall_state.expect_errno = EINVAL;
          }
          break;

        case PR_SET_SECCOMP:
          // Allow all known seccomp calls. We must allow the seccomp call
          // that rr triggers when spawning the initial tracee.
          switch ((unsigned long)regs.arg2()) {
            case SECCOMP_MODE_STRICT:
              break;
            case SECCOMP_MODE_FILTER: {
              // If we're bootstrapping then this must be rr's own syscall
              // filter, so just install it normally now.
              if (t->session().done_initial_exec()) {
                // Prevent the actual prctl call. We'll fix this up afterwards.
                Registers r = regs;
                r.set_arg1(intptr_t(-1));
                t->set_regs(r);
              }
              break;
            }
            default:
              syscall_state.expect_errno = EINVAL;
              break;
          }
          break;

        case PR_SET_PTRACER: {
          // Prevent any PR_SET_PTRACER call, but pretend it succeeded, since
          // we don't want any interference with our ptracing.
          Registers r = regs;
          r.set_arg1(intptr_t(-1));
          t->set_regs(r);
          syscall_state.emulate_result(0);
          break;
        }

        default:
          syscall_state.expect_errno = EINVAL;
          break;
      }
      return PREVENT_SWITCH;

    case Arch::arch_prctl:
      switch ((int)regs.arg1_signed()) {
        case ARCH_SET_FS:
        case ARCH_SET_GS:
          break;

        case ARCH_GET_FS:
        case ARCH_GET_GS:
          syscall_state.reg_parameter<typename Arch::unsigned_long>(2);
          break;

        case ARCH_SET_CPUID: {
          if (!t->session().has_cpuid_faulting()) {
            // Not supported or not working. Allow the call to go
            // through to get the right result.
            break;
          }

          // Prevent the actual SET_CPUID call.
          Registers r = t->regs();
          r.set_arg1(intptr_t(-1));
          t->set_regs(r);
          int val = (int)t->regs().arg2();
          t->cpuid_mode = !!val;
          syscall_state.emulate_result(0);
          break;
        }

        case ARCH_GET_CPUID: {
          if (!t->session().has_cpuid_faulting()) {
            // Not supported or not working. Allow the call to go
            // through to get the right result.
            break;
          }

          // Prevent the actual GET_CPUID call and return our emulated state.
          Registers r = t->regs();
          r.set_arg1(intptr_t(-1));
          t->set_regs(r);
          syscall_state.emulate_result(t->cpuid_mode);
          break;
        }

        default:
          syscall_state.expect_errno = EINVAL;
          break;
      }
      return PREVENT_SWITCH;

    case Arch::ioctl:
      return prepare_ioctl<Arch>(t, syscall_state);

    case Arch::bpf:
      return prepare_bpf<Arch>(t, syscall_state);

    case Arch::_sysctl: {
      auto argsp =
          syscall_state.reg_parameter<typename Arch::__sysctl_args>(1, IN);
      auto oldlenp = syscall_state.mem_ptr_parameter_inferred(
          REMOTE_PTR_FIELD(argsp, oldlenp), IN_OUT);
      syscall_state.mem_ptr_parameter(
          REMOTE_PTR_FIELD(argsp, oldval),
          ParamSize::from_initialized_mem(t, oldlenp));
      return PREVENT_SWITCH;
    }

    case Arch::quotactl:
      switch (regs.arg1() >> SUBCMDSHIFT) {
        case Q_GETQUOTA:
          syscall_state.reg_parameter<typename Arch::dqblk>(4);
          break;
        case Q_GETINFO:
          syscall_state.reg_parameter<typename Arch::dqinfo>(4);
          break;
        case Q_GETFMT:
          syscall_state.reg_parameter<int>(4);
          break;
        case Q_SETQUOTA:
          FATAL() << "Trying to set disk quota usage, this may interfere with "
                     "rr recording";
          // not reached; the break is just to silence fallthrough warnings
          break;
        case Q_QUOTAON:
        case Q_QUOTAOFF:
        case Q_SETINFO:
        case Q_SYNC:
          break;
        default:
          // Don't set expect_errno here because quotactl can fail with
          // various error codes before checking the command
          break;
      }
      return PREVENT_SWITCH;

    case Arch::keyctl:
      switch ((int)regs.arg1_signed()) {
        case KEYCTL_GET_KEYRING_ID:
        case KEYCTL_JOIN_SESSION_KEYRING:
        case KEYCTL_UPDATE:
        case KEYCTL_REVOKE:
        case KEYCTL_CHOWN:
        case KEYCTL_SETPERM:
        case KEYCTL_CLEAR:
        case KEYCTL_LINK:
        case KEYCTL_UNLINK:
        case KEYCTL_SEARCH:
        case KEYCTL_INSTANTIATE:
        case KEYCTL_INSTANTIATE_IOV:
        case KEYCTL_NEGATE:
        case KEYCTL_REJECT:
        case KEYCTL_SET_REQKEY_KEYRING:
        case KEYCTL_SET_TIMEOUT:
        case KEYCTL_ASSUME_AUTHORITY:
        case KEYCTL_SESSION_TO_PARENT:
        case KEYCTL_INVALIDATE:
          break;

        case KEYCTL_DESCRIBE:
        case KEYCTL_READ:
        case KEYCTL_GET_SECURITY:
        case KEYCTL_DH_COMPUTE:
          syscall_state.reg_parameter(
              3, ParamSize::from_syscall_result<typename Arch::signed_long>(
                     regs.arg4()));
          break;

        default:
          syscall_state.expect_errno = EINVAL;
          break;
      }
      return PREVENT_SWITCH;

    /* int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int
     * timeout); */
    case Arch::epoll_wait:
      syscall_state.reg_parameter(
          2, sizeof(typename Arch::epoll_event) * regs.arg3_signed());
      return ALLOW_SWITCH;

    case Arch::epoll_pwait: {
      syscall_state.reg_parameter(
          2, sizeof(typename Arch::epoll_event) * regs.arg3_signed());
      t->invalidate_sigmask();
      return ALLOW_SWITCH;
    }

    /* The following two syscalls enable context switching not for
     * liveness/correctness reasons, but rather because if we
     * didn't context-switch away, rr might end up busy-waiting
     * needlessly.  In addition, albeit far less likely, the
     * client program may have carefully optimized its own context
     * switching and we should take the hint. */

    case Arch::nanosleep:
      syscall_state.reg_parameter<typename Arch::timespec>(2);
      return ALLOW_SWITCH;

    case Arch::clock_nanosleep:
      syscall_state.reg_parameter<typename Arch::timespec>(4);
      return ALLOW_SWITCH;

    case Arch::clock_nanosleep_time64:
      syscall_state.reg_parameter<typename Arch::Arch64::timespec>(4);
      return ALLOW_SWITCH;

    case Arch::sched_yield:
      t->session().scheduler().schedule_one_round_robin(t);
      return ALLOW_SWITCH;

    case Arch::rt_sigpending:
      syscall_state.reg_parameter(1, (size_t)regs.arg2());
      return PREVENT_SWITCH;

    case Arch::rt_sigtimedwait_time64:
    case Arch::rt_sigtimedwait:
      syscall_state.reg_parameter<typename Arch::siginfo_t>(2);
      return ALLOW_SWITCH;

    case Arch::rt_sigprocmask:
    case Arch::sigprocmask: {
      syscall_state.reg_parameter<typename Arch::kernel_sigset_t>(3);
      syscall_state.reg_parameter<typename Arch::kernel_sigset_t>(
          2, IN, protect_rr_sigs);
      return PREVENT_SWITCH;
    }

    case Arch::sigaction:
    case Arch::rt_sigaction: {
      syscall_state.reg_parameter<typename Arch::kernel_sigaction>(
          2, IN, protect_rr_sigs_sa_mask);
      syscall_state.reg_parameter<typename Arch::kernel_sigaction>(3, OUT);
      return PREVENT_SWITCH;
    }

    case Arch::getxattr:
    case Arch::lgetxattr:
    case Arch::fgetxattr:
      syscall_state.reg_parameter(
          3, ParamSize::from_syscall_result<ssize_t>(regs.arg4()));
      return PREVENT_SWITCH;

    case Arch::listxattr:
    case Arch::llistxattr:
    case Arch::flistxattr:
      syscall_state.reg_parameter(
          2, ParamSize::from_syscall_result<ssize_t>(regs.arg3()));
      return PREVENT_SWITCH;

    case Arch::sched_getattr: {
      syscall_state.reg_parameter(2, ParamSize(regs.arg3()));
      return PREVENT_SWITCH;
    }

    case Arch::sched_setaffinity: {
      // Ignore all sched_setaffinity syscalls. They might interfere
      // with our own affinity settings.
      Registers r = regs;
      // Set arg1 to an invalid PID to ensure this syscall is ignored.
      r.set_arg1(-1);
      t->set_regs(r);
      syscall_state.emulate_result(0);
      return PREVENT_SWITCH;
    }

    case Arch::sched_getaffinity:
      syscall_state.reg_parameter(3, ParamSize(regs.arg2()));
      return PREVENT_SWITCH;

    case Arch::ptrace:
      return prepare_ptrace<Arch>(t, syscall_state);

    case Arch::mincore:
      syscall_state.reg_parameter(
          3, (regs.arg2() + page_size() - 1) / page_size());
      return PREVENT_SWITCH;

    case Arch::shmctl:
      return prepare_shmctl<Arch>(syscall_state, (int)regs.arg2_signed(), 3);

    case Arch::semctl:
      return prepare_semctl<Arch>(t, syscall_state, (int)regs.arg1_signed(),
                                  (int)regs.arg3_signed(), 4, USE_DIRECTLY);

    case Arch::seccomp:
      switch ((unsigned int)regs.arg1()) {
        case SECCOMP_SET_MODE_STRICT:
          break;
        case SECCOMP_SET_MODE_FILTER: {
          // Prevent the actual seccomp call. We'll fix this up afterwards.
          Registers r = regs;
          r.set_arg1(intptr_t(-1));
          t->set_regs(r);
          break;
        }
        default:
          syscall_state.expect_errno = EINVAL;
          break;
      }
      return PREVENT_SWITCH;

    case Arch::get_mempolicy: {
      syscall_state.reg_parameter(1, sizeof(int));
      unsigned long maxnode = t->regs().arg3();
      unsigned long align_mask = 8 * sizeof(typename Arch::unsigned_long) - 1;
      unsigned long aligned_maxnode = (maxnode + align_mask) & ~align_mask;
      syscall_state.reg_parameter(2, aligned_maxnode / 8);
      return PREVENT_SWITCH;
    }

    case Arch::madvise:
      switch ((int)regs.arg3()) {
        case MADV_NORMAL:
        case MADV_RANDOM:
        case MADV_SEQUENTIAL:
        case MADV_WILLNEED:
        case MADV_DONTNEED:
        case MADV_REMOVE:
        case MADV_DONTFORK:
        case MADV_DOFORK:
        case MADV_SOFT_OFFLINE:
        case MADV_HWPOISON:
        case MADV_MERGEABLE:
        case MADV_UNMERGEABLE:
        case MADV_HUGEPAGE:
        case MADV_NOHUGEPAGE:
        case MADV_DONTDUMP:
        case MADV_DODUMP:
        case MADV_WIPEONFORK:
        case MADV_KEEPONFORK:
          break;
        case MADV_FREE: {
          // MADV_FREE introduces nondeterminism --- the kernel zeroes the
          // pages when under memory pressure. So we don't allow it.
          Registers r = regs;
          r.set_arg3(-1);
          t->set_regs(r);
          break;
        }
        default:
          syscall_state.expect_errno = EINVAL;
          break;
      }
      return PREVENT_SWITCH;

    case Arch::personality: {
      int p = regs.arg1();
      if (p == -1) {
        // A special argument that only returns the existing personality.
        return PREVENT_SWITCH;
      }
      switch ((uint8_t)p) {
        case PER_LINUX32:
        case PER_LINUX:
          // The default personality requires no handling.
          break;
        default:
          syscall_state.expect_errno = EINVAL;
          break;
      }

      if (t->session().enable_chaos()) {
        // XXX fix this to actually disable chaos mode ASLR?
        ASSERT(t,
               !(p & (ADDR_COMPAT_LAYOUT | ADDR_NO_RANDOMIZE |
                      ADDR_LIMIT_32BIT | ADDR_LIMIT_3GB)))
            << "Personality value " << HEX(p)
            << " not compatible with chaos mode addres-space randomization";
      }
      if (p & 0xffffff00 &
          ~(ADDR_COMPAT_LAYOUT | ADDR_NO_RANDOMIZE | ADDR_LIMIT_32BIT |
            ADDR_LIMIT_3GB | FDPIC_FUNCPTRS | MMAP_PAGE_ZERO | SHORT_INODE |
            STICKY_TIMEOUTS | UNAME26 | WHOLE_SECONDS | READ_IMPLIES_EXEC)) {
        syscall_state.expect_errno = EINVAL;
      }
      return PREVENT_SWITCH;
    }

    case Arch::mmap:
      switch (Arch::mmap_semantics) {
        case Arch::StructArguments: {
          auto args =
              t->read_mem(remote_ptr<typename Arch::mmap_args>(regs.arg1()));
          // XXX fix this
          ASSERT(t, !(args.flags & MAP_GROWSDOWN));
          break;
        }
        case Arch::RegisterArguments: {
          prepare_mmap_register_params(t);
          break;
        }
      }
      return PREVENT_SWITCH;

    case Arch::mmap2:
      prepare_mmap_register_params(t);
      return PREVENT_SWITCH;

    case Arch::mprotect:
      // Since we're stripping MAP_GROWSDOWN from kernel mmap calls, we need
      // to implement PROT_GROWSDOWN ourselves.
      t->vm()->fixup_mprotect_growsdown_parameters(t);
      return PREVENT_SWITCH;

    case SYS_rrcall_notify_control_msg:
    case SYS_rrcall_init_preload:
    case SYS_rrcall_notify_stap_semaphore_added:
    case SYS_rrcall_notify_stap_semaphore_removed:
      syscall_state.emulate_result(0);
      return PREVENT_SWITCH;

    case SYS_rrcall_init_buffers:
      // This is purely for testing purposes. See signal_during_preload_init.
      if (send_signal_during_init_buffers()) {
        syscall(SYS_tgkill, t->tgid(), t->tid, SIGCHLD);
      }
      syscall_state.reg_parameter<rrcall_init_buffers_params<Arch>>(1, IN_OUT);
      return PREVENT_SWITCH;

    case SYS_rrcall_check_presence: {
      // Since this is "user" facing, we follow best practices for regular
      // syscalls and make sure that unused arguments (in this case all of them)
      // are zero.
      bool arguments_are_zero = true;
      Registers r = t->regs();
      for (int i = 1; i <= 6; ++i) {
        arguments_are_zero &= r.arg(i) == 0;
      }
      syscall_state.emulate_result(arguments_are_zero ? 0 : (uintptr_t)-EINVAL);
      syscall_state.expect_errno = ENOSYS;
      return PREVENT_SWITCH;
    }

    case SYS_rrcall_detach_teleport: {
      bool arguments_are_zero = true;
      Registers r = t->regs();
      for (int i = 1; i <= 6; ++i) {
        arguments_are_zero &= r.arg(i) == 0;
      }
      if (!arguments_are_zero) {
        syscall_state.emulate_result((uintptr_t)-EINVAL);
        syscall_state.expect_errno = ENOSYS;
        return PREVENT_SWITCH;
      }

      t->exit_syscall();
      Registers regs = t->regs();
      pid_t new_tid = do_detach_teleport(t);

      // Cause the actual task to exit
      regs.set_syscallno(SYS_exit_group);
      regs.set_arg1(0);
      regs.set_original_syscallno(-1);
      regs.set_ip(regs.ip() - syscall_instruction_length(t->arch()));
      ASSERT(t, is_at_syscall_instruction(t, regs.ip()));;
      // Restart the SYS_exit call.
      t->set_regs(regs);
      t->enter_syscall();
      t->exit_syscall();

      // Don't reap the zombie to prevent the pid from being re-used, which
      // the child might see.
      t->detached_proxy = true;
      // Just have the same task object represent both the zombie task
      // and be able to receive death notices for the detached tracee
      // to forward.
      t->session().on_proxy_detach(t, new_tid);
      t->rec_tid = new_tid;

      return ALLOW_SWITCH;
    }

    case Arch::brk:
    case Arch::munmap:
    case Arch::process_vm_readv:
    case Arch::process_vm_writev:
    case SYS_rrcall_notify_syscall_hook_exit:
    case Arch::mremap:
    case Arch::shmat:
    case Arch::shmdt:
      return PREVENT_SWITCH;

    case Arch::sigsuspend:
    case Arch::rt_sigsuspend:
      t->invalidate_sigmask();
      return ALLOW_SWITCH;

    case Arch::sigreturn:
    case Arch::rt_sigreturn:
      // If a sigreturn/rt_sigreturn ever comes through the syscallbuf, we
      // have switched to the syscallbuf stack (which does not contain any of the
      // kernel's sigframe data) and we are about to explode (when the kernel restores
      // the program's registers to random garbage from the syscallbuf stack). Die now
      // with a useful error message.
      //
      // We decline to patch syscall instructions when they're invoked with the
      // sigreturn/rt_sigreturn syscall. This covers the kernel's inserted sigreturn
      // trampolines. If the program intentionally invokes these syscalls through a
      // generic wrapper like syscall(2), it'll have to be recorded with the syscallbuf
      // disabled.
      ASSERT(t, !t->is_in_rr_page()) <<
        "sigreturn/rt_sigreturn syscalls cannot be processed through the syscallbuf "
        "because the stack pointer will be wrong. Is this program invoking them "
        "through the glibc `syscall` wrapper?\nrerecord with -n to fix this";
      if (t->arch() == aarch64) {
        // This is a bit of a hack, but we don't really have a
        // good way to do this otherwise. We need to record the
        // restored x7 register, but the kernel will lie to us
        // about it.
        remote_ptr<ARM64Arch::rt_sigframe> frame = t->regs().sp().cast<ARM64Arch::rt_sigframe>();
        auto x_regs_arr = REMOTE_PTR_FIELD(REMOTE_PTR_FIELD(
          REMOTE_PTR_FIELD(REMOTE_PTR_FIELD(frame, uc), uc_mcontext),
          regs),x);
        auto x7 = t->read_mem(x_regs_arr.field((uintptr_t*)nullptr,
          7 * sizeof(uintptr_t)));
        syscall_state.syscall_entry_registers.set_x7(x7);
      }
      t->invalidate_sigmask();
      return PREVENT_SWITCH;

    case Arch::mq_timedreceive_time64:
    case Arch::mq_timedreceive: {
      syscall_state.reg_parameter(
          2, ParamSize::from_syscall_result<typename Arch::ssize_t>(
                 (size_t)regs.arg3()));
      syscall_state.reg_parameter<unsigned>(4);
      return ALLOW_SWITCH;
    }

    case Arch::modify_ldt: {
      int func = regs.arg1();
      if (func == 0 || func == 2) {
        syscall_state.reg_parameter(
            2, ParamSize::from_syscall_result<int>((size_t)regs.arg3()));
      }
      // N.B. Unlike set_thread_area, the entry number is not written
      // for (func == 1 || func == 0x11)
      return ALLOW_SWITCH;
    }

    case Arch::name_to_handle_at: {
      syscall_state.reg_parameter(3,
                                  sizeof(typename Arch::file_handle) + MAX_HANDLE_SZ);
      syscall_state.reg_parameter(4, sizeof(int));
      return ALLOW_SWITCH;
    }

    default:
      // Invalid syscalls return -ENOSYS. Assume any such
      // result means the syscall was completely ignored by the
      // kernel so it's OK for us to not do anything special.
      // Other results mean we probably need to understand this
      // syscall, but we don't.
      syscall_state.expect_errno = ENOSYS;
      return PREVENT_SWITCH;
  }
}

static Switchable rec_prepare_syscall_internal(
    RecordTask* t, TaskSyscallState& syscall_state) {
  SupportedArch arch = t->ev().Syscall().arch();
  return with_converted_registers<Switchable>(
      t->regs(), arch, [&](const Registers& regs) -> Switchable {
        RR_ARCH_FUNCTION(rec_prepare_syscall_arch, arch, t, syscall_state,
                         regs);
      });
}

Switchable rec_prepare_syscall(RecordTask* t) {
  auto& syscall_state = syscall_state_property.get_or_create(*t);
  syscall_state.init(t);

  Switchable s = rec_prepare_syscall_internal(t, syscall_state);
  return syscall_state.done_preparing(s);
}

void rec_abort_prepared_syscall(RecordTask* t) {
  auto syscall_state = syscall_state_property.get(*t);
  if (syscall_state) {
    syscall_state->abort_syscall_results();
    syscall_state_property.remove(*t);
  }
}

static void aarch64_kernel_bug_workaround(RecordTask *t,
                                          const TaskSyscallState &syscall_state)
{
  if (syscall_state.syscall_entry_registers.arch() == aarch64) {
    // The kernel lies about the real register state during syscall exits.
    // Try to fix that up to retain some measure of sanity (otherwise we
    // might leak an incorrect register into userspace, causing an
    // un-recorded divergence). I'm really hoping to get this fixed
    // in the kernel.
    Registers r = t->regs();
    r.set_x7(syscall_state.syscall_entry_registers.x7());
    t->set_regs(r);
  }
}

template <typename Arch>
static void rec_prepare_restart_syscall_arch(RecordTask* t,
                                             TaskSyscallState& syscall_state) {
  int syscallno = t->ev().Syscall().number;
  aarch64_kernel_bug_workaround(t, syscall_state);
  switch (syscallno) {
    case Arch::nanosleep:
    case Arch::clock_nanosleep:
    case Arch::clock_nanosleep_time64:
      /* Hopefully uniquely among syscalls, nanosleep()/clock_nanosleep()
       * requires writing to its remaining-time outparam
       * *only if* the syscall fails with -EINTR.  When a
       * nanosleep() is interrupted by a signal, we don't
       * know a priori whether it's going to be eventually
       * restarted or not.  (Not easily, anyway.)  So we
       * don't know whether it will eventually return -EINTR
       * and would need the outparam written.  To resolve
       * that, we do what the kernel does, and update the
       * outparam at the -ERESTART_RESTART interruption
       * regardless. */
      syscall_state.process_syscall_results();
      break;
    case Arch::ppoll:
    case Arch::ppoll_time64:
    case Arch::pselect6:
    case Arch::pselect6_time64:
    case Arch::sigsuspend:
    case Arch::rt_sigsuspend:
      t->invalidate_sigmask();
      break;
    case Arch::wait4:
    case Arch::waitid:
    case Arch::waitpid: {
      Registers r = t->regs();
      r.set_original_syscallno(
          syscall_state.syscall_entry_registers.original_syscallno());
      t->set_regs(r);
      t->canonicalize_regs(t->arch());
      t->in_wait_type = WAIT_TYPE_NONE;
      break;
    }
  }
}

static void rec_prepare_restart_syscall_internal(
    RecordTask* t, TaskSyscallState& syscall_state) {
  RR_ARCH_FUNCTION(rec_prepare_restart_syscall_arch, t->arch(), t,
                   syscall_state);
}

void rec_prepare_restart_syscall(RecordTask* t) {
  auto& syscall_state = *syscall_state_property.get(*t);
  rec_prepare_restart_syscall_internal(t, syscall_state);
  syscall_state_property.remove(*t);
}

static const char* dropped_privs_warning =
    "[WARNING] rr: Executed file with setuid or file capabilities set.\n"
    "          Capabilities did not take effect. Errors may follow.\n"
    "          To record this execution faithfully, re-run rr as:\n"
    "\n"
    "             sudo -EP --preserve-env=HOME rr record --setuid-sudo\n"
    "\n";

static bool is_privileged_executable(RecordTask* t, const string& path) {
  struct vfs_cap_data actual, empty;
  memset(actual.data, 0, sizeof(actual.data));
  memset(empty.data, 0, sizeof(empty.data));
  if (-1 != getxattr(path.c_str(), "security.capability", &actual,
                     sizeof(vfs_cap_data))) {
    if (memcmp(&actual, &empty, sizeof(actual.data)) != 0) {
      return true;
    }
  } else {
    ASSERT(t, errno == ENODATA || errno == ENOTSUP);
    struct stat buf;
    stat(path.c_str(), &buf);
    if (buf.st_mode & (S_ISUID | S_ISGID)) {
      return true;
    }
  }
  return false;
}

static bool in_same_mount_namespace_as(RecordTask* t) {
  char proc_ns_mount[PATH_MAX];
  snprintf(proc_ns_mount, sizeof(proc_ns_mount), "/proc/%d/ns/mnt", t->tid);
  struct stat my_buf, their_buf;
  ASSERT(t, stat("/proc/self/ns/mnt", &my_buf) == 0);
  ASSERT(t, stat(proc_ns_mount, &their_buf) == 0);
  return my_buf.st_ino == their_buf.st_ino;
}

static void check_privileged_exe(RecordTask* t) {
  // Check if the executable we just execed has setuid bits or file capabilities
  // If so (and rr doesn't have CAP_SYS_ADMIN, which would have let us avoid,
  // no_new privs), they may have been ignored, due to our no_new_privs setting
  // in the tracee. That's most likely not what the user intended (and setuid
  // applications may not handle not being root particularly gracefully - after
  // all under usual circumstances, it would be an exec-time error). Give a loud
  // warning to tell the user what happened, but continue anyway.
  static bool gave_stern_warning = false;
  if (!in_same_mount_namespace_as(t)) {
    // We could try to enter the mount namespace and perform the below check
    // there, but don't bother. We know we must have privileges over the mount
    // namespaces (either because it's an unprivileged user namespace, in which
    // case we have full privileges, or because at some point one of our
    // tracees had to have CAP_SYS_ADMIN/CAP_SETUID to create the mount
    // namespace - as a result we must have at least as much privilege).
    // Nevertheless, we still need to stop the hpc counters, since
    // the executable may be privileged with respect to its namespace.
    t->hpc.stop();
  } else if (is_privileged_executable(t, t->vm()->exe_image())) {
    if (has_effective_caps(1 << CAP_SYS_ADMIN)) {
      // perf_events may have decided to stop counting for security reasons.
      // To be safe, close all perf counters now, to force re-opening the
      // perf file descriptors the next time we resume the task.
      t->hpc.stop();
    } else {
      // Only issue the warning once. If it's a problem, the user will likely
      // find out soon enough. If not, no need to keep bothering them.
      if (!gave_stern_warning) {
        fputs(dropped_privs_warning, stderr);
        gave_stern_warning = true;
      }
    }
  }
}

static uint64_t word_at(uint8_t* buf, size_t wsize) {
  union {
    uint8_t buf[8];
    uint64_t v;
  } u;
  memcpy(u.buf, buf, wsize);
  memset(u.buf + wsize, 0, 8 - wsize);
  return u.v;
}

static remote_ptr<void> get_exe_entry(Task* t) {
  vector<uint8_t> v = read_auxv(t);
  size_t i = 0;
  size_t wsize = word_size(t->arch());
  while ((i + 1)*wsize*2 <= v.size()) {
    if (word_at(v.data() + i*2*wsize, wsize) == AT_ENTRY) {
      return word_at(v.data() + (i*2 + 1)*wsize, wsize);
    }
    ++i;
  }
  return remote_ptr<void>();
}

/**
 * Given `file_name`, where `file_name` is relative to our root directory
 * but is in the mount namespace of `t`, try to make it a file we can read.
 */
static string try_make_process_file_name(RecordTask* t,
                                         const std::string& file_name) {
  char proc_root[32];
  // /proc/<pid>/root has magical properties; not only is it a link, but
  // it links to a view of the filesystem as the process sees it, taking into
  // account the process mount namespace etc.
  snprintf(proc_root, sizeof(proc_root), "/proc/%d/root", t->tid);
  char root[PATH_MAX];
  ssize_t ret = readlink(proc_root, root, sizeof(root) - 1);
  ASSERT(t, ret >= 0);
  root[ret] = 0;

  if (strncmp(root, file_name.c_str(), ret)) {
    LOG(debug) << "File " << file_name << " is outside known root "
               << proc_root;
    return file_name;
  }
  return string(proc_root) + (ret == 1 ? file_name : file_name.substr(ret));
}


static void process_execve(RecordTask* t, TaskSyscallState& syscall_state) {
  Registers r = t->regs();
  if (r.syscall_failed()) {
    return;
  }

  t->post_exec_syscall();
  t->ev().Syscall().exec_fds_to_close =
      t->fd_table()->fds_to_close_after_exec(t);

  check_privileged_exe(t);

  KernelMapping rr_page_mapping =
      t->vm()->mapping_of(AddressSpace::rr_page_start()).map;
  auto mode = t->trace_writer().write_mapped_region(
      t, rr_page_mapping, rr_page_mapping.fake_stat(),
      rr_page_mapping.fsname(),
      vector<TraceRemoteFd>(),
      TraceWriter::RR_BUFFER_MAPPING);
  ASSERT(t, mode == TraceWriter::DONT_RECORD_IN_TRACE);

  KernelMapping preload_thread_locals_mapping =
      t->vm()->mapping_of(AddressSpace::preload_thread_locals_start()).map;
  mode = t->trace_writer().write_mapped_region(
      t, preload_thread_locals_mapping,
      preload_thread_locals_mapping.fake_stat(),
      preload_thread_locals_mapping.fsname(),
      vector<TraceRemoteFd>(),
      TraceWriter::RR_BUFFER_MAPPING);
  ASSERT(t, mode == TraceWriter::DONT_RECORD_IN_TRACE);

  KernelMapping vvar;
  KernelMapping vdso;

  // get the remote executable entry point
  // with the pointer, we find out which mapping is the executable
  auto exe_entry = get_exe_entry(t);
  ASSERT(t, !exe_entry.is_null()) << "AT_ENTRY not found";

  // Write out stack mappings first since during replay we need to set up the
  // stack before any files get mapped.
  vector<KernelMapping> stacks;
  for (const auto& m : t->vm()->maps()) {
    auto& km = m.map;
    if (km.is_stack()) {
      stacks.push_back(km);
    } else if (km.is_vvar()) {
      vvar = km;
    } else if (km.is_vdso()) {
      vdso = km;
    }

    // if true, this mapping is our executable
    if (km.start() <= exe_entry && exe_entry < km.end()) {
      ASSERT(t, km.prot() & PROT_EXEC) << "Entry point not in executable code?";
      syscall_state.exec_saved_event->set_exe_base(km.start());
    }
  }
  ASSERT(t, !syscall_state.exec_saved_event->exe_base().is_null());

  t->session().trace_writer().write_task_event(*syscall_state.exec_saved_event);

  {
    AutoRemoteSyscalls remote(t, AutoRemoteSyscalls::DISABLE_MEMORY_PARAMS);

    if (vvar.size()) {
      // We're not going to map [vvar] during replay --- that wouldn't
      // make sense, since it contains data from the kernel that isn't correct
      // for replay, and we patch out the vdso syscalls that would use it.
      // Unmapping it now makes recording look more like replay.
      // Also note that under 4.0.7-300.fc22.x86_64 (at least) /proc/<pid>/mem
      // can't read the contents of [vvar].
      remote.infallible_syscall(syscall_number_for_munmap(remote.arch()),
                                vvar.start(), vvar.size());
      t->vm()->unmap(t, vvar.start(), vvar.size());
    }

    if (t->session().unmap_vdso() && vdso.size()) {
      remote.infallible_syscall(syscall_number_for_munmap(remote.arch()),
                                vdso.start(), vdso.size());
      t->vm()->unmap(t, vdso.start(), vdso.size());
    }

    for (auto& km : stacks) {
      mode = t->trace_writer().write_mapped_region(t, km, km.fake_stat(),
                                                   km.fsname(), vector<TraceRemoteFd>(),
                                                   TraceWriter::EXEC_MAPPING);
      ASSERT(t, mode == TraceWriter::RECORD_IN_TRACE);
      auto buf = t->read_mem(km.start().cast<uint8_t>(), km.size());
      t->trace_writer().write_raw(t->rec_tid, buf.data(), km.size(),
                                  km.start());

      // Remove MAP_GROWSDOWN from stacks by remapping the memory and
      // writing the contents back.
      int flags = (km.flags() & ~MAP_GROWSDOWN) | MAP_ANONYMOUS;
      remote.infallible_syscall(syscall_number_for_munmap(remote.arch()),
                                km.start(), km.size());
      if (!t->vm()->has_mapping(km.start() - page_size())) {
        // Unmap an extra page at the start; this seems to be necessary
        // to properly wipe out the growsdown mapping. Doing it as a separate
        // munmap call also seems to be necessary.
        remote.infallible_syscall(syscall_number_for_munmap(remote.arch()),
                                  km.start() - page_size(), page_size());
      }
      remote.infallible_mmap_syscall(km.start(), km.size(), km.prot(), flags,
                                     -1, 0);
      t->write_mem(km.start().cast<uint8_t>(), buf.data(), buf.size());
    }
  }

  // The kernel may zero part of the last page in each data mapping according
  // to ELF BSS metadata. So we record the last page of each data mapping in
  // the trace.
  vector<remote_ptr<void>> pages_to_record;

  for (const auto& m : t->vm()->maps()) {
    auto& km = m.map;
    if (km.start() == AddressSpace::rr_page_start() ||
        km.start() == AddressSpace::preload_thread_locals_start()) {
      continue;
    }
    if (km.is_stack() || km.is_vsyscall()) {
      // [stack] has already been handled.
      // [vsyscall] can't be read via /proc/<pid>/mem, *should*
      // be the same across all execs, and can't be munmapped so we can't fix
      // it even if it does vary. Plus no-one should be using it anymore.
      continue;
    }
    struct stat st;
    string file_name = try_make_process_file_name(t, km.fsname());
    if (stat(file_name.c_str(), &st) != 0) {
      st = km.fake_stat();
      // Size is not real. Don't confuse the logic below
      st.st_size = 0;
    }
    if (t->trace_writer().write_mapped_region(t, km, st, file_name, vector<TraceRemoteFd>(),
                                              TraceWriter::EXEC_MAPPING) ==
        TraceWriter::RECORD_IN_TRACE) {
      if (st.st_size > 0) {
        off64_t end = (off64_t)st.st_size - km.file_offset_bytes();
        t->record_remote(km.start(), min(end, (off64_t)km.size()));
      } else {
        // st_size is not valid. Some device files are mmappable but have zero
        // size. We also take this path if there's no file at all (vdso etc).
        t->record_remote(km.start(), km.size());
      }
    } else {
      // See https://github.com/rr-debugger/rr/issues/1568; in some cases
      // after exec we have memory areas that are rwx. These areas have
      // a trailing page that may be partially zeroed by the kernel. Record the
      // trailing page of every mapping just to be simple and safe.
      pages_to_record.push_back(km.end() - page_size());
    }
  }

  for (auto& p : pages_to_record) {
    t->record_remote(p, page_size());
  }

  // Patch LD_PRELOAD and VDSO after saving the mappings. Replay will apply
  // patches to the saved mappings.
  t->vm()->monkeypatcher().patch_after_exec(t);

  init_scratch_memory(t, FIXED_ADDRESS);
}

static bool is_writable(RecordTask* t, int fd) {
  struct stat lst = t->lstat_fd(fd);
  return (lst.st_mode & S_IWUSR) != 0;
}

// Returns true if the fd used to map the file is writable and thus needs
// monitoring.
static bool monitor_fd_for_mapping(RecordTask* mapped_t, int mapped_fd, const struct stat& file,
                                   vector<TraceRemoteFd>& extra_fds) {
  unordered_set<FdTable*> tables;
  bool found_our_mapping = false;
  bool our_mapping_writable = false;
  auto mapped_table = mapped_t->fd_table();
  for (auto& ts : mapped_t->session().tasks()) {
    auto rt = static_cast<RecordTask*>(ts.second);
    if (rt->already_exited()) {
      continue;
    }
    auto table = rt->fd_table();
    if (tables.find(table.get()) != tables.end()) {
      continue;
    }

    char buf[100];
    sprintf(buf, "/proc/%d/fd", rt->tid);
    DIR* dir = opendir(buf);
    if (!dir && (errno == EACCES || errno == ENOENT)) {
      LOG(warn) << "Task must have exited out from underneath us. Skipping it";
      continue;
    }
    ASSERT(rt, dir) << "Can't open fd directory " << buf;
    tables.insert(table.get());

    struct dirent* d;
    errno = 0;
    vector<string> names;
    while ((d = readdir(dir)) != nullptr) {
      char* end;
      int fd = strtol(d->d_name, &end, 10);
      if (*end) {
        // Some kind of parse error
        continue;
      }
      struct stat fd_stat = rt->stat_fd(fd);
      if (fd_stat.st_dev != file.st_dev || fd_stat.st_ino != file.st_ino) {
        // Not our file
        continue;
      }
      bool writable = is_writable(rt, fd);
      if (table == mapped_table && fd == mapped_fd) {
        // This is what we're using to do the mmap. Don't put it in extra_fds.
        found_our_mapping = true;
        our_mapping_writable = writable;
        continue;
      }
      if (!writable) {
        // Ignore non-writable fds since they can't modify memory
        continue;
      }
      extra_fds.push_back({ rt->tid, fd });
    }
    ASSERT(rt, !errno) << "Can't read fd directory " << buf;
    closedir(dir);
  }
  ASSERT(mapped_t, found_our_mapping) << "Can't find fd for mapped file";
  return our_mapping_writable;
}

static void process_mmap(RecordTask* t, size_t length, int prot, int flags,
                         int fd, off_t offset_pages) {
  if (t->regs().syscall_failed()) {
    // We purely emulate failed mmaps.
    return;
  }

  size_t size = ceil_page_size(length);
  off64_t offset = offset_pages * 4096;
  remote_ptr<void> addr = t->regs().syscall_result();
  if (flags & MAP_ANONYMOUS) {
    KernelMapping km;
    if (!(flags & MAP_SHARED)) {
      // Anonymous mappings are by definition not backed by any file-like
      // object, and are initialized to zero, so there's no nondeterminism to
      // record.
      km = t->vm()->map(t, addr, size, prot, flags, 0, string());
    } else {
      ASSERT(t, !(flags & MAP_GROWSDOWN));
      // Read the kernel's mapping. There doesn't seem to be any other way to
      // get the correct device/inode numbers. Fortunately anonymous shared
      // mappings are rare.
      KernelMapping kernel_info = t->vm()->read_kernel_mapping(t, addr);
      km = t->vm()->map(t, addr, size, prot, flags, 0, kernel_info.fsname(),
                        kernel_info.device(), kernel_info.inode());
    }
    auto d = t->trace_writer().write_mapped_region(t, km, km.fake_stat(), km.fsname(), vector<TraceRemoteFd>());
    ASSERT(t, d == TraceWriter::DONT_RECORD_IN_TRACE);
    return;
  }

  ASSERT(t, fd >= 0) << "Valid fd required for file mapping";
  ASSERT(t, !(flags & MAP_GROWSDOWN));

  bool effectively_anonymous = false;
  auto st = t->stat_fd(fd);
  string our_file_name =t->proc_fd_path(fd);
  string tracee_file_name = t->file_name_of_fd(fd);
  if (MAJOR(st.st_rdev) == 1 &&
      MINOR(st.st_rdev) == 5) {
    // mmapping /dev/zero is equivalent to MAP_ANONYMOUS, just more annoying.
    // grab the device/inode from the kernel mapping so that it will be unique.
    KernelMapping kernel_synthetic_info = t->vm()->read_kernel_mapping(t, addr);
    st.st_dev = kernel_synthetic_info.device();
    st.st_ino = kernel_synthetic_info.inode();
    our_file_name = tracee_file_name = kernel_synthetic_info.fsname();
    effectively_anonymous = true;
  }

  KernelMapping km =
      t->vm()->map(t, addr, size, prot, flags, offset, tracee_file_name, st.st_dev,
                   st.st_ino, unique_ptr<struct stat>(new struct stat(st)));

  bool adjusted_size = false;
  if (!st.st_size && !S_ISREG(st.st_mode)) {
    // Some device files are mmappable but have zero size. Increasing the
    // size here is safe even if the mapped size is greater than the real size.
    st.st_size = offset + size;
    adjusted_size = true;
  }

  vector<TraceRemoteFd> extra_fds;
  bool monitor_this_fd = false;
  if ((flags & MAP_SHARED) && !effectively_anonymous) {
    monitor_this_fd = monitor_fd_for_mapping(t, fd, st, extra_fds);
  }
  if (t->trace_writer().write_mapped_region(t, km, st, our_file_name, extra_fds,
                                            TraceWriter::SYSCALL_MAPPING,
                                            !monitor_this_fd) ==
      TraceWriter::RECORD_IN_TRACE) {
    off64_t end = (off64_t)st.st_size - km.file_offset_bytes();
    off64_t nbytes = min(end, (off64_t)km.size());
    ssize_t nread = t->record_remote_fallible(addr, nbytes);
    if (!adjusted_size && nread != nbytes) {
      // If we adjusted the size, we're not guaranteed that the bytes we're
      // reading are actually valid (it could actually have been a zero-sized
      // file).
      auto st2 = t->stat_fd(fd);
      AddressSpace::print_process_maps(t);
      if (system("df -h")) {
        // Couldn't run 'df'...
      }
      ASSERT(t, false) << "Failed to read expected mapped data at " << km
          << "; expected " << nbytes << " bytes, got " << nread << " bytes,"
          << " got file size " << st.st_size << " before and " << st2.st_size
          << " after; is filesystem full?";
    }
  }
  if ((flags & MAP_SHARED) && !effectively_anonymous) {
    // Setting up MmappedFileMonitor may trigger updates to syscallbuf_fds_disabled
    // in the tracee, recording memory records. Those should be recorded now, after the
    // memory region data itself. Needs to be consistent with replay_syscall.
    if (monitor_this_fd) {
      extra_fds.push_back({ t->tid, fd});
    }
    for (auto& f : extra_fds) {
      auto rt = t->session().find_task(f.tid);
      if (rt->fd_table()->is_monitoring(f.fd)) {
        ASSERT(rt,
                rt->fd_table()->get_monitor(f.fd)->type() ==
                    FileMonitor::Type::Mmapped);
        ((MmappedFileMonitor*)rt->fd_table()->get_monitor(f.fd))->revive();
      } else {
        rt->fd_table()->add_monitor(rt, f.fd, new MmappedFileMonitor(rt, f.fd));
      }
    }

    if ((prot & PROT_WRITE)) {
      LOG(debug) << tracee_file_name <<
        " is SHARED|writable; that's not handled "
        "correctly yet. Optimistically hoping it's not "
        "written by programs outside the rr tracee "
        "tree.";
    }
  }

  // We don't want to patch MAP_SHARED files. In the best case we'd end crashing
  // at an assertion, in the worst case, we'd end up modifying the underlying
  // file.
  if (!(flags & MAP_SHARED)) {
    t->vm()->monkeypatcher().patch_after_mmap(t, addr, size, offset_pages, fd,
                                              Monkeypatcher::MMAP_SYSCALL);
  }

  if ((prot & (PROT_WRITE | PROT_READ)) == PROT_READ && (flags & MAP_SHARED) &&
      !effectively_anonymous) {
    MonitoredSharedMemory::maybe_monitor(t, tracee_file_name,
                                         t->vm()->mapping_of(addr), fd, offset);
  }
}

static void process_mremap(RecordTask* t, remote_ptr<void> old_addr,
                           size_t old_length, size_t new_length) {
  if (t->regs().syscall_failed()) {
    // We purely emulate failed mremaps.
    return;
  }

  size_t old_size = ceil_page_size(old_length);
  size_t new_size = ceil_page_size(new_length);
  remote_ptr<void> new_addr = t->regs().syscall_result();

  t->vm()->remap(t, old_addr, old_size, new_addr, new_size);
  AddressSpace::Mapping m = t->vm()->mapping_of(new_addr);
  KernelMapping km =
      m.map.subrange(new_addr, new_addr + min(new_size, old_size));
  struct stat st = m.mapped_file_stat ? *m.mapped_file_stat : km.fake_stat();

  // Make sure that the trace records the mapping at the new location, even
  // if the mapping didn't grow.
  auto r = t->trace_writer().write_mapped_region(t, km, st, km.fsname(),
                                                 vector<TraceRemoteFd>(),
                                                 TraceWriter::REMAP_MAPPING);
  ASSERT(t, r == TraceWriter::DONT_RECORD_IN_TRACE);
  if (old_size >= new_size) {
    return;
  }

  // Now record the new part of the mapping.
  km = m.map.subrange(new_addr + old_size, new_addr + new_size);
  if (!st.st_size) {
    // Some device files are mmappable but have zero size. Increasing the
    // size here is safe even if the mapped size is greater than the real size.
    st.st_size = m.map.file_offset_bytes() + new_size;
  }

  if (t->trace_writer().write_mapped_region(t, km, st, km.fsname(),
                                            vector<TraceRemoteFd>()) ==
      TraceWriter::RECORD_IN_TRACE) {
    off64_t end = max<off64_t>(st.st_size - km.file_offset_bytes(), 0);
    // Allow failure; the underlying file may have true zero size, in which
    // case this may try to record unmapped memory.
    t->record_remote_fallible(km.start(), min(end, (off64_t)km.size()));
  }

  // If the original mapping was monitored, we'll continue monitoring it
  // automatically.
}

static void process_shmat(RecordTask* t, int shmid, int shm_flags,
                          remote_ptr<void> addr) {
  if (t->regs().syscall_failed()) {
    // We purely emulate failed shmats.
    return;
  }

  struct shmid64_ds ds;
  int ret = _shmctl(shmid, IPC_STAT, &ds);
  msan_unpoison(&ds, sizeof(semid64_ds));
  ASSERT(t, !ret) << "shmid should be readable by rr since rr has the same "
                     "UID as tracees";
  size_t size = ceil_page_size(ds.shm_segsz);

  int prot = shm_flags_to_mmap_prot(shm_flags);
  int flags = MAP_SHARED;

  // Read the kernel's mapping for the shm segment. There doesn't seem to be
  // any other way to get the correct device number. (The inode number seems to
  // be the shm key.) This should be OK since SysV shmem is not used very much
  // and reading /proc/<pid>/maps should be reasonably cheap.
  KernelMapping kernel_info = t->vm()->read_kernel_mapping(t, addr);
  KernelMapping km =
      t->vm()->map(t, addr, size, prot, flags, 0, kernel_info.fsname(),
                   kernel_info.device(), kernel_info.inode());
  t->vm()->set_shm_size(km.start(), km.size());
  auto disposition =
      t->trace_writer().write_mapped_region(t, km, km.fake_stat(), km.fsname(), vector<TraceRemoteFd>());
  ASSERT(t, disposition == TraceWriter::RECORD_IN_TRACE);
  t->record_remote(addr, size);

  LOG(debug) << "Optimistically hoping that SysV segment is not used outside "
                "of tracees";
}

template <typename Arch>
static string extra_expected_errno_info(RecordTask* t,
                                        TaskSyscallState& syscall_state) {
  stringstream ss;
  switch (syscall_state.expect_errno) {
    case ENOSYS:
      ss << "; execution of syscall unsupported by rr";
      break;
    case EINVAL:
      switch (t->regs().original_syscallno()) {
        case Arch::ioctl: {
          int request = (int)t->regs().arg2_signed();
          if (request == SIOCETHTOOL) {
            auto ifreq_ptr = remote_ptr<typename Arch::ifreq>(t->regs().arg3());
            auto ifreq = t->read_mem(ifreq_ptr);
            remote_ptr<void> cmd_ptr = ifreq.ifr_ifru.ifru_data.rptr();
            auto cmd = t->read_mem(cmd_ptr.cast<uint32_t>());
            ss << "; unknown ETHTOOL command " << cmd;
          } else {
            int type = _IOC_TYPE(request);
            int nr = _IOC_NR(request);
            int dir = _IOC_DIR(request);
            int size = _IOC_SIZE(request);
            ss << "; Unknown ioctl(" << HEX(request) << "): type:" << HEX(type)
               << " nr:" << HEX(nr) << " dir:" << HEX(dir) << " size:" << size
               << " addr:" << HEX(t->regs().arg3());
          }
          break;
        }
        case Arch::fcntl:
        case Arch::fcntl64:
          ss << "; unknown fcntl(" << HEX((int)t->regs().arg2_signed()) << ")";
          break;
        case Arch::prctl:
          ss << "; unknown prctl(" << HEX((int)t->regs().arg1_signed()) << ")";
          break;
        case Arch::arch_prctl:
          ss << "; unknown arch_prctl(" << HEX((int)t->regs().arg1_signed())
             << ")";
          break;
        case Arch::keyctl:
          ss << "; unknown keyctl(" << HEX((int)t->regs().arg1_signed()) << ")";
          break;
        case Arch::socketcall:
          ss << "; unknown socketcall(" << HEX((int)t->regs().arg1_signed())
             << ")";
          break;
        case Arch::ipc:
          ss << "; unknown ipc(" << HEX((int)t->regs().arg1_signed()) << ")";
          break;
        case Arch::futex_time64:
        case Arch::futex:
          ss << "; unknown futex("
             << HEX((int)t->regs().arg2_signed() & FUTEX_CMD_MASK) << ")";
          break;
        case Arch::waitid:
          ss << "; unknown waitid(" << HEX((idtype_t)t->regs().arg1()) << ")";
          break;
        case Arch::seccomp:
          ss << "; unknown seccomp(" << HEX((unsigned int)t->regs().arg1())
             << ")";
          break;
        case Arch::madvise:
          ss << "; unknown madvise(" << (int)t->regs().arg3() << ")";
          break;
      }
      break;
    case EIO:
      switch (t->regs().original_syscallno()) {
        case Arch::ptrace:
          ss << "; unsupported ptrace(" << HEX((int)t->regs().arg1()) << " ["
             << ptrace_req_name<Arch>((int)t->regs().arg1_signed()) << "])";
          break;
      }
      break;
  }
  return ss.str();
}

static bool is_rr_fd_terminal(int fd, const string& pathname) {
  char buf[PATH_MAX];
  if (ttyname_r(fd, buf, sizeof(buf))) {
    return false;
  }
  buf[sizeof(buf) - 1] = 0;
  return pathname == buf;
}

static bool is_rr_terminal(const string& pathname) {
  if (pathname == "/dev/tty") {
    // XXX the tracee's /dev/tty could refer to a tty other than
    // the recording tty, in which case output should not be
    // redirected. That's not too bad, replay will still work, just
    // with some spurious echoes.
    return true;
  }

  return is_rr_fd_terminal(STDIN_FILENO, pathname) ||
         is_rr_fd_terminal(STDOUT_FILENO, pathname) ||
         is_rr_fd_terminal(STDERR_FILENO, pathname);
}

static int dev_tty_fd() {
  static int fd = -1;
  if (fd < 0) {
    fd = open("/dev/tty", O_WRONLY);
  }
  return fd;
}

template <typename Arch>
static void record_iovec_output(RecordTask* t, RecordTask* dest,
                                remote_ptr<typename Arch::iovec> piov,
                                uint32_t iov_cnt) {
  // Ignore the syscall result, the kernel may have written more data than that.
  // See https://bugzilla.kernel.org/show_bug.cgi?id=113541
  auto iovs = t->read_mem(piov, iov_cnt);
  for (auto& iov : iovs) {
    dest->record_remote_writable(iov.iov_base, iov.iov_len);
  }
}

static bool is_mapped_shared(RecordTask* t, const struct stat& st) {
  for (AddressSpace* vm : t->session().vms()) {
    for (auto& m : vm->maps()) {
      if ((m.map.flags() & MAP_SHARED) &&
          m.mapped_file_stat && m.mapped_file_stat->st_dev == st.st_dev &&
          m.mapped_file_stat->st_ino == st.st_ino) {
        LOG(debug) << "is_mapped_shared is shared: "
          << st.st_dev << " " << st.st_ino;
        return true;
      }
    }
  }
  return false;
}

// Returns the file path. This could be a blacklisted file so don't
// do anything for blacklisted files.
static string handle_opened_file(RecordTask* t, int fd, int flags) {
  string pathname = t->file_name_of_fd(fd);
  struct stat st = t->stat_fd(fd);

  // This must be kept in sync with replay_syscall's handle_opened_files.
  FileMonitor* file_monitor = nullptr;
  if (is_mapped_shared(t, st) && is_writable(t, fd)) {
    // This is quite subtle. Because open(2) is ALLOW_SWITCH, we could have been
    // descheduled after entering the syscall we're now exiting. If that happened,
    // and another task did a shared mapping of this file while we were suspended,
    // it would have trawled the proc filesystem looking for other open fds for
    // the same file. If this syscall had been completed in the kernel by then,
    // it will have already installed this monitor for us. So we must allow this
    // benign race.
    if (t->fd_table()->is_monitoring(fd)) {
      LOG(debug) << "Already monitoring " << fd;
        ASSERT(t,
               t->fd_table()->get_monitor(fd)->type() ==
               FileMonitor::Type::Mmapped);
    } else {
      // The normal case, we are unmonitored because we are a new file.
      LOG(info) << "Installing MmappedFileMonitor for " << fd;
      file_monitor = new MmappedFileMonitor(t, fd);
    }
  } else if (is_rr_terminal(pathname)) {
    // This will let rr event annotations echo to the terminal. It will also
    // ensure writes to this fd are not syscall-buffered.
    LOG(info) << "Installing StdioMonitor for " << fd;
    file_monitor = new StdioMonitor(dev_tty_fd());
    pathname = "terminal";
  } else if (is_proc_mem_file(pathname.c_str())) {
    LOG(info) << "Installing ProcMemMonitor for " << fd;
    file_monitor = new ProcMemMonitor(t, pathname);
  } else if (is_proc_fd_dir(pathname.c_str())) {
    LOG(info) << "Installing ProcFdDirMonitor for " << fd;
    file_monitor = new ProcFdDirMonitor(t, pathname);
  } else if (is_sys_cpu_online_file(pathname.c_str())) {
    LOG(info) << "Installing SysCpuMonitor for " << fd;
    file_monitor = new SysCpuMonitor(t, pathname);
  } else if (is_proc_stat_file(pathname.c_str())) {
    LOG(info) << "Installing ProcStatMonitor for " << fd;
    file_monitor = new ProcStatMonitor(t, pathname);
  } else if (flags & O_DIRECT) {
    // O_DIRECT can impose unknown alignment requirements, in which case
    // syscallbuf records will not be properly aligned and will cause I/O
    // to fail. Disable syscall buffering for O_DIRECT files.
    LOG(info) << "Installing FileMonitor for O_DIRECT " << fd;
    file_monitor = new FileMonitor();
  }

  if (file_monitor) {
    // Write absolute file name
    auto& syscall = t->ev().Syscall();
    syscall.opened.push_back({ pathname, fd, st.st_dev, st.st_ino });
    t->fd_table()->add_monitor(t, fd, file_monitor);
  }
  return pathname;
}

template <typename Arch>
static void check_scm_rights_fd(RecordTask* t, typename Arch::msghdr& msg) {
  if (msg.msg_controllen < sizeof(typename Arch::cmsghdr)) {
    return;
  }
  auto data = t->read_mem(msg.msg_control.rptr().template cast<uint8_t>(),
                          msg.msg_controllen);
  size_t index = 0;
  while (true) {
    auto cmsg = reinterpret_cast<typename Arch::cmsghdr*>(data.data() + index);
    if (cmsg->cmsg_len < sizeof(*cmsg) ||
        index + Arch::cmsg_align(cmsg->cmsg_len) > data.size()) {
      break;
    }
    if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
      int* fds = static_cast<int*>(Arch::cmsg_data(cmsg));
      int fd_count = (cmsg->cmsg_len - sizeof(*cmsg)) / sizeof(int);
      for (int i = 0; i < fd_count; ++i) {
        handle_opened_file(t, fds[i], 0);
      }
    }
    index += Arch::cmsg_align(cmsg->cmsg_len);
    if (index + sizeof(*cmsg) > data.size()) {
      break;
    }
  }
}

static void fake_gcrypt_file(RecordTask* t, Registers* r) {
  // We hijacked this call to deal with /etc/gcrypt/hwf.deny.
  char fname[255];
  snprintf(fname, sizeof(fname), "rr-gcrypt-hwf-deny-%d", getpid());
  ScopedFd fd(open_memory_file(fname));

  struct stat dummy;
  if (!stat("/etc/gcrypt/hwf.deny", &dummy)) {
    // Copy the contents into our temporary file
    ScopedFd existing("/etc/gcrypt/hwf.deny", O_RDONLY);
    if (!copy_file(fd, existing)) {
      FATAL() << "Can't copy file";
    }
  }

  static const char disable_rdrand[] = "\nintel-rdrand\n";
  write_all(fd, disable_rdrand, sizeof(disable_rdrand) - 1);

  // Now open the file in the child.
  int child_fd;
  {
    AutoRemoteSyscalls remote(t);
    lseek(fd, 0, SEEK_SET);
    child_fd = remote.send_fd(fd);
  }

  // And hand out our fake file.
  r->set_syscall_result(child_fd);
}

template <typename Arch>
static void rec_process_syscall_arch(RecordTask* t,
                                     TaskSyscallState& syscall_state) {
  int syscallno = t->ev().Syscall().number;

  if (t->regs().original_syscallno() == SECCOMP_MAGIC_SKIP_ORIGINAL_SYSCALLNO) {
    // rr vetoed this syscall. Don't do any post-processing.
    return;
  }

  LOG(debug) << t->tid << ": processing: " << t->ev()
             << " -- time: " << t->trace_time();

  if (remote_ptr<const struct syscallbuf_record> rec = t->desched_rec()) {
    // If the syscallbuf has already been unmapped, there's no need to record
    // the entry.
    if (t->syscallbuf_child) {
      t->record_remote(REMOTE_PTR_FIELD(rec, extra_data),
                       t->read_mem(REMOTE_PTR_FIELD(rec, size)) -
                           sizeof(struct syscallbuf_record));
    }
    return;
  }

  if (syscall_state.expect_errno) {
    if (syscall_state.expect_errno == EINVAL && syscallno == Arch::ioctl &&
        t->regs().syscall_result_signed() == -ENOTTY) {
      // Unsupported ioctl was called, but is not supported for this device,
      // so we can safely ignore it.
      return;
    }
    ASSERT(t, t->regs().syscall_result_signed() == -syscall_state.expect_errno)
        << "Expected " << errno_name(syscall_state.expect_errno) << " for '"
        << syscall_name(syscallno, Arch::arch()) << "' but got result "
        << t->regs().syscall_result_signed() << " (errno "
        << errno_name(-t->regs().syscall_result_signed()) << ")"
        << extra_expected_errno_info<Arch>(t, syscall_state);
    if (syscallno == Arch::execve) {
      t->session().scheduler().did_exit_execve(t);
    }
    return;
  }

  // Here we handle syscalls that need work that can only happen after the
  // syscall completes --- and that our TaskSyscallState infrastructure can't
  // handle.
  switch (syscallno) {
    case Arch::fork:
    case Arch::vfork:
    case Arch::clone: {
      if (Arch::is_x86ish()) {
        // On a 3.19.0-39-generic #44-Ubuntu kernel we have observed clone()
        // clearing the parity flag internally.
        Registers r = t->regs();
        r.set_flags(syscall_state.syscall_entry_registers.flags());
        t->set_regs(r);
      }
      break;
    }

    case Arch::execve:
      t->session().scheduler().did_exit_execve(t);
      process_execve(t, syscall_state);
      if (t->emulated_ptracer) {
        if (t->emulated_ptrace_options & PTRACE_O_TRACEEXEC) {
          t->emulate_ptrace_stop(
              WaitStatus::for_ptrace_event(PTRACE_EVENT_EXEC));
        } else if (!t->emulated_ptrace_seized) {
          // Inject legacy SIGTRAP-after-exec
          t->tgkill(SIGTRAP);
        }
      }
      break;

    case Arch::brk: {
      remote_ptr<void> old_brk = ceil_page_size(t->vm()->current_brk());
      remote_ptr<void> new_brk = ceil_page_size(t->regs().syscall_result());
      KernelMapping km;
      if (old_brk < new_brk) {
        // Read the kernel's mapping. There doesn't seem to be any other way to
        // get the correct prot bits for heaps. Usually it's READ|WRITE but
        // there seem to be exceptions depending on system settings.
        KernelMapping kernel_info = t->vm()->read_kernel_mapping(t, old_brk);
        ASSERT(t, kernel_info.device() == KernelMapping::NO_DEVICE);
        ASSERT(t, kernel_info.inode() == KernelMapping::NO_INODE);
        km = kernel_info.subrange(old_brk, new_brk);
      } else {
        // Write a dummy KernelMapping that indicates an unmap
        km = KernelMapping(new_brk, old_brk, string(), KernelMapping::NO_DEVICE,
                           KernelMapping::NO_INODE, 0, 0, 0);
      }
      auto d = t->trace_writer().write_mapped_region(t, km, km.fake_stat(), km.fsname(), vector<TraceRemoteFd>());
      ASSERT(t, d == TraceWriter::DONT_RECORD_IN_TRACE);
      t->vm()->brk(t, t->regs().syscall_result(), km.prot());
      break;
    }

    case Arch::mmap:
      switch (Arch::mmap_semantics) {
        case Arch::StructArguments: {
          auto args = t->read_mem(
              remote_ptr<typename Arch::mmap_args>(t->regs().orig_arg1()));
          process_mmap(t, args.len, args.prot, args.flags, args.fd,
                       args.offset / 4096);
          break;
        }
        case Arch::RegisterArguments: {
          Registers r = t->regs();
          r.set_orig_arg1(syscall_state.syscall_entry_registers.arg1());
          r.set_arg4(syscall_state.syscall_entry_registers.arg4_signed());
          t->set_regs(r);
          process_mmap(t, (size_t)r.arg2(), (int)r.arg3_signed(),
                       (int)r.arg4_signed(), (int)r.arg5_signed(),
                       ((off_t)r.arg6_signed()) / 4096);
          break;
        }
      }
      break;

    case Arch::mmap2: {
      Registers r = t->regs();
      r.set_orig_arg1(syscall_state.syscall_entry_registers.arg1());
      r.set_arg4(syscall_state.syscall_entry_registers.arg4_signed());
      t->set_regs(r);
      process_mmap(t, (size_t)r.arg2(), (int)r.arg3_signed(),
                   (int)r.arg4_signed(), (int)r.arg5_signed(),
                   (off_t)r.arg6_signed());
      break;
    }

    case Arch::mremap:
      process_mremap(t, t->regs().orig_arg1(), t->regs().arg2(), t->regs().arg3());
      break;

    case Arch::shmat:
      process_shmat(t, (int)t->regs().orig_arg1_signed(),
                    (int)t->regs().arg3_signed(), t->regs().syscall_result());
      break;

    case Arch::ipc:
      switch ((int)t->regs().orig_arg1_signed()) {
        case SHMAT: {
          auto out_ptr = t->read_mem(
              remote_ptr<typename Arch::unsigned_long>(t->regs().arg4()));
          process_shmat(t, (int)t->regs().arg2_signed(),
                        (int)t->regs().arg3_signed(), out_ptr);
          break;
        }
        default:
          break;
      }
      break;

    case Arch::clock_nanosleep:
    case Arch::nanosleep: {
      /* If the sleep completes, the kernel doesn't
       * write back to the remaining-time
       * argument. */
      if (!(int)t->regs().syscall_result_signed()) {
        syscall_state.write_back = TaskSyscallState::NO_WRITE_BACK;
      }
      break;
    }

    case Arch::perf_event_open:
      if (t->regs().original_syscallno() == Arch::inotify_init1) {
        ASSERT(t, !t->regs().syscall_failed());
        int fd = t->regs().syscall_result_signed();
        Registers r = t->regs();
        r.set_original_syscallno(
            syscall_state.syscall_entry_registers.original_syscallno());
        r.set_orig_arg1(syscall_state.syscall_entry_registers.arg1());
        t->set_regs(r);
        auto attr =
            t->read_mem(remote_ptr<struct perf_event_attr>(t->regs().orig_arg1()));
        t->fd_table()->add_monitor(t,
            fd, new VirtualPerfCounterMonitor(
                    t, t->session().find_task((pid_t)t->regs().arg2_signed()),
                    attr));
      }
      break;

    case Arch::connect: {
      // Restore the registers that we may have altered.
      Registers r = t->regs();
      if (r.original_syscallno() == Arch::gettid) {
        // We hijacked this call to deal with blacklisted sockets
        r.set_original_syscallno(Arch::connect);
        r.set_syscall_result(-EACCES);
        t->set_regs(r);
      }
      break;
    }

    case Arch::open:
    case Arch::openat: {
      Registers r = t->regs();
      if (r.syscall_failed()) {
        uintptr_t path = syscallno == Arch::openat ? r.arg2() : r.orig_arg1();
        string pathname = t->read_c_str(remote_ptr<char>(path));
        if (is_gcrypt_deny_file(pathname.c_str())) {
          fake_gcrypt_file(t, &r);
          t->set_regs(r);
        }
      } else {
        int fd = r.syscall_result_signed();
        int flags = syscallno == Arch::openat ? r.arg3() : r.arg2();
        string pathname = handle_opened_file(t, fd, flags);
        bool gcrypt = is_gcrypt_deny_file(pathname.c_str());
        if (gcrypt || is_blacklisted_filename(pathname.c_str())) {
          {
            AutoRemoteSyscalls remote(t);
            remote.infallible_syscall(syscall_number_for_close(remote.arch()), fd);
          }
          if (gcrypt) {
            fake_gcrypt_file(t, &r);
          } else {
            LOG(warn) << "Cowardly refusing to open " << pathname;
            r.set_syscall_result(-ENOENT);
          }
          t->set_regs(r);
        }
      }
      break;
    }

    case SYS_rrcall_notify_control_msg: {
      auto msg =
          t->read_mem(remote_ptr<typename Arch::msghdr>(t->regs().orig_arg1()));
      check_scm_rights_fd<Arch>(t, msg);
      break;
    }

    case Arch::recvmsg:
      if (!t->regs().syscall_failed()) {
        auto msg =
            t->read_mem(remote_ptr<typename Arch::msghdr>(t->regs().arg2()));
        check_scm_rights_fd<Arch>(t, msg);
      }
      break;

    case Arch::recvmmsg_time64:
    case Arch::recvmmsg:
      if (!t->regs().syscall_failed()) {
        int msg_count = (int)t->regs().syscall_result_signed();
        auto msgs = t->read_mem(
            remote_ptr<typename Arch::mmsghdr>(t->regs().arg2()), msg_count);
        for (auto& m : msgs) {
          check_scm_rights_fd<Arch>(t, m.msg_hdr);
        }
      }
      break;

    case Arch::sched_getaffinity: {
      pid_t pid = (pid_t)t->regs().orig_arg1();
      if (!t->regs().syscall_failed() && (pid == 0 || pid == t->rec_tid)) {
        if (t->regs().syscall_result() > sizeof(cpu_set_t)) {
          LOG(warn) << "Don't understand kernel's sched_getaffinity result";
        } else {
          t->write_bytes_helper(t->regs().arg3(), t->regs().syscall_result(),
              &t->session().scheduler().pretend_affinity_mask());
        }
      }
      break;
    }

    case Arch::setsockopt: {
      // restore possibly-modified regs
      Registers r = t->regs();
      r.set_orig_arg1(syscall_state.syscall_entry_registers.arg1());
      t->set_regs(r);
      break;
    }

    case Arch::socketcall: {
      // restore possibly-modified regs
      Registers r = t->regs();
      if (r.original_syscallno() == Arch::gettid) {
        // `connect` was suppressed
        r.set_syscall_result(-EACCES);
      }
      r.set_orig_arg1(syscall_state.syscall_entry_registers.arg1());
      r.set_original_syscallno(
          syscall_state.syscall_entry_registers.original_syscallno());
      t->set_regs(r);

      if (!t->regs().syscall_failed()) {
        switch ((int)t->regs().orig_arg1_signed()) {
          case SYS_RECVMSG: {
            auto args = t->read_mem(
                remote_ptr<typename Arch::recvmsg_args>(t->regs().arg2()));
            auto msg = t->read_mem(args.msg.rptr());
            check_scm_rights_fd<Arch>(t, msg);
            break;
          }
          case SYS_RECVMMSG: {
            auto args = t->read_mem(
                remote_ptr<typename Arch::recvmmsg_args>(t->regs().arg2()));
            int msg_count = (int)t->regs().syscall_result_signed();
            auto msgs = t->read_mem(args.msgvec.rptr(), msg_count);
            for (auto& m : msgs) {
              check_scm_rights_fd<Arch>(t, m.msg_hdr);
            }
            break;
          }
        }
      }
      break;
    }

    case Arch::process_vm_readv:
      record_iovec_output<Arch>(t, t, t->regs().arg2(), t->regs().arg3());
      break;

    case Arch::process_vm_writev: {
      RecordTask* dest = t->session().find_task(t->regs().orig_arg1());
      if (dest) {
        record_iovec_output<Arch>(t, dest, t->regs().arg4(), t->regs().arg5());
      }
      break;
    }

    case Arch::close:
    case Arch::dup2:
    case Arch::dup3:
    case Arch::fcntl:
    case Arch::fcntl64:
    case Arch::futex_time64:
    case Arch::futex:
    case Arch::ioctl:
    case Arch::io_setup:
    case Arch::madvise:
    case Arch::memfd_create:
    case Arch::pread64:
    case Arch::preadv:
    case Arch::ptrace:
    case Arch::read:
    case Arch::readv:
    case Arch::sched_setaffinity:
    case Arch::mprotect: {
      // Restore the registers that we may have altered.
      Registers r = t->regs();
      r.set_orig_arg1(syscall_state.syscall_entry_registers.arg1());
      r.set_arg2(syscall_state.syscall_entry_registers.arg2());
      r.set_arg3(syscall_state.syscall_entry_registers.arg3());
      t->set_regs(r);
      break;
    }

    case Arch::getdents:
    case Arch::getdents64: {
      Registers r = t->regs();
      int fd = r.orig_arg1();
      t->fd_table()->filter_getdents(fd, t);
      break;
    }

    case Arch::waitpid:
    case Arch::wait4:
    case Arch::waitid: {
      t->in_wait_type = WAIT_TYPE_NONE;
      // Restore possibly-modified registers
      Registers r = t->regs();
      r.set_orig_arg1(syscall_state.syscall_entry_registers.arg1());
      r.set_arg2(syscall_state.syscall_entry_registers.arg2());
      r.set_arg3(syscall_state.syscall_entry_registers.arg3());
      r.set_arg4(syscall_state.syscall_entry_registers.arg4());
      r.set_original_syscallno(
          syscall_state.syscall_entry_registers.original_syscallno());
      t->set_regs(r);

      RecordTask* tracee = syscall_state.emulate_wait_for_child;
      if (tracee) {
        // Finish emulation of ptrace result or stop-signal
        Registers r = t->regs();
        r.set_syscall_result(syscallno == Arch::waitid ? 0 : tracee->tid);
        t->set_regs(r);
        if (syscallno == Arch::waitid) {
          remote_ptr<typename Arch::siginfo_t> sip = r.arg3();
          if (!sip.is_null()) {
            typename Arch::siginfo_t si;
            memset(&si, 0, sizeof(si));
            si.si_signo = SIGCHLD;
            tracee->set_siginfo_for_waited_task<Arch>(&si);
            t->write_mem(sip, si);
          }
        } else {
          remote_ptr<int> statusp = r.arg2();
          if (!statusp.is_null()) {
            t->write_mem(statusp, tracee->emulated_stop_code.get());
          }
        }
        if (syscallno == Arch::waitid && (r.arg4() & WNOWAIT)) {
          // Leave the child in a waitable state
        } else {
          if (tracee->emulated_ptracer == t) {
            tracee->emulated_stop_pending = false;
          } else {
            for (Task* thread : tracee->thread_group()->task_set()) {
              auto rt = static_cast<RecordTask*>(thread);
              rt->emulated_stop_pending = false;
            }
          }
        }
        if (tracee->waiting_for_reap) {
          if (tracee->waiting_for_zombie) {
            tracee->waiting_for_reap = false;
          } else {
            delete tracee;
          }
        }
      }
      break;
    }

    case Arch::prctl: {
      // Restore arg1 in case we modified it to disable the syscall
      Registers r = t->regs();
      r.set_orig_arg1(syscall_state.syscall_entry_registers.arg1());
      t->set_regs(r);
      switch ((int)t->regs().orig_arg1()) {
        case PR_SET_SECCOMP:
          if (t->session().done_initial_exec()) {
            t->session()
                .as_record()
                ->seccomp_filter_rewriter()
                .install_patched_seccomp_filter(t);
          }
          break;
      }
      break;
    }

    case Arch::arch_prctl: {
      // Restore arg1 in case we modified it to disable the syscall
      Registers r = t->regs();
      r.set_orig_arg1(syscall_state.syscall_entry_registers.arg1());
      t->set_regs(r);
      break;
    }

    case Arch::quotactl:
      switch (t->regs().orig_arg1() >> SUBCMDSHIFT) {
        case Q_GETQUOTA:
        case Q_GETINFO:
        case Q_GETFMT:
        case Q_SETQUOTA:
        case Q_QUOTAON:
        case Q_QUOTAOFF:
        case Q_SETINFO:
        case Q_SYNC:
          break;
        default: {
          auto ret = t->regs().syscall_result_signed();
          ASSERT(t,
                 ret == -ENOENT || ret == -ENODEV || ret == -ENOTBLK ||
                     ret == -EINVAL)
              << " unknown quotactl(" << HEX(t->regs().arg1() >> SUBCMDSHIFT)
              << ")";
          break;
        }
      }
      break;

    case Arch::seccomp: {
      // Restore arg1 in case we modified it to disable the syscall
      Registers r = t->regs();
      r.set_orig_arg1(syscall_state.syscall_entry_registers.arg1());
      t->set_regs(r);
      if (t->regs().orig_arg1() == SECCOMP_SET_MODE_FILTER) {
        ASSERT(t, t->session().done_initial_exec())
            << "no seccomp calls during spawn";
        t->session()
            .as_record()
            ->seccomp_filter_rewriter()
            .install_patched_seccomp_filter(t);
      }
      break;
    }

    case SYS_rrcall_init_buffers:
      t->init_buffers();
      break;

    case SYS_rrcall_init_preload: {
      t->at_preload_init();
      break;
    }

    case SYS_rrcall_notify_syscall_hook_exit: {
      remote_ptr<uint8_t> child_addr =
          REMOTE_PTR_FIELD(t->syscallbuf_child, notify_on_syscall_hook_exit);
      t->write_mem(child_addr, (uint8_t)0);
      t->record_remote(child_addr);

      struct rrcall_params {
        typename Arch::unsigned_word result;
        typename Arch::unsigned_word original_syscallno;
      };
      Registers r = t->regs();
      auto params_ptr = r.sp() + sizeof(typename Arch::unsigned_word);
      auto params = t->read_mem(params_ptr.cast<rrcall_params>());
      r.set_syscall_result((uintptr_t)params.result);
      r.set_original_syscallno((intptr_t)params.original_syscallno);
      t->set_regs(r);
      break;
    }
  }
}

/* N.B.: `arch` is the the architecture of the syscall, which may be different
         from the architecture of the call (e.g. x86_64 may invoke x86 syscalls)
*/
static void rec_process_syscall_internal(RecordTask* t, SupportedArch arch,
                                         TaskSyscallState& syscall_state) {
  RR_ARCH_FUNCTION(rec_process_syscall_arch, arch, t, syscall_state)
}

void rec_did_sigreturn(RecordTask *t) {
  auto& syscall_state = *syscall_state_property.get(*t);
  aarch64_kernel_bug_workaround(t, syscall_state);
  syscall_state_property.remove(*t);
}

void rec_process_syscall(RecordTask* t) {
  auto& syscall_state = *syscall_state_property.get(*t);
  const SyscallEvent& sys_ev = t->ev().Syscall();
  if (sys_ev.arch() != t->arch()) {
    static bool did_warn = false;
    if (!did_warn) {
      LOG(warn)
          << "Cross architecture syscall detected. Support is best effort";
      did_warn = true;
    }
  }
  rec_process_syscall_internal(t, sys_ev.arch(), syscall_state);
  syscall_state.process_syscall_results();

  aarch64_kernel_bug_workaround(t, syscall_state);

  t->on_syscall_exit(sys_ev.number, sys_ev.arch(), t->regs());
  syscall_state_property.remove(*t);

  MonitoredSharedMemory::check_all(t);
}

} // namespace rr
