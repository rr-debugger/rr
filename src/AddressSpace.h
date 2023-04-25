/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_ADDRESS_SPACE_H_
#define RR_ADDRESS_SPACE_H_

#include <inttypes.h>
#include <linux/kdev_t.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <functional>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "preload/preload_interface.h"

#include "EmuFs.h"
#include "HasTaskSet.h"
#include "MemoryRange.h"
#include "Monkeypatcher.h"
#include "TaskishUid.h"
#include "TraceStream.h"
#include "core.h"
#include "kernel_abi.h"
#include "log.h"
#include "remote_code_ptr.h"
#include "util.h"

namespace rr {

class AutoRemoteSyscalls;
class MonitoredSharedMemory;
class RecordSession;
class RecordTask;
class Session;
class Task;

/**
 * Records information that the kernel knows about a mapping. This includes
 * everything returned through /proc/<pid>/maps but also information that
 * we know from observing mmap and mprotect calls.
 */
class KernelMapping : public MemoryRange {
public:
  /**
   * These are the flags we track internally to distinguish
   * between adjacent segments.  For example, the kernel
   * considers a NORESERVE anonymous mapping that's adjacent to
   * a non-NORESERVE mapping distinct, even if all other
   * metadata are the same.  See |is_adjacent_mapping()|.
   */
  static const int map_flags_mask = MAP_ANONYMOUS | MAP_NORESERVE |
                                    MAP_PRIVATE | MAP_SHARED | MAP_STACK |
                                    MAP_GROWSDOWN;
  static const int checkable_flags_mask = MAP_PRIVATE | MAP_SHARED;
  static const dev_t NO_DEVICE = 0;
  static const ino_t NO_INODE = 0;

  KernelMapping() : device_(0), inode_(0), prot_(0), flags_(0), offset(0) {}
  KernelMapping(remote_ptr<void> start, remote_ptr<void> end,
                const std::string& fsname, dev_t device, ino_t inode, int prot,
                int flags, off64_t offset = 0)
      : MemoryRange(start, end),
        fsname_(fsname),
        device_(device),
        inode_(inode),
        prot_(prot),
        flags_(flags & map_flags_mask),
        offset(offset) {
    assert_valid();
  }

  KernelMapping(const KernelMapping& o)
      : MemoryRange(o),
        fsname_(o.fsname_),
        device_(o.device_),
        inode_(o.inode_),
        prot_(o.prot_),
        flags_(o.flags_),
        offset(o.offset) {
    assert_valid();
  }
  KernelMapping operator=(const KernelMapping& o) {
    this->~KernelMapping();
    new (this) KernelMapping(o);
    return *this;
  }

  void assert_valid() const {
    DEBUG_ASSERT(end() >= start());
    DEBUG_ASSERT(size() % page_size() == 0);
    DEBUG_ASSERT(!(flags_ & ~map_flags_mask));
    DEBUG_ASSERT(offset % page_size() == 0);
  }

  KernelMapping extend(remote_ptr<void> end) const {
    DEBUG_ASSERT(end >= MemoryRange::end());
    return KernelMapping(start(), end, fsname_, device_, inode_, prot_, flags_,
                         offset);
  }
  KernelMapping set_range(remote_ptr<void> start, remote_ptr<void> end) const {
    return KernelMapping(start, end, fsname_, device_, inode_, prot_, flags_,
                         offset);
  }
  KernelMapping subrange(remote_ptr<void> start, remote_ptr<void> end) const {
    DEBUG_ASSERT(start >= MemoryRange::start() && end <= MemoryRange::end());
    return KernelMapping(
        start, end, fsname_, device_, inode_, prot_, flags_,
        offset + (is_real_device() ? start - MemoryRange::start() : 0));
  }
  KernelMapping set_prot(int prot) const {
    return KernelMapping(start(), end(), fsname_, device_, inode_, prot, flags_,
                         offset);
  }

  /**
   * Dump a representation of |this| to a string in a format
   * similar to the former part of /proc/[tid]/maps.
  */
  std::string str() const {
    char str[200];
    sprintf(str, "%8p-%8p %c%c%c%c %08" PRIx64 " %02x:%02x %-10ld ",
            (void*)start().as_int(), (void*)end().as_int(),
            (PROT_READ & prot_) ? 'r' : '-', (PROT_WRITE & prot_) ? 'w' : '-',
            (PROT_EXEC & prot_) ? 'x' : '-', (MAP_SHARED & flags_) ? 's' : 'p',
            offset, (int)MAJOR(device()), (int)MINOR(device()), (long)inode());
    return str + fsname();
  }

  const std::string& fsname() const { return fsname_; }
  std::string fsname_strip_deleted() const;
  dev_t device() const { return device_; }
  ino_t inode() const { return inode_; }
  int prot() const { return prot_; }
  int flags() const { return flags_; }
  uint64_t file_offset_bytes() const { return offset; }

  /**
   * Return true if this file is/was backed by an external
   * device, as opposed to a transient RAM mapping.
   */
  bool is_real_device() const { return device() > NO_DEVICE; }
  bool is_vdso() const { return fsname() == "[vdso]"; }
  bool is_heap() const { return fsname() == "[heap]"; }
  bool is_stack() const { return fsname().find("[stack") == 0; }
  bool is_vvar() const { return fsname() == "[vvar]"; }
  bool is_vsyscall() const { return fsname() == "[vsyscall]"; }

  struct stat fake_stat() const {
    struct stat fake_stat;
    memset(&fake_stat, 0, sizeof(fake_stat));
    fake_stat.st_dev = device();
    fake_stat.st_ino = inode();
    fake_stat.st_size = size();
    return fake_stat;
  }

private:
  // The kernel's name for the mapping, as per /proc/<pid>/maps. This must
  // be exactly correct.
  const std::string fsname_;
  // Note that btrfs has weird behavior and /proc/.../maps can show a different
  // device number to the device from stat()ing the file that was mapped.
  // https://www.mail-archive.com/linux-btrfs@vger.kernel.org/msg57667.html
  // We store here the device number obtained from fstat()ing the file.
  // This also seems to be consistent with what we read from populate_address_space
  // for the initial post-exec mappings. It is NOT consistent with what we get
  // from reading /proc/.../maps for non-initial mappings.
  dev_t device_;
  ino_t inode_;
  const int prot_;
  const int flags_;
  const uint64_t offset;
};
inline std::ostream& operator<<(std::ostream& o, const KernelMapping& m) {
  o << m.str();
  return o;
}

/**
 * Compare |a| and |b| so that "subset" lookups will succeed.  What
 * does that mean?  If |a| and |b| overlap (intersect), then this
 * comparator considers them equivalent.  That means that if |a|
 * represents one byte within a mapping |b|, then |a| and |b| will be
 * considered equivalent.
 *
 * If |a| and |b| don't overlap, return true if |a|'s start address is
 * less than |b|'s/
 */
struct MappingComparator {
  bool operator()(const MemoryRange& a, const MemoryRange& b) const {
    return !a.intersects(b) && a.start() < b.start();
  }
};

enum BreakpointType {
  BKPT_NONE = 0,
  // Trap for internal rr purposes, f.e. replaying async
  // signals.
  BKPT_INTERNAL,
  // Trap on behalf of a debugger user.
  BKPT_USER,
};

enum WatchType {
  // NB: these random-looking enumeration values are chosen to
  // match the numbers programmed into x86 debug registers.
  WATCH_EXEC = 0x00,
  WATCH_WRITE = 0x01,
  WATCH_READWRITE = 0x03
};

enum ArmWatchType {
  ARM_WATCH_EXEC = 0x0,
  ARM_WATCH_READ = 0x1,
  ARM_WATCH_WRITE = 0x2,
  ARM_WATCH_READWRITE = ARM_WATCH_READ | ARM_WATCH_WRITE
};

enum ArmPrivLevel {
  ARM_PRIV_EL0 = 0x2
};

enum DebugStatus {
  DS_WATCHPOINT_ANY = 0xf,
  DS_SINGLESTEP = 1 << 14,
};

/**
 * A distinct watchpoint, corresponding to the information needed to
 * program a single hardware watchpoint.
 */
struct WatchConfig {
  WatchConfig(remote_ptr<void> addr, size_t num_bytes, WatchType type)
      : addr(addr), num_bytes(num_bytes), type(type) {}
  remote_ptr<void> addr;
  size_t num_bytes;
  WatchType type;

  bool operator==(const WatchConfig& other) const {
    return addr == other.addr && num_bytes == other.num_bytes &&
      type == other.type;
  }
  bool operator!=(const WatchConfig& other) const {
    return !(*this == other);
  }
};

/**
 * Models the address space for a set of tasks.  This includes the set
 * of mapped pages, and the resources those mappings refer to.
 */
class AddressSpace : public HasTaskSet {
  friend class Session;
  friend struct VerifyAddressSpace;

public:
  class Mapping {
  public:
    Mapping(const KernelMapping& map, const KernelMapping& recorded_map,
            EmuFile::shr_ptr emu_file = nullptr,
            std::unique_ptr<struct stat> mapped_file_stat = nullptr,
            void* local_addr = nullptr,
            std::shared_ptr<MonitoredSharedMemory>&& monitored = nullptr);
    ~Mapping();
    Mapping(const Mapping&);
    Mapping() : local_addr(nullptr), flags(0) {}
    const Mapping& operator=(const Mapping& other) {
      this->~Mapping();
      new (this) Mapping(other);
      return *this;
    }

    const KernelMapping map;
    // The corresponding KernelMapping in the recording. During recording,
    // equal to 'map'.
    const KernelMapping recorded_map;
    const EmuFile::shr_ptr emu_file;
    std::unique_ptr<struct stat> mapped_file_stat;
    // If this mapping has been mapped into the local address space,
    // this is the address of the first byte of the equivalent local mapping.
    // This mapping is always mapped as PROT_READ|PROT_WRITE regardless of the
    // mapping's permissions in the tracee. Also note that it is the caller's
    // responsibility to keep this alive at least as long as this mapping is
    // present in the address space.
    uint8_t* local_addr;
    const std::shared_ptr<MonitoredSharedMemory> monitored_shared_memory;
    // Flags indicate mappings that require special handling. Adjacent mappings
    // may only be merged if their `flags` value agree.
    enum : uint32_t {
      FLAG_NONE = 0x0,
      // This mapping represents a syscallbuf. It needs to handled specially
      // during checksumming since its contents are not fully restored by the
      // replay.
      IS_SYSCALLBUF = 0x1,
      // This mapping is used as our thread-local variable area for this
      // address space
      IS_THREAD_LOCALS = 0x2,
      // This mapping is used for syscallbuf patch stubs
      IS_PATCH_STUBS = 0x4,
      // This mapping is the rr page
      IS_RR_PAGE = 0x8
    };
    uint32_t flags;
  };

  typedef std::map<MemoryRange, Mapping, MappingComparator> MemoryMap;
  typedef std::shared_ptr<AddressSpace> shr_ptr;

  virtual ~AddressSpace();

  /**
   * Call this after a successful execve syscall has completed. At this point
   * it is safe to perform remote syscalls.
   */
  void post_exec_syscall(Task* t);

  /**
   * Change the program data break of this address space to
   * |addr|. Only called during recording!
   */
  void brk(Task* t, remote_ptr<void> addr, int prot);

  /**
   * This can only be called during recording.
   */
  remote_ptr<void> current_brk() const {
    DEBUG_ASSERT(!brk_end.is_null());
    return brk_end;
  }

  /**
   * Dump a representation of |this| to stderr in a format
   * similar to /proc/[tid]/maps.
   *
   * XXX/ostream-ify me.
   */
  void dump() const;

  /**
   * Return tid of the first task for this address space.
   */
  pid_t leader_tid() const { return leader_tid_; }

  /**
   * Return AddressSpaceUid for this address space.
   */
  AddressSpaceUid uid() const {
    return AddressSpaceUid(leader_tid_, leader_serial, exec_count);
  }

  Session* session() const { return session_; }

  SupportedArch arch() const;

  /**
   * Return the path this address space was exec()'d with.
   */
  const std::string& exe_image() const { return exe; }

  const std::string& interp_name() const { return interp_name_; }
  void set_interp_name(std::string name) { interp_name_ = name; }

  remote_ptr<void> interp_base() const { return interp_base_; }
  void set_interp_base(remote_ptr<void> base) { interp_base_ = base; }

  /**
   * Assuming the last retired instruction has raised a SIGTRAP
   * and might be a breakpoint trap instruction, return the type
   * of breakpoint set at |ip() - sizeof(breakpoint_insn)|, if
   * one exists.  Otherwise return TRAP_NONE.
   */
  BreakpointType get_breakpoint_type_for_retired_insn(remote_code_ptr ip);

  /**
   * Return the type of breakpoint that's been registered for
   * |addr|.
   */
  BreakpointType get_breakpoint_type_at_addr(remote_code_ptr addr);

  /**
   * Check if the user has placed a hardware EXEC watchpoint at addr.
   */
  bool is_exec_watchpoint(remote_code_ptr addr);

  /**
   * Returns true when the breakpoint at |addr| is in private
   * non-writeable memory. When this returns true, the breakpoint can't be
   * overwritten by the tracee without an intervening mprotect or mmap
   * syscall.
   */
  bool is_breakpoint_in_private_read_only_memory(remote_code_ptr addr);

  /**
   * Return true if there's a breakpoint instruction at |ip|. This might
   * be an explicit instruction, even if there's no breakpoint set via our API.
   */
  bool is_breakpoint_instruction(Task* t, remote_code_ptr ip);

  /**
   * The buffer |dest| of length |length| represents the contents of tracee
   * memory at |addr|. Replace the bytes in |dest| that have been overwritten
   * by breakpoints with the original data that was replaced by the breakpoints.
   */
  void replace_breakpoints_with_original_values(uint8_t* dest, size_t length,
                                                remote_ptr<uint8_t> addr);

  /**
   * Map |num_bytes| into this address space at |addr|, with
   * |prot| protection and |flags|.  The pages are (possibly
   * initially) backed starting at |offset| of |res|. |fsname|, |device| and
   * |inode| are values that will appear in the /proc/<pid>/maps entry.
   * |mapped_file_stat| is a complete copy of the 'stat' data for the mapped
   * file, or null if this isn't a file mapping or isn't during recording.
   * |*recorded_map| is the mapping during recording, or null if the mapping
   * during recording is known to be the same as the new map (e.g. because
   * we are recording!).
   * |local_addr| is the local address of the memory shared with the tracee,
   * or null if it's not shared with the tracee. AddressSpace takes ownership
   * of the shared memory and is responsible for unmapping it.
   */
  KernelMapping map(
      Task* t, remote_ptr<void> addr, size_t num_bytes, int prot, int flags,
      off64_t offset_bytes, const std::string& fsname,
      dev_t device = KernelMapping::NO_DEVICE,
      ino_t inode = KernelMapping::NO_INODE,
      std::unique_ptr<struct stat> mapped_file_stat = nullptr,
      const KernelMapping* recorded_map = nullptr,
      EmuFile::shr_ptr emu_file = nullptr, void* local_addr = nullptr,
      std::shared_ptr<MonitoredSharedMemory> monitored = nullptr);

  /**
   * Return the mapping and mapped resource for the byte at address 'addr'.
   * There must be such a mapping.
   */
  const Mapping& mapping_of(remote_ptr<void> addr) const;

  /**
   * Detach local mapping and return it.
   */
  void* detach_local_mapping(remote_ptr<void> addr);

  /**
   * Return a reference to the flags of the mapping at this address, allowing
   * manipulation. There must exist a mapping at `addr`.
   */
  uint32_t& mapping_flags_of(remote_ptr<void> addr);

  /**
   * Return true if there is some mapping for the byte at 'addr'.
   */
  bool has_mapping(remote_ptr<void> addr) const;

  /**
   * If the given memory region is mapped into the local address space, obtain
   * the local address from which the `size` bytes at `addr` can be accessed.
   */
  uint8_t* local_mapping(remote_ptr<void> addr, size_t size);

  /**
   * Return true if the rr page is mapped at its expected address.
   */
  bool has_rr_page() const;

  /**
   * Object that generates robust iterators through the memory map. The
   * memory map can be updated without invalidating iterators, as long as
   * Mappings are not added or removed.
   */
  class Maps {
  public:
    Maps(const AddressSpace& outer, remote_ptr<void> start)
        : outer(outer), start(start) {}
    class iterator {
    public:
      iterator(const iterator& it) = default;
      const iterator& operator++() {
        ptr = to_it()->second.map.end();
        return *this;
      }
      bool operator==(const iterator& other) const {
        return to_it() == other.to_it();
      }
      bool operator!=(const iterator& other) const { return !(*this == other); }
      const Mapping* operator->() const { return &to_it()->second; }
      const Mapping& operator*() const { return to_it()->second; }
      iterator& operator=(const iterator& other) {
        this->~iterator();
        new (this) iterator(other);
        return *this;
      }

    private:
      friend class Maps;
      iterator(const MemoryMap& outer, remote_ptr<void> ptr)
          : outer(outer), ptr(ptr), at_end(false) {}
      iterator(const MemoryMap& outer) : outer(outer), at_end(true) {}
      MemoryMap::const_iterator to_it() const {
        return at_end ? outer.end() : outer.lower_bound(MemoryRange(ptr, ptr));
      }
      const MemoryMap& outer;
      remote_ptr<void> ptr;
      bool at_end;
    };
    iterator begin() const { return iterator(outer.mem, start); }
    iterator end() const { return iterator(outer.mem); }

  private:
    const AddressSpace& outer;
    remote_ptr<void> start;
  };
  friend class Maps;
  Maps maps() const { return Maps(*this, remote_ptr<void>()); }
  Maps maps_starting_at(remote_ptr<void> start) { return Maps(*this, start); }
  Maps maps_containing_or_after(remote_ptr<void> start) {
    if (has_mapping(start)) {
      return Maps(*this, mapping_of(start).map.start());
    } else {
      return Maps(*this, start);
    }
  }

  const std::set<remote_ptr<void>>& monitored_addrs() const {
    return monitored_mem;
  }

  /**
   * Change the protection bits of [addr, addr + num_bytes) to
   * |prot|.
   */
  void protect(Task* t, remote_ptr<void> addr, size_t num_bytes, int prot);

  /**
   * Fix up mprotect registers parameters to take account of PROT_GROWSDOWN.
   */
  void fixup_mprotect_growsdown_parameters(Task* t);

  /**
   * Move the mapping [old_addr, old_addr + old_num_bytes) to
   * [new_addr, old_addr + new_num_bytes), preserving metadata.
   */
  void remap(Task* t, remote_ptr<void> old_addr, size_t old_num_bytes,
             remote_ptr<void> new_addr, size_t new_num_bytes, int flags);

  /**
   * Notify that data was written to this address space by rr or
   * by the kernel.
   * |flags| can contain values from Task::WriteFlags.
   */
  void notify_written(remote_ptr<void> addr, size_t num_bytes, uint32_t flags);

  /** Ensure a breakpoint of |type| is set at |addr|. */
  bool add_breakpoint(remote_code_ptr addr, BreakpointType type);
  /**
   * Remove a |type| reference to the breakpoint at |addr|.  If
   * the removed reference was the last, the breakpoint is
   * destroyed.
   */
  void remove_breakpoint(remote_code_ptr addr, BreakpointType type);
  /**
   * Destroy all breakpoints in this VM, regardless of their
   * reference counts.
   */
  void remove_all_breakpoints();

  /**
   * Temporarily remove the breakpoint at |addr|.
   */
  void suspend_breakpoint_at(remote_code_ptr addr);
  /**
   * Restore any temporarily removed breakpoint at |addr|.
   */
  void restore_breakpoint_at(remote_code_ptr addr);

  /**
   * Manage watchpoints.  Analogous to breakpoint-managing
   * methods above, except that watchpoints can be set for an
   * address range.
   */
  bool add_watchpoint(remote_ptr<void> addr, size_t num_bytes, WatchType type);
  void remove_watchpoint(remote_ptr<void> addr, size_t num_bytes,
                         WatchType type);
  void remove_all_watchpoints();
  std::vector<WatchConfig> all_watchpoints() {
    return get_watchpoints_internal(ALL_WATCHPOINTS, UNALIGNED,
      DONT_UPDATE_WATCHPOINT_REGISTER_ASSIGNMENTS);
  }

  /**
   * Save all watchpoint state onto a stack.
   */
  void save_watchpoints();
  /**
   * Pop all watchpoint state from the saved-state stack.
   */
  bool restore_watchpoints();

  /**
   * Notify that at least one watchpoint was hit --- recheck them all.
   * Returns true if any watchpoint actually triggered. Note that
   * debug_status can indicate a hit watchpoint that doesn't actually
   * trigger, because the value of a write-watchpoint did not change.
   * Likewise, debug_status can indicate a watchpoint wasn't hit that
   * actually was (because in some configurations, e.g. VMWare
   * hypervisor with 32-bit x86 guest, debug_status watchpoint bits
   * are known to not be set on singlestep).
   */
  bool notify_watchpoint_fired(uintptr_t debug_status,
      remote_ptr<void> hit_addr,
      remote_code_ptr address_of_singlestep_start);
  /**
   * Return true if any watchpoint has fired. Will keep returning true until
   * consume_watchpoint_changes() is called.
   */
  bool has_any_watchpoint_changes();
  /**
   * Return true if an EXEC watchpoint has fired at addr since the last
   * consume_watchpoint_changes.
   */
  bool has_exec_watchpoint_fired(remote_code_ptr addr);

  /**
   * Return all changed watchpoints in |watches| and clear their changed flags.
   */
  std::vector<WatchConfig> consume_watchpoint_changes() {
    return get_watchpoints_internal(CHANGED_WATCHPOINTS, UNALIGNED,
      DONT_UPDATE_WATCHPOINT_REGISTER_ASSIGNMENTS);
  }

  /**
   * Get hardware watchpoint assignments.
   */
  std::vector<WatchConfig> get_hw_watchpoints() {
    return get_watchpoints_internal(ALL_WATCHPOINTS, ALIGNED,
      DONT_UPDATE_WATCHPOINT_REGISTER_ASSIGNMENTS);
  }

  void set_shm_size(remote_ptr<void> addr, size_t bytes) {
    shm_sizes[addr] = bytes;
  }
  /**
   * Dies if no shm size is registered for the address.
   */
  size_t get_shm_size(remote_ptr<void> addr) { return shm_sizes[addr]; }
  void remove_shm_size(remote_ptr<void> addr) { shm_sizes.erase(addr); }

  /**
   * Make [addr, addr + num_bytes) inaccessible within this
   * address space.
   */
  void unmap(Task* t, remote_ptr<void> addr, ssize_t num_bytes);

  /**
   * Notification of madvise call.
   */
  void advise(Task* t, remote_ptr<void> addr, ssize_t num_bytes, int advice);

  /** Return the vdso mapping of this. */
  KernelMapping vdso() const;
  bool has_vdso() const { return has_mapping(vdso_start_addr); }

  /**
   * Verify that this cached address space matches what the
   * kernel thinks it should be.
   */
  void verify(Task* t) const;

  bool has_breakpoints() { return !breakpoints.empty(); }
  bool has_watchpoints() { return !watchpoints.empty(); }

  ScopedFd& mem_fd() { return child_mem_fd; }
  void set_mem_fd(ScopedFd&& fd) { child_mem_fd = std::move(fd); }

  ScopedFd& pagemap_fd() { return child_pagemap_fd; }
  void set_pagemap_fd(ScopedFd&& fd) { child_pagemap_fd = std::move(fd); }

  Monkeypatcher& monkeypatcher() {
    DEBUG_ASSERT(monkeypatch_state);
    return *monkeypatch_state;
  }

  void at_preload_init(Task* t);

  /* The address of the syscall instruction from which traced syscalls made by
   * the syscallbuf will originate. */
  remote_code_ptr traced_syscall_ip() const { return traced_syscall_ip_; }
  /* The address of the syscall instruction from which privileged traced
   * syscalls made by the syscallbuf will originate. */
  remote_code_ptr privileged_traced_syscall_ip() const {
    return privileged_traced_syscall_ip_;
  }

  bool syscallbuf_enabled() const { return syscallbuf_enabled_; }

  /**
   * We'll map a page of memory here into every exec'ed process for our own
   * use.
   */
  static remote_ptr<void> rr_page_start() { return RR_PAGE_ADDR; }
  static remote_ptr<void> rr_page_end() {
    return rr_page_start() + PRELOAD_LIBRARY_PAGE_SIZE;
  }

  static remote_ptr<void> preload_thread_locals_start() {
    return rr_page_start() + PRELOAD_LIBRARY_PAGE_SIZE;
  }
  static uint32_t preload_thread_locals_size() {
    return PRELOAD_THREAD_LOCALS_SIZE;
  }

  enum Traced { TRACED, UNTRACED };
  enum Privileged { PRIVILEGED, UNPRIVILEGED };
  /**
   * Depending on which entry point this is and whether or not we're recording
   * or replaying, the instruction in the rr page, may be something other than
   * a syscall. This enum encodes the combination of instructions for each entry
   * point:
   *
   *      Enabled         | Record  | Replay
   * ---------------------|---------|-------
   * RECORDING_ONLY       | syscall | nop
   * REPLAY_ONLY          | nop     | syscall
   * RECORDING_AND_REPLAY | syscall | syscall
   * REPLAY_ASSIST        | syscall | int3
   *
   * The REPLAY_ASSIST is used for a syscall that is untraced during record (so
   * we can save the context switch penalty), but requires us to apply side
   * effects during replay. The int3 lets the replayer stop and apply these
   * at the appropriate point.
   */
  enum Enabled { RECORDING_ONLY, REPLAY_ONLY, RECORDING_AND_REPLAY, REPLAY_ASSIST };
  static remote_code_ptr rr_page_syscall_exit_point(Traced traced,
                                                    Privileged privileged,
                                                    Enabled enabled,
                                                    SupportedArch arch);
  static remote_code_ptr rr_page_syscall_entry_point(Traced traced,
                                                     Privileged privileged,
                                                     Enabled enabled,
                                                     SupportedArch arch);

  struct SyscallType {
    Traced traced;
    Privileged privileged;
    Enabled enabled;
  };
  static std::vector<SyscallType> rr_page_syscalls();
  static const SyscallType* rr_page_syscall_from_exit_point(
    SupportedArch arch, remote_code_ptr ip);
  static const SyscallType* rr_page_syscall_from_entry_point(
    SupportedArch arch, remote_code_ptr ip);

  /**
   * Return a pointer to 8 bytes of 0xFF.
   * (Currently only set during record / not part of the ABI)
   */
  static remote_ptr<uint8_t> rr_page_record_ff_bytes() { return RR_PAGE_FF_BYTES; }

  /**
   * Locate a syscall instruction in t's VDSO.
   * This gives us a way to execute remote syscalls without having to write
   * a syscall instruction into executable tracee memory (which might not be
   * possible with some kernels, e.g. PaX).
   */
  remote_code_ptr find_syscall_instruction(Task* t);

  /**
   * Task |t| just forked from this address space. Apply dont_fork and
   * wipe_on_fork settings.
   */
  void did_fork_into(Task* t);

  void set_first_run_event(FrameTime event) { first_run_event_ = event; }
  FrameTime first_run_event() { return first_run_event_; }

  const std::vector<uint8_t>& saved_auxv() { return saved_auxv_; }
  void save_auxv(Task* t);

  remote_ptr<void> saved_interpreter_base() { return saved_interpreter_base_; }
  void save_interpreter_base(Task* t, std::vector<uint8_t> auxv);

  std::string saved_ld_path() { return saved_ld_path_;}
  void save_ld_path(Task* t, remote_ptr<void>);

  void read_mm_map(Task* t, NativeArch::prctl_mm_map* map);

  /**
   * Reads the /proc/<pid>/maps entry for a specific address. Does no caching.
   * If performed on a file in a btrfs file system, this may return the
   * wrong device number! If you stick to anonymous or special file
   * mappings, this should be OK.
   */
  KernelMapping read_kernel_mapping(Task* t, remote_ptr<void> addr);

  /**
   * Same as read_kernel_mapping, but reads rr's own memory map.
   */
  static KernelMapping read_local_kernel_mapping(uint8_t* addr);

  static uint32_t chaos_mode_min_stack_size() { return 8 * 1024 * 1024; }

  /* Returns null if we should return ENOMEM because there is no free space available. */
  remote_ptr<void> chaos_mode_find_free_memory(RecordTask* t, size_t len, remote_ptr<void> hint);
  enum class FindFreeMemoryPolicy {
    /* Use the first free memory after `after` */
    STRICT_SEARCH,
    /* Optimize for speed by starting the search from the address of the last
       area returned by find_free_memory (if greater than `after`). */
    USE_LAST_FREE_HINT,
  };
  remote_ptr<void> find_free_memory(Task* t,
      size_t len, remote_ptr<void> after = remote_ptr<void>(),
      FindFreeMemoryPolicy policy = FindFreeMemoryPolicy::STRICT_SEARCH);

  /**
   * The return value indicates whether we (re)created the preload_thread_locals
   * area.
   */
  bool post_vm_clone(Task* t);
  /**
   * TaskUid for the task whose locals are stored in the preload_thread_locals
   * area.
   */
  const TaskUid& thread_locals_tuid() { return thread_locals_tuid_; }
  void set_thread_locals_tuid(const TaskUid& tuid) {
    thread_locals_tuid_ = tuid;
  }

  /**
   * Call this when the memory at [addr,addr+len) was externally overwritten.
   * This will attempt to update any breakpoints that may be set within the
   * range (resetting them and storing the new value).
   */
  void maybe_update_breakpoints(Task* t, remote_ptr<uint8_t> addr, size_t len);

  /**
   * Call this to ensure that the mappings in `range` during replay has the same length
   * is collapsed to a single mapping. The caller guarantees that all the
   * mappings in the range can be coalesced (because they corresponded to a single
   * mapping during recording).
   * The end of the range might be in the middle of a mapping.
   * The start of the range might also be in the middle of a mapping.
   */
  void ensure_replay_matches_single_recorded_mapping(Task* t, MemoryRange range);

  /**
   * Print process maps.
   */
  static void print_process_maps(Task* t);

  void add_stap_semaphore_range(Task* t, MemoryRange range);
  void remove_stap_semaphore_range(Task* t, MemoryRange range);
  bool is_stap_semaphore(remote_ptr<uint16_t> addr);

  bool legacy_breakpoint_mode() { return stopping_breakpoint_table_ != nullptr; }
  remote_code_ptr do_breakpoint_fault_addr() { return do_breakpoint_fault_addr_; }
  remote_code_ptr stopping_breakpoint_table() { return stopping_breakpoint_table_; }
  int stopping_breakpoint_table_entry_size() { return stopping_breakpoint_table_entry_size_; }

  // Also sets brk_ptr.
  enum {
    RRVDSO_PAGE_OFFSET = 2,
    RRPAGE_RECORD_PAGE_OFFSET = 3,
    RRPAGE_REPLAY_PAGE_OFFSET = 4
  };

  void map_rr_page(AutoRemoteSyscalls& remote);
  void unmap_all_but_rr_page(AutoRemoteSyscalls& remote);

  void erase_task(Task* t) {
    this->HasTaskSet::erase_task(t);
    if (task_set().size() != 0) {
      fd_tables_changed();
    }
  }

  /**
   * Called when the set of different fd tables associated with tasks
   * in this address space may have changed (e.g. a task changed its fd table,
   * or a task got added or removed, etc).
   */
  void fd_tables_changed();

  static MemoryRange get_global_exclusion_range(const RecordSession* session);

  // Whether to return WatchConfigs consisting of only aligned locations
  // suitable for hardware watchpoint registers.
  enum WatchpointAlignment { UNALIGNED, ALIGNED };

private:
  struct Breakpoint;
  typedef std::map<remote_code_ptr, Breakpoint> BreakpointMap;
  class Watchpoint;

  /**
   * Called after a successful execve to set up the new AddressSpace.
   * Also called once for the initial spawn.
   */
  AddressSpace(Task* t, const std::string& exe, uint32_t exec_count);
  /**
   * Called when an AddressSpace is cloned due to a fork() or a Session
   * clone. After this, and the task is properly set up, post_vm_clone will
   * be called.
   */
  AddressSpace(Session* session, const AddressSpace& o, pid_t leader_tid,
               uint32_t leader_serial, uint32_t exec_count);

  /**
   * After an exec, populate the new address space of |t| with
   * the existing mappings we find in /proc/maps.
   */
  void populate_address_space(Task* t);

  void unmap_internal(Task* t, remote_ptr<void> addr, ssize_t num_bytes);

  bool update_watchpoint_value(const MemoryRange& range,
                               Watchpoint& watchpoint);
  void update_watchpoint_values(remote_ptr<void> start, remote_ptr<void> end);
  // Whether to handle all watchpoints or just data watchpoints whose data
  // has changed. In the latter case we clear their changed status.
  enum WatchpointFilter { ALL_WATCHPOINTS, CHANGED_WATCHPOINTS };
  // Whether to update the watchpoint's assigned register list. Use
  // UPDATE_WATCHPOINT_REGISTER_ASSIGNMENTS when we'll use the watchpoints
  // to configure HW watchpoint registers.
  enum UpdateWatchpointRegisterAssignments { UPDATE_WATCHPOINT_REGISTER_ASSIGNMENTS,
      DONT_UPDATE_WATCHPOINT_REGISTER_ASSIGNMENTS };
  std::vector<WatchConfig> get_watchpoints_internal(WatchpointFilter filter,
        WatchpointAlignment alignment,
        UpdateWatchpointRegisterAssignments update_watchpoint_register_assignments);

  /**
   * Construct a minimal set of watchpoints to be enabled based
   * on |set_watchpoint()| calls, and program them for each task
   * in this address space.
   */
  bool allocate_watchpoints();

  /**
   * Merge the mappings adjacent to |it| in memory that are
   * semantically "adjacent mappings" of the same resource as
   * well, for example have adjacent file offsets and the same
   * prot and flags.
   */
  void coalesce_around(Task* t, MemoryMap::iterator it);

  /**
   * Erase |it| from |breakpoints| and restore any memory in
   * this it may have overwritten.
   */
  void destroy_breakpoint(BreakpointMap::const_iterator it);

  /**
   * For each mapped segment overlapping [addr, addr +
   * num_bytes), call |f|.  Pass |f| the overlapping mapping,
   * the mapped resource, and the range of addresses remaining
   * to be iterated over.
   *
   * Pass |ITERATE_CONTIGUOUS| to stop iterating when the last
   * contiguous mapping after |addr| within the region is seen.
   * Default is to iterate all mappings in the region.
   *
   * The callback takes parameters by value to avoid dangling
   * references if the memory map is modified inside the callback.
   */
  enum { ITERATE_DEFAULT, ITERATE_CONTIGUOUS };
  void for_each_in_range(
      remote_ptr<void> addr, ssize_t num_bytes,
      std::function<void(Mapping m, MemoryRange rem)> f,
      int how = ITERATE_DEFAULT);

  /**
   * Map |m| of |r| into this address space, and coalesce any
   * mappings of |r| that are adjacent to |m|.
   */
  void map_and_coalesce(Task* t, const KernelMapping& m,
                        const KernelMapping& recorded_map,
                        EmuFile::shr_ptr emu_file,
                        std::unique_ptr<struct stat> mapped_file_stat,
                        void* local_addr,
                        std::shared_ptr<MonitoredSharedMemory> monitored);

  void remove_from_map(const MemoryRange& range) {
    mem.erase(range);
    monitored_mem.erase(range.start());
  }
  void add_to_map(const Mapping& m) {
    mem[m.map] = m;
    if (m.monitored_shared_memory) {
      monitored_mem.insert(m.map.start());
    }
  }

  /**
   * Call this only during recording.
   */
  template <typename Arch> void at_preload_init_arch(Task* t);

  enum { EXEC_BIT = 1 << 0, READ_BIT = 1 << 1, WRITE_BIT = 1 << 2 };

  /** Return the access bits above needed to watch |type|. */
  static int access_bits_of(WatchType type);

  /**
   * Represents a refcount set on a particular address.  Because there
   * can be multiple refcounts of multiple types set on a single
   * address, Breakpoint stores explicit USER and INTERNAL breakpoint
   * refcounts.  Clients adding/removing breakpoints at this addr must
   * call ref()/unref() as appropriate.
   */
  struct Breakpoint {
    Breakpoint() : internal_count(0), user_count(0) {}
    Breakpoint(const Breakpoint& o) = default;
    // AddressSpace::destroy_all_breakpoints() can cause this
    // destructor to be invoked while we have nonzero total
    // refcount, so the most we can DEBUG_ASSERT is that the refcounts
    // are valid.
    ~Breakpoint() { DEBUG_ASSERT(internal_count >= 0 && user_count >= 0); }

    void ref(BreakpointType which) {
      DEBUG_ASSERT(internal_count >= 0 && user_count >= 0);
      ++*counter(which);
    }
    int unref(BreakpointType which) {
      DEBUG_ASSERT(internal_count > 0 || user_count > 0);
      --*counter(which);
      DEBUG_ASSERT(internal_count >= 0 && user_count >= 0);
      return internal_count + user_count;
    }

    BreakpointType type() const {
      // NB: USER breakpoints need to be processed before
      // INTERNAL ones.  We want to give the debugger a
      // chance to dispatch commands before we attend to the
      // internal rr business.  So if there's a USER "ref"
      // on the breakpoint, treat it as a USER breakpoint.
      return user_count > 0 ? BKPT_USER : BKPT_INTERNAL;
    }

    uint8_t* original_data() { return overwritten_data; }

    // "Refcounts" of breakpoints set at |addr|.  The breakpoint
    // object must be unique since we have to save the overwritten
    // data, and we can't enforce the order in which breakpoints
    // are set/removed.
    int internal_count, user_count;
    uint8_t overwritten_data[MAX_BKPT_INSTRUCTION_LENGTH];

    int* counter(BreakpointType which) {
      DEBUG_ASSERT(BKPT_INTERNAL == which || BKPT_USER == which);
      int* p = BKPT_USER == which ? &user_count : &internal_count;
      DEBUG_ASSERT(*p >= 0);
      return p;
    }
  };

  // XXX one is tempted to merge Breakpoint and Watchpoint into a single
  // entity, but the semantics are just different enough that separate
  // objects are easier for now.
  /**
   * Track the watched accesses of a contiguous range of memory
   * addresses.
   */
  class Watchpoint {
  public:
    Watchpoint(size_t num_bytes)
        : exec_count(0),
          read_count(0),
          write_count(0),
          value_bytes(num_bytes),
          valid(false),
          changed(false) {}
    Watchpoint(const Watchpoint&) = default;
    ~Watchpoint() { assert_valid(); }

    void watch(int which) {
      assert_valid();
      exec_count += (EXEC_BIT & which) != 0;
      read_count += (READ_BIT & which) != 0;
      write_count += (WRITE_BIT & which) != 0;
    }
    int unwatch(int which) {
      assert_valid();
      if (EXEC_BIT & which) {
        DEBUG_ASSERT(exec_count > 0);
        --exec_count;
      }
      if (READ_BIT & which) {
        DEBUG_ASSERT(read_count > 0);
        --read_count;
      }
      if (WRITE_BIT & which) {
        DEBUG_ASSERT(write_count > 0);
        --write_count;
      }
      return exec_count + read_count + write_count;
    }

    int watched_bits() const {
      return (exec_count > 0 ? EXEC_BIT : 0) | (read_count > 0 ? READ_BIT : 0) |
             (write_count > 0 ? WRITE_BIT : 0);
    }

    void assert_valid() const {
      DEBUG_ASSERT(exec_count >= 0 && read_count >= 0 && write_count >= 0);
    }

    // Watchpoints stay alive until all watched access typed have
    // been cleared.  We track refcounts of each watchable access
    // separately.
    int exec_count, read_count, write_count;
    // Debug registers allocated for read/exec access checking.
    // Write watchpoints are always triggered by checking for actual memory
    // value changes. Read/exec watchpoints can't be triggered that way, so
    // we look for these registers being triggered instead.
    std::vector<int8_t> debug_regs_for_exec_read;
    std::vector<uint8_t> value_bytes;
    bool valid;
    bool changed;
  };

  // All breakpoints set in this VM.
  BreakpointMap breakpoints;
  /* Path of the real executable image this address space was
   * exec()'d with. */
  std::string exe;
  /* Path of the interpreter, if any, of exe. */
  std::string interp_name_;
  /* Base address of the interpreter (might be null!) */
  remote_ptr<void> interp_base_;
  /* Pid of first task for this address space */
  pid_t leader_tid_;
  /* Serial number of first task for this address space */
  uint32_t leader_serial;
  uint32_t exec_count;
  // Only valid during recording
  remote_ptr<void> brk_start;
  /* Current brk. Not necessarily page-aligned. */
  remote_ptr<void> brk_end;
  /* All segments mapped into this address space. */
  MemoryMap mem;
  /* Sizes of SYSV shm segments, by address. We use this to determine the size
   * of memory regions unmapped via shmdt(). */
  std::map<remote_ptr<void>, size_t> shm_sizes;
  std::set<remote_ptr<void>> monitored_mem;
  /* madvise DONTFORK regions */
  std::set<MemoryRange> dont_fork;
  /* madvise WIPEONFORK regions */
  std::set<MemoryRange> wipe_on_fork;
  // The session that created this.  We save a ref to it so that
  // we can notify it when we die.
  Session* session_;
  // tid of the task whose thread-locals are in preload_thread_locals
  TaskUid thread_locals_tuid_;
  /* First mapped byte of the vdso. */
  remote_ptr<void> vdso_start_addr;
  // The monkeypatcher that's handling this address space.
  std::unique_ptr<Monkeypatcher> monkeypatch_state;
  // The watchpoints set for tasks in this VM.  Watchpoints are
  // programmed per Task, but we track them per address space on
  // behalf of debuggers that assume that model.
  std::map<MemoryRange, Watchpoint> watchpoints;
  std::vector<std::map<MemoryRange, Watchpoint>> saved_watchpoints;
  // Tracee memory is read and written through this fd, which is
  // opened for the tracee's magic /proc/[tid]/mem device.  The
  // advantage of this over ptrace is that we can access it even
  // when the tracee isn't at a ptrace-stop.  It's also
  // theoretically faster for large data transfers, which rr can
  // do often.
  //
  // Users of child_mem_fd should fall back to ptrace-based memory
  // access when child_mem_fd is not open.
  ScopedFd child_mem_fd;
  remote_code_ptr traced_syscall_ip_;
  remote_code_ptr privileged_traced_syscall_ip_;
  bool syscallbuf_enabled_;

  remote_code_ptr do_breakpoint_fault_addr_;
  // These fields are deprecated and have been replaced by the
  // breakpoint_value mechanism. They are retained for replayability
  // of old traces.
  remote_code_ptr stopping_breakpoint_table_;
  int stopping_breakpoint_table_entry_size_;

  std::vector<uint8_t> saved_auxv_;
  remote_ptr<void> saved_interpreter_base_;
  std::string saved_ld_path_;

  remote_ptr<void> last_free_memory;

  /**
   * The time of the first event that ran code for a task in this address space.
   * 0 if no such event has occurred.
   */
  FrameTime first_run_event_;

  std::set<remote_ptr<uint16_t>> stap_semaphores;

  /**
   * For each architecture, the offset of a syscall instruction with that
   * architecture's VDSO, or 0 if not known.
   */
  static uint32_t offset_to_syscall_in_vdso[SupportedArch_MAX + 1];

  /**
   * Ensure that the cached mapping of |t| matches /proc/maps,
   * using adjacent-map-merging heuristics that are as lenient
   * as possible given the data available from /proc/maps.
   */
  static void check_segment_iterator(void* vasp, Task* t,
                                     const struct map_iterator_data* data);

  AddressSpace operator=(const AddressSpace&) = delete;

  ScopedFd child_pagemap_fd;
};

/**
 * The following helper is used to iterate over a tracee's memory
 * map.
 */
class KernelMapIterator {
public:
  KernelMapIterator(Task* t);
  KernelMapIterator(pid_t tid) : tid(tid) { init(); }
  ~KernelMapIterator();

  // It's very important to keep in mind that btrfs files can have the wrong
  // device number!
  const KernelMapping& current(std::string* raw_line = nullptr) {
    if (raw_line) {
      *raw_line = this->raw_line;
    }
    return km;
  }
  bool at_end() { return !maps_file; }
  void operator++();

private:
  void init();

  pid_t tid;
  FILE* maps_file;
  std::string raw_line;
  KernelMapping km;
};

} // namespace rr

#endif /* RR_ADDRESS_SPACE_H_ */
