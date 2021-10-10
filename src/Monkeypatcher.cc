/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "Monkeypatcher.h"

#include <limits.h>
#include <linux/auxvec.h>

#include <sstream>

#include "AddressSpace.h"
#include "AutoRemoteSyscalls.h"
#include "ElfReader.h"
#include "Flags.h"
#include "RecordSession.h"
#include "RecordTask.h"
#include "ReplaySession.h"
#include "ScopedFd.h"
#include "core.h"
#include "kernel_abi.h"
#include "kernel_metadata.h"
#include "log.h"

using namespace std;

namespace rr {

#include "AssemblyTemplates.generated"

static void write_and_record_bytes(RecordTask* t, remote_ptr<void> child_addr,
                                   size_t size, const void* buf) {
  t->write_bytes_helper(child_addr, size, buf);
  t->record_local(child_addr, size, buf);
}

template <size_t N>
static void write_and_record_bytes(RecordTask* t, remote_ptr<void> child_addr,
                                   const uint8_t (&buf)[N]) {
  write_and_record_bytes(t, child_addr, N, buf);
}

template <typename T>
static void write_and_record_mem(RecordTask* t, remote_ptr<T> child_addr,
                                 const T* val, int count) {
  t->write_bytes_helper(child_addr, sizeof(*val) * count,
                        static_cast<const void*>(val));
  t->record_local(child_addr, sizeof(T) * count, val);
}

/**
 * RecordSession sets up an LD_PRELOAD environment variable with an entry
 * SYSCALLBUF_LIB_FILENAME_PADDED (and, if enabled, an LD_AUDIT environment
 * variable with an entry RTLDAUDIT_LIB_FILENAME_PADDED) which is big enough to
 * hold either the 32-bit or 64-bit preload/audit library file names.
 * Immediately after exec we enter this function, which patches the environment
 * variable value with the correct library name for the task's architecture.
 *
 * It's possible for this to fail if a tracee alters the LD_PRELOAD value
 * and then does an exec. That's just too bad. If we ever have to handle that,
 * we should modify the environment passed to the exec call. This function
 * failing isn't necessarily fatal; a tracee might not rely on the functions
 * overridden by the preload library, or might override them itself (e.g.
 * because we're recording an rr replay).
 */
#define setup_library_path(arch, env_var, soname, task) \
  setup_library_path_arch<arch>(task, env_var, soname ## _BASE, \
                                soname ## _PADDED, soname ## _32)

template <typename Arch>
static void setup_library_path_arch(RecordTask* t, const char* env_var,
                                    const char* soname_base,
                                    const char* soname_padded,
                                    const char* soname_32) {
  const char* lib_name =
      sizeof(typename Arch::unsigned_word) < sizeof(uintptr_t)
          ? soname_32
          : soname_padded;
  auto env_assignment = string(env_var) + "=";

  auto p = t->regs().sp().cast<typename Arch::unsigned_word>();
  auto argc = t->read_mem(p);
  p += 1 + argc + 1; // skip argc, argc parameters, and trailing NULL
  while (true) {
    auto envp = t->read_mem(p);
    if (!envp) {
      LOG(debug) << env_var << " not found";
      return;
    }
    string env = t->read_c_str(envp);
    if (env.find(env_assignment) != 0) {
      ++p;
      continue;
    }
    size_t lib_pos = env.find(soname_base);
    if (lib_pos == string::npos) {
      LOG(debug) << soname_base << " not found in " << env_var;
      return;
    }
    size_t next_colon = env.find(':', lib_pos);
    if (next_colon != string::npos) {
      while ((next_colon + 1 < env.length()) &&
             (env[next_colon + 1] == ':' || env[next_colon + 1] == 0)) {
        ++next_colon;
      }
      if (next_colon + 1 <
          lib_pos + sizeof(soname_padded) - 1) {
        LOG(debug) << "Insufficient space for " << lib_name
                   << " in " << env_var << " before next ':'";
        return;
      }
    }
    if (env.length() < lib_pos + sizeof(soname_padded) - 1) {
      LOG(debug) << "Insufficient space for " << lib_name
                 << " in " << env_var << " before end of string";
      return;
    }
    remote_ptr<void> dest = envp + lib_pos;
    write_and_record_mem(t, dest.cast<char>(), lib_name, strlen(soname_padded));
    return;
  }
}

template <typename Arch> static void setup_preload_library_path(RecordTask* t) {
  static_assert(sizeof(SYSCALLBUF_LIB_FILENAME_PADDED) ==
                    sizeof(SYSCALLBUF_LIB_FILENAME_32),
                "filename length mismatch");
  setup_library_path(Arch, "LD_PRELOAD", SYSCALLBUF_LIB_FILENAME, t);
}

template <typename Arch> static void setup_audit_library_path(RecordTask* t) {
  static_assert(sizeof(RTLDAUDIT_LIB_FILENAME_PADDED) ==
                    sizeof(RTLDAUDIT_LIB_FILENAME_32),
                "filename length mismatch");
  if (t->session().use_audit()) {
    setup_library_path(Arch, "LD_AUDIT", RTLDAUDIT_LIB_FILENAME, t);
  }
}

void Monkeypatcher::init_dynamic_syscall_patching(
    RecordTask* t, int syscall_patch_hook_count,
    remote_ptr<struct syscall_patch_hook> syscall_patch_hooks) {
  if (syscall_patch_hook_count && syscall_hooks.empty()) {
    syscall_hooks = t->read_mem(syscall_patch_hooks, syscall_patch_hook_count);
  }
}

template <typename Arch>
static bool patch_syscall_with_hook_arch(Monkeypatcher& patcher, RecordTask* t,
                                         const syscall_patch_hook& hook);

template <typename StubPatch>
static void substitute(uint8_t* buffer, uint64_t return_addr,
                       uint32_t trampoline_relative_addr);

template <typename ExtendedJumpPatch>
static void substitute_extended_jump(uint8_t* buffer, uint64_t patch_addr,
                                     uint64_t return_addr,
                                     uint64_t target_addr);

template <>
void substitute_extended_jump<X86SyscallStubExtendedJump>(
    uint8_t* buffer, uint64_t patch_addr, uint64_t return_addr,
    uint64_t target_addr) {
  int64_t offset =
      target_addr -
      (patch_addr + X86SyscallStubExtendedJump::trampoline_relative_addr_end);
  // An offset that appears to be > 2GB is OK here, since EIP will just
  // wrap around.
  X86SyscallStubExtendedJump::substitute(buffer, (uint32_t)return_addr,
                                         (uint32_t)offset);
}

template <>
void substitute_extended_jump<X64SyscallStubExtendedJump>(
    uint8_t* buffer, uint64_t, uint64_t return_addr, uint64_t target_addr) {
  X64SyscallStubExtendedJump::substitute(buffer, (uint32_t)return_addr,
                                         (uint32_t)(return_addr >> 32),
                                         target_addr);
}

/**
 * Allocate an extended jump in an extended jump page and return its address.
 * The resulting address must be within 2G of from_end, and the instruction
 * there must jump to to_start.
 */
template <typename ExtendedJumpPatch>
static remote_ptr<uint8_t> allocate_extended_jump(
    RecordTask* t, vector<Monkeypatcher::ExtendedJumpPage>& pages,
    remote_ptr<uint8_t> from_end) {
  Monkeypatcher::ExtendedJumpPage* page = nullptr;
  for (auto& p : pages) {
    remote_ptr<uint8_t> page_jump_start = p.addr + p.allocated;
    int64_t offset = page_jump_start - from_end;
    if ((int32_t)offset == offset &&
        p.allocated + ExtendedJumpPatch::size <= page_size()) {
      page = &p;
      break;
    }
  }

  if (!page) {
    // We're looking for a gap of three pages --- one page to allocate and
    // a page on each side as a guard page.
    uint32_t required_space = 3 * page_size();
    remote_ptr<void> free_mem =
        t->vm()->find_free_memory(required_space,
                                  // Find free space after the patch site.
                                  t->vm()->mapping_of(from_end).map.start());

    remote_ptr<uint8_t> addr = (free_mem + page_size()).cast<uint8_t>();
    int64_t offset = addr - from_end;
    if ((int32_t)offset != offset) {
      LOG(debug) << "Can't find space close enough for the jump";
      return nullptr;
    }

    {
      AutoRemoteSyscalls remote(t);
      int prot = PROT_READ | PROT_EXEC;
      int flags = MAP_ANONYMOUS | MAP_FIXED | MAP_PRIVATE;
      remote.infallible_mmap_syscall(addr, page_size(), prot, flags, -1, 0);
      KernelMapping recorded(addr, addr + page_size(), string(),
                             KernelMapping::NO_DEVICE, KernelMapping::NO_INODE,
                             prot, flags);
      t->vm()->map(t, addr, page_size(), prot, flags, 0, string(),
                   KernelMapping::NO_DEVICE, KernelMapping::NO_INODE, nullptr,
                   &recorded);
      t->vm()->mapping_flags_of(addr) |= AddressSpace::Mapping::IS_PATCH_STUBS;
      t->trace_writer().write_mapped_region(t, recorded, recorded.fake_stat(),
                                            recorded.fsname(),
                                            vector<TraceRemoteFd>(),
                                            TraceWriter::PATCH_MAPPING);
    }

    pages.push_back(Monkeypatcher::ExtendedJumpPage(addr));
    page = &pages.back();
  }

  remote_ptr<uint8_t> jump_addr = page->addr + page->allocated;
  page->allocated += ExtendedJumpPatch::size;
  return jump_addr;
}

bool Monkeypatcher::is_jump_stub_instruction(remote_code_ptr ip) {
  remote_ptr<uint8_t> pp = ip.to_data_ptr<uint8_t>();
  auto it = syscallbuf_stubs.upper_bound(pp);
  if (it == syscallbuf_stubs.begin()) {
    return false;
  }
  --it;
  return it->first <= pp && pp < it->first + it->second.size;
}

/**
 * Some functions make system calls while storing local variables in memory
 * below the stack pointer. We need to decrement the stack pointer by
 * some "safety zone" amount to get clear of those variables before we make
 * a call instruction. So, we allocate a stub per patched callsite, and jump
 * from the callsite to the stub. The stub decrements the stack pointer,
 * calls the appropriate syscall hook function, reincrements the stack pointer,
 * and jumps back to immediately after the patched callsite.
 *
 * It's important that gdb stack traces work while a thread is stopped in the
 * syscallbuf code. To ensure that the above manipulations don't foil gdb's
 * stack walking code, we add CFI data to all the stubs. To ease that, the
 * stubs are written in assembly and linked into the preload library.
 *
 * On x86-64 with ASLR, we need to be able to patch a call to a stub from
 * sites more than 2^31 bytes away. We only have space for a 5-byte jump
 * instruction. So, we allocate "extender pages" --- pages of memory within
 * 2GB of the patch site, that contain the stub code. We don't really need this
 * on x86, but we do it there too for consistency.
 *
 */
template <typename JumpPatch, typename ExtendedJumpPatch>
static bool patch_syscall_with_hook_x86ish(Monkeypatcher& patcher,
                                           RecordTask* t,
                                           const syscall_patch_hook& hook) {
  uint8_t jump_patch[JumpPatch::size];
  // We're patching in a relative jump, so we need to compute the offset from
  // the end of the jump to our actual destination.
  auto jump_patch_start = t->regs().ip().to_data_ptr<uint8_t>();
  auto jump_patch_end = jump_patch_start + sizeof(jump_patch);
  auto return_addr = t->regs().ip().to_data_ptr<uint8_t>().as_int() +
                     syscall_instruction_length(x86_64) +
                     hook.patch_region_length;
  if ((hook.flags & PATCH_SYSCALL_INSTRUCTION_IS_LAST)) {
    auto adjust = hook.patch_region_length + syscall_instruction_length(x86_64);
    jump_patch_start -= adjust;
    jump_patch_end -= adjust;
    return_addr -= adjust;
  }

  remote_ptr<uint8_t> extended_jump_start =
      allocate_extended_jump<ExtendedJumpPatch>(
          t, patcher.extended_jump_pages, jump_patch_end);
  if (extended_jump_start.is_null()) {
    return false;
  }

  uint8_t stub_patch[ExtendedJumpPatch::size];
  substitute_extended_jump<ExtendedJumpPatch>(stub_patch,
                                              extended_jump_start.as_int(),
                                              return_addr,
                                              hook.hook_address);
  write_and_record_bytes(t, extended_jump_start, stub_patch);

  patcher.syscallbuf_stubs[extended_jump_start] = { &hook, ExtendedJumpPatch::size };

  intptr_t jump_offset = extended_jump_start - jump_patch_end;
  int32_t jump_offset32 = (int32_t)jump_offset;
  ASSERT(t, jump_offset32 == jump_offset)
      << "allocate_extended_jump didn't work";

  JumpPatch::substitute(jump_patch, jump_offset32);
  write_and_record_bytes(t, jump_patch_start, jump_patch);

  // pad with NOPs to the next instruction
  static const uint8_t NOP = 0x90;
  DEBUG_ASSERT(syscall_instruction_length(x86_64) ==
               syscall_instruction_length(x86));
  size_t nops_bufsize = syscall_instruction_length(x86_64) +
                        hook.patch_region_length - sizeof(jump_patch);
  std::unique_ptr<uint8_t[]> nops(new uint8_t[nops_bufsize]);
  memset(nops.get(), NOP, nops_bufsize);
  write_and_record_mem(t, jump_patch_start + sizeof(jump_patch), nops.get(),
                       nops_bufsize);

  return true;
}

template <>
bool patch_syscall_with_hook_arch<X86Arch>(Monkeypatcher& patcher,
                                           RecordTask* t,
                                           const syscall_patch_hook& hook) {
  return patch_syscall_with_hook_x86ish<X86SysenterVsyscallSyscallHook,
                                        X86SyscallStubExtendedJump>(patcher, t,
                                                                    hook);
}

template <>
bool patch_syscall_with_hook_arch<X64Arch>(Monkeypatcher& patcher,
                                           RecordTask* t,
                                           const syscall_patch_hook& hook) {
  return patch_syscall_with_hook_x86ish<X64JumpMonkeypatch,
                                        X64SyscallStubExtendedJump>(patcher, t,
                                                                    hook);
}

template <>
bool patch_syscall_with_hook_arch<ARM64Arch>(Monkeypatcher&,
                                             RecordTask*,
                                             const syscall_patch_hook&) {
  FATAL() << "Unimplemented";
  return false;
}


static bool patch_syscall_with_hook(Monkeypatcher& patcher, RecordTask* t,
                                    const syscall_patch_hook& hook) {
  RR_ARCH_FUNCTION(patch_syscall_with_hook_arch, t->arch(), patcher, t, hook);
}

template <typename ExtendedJumpPatch>
static bool match_extended_jump_patch(uint8_t patch[],
 uint64_t *return_addr);

template <>
bool match_extended_jump_patch<X64SyscallStubExtendedJump>(
      uint8_t patch[], uint64_t *return_addr) {
  uint32_t return_addr_lo, return_addr_hi;
  uint64_t jmp_target;
  if (!X64SyscallStubExtendedJump::match(patch, &return_addr_lo, &return_addr_hi, &jmp_target)) {
    return false;
  }
  *return_addr = return_addr_lo | (((uint64_t)return_addr_hi) << 32);
  return true;
}

template <>
bool match_extended_jump_patch<X86SyscallStubExtendedJump>(
      uint8_t patch[], uint64_t *return_addr) {
  uint32_t return_addr_32, jmp_target_relative;
  if (!X86SyscallStubExtendedJump::match(patch, &return_addr_32, &jmp_target_relative)) {
    return false;
  }
  *return_addr = return_addr_32;
  return true;
}

template <typename ReplacementPatch>
static void substitute_replacement_patch(uint8_t *buffer, uint64_t patch_addr,
                                     uint64_t jmp_target);

template <>
void substitute_replacement_patch<X64SyscallStubRestore>(uint8_t *buffer, uint64_t patch_addr,
                                  uint64_t jmp_target) {
  (void)patch_addr;
  X64SyscallStubRestore::substitute(buffer, jmp_target);
}

template <>
void substitute_replacement_patch<X86SyscallStubRestore>(uint8_t *buffer, uint64_t patch_addr,
                                  uint64_t jmp_target) {
  int64_t offset =
      jmp_target -
      (patch_addr + X86SyscallStubRestore::trampoline_relative_addr_end);
  // An offset that appears to be > 2GB is OK here, since EIP will just
  // wrap around.
  X86SyscallStubRestore::substitute(buffer, (uint32_t)offset);
}

template <typename ExtendedJumpPatch, typename ReplacementPatch>
static void unpatch_extended_jumps(Monkeypatcher& patcher,
                                   Task* t) {
  for (auto patch : patcher.syscallbuf_stubs) {
    const syscall_patch_hook &hook = *patch.second.hook;
    ASSERT(t, patch.second.size == ExtendedJumpPatch::size);
    uint8_t bytes[ExtendedJumpPatch::size];
    t->read_bytes_helper(patch.first, sizeof(bytes), bytes);
    uint64_t return_addr;
    if (!match_extended_jump_patch<ExtendedJumpPatch>(bytes, &return_addr)) {
      ASSERT(t, false) << "Failed to match extended jump patch at " << patch.first;
      return;
    }

    std::vector<uint8_t> syscall = rr::syscall_instruction(t->arch());

    // Replace with
    //  extended_jump:
    //    <syscall> (unless PATCH_SYSCALL_INSTRUCTION_IS_LAST)
    //    <original bytes>
    //    <syscall> (if PATCH_SYSCALL_INSTRUCTION_IS_LAST)
    //    jmp *(return_addr)
    // As long as there are not relative branches or anything, this should
    // always be correct.
    ASSERT(t, hook.patch_region_length + ReplacementPatch::size + syscall.size() <
              ExtendedJumpPatch::size);
    uint8_t *ptr = bytes;
    if (!(hook.flags & PATCH_SYSCALL_INSTRUCTION_IS_LAST)) {
      memcpy(ptr, syscall.data(), syscall.size());
      ptr += syscall.size();
    }
    memcpy(ptr, hook.patch_region_bytes, hook.patch_region_length);
    ptr += hook.patch_region_length;
    if (hook.flags & PATCH_SYSCALL_INSTRUCTION_IS_LAST) {
      memcpy(ptr, syscall.data(), syscall.size());
      ptr += syscall.size();
    }
    substitute_replacement_patch<ReplacementPatch>(ptr,
      patch.first.as_int()+(ptr-bytes), return_addr);
    t->write_bytes_helper(patch.first, sizeof(bytes), bytes);
  }
}

template <typename Arch>
static void unpatch_syscalls_arch(Monkeypatcher &patcher, Task *t);

template <>
void unpatch_syscalls_arch<X86Arch>(Monkeypatcher &patcher, Task *t) {
  return unpatch_extended_jumps<X86SyscallStubExtendedJump,
                                X86SyscallStubRestore>(patcher, t);
}

template <>
void unpatch_syscalls_arch<X64Arch>(Monkeypatcher &patcher, Task *t) {
  return unpatch_extended_jumps<X64SyscallStubExtendedJump,
                                X64SyscallStubRestore>(patcher, t);
}

template <>
void unpatch_syscalls_arch<ARM64Arch>(Monkeypatcher &patcher, Task *t) {
  (void)patcher; (void)t;
  FATAL() << "Unimplemented";
}

void Monkeypatcher::unpatch_syscalls_in(Task *t) {
  RR_ARCH_FUNCTION(unpatch_syscalls_arch, t->arch(), *this, t);
}

static string bytes_to_string(uint8_t* bytes, size_t size) {
  stringstream ss;
  for (size_t i = 0; i < size; ++i) {
    if (i > 0) {
      ss << ' ';
    }
    ss << HEX(bytes[i]);
  }
  return ss.str();
}

static bool task_safe_for_syscall_patching(RecordTask* t, remote_code_ptr start,
                                           remote_code_ptr end) {
  if (!t->is_running()) {
    remote_code_ptr ip = t->ip();
    if (start <= ip && ip < end) {
      return false;
    }
  }
  for (auto& e : t->pending_events) {
    if (e.is_syscall_event()) {
      remote_code_ptr ip = e.Syscall().regs.ip();
      if (start <= ip && ip < end) {
        return false;
      }
    }
  }
  return true;
}

static bool safe_for_syscall_patching(remote_code_ptr start,
                                      remote_code_ptr end,
                                      RecordTask* exclude) {
  for (auto& p : exclude->session().tasks()) {
    RecordTask* rt = static_cast<RecordTask*>(p.second);
    if (rt != exclude && !task_safe_for_syscall_patching(rt, start, end)) {
      return false;
    }
  }
  return true;
}

bool Monkeypatcher::try_patch_vsyscall_caller(RecordTask* t, remote_code_ptr ret_addr)
{
  uint8_t bytes[X64VSyscallEntry::size];
  remote_ptr<uint8_t> patch_start = ret_addr.to_data_ptr<uint8_t>() - sizeof(bytes);
  size_t bytes_count = t->read_bytes_fallible(patch_start, sizeof(bytes), bytes);
  if (bytes_count < sizeof(bytes)) {
    return false;
  }
  uint32_t target_addr = 0;
  if (!X64VSyscallEntry::match(bytes, &target_addr)) {
    return false;
  }
  uint64_t target_addr_sext = (uint64_t)(int32_t)target_addr;
  int syscallno = 0;
  switch (target_addr_sext) {
    case 0xffffffffff600000:
      syscallno = X64Arch::gettimeofday;
      break;
    case 0xffffffffff600400:
      syscallno = X64Arch::time;
      break;
    case 0xffffffffff600800:
      syscallno = X64Arch::getcpu;
      break;
    default:
      return false;
  }
  X64VSyscallReplacement::substitute(bytes, syscallno);
  write_and_record_bytes(t, patch_start, bytes);
  LOG(debug) << "monkeypatched vsyscall caller at " << patch_start;
  return true;
}

// Syscalls can be patched either on entry or exit. For most syscall
// instruction code patterns we can steal bytes after the syscall instruction
// and thus we patch on entry, but some patterns require using bytes from
// before the syscall instruction itself and thus can only be patched on exit.
// The `entering_syscall` flag tells us whether or not we're at syscall entry.
// If we are, and we find a pattern that can only be patched at exit, we'll
// set a flag on the RecordTask telling it to try again after syscall exit.
bool Monkeypatcher::try_patch_syscall(RecordTask* t, bool entering_syscall) {
  if (syscall_hooks.empty()) {
    // Syscall hooks not set up yet. Don't spew warnings, and don't
    // fill tried_to_patch_syscall_addresses with addresses that we might be
    // able to patch later.
    return false;
  }
  if (t->emulated_ptracer) {
    // Syscall patching can confuse ptracers, which may be surprised to see
    // a syscall instruction at the current IP but then when running
    // forwards, that the syscall occurs deep in the preload library instead.
    return false;
  }
  if (t->is_in_traced_syscall()) {
    // Never try to patch the traced-syscall in our preload library!
    return false;
  }

  Registers r = t->regs();
  remote_code_ptr ip = r.ip();
  if (tried_to_patch_syscall_addresses.count(ip)) {
    return false;
  }

  // We could examine the current syscall number and if it's not one that
  // we support syscall buffering for, refuse to patch the syscall instruction.
  // This would, on the face of it, reduce overhead since patching the
  // instruction just means a useless trip through the syscall buffering logic.
  // However, it actually wouldn't help much since we'd still do a switch
  // on the syscall number in this function instead, and due to context
  // switching costs any overhead saved would be insignificant.
  // Also, implementing that would require keeping a buffered-syscalls
  // list in sync with the preload code, which is unnecessary complexity.

  SupportedArch arch;
  if (!get_syscall_instruction_arch(
          t, ip.decrement_by_syscall_insn_length(t->arch()), &arch) ||
      arch != t->arch()) {
    LOG(debug) << "Declining to patch cross-architecture syscall at " << ip;
    tried_to_patch_syscall_addresses.insert(ip);
    return false;
  }

  static const intptr_t MAXIMUM_LOOKBACK = 6;
  uint8_t bytes[256 + MAXIMUM_LOOKBACK];
  size_t bytes_count = t->read_bytes_fallible(
      ip.to_data_ptr<uint8_t>() - MAXIMUM_LOOKBACK, sizeof(bytes), bytes);
  if (bytes_count < MAXIMUM_LOOKBACK) {
    LOG(debug) << "Declining to patch syscall at " << ip << " for lack of lookback";
    tried_to_patch_syscall_addresses.insert(ip);
    return false;
  }
  size_t following_bytes_count = bytes_count - MAXIMUM_LOOKBACK;
  uint8_t* following_bytes = &bytes[MAXIMUM_LOOKBACK];

  intptr_t syscallno = r.original_syscallno();
  bool success = false;
  for (auto& hook : syscall_hooks) {
    bool matches_hook = false;
    if ((!(hook.flags & PATCH_SYSCALL_INSTRUCTION_IS_LAST) &&
         following_bytes_count >= hook.patch_region_length &&
         memcmp(following_bytes, hook.patch_region_bytes,
                hook.patch_region_length) == 0)) {
      matches_hook = true;
    } else if ((hook.flags & PATCH_SYSCALL_INSTRUCTION_IS_LAST) &&
               bytes_count >=
                   hook.patch_region_length +
                       (size_t)rr::syscall_instruction_length(arch) &&
               memcmp(bytes + MAXIMUM_LOOKBACK - rr::syscall_instruction_length(arch) - hook.patch_region_length,
                      hook.patch_region_bytes,
                      hook.patch_region_length) == 0) {
      if (entering_syscall) {
        // A patch that uses bytes before the syscall can't be done when
        // entering the syscall, it must be done when exiting. So set a flag on
        // the Task that tells us to come back later.
        t->retry_syscall_patching = true;
        LOG(debug) << "Deferring syscall patching at " << ip << " in " << t
                   << " until syscall exit.";
        return false;
      }
      matches_hook = true;
    }

    if (!matches_hook) {
      continue;
    }

    // Search for a following short-jump instruction that targets an
    // instruction
    // after the syscall. False positives are OK.
    // glibc-2.23.1-8.fc24.x86_64's __clock_nanosleep needs this.
    bool found_potential_interfering_branch = false;
    size_t max_bytes, warn_offset;
    uint8_t* search_bytes;
    if (hook.flags & PATCH_SYSCALL_INSTRUCTION_IS_LAST) {
      max_bytes = bytes_count;
      search_bytes = bytes;
      warn_offset = MAXIMUM_LOOKBACK;
    } else {
      max_bytes = following_bytes_count;
      search_bytes = following_bytes;
      warn_offset = 0;
    }

    for (size_t i = 0; i + 2 <= max_bytes; ++i) {
      uint8_t b = search_bytes[i];
      // Check for short conditional or unconditional jump
      if (b == 0xeb || (b >= 0x70 && b < 0x80)) {
        int offset = i + 2 + (int8_t)search_bytes[i + 1];
        if ((hook.flags & PATCH_IS_MULTIPLE_INSTRUCTIONS)
                ? (offset >= 0 && offset < hook.patch_region_length)
                : offset == 0) {
          LOG(debug) << "Found potential interfering branch at "
                      << ip.to_data_ptr<uint8_t>() + i - warn_offset;
          // We can't patch this because it would jump straight back into
          // the middle of our patch code.
          found_potential_interfering_branch = true;
        }
      }
    }

    if (!found_potential_interfering_branch) {
      remote_code_ptr start_range, end_range;
      if (hook.flags & PATCH_SYSCALL_INSTRUCTION_IS_LAST) {
        start_range = ip.decrement_by_syscall_insn_length(arch) -
                      hook.patch_region_length;
        end_range = ip;
      } else {
        start_range = ip.decrement_by_syscall_insn_length(arch);
        end_range = ip + hook.patch_region_length;
      }
      if (!safe_for_syscall_patching(start_range, end_range, t)) {
        LOG(debug)
            << "Temporarily declining to patch syscall at " << ip
            << " because a different task has its ip in the patched range";
        return false;
      }

      // Get out of executing the current syscall before we patch it.
      if (entering_syscall && !t->exit_syscall_and_prepare_restart()) {
        return false;
      }

      LOG(debug) << "Patching syscall at " << ip << " syscall "
                 << syscall_name(syscallno, t->arch()) << " tid " << t->tid
                 << " bytes "
                 << bytes_to_string(
                        following_bytes,
                        min(bytes_count,
                            sizeof(syscall_patch_hook::patch_region_bytes)));

      success = patch_syscall_with_hook(*this, t, hook);
      break;
    }
  }

  if (!success) {
    LOG(debug) << "Failed to patch syscall at " << ip << " syscall "
               << syscall_name(syscallno, t->arch()) << " tid " << t->tid
               << " bytes "
               << bytes_to_string(
                      following_bytes,
                      min(bytes_count,
                          sizeof(syscall_patch_hook::patch_region_bytes)));
    tried_to_patch_syscall_addresses.insert(ip);
    return false;
  }

  return true;
}

// VDSOs are filled with overhead critical functions related to getting the
// time and current CPU.  We need to ensure that these syscalls get redirected
// into actual trap-into-the-kernel syscalls so rr can intercept them.

template <typename Arch>
static void patch_after_exec_arch(RecordTask* t, Monkeypatcher& patcher);

template <typename Arch>
static void patch_at_preload_init_arch(RecordTask* t, Monkeypatcher& patcher);

template <>
void patch_after_exec_arch<X86Arch>(RecordTask* t, Monkeypatcher& patcher) {
  (void)patcher;
  setup_preload_library_path<X86Arch>(t);
  setup_audit_library_path<X86Arch>(t);

  if (!t->vm()->has_vdso()) {
    patch_auxv_vdso(t, AT_SYSINFO_EHDR, AT_IGNORE);
  } else {
    size_t librrpage_base = RR_PAGE_ADDR - AddressSpace::RRPAGE_RECORD_PAGE_OFFSET*RR_PAGE_SIZE;
    patch_auxv_vdso(t, AT_SYSINFO_EHDR, librrpage_base);
    patch_auxv_vdso(t, X86Arch::RR_AT_SYSINFO, librrpage_base +
      AddressSpace::RRVDSO_PAGE_OFFSET*RR_PAGE_SIZE);
  }
}

// Monkeypatch x86 vsyscall hook only after the preload library
// has initialized. The vsyscall hook expects to be able to use the syscallbuf.
// Before the preload library has initialized, the regular vsyscall code
// will trigger ptrace traps and be handled correctly by rr.
template <>
void patch_at_preload_init_arch<X86Arch>(RecordTask* t,
                                         Monkeypatcher& patcher) {
  auto params = t->read_mem(
      remote_ptr<rrcall_init_preload_params<X86Arch>>(t->regs().arg1()));
  if (!params.syscallbuf_enabled) {
    return;
  }

  patcher.init_dynamic_syscall_patching(t, params.syscall_patch_hook_count,
                                        params.syscall_patch_hooks);
}

template <>
void patch_after_exec_arch<X64Arch>(RecordTask* t, Monkeypatcher& patcher) {
  setup_preload_library_path<X64Arch>(t);
  setup_audit_library_path<X64Arch>(t);

  for (const auto& m : t->vm()->maps()) {
    auto& km = m.map;
    patcher.patch_after_mmap(t, km.start(), km.size(),
                             km.file_offset_bytes()/page_size(), -1,
                             Monkeypatcher::MMAP_EXEC);
  }

  if (!t->vm()->has_vdso()) {
    patch_auxv_vdso(t, AT_SYSINFO_EHDR, AT_IGNORE);
  } else {
    size_t librrpage_base = RR_PAGE_ADDR - AddressSpace::RRPAGE_RECORD_PAGE_OFFSET*RR_PAGE_SIZE;
    patch_auxv_vdso(t, AT_SYSINFO_EHDR, librrpage_base);
  }
}

template <>
void patch_after_exec_arch<ARM64Arch>(RecordTask* t, Monkeypatcher& patcher) {
  setup_preload_library_path<ARM64Arch>(t);
  setup_audit_library_path<ARM64Arch>(t);

  for (const auto& m : t->vm()->maps()) {
    auto& km = m.map;
    patcher.patch_after_mmap(t, km.start(), km.size(),
                             km.file_offset_bytes()/page_size(), -1,
                             Monkeypatcher::MMAP_EXEC);
  }

  if (!t->vm()->has_vdso()) {
    patch_auxv_vdso(t, AT_SYSINFO_EHDR, AT_IGNORE);
  } else {
    size_t librrpage_base = RR_PAGE_ADDR - AddressSpace::RRPAGE_RECORD_PAGE_OFFSET*RR_PAGE_SIZE;
    patch_auxv_vdso(t, AT_SYSINFO_EHDR, librrpage_base);
  }
}

template <>
void patch_at_preload_init_arch<X64Arch>(RecordTask* t,
                                         Monkeypatcher& patcher) {
  auto params = t->read_mem(
      remote_ptr<rrcall_init_preload_params<X64Arch>>(t->regs().arg1()));
  if (!params.syscallbuf_enabled) {
    return;
  }

  patcher.init_dynamic_syscall_patching(t, params.syscall_patch_hook_count,
                                        params.syscall_patch_hooks);
}

template <>
void patch_at_preload_init_arch<ARM64Arch>(RecordTask* t,
                                           Monkeypatcher&) {
  auto params = t->read_mem(
      remote_ptr<rrcall_init_preload_params<ARM64Arch>>(t->regs().arg1()));
  if (!params.syscallbuf_enabled) {
    return;
  }
  FATAL() << "Unimplemented";
}

void Monkeypatcher::patch_after_exec(RecordTask* t) {
  ASSERT(t, 1 == t->vm()->task_set().size())
      << "Can't have multiple threads immediately after exec!";

  RR_ARCH_FUNCTION(patch_after_exec_arch, t->arch(), t, *this);
}

void Monkeypatcher::patch_at_preload_init(RecordTask* t) {
  // NB: the tracee can't be interrupted with a signal while
  // we're processing the rrcall, because it's masked off all
  // signals.
  RR_ARCH_FUNCTION(patch_at_preload_init_arch, t->arch(), t, *this);
}

static remote_ptr<void> resolve_address(ElfReader& reader, uintptr_t elf_addr,
                                        remote_ptr<void> map_start,
                                        size_t map_size,
                                        size_t map_offset_pages) {
  uintptr_t file_offset;
  if (!reader.addr_to_offset(elf_addr, file_offset)) {
    LOG(warn) << "ELF address " << HEX(elf_addr) << " not in file";
  }
  uintptr_t map_offset = uintptr_t(map_offset_pages) * page_size();
  if (file_offset < map_offset || file_offset + 32 > map_offset + map_size) {
    // The value(s) to be set are outside the mapped range. This happens
    // because code and data can be mapped in separate, partial mmaps in which
    // case some symbols will be outside the mapped range.
    return nullptr;
  }
  return map_start + uintptr_t(file_offset - map_offset);
}

static void set_and_record_bytes(RecordTask* t, ElfReader& reader,
                                 uintptr_t elf_addr, const void* bytes,
                                 size_t size, remote_ptr<void> map_start,
                                 size_t map_size, size_t map_offset_pages) {
  remote_ptr<void> addr =
    resolve_address(reader, elf_addr, map_start, map_size, map_offset_pages);
  if (!addr) {
    return;
  }
  bool ok = true;
  t->write_bytes_helper(addr, size, bytes, &ok);
  // Writing can fail when the value appears to be in the mapped range, but it
  // actually is beyond the file length.
  if (ok) {
    t->record_local(addr, size, bytes);
  }
}

/**
 * Patch _dl_runtime_resolve_(fxsave,xsave,xsavec) to clear "FDP Data Pointer"
 * register so that CPU-specific behaviors involving that register don't leak
 * into stack memory.
 */
static void patch_dl_runtime_resolve(Monkeypatcher& patcher,
                                     RecordTask* t, ElfReader& reader,
                                     uintptr_t elf_addr,
                                     remote_ptr<void> map_start,
                                     size_t map_size,
                                     size_t map_offset_pages) {
  if (t->arch() != x86_64) {
    return;
  }
  remote_ptr<void> addr =
    resolve_address(reader, elf_addr, map_start, map_size, map_offset_pages);
  if (!addr) {
    return;
  }

  uint8_t impl[X64DLRuntimeResolve::size + X64EndBr::size];
  uint8_t *impl_start = impl;
  t->read_bytes(addr, impl);
  if (X64EndBr::match(impl) || X86EndBr::match(impl)) {
    assert(X64EndBr::size == X86EndBr::size);
    LOG(debug) << "Starts with endbr, skipping";
    addr += X64EndBr::size;
    impl_start += X64EndBr::size;
  }

  if (!X64DLRuntimeResolve::match(impl_start) &&
      !X64DLRuntimeResolve2::match(impl_start)) {
    LOG(warn) << "_dl_runtime_resolve implementation doesn't look right";
    return;
  }

  uint8_t call_patch[X64CallMonkeypatch::size];
  // We're patching in a relative call, so we need to compute the offset from
  // the end of the call to our actual destination.
  auto call_patch_start = addr.cast<uint8_t>();
  auto call_patch_end = call_patch_start + sizeof(call_patch);

  remote_ptr<uint8_t> extended_call_start =
      allocate_extended_jump<X64DLRuntimeResolvePrelude>(
          t, patcher.extended_jump_pages, call_patch_end);
  if (extended_call_start.is_null()) {
    return;
  }
  uint8_t stub_patch[X64DLRuntimeResolvePrelude::size];
  X64DLRuntimeResolvePrelude::substitute(stub_patch);
  write_and_record_bytes(t, extended_call_start, stub_patch);

  intptr_t call_offset = extended_call_start - call_patch_end;
  int32_t call_offset32 = (int32_t)call_offset;
  ASSERT(t, call_offset32 == call_offset)
      << "allocate_extended_jump didn't work";
  X64CallMonkeypatch::substitute(call_patch, call_offset32);
  write_and_record_bytes(t, call_patch_start, call_patch);

  // pad with NOPs to the next instruction
  static const uint8_t NOP = 0x90;
  uint8_t nops[X64DLRuntimeResolve::size - sizeof(call_patch)];
  memset(nops, NOP, sizeof(nops));
  write_and_record_mem(t, call_patch_start + sizeof(call_patch), nops,
                       sizeof(nops));
}

static bool file_may_need_instrumentation(const AddressSpace::Mapping& map) {
  size_t file_part = map.map.fsname().rfind('/');
  if (file_part == string::npos) {
    file_part = 0;
  } else {
    ++file_part;
  }
  const string& fsname = map.map.fsname();
  return fsname.find("libpthread", file_part) != string::npos ||
    fsname.find("ld", file_part) != string::npos;
}

void Monkeypatcher::patch_after_mmap(RecordTask* t, remote_ptr<void> start,
                                     size_t size, size_t offset_pages,
                                     int child_fd, MmapMode mode) {
  const auto& map = t->vm()->mapping_of(start);
  if (file_may_need_instrumentation(map) &&
      (t->arch() == x86 || t->arch() == x86_64)) {
    ScopedFd open_fd;
    if (child_fd >= 0) {
      open_fd = t->open_fd(child_fd, O_RDONLY);
      ASSERT(t, open_fd.is_open()) << "Failed to open child fd " << child_fd;
    } else {
      char buf[100];
      sprintf(buf, "/proc/%d/map_files/%llx-%llx", t->tid,
              (long long)start.as_int(), (long long)start.as_int() + size);
      // Reading these directly requires CAP_SYS_ADMIN, so open the link target
      // instead.
      char link[PATH_MAX];
      int ret = readlink(buf, link, sizeof(link) - 1);
      if (ret < 0) {
        return;
      }
      link[ret] = 0;
      open_fd = ScopedFd(link, O_RDONLY);
      if (!open_fd.is_open()) {
        return;
      }
    }
    ElfFileReader reader(open_fd, t->arch());
    // Check for symbols first in the library itself, regardless of whether
    // there is a debuglink.  For example, on Fedora 26, the .symtab and
    // .strtab sections are stripped from the debuginfo file for
    // libpthread.so.
    SymbolTable syms = reader.read_symbols(".symtab", ".strtab");
    if (syms.size() == 0) {
      ScopedFd debug_fd = reader.open_debug_file(map.map.fsname());
      if (debug_fd.is_open()) {
        ElfFileReader debug_reader(debug_fd, t->arch());
        syms = debug_reader.read_symbols(".symtab", ".strtab");
      }
    }
    for (size_t i = 0; i < syms.size(); ++i) {
      if (syms.is_name(i, "__elision_aconf")) {
        static const int zero = 0;
        // Setting __elision_aconf.retry_try_xbegin to zero means that
        // pthread rwlocks don't try to use elision at all. See ELIDE_LOCK
        // in glibc's elide.h.
        set_and_record_bytes(t, reader, syms.addr(i) + 8, &zero, sizeof(zero),
                             start, size, offset_pages);
      }
      if (syms.is_name(i, "elision_init")) {
        // Make elision_init return without doing anything. This means
        // the __elision_available and __pthread_force_elision flags will
        // remain zero, disabling elision for mutexes. See glibc's
        // elision-conf.c.
        static const uint8_t ret = 0xC3;
        set_and_record_bytes(t, reader, syms.addr(i), &ret, sizeof(ret), start,
                             size, offset_pages);
      }
      // The following operations can only be applied once because after the
      // patch is applied the code no longer matches the expected template.
      // For replaying a replay to work, we need to only apply these changes
      // during a real exec, not during the mmap operations performed when rr
      // replays an exec.
      if (mode == MMAP_EXEC &&
          (syms.is_name(i, "_dl_runtime_resolve_fxsave") ||
           syms.is_name(i, "_dl_runtime_resolve_xsave") ||
           syms.is_name(i, "_dl_runtime_resolve_xsavec"))) {
        patch_dl_runtime_resolve(*this, t, reader, syms.addr(i), start, size,
                                 offset_pages);
      }
    }
  }
}

} // namespace rr
