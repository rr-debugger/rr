/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

//#define DEBUGTAG "Monkeypatcher"

#include "Monkeypatcher.h"

#include "AddressSpace.h"
#include "elf.h"
#include "kernel_abi.h"
#include "kernel_metadata.h"
#include "log.h"
#include "ReplaySession.h"
#include "ScopedFd.h"
#include "task.h"

using namespace rr;
using namespace std;

#include "AssemblyTemplates.generated"

/**
 * RecordSession sets up an LD_PRELOAD environment variable with an entry
 * SYSCALLBUF_LIB_FILENAME_PADDED which is big enough to hold either the
 * 32-bit or 64-bit preload library file names. Immediately after exec we
 * enter this function, which patches the environment variable value with
 * the correct library name for the task's architecture.
 *
 * It's possible for this to fail if a tracee alters the LD_PRELOAD value
 * and then does an exec. That's just too bad. If we ever have to handle that,
 * we should modify the environment passed to the exec call.
 */
template <typename Arch> static void setup_preload_library_path(Task* t) {
  static_assert(sizeof(SYSCALLBUF_LIB_FILENAME_PADDED) ==
                    sizeof(SYSCALLBUF_LIB_FILENAME_32),
                "filename length mismatch");

  const char* lib_name =
      sizeof(typename Arch::unsigned_word) < sizeof(uintptr_t)
          ? SYSCALLBUF_LIB_FILENAME_32
          : SYSCALLBUF_LIB_FILENAME_PADDED;

  auto p = t->regs().sp().cast<typename Arch::unsigned_word>();
  auto argc = t->read_mem(p);
  p += 1 + argc + 1; // skip argc, argc parameters, and trailing NULL
  while (true) {
    auto envp = t->read_mem(p);
    if (!envp) {
      ASSERT(t, false) << "LD_PRELOAD not found";
      return;
    }
    string env = t->read_c_str(envp);
    if (env.find("LD_PRELOAD=") != 0) {
      ++p;
      continue;
    }
    size_t lib_pos = env.find(SYSCALLBUF_LIB_FILENAME_BASE);
    if (lib_pos == string::npos) {
      ASSERT(t, false) << SYSCALLBUF_LIB_FILENAME_BASE
          " not found in LD_PRELOAD";
      return;
    }
    size_t next_colon = env.find(':', lib_pos);
    if (next_colon != string::npos) {
      while (env[next_colon + 1] == ':' || env[next_colon + 1] == 0) {
        ++next_colon;
      }
      if (next_colon < lib_pos + sizeof(SYSCALLBUF_LIB_FILENAME_PADDED) - 1) {
        ASSERT(t, false) << "Insufficient space for " << lib_name
                         << " in LD_PRELOAD before next ':'";
        return;
      }
    }
    if (env.length() < lib_pos + sizeof(SYSCALLBUF_LIB_FILENAME_PADDED) - 1) {
      ASSERT(t, false) << "Insufficient space for " << lib_name
                       << " in LD_PRELOAD before end of string";
      return;
    }
    remote_ptr<void> dest = envp + lib_pos;
    t->write_mem(dest.cast<char>(), lib_name,
                 sizeof(SYSCALLBUF_LIB_FILENAME_PADDED) - 1);
    return;
  }
}

void Monkeypatcher::init_dynamic_syscall_patching(
    Task* t, int syscall_patch_hook_count,
    remote_ptr<struct syscall_patch_hook> syscall_patch_hooks,
    remote_ptr<void> stub_buffer, remote_ptr<void> stub_buffer_end) {
  if (syscall_patch_hook_count) {
    syscall_hooks = t->read_mem(syscall_patch_hooks, syscall_patch_hook_count);
  }
  this->stub_buffer = stub_buffer;
  this->stub_buffer_end = stub_buffer_end;
}

template <typename Arch>
static bool patch_syscall_with_hook_arch(Monkeypatcher& patcher, Task* t,
                                         const syscall_patch_hook& hook);

remote_ptr<uint8_t> Monkeypatcher::allocate_stub(Task* t, size_t bytes) {
  if (!stub_buffer) {
    return nullptr;
  }
  ASSERT(t, (stub_buffer_end - stub_buffer) % bytes == 0)
      << "Stub size mismatch";
  if (stub_buffer + stub_buffer_allocated + bytes > stub_buffer_end) {
    return nullptr;
  }
  auto result = stub_buffer.cast<uint8_t>() + stub_buffer_allocated;
  stub_buffer_allocated += bytes;
  return result;
}

template <typename StubPatch>
static void substitute(uint8_t* buffer, uint64_t return_addr,
                       uint32_t trampoline_relative_addr,
                       uint32_t return_relative_addr);

template <>
void substitute<X86SyscallStubMonkeypatch>(uint8_t* buffer,
                                           uint64_t return_addr,
                                           uint32_t trampoline_relative_addr,
                                           uint32_t return_relative_addr) {
  X86SyscallStubMonkeypatch::substitute(buffer, (uint32_t)return_addr,
                                        trampoline_relative_addr,
                                        return_relative_addr);
}

template <>
void substitute<X64SyscallStubMonkeypatch>(uint8_t* buffer,
                                           uint64_t return_addr,
                                           uint32_t trampoline_relative_addr,
                                           uint32_t return_relative_addr) {
  X64SyscallStubMonkeypatch::substitute(
      buffer, (uint32_t)return_addr, (uint32_t)(return_addr >> 32),
      trampoline_relative_addr, return_relative_addr);
}

/**
 * Some functions make system calls while storing local variables in memory
 * below the stack pointer. We need to decrement the stack pointer by
 * some "safety zone" amount to get clear of those variables before we make
 * a call instruction. So, we allocate a stub per patched callsite, and jump
 * from the callsite to the stub. The stub decrements the stack pointer,
 * calls the appropriate syscall hook function, reincrements the stack pointer,
 * and jumps back to immediately after the patched callsite.
 */
template <typename JumpPatch, typename StubPatch, uint32_t trampoline_call_end>
static bool patch_syscall_with_hook_x86ish(Monkeypatcher& patcher, Task* t,
                                           const syscall_patch_hook& hook) {
  uint8_t stub_patch[StubPatch::size];
  auto stub_patch_start = patcher.allocate_stub(t, sizeof(stub_patch));
  if (!stub_patch_start) {
    LOG(debug) << "syscall can't be patched due to stub allocation failure";
    return false;
  }
  auto stub_patch_after_trampoline_call =
      stub_patch_start + trampoline_call_end;
  auto stub_patch_end = stub_patch_start + sizeof(stub_patch);

  uint8_t jump_patch[JumpPatch::size];
  // We're patching in a relative jump, so we need to compute the offset from
  // the end of the jump to our actual destination.
  auto jump_patch_start = t->regs().ip().to_data_ptr<uint8_t>();
  auto jump_patch_end = jump_patch_start + sizeof(jump_patch);

  intptr_t jump_offset = stub_patch_start - jump_patch_end;
  int32_t jump_offset32 = (int32_t)jump_offset;
  if (jump_offset32 != jump_offset) {
    LOG(debug) << "syscall can't be patched due to jump out of range from "
               << jump_patch_end << " to " << stub_patch_start;
    return false;
  }
  intptr_t return_jump_offset = jump_patch_end - stub_patch_end;
  int32_t return_jump_offset32 = (int32_t)return_jump_offset;
  if (return_jump_offset32 != return_jump_offset) {
    LOG(debug) << "syscall can't be patched due to jump out of range from "
               << stub_patch_end << " to " << jump_patch_end;
    return false;
  }
  intptr_t trampoline_call_offset =
      hook.hook_address - stub_patch_after_trampoline_call.as_int();
  int32_t trampoline_call_offset32 = (int32_t)trampoline_call_offset;
  ASSERT(t, trampoline_call_offset32 == trampoline_call_offset)
      << "How did the stub area get far away from the hooks?";

  JumpPatch::substitute(jump_patch, jump_offset32);
  t->write_bytes(jump_patch_start, jump_patch);

  // pad with NOPs to the next instruction
  static const uint8_t NOP = 0x90;
  assert(syscall_instruction_length(x86_64) == syscall_instruction_length(x86));
  uint8_t nops[syscall_instruction_length(x86_64) +
               hook.next_instruction_length - sizeof(jump_patch)];
  memset(nops, NOP, sizeof(nops));
  t->write_mem(jump_patch_start + sizeof(jump_patch), nops, sizeof(nops));

  // Now write out the stub
  substitute<StubPatch>(stub_patch, jump_patch_end.as_int(),
                        trampoline_call_offset32, return_jump_offset32);
  t->write_bytes(stub_patch_start, stub_patch);

  return true;
}

template <>
bool patch_syscall_with_hook_arch<X86Arch>(Monkeypatcher& patcher, Task* t,
                                           const syscall_patch_hook& hook) {
  return patch_syscall_with_hook_x86ish<X86SysenterVsyscallSyscallHook,
                                        X86SyscallStubMonkeypatch, 30>(patcher,
                                                                       t, hook);
}

template <>
bool patch_syscall_with_hook_arch<X64Arch>(Monkeypatcher& patcher, Task* t,
                                           const syscall_patch_hook& hook) {
  return patch_syscall_with_hook_x86ish<
      X64JumpMonkeypatch, X64SyscallStubMonkeypatch, 43>(patcher, t, hook);
}

static bool patch_syscall_with_hook(Monkeypatcher& patcher, Task* t,
                                    const syscall_patch_hook& hook) {
  RR_ARCH_FUNCTION(patch_syscall_with_hook_arch, t->arch(), patcher, t, hook);
}

// TODO de-dup
static void advance_syscall(Task* t) {
  do {
    t->cont_syscall();
  } while (t->is_ptrace_seccomp_event() ||
           ReplaySession::is_ignored_signal(t->pending_sig()));
  assert(t->ptrace_event() == 0);
}

static void operator<<(ostream& stream, const vector<uint8_t>& bytes) {
  for (uint32_t i = 0; i < bytes.size(); ++i) {
    if (i > 0) {
      stream << ' ';
    }
    stream << HEX(bytes[i]);
  }
}

bool Monkeypatcher::try_patch_syscall(Task* t) {
  if (syscall_hooks.empty()) {
    // Syscall hooks not set up yet. Don't spew warnings, and don't
    // fill tried_to_patch_syscall_addresses with addresses that we might be
    // able to patch later.
    return false;
  }
  if (t->is_in_traced_syscall()) {
    // Never try to patch the traced-syscall in our preload library!
    return false;
  }

  Registers r = t->regs();
  if (tried_to_patch_syscall_addresses.count(r.ip())) {
    return false;
  }
  // We could examine the current syscall number and if it's not one that
  // we support syscall buffering for, refuse to patch the syscall instruction.
  // This would, on the face of it, reduce overhead since patching the
  // instruction just means a useless trip through the syscall buffering logic.
  // However, it actually wouldn't help much since we'd still to a switch
  // on the syscall number in this function instead, and due to context
  // switching costs any overhead saved would be insignificant.
  // Also, implementing that would require keeping a buffered-syscalls
  // list in sync with the preload code, which is unnecessary complexity.

  tried_to_patch_syscall_addresses.insert(r.ip());

  syscall_patch_hook dummy;
  auto next_instruction = t->read_mem(r.ip().to_data_ptr<uint8_t>(),
                                      sizeof(dummy.next_instruction_bytes));
  intptr_t syscallno = r.original_syscallno();
  for (auto& hook : syscall_hooks) {
    if (memcmp(next_instruction.data(), hook.next_instruction_bytes,
               hook.next_instruction_length) == 0) {
      // Get out of executing the current syscall before we patch it.
      r.set_original_syscallno(syscall_number_for_gettid(t->arch()));
      t->set_regs(r);
      // This exits the hijacked SYS_gettid.  Now the tracee is
      // ready to do our bidding.
      advance_syscall(t);

      // Restore these regs to what they would have been just before
      // the tracee trapped at the syscall.
      r.set_original_syscallno(-1);
      r.set_syscallno(syscallno);
      r.set_ip(r.ip() - syscall_instruction_length(t->arch()));
      t->set_regs(r);

      patch_syscall_with_hook(*this, t, hook);

      LOG(debug) << "Patched syscall at " << r.ip() << " syscall "
                 << syscall_name(syscallno, t->arch()) << " tid " << t->tid
                 << " bytes " << next_instruction;
      // Return to caller, which resume normal execution.
      return true;
    }
  }
  LOG(debug) << "Failed to patch syscall at " << r.ip() << " syscall "
             << syscall_name(syscallno, t->arch()) << " tid " << t->tid
             << " bytes " << next_instruction;
  return false;
}

class SymbolTable {
public:
  bool is_name(size_t i, const char* name) const {
    size_t offset = symbols[i].name_index;
    return offset < strtab.size() && strcmp(&strtab[offset], name) == 0;
  }
  uintptr_t value(size_t i) const { return symbols[i].value; }
  size_t size() const { return symbols.size(); }

  struct Symbol {
    Symbol(uintptr_t value, size_t name_index)
        : value(value), name_index(name_index) {}
    Symbol() {}
    uintptr_t value;
    size_t name_index;
  };
  vector<Symbol> symbols;
  vector<char> strtab;
};

class ElfReader {
public:
  virtual ~ElfReader() {}
  virtual bool read(size_t offset, size_t size, void* buf) = 0;
  template <typename T> bool read(size_t offset, T& result) {
    return read(offset, sizeof(result), &result);
  }
  template <typename T> vector<T> read(size_t offset, size_t count) {
    vector<T> result;
    result.resize(count);
    if (!read(offset, sizeof(T) * count, result.data())) {
      result.clear();
    }
    return result;
  }
  template <typename Arch>
  SymbolTable read_symbols_arch(const char* symtab, const char* strtab);
  SymbolTable read_symbols(SupportedArch arch, const char* symtab,
                           const char* strtab);
};

template <typename Arch>
SymbolTable ElfReader::read_symbols_arch(const char* symtab,
                                         const char* strtab) {
  SymbolTable result;
  typename Arch::ElfEhdr elfheader;
  if (!read(0, elfheader) || memcmp(&elfheader, ELFMAG, SELFMAG) != 0 ||
      elfheader.e_ident[EI_CLASS] != Arch::elfclass ||
      elfheader.e_ident[EI_DATA] != Arch::elfendian ||
      elfheader.e_machine != Arch::elfmachine ||
      elfheader.e_shentsize != sizeof(typename Arch::ElfShdr) ||
      elfheader.e_shstrndx >= elfheader.e_shnum) {
    LOG(debug) << "Invalid ELF file: invalid header";
    return result;
  }

  auto sections =
      read<typename Arch::ElfShdr>(elfheader.e_shoff, elfheader.e_shnum);
  if (sections.empty()) {
    LOG(debug) << "Invalid ELF file: no sections";
    return result;
  }

  auto& section_names_section = sections[elfheader.e_shstrndx];
  auto section_names = read<char>(section_names_section.sh_offset,
                                  section_names_section.sh_size);
  if (section_names.empty()) {
    LOG(debug) << "Invalid ELF file: can't read section names";
    return result;
  }
  section_names[section_names.size() - 1] = 0;

  typename Arch::ElfShdr* symbols = nullptr;
  typename Arch::ElfShdr* strings = nullptr;
  for (size_t i = 0; i < elfheader.e_shnum; ++i) {
    auto& s = sections[i];
    if (s.sh_name >= section_names.size()) {
      LOG(debug) << "Invalid ELF file: invalid name offset for section " << i;
      return result;
    }
    const char* name = section_names.data() + s.sh_name;
    if (strcmp(name, symtab) == 0) {
      if (symbols) {
        LOG(debug) << "Invalid ELF file: duplicate symbol section " << symtab;
        return result;
      }
      symbols = &s;
    }
    if (strcmp(name, strtab) == 0) {
      if (strings) {
        LOG(debug) << "Invalid ELF file: duplicate string section " << strtab;
        return result;
      }
      strings = &s;
    }
  }

  if (!symbols) {
    LOG(debug) << "Invalid ELF file: missing symbol section " << symtab;
    return result;
  }
  if (!strings) {
    LOG(debug) << "Invalid ELF file: missing string section " << strtab;
    return result;
  }
  if (symbols->sh_entsize != sizeof(typename Arch::ElfSym)) {
    LOG(debug) << "Invalid ELF file: incorrect symbol size "
               << symbols->sh_entsize;
    return result;
  }
  if (symbols->sh_size % symbols->sh_entsize) {
    LOG(debug) << "Invalid ELF file: incorrect symbol section size "
               << symbols->sh_size;
    return result;
  }

  auto symbol_list = read<typename Arch::ElfSym>(
      symbols->sh_offset, symbols->sh_size / symbols->sh_entsize);
  if (symbol_list.empty()) {
    LOG(debug) << "Invalid ELF file: can't read symbols " << symtab;
    return result;
  }
  result.strtab = read<char>(strings->sh_offset, strings->sh_size);
  if (result.strtab.empty()) {
    LOG(debug) << "Invalid ELF file: can't read strings " << strtab;
  }
  result.symbols.resize(symbol_list.size());
  for (size_t i = 0; i < symbol_list.size(); ++i) {
    auto& s = symbol_list[i];
    result.symbols[i] = SymbolTable::Symbol(s.st_value, s.st_name);
  }
  return result;
}

SymbolTable ElfReader::read_symbols(SupportedArch arch, const char* symtab,
                                    const char* strtab) {
  RR_ARCH_FUNCTION(read_symbols_arch, arch, symtab, strtab);
}

class VdsoReader : public ElfReader {
public:
  VdsoReader(Task* t) : t(t) {}
  virtual bool read(size_t offset, size_t size, void* buf) {
    bool ok = true;
    t->read_bytes_helper(t->vm()->vdso().start + offset, size, buf, &ok);
    return ok;
  }
  Task* t;
};

static SymbolTable read_vdso_symbols(Task* t) {
  return VdsoReader(t).read_symbols(t->arch(), ".dynsym", ".dynstr");
}

/**
 * Return true iff |addr| points to a known |__kernel_vsyscall()|
 * implementation.
 */
static bool is_kernel_vsyscall(Task* t, remote_ptr<void> addr) {
  uint8_t impl[X86SysenterVsyscallImplementation::size];
  t->read_bytes(addr, impl);
  return X86SysenterVsyscallImplementation::match(impl);
}

/**
 * Return the address of a recognized |__kernel_vsyscall()|
 * implementation in |t|'s address space.
 */
static remote_ptr<void> locate_and_verify_kernel_vsyscall(Task* t,
    const SymbolTable& syms) {
  remote_ptr<void> kernel_vsyscall = nullptr;
  // It is unlikely but possible that multiple, versioned __kernel_vsyscall
  // symbols will exist.  But we can't rely on setting |kernel_vsyscall| to
  // catch that case, because only one of the versioned symbols will
  // actually match what we expect to see, and the matching one might be
  // the last one.  Therefore, we have this separate flag to alert us to
  // this possbility.
  bool seen_kernel_vsyscall = false;

  for (size_t i = 0; i < syms.size(); ++i) {
    if (syms.is_name(i, "__kernel_vsyscall")) {
      assert(!seen_kernel_vsyscall);
      seen_kernel_vsyscall = true;
      // The ELF information in the VDSO assumes that the VDSO
      // is always loaded at a particular address.  The kernel,
      // however, subjects the VDSO to ASLR, which means that
      // we have to adjust the offsets properly.
      auto vdso_start = t->vm()->vdso().start;
      remote_ptr<void> candidate = syms.value(i);
      // The symbol values can be absolute or relative addresses.
      // The first part of the assertion is for absolute
      // addresses, and the second part is for relative.
      assert((candidate.as_int() & ~uintptr_t(0xfff)) == 0xffffe000 ||
             (candidate.as_int() & ~uintptr_t(0xfff)) == 0);
      uintptr_t candidate_offset = candidate.as_int() & uintptr_t(0xfff);
      candidate = vdso_start + candidate_offset;

      if (is_kernel_vsyscall(t, candidate)) {
        kernel_vsyscall = candidate;
      }
    }
  }

  return kernel_vsyscall;
}

// VDSOs are filled with overhead critical functions related to getting the
// time and current CPU.  We need to ensure that these syscalls get redirected
// into actual trap-into-the-kernel syscalls so rr can intercept them.

template <typename Arch> static void patch_after_exec_arch(Task* t, Monkeypatcher& patcher);

template <typename Arch>
static void patch_at_preload_init_arch(Task* t, Monkeypatcher& patcher);

struct named_syscall {
  const char* name;
  int syscall_number;
};

// Monkeypatch x86-32 vdso syscalls immediately after exec. The vdso syscalls
// will cause replay to fail if called by the dynamic loader or some library's
// static constructors, so we can't wait for our preload library to be
// initialized. Fortunately we're just replacing the vdso code with real
// syscalls so there is no dependency on the preload library at all.
template <> void patch_after_exec_arch<X86Arch>(Task* t, Monkeypatcher& patcher) {
  setup_preload_library_path<X86Arch>(t);

  auto syms = read_vdso_symbols(t);
  patcher.x86_sysenter_vsyscall = locate_and_verify_kernel_vsyscall(t, syms);
  if (!patcher.x86_sysenter_vsyscall) {
    FATAL() << "Failed to monkeypatch vdso: your __kernel_vsyscall() wasn't "
               "recognized.\n"
               "    Syscall buffering is now effectively disabled.  If you're "
               "OK with\n"
               "    running rr without syscallbuf, then run the recorder "
               "passing the\n"
               "    --no-syscall-buffer arg.\n"
               "    If you're *not* OK with that, file an issue.";
  }

  // Patch __kernel_vsyscall to use int 80 instead of sysenter.
  // During replay we may remap the VDSO to a new address, and the sysenter
  // instruction would return to the old address, so we must make sure sysenter
  // is never used.
  uint8_t patch[X86SysenterVsyscallUseInt80::size];
  X86SysenterVsyscallUseInt80::substitute(patch);
  t->write_bytes(patcher.x86_sysenter_vsyscall, patch);
  LOG(debug) << "monkeypatched __kernel_vsyscall to use int $80";

  auto vdso_start = t->vm()->vdso().start;

  static const named_syscall syscalls_to_monkeypatch[] = {
#define S(n)                                                                   \
  { "__vdso_" #n, X86Arch::n }
    S(clock_gettime), S(gettimeofday), S(time),
#undef S
  };

  for (size_t i = 0; i < syms.size(); ++i) {
    for (size_t j = 0; j < array_length(syscalls_to_monkeypatch); ++j) {
      if (syms.is_name(i, syscalls_to_monkeypatch[j].name)) {
        static const uintptr_t vdso_max_size = 0xffffLL;
        uintptr_t sym_address = syms.value(i);
        assert((sym_address & ~vdso_max_size) == 0);
        uintptr_t absolute_address = vdso_start.as_int() + sym_address;

        uint8_t patch[X86VsyscallMonkeypatch::size];
        uint32_t syscall_number = syscalls_to_monkeypatch[j].syscall_number;
        X86VsyscallMonkeypatch::substitute(patch, syscall_number);

        t->write_bytes(absolute_address, patch);
        LOG(debug) << "monkeypatched " << syscalls_to_monkeypatch[j].name
                   << " to syscall "
                   << syscalls_to_monkeypatch[j].syscall_number;
      }
    }
  }
}

// Monkeypatch x86 vsyscall hook only after the preload library
// has initialized. The vsyscall hook expects to be able to use the syscallbuf.
// Before the preload library has initialized, the regular vsyscall code
// will trigger ptrace traps and be handled correctly by rr.
template <>
void patch_at_preload_init_arch<X86Arch>(Task* t, Monkeypatcher& patcher) {
  auto params = t->read_mem(
      remote_ptr<rrcall_init_preload_params<X86Arch> >(t->regs().arg1()));
  if (!params.syscallbuf_enabled) {
    return;
  }

  auto kernel_vsyscall = patcher.x86_sysenter_vsyscall;

  // Luckily, linux is happy for us to scribble directly over
  // the vdso mapping's bytes without mprotecting the region, so
  // we don't need to prepare remote syscalls here.
  remote_ptr<void> syscall_hook_trampoline = params.syscall_hook_trampoline;

  uint8_t patch[X86SysenterVsyscallSyscallHook::size];
  // We're patching in a relative jump, so we need to compute the offset from
  // the end of the jump to our actual destination.
  X86SysenterVsyscallSyscallHook::substitute(
      patch, syscall_hook_trampoline.as_int() -
                 (kernel_vsyscall + sizeof(patch)).as_int());
  t->write_bytes(kernel_vsyscall, patch);
  LOG(debug) << "monkeypatched __kernel_vsyscall to jump to "
             << HEX(syscall_hook_trampoline.as_int());

  patcher.init_dynamic_syscall_patching(
      t, params.syscall_patch_hook_count, params.syscall_patch_hooks,
      params.syscall_hook_stub_buffer, params.syscall_hook_stub_buffer_end);
}

// Monkeypatch x86-64 vdso syscalls immediately after exec. The vdso syscalls
// will cause replay to fail if called by the dynamic loader or some library's
// static constructors, so we can't wait for our preload library to be
// initialized. Fortunately we're just replacing the vdso code with real
// syscalls so there is no dependency on the preload library at all.
template <> void patch_after_exec_arch<X64Arch>(Task* t, Monkeypatcher& patcher) {
  setup_preload_library_path<X64Arch>(t);

  auto vdso_start = t->vm()->vdso().start;

  auto syms = read_vdso_symbols(t);

  static const named_syscall syscalls_to_monkeypatch[] = {
#define S(n)                                                                   \
  { "__vdso_" #n, X64Arch::n }
    S(clock_gettime), S(gettimeofday), S(time),
    // getcpu isn't supported by rr, so any changes to this monkeypatching
    // scheme for efficiency's sake will have to ensure that getcpu gets
    // converted to an actual syscall so rr will complain appropriately.
    S(getcpu),
#undef S
  };

  for (size_t i = 0; i < syms.size(); ++i) {
    for (size_t j = 0; j < array_length(syscalls_to_monkeypatch); ++j) {
      if (syms.is_name(i, syscalls_to_monkeypatch[j].name)) {
        // Absolutely-addressed symbols in the VDSO claim to start here.
        static const uint64_t vdso_static_base = 0xffffffffff700000LL;
        static const uintptr_t vdso_max_size = 0xffffLL;
        uintptr_t sym_address = syms.value(i);
        // The symbol values can be absolute or relative addresses.
        // The first part of the assertion is for absolute
        // addresses, and the second part is for relative.
        assert((sym_address & ~vdso_max_size) == vdso_static_base ||
               (sym_address & ~vdso_max_size) == 0);
        uintptr_t sym_offset = sym_address & vdso_max_size;
        uintptr_t absolute_address = vdso_start.as_int() + sym_offset;

        uint8_t patch[X64VsyscallMonkeypatch::size];
        uint32_t syscall_number = syscalls_to_monkeypatch[j].syscall_number;
        X64VsyscallMonkeypatch::substitute(patch, syscall_number);

        t->write_bytes(absolute_address, patch);
        LOG(debug) << "monkeypatched " << syscalls_to_monkeypatch[j].name
                   << " to syscall "
                   << syscalls_to_monkeypatch[j].syscall_number;
      }
    }
  }
}

template <>
void patch_at_preload_init_arch<X64Arch>(Task* t, Monkeypatcher& patcher) {
  auto params = t->read_mem(
      remote_ptr<rrcall_init_preload_params<X64Arch> >(t->regs().arg1()));
  if (!params.syscallbuf_enabled) {
    return;
  }

  patcher.init_dynamic_syscall_patching(
      t, params.syscall_patch_hook_count, params.syscall_patch_hooks,
      params.syscall_hook_stub_buffer, params.syscall_hook_stub_buffer_end);
}

void Monkeypatcher::patch_after_exec(Task* t) {
  ASSERT(t, 1 == t->vm()->task_set().size())
      << "Can't have multiple threads immediately after exec!";

  RR_ARCH_FUNCTION(patch_after_exec_arch, t->arch(), t, *this);
}

void Monkeypatcher::patch_at_preload_init(Task* t) {
  ASSERT(t, 1 == t->vm()->task_set().size())
      << "TODO: monkeypatch multithreaded process";

  // NB: the tracee can't be interrupted with a signal while
  // we're processing the rrcall, because it's masked off all
  // signals.
  RR_ARCH_FUNCTION(patch_at_preload_init_arch, t->arch(), t, *this);
}

class FileReader : public ElfReader {
public:
  FileReader(ScopedFd& fd) : fd(fd) {}
  virtual bool read(size_t offset, size_t size, void* buf) {
    return pread(fd.get(), buf, size, offset) == ssize_t(size);
  }
  ScopedFd& fd;
};

static void set_and_record_bytes(Task* t, uint64_t file_offset,
                                 const void* bytes, size_t size,
                                 remote_ptr<void> map_start, size_t map_size,
                                 size_t map_offset_pages) {
  uint64_t map_offset = uint64_t(map_offset_pages) * page_size();
  if (file_offset < map_offset || file_offset + size > map_offset + map_size) {
    // The value(s) to be set are outside the mapped range. This happens
    // because code and data can be mapped in separate, partial mmaps in which
    // case some symbols will be outside the mapped range.
    return;
  }
  remote_ptr<void> addr = map_start + uintptr_t(file_offset - map_offset);
  t->write_bytes_helper(addr, size, bytes);
  t->record_local(addr, size, bytes);
}

void Monkeypatcher::patch_after_mmap(Task* t, remote_ptr<void> start,
                                     size_t size, size_t offset_pages,
                                     ScopedFd& open_fd) {
  const auto& map = t->vm()->mapping_of(start);
  if (map.second.fsname.find("libpthread.so") != string::npos &&
      (t->arch() == x86 || t->arch() == x86_64)) {
    auto syms =
        FileReader(open_fd).read_symbols(t->arch(), ".symtab", ".strtab");
    for (size_t i = 0; i < syms.size(); ++i) {
      if (syms.is_name(i, "__elision_aconf")) {
        static const int zero = 0;
        // Setting __elision_aconf.retry_try_xbegin to zero means that
        // pthread rwlocks don't try to use elision at all. See ELIDE_LOCK
        // in glibc's elide.h.
        set_and_record_bytes(t, syms.value(i) + 8, &zero, sizeof(zero), start,
                             size, offset_pages);
      }
      if (syms.is_name(i, "elision_init")) {
        // Make elision_init return without doing anything. This means
        // the __elision_available and __pthread_force_elision flags will
        // remain zero, disabling elision for mutexes. See glibc's
        // elision-conf.c.
        static const uint8_t ret = 0xC3;
        set_and_record_bytes(t, syms.value(i), &ret, sizeof(ret), start, size,
                             offset_pages);
      }
    }
  }
}
