/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "ThreadDb.h"
#include "GdbServer.h"
#include "Task.h"
#include "ThreadGroup.h"
#include "core.h"
#include "log.h"

extern "C" {
// The proc_service/thread_db library has a very weird API.  It
// requires the user of the library to provide certain functions which
// it links to (rather than, say, having the library user supply a
// struct of function pointers).  We have to ensure that these
// functions have C linkage, so that libthread_db can find them.
#include "proc_service.h"
}

#include <asm/prctl.h>
#include <dlfcn.h>
#include <linux/elf.h>
#include <sys/reg.h>

#define LIBRARY_NAME "libthread_db.so.1"

// Needed for the logging API.
using namespace rr;

ps_err_e ps_pglobal_lookup(struct ps_prochandle* h, const char*,
                           const char* symbol, psaddr_t* sym_addr) {
  rr::remote_ptr<void> addr;
  if (!h->db->query_symbol(symbol, &addr)) {
    LOG(debug) << "ps_pglobal_lookup " << symbol << " failed";
    return PS_NOSYM;
  }
  *sym_addr = reinterpret_cast<psaddr_t>(addr.as_int());
  LOG(debug) << "ps_pglobal_lookup " << symbol << " OK";
  return PS_OK;
}

ps_err_e ps_pdread(struct ps_prochandle* h, psaddr_t addr, void* buffer,
                   size_t len) {
  if (!h->thread_group) {
    FATAL() << "unexpected ps_pdread call with uninitialized thread_group";
  }
  bool ok = true;
  uintptr_t uaddr = reinterpret_cast<uintptr_t>(addr);
  // We need any task associated with the thread group.  Here we assume
  // that all the tasks in the thread group share VM, which is enforced
  // by clone(2).
  rr::Task* task = *h->thread_group->task_set().begin();
  task->read_bytes_helper(uaddr, len, buffer, &ok);
  LOG(debug) << "ps_pdread " << ok;
  return ok ? PS_OK : PS_ERR;
}

ps_err_e ps_pdwrite(struct ps_prochandle*, psaddr_t, const void*, size_t) {
  FATAL() << "ps_pdwrite not implemented";
  return PS_ERR;
}

ps_err_e ps_lgetregs(struct ps_prochandle* h, lwpid_t rec_tid,
                     prgregset_t result) {
  if (!h->thread_group) {
    FATAL() << "unexpected ps_lgetregs call with uninitialized thread_group";
  }
  rr::Task* task = h->thread_group->session()->find_task(rec_tid);
  DEBUG_ASSERT(task != nullptr);

  struct ::user_regs_struct regs = task->regs().get_ptrace();
  memcpy(result, static_cast<void*>(&regs), sizeof(regs));
  LOG(debug) << "ps_lgetregs OK";
  return PS_OK;
}

ps_err_e ps_lsetregs(struct ps_prochandle*, lwpid_t, const prgregset_t) {
  FATAL() << "ps_lsetregs not implemented";
  return PS_ERR;
}

ps_err_e ps_lgetfpregs(struct ps_prochandle*, lwpid_t, prfpregset_t*) {
  FATAL() << "ps_lgetfpregs not implemented";
  return PS_ERR;
}

ps_err_e ps_lsetfpregs(struct ps_prochandle*, lwpid_t, const prfpregset_t*) {
  FATAL() << "ps_lsetfpregs not implemented";
  return PS_ERR;
}

pid_t ps_getpid(struct ps_prochandle* h) {
  LOG(debug) << "ps_getpid " << h->tgid;
  return h->tgid;
}

ps_err_e ps_get_thread_area(const struct ps_prochandle* h, lwpid_t rec_tid,
                            int val, psaddr_t* base) {
  if (!h->thread_group) {
    FATAL()
        << "unexpected ps_get_thread_area call with uninitialized thread_group";
  }
  rr::Task* task = h->thread_group->session()->find_task(rec_tid);
  DEBUG_ASSERT(task != nullptr);

  if (task->arch() == rr::x86) {
    unsigned int uval = static_cast<unsigned int>(val);
    for (auto& area : task->thread_areas()) {
      if (area.entry_number == uval) {
        uintptr_t result = static_cast<uintptr_t>(area.base_addr);
        *base = reinterpret_cast<psaddr_t>(result);
        return PS_OK;
      }
    }
    LOG(debug) << "ps_get_thread_area 32 failed";
    return PS_ERR;
  }

  uintptr_t result;
  switch (val) {
    case FS:
      result = task->regs().fs_base();
      break;
    case GS:
      result = task->regs().gs_base();
      break;
    default:
      LOG(debug) << "ps_get_thread_area PS_BADADDR";
      return PS_BADADDR;
  }

  *base = reinterpret_cast<psaddr_t>(result);
  return PS_OK;
}

rr::ThreadDb::ThreadDb(pid_t tgid)
    : internal_handle(nullptr),
      thread_db_library(nullptr),
      td_ta_delete_fn(nullptr),
      td_thr_tls_get_addr_fn(nullptr),
      td_ta_map_lwp2thr_fn(nullptr) {
  prochandle.thread_group = nullptr;
  prochandle.db = this;
  prochandle.tgid = tgid;
}

rr::ThreadDb::~ThreadDb() {
  if (internal_handle) {
    td_ta_delete_fn(internal_handle);
  }
  if (thread_db_library) {
    dlclose(thread_db_library);
  }
}

const std::set<std::string> rr::ThreadDb::get_symbols_and_clear_map(
    ThreadGroup* thread_group) {
  // If we think the symbol locations might have changed, then we
  // probably need to recreate the handle.
  if (internal_handle) {
    td_ta_delete_fn(internal_handle);
    internal_handle = nullptr;
  }

  prochandle.thread_group = thread_group;
  symbols.clear();
  load_library();
  prochandle.thread_group = nullptr;
  return symbol_names;
}

void rr::ThreadDb::register_symbol(const std::string& name,
                                   remote_ptr<void> address) {
  LOG(debug) << "register_symbol " << name;
  symbols[name] = address;
}

bool rr::ThreadDb::query_symbol(const char* name, remote_ptr<void>* address) {
  auto it = symbols.find(name);
  if (it == symbols.end()) {
    return false;
  }
  *address = it->second;
  return true;
}

bool rr::ThreadDb::get_tls_address(ThreadGroup* thread_group, pid_t rec_tid,
                                   size_t offset, remote_ptr<void> load_module,
                                   remote_ptr<void>* result) {
  prochandle.thread_group = thread_group;
  if (!initialize()) {
    prochandle.thread_group = nullptr;
    return false;
  }

  td_thrhandle_t th;
  if (td_ta_map_lwp2thr_fn(internal_handle, rec_tid, &th) != TD_OK) {
    prochandle.thread_group = nullptr;
    return false;
  }

  psaddr_t load_module_addr = reinterpret_cast<psaddr_t>(load_module.as_int());
  psaddr_t addr;
  if (td_thr_tls_get_addr_fn(&th, load_module_addr, offset, &addr) != TD_OK) {
    prochandle.thread_group = nullptr;
    return false;
  }
  prochandle.thread_group = nullptr;
  *result = remote_ptr<void>(reinterpret_cast<uintptr_t>(addr));
  return true;
}

bool rr::ThreadDb::initialize() {
  if (internal_handle) {
    return true;
  }

  if (!load_library()) {
    return false;
  }

  if (!td_ta_new_fn || td_ta_new_fn(&prochandle, &internal_handle) != TD_OK) {
    LOG(debug) << "initialize td_ta_new_fn failed";
    return false;
  }

  LOG(debug) << "initialize OK";
  return true;
}

bool rr::ThreadDb::load_library() {
  if (thread_db_library) {
    LOG(debug) << "load_library already loaded: " << loaded;
    return loaded;
  }

  thread_db_library = dlopen(LIBRARY_NAME, RTLD_NOW);
  if (!thread_db_library) {
    LOG(debug) << "load_library dlopen failed";
    return false;
  }

  decltype(td_symbol_list)* td_symbol_list_fn;

#define FIND_FUNCTION(Name)                                                    \
  do {                                                                         \
    Name##_fn = (decltype(Name)*)(dlsym(thread_db_library, #Name));            \
    if (!Name##_fn) {                                                          \
      LOG(debug) << "load_library failed to find " << #Name;                   \
      return false;                                                            \
    }                                                                          \
  } while (0)

  FIND_FUNCTION(td_thr_tls_get_addr);
  FIND_FUNCTION(td_ta_delete);
  FIND_FUNCTION(td_symbol_list);
  FIND_FUNCTION(td_ta_new);
  FIND_FUNCTION(td_ta_map_lwp2thr);

#undef FIND_FUNCTION

  for (const char** syms = td_symbol_list_fn(); *syms; ++syms) {
    symbol_names.insert(*syms);
  }

  // Good to go.
  loaded = true;
  LOG(debug) << "load_library OK";
  return true;
}
