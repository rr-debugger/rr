/* -*- Mode: C++; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_THREADDB_H_
#define RR_THREADDB_H_

#include "remote_ptr.h"
#include <map>
#include <set>
#include <string>

extern "C" {
#include <thread_db.h>
}

namespace rr {
class ThreadGroup;
class ThreadDb;
}

// This is declared as incomplete by the libthread_db API and is
// expected to be defined by the API user.  We define it to hold just
// pointers back to the thread group and to the ThreadDb object.
struct ps_prochandle {
  rr::ThreadGroup* thread_group;
  rr::ThreadDb* db;
  pid_t tgid;
};

namespace rr {

/**
 * This provides an interface to libthread_db.so to help with TLS
 * lookup. In principle there could be one instance per process, but we only
 * support one instance for the GdbServer's target process.
 *
 * The overall approach is that a libthread_db.so is loaded into rr
 * when this class is initialized (see |load_library|).  This provides
 * the GdbServer with a list of symbols whose addresses might be
 * needed in order to resolve TLS accesses.
 *
 * Then, when the address of a TLS variable is requested by the
 * debugger, GdbServer calls |get_tls_address|.  This uses the
 * libthread_db "new" function ("td_ta_new"); if this succeeds then
 * ThreadDb proceeds to use other APIs to find the desired address.
 *
 * ThreadDb works on a callback model, using symbols provided by the
 * hosting application.  These are all defined in ThreadDb.cc.
 */
class ThreadDb {
public:
  explicit ThreadDb(pid_t tgid);
  ~ThreadDb();

  /**
   * Return a set of the names of all the symbols that might be needed
   * by libthread_db.  Also clears the current mapping of symbol names
   * to addresses.
   */
  const std::set<std::string> get_symbols_and_clear_map(
      ThreadGroup* thread_group);

  /**
   * Note that the symbol |name| has the given address.
   */
  void register_symbol(const std::string& name, remote_ptr<void> address);

  /**
   * Look up the symbol |name|.  If found, set |*address| and return
   * true.  If not found, return false.
   */
  bool query_symbol(const char* name, remote_ptr<void>* address);

  /**
   * Look up a TLS address for thread |rec_tid|.  |offset| and
   * |load_module| are as specified in the qGetTLSAddr packet.  If the
   * address is found, set |*result| and return true.  Otherwise,
   * return false.
   */
  bool get_tls_address(ThreadGroup* thread_group, pid_t rec_tid, size_t offset,
                       remote_ptr<void> load_module, remote_ptr<void>* result);

private:
  bool load_library();
  bool initialize();

  ThreadDb(ThreadDb&) = delete;
  ThreadDb operator=(ThreadDb&) = delete;

  // True if libthread_db has been successfully initialized, if all
  // the functions exist, and if the list of needed symbol names has
  // been computed.
  bool loaded;

  // The external handle for this thread, for libthread_db.
  struct ps_prochandle prochandle;
  // The internal handle for this thread, from libthread_db.
  td_thragent_t* internal_handle;
  // Handle on the libthread_db library itself.
  void* thread_db_library;

  // Functions from libthread_db.
  decltype(td_ta_delete)* td_ta_delete_fn;
  decltype(td_thr_tls_get_addr)* td_thr_tls_get_addr_fn;
  decltype(td_ta_map_lwp2thr)* td_ta_map_lwp2thr_fn;
  decltype(td_ta_new)* td_ta_new_fn;

  // Set of all symbol names.
  std::set<std::string> symbol_names;

  // Map from symbol names to addresses.
  std::map<std::string, remote_ptr<void>> symbols;
};

} // namespace rr

#endif // RR_THREADDB_H_
