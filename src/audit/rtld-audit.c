#include "rtld-audit.h"
#include <stdlib.h>
#define RR_IMPLEMENT_AUDIT
#include "../preload/preload_interface.h"

/* Some notes about audit libraries:
 *
 * Due to some libpthread bugs[0][1] (and probably others in other libraries)
 * not everything is safe to call from here. In particular, anything that calls
 * _dlerror_run or __dlerror (i.e., most/all of the public dlfcn functions)
 * will cause a TLS slot to be allocated more than once. Make sure nothing
 * calls pthread_key_create() outside of the main link namespace.
 *
 * Since gdb lacks support for multiple link namespaces[2], no debugging
 * information is available for audit libraries in gdb sessions by default. To
 * avoid debugging unannotated disassembly, we have to inform gdb about the
 * other libraries:
 *  - Run rr-record with '-v LD_DEBUG=files'. This will present output in the form
 *      <pid>:      file=libfoo.so [<link map id>];  needed by bar [<link map id>]
 *      <pid>:      file=libfoo.so [<link map id>];  generating link map
 *      <pid>:        dynamic: 0xxxxxxxxxxxxxxxxx  base: 0xxxxxxxxxxxxxxxxx  size:  0xxxxxxxxxxxxxxxxx
 *      <pid>:        entry:   0xxxxxxxxxxxxxxxxx  phdr: 0xxxxxxxxxxxxxxxxx  phnum:                 XX
 *    We're interested in entries with link map ID 1, assuming librraudit is
 *    first in the audit library list.
 *  - Load the library into gdb:
 *      (rr) add-symbol-file /path/to/libfoo.so -o <base address>
 *    Where <base address> is the value labelled 'base' above.
 *
 * [0]: https://sourceware.org/bugzilla/show_bug.cgi?id=24773#c1
 * [1]: https://sourceware.org/bugzilla/show_bug.cgi?id=24776
 * [2]: https://sourceware.org/bugzilla/show_bug.cgi?id=15971
 */

extern __attribute__((visibility("hidden")))
long _raw_syscall(int syscallno, long a0, long a1, long a2,
                  long a3, long a4, long a5,
                  void* syscall_instruction,
                  long stack_param_1, long stack_param_2);

bool rr_audit_debug;

unsigned la_version(unsigned version) {
  rr_audit_debug = !!getenv("RR_AUDIT_DEBUG");
  return version;
}
