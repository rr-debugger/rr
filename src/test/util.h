/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RRUTIL_H
#define RRUTIL_H

#define _GNU_SOURCE 1
#define _POSIX_C_SOURCE 2

/* we assume code in assert() is executed.  */
#ifdef NDEBUG
#error The rr testsuite requires NDEBUG to be undefined.
#endif

/* btrfs needs NULL but doesn't #include it */
#include <stdlib.h>
/* need to include sys/mount.h before linux/fs.h */
#include <sys/mount.h>

#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <dirent.h>
#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <inttypes.h>
#include <linux/aio_abi.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/cdrom.h>
#include <linux/ethtool.h>
#include <linux/fb.h>
#include <linux/fiemap.h>
#include <linux/filter.h>
#include <linux/fs.h>
#include <linux/futex.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <linux/if_tun.h>
#include <linux/kd.h>
#include <linux/limits.h>
#include <linux/mtio.h>
#include <linux/netlink.h>
#include <linux/perf_event.h>
#include <linux/personality.h>
#include <linux/random.h>
#include <linux/seccomp.h>
#include <linux/sockios.h>
#include <linux/unistd.h>
#include <linux/videodev2.h>
#include <linux/vt.h>
#include <linux/wireless.h>
#include <mqueue.h>
#include <poll.h>
#include <pthread.h>
#include <pty.h>
#include <pwd.h>
#include <sched.h>
#include <scsi/sg.h>
#include <signal.h>
#include <sound/asound.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/fanotify.h>
#include <sys/file.h>
#include <sys/fsuid.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/ipc.h>
#include <sys/mman.h>
#include <sys/msg.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/quota.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/sem.h>
#include <sys/sendfile.h>
#include <sys/shm.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <sys/sysmacros.h>
#include <sys/time.h>
#include <sys/timerfd.h>
#include <sys/times.h>
#include <sys/types.h>
#include <sys/ucontext.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <sys/user.h>
#include <sys/utsname.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <syscall.h>
#include <termios.h>
#include <time.h>
#include <ucontext.h>
#include <unistd.h>
#include <utime.h>

// X86 specific headers
#if defined(__i386__) || defined(__x86_64__)
#include <asm/prctl.h>
#include <sys/io.h>
#include <x86intrin.h>
#endif

#if defined(__i386__)
#include "SyscallEnumsForTestsX86.generated"
#elif defined(__x86_64__)
#include "SyscallEnumsForTestsX64.generated"
#elif defined(__aarch64__)
#include "SyscallEnumsForTestsGeneric.generated"
#else
#error Unknown architecture
#endif

#include <rr/rr.h>

typedef unsigned char uint8_t;

#define ALEN(_a) (sizeof(_a) / sizeof(_a[0]))

#ifndef SOL_NETLINK
#define SOL_NETLINK 270
#endif

/**
 * Allocate new memory of |size| in bytes. The pointer returned is never NULL.
 * This calls aborts the program if the host runs out of memory.
 */
inline static void* xmalloc(size_t size) {
  void* mem_ptr = malloc(size);
  if (!mem_ptr) {
    abort();
  }
  return mem_ptr;
}

/**
 * Print the printf-like arguments to stdout as atomic-ly as we can
 * manage.  Async-signal-safe.  Does not flush stdio buffers (doing so
 * isn't signal safe).
 */
__attribute__((format(printf, 1, 2))) inline static int atomic_printf(
    const char* fmt, ...) {
  va_list args;
  char buf[1024];
  int len;

  va_start(args, fmt);
  len = vsnprintf(buf, sizeof(buf) - 1, fmt, args);
  va_end(args);
  return write(STDOUT_FILENO, buf, len);
}

/**
 * Write |str| on its own line to stdout as atomic-ly as we can
 * manage.  Async-signal-safe.  Does not flush stdio buffers (doing so
 * isn't signal safe).
 */
inline static int atomic_puts(const char* str) {
  return atomic_printf("%s\n", str);
}

#define fprintf(...) USE_dont_write_stderr
#define printf(...) USE_atomic_printf_INSTEAD
#define puts(...) USE_atomic_puts_INSTEAD

inline static int check_cond(int cond) {
  if (!cond) {
    atomic_printf("FAILED: errno=%d (%s)\n", errno, strerror(errno));
  }
  return cond;
}

inline static int atomic_assert(int cond, const char *str) {
  if (!check_cond(cond)) {
    atomic_printf("FAILED: !%s\n", str);
    raise(SIGABRT);
  }
  return 1;
}

#define test_assert(cond) atomic_assert(cond, #cond)

/**
 * Return the calling task's id.
 */
inline static pid_t sys_gettid(void) { return syscall(SYS_gettid); }

/**
 * Ensure that |len| bytes of |buf| are the same across recording and
 * replay.
 */
inline static void check_data(void* buf, size_t len) {
  ssize_t ret = syscall(SYS_write, RR_MAGIC_SAVE_DATA_FD, buf, len);
  if (ret == -1 && errno == EBADF) {
    atomic_printf("Failed to write to RR_MAGIC_SAVE_DATA_FD. Not running under rr?\n");
  } else {
    test_assert(ret == (ssize_t)len);
    atomic_printf("Wrote %zu bytes to magic fd\n", len);
  }
}

#if defined(__i386__) || defined(__x86_64)
/**
 * Return the current value of the time-stamp counter.
 */
inline static uint64_t rdtsc(void) { return __rdtsc(); }
#endif

/**
 * Perform some syscall that writes an event, i.e. is not syscall-buffered.
 */
inline static void event_syscall(void) { syscall(-1); }

static uint64_t GUARD_VALUE = 0xdeadbeeff00dbaad;

inline static size_t ceil_page_size(size_t size) {
  size_t page_size = sysconf(_SC_PAGESIZE);
  return (size + page_size - 1) & ~(page_size - 1);
}

#if defined(__i386__) || defined(__x86_64)
#define debug_trap() __asm__("int $3")
#define undefined_instr() __asm__("ud2")
#elif defined(__aarch64__)
#define debug_trap() __asm__("brk #0")
/**
 * GCC emits `brk #1000` for __builtin_trap,
 * Clang emits `brk #1` for the same.
 * It appears there was some plans early on to generate
 * SIGILL for breakpoint instructions with a high immediate,
 * but that never materialized. Instead, to get SIGILL, we use
 * an mrs instruction, which will cause SIGILL if the system
 * register used isn't accessible in EL0. Which register we
 * use doesn't matter here, but we should one that is neither
 * unsused and might do something else in the future, nor one
 * that the kernel or a hypervisor might emulate in the future.
 * Here we use `S3_6_C15_C8_0` which is a microcode patching
 * register and only available in EL3. Accessing it here
 * should always cause SIGILL
 */
#define undefined_instr() __asm__("mrs x0, S3_6_C15_C8_0")
#else
#error "Unknown architecture"
#endif

/**
 * Allocate 'size' bytes, fill with 'value', place canary value before
 * the allocated block, and put guard pages before and after. Ensure
 * there's a guard page immediately after `size`.
 * This lets us catch cases where too much data is being recorded --- which can
 * cause errors if the recorder tries to read invalid memory.
 */
inline static void* allocate_guard(size_t size, char value) {
  size_t page_size = sysconf(_SC_PAGESIZE);
  size_t map_size = ceil_page_size(size + sizeof(GUARD_VALUE)) + 2 * page_size;
  char* cp = (char*)mmap(NULL, map_size, PROT_READ | PROT_WRITE,
                         MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  test_assert(cp != MAP_FAILED);
  /* create guard pages */
  test_assert(munmap(cp, page_size) == 0);
  test_assert(munmap(cp + map_size - page_size, page_size) == 0);
  cp = cp + map_size - page_size - size;
  memcpy(cp - sizeof(GUARD_VALUE), &GUARD_VALUE, sizeof(GUARD_VALUE));
  memset(cp, value, size);
  return cp;
}

/**
 * Verify that canary value before the block allocated at 'p'
 * (of size 'size') is still valid.
 */
inline static void verify_guard(__attribute__((unused)) size_t size, void* p) {
  char* cp = (char*)p;
  test_assert(
      memcmp(cp - sizeof(GUARD_VALUE), &GUARD_VALUE, sizeof(GUARD_VALUE)) == 0);
}

/**
 * Verify that canary value before the block allocated at 'p'
 * (of size 'size') is still valid, and free the block.
 */
inline static void free_guard(size_t size, void* p) {
  verify_guard(size, p);
  size_t page_size = sysconf(_SC_PAGESIZE);
  size_t map_size = ceil_page_size(size + sizeof(GUARD_VALUE)) + 2 * page_size;
  char* cp = (char*)p + size + page_size - map_size;
  test_assert(0 == munmap(cp, map_size - 2 * page_size));
}

inline static void crash_null_deref(void) { *(volatile int*)NULL = 0; }

static char* trim_leading_blanks(char* str) {
  char* trimmed = str;
  while (isblank(*trimmed)) {
    ++trimmed;
  }
  return trimmed;
}

typedef struct map_properties {
  uint64_t start, end, offset, inode;
  int dev_major, dev_minor;
  char flags[32];
} map_properties_t;
typedef void (*maps_callback)(uint64_t env, char* name,
                              map_properties_t* props);
inline static void iterate_maps(uint64_t env, maps_callback callback,
                                FILE* maps_file) {
  while (!feof(maps_file)) {
    char line[PATH_MAX * 2];
    if (!fgets(line, sizeof(line), maps_file)) {
      break;
    }

    map_properties_t properties;
    int chars_scanned;
    int nparsed = sscanf(
        line, "%" SCNx64 "-%" SCNx64 " %31s %" SCNx64 " %x:%x %" SCNu64 " %n",
        &properties.start, &properties.end, properties.flags,
        &properties.offset, &properties.dev_major, &properties.dev_minor,
        &properties.inode, &chars_scanned);
    assert(8 /*number of info fields*/ == nparsed ||
           7 /*num fields if name is blank*/ == nparsed);

    // trim trailing newline, if any
    int last_char = strlen(line) - 1;
    if (line[last_char] == '\n') {
      line[last_char] = 0;
    }
    char* name = trim_leading_blanks(line + chars_scanned);

    callback(env, name, &properties);
  }
}

/**
 * Represents syscall params.  Makes it simpler to pass them around,
 * and avoids pushing/popping all the data for calls.
 */
struct syscall_info {
  long no;
  long args[6];
};

typedef void (*SyscallWrapper)(struct syscall_info* info);

inline static void default_syscall_wrapper(struct syscall_info* info) {
  syscall(info->no, info->args[0], info->args[1], info->args[2], info->args[3],
          info->args[4], info->args[5]);
}

/**
 * Returns a function which will execute a syscall after spending a long time
 * stuck in syscallbuf code doing nothing. Returns NULL
 */
inline static SyscallWrapper get_delayed_syscall(void) {
  SyscallWrapper ret = (SyscallWrapper)dlsym(RTLD_DEFAULT, "delayed_syscall");
  return ret ? ret : default_syscall_wrapper;
}

/**
 * Returns a function which will execute a syscall after spending a long time
 * stuck in syscallbuf code doing nothing. Returns NULL
 */
inline static SyscallWrapper get_spurious_desched_syscall(void) {
  SyscallWrapper ret =
      (SyscallWrapper)dlsym(RTLD_DEFAULT, "spurious_desched_syscall");
  return ret ? ret : default_syscall_wrapper;
}

#define ALLOCATE_GUARD(p, v) p = allocate_guard(sizeof(*p), v)
#define VERIFY_GUARD(p) verify_guard(sizeof(*p), p)
#define FREE_GUARD(p) free_guard(sizeof(*p), p)

#ifndef SECCOMP_SET_MODE_STRICT
#define SECCOMP_SET_MODE_STRICT 0
#endif
#ifndef SECCOMP_SET_MODE_FILTER
#define SECCOMP_SET_MODE_FILTER 1
#endif
#ifndef SECCOMP_FILTER_FLAG_TSYNC
#define SECCOMP_FILTER_FLAG_TSYNC 1
#endif
#ifndef SECCOMP_GET_ACTION_AVAIL
#define SECCOMP_GET_ACTION_AVAIL 2
#endif
#ifndef SECCOMP_GET_NOTIF_SIZES
#define SECCOMP_GET_NOTIF_SIZES 3
#endif

/* Old systems don't have linux/kcmp.h */
#define RR_KCMP_FILE 0
#define RR_KCMP_FILES 2

/* Old systems don't have these */
#ifndef TIOCGPKT
#define TIOCGPKT _IOR('T', 0x38, int)
#endif
#ifndef TIOCGPTLCK
#define TIOCGPTLCK _IOR('T', 0x39, int)
#endif
#ifndef TIOCGEXCL
#define TIOCGEXCL _IOR('T', 0x40, int)
#endif
#ifndef TIOCGPTPEER
#define TIOCGPTPEER _IO('T', 0x41)
#endif

#ifndef MADV_FREE
#define MADV_FREE 8
#endif

#ifndef F_OFD_GETLK
#define F_OFD_GETLK 36
#endif
#ifndef F_OFD_SETLK
#define F_OFD_SETLK 37
#endif

#ifndef PR_CAP_AMBIENT
#define PR_CAP_AMBIENT 47
#endif
#ifndef PR_CAP_AMBIENT_IS_SET
#define PR_CAP_AMBIENT_IS_SET 1
#endif
#ifndef PR_CAP_AMBIENT_RAISE
#define PR_CAP_AMBIENT_RAISE 2
#endif
#ifndef PR_CAP_AMBIENT_LOWER
#define PR_CAP_AMBIENT_LOWER 3
#endif
#ifndef PR_CAP_AMBIENT_CLEAR_ALL
#define PR_CAP_AMBIENT_CLEAR_ALL 4
#endif

#ifndef PR_GET_SPECULATION_CTRL
#define PR_GET_SPECULATION_CTRL 52
#endif
#ifndef PR_SET_SPECULATION_CTRL
#define PR_SET_SPECULATION_CTRL 53
#endif
#ifndef PR_SPEC_STORE_BYPASS
#define PR_SPEC_STORE_BYPASS 0
#endif
#ifndef PR_SPEC_NOT_AFFECTED
#define PR_SPEC_NOT_AFFECTED 0
#endif
#ifndef PR_SPEC_PRCTL
#define PR_SPEC_PRCTL 1
#endif
#ifndef PR_SPEC_ENABLE
#define PR_SPEC_ENABLE 2
#endif
#ifndef PR_SPEC_DISABLE
#define PR_SPEC_DISABLE 4
#endif
#ifndef PR_SPEC_FORCE_DISABLE
#define PR_SPEC_FORCE_DISABLE 8
#endif

#endif /* RRUTIL_H */
