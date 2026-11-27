/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

#define LOG_TEST_FUNC_NAME                                                     \
  _ZN7mozilla6detail8log_testEPKNS_9LogModuleENS_8LogLevelE

static void my_print(const char* p) {
  ssize_t len = strlen(p);
  ssize_t ret = write(STDOUT_FILENO, p, len);
  test_assert(ret == len);
}

static void my_print_err(const char* p) {
  ssize_t len = strlen(p);
  ssize_t ret = write(STDERR_FILENO, p, len);
  test_assert(ret == len);
}

typedef struct { char* module_name; int level; } FakeLogModule;

__attribute__((noinline)) int LOG_TEST_FUNC_NAME(__attribute__((unused))
                                                 FakeLogModule* module) {
  return 0;
}

__attribute__((noinline)) void early_exit_print(void) {
  my_print("early_exit-OK\n");
}

static FakeLogModule module = { "TestMod", 0 };

#define LOG_TEST_FUNC() LOG_TEST_FUNC_NAME(&module)

int test_var;

static void do_stosb(void* p, size_t size) {
#if defined(__i386__) || defined(__x86_64__)
  __asm__("rep stosb\n\t" ::"a"(1), "c"(size), "D"(p));
#endif
}

extern void early_exit(FakeLogModule* module);
/* Test non-rejoining control flow (rejoins only on return) */
asm("early_exit: call "
    "_ZN7mozilla6detail8log_testEPKNS_9LogModuleENS_8LogLevelE\n\t"
    "test %al,%al\n\t"
    "je 1f\n\t"
    "jmp early_exit_print\n\t"
    "1: ret\n\t");

void do_unsupported_thing(void) {
  pid_t child = fork();
  int status;
  if (!child) {
    exit(77);
  }
  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);
}

__attribute__((noinline)) void duplicated_print(void) {
  my_print("duplicated-OK\n");
}

extern void duplicated_instructions(FakeLogModule* module);
/* Test non-rejoining control flow (rejoins only on return) */
asm("duplicated_instructions: call "
    "_ZN7mozilla6detail8log_testEPKNS_9LogModuleENS_8LogLevelE\n\t"
    "test %al,%al\n\t"
    "je 1f\n\t"
    "call duplicated_print\n\t"
    "jmp 2f\n\t"
    "1: mov $1,%al\n\t"
    "2: call do_unsupported_thing\n\t"
    "ret\n\t");

__attribute__((noinline)) void setne_print(void) {
  my_print("setne-OK\n");
}

static void* do_thread(__attribute__((unused)) void* p) {
  return NULL;
}

extern void setne_test(FakeLogModule* module);
/* Test setne usage in log test */
asm("setne_test: call "
    "_ZN7mozilla6detail8log_testEPKNS_9LogModuleENS_8LogLevelE\n\t"
    "test %eax,%eax\n\t"
    "setne %al\n\t"
    "test %al,%al\n\t"
    "je 1f\n\t"
    "call setne_print\n\t"
    "1: ret\n\t");

__attribute__((noinline)) void inner_setjmp(jmp_buf env) { longjmp(env, 1); }

__attribute__((noinline)) void test_setjmp(void) {
  jmp_buf env;
  if (setjmp(env)) {
    return;
  }
  inner_setjmp(env);
}

static pid_t my_gettid(void) { return (pid_t)syscall(SYS_gettid); }

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

static void do_simple_syscall(void) {
#if defined(__x86_64__)
  __asm__("syscall\n\t"
          "test %%rax,%%rax\n\t"
          "jl 1f\n\t"
          "nop\n\t"
          "1:\n\t"
          ::"a"(SYS_getsid) : "%rcx", "%r11");
#endif
}

static void do_getpid_loop(void) {
#if defined(__x86_64__)
  __asm__("1: mov %%rsi,%%rax\n\t"
          "syscall\n\t"
          "nop\n\t"
          "nop\n\t"
          "nop\n\t"
          "dec %%rdi\n\t"
          "jne 1b\n\t"
          :: "S"(SYS_getpid), "D"(1000000) : "%rax", "%rcx", "%r11");
#endif
}

const uint64_t buf[4] = { 100, 200, 300, 400 };
const uint64_t buf2[4] = { 66, 66, 66, 66 };
uint64_t buf3[4];

static void test_ymm(void) {
#if defined(__x86_64__)
  int i;
  __asm__ __volatile__("vmovdqu buf(%rip),%ymm1\n");
  if (LOG_TEST_FUNC()) {
    __asm__ __volatile__("vmovdqu buf2(%rip),%ymm1\n");
  }
  __asm__ __volatile__("vmovdqu %ymm1,buf3(%rip)\n");
  for (i = 0; i < 4; ++i) {
    test_assert(buf3[i] == buf[i]);
  }
#endif
}

static void use_lots_of_stack(void) {
  char buf[0x80000];
  sprintf(buf, "%s-OK", "Stack");
  atomic_puts(buf);
}

char x87_buf[10] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

extern void x87_func(void);

extern void x87_func2(void);

static void* get_fip(void) {
  __attribute__((aligned(16))) char fxsave_buf[512];
#if defined(__x86_64__)
  asm volatile ("fxsave64 (%0)" :: "r"(fxsave_buf) : "memory");
#else
  asm volatile ("fxsave (%0)" :: "r"(fxsave_buf) : "memory");
#endif
  return *(void**)(fxsave_buf + 8);
}

void cpuid(void) {
  int cx = 0;
  asm volatile ("cpuid\n\t"
                : "=c"(cx) : "a"(0));
  if (cx == 0) {
    /* This should not be reached */
    my_print_err("unexpected ECX");
  }
}

char* write_buf;

void do_many_writes(void) {
  static const int SIZE = 1000000;
  write_buf =
    (char*)mmap(NULL, SIZE, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  int i;
  for (i = 0; i < SIZE; ++i) {
    write_buf[i] = i*99;
    *(uint16_t*)(write_buf + i) = i*101;
  }
  my_print("many_writes-OK\n");
}

typedef char (* ChromiumLogMessageHandler)(int, const char*, int, size_t, void*);
ChromiumLogMessageHandler _ZN7logging12_GLOBAL__N_119log_message_handlerE;
char _ZN7logging12_GLOBAL__N_121g_logging_destinationE;
char _ZN7logging12_GLOBAL__N_115g_log_timestampE = 1;
char _ZN7logging12_GLOBAL__N_115g_log_tickcountE = 1;

void _ZN7logging10LogMessageD1Ev(const char* msg) {
  if (_ZN7logging12_GLOBAL__N_119log_message_handlerE &&
      _ZN7logging12_GLOBAL__N_119log_message_handlerE(0, "./Chromium.cpp", 1, 0, NULL)) {
    return;
  }
  if (_ZN7logging12_GLOBAL__N_121g_logging_destinationE & 2) {
    my_print(msg);
  }
}

int _ZN7logging18GetVlogLevelHelperEPKcm(void) {
  return -1;
}

int chromium_get_vlog_verbosity(void) {
  return _ZN7logging18GetVlogLevelHelperEPKcm();
}

#define CHROMIUM_LOG_MESSAGE _ZN7logging10LogMessageD1Ev

void print_chromium_message2(void) {
  CHROMIUM_LOG_MESSAGE("Chromium-LogMessage2-OK\n");
}

void print_chromium_message3(void) {
  CHROMIUM_LOG_MESSAGE("Chromium-LogMessage3-OK\n");
}

void chromium_test1(void) {
  if (1 <= chromium_get_vlog_verbosity() &&
      !_ZN7logging12_GLOBAL__N_115g_log_timestampE &&
      !_ZN7logging12_GLOBAL__N_115g_log_tickcountE) {
    CHROMIUM_LOG_MESSAGE("Chromium-LogMessage-OK\n");
  }
}

void chromium_test2(void) {
  asm ("call chromium_get_vlog_verbosity\n\t"
       "mov $1,%%ecx\n\t"
       "cmp %%ecx,%%eax\n\t"
       "jl 1f\n\t"
       "call print_chromium_message2\n\t"
       "1:" : : : "ecx", "eax");
}

void chromium_test3(void) {
  asm ("call chromium_get_vlog_verbosity\n\t"
       "mov $1,%%ecx\n\t"
       "cmp %%eax,%%ecx\n\t"
       "jg 1f\n\t"
       "call print_chromium_message3\n\t"
       "1:" : : : "ecx", "eax");
}

void chromium_test4(void) {
  if (1 <= chromium_get_vlog_verbosity() &&
      1 <= chromium_get_vlog_verbosity()) {
    CHROMIUM_LOG_MESSAGE("Chromium-LogMessage4-OK\n");
  }
}

struct ChromiumDiagnosticLogMessage {
  void* dummy1;
  void* dummy2;
  void* dummy3;
  void* dummy4;
  char log_to_chrome;
};

void _ZN3rtc20DiagnosticLogMessageD1Ev(struct ChromiumDiagnosticLogMessage* value) {
  if (value->log_to_chrome) {
    CHROMIUM_LOG_MESSAGE("Chromium-DiagnosticLogMessage-OK\n");
  }
}

void chromium_diagnostic_log_message(void) {
  struct ChromiumDiagnosticLogMessage msg;
  msg.log_to_chrome = 0;
  _ZN3rtc20DiagnosticLogMessageD1Ev(&msg);
}

static void failed_diversion(void) {
  syscall(-66);
}

static void getrlimit_probe(void) {
  // glibc turns getrlimit() into prlimit(), but we want to test getrlimit()
  // so do it directly
  if (!syscall(SYS_getrlimit, RLIMIT_NPROC, (struct rlimit*)getrlimit_probe) ||
      errno != EFAULT) {
    failed_diversion();
  }
  my_print("getrlimit-OK\n");
}

static void do_mprotect(void) {
  void* p = mmap(NULL, 1, PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  int ret = mprotect(p, 1, PROT_READ | PROT_WRITE);
  if (ret) {
    failed_diversion();
  }
  *(char*)p = 7;
  my_print("mprotect-OK\n");
}

static void do_madvise(void) {
  void* p = mmap(NULL, 1, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  *(char*)p = 7;
  int ret = madvise(p, 1, MADV_DONTNEED);
  if (ret) {
    failed_diversion();
  }
  if (*(char*)p) {
    failed_diversion();
  }
  ret = madvise(p, 1, MADV_FREE);
  if (ret) {
    failed_diversion();
  }
  my_print("madvise-OK\n");
}

int main(void) {
  int status;
  size_t i;
  int count;
  void* fip;
  char* mapped_page;
  size_t page_size = sysconf(_SC_PAGESIZE);
  pid_t tid = my_gettid();
  pid_t child = fork();
  if (!child) {
    child = getpid();
    if (LOG_TEST_FUNC()) {
      test_assert(child == getpid());
      my_print("Forked-OK\n");
    }
    return 77;
  }
  pthread_t thread;

  mapped_page = (char*)mmap(NULL, 2 * page_size, PROT_READ | PROT_WRITE,
                            MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  test_assert(mapped_page != MAP_FAILED);
  test_assert(0 == munmap(mapped_page + page_size, page_size));

  test_assert(child == waitpid(child, &status, 0));
  test_assert(WIFEXITED(status) && WEXITSTATUS(status) == 77);

  test_setjmp();

  for (count = 0; count < 2; ++count) {
    struct timespec ts = { 1, 1 };
    struct timeval tv = { 1, 1 };
    struct timezone tz = { 1, 1 };
    if (LOG_TEST_FUNC()) {
      int inner_count;
      void* p = mmap(NULL, 100, PROT_READ | PROT_WRITE,
                     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
      test_assert(p != MAP_FAILED);
      test_assert(0 == munmap(p, 100));

      test_assert(0 == clock_gettime(CLOCK_MONOTONIC, &ts));
      test_assert(0 == gettimeofday(&tv, &tz));
      test_assert(my_gettid() == tid);
      my_print("clock_gettime-OK\n");
      test_var = 1;
      for (inner_count = 0; inner_count < 100000; ++inner_count) {
        do_stosb(mapped_page, page_size);
      }
    }
    test_assert(ts.tv_sec == 1 && ts.tv_nsec == 1);
    test_assert(tv.tv_sec == 1 && tv.tv_usec == 1);
    test_assert(tz.tz_minuteswest == 1 && tz.tz_dsttime == 1);
  }

  pthread_mutex_lock(&lock);
  if (LOG_TEST_FUNC()) {
    /* Should trigger immediate abort */
    pthread_mutex_lock(&lock);
  }

  if (LOG_TEST_FUNC()) {
    /* Should safely bail out */
    rdtsc();
  }
  if (LOG_TEST_FUNC()) {
    /* Make sure repeated calls are OK */
    rdtsc();
  }
  /* Test cpuid when the first hit was outside a diversion */
  cpuid();
  if (LOG_TEST_FUNC()) {
    /* Should safely bail out */
    cpuid();
  }
  /* Make sure repeated calls are OK */
  cpuid();

  if (LOG_TEST_FUNC()) {
    do_simple_syscall();
  }
  do_simple_syscall();

  /* Test that flushing translated FIP in a diversion doesn't cause us to
     forget to flush non-diversion FIP */
  asm volatile ("x87_func: fld (%0)" :: "r"(x87_buf));
  if (LOG_TEST_FUNC()) {
    asm ("xsave %2" :: "d"(0), "a"(0x5), "m"(*mapped_page));
  }
  fip = get_fip();
  test_assert(fip == x87_func);

  /* Test that running x87 code in a diversion doesn't leave a pending
     flush to be processed outside the diversion */
  if (LOG_TEST_FUNC()) {
    asm volatile ("x87_func2: fld (%0)" :: "r"(x87_buf));
  }
  fip = get_fip();
  test_assert(fip == x87_func);

  if (LOG_TEST_FUNC()) {
    asm("ud2");
  }
  if (LOG_TEST_FUNC()) {
    *(volatile char*)0 = 0;
  }
  if (LOG_TEST_FUNC()) {
    asm("int3");
  }

  test_assert(test_var == 0);
  for (i = 0; i < page_size; ++i) {
    test_assert(mapped_page[i] == 0);
  }

  early_exit(&module);
  duplicated_instructions(&module);
  setne_test(&module);

  if (LOG_TEST_FUNC()) {
    if (LOG_TEST_FUNC()) {
      my_print("Nested-OK\n");
    }
  }

  if (LOG_TEST_FUNC()) {
    my_print("");
  }

  if (LOG_TEST_FUNC()) {
    use_lots_of_stack();
  }

  if (LOG_TEST_FUNC()) {
    do_many_writes();
  }

  if (LOG_TEST_FUNC()) {
    getrlimit_probe();
  }

  if (LOG_TEST_FUNC()) {
    do_mprotect();
  }

  if (LOG_TEST_FUNC()) {
    do_madvise();
  }

  test_ymm();

  /* Ensure stack tracking through syscallbuf handles returns correctly. */
  do_getpid_loop();

  pthread_create(&thread, NULL, do_thread, NULL);
  pthread_join(thread, NULL);

  /* This doesn't really matter since writes to stdout/stderr aren't buffered
     anyway. If we later want to catch writing to other fds, we'll have to
     start locking syscallbuf during microdiversions. */
  my_print("Enabling syscallbuf of write()\n");

  chromium_test1();
  chromium_test2();
  chromium_test3();
  chromium_test4();
  chromium_diagnostic_log_message();

  if (LOG_TEST_FUNC()) {
    my_print("EXIT-SUCCESS\n");
  }
  return 0;
}
