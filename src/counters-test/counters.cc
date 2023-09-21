#include <errno.h>
#include <fcntl.h>
#include <linux/perf_event.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(condition) \
  do { \
    if (!(condition)) { \
      fprintf(stderr, "CHECK '%s' failed at %s:%d (errno=%d)\n", #condition, __FILE__, __LINE__, errno); \
      abort(); \
    } \
  } while (0)

static void die(const char* msg) {
  fprintf(stderr, "%s\n", msg);
  abort();
}

/* ==== Copied from PerfCounters.cc ==== */

/*
 * Find out the cpu model using the cpuid instruction.
 * Full list of CPUIDs at http://sandpile.org/x86/cpuid.htm
 * Another list at
 * http://software.intel.com/en-us/articles/intel-architecture-and-processor-identification-with-cpuid-model-and-family-numbers
 */
typedef enum {
  UnknownCpu,
  FirstIntel,
  IntelMerom = FirstIntel,
  IntelPenryn,
  IntelNehalem,
  IntelWestmere,
  IntelSandyBridge,
  IntelIvyBridge,
  IntelHaswell,
  IntelBroadwell,
  IntelSkylake,
  IntelSilvermont,
  IntelGoldmont,
  IntelKabylake,
  IntelCometlake,
  IntelIcelake,
  IntelTigerlake,
  IntelAlderlake,
  LastIntel = IntelAlderlake,
  FirstAMD,
  AMDF15R30 = FirstAMD,
  AMDZen,
  LastAMD = AMDZen,
  FirstARM,
  ARMNeoverseN1 = FirstARM,
  LastARM = ARMNeoverseN1,
} CpuMicroarch;

/*
 * Set if this CPU supports ticks counting retired conditional branches.
 */
#define PMU_TICKS_RCB (1<<0)

/*
 * Some CPUs turn off the whole PMU when there are no remaining events
 * scheduled (perhaps as a power consumption optimization). This can be a
 * very expensive operation, and is thus best avoided. For cpus, where this
 * is a problem, we keep a cycles counter (which corresponds to one of the
 * fixed function counters, so we don't use up a programmable PMC) that we
 * don't otherwise use, but keeps the PMU active, greatly increasing
 * performance.
 */
#define PMU_BENEFITS_FROM_USELESS_COUNTER (1<<1)

/*
 * Set if this CPU supports ticks counting all taken branches
 * (excluding interrupts, far branches, and rets).
 */
#define PMU_TICKS_TAKEN_BRANCHES (1<<3)

struct PmuConfig {
  CpuMicroarch uarch;
  const char* name;
  unsigned rcb_cntr_event;
  unsigned minus_ticks_cntr_event;
  unsigned hw_intr_cntr_event;
  unsigned llsc_cntr_event;
  uint32_t skid_size;
  uint32_t flags;
};

// XXX please only edit this if you really know what you're doing.
// event = 0x5101c4:
// - 51 = generic PMU
// - 01 = umask for event BR_INST_RETIRED.CONDITIONAL
// - c4 = eventsel for event BR_INST_RETIRED.CONDITIONAL
// event = 0x5301cb:
// - 51 = generic PMU
// - 01 = umask for event HW_INTERRUPTS.RECEIVED
// - cb = eventsel for event HW_INTERRUPTS.RECEIVED
// See Intel 64 and IA32 Architectures Performance Monitoring Events.
// See check_events from libpfm4.
static const PmuConfig pmu_configs[] = {
  { IntelAlderlake, "Intel Alderlake", 0x5111c4, 0, 0, 0, 100, PMU_TICKS_RCB },
  { IntelTigerlake, "Intel Tigerlake", 0x5111c4, 0, 0, 0, 100, PMU_TICKS_RCB },
  { IntelIcelake, "Intel Icelake", 0x5111c4, 0, 0, 0, 100, PMU_TICKS_RCB },
  { IntelCometlake, "Intel Cometlake", 0x5101c4, 0, 0x5301cb, 0, 100, PMU_TICKS_RCB },
  { IntelKabylake, "Intel Kabylake", 0x5101c4, 0, 0x5301cb, 0, 100, PMU_TICKS_RCB },
  { IntelSilvermont, "Intel Silvermont", 0x517ec4, 0, 0x5301cb, 0, 100, PMU_TICKS_RCB },
  { IntelGoldmont, "Intel Goldmont", 0x517ec4, 0, 0x5301cb, 0, 100, PMU_TICKS_RCB },
  { IntelSkylake, "Intel Skylake", 0x5101c4, 0, 0x5301cb, 0, 100, PMU_TICKS_RCB },
  { IntelBroadwell, "Intel Broadwell", 0x5101c4, 0, 0x5301cb, 0, 100, PMU_TICKS_RCB },
  { IntelHaswell, "Intel Haswell", 0x5101c4, 0, 0x5301cb, 0, 100, PMU_TICKS_RCB },
  { IntelIvyBridge, "Intel Ivy Bridge", 0x5101c4, 0, 0x5301cb, 0, 100, PMU_TICKS_RCB },
  { IntelSandyBridge, "Intel Sandy Bridge", 0x5101c4, 0, 0x5301cb, 0, 100, PMU_TICKS_RCB },
  { IntelNehalem, "Intel Nehalem", 0x5101c4, 0, 0x50011d, 0, 100, PMU_TICKS_RCB },
  { IntelWestmere, "Intel Westmere", 0x5101c4, 0, 0x50011d, 0, 100, PMU_TICKS_RCB },
  { IntelPenryn, "Intel Penryn", 0, 0, 0, 0, 100, 0 },
  { IntelMerom, "Intel Merom", 0, 0, 0, 0, 100, 0 },
  { AMDF15R30, "AMD Family 15h Revision 30h", 0xc4, 0xc6, 0, 0, 250, PMU_TICKS_TAKEN_BRANCHES },
  // 0xd1 == RETIRED_CONDITIONAL_BRANCH_INSTRUCTIONS - Number of retired conditional branch instructions
  // 0x2c == INTERRUPT_TAKEN - Counts the number of interrupts taken
  // Both counters are available on Zen, Zen+ and Zen2.
  { AMDZen, "AMD Zen", 0x5100d1, 0, 0x51002c, 0, 10000, PMU_TICKS_RCB },
  // 0x21 == BR_RETIRED - Architecturally retired taken branches
  // 0x6F == STREX_SPEC - Speculatively executed strex instructions
  { ARMNeoverseN1, "ARM Neoverse N1", 0x21, 0, 0, 0x6F, 1000, PMU_TICKS_TAKEN_BRANCHES }
};

/* ==== End copying from PerfCounters.cc ==== */

/* ==== Copied from util.h ==== */

typedef struct {
  uint32_t eax, ebx, ecx, edx;
} CPUIDData;

typedef enum  {
  CPUID_GETVENDORSTRING,
  CPUID_GETFEATURES,
  CPUID_GETTLB,
  CPUID_GETSERIAL,
  CPUID_GETCACHEPARAMS = 0x04,
  CPUID_GETEXTENDEDFEATURES = 0x07,
  CPUID_GETEXTENDEDTOPOLOGY = 0x0B,
  CPUID_GETXSAVE = 0x0D,
  CPUID_GETRDTMONITORING = 0x0F,
  CPUID_GETRDTALLOCATION = 0x10,
  CPUID_GETSGX = 0x12,
  CPUID_GETPT = 0x14,
  CPUID_GETSOC = 0x17,
  CPUID_HYPERVISOR = 0x40000000,
  CPUID_INTELEXTENDED = 0x80000000,
  CPUID_INTELFEATURES,
  CPUID_INTELBRANDSTRING,
  CPUID_INTELBRANDSTRINGMORE,
  CPUID_INTELBRANDSTRINGEND,
  CPUID_AMD_CACHE_TOPOLOGY = 0x8000001D,
  CPUID_AMD_PLATFORM_QOS = 0x80000020
} cpuid_requests;

/* ==== End copying from util.h ==== */

/* ==== Copied from util.cc ==== */

CPUIDData cpuid(uint32_t code, uint32_t subrequest) {
  CPUIDData result;
  asm volatile("cpuid"
               : "=a"(result.eax), "=b"(result.ebx), "=c"(result.ecx),
                 "=d"(result.edx)
               : "a"(code), "c"(subrequest));
  return result;
}

/* ==== End copying from util.cc === */

/* ==== Copied from PerfCounters_x86.h ==== */

/**
 * Return the detected, known microarchitecture of this CPU, or don't
 * return; i.e. never return UnknownCpu.
 */
static CpuMicroarch compute_cpu_microarch(void) {
  CPUIDData cpuid_vendor = cpuid(CPUID_GETVENDORSTRING, 0);
  char vendor[12];
  memcpy(&vendor[0], &cpuid_vendor.ebx, 4);
  memcpy(&vendor[4], &cpuid_vendor.edx, 4);
  memcpy(&vendor[8], &cpuid_vendor.ecx, 4);
  if (strncmp(vendor, "GenuineIntel", sizeof(vendor)) &&
      strncmp(vendor, "AuthenticAMD", sizeof(vendor))) {
    die("Unknown CPU vendor");
  }

  CPUIDData cpuid_data = cpuid(CPUID_GETFEATURES, 0);
  unsigned int cpu_type = cpuid_data.eax & 0xF0FF0;
  unsigned int ext_family = (cpuid_data.eax >> 20) & 0xff;
  switch (cpu_type) {
    case 0x006F0:
    case 0x10660:
      return IntelMerom;
    case 0x10670:
    case 0x106D0:
      return IntelPenryn;
    case 0x106A0:
    case 0x106E0:
    case 0x206E0:
      return IntelNehalem;
    case 0x20650:
    case 0x206C0:
    case 0x206F0:
      return IntelWestmere;
    case 0x206A0:
    case 0x206D0:
    case 0x306e0:
      return IntelSandyBridge;
    case 0x306A0:
      return IntelIvyBridge;
    case 0x306C0: /* Devil's Canyon */
    case 0x306F0:
    case 0x40650:
    case 0x40660:
      return IntelHaswell;
    case 0x306D0:
    case 0x40670:
    case 0x406F0:
    case 0x50660:
      return IntelBroadwell;
    case 0x406e0:
    case 0x50650:
    case 0x506e0:
      return IntelSkylake;
    case 0x30670:
    case 0x406c0:
    case 0x50670:
      return IntelSilvermont;
    case 0x506f0:
    case 0x506c0:
      return IntelGoldmont;
    case 0x706e0:
    case 0x606a0:
      return IntelIcelake;
    case 0x806c0:
    case 0x806d0:
      return IntelTigerlake;
    case 0x806e0:
    case 0x906e0:
      return IntelKabylake;
    case 0xa0650:
    case 0xa0660:
	return IntelCometlake;
    case 0x90670:
      return IntelAlderlake;
    case 0x30f00:
      return AMDF15R30;
    case 0x00f10: // Naples, Whitehaven, Summit Ridge, Snowy Owl (Zen), Milan (Zen 3) (UNTESTED)
    case 0x10f10: // Raven Ridge, Great Horned Owl (Zen) (UNTESTED)
    case 0x10f80: // Banded Kestrel (Zen), Picasso (Zen+) (UNTESTED)
    case 0x20f00: // Dali (Zen) (UNTESTED)
    case 0x00f80: // Colfax, Pinnacle Ridge (Zen+) (UNTESTED)
    case 0x30f10: // Rome, Castle Peak (Zen 2)
    case 0x60f00: // Renoir (Zen 2) (UNTESTED)
    case 0x70f10: // Matisse (Zen 2) (UNTESTED)
    case 0x60f80: // Lucienne
      if (ext_family == 8 || ext_family == 0xa) {
        return AMDZen;
      } else if (ext_family == 3) {
        return AMDF15R30;
      }
      break;
    case 0x20f10: // Vermeer (Zen 3)
    case 0x50f00: // Cezanne (Zen 3)
      if (ext_family == 0xa) {
        return AMDZen;
      }
    default:
      break;
  }

  if (!strncmp(vendor, "AuthenticAMD", sizeof(vendor))) {
    die("AMD CPU type unknown");
  } else {
    die("Intel CPU type unknown");
  }
  return UnknownCpu; // not reached
}

/* ==== End copying from PerfCounters_x86.h ==== */

static int parent_to_child_fds[2];
static int child_to_parent_fds[2];

/* Tell the parent we're ready, then wait for the parent to signal us,
   without executing any conditional branches */
static void child_wait(void) {
  /* write(child_to_parent_fds[1], buf, 1) */
  /* Use hand-rolled syscalls to avoid conditional branches (e.g. setting errno) */
  __asm__ __volatile__ ("syscall" : : "a"(__NR_write), "D"(child_to_parent_fds[1]), "S"("x"), "d"(1) : "rcx", "r11", "flags");
  char buf;
  /* read(parent_to_child_fds[0], buf, 1) */
  __asm__ __volatile__ ("syscall" : : "a"(__NR_read), "D"(parent_to_child_fds[0]), "S"(&buf), "d"(1) : "rcx", "r11", "flags");
}

#define NUM_ITERATIONS_BASIC 100000
#define NUM_VOLATILE_UPDATES 1000
#define NUM_ITERATIONS_SYSCALLS 100000

static volatile long volatile_value;

void test_ticks_basic(void) {
  int i, j;
  for (i = 0; i < NUM_ITERATIONS_BASIC; ++i) {
    child_wait();
    volatile_value = 0;
    for (j = 0; j < NUM_VOLATILE_UPDATES; ++j) {
      ++volatile_value;
    }
  }
  child_wait();
}

void test_ticks_syscalls(void) {
  int i, j;
  char buf[1024];
  for (i = 0; i < NUM_ITERATIONS_SYSCALLS; ++i) {
    child_wait();
    size_t buflen = i % sizeof(buf);
    /* Use hand-rolled syscalls to avoid conditional branches (e.g. setting errno) */
    __asm__ __volatile__ ("syscall" : : "a"(__NR_getrandom), "D"(buf), "S"(buflen), "d"(0) : "rcx", "r11", "flags");
    __asm__ __volatile__ ("syscall" : : "a"(__NR_sched_yield) : "rcx", "r11", "flags");
  }
  child_wait();
}

void sighandler(int sig) {
  child_wait();
}

void test_interrupts(void) {
  /* wait for the parent to set the period */
  child_wait();
  /* Sync with the parent every time we get a signal */
  signal(SIGIO, sighandler);
  volatile_value = 0;
  /* Loop forever. Eventually the parent will kill us. */
  while (!volatile_value) {
  }
}

static int do_child(void) {
  test_ticks_basic();
  test_ticks_syscalls();
  test_interrupts();
  return 0;
}

typedef uint64_t Ticks;

static void check_ticks(Ticks got, Ticks expected) {
  if (got != expected) {
    fprintf(stderr, "Ticks mismatch; got %lld, expected %lld\n", (long long)got, (long long)expected);
    abort();
  }
}

/* Wait for child to pause, read counter value, reset the counter value,
   resume the child, and report the read counter value */
static Ticks reset_counting(pid_t child, int counter_fd, uint64_t period) {
  char ch;
  CHECK(1 == read(child_to_parent_fds[0], &ch, 1));
  CHECK(ch == 'x');
  Ticks ticks;
  CHECK(sizeof(ticks) == read(counter_fd, &ticks, sizeof(ticks)));
  CHECK(0 == ioctl(counter_fd, PERF_EVENT_IOC_DISABLE, 0));
  CHECK(0 == ioctl(counter_fd, PERF_EVENT_IOC_RESET, 0));
  CHECK(0 == ioctl(counter_fd, PERF_EVENT_IOC_PERIOD, &period));
  CHECK(0 == ioctl(counter_fd, PERF_EVENT_IOC_ENABLE, 0));
  CHECK(1 == write(parent_to_child_fds[1], "y", 1));
  return ticks;
}

#define MAX_PERIOD 0x1000000000000000LL

int main(int argc, char** argv) {
  int interrupt_tests = 1;
  int interrupt_period = 1000000;

  if (argc > 1) {
    interrupt_tests = atoi(argv[1]);
  }
  if (argc > 2) {
    interrupt_period = atoi(argv[2]);
  }

  CpuMicroarch uarch = compute_cpu_microarch();

  const PmuConfig* pmu = NULL;
  for (size_t i = 0; i < sizeof(pmu_configs)/sizeof(pmu_configs[0]); ++i) {
    if (uarch == pmu_configs[i].uarch) {
      pmu = &pmu_configs[i];
      break;
    }
  }
  CHECK(pmu);

  CHECK(0 == pipe(parent_to_child_fds));
  CHECK(0 == pipe(child_to_parent_fds));

  pid_t child = fork();
  if (!child) {
    return do_child();
  }
  CHECK(child >= 0);

  struct perf_event_attr perf_attr;
  memset(&perf_attr, 0, sizeof(perf_attr));
  perf_attr.type = PERF_TYPE_RAW;
  perf_attr.size = sizeof(perf_attr);
  perf_attr.config = pmu->rcb_cntr_event;
  perf_attr.exclude_kernel = 1;
  perf_attr.exclude_guest = 1;
  perf_attr.pinned = 1;
  perf_attr.sample_period = MAX_PERIOD;

  int counter_fd = syscall(__NR_perf_event_open, &perf_attr, child, -1, -1, PERF_FLAG_FD_CLOEXEC);
  CHECK(counter_fd >= 0);

  reset_counting(child, counter_fd, MAX_PERIOD);
  for (int i = 0; i < NUM_ITERATIONS_BASIC; ++i) {
    Ticks ticks = reset_counting(child, counter_fd, MAX_PERIOD);
    /* NUM_VOLATILE_UPDATES conditional branches for the inner loop, plus one conditional branch
       for the outer loop. */
    int expect;
    if (i == 0) {
      if (ticks == NUM_VOLATILE_UPDATES + 1) {
        expect = ticks;
      } else {
        expect = NUM_VOLATILE_UPDATES + 2;
      }
    } else {
      expect = NUM_VOLATILE_UPDATES + 2;
    }
    check_ticks(ticks, expect);
  }

  reset_counting(child, counter_fd, MAX_PERIOD);
  for (int i = 0; i < NUM_ITERATIONS_SYSCALLS; ++i) {
    Ticks ticks = reset_counting(child, counter_fd, MAX_PERIOD);
    /* One conditional branch for the outer loop. */
    check_ticks(ticks, 1);
  }

  /* program an interrupt */
  CHECK(0 == fcntl(counter_fd, F_SETOWN, child));
  CHECK(0 == fcntl(counter_fd, F_SETFL, O_ASYNC));

  reset_counting(child, counter_fd, interrupt_period);
  for (int i = 0; i < interrupt_tests; ++i) {
    char ch;
    CHECK(1 == read(child_to_parent_fds[0], &ch, 1));
    CHECK(ch == 'x');
    Ticks ticks;
    CHECK(sizeof(ticks) == read(counter_fd, &ticks, sizeof(ticks)));
    printf("Interrupted after %lld ticks, expected %lld ticks\n", (long long)ticks, (long long)interrupt_period);
    CHECK(ticks >= interrupt_period);
    if (ticks > interrupt_period + pmu->skid_size) {
      fprintf(stderr, "Skid %d exceeded :-(\n", pmu->skid_size);
      abort();
    }
    CHECK(0 == ioctl(counter_fd, PERF_EVENT_IOC_RESET, 0));
    CHECK(1 == write(parent_to_child_fds[1], "y", 1));
  }

  kill(child, SIGKILL);
  int status;
  CHECK(child == waitpid(child, &status, 0));
  CHECK(WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);

  puts("EXIT-SUCCESS");

  return 0;
}
