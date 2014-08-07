/* -*- Mode: C++; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "hpc.h"

#include <assert.h>
#include <fcntl.h>
#include <linux/perf_event.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <sys/select.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <algorithm>
#include <fstream>
#include <string>

#include "log.h"
#include "task.h"
#include "util.h"

using namespace std;

struct hpc_event_t {
	struct perf_event_attr attr;
	int fd;
};

struct hpc_context {
	bool started;
	int group_leader;

	hpc_event_t rbc;
#ifdef HPC_ENABLE_EXTRA_PERF_COUNTERS
	hpc_event_t inst;
	hpc_event_t page_faults;
	hpc_event_t hw_int;
#endif
};

/*
 * Find out the cpu model using the cpuid instruction.
 * Full list of CPUIDs at http://sandpile.org/x86/cpuid.htm
 * Another list at http://software.intel.com/en-us/articles/intel-architecture-and-processor-identification-with-cpuid-model-and-family-numbers
 */
enum CpuMicroarch {
	UnknownCpu,
	IntelMerom,
	IntelPenryn,
	IntelNehalem,
	IntelWestmere,
	IntelSandyBridge,
	IntelIvyBridge,
	IntelHaswell
};

struct PmuConfig {
	CpuMicroarch uarch;
	const char* name;
	unsigned rcb_cntr_event;
	unsigned rinsn_cntr_event;
	unsigned hw_intr_cntr_event;
	bool supported;
};

// XXX please only edit this if you really know what you're doing.
PmuConfig pmu_configs[] = {
	{ IntelHaswell, "Intel Haswell",
	  0x5101c4, 0x5100c0, 0x5301cb, true },
	{ IntelIvyBridge, "Intel Ivy Bridge",
	  0x5101c4, 0x5100c0, 0x5301cb, true },
	{ IntelSandyBridge, "Intel Sandy Bridge",
	  0x5101c4, 0x5100c0, 0x5301cb, true },
	{ IntelNehalem, "Intel Nehalem",
	  0x5101c4, 0x5100c0, 0x50011d, true },
	{ IntelWestmere, "Intel Westmere",
	  0x5101c4, 0x5100c0, 0x50011d, true },

	{ IntelPenryn, "Intel Penryn", 0, 0, 0, false },
	{ IntelMerom, "Intel Merom", 0, 0, 0, false },
};

static string lowercase(const string& s)
{
	string c = s;
	transform(c.begin(), c.end(), c.begin(), ::tolower);
	return c;
}

/**
 * Return the detected, known microarchitecture of this CPU, or don't
 * return; i.e. never return UnknownCpu.
 */
static CpuMicroarch get_cpu_microarch()
{
	string forced_uarch = lowercase(rr_flags()->forced_uarch);
	if (!forced_uarch.empty()) {
		for (size_t i = 0; i < ALEN(pmu_configs); ++i) {
			const PmuConfig& pmu = pmu_configs[i];
			string name = lowercase(pmu.name);
			if (name.npos != name.find(forced_uarch)) {
				LOG(info) <<"Using forced uarch "<< pmu.name;
				return pmu.uarch;
			}
		}
		FATAL() <<"Forced uarch "<< rr_flags()->forced_uarch <<" isn't known.";
	}

	unsigned int cpu_type, eax, ecx, edx;
	cpuid(CPUID_GETFEATURES, 0, &eax, &ecx, &edx);
	cpu_type = (eax & 0xF0FF0);
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
		return IntelSandyBridge;
	case 0x306A0:
		return IntelIvyBridge;
	case 0x306C0:
	case 0x40660:
		return IntelHaswell;
	default:
		FATAL() << "CPU "<< HEX(cpu_type) << " unknown.";
		return UnknownCpu; // not reached
	}
}

static void init_perf_event_attr(struct perf_event_attr* attr,
				 perf_type_id type, unsigned config)
{
	memset(attr, 0, sizeof(*attr));
	attr->type = type;
	attr->size = sizeof(*attr);
	attr->config = config;
	// rr requires that its events count userspace tracee code
	// only.
	attr->exclude_kernel = 1;
	attr->exclude_guest = 1;
}

void init_hpc(Task* t)
{
	struct hpc_context* counters =
		(struct hpc_context*)calloc(1, sizeof(*counters));
	t->hpc = counters;

	CpuMicroarch uarch = get_cpu_microarch();
	const PmuConfig* pmu = nullptr;
	for (size_t i = 0; i < ALEN(pmu_configs); ++i) {
		if (uarch == pmu_configs[i].uarch) {
			pmu = &pmu_configs[i];
			break;
		}
	}
	assert(pmu);

	if (!pmu->supported) {
		FATAL() <<"Microarchitecture `"<< pmu->name <<"' currently unsupported.";
	}

	init_perf_event_attr(&counters->rbc.attr, PERF_TYPE_RAW,
			     pmu->rcb_cntr_event);
#ifdef HPC_ENABLE_EXTRA_PERF_COUNTERS
	init_perf_event_attr(&counters->inst.attr, PERF_TYPE_RAW,
			     pmu->rinsn_cntr_event);

	init_perf_event_attr(&counters->hw_int.attr, PERF_TYPE_RAW,
			     pmu->hw_intr_cntr_event);
	// libpfm encodes the event with this bit set, so we'll do the
	// same thing.  Unclear if necessary.
	counters->hw_int.attr.exclude_hv = 1;

	init_perf_event_attr(&counters->page_faults.attr, PERF_TYPE_SOFTWARE,
			     PERF_COUNT_SW_PAGE_FAULTS);
#endif
}

static void start_counter(Task* t, int group_fd, hpc_event_t* counter)
{
	counter->fd = syscall(__NR_perf_event_open, &counter->attr, t->tid,
			      -1, group_fd, 0);
	if (0 > counter->fd) {
		FATAL() <<"Failed to initialize counter";
	}
	if (ioctl(counter->fd, PERF_EVENT_IOC_ENABLE, 0)) {
		FATAL() <<"Failed to start counter";
	}
}

static void stop_counter(Task* t, const hpc_event_t* counter)
{
	if (ioctl(counter->fd, PERF_EVENT_IOC_DISABLE, 0)) {
		FATAL() <<"Failed to stop counter";
	}
}

static void __start_hpc(Task* t)
{
	struct hpc_context *counters = t->hpc;
	pid_t tid = t->tid;

	start_counter(t, -1, &counters->rbc);
	counters->group_leader = counters->rbc.fd;

#ifdef HPC_ENABLE_EXTRA_PERF_COUNTERS
	start_counter(t, counters->group_leader, &counters->hw_int);
	start_counter(t, counters->group_leader, &counters->inst);
	start_counter(t, counters->group_leader, &counters->page_faults);
#endif

	struct f_owner_ex own;
	own.type = F_OWNER_TID;
	own.pid = tid;
	if (fcntl(counters->rbc.fd, F_SETOWN_EX, &own)) {
		FATAL() <<"Failed to SETOWN_EX rbc event fd";
	}
	if (fcntl(counters->rbc.fd, F_SETFL, O_ASYNC)
	    || fcntl(counters->rbc.fd, F_SETSIG, HPC_TIME_SLICE_SIGNAL)) {
		FATAL() <<"Failed to make rbc counter ASYNC with sig"
			<< signalname(HPC_TIME_SLICE_SIGNAL);
	}

	counters->started = true;
}

void stop_hpc(Task* t)
{
	struct hpc_context* counters = t->hpc;
	if (!counters->started) {
		return;
	}

	stop_counter(t, &counters->rbc);
#ifdef HPC_ENABLE_EXTRA_PERF_COUNTERS
	stop_counter(t, &counters->hw_int);
	stop_counter(t, &counters->inst);
	stop_counter(t, &counters->page_faults);
#endif
}

static void cleanup_hpc(Task* t)
{
	struct hpc_context* counters = t->hpc;

	stop_hpc(t);

	close(counters->rbc.fd);
#ifdef HPC_ENABLE_EXTRA_PERF_COUNTERS
	close(counters->hw_int.fd);
	close(counters->inst.fd);
	close(counters->page_faults.fd);
#endif
	counters->started = false;
}

void reset_hpc(Task *t, int64_t val)
{
	if (t->hpc->started) {
		cleanup_hpc(t);
	}
	t->hpc->rbc.attr.sample_period = val;
	__start_hpc(t);
}
/**
 * Ultimately frees all resources that are used by hpc of the corresponding
 * t. After calling this function, counters cannot be used anymore
 */
void destroy_hpc(Task *t)
{
	struct hpc_context* counters = t->hpc;
	cleanup_hpc(t);
	free(counters);
}

static int64_t read_counter(struct hpc_context* hpc, int fd)
{
	if (!hpc->started) {
		return 0;
	}
	int64_t val;
	ssize_t nread = read(fd, &val, sizeof(val));
	assert(nread == sizeof(val));
	return val;
}

int64_t read_rbc(struct hpc_context* hpc)
{
	return read_counter(hpc, hpc->rbc.fd);
}

int rcb_cntr_fd(struct hpc_context* hpc)
{
	return hpc->rbc.fd;
}

#ifdef HPC_ENABLE_EXTRA_PERF_COUNTERS
int64_t read_hw_int(struct hpc_context* hpc)
{
	return read_counter(hpc, hpc->hw_int.fd);
}

int64_t read_insts(struct hpc_context* hpc)
{
	return read_counter(hpc, hpc->inst.fd);
}


int64_t read_page_faults(struct hpc_context* hpc)
{
	return read_counter(hpc, hpc->page_faults.fd);
}
#endif
