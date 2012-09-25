#include <assert.h>
#include <err.h>
#include <sys/select.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/syscall.h>
#include <sys/mman.h>

#include "hpc.h"
#include "../share/sys.h"
#include <perfmon/pfmlib_perf_event.h>


/**
 * libpfm4 specific stuff
 */
void init_libpfm()
{
	int ret = pfm_initialize();
	if (ret != PFM_SUCCESS) {
		errx(1, "cannot initialize libpfm: %s\n", pfm_strerror(ret));
	}
}

void close_libpfm()
{
	pfm_terminate();
}

void libpfm_event_encoding(struct perf_event_attr* attr, const char* event_str, int hw_event)
{
	memset(attr, 0, sizeof(struct perf_event_attr));

	int ret;
	char* fstr;

	attr->size = sizeof(struct perf_event_attr);
	ret = pfm_get_perf_event_encoding(event_str, PFM_PLM0, attr, &fstr, NULL);
	if (ret != PFM_SUCCESS) {
		errx(1, "error while encoding event string %s :%s\n", event_str, pfm_strerror(ret));
	}
	if (hw_event && attr->type != PERF_TYPE_RAW) {
		errx(1, "error: %s is not a raw hardware event\n", event_str);
	}
	sys_free((void**) &fstr);
}


enum cpuid_requests {
  CPUID_GETVENDORSTRING,
  CPUID_GETFEATURES,
  CPUID_GETTLB,
  CPUID_GETSERIAL,

  CPUID_INTELEXTENDED=0x80000000,
  CPUID_INTELFEATURES,
  CPUID_INTELBRANDSTRING,
  CPUID_INTELBRANDSTRINGMORE,
  CPUID_INTELBRANDSTRINGEND,
};

/** issue a single request to CPUID. Fits 'intel features', for instance
 *  note that even if only "eax" and "edx" are of interest, other registers
 *  will be modified by the operation, so we need to tell the compiler about it.
 */
static inline void cpuid(int code, unsigned int *a, unsigned int *d) {
/* this asm returns 1 if CPUID is supported, 0 otherwise (ZF is also set accordingly)
 * add it later for full compatibility

	pushfd ; get
	pop eax
	mov ecx, eax ; save
	xor eax, 0x200000 ; flip
	push eax ; set
	popfd
	pushfd ; and test
	pop eax
	xor eax, ecx ; mask changed bits
	shr eax, 21 ; move bit 21 to bit 0
	and eax, 1 ; and mask others
	push ecx
	popfd ; restore original flags
	ret

 */
  asm volatile("cpuid":"=a"(*a),"=d"(*d):"a"(code):"ecx","ebx");
}

/*
 * Find out the cpu model using the cpuid instruction.
 * full list of CPUIDs at http://sandpile.org/x86/cpuid.htm
 */
typedef enum { UnknownArch = -1, IntelSandyBridge , IntelIvyBridge } cpu_type;
cpu_type get_cpu_type(){
	unsigned int eax,edx;
	cpuid(CPUID_GETFEATURES,&eax,&edx);
	switch (eax & 0xF00F0) {
	case 0x200A0:
	case 0x200D0:
		return IntelSandyBridge;
		break;
	case 0x300A0:
		return IntelIvyBridge;
		break;
	default:
		assert(0 && "CPU not supported yet (add cpuid and adjust the event string to add support).");
		break;
	}
	return UnknownArch;
}

/**
 * initialize hpc here
 */
void init_hpc(struct context *context)
{

	struct hpc_context* counters = sys_malloc_zero(sizeof(struct hpc_context));
	context->hpc = counters;

	/* get the event that counts down to the initial value
	 * the precision level enables PEBS support. precise=0 uses the counter
	 * with PEBS disabled */
	const char * event_str = 0;
	switch (get_cpu_type()) {
	case IntelSandyBridge :
		event_str = "BR_INST_RETIRED:CONDITIONAL:u:precise=0";
		break;
	case IntelIvyBridge :
		event_str = "BR_INST_RETIRED:COND:u:precise=0";
		break;
	default:
		event_str = "BR_INST_RETIRED:CONDITIONAL:u:precise=0";
		break;
	}

	libpfm_event_encoding(&(counters->rbc_down.attr), event_str , 1);
	/* counts up to double check */
	libpfm_event_encoding(&(counters->rbc_up.attr), event_str, 1);
	//libpfm_event_encoding(&(counters->hw_int.attr), "HW_INTERRUPTS:u", 1);
	libpfm_event_encoding(&(counters->hw_int.attr), event_str, 1);
	libpfm_event_encoding(&(counters->page_faults.attr), "PERF_COUNT_SW_PAGE_FAULTS:u", 0);
}

static void __start_hpc(struct context* ctx)
{

	struct hpc_context *counters = ctx->hpc;
	pid_t tid = ctx->child_tid;
	START_COUNTER(tid,-1,counters->hw_int);
	START_COUNTER(tid,counters->hw_int.fd,counters->rbc_up);
	START_COUNTER(tid,counters->hw_int.fd,counters->page_faults);
	START_COUNTER(tid,counters->hw_int.fd,counters->rbc_down);

	sys_fcntl_f_setown(counters->rbc_down.fd, tid);
	sys_fcntl_f_setfl_o_async(counters->rbc_down.fd);

	//allocate page(es) for hpm data
	int pgsz = sysconf(_SC_PAGESIZE);
	//+1 since the first page is header stuff
	int map_size = (1 + 1) * pgsz;

	counters->hpc_mmap = sys_mmap(NULL, map_size, PROT_READ, MAP_SHARED, counters->rbc_down.fd, 0);
	counters->hpc_map_size = map_size;
	counters->started = 1;
}

void stop_hpc_down(struct context* context)
{
	STOP_COUNTER(context->hpc->rbc_down.fd);
}

void stop_hpc(struct context* context)
{
	struct hpc_context* counters = context->hpc;

	STOP_COUNTER(counters->hw_int.fd);
	STOP_COUNTER(counters->page_faults.fd);
	STOP_COUNTER(counters->rbc_up.fd);
	STOP_COUNTER(counters->rbc_down.fd);
}

void cleanup_hpc(struct context* context)
{
	struct hpc_context* counters = context->hpc;

	if (munmap(counters->hpc_mmap, counters->hpc_map_size) == -1) {
		perror("error unmapping hpc_map -- bailing out\n");
		sys_exit();
	}

	counters->hpc_mmap = NULL;
	stop_hpc(context);

	sys_close(counters->hw_int.fd);
	sys_close(counters->page_faults.fd);
	sys_close(counters->rbc_up.fd);
	sys_close(counters->rbc_down.fd);
	counters->started = 0;
}

/*
 * Starts the hpc.
 * @param ctx: the current execution context
 * @param reset: the counters are (if enabled) reset
 */
void start_hpc(struct context *ctx, uint64_t val)
{
	ctx->hpc->rbc_down.attr.sample_period = val;
	__start_hpc(ctx);
}

void reset_hpc(struct context *ctx, uint64_t val)
{
	if (ctx->hpc->started) {
		cleanup_hpc(ctx);
	}
	ctx->hpc->rbc_down.attr.sample_period = val;
	__start_hpc(ctx);
}
/**
 * Ultimately frees all resources that are used by hpc of the corresponding
 * context. After calling this function, counters cannot be used anymore
 */
void destry_hpc(struct context *ctx)
{
	struct hpc_context* counters = ctx->hpc;
	if (counters->hpc_mmap != NULL) {
		munmap(counters->hpc_mmap, counters->hpc_map_size);
	}

	sys_free((void**) &counters);
}

/**
 * Counter access functions
 */
uint64_t read_hw_int(struct hpc_context *counters)
{
	uint64_t tmp;
	READ_COUNTER(counters->hw_int.fd, &tmp, sizeof(uint64_t));
	return tmp;
}

uint64_t read_page_faults(struct hpc_context *counters)
{
	uint64_t tmp;
	READ_COUNTER(counters->page_faults.fd, &tmp, sizeof(uint64_t));
	return tmp;
}

uint64_t read_rbc_up(struct hpc_context *counters)
{
	uint64_t tmp;
	READ_COUNTER(counters->rbc_up.fd, &tmp, sizeof(uint64_t));
	return tmp;
}

uint64_t read_rbc_down(struct hpc_context *counters)
{
	uint64_t tmp;
	READ_COUNTER(counters->rbc_down.fd, &tmp, sizeof(uint64_t));
	return tmp;
}
