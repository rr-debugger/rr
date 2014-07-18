/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

#include "rrutil.h"

/* Test to ensure that sigreturn restores all necessary registers */

struct reg_ops {
  void (* set)(const void* p);
  void (* get)(void* p);
};

static struct reg_ops xmm_ops[8];

static void init(void)
{
/* Assembly functions to get/set particular registers.
   They all read/write to/from buffers.
   All defined in sigreturn_helper.S.
*/
#define DEFINE_XMM_HELPERS(i) \
  extern void set_xmm##i(const void* p); \
  extern void get_xmm##i(void* p); \
  xmm_ops[i].set = set_xmm##i; \
  xmm_ops[i].get = get_xmm##i;

  DEFINE_XMM_HELPERS(0) /*
  DEFINE_XMM_HELPERS(1)
  DEFINE_XMM_HELPERS(2)
  DEFINE_XMM_HELPERS(3)
  DEFINE_XMM_HELPERS(4)
  DEFINE_XMM_HELPERS(5)
  DEFINE_XMM_HELPERS(6)
  DEFINE_XMM_HELPERS(7) */
}

#define GOOD 0x12345678
#define BAD 0xFEDCBA98

#define XMM_SIZE 16
#define XMM_ALIGNMENT __attribute__ ((aligned (XMM_SIZE)))

static const int xmm_good[XMM_SIZE/sizeof(int)] XMM_ALIGNMENT = { GOOD, GOOD + 1, GOOD + 2, GOOD + 3 };
static const int xmm_bad[XMM_SIZE/sizeof(int)] XMM_ALIGNMENT = { BAD, BAD + 1, BAD + 2, BAD + 3 };

static int regnum;

static void handle_usr1(int sig) {
	/* Try to corrupt register, to see if it gets restored */
	xmm_ops[regnum].set(xmm_bad);
}

int main(int argc, char *argv[]) {
	init();
	signal(SIGUSR1, handle_usr1);

	for (regnum = 0; regnum < 1; ++regnum) {
		int xmm[XMM_SIZE/sizeof(int)] XMM_ALIGNMENT;

		xmm_ops[regnum].set(xmm_good);
		raise(SIGUSR1);
		xmm_ops[regnum].get(xmm);

		test_assert("XMM register should have been preserved" &&
		            memcmp(xmm, xmm_good, sizeof(xmm)) == 0);
	}
	atomic_puts("EXIT-SUCCESS");
	return 0;
}
