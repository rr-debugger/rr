/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#include "util.h"

/* Test to ensure that sigreturn restores all necessary registers */

struct reg_ops {
  void (*set)(const void* p);
  void (*get)(void* p);
};

static struct reg_ops xmm_ops[8];
static struct reg_ops st_ops[8];

/* The assignments to uint32_t* in the inline assembly statements below
   are because if we used *p in the asm constraints, GCC would think we
   were dereferencing a void pointer (!).
*/
#define DEFINE_XMM_HELPERS(i)                                                  \
  void set_xmm##i(const void* p) {                                             \
    const uint32_t* x = p;                                                     \
    asm("movaps %[ptr], %%xmm" #i : /* no outputs */ : [ptr] "m"(*x));         \
  }                                                                            \
  void get_xmm##i(void* p) {                                                   \
    uint32_t* x = p;                                                           \
    asm("movaps %%xmm" #i ", %[ptr]" : [ptr] "=m"(*x) : /* no inputs */);      \
  }

DEFINE_XMM_HELPERS(0)
DEFINE_XMM_HELPERS(1)
DEFINE_XMM_HELPERS(2)
DEFINE_XMM_HELPERS(3)
DEFINE_XMM_HELPERS(4)
DEFINE_XMM_HELPERS(5)
DEFINE_XMM_HELPERS(6)
DEFINE_XMM_HELPERS(7)

void set_st7(const void* p) {
  const uint32_t* x = p;
  asm("\tfinit\n"
      "\tfldt %[ptr]\n"
      "\tfst %%st(7)\n"
      : /* no outputs */
      : [ptr] "m"(*x));
}
void get_st7(void* p) {
  uint32_t* x = p;
  asm("\tfdecstp\n"
      "\tfstpt %[ptr]\n"
      : [ptr] "=m"(*x)
      : /* no inputs */);
}

#define DEFINE_ST_HELPERS(i)                                                   \
  void set_st##i(const void* p) {                                              \
    const uint32_t* x = p;                                                     \
    asm("\tfinit\n"                                                            \
        "\tfldt %[ptr]\n"                                                      \
        "\tfst %%st(" #i ")\n"                                                 \
        : /* no outputs */                                                     \
        : [ptr] "m"(*x));                                                      \
  }                                                                            \
  void get_st##i(void* p) {                                                    \
    uint32_t* x = p;                                                           \
    asm("\tfld %%st(" #i ")\n"                                                 \
        "\tfstpt %[ptr]\n"                                                     \
        : [ptr] "=m"(*x)                                                       \
        : /* no inputs */);                                                    \
  }

DEFINE_ST_HELPERS(0)
DEFINE_ST_HELPERS(1)
DEFINE_ST_HELPERS(2)
DEFINE_ST_HELPERS(3)
DEFINE_ST_HELPERS(4)
DEFINE_ST_HELPERS(5)
DEFINE_ST_HELPERS(6)

static void init(void) {
#define INIT(i)                                                                \
  xmm_ops[i].set = set_xmm##i;                                                 \
  xmm_ops[i].get = get_xmm##i;                                                 \
  st_ops[i].set = set_st##i;                                                   \
  st_ops[i].get = get_st##i;

  INIT(0)
  INIT(1)
  INIT(2)
  INIT(3)
  INIT(4)
  INIT(5)
  INIT(6)
  INIT(7)
}

#define GOOD 0x12345678
#define BAD 0xFEDCBA98

#define XMM_SIZE 16
#define XMM_ALIGNMENT __attribute__((aligned(XMM_SIZE)))

static const int xmm_good[XMM_SIZE / sizeof(int)] XMM_ALIGNMENT = {
  GOOD, GOOD + 1, GOOD + 2, GOOD + 3
};
static const int xmm_bad[XMM_SIZE / sizeof(int)] XMM_ALIGNMENT = { BAD, BAD + 1,
                                                                   BAD + 2,
                                                                   BAD + 3 };

#define ST_SIZE 10

static long double st_good = 12345678.90;
static long double st_bad = -1.23456789;

static int regnum;

static void handle_usr1_xmm(__attribute__((unused)) int sig) {
  int xmm[XMM_SIZE / sizeof(int)] XMM_ALIGNMENT;
  xmm_ops[regnum].get(xmm);
  /* Print incoming xmm value to ensure any modifications made while
     entering the signal handler are replayed correctly */
  atomic_printf("xmm %d incoming: %x %x %x %x\n", regnum, xmm[0], xmm[1],
                xmm[2], xmm[3]);
  /* Try to corrupt register, to see if it gets restored */
  xmm_ops[regnum].set(xmm_bad);
}

static void handle_usr1_st(__attribute__((unused)) int sig) {
  char st[ST_SIZE];
  st_ops[regnum].get(st);
  /* Print incoming st value to ensure any modifications made while
     entering the signal handler are replayed correctly */
  atomic_printf("st %d incoming: %x %x %x\n", regnum, *((int*)(st)),
                *((int*)(st + 4)), *((short*)(st + 8)) & 0xffff);
  /* Try to corrupt register, to see if it gets restored */
  st_ops[regnum].set(&st_bad);
}

/* Some libcs use the xmm registers for signal mask manipulation in
   `raise`. Provide a version that doesn't. */
static void my_raise(int sig) {
  pid_t tid = sys_gettid();
  syscall(SYS_tgkill, tid, tid, sig);
}

int main(void) {
  init();

  signal(SIGUSR1, handle_usr1_xmm);
  for (regnum = 0; regnum < 8; ++regnum) {
    int xmm[XMM_SIZE / sizeof(int)] XMM_ALIGNMENT;
    memcpy(xmm, xmm_bad, sizeof(xmm));

    xmm_ops[regnum].set(xmm_good);
    my_raise(SIGUSR1);
    xmm_ops[regnum].get(xmm);

    test_assert("XMM register should have been preserved" &&
                memcmp(xmm, xmm_good, sizeof(xmm)) == 0);
  }

  signal(SIGUSR1, handle_usr1_st);
  for (regnum = 0; regnum < 8; ++regnum) {
    char st[ST_SIZE];
    memcpy(st, &st_bad, sizeof(st));

    st_ops[regnum].set(&st_good);
    my_raise(SIGUSR1);
    st_ops[regnum].get(st);

    test_assert("ST register should have been preserved" &&
                memcmp(st, &st_good, sizeof(st)) == 0);
  }

  atomic_puts("EXIT-SUCCESS");
  return 0;
}
