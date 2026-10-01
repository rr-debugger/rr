/* Software ticks: the tracee ABI (version 1).
 *
 * A program compiled with a software-ticks compiler pass (one for LLVM and one for GCC)
 * counts its own progress instead of relying on the CPU's branch counter. The passes place
 * a tick (RR_SOFTTICKS_TICK_ASM) so that no instrumented instruction executes twice in the
 * same stack frame (at the same pc and stack pointer) without a tick in between: at the
 * start of every function, at the start of every block that is the target of a retreating
 * edge of a depth-first walk of the CFG (every cycle, reducible or not, contains one), and
 * right after every call to a returns_twice function (setjmp, vfork). A pc can repeat
 * without a tick only in different, simultaneously live activations (returning through
 * recursive calls), which the stack pointer tells apart, as with rr's branch counter.
 * Exactly where ticks go is up to the pass; the tracer only relies on that guarantee and
 * on a given binary always ticking the same way.
 *
 * A tick decrements a per-task countdown at a fixed address and traps when it reaches 0.
 * The countdown lives at RR_SOFTTICKS_COUNTDOWN_ADDR, a slot in rr's preload thread-locals
 * page (PRELOAD_THREAD_LOCALS_ADDR in preload/preload_interface.h), which the recorder and
 * the replayer already make per-task. The tracer programs it like a PMU sample period:
 *
 *   - x86-64 and aarch64: the countdown is 64 bits. Write W before resuming the task; after
 *     it stops, it executed (W - C) mod 2^64 ticks, where C is the value read. W = N
 *     (N >= 1) traps right after the Nth tick; W = 0 never traps (it wraps to 2^64 - 1).
 *   - i386: the countdown is the 32-bit word at RR_SOFTTICKS_COUNTDOWN_ADDR, and the next
 *     word is the "disarmed" word: a tick traps when the countdown becomes 0 and the
 *     disarmed word is 0. Whoever creates the page sets the disarmed word to 1 (the
 *     initializer below when its mmap creates the page; the tracer when it creates rr's
 *     thread-locals page), so the program never traps unless a tracer arms it. To arm,
 *     the tracer writes the countdown N (1 <= N <= 2^32 - 1) and the disarmed word 0;
 *     ticks executed = (N - C) mod 2^32.
 *
 * Each tick commits in one instruction (the decrement), so the countdown is valid at any
 * stop. The trap comes after the commit: the stop of a tick trap is at a fixed place in the
 * sequence (x86: SIGTRAP from the int3, pc after it; aarch64: SIGTRAP from
 * `brk #RR_SOFTTICKS_BRK_IMM`, pc at the brk, which the tracer must step over). A SIGTRAP
 * at a sequence's trap instruction is a tick trap; if the countdown is not 0 then, it is a
 * stale one (the tick was counted before an earlier stop) and the tracer just resumes.
 * A stop between the commit and the trap is an ordinary position: a replayer reaches it by
 * running to one tick before and advancing from there (a skid of 1). Inside a sequence,
 * state that depends on the countdown's value (x86: the flags; aarch64: x17) differs
 * between recording and replay; a replayer must not compare it there.
 *
 * Outside rr, each instrumented module's initializer (RR_SOFTTICKS_INIT_ASM, run from
 * .init_array at priority RR_SOFTTICKS_INIT_PRIORITY) maps the page if it is not mapped.
 * Under rr the page already exists and the mapping fails with EEXIST, which is ignored.
 *
 * Every instrumented module also carries the note RR_SOFTTICKS_NOTE_SECTION (name "rr",
 * type RR_SOFTTICKS_NOTE_TYPE, a 4-byte descriptor holding RR_SOFTTICKS_ABI_VERSION), in
 * the initializer's COMDAT group. A recorder records in software-ticks mode when the
 * program it starts carries it.
 *
 * Everything below is ABI: changing it needs a new RR_SOFTTICKS_ABI_VERSION, which the
 * trace header records (Header.softwareTicks.abiVersion). The strings are GNU assembler
 * syntax (AT&T on x86), accepted by GCC and by LLVM's integrated assembler.
 * In an LLVM IR inline-asm string, `$` must be written `$$`.
 */
#ifndef RR_SOFTTICKS_H_
#define RR_SOFTTICKS_H_

#define RR_SOFTTICKS_ABI_VERSION 1

/* The offset of the countdown in the preload thread-locals page. rr's
 * struct preload_thread_locals uses the first PRELOAD_THREAD_LOCALS_SIZE bytes
 * (144, plus 1040 on aarch64). */
#define RR_SOFTTICKS_COUNTDOWN_OFFSET 0x800

/* The priority of the page-mapping initializer: before every user constructor
 * (101 and up) and every other initializer of the implementation. */
#define RR_SOFTTICKS_INIT_PRIORITY 1

/* The symbol of the initializer. Hidden and in a COMDAT group, so each linked
 * module (executable or shared library) has one, however many of its
 * translation units are instrumented. (lld's ThinLTO ignores COMDAT groups in
 * module asm, so there it keeps one .init_array entry per backend object, all
 * calling the same initializer; running it again is harmless.) */
#define RR_SOFTTICKS_INIT_SYMBOL "__rr_softticks_init"

#define RR_SOFTTICKS_BRK_IMM 0x5354

#define RR_SOFTTICKS_NOTE_SECTION ".note.rrsoftticks"
#define RR_SOFTTICKS_NOTE_NAME "rr"
#define RR_SOFTTICKS_NOTE_TYPE 1

#define RR_SOFTTICKS_STR_(x) #x
#define RR_SOFTTICKS_STR(x) RR_SOFTTICKS_STR_(x)

/* The initializer's .init_array entry, in the initializer's COMDAT group. */
#define RR_SOFTTICKS_INIT_ARRAY_(ptr)                                          \
  "\t.section .init_array.00001,\"awG\",@init_array," RR_SOFTTICKS_INIT_SYMBOL \
  ",comdat\n"                                                                  \
  "\t.p2align " ptr "\n"

#define RR_SOFTTICKS_INIT_HEAD_(sectype)                                       \
  "\t.pushsection .text." RR_SOFTTICKS_INIT_SYMBOL ",\"axG\"," sectype ","     \
  RR_SOFTTICKS_INIT_SYMBOL ",comdat\n"                                         \
  "\t.weak " RR_SOFTTICKS_INIT_SYMBOL "\n"                                     \
  "\t.hidden " RR_SOFTTICKS_INIT_SYMBOL "\n"                                   \
  "\t.type " RR_SOFTTICKS_INIT_SYMBOL ",%function\n"                           \
  "\t.p2align 4\n" RR_SOFTTICKS_INIT_SYMBOL ":\n"

/* The note, in the initializer's COMDAT group. */
#define RR_SOFTTICKS_NOTE_(notetype)                                           \
  "\t.section " RR_SOFTTICKS_NOTE_SECTION ",\"aG\"," notetype ","             \
  RR_SOFTTICKS_INIT_SYMBOL ",comdat\n"                                         \
  "\t.p2align 2\n"                                                             \
  "\t.long 3\n"                 /* namesz: "rr\\0" */                          \
  "\t.long 4\n"                 /* descsz */                                   \
  "\t.long " RR_SOFTTICKS_STR(RR_SOFTTICKS_NOTE_TYPE) "\n"                     \
  "\t.asciz \"rr\"\n"                                                          \
  "\t.p2align 2\n"                                                             \
  "\t.long " RR_SOFTTICKS_STR(RR_SOFTTICKS_ABI_VERSION) "\n"

#define RR_SOFTTICKS_INIT_TAIL_(ptrdir, ptralign, notetype)                    \
  "\t.size " RR_SOFTTICKS_INIT_SYMBOL ",.-" RR_SOFTTICKS_INIT_SYMBOL "\n"      \
  RR_SOFTTICKS_INIT_ARRAY_(ptralign)                                           \
  "\t" ptrdir " " RR_SOFTTICKS_INIT_SYMBOL "\n"                                \
  RR_SOFTTICKS_NOTE_(notetype)                                                 \
  "\t.popsection\n"

/* mmap flags: MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE. Kernels before
 * 4.17 treat MAP_FIXED_NOREPLACE as a hint; a mapping placed elsewhere is
 * unmapped again. */
#define RR_SOFTTICKS_MMAP_FLAGS 0x100022

#if defined(__x86_64__) || defined(__i386__) || defined(RR_SOFTTICKS_ALL_ARCHES)

#define RR_SOFTTICKS_X86_PAGE_ADDR 0x70001000
#define RR_SOFTTICKS_X86_COUNTDOWN_ADDR 0x70001800

/* x86-64: 11 bytes; clobbers the flags only. */
#define RR_SOFTTICKS_X64_TICK_ASM                                              \
  "decq 0x70001800\n\t"                                                        \
  "jnz 1f\n\t"                                                                 \
  "int3\n"                                                                     \
  "1:"

/* i386: 19 bytes; a 32-bit countdown and a trap only when the disarmed word
 * (0x70001804) is 0. Clobbers the flags only. */
#define RR_SOFTTICKS_X86_TICK_ASM                                              \
  "subl $1, 0x70001800\n\t"                                                    \
  "jnz 1f\n\t"                                                                 \
  "cmpl $0, 0x70001804\n\t"                                                    \
  "jnz 1f\n\t"                                                                 \
  "int3\n"                                                                     \
  "1:"

#define RR_SOFTTICKS_X64_INIT_ASM                                              \
  RR_SOFTTICKS_INIT_HEAD_("@progbits")                                         \
  "\tmovl $9, %eax\n"            /* SYS_mmap */                                \
  "\tmovl $0x70001000, %edi\n"                                                 \
  "\tmovl $4096, %esi\n"                                                       \
  "\tmovl $3, %edx\n"            /* PROT_READ | PROT_WRITE */                  \
  "\tmovl $0x100022, %r10d\n"                                                  \
  "\tmovq $-1, %r8\n"                                                          \
  "\txorl %r9d, %r9d\n"                                                        \
  "\tsyscall\n"                                                                \
  "\tcmpq $0x70001000, %rax\n"                                                 \
  "\tje 1f\n"                                                                  \
  "\tcmpq $-4095, %rax\n"                                                      \
  "\tjae 1f\n"                   /* an error: EEXIST under rr */               \
  "\tmovq %rax, %rdi\n"                                                        \
  "\tmovl $11, %eax\n"           /* SYS_munmap */                              \
  "\tmovl $4096, %esi\n"                                                       \
  "\tsyscall\n"                                                                \
  "1:\tret\n"                                                                  \
  RR_SOFTTICKS_INIT_TAIL_(".quad", "3", "@note")

#define RR_SOFTTICKS_X86_INIT_ASM                                              \
  RR_SOFTTICKS_INIT_HEAD_("@progbits")                                         \
  "\tpushl %ebx\n"                                                             \
  "\tpushl %esi\n"                                                             \
  "\tpushl %edi\n"                                                             \
  "\tpushl %ebp\n"                                                             \
  "\tmovl $192, %eax\n"          /* SYS_mmap2 */                               \
  "\tmovl $0x70001000, %ebx\n"                                                 \
  "\tmovl $4096, %ecx\n"                                                       \
  "\tmovl $3, %edx\n"                                                          \
  "\tmovl $0x100022, %esi\n"                                                   \
  "\tmovl $-1, %edi\n"                                                         \
  "\txorl %ebp, %ebp\n"                                                        \
  "\tint $0x80\n"                                                              \
  "\tcmpl $0x70001000, %eax\n"                                                 \
  "\tjne 2f\n"                                                                 \
  "\tmovl $1, 0x70001804\n"     /* created the page: disarmed */               \
  "\tjmp 1f\n"                                                                 \
  "2:\n"                                                                       \
  "\tcmpl $-4095, %eax\n"                                                      \
  "\tjae 1f\n"                                                                 \
  "\tmovl %eax, %ebx\n"                                                        \
  "\tmovl $91, %eax\n"           /* SYS_munmap */                              \
  "\tmovl $4096, %ecx\n"                                                       \
  "\tint $0x80\n"                                                              \
  "1:\tpopl %ebp\n"                                                            \
  "\tpopl %edi\n"                                                              \
  "\tpopl %esi\n"                                                              \
  "\tpopl %ebx\n"                                                              \
  "\tret\n"                                                                    \
  RR_SOFTTICKS_INIT_TAIL_(".long", "2", "@note")

#endif

#if defined(__aarch64__) || defined(RR_SOFTTICKS_ALL_ARCHES)

/* PRELOAD_LIBRARY_PAGE_SIZE is 64 KiB on aarch64. */
#define RR_SOFTTICKS_ARM64_PAGE_ADDR 0x70010000
#define RR_SOFTTICKS_ARM64_COUNTDOWN_ADDR 0x70010800

/* aarch64: 28 bytes; clobbers x16 and x17 (the intra-procedure-call scratch
 * registers), not the flags. x17 holds the countdown only inside the sequence: it is
 * cleared at the end, because rr compares general registers between recording and
 * replay and the countdown's values differ between the two. (On x86 only the flags
 * depend on the countdown, and rr does not compare them.) */
#define RR_SOFTTICKS_ARM64_TICK_ASM                                            \
  "movz x16, #0x7001, lsl #16\n\t"                                             \
  "ldr x17, [x16, #0x800]\n\t"                                                 \
  "sub x17, x17, #1\n\t"                                                       \
  "str x17, [x16, #0x800]\n\t"                                                 \
  "cbnz x17, 1f\n\t"                                                           \
  "brk #0x5354\n"                                                              \
  "1:\n\t"                                                                     \
  "mov x17, xzr"

#define RR_SOFTTICKS_ARM64_INIT_ASM                                            \
  RR_SOFTTICKS_INIT_HEAD_("%progbits")                                         \
  "\tmov x8, #222\n"             /* SYS_mmap */                                \
  "\tmovz x0, #0x0000\n"                                                       \
  "\tmovk x0, #0x7001, lsl #16\n"                                              \
  "\tmov x1, #4096\n"                                                          \
  "\tmov x2, #3\n"                                                             \
  "\tmovz x3, #0x0022\n"                                                       \
  "\tmovk x3, #0x10, lsl #16\n"                                                \
  "\tmov x4, #-1\n"                                                            \
  "\tmov x5, #0\n"                                                             \
  "\tsvc #0\n"                                                                 \
  "\tmovz x9, #0x0000\n"                                                       \
  "\tmovk x9, #0x7001, lsl #16\n"                                              \
  "\tcmp x0, x9\n"                                                             \
  "\tb.eq 1f\n"                                                                \
  "\tcmn x0, #4095\n"                                                          \
  "\tb.hs 1f\n"                                                                \
  "\tmov x8, #215\n"             /* SYS_munmap */                              \
  "\tmov x1, #4096\n"                                                          \
  "\tsvc #0\n"                                                                 \
  "1:\tret\n"                                                                  \
  RR_SOFTTICKS_INIT_TAIL_(".xword", "3", "%note")

#endif

/* The native sequences, for hand-instrumented code and the plugins' host tests. */
#if defined(__x86_64__)
#define RR_SOFTTICKS_TICK_ASM RR_SOFTTICKS_X64_TICK_ASM
#define RR_SOFTTICKS_INIT_ASM RR_SOFTTICKS_X64_INIT_ASM
#define RR_SOFTTICKS_COUNTDOWN_ADDR RR_SOFTTICKS_X86_COUNTDOWN_ADDR
#define RR_SOFTTICKS_TICK_CLOBBERS "cc"
#elif defined(__i386__)
#define RR_SOFTTICKS_TICK_ASM RR_SOFTTICKS_X86_TICK_ASM
#define RR_SOFTTICKS_INIT_ASM RR_SOFTTICKS_X86_INIT_ASM
#define RR_SOFTTICKS_COUNTDOWN_ADDR RR_SOFTTICKS_X86_COUNTDOWN_ADDR
#define RR_SOFTTICKS_TICK_CLOBBERS "cc"
#elif defined(__aarch64__)
#define RR_SOFTTICKS_TICK_ASM RR_SOFTTICKS_ARM64_TICK_ASM
#define RR_SOFTTICKS_INIT_ASM RR_SOFTTICKS_ARM64_INIT_ASM
#define RR_SOFTTICKS_COUNTDOWN_ADDR RR_SOFTTICKS_ARM64_COUNTDOWN_ADDR
#define RR_SOFTTICKS_TICK_CLOBBERS "x16", "x17"
#endif

#ifdef RR_SOFTTICKS_TICK_ASM
/* One tick, for hand-instrumented C/C++. */
#define RR_SOFTTICK()                                                          \
  __asm__ __volatile__(RR_SOFTTICKS_TICK_ASM ::: RR_SOFTTICKS_TICK_CLOBBERS)
#endif

#endif /* RR_SOFTTICKS_H_ */
