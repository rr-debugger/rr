#ifdef __aarch64__
#define STARTPROC_GLOBAL(name) .globl #name; .type #name, @function; \
 #name:; .cfi_startproc
#else
#define STARTPROC_GLOBAL(name) .global #name; .type #name, @function; \
 #name:; .cfi_startproc
#endif
#define CFI_ENDPROC .cfi_endproc

// Older libs don't use the __vdso symbols, but try to look for the syscall
// names directly. Follow the kernel vdso and make them weak aliases
#define WEAK_ALIAS(sym, target) .weak sym; .set sym, target

#if defined(__x86_64__)

.section .plt, "a", @progbits

// Current address is 0x70000000 - PRELOAD_LIBRARY_PAGE_SIZE
// The following is equal to __rr_dl_runtime_resolve_prelude,
// but doesn't introduce a relocation record.
.quad  0x70000000 - PRELOAD_LIBRARY_PAGE_SIZE + 8

STARTPROC_GLOBAL(__rr_dl_runtime_resolve_prelude)
fstenv -32(%rsp)
movq $0,-12(%rsp)
fldenv -32(%rsp)
xchg (%rsp),%rbx
# r11 is destroyed anyway by _dl_runtime_resolve, so we can use it here.
mov %rbx,%r11
mov %rsp,%rbx
and $0xffffffffffffffc0,%rsp
push %r11
ret
CFI_ENDPROC

#define SYSCALL(which) \
    movq $which, %rax;  \
    syscall; \
    nop; \
    nop; \
    nop; \
    retq

STARTPROC_GLOBAL(__vdso_clock_getres)
SYSCALL(229)
CFI_ENDPROC
STARTPROC_GLOBAL(__vdso_getcpu)
SYSCALL(309)
CFI_ENDPROC
STARTPROC_GLOBAL(__vdso_time)
SYSCALL(201)
CFI_ENDPROC
STARTPROC_GLOBAL(__vdso_clock_gettime)
SYSCALL(228)
CFI_ENDPROC
STARTPROC_GLOBAL(__vdso_gettimeofday)
SYSCALL(96)
CFI_ENDPROC

WEAK_ALIAS(clock_getres, __vdso_clock_getres)
WEAK_ALIAS(getcpu, __vdso_getcpu)
WEAK_ALIAS(time, __vdso_time)
WEAK_ALIAS(clock_gettime, __vdso_clock_gettime)
WEAK_ALIAS(gettimeofday,__vdso_gettimeofday)

.symver gettimeofday,gettimeofday@LINUX_2.6
.symver clock_gettime,clock_gettime@LINUX_2.6
.symver __vdso_gettimeofday,__vdso_gettimeofday@LINUX_2.6
.symver __vdso_clock_getres,__vdso_clock_getres@LINUX_2.6
.symver __vdso_time,__vdso_time@LINUX_2.6
.symver __vdso_clock_gettime,__vdso_clock_gettime@LINUX_2.6
.symver __vdso_getcpu,__vdso_getcpu@LINUX_2.6

#elif defined(__i386__)

// __vdso functions use the C calling convention, so
// we have to set up the syscall parameters here.
// No x86-32 __vdso functions take more than two parameters.
#define SYSCALL(which) \
    push %ebx; \
    .cfi_adjust_cfa_offset 4; \
    .cfi_rel_offset %ebx, 0; \
    mov 8(%esp),%ebx; \
    mov 12(%esp),%ecx; \
    mov $which, %eax;  \
    int $0x80; \
    nop; \
    nop; \
    nop; \
    pop %ebx; \
    .cfi_adjust_cfa_offset -4; \
    .cfi_restore %ebx; \
    ret

// N.B.: We depend on this being the first symbol in the vdso page.
STARTPROC_GLOBAL(__kernel_vsyscall)
int $0x80
nop
nop
nop
ret
CFI_ENDPROC
STARTPROC_GLOBAL(__vdso_clock_getres)
SYSCALL(266)
CFI_ENDPROC
STARTPROC_GLOBAL(__vdso_time)
SYSCALL(13)
CFI_ENDPROC
STARTPROC_GLOBAL(__vdso_clock_gettime)
SYSCALL(265)
CFI_ENDPROC
STARTPROC_GLOBAL(__vdso_clock_gettime64)
SYSCALL(403)
CFI_ENDPROC
STARTPROC_GLOBAL(__vdso_gettimeofday)
SYSCALL(78)
CFI_ENDPROC

WEAK_ALIAS(clock_getres, __vdso_clock_getres)
WEAK_ALIAS(time, __vdso_time)
WEAK_ALIAS(clock_gettime, __vdso_clock_gettime)
WEAK_ALIAS(clock_gettime64, __vdso_clock_gettime64)
WEAK_ALIAS(gettimeofday,__vdso_gettimeofday)

.symver __vdso_gettimeofday,__vdso_gettimeofday@LINUX_2.6
.symver __vdso_clock_getres,__vdso_clock_getres@LINUX_2.6
.symver __vdso_time,__vdso_time@LINUX_2.6
.symver __vdso_clock_gettime,__vdso_clock_gettime@LINUX_2.6
.symver __vdso_getcpu,__vdso_getcpu@LINUX_2.6

#elif defined(__aarch64__)

#define SYSCALL(which)          \
        mov     x8, which;      \
        svc     0;              \
        ret

STARTPROC_GLOBAL(__kernel_clock_getres)
SYSCALL(114)
CFI_ENDPROC
STARTPROC_GLOBAL(__kernel_rt_sigreturn)
SYSCALL(139)
CFI_ENDPROC
STARTPROC_GLOBAL(__kernel_gettimeofday)
SYSCALL(169)
CFI_ENDPROC
STARTPROC_GLOBAL(__kernel_clock_gettime)
SYSCALL(113)
CFI_ENDPROC

#else

#error "VDSO Hooks not defined for this platform"

#endif

#undef STARTPROC_GLOBAL
#undef CFI_ENDPROC
