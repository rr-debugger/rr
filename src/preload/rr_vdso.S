#define STARTPROC_GLOBAL(name) .global #name; .type #name, @function; \
 #name:; .cfi_startproc
#define CFI_ENDPROC .cfi_endproc

// Older libs don't use the __vdso symbols, but try to look for the syscall
// names directly. Follow the kernel vdso and make them weak aliases
#define WEAK_ALIAS(sym, target) .weak sym; .set sym, target

#if defined(__x86_64__)

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

#else

#error "VDSO Hooks not defined for this platform"

#endif

#undef STARTPROC_GLOBAL
#undef CFI_ENDPROC
