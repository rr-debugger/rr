#ifndef RAW_SYSCALL_FUNCTION
#error must define RAW_SYSCALL_FUNCTION before including this file
#endif
#ifndef SYSCALL_ENTRY_POINT
#error must define SYSCALL_ENTRY_POINT before including this file
#endif

#define ENTRY_POINT_IP .L##RAW_SYSCALL_FUNCTION##entry_point_ip

#if defined(__i386__)
        .text
        .globl RAW_SYSCALL_FUNCTION
        .hidden RAW_SYSCALL_FUNCTION
        .type RAW_SYSCALL_FUNCTION, @function
RAW_SYSCALL_FUNCTION:     /* syscallno = 4(%esp) */
        .cfi_startproc
        pushl %ebx        /* syscallno = 8(%esp) */
        .cfi_adjust_cfa_offset 4
        .cfi_rel_offset %ebx, 0
        pushl %esi        /* syscallno = 12(%esp) */
        .cfi_adjust_cfa_offset 4
        .cfi_rel_offset %esi, 0
        pushl %edi        /* syscallno = 16(%esp) */
        .cfi_adjust_cfa_offset 4
        .cfi_rel_offset %edi, 0
        pushl %ebp        /* syscallno = 20(%esp) */
        .cfi_adjust_cfa_offset 4
        .cfi_rel_offset %ebp, 0

        movl 20(%esp), %eax /* %eax = syscallno */
        movl 24(%esp), %ebx /* %ebx = a0 */
        movl 28(%esp), %ecx /* %ecx = a1 */
        movl 32(%esp), %edx /* %edx = a2 */
        movl 36(%esp), %esi /* %esi = a3 */
        movl 40(%esp), %edi /* %edi = a4 */
        movl 44(%esp), %ebp /* %ebp = a5 */

        /* We need to be able to recognize when the tracees are in
           traced (or untraced) syscalls. */
ENTRY_POINT_IP:
        int $0x80         /* syscall() */
        popl %ebp
        .cfi_adjust_cfa_offset -4
        .cfi_restore %ebp
        popl %edi
        .cfi_adjust_cfa_offset -4
        .cfi_restore %edi
        popl %esi
        .cfi_adjust_cfa_offset -4
        .cfi_restore %esi
        popl %ebx
        .cfi_adjust_cfa_offset -4
        .cfi_restore %ebx
        ret
        .cfi_endproc
        .size RAW_SYSCALL_FUNCTION, . - RAW_SYSCALL_FUNCTION

        .globl SYSCALL_ENTRY_POINT
        .hidden SYSCALL_ENTRY_POINT
        .type SYSCALL_ENTRY_POINT, @function
SYSCALL_ENTRY_POINT:
        call .L1
.L1:
        pop %eax
        addl $(ENTRY_POINT_IP - .L1), %eax
        ret
        .size SYSCALL_ENTRY_POINT, . - SYSCALL_ENTRY_POINT

#undef ENTRY_POINT_IP
#elif defined(__x86_64__)
        .text
        .globl RAW_SYSCALL_FUNCTION
        .hidden RAW_SYSCALL_FUNCTION
        .type RAW_SYSCALL_FUNCTION, @function
RAW_SYSCALL_FUNCTION:
	/* Incoming args are in %rdi, %rsi, %rdx, %rcx, %r8, %r9, and 8(%rsp).
	   Syscall arguments are %rdi, %rsi, %rdx, %r10, %r8, %r9. */
	movq %rdi, %rax         /* syscall number */
	movq %rsi, %rdi         /* first syscall arg */
	movq %rdx, %rsi         /* second syscall arg */
	movq %rcx, %rdx         /* third syscall arg */
	movq %r8, %r10          /* fourth syscall arg */
	movq %r9, %r8           /* fifth syscall arg */
	movq 8(%rsp), %r9       /* sixth syscall arg */

        /* We need to be able to recognize when the tracees are in
           traced (or untraced) syscalls. */
ENTRY_POINT_IP:
	syscall
        /* Clear TF bit from RFLAGS copied to R11 by syscall instruction */
        andq $0xfffffffffffffeff, %r11

        ret
	.size RAW_SYSCALL_FUNCTION, . - RAW_SYSCALL_FUNCTION

        .globl SYSCALL_ENTRY_POINT
        .hidden SYSCALL_ENTRY_POINT
        .type SYSCALL_ENTRY_POINT, @function
SYSCALL_ENTRY_POINT:
        lea ENTRY_POINT_IP(%rip), %rax
.L1:
        ret
        .size SYSCALL_ENTRY_POINT, . - SYSCALL_ENTRY_POINT
#else
#error unknown CPU architecture
#endif /* __i386__/__x86_64__ */
        .section .note.GNU-stack,"",@progbits
        .previous
