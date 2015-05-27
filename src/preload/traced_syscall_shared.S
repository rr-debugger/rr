#ifndef RAW_SYSCALL_FUNCTION
#error must define RAW_SYSCALL_FUNCTION before including this file
#endif

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

        pushl 56(%esp)
        .cfi_adjust_cfa_offset 4
        pushl 56(%esp)
        .cfi_adjust_cfa_offset 4

        call *56(%esp)

        addl $8,%esp
        .cfi_adjust_cfa_offset -8
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

#elif defined(__x86_64__)
        .text
        .globl RAW_SYSCALL_FUNCTION
        .hidden RAW_SYSCALL_FUNCTION
        .type RAW_SYSCALL_FUNCTION, @function
RAW_SYSCALL_FUNCTION:
        .cfi_startproc
	/* Incoming args are in %rdi, %rsi, %rdx, %rcx, %r8, %r9, and 8(%rsp).
	   Syscall arguments are %rdi, %rsi, %rdx, %r10, %r8, %r9. */
	movq %rdi, %rax         /* syscall number */
	movq %rsi, %rdi         /* first syscall arg */
	movq %rdx, %rsi         /* second syscall arg */
	movq %rcx, %rdx         /* third syscall arg */
	movq %r8, %r10          /* fourth syscall arg */
	movq %r9, %r8           /* fifth syscall arg */
	movq 8(%rsp), %r9       /* sixth syscall arg */

        pushq 32(%rsp)
        .cfi_adjust_cfa_offset 8
        pushq 32(%rsp)
        .cfi_adjust_cfa_offset 8

	callq *32(%rsp)

        addq $16,%rsp
        .cfi_adjust_cfa_offset -16
        ret
        .cfi_endproc
	.size RAW_SYSCALL_FUNCTION, . - RAW_SYSCALL_FUNCTION

#else
#error unknown CPU architecture
#endif /* __i386__/__x86_64__ */
        .section .note.GNU-stack,"",@progbits
        .previous
