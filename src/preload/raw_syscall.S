#if defined(__i386__)
        .text
        .globl _raw_syscall
        .hidden _raw_syscall
        .type _raw_syscall, @function
_raw_syscall:     /* syscallno = 4(%esp) */
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
        .size _raw_syscall, . - _raw_syscall

#elif defined(__x86_64__)
        .text
        .globl _raw_syscall
        .hidden _raw_syscall
        .type _raw_syscall, @function
_raw_syscall:
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

        /* During a system call the kernel makes some user-space-visible
           register changes:
           a) on entry, %r11 is set to %rflags
           b) %rcx is sometimes set to -1 (perhaps because of something rr does)
           c) on entry or exit, some flags are sometimes changed
           Also, during replay we may perform single-stepping which can set
           TF (trace flag). We need to hide this.

           fixup_syscall_registers is responsible for fixing up registers
           to hide these effects when we get a ptrace trap from system calls
           in the kernel: it clears TF from %r11, forces %rcx to -1, and sets
           flags to fixed values (ZF+PF+IF+reserved, same as for "xor reg,reg").
           Task::canonicalize_and_set_regs is responsible for fixing up registers
           when we emulate a system call that was traced during recording (by
           running to a breakpoint at that system call). It does the above
           effects after setting %r11 to %rflags.

           For untraced system calls there is no trap to rr during recording or
           replay, so we must handle these issues here. We do not need
           untraced system calls to behave exactly the same as traced
           system calls, since whether a given system call was traced or not is
           the same whether recording or replaying, but it's a good idea to
           make them as similar as possible. We do need register values
           to be perfectly consistent at every instruction in every replay
           whether or not singlestepping is used (because a ReplayTimeline::mark
           might be created at any point). During replay, untraced syscall
           instructions are replaced with "xor %eax,%eax".

           The following code is harmless for traced syscalls (and needs to be,
           because traced syscalls go through here too).
         */

        /* Set %r11 and %rcx to the values we expect them to have after the
           system call.
           Set flags to ZF+PF+IF+reserved (0x246) first. This simplifies
           everything.
           This all has to be independent of TF being set at any point during
           replay! But the way we're doing it here, it's trivial.
         */
        xor %ecx,%ecx
        /* At this point, flags are 0x246 + possibly TF. */
        movq $0x246,%r11
        movq $-1,%rcx

        callq *32(%rsp)

        /* At this point, during recording we don't trust the kernel to have
           restored flags correctly. It probably doesn't matter, but fix it
           anyway. */
        xor %ecx,%ecx
        /* At this point, the high 32 bits of %rcx are unknown. Fix that by
           setting to -1 to match traced syscalls. */
        movq $-1,%rcx
        /* At this point, %r11 is always 0x246 during replay and during
           recording (because TF is never set during recording). Nothing to
           fix in %r11. */

        addq $16,%rsp
        .cfi_adjust_cfa_offset -16
        ret
        .cfi_endproc
        .size _raw_syscall, . - _raw_syscall

#else
#error unknown CPU architecture
#endif /* __i386__/__x86_64__ */
        .section .note.GNU-stack,"",@progbits
        .previous
