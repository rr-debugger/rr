#if defined(__i386__)
        .text



        .p2align 4,,15
        .globl  cpuid_call
        .type   cpuid_call, @function
cpuid_call:
_cpuid_call:
        .cfi_startproc
        pushl   %edi
        .cfi_def_cfa_offset 8
        .cfi_offset 7, -8
        pushl   %esi
        .cfi_def_cfa_offset 12
        .cfi_offset 6, -12
        pushl   %ebx
        .cfi_def_cfa_offset 16
        .cfi_offset 3, -16
        xorl    %ebx, %ebx
        movl    20(%esp), %esi
        movl    %ebx, %eax
        xchgl   %ebx, %edi
        cpuid
        xchgl   %ebx, %edi
        movl    %eax, %ebx
        xorl    %eax, %eax
        cmpl    $4, %ebx
        jbe     .L4
        movl    16(%esp), %eax
        andl    $4, %eax
        cpuid
        movl    %eax, (%esi)
        movl    24(%esp), %eax
        movl    %ebx, (%eax)
        movl    (%esi), %eax
.L4:
        popl    %ebx
        .cfi_restore 3
        .cfi_def_cfa_offset 12
        popl    %esi
        .cfi_restore 6
        .cfi_def_cfa_offset 8
        popl    %edi
        .cfi_restore 7
        .cfi_def_cfa_offset 4
        ret
        .cfi_endproc
.LFE89:
        .size   cpuid_call, .-cpuid_call



        .p2align 4,,15
        .globl  cpuid_loop
        .type   cpuid_loop, @function
cpuid_loop:
        .cfi_startproc
        pushl   %ebp
        .cfi_def_cfa_offset 8
        .cfi_offset 5, -8
        pushl   %edi
        .cfi_def_cfa_offset 12
        .cfi_offset 7, -12
        pushl   %esi
        .cfi_def_cfa_offset 16
        .cfi_offset 6, -16
        movl    16(%esp), %esi
        pushl   %ebx
        .cfi_def_cfa_offset 20
        .cfi_offset 3, -20
        xorl    %ebx, %ebx
        subl    $44, %esp
        .cfi_def_cfa_offset 64
        leal    28(%esp), %ebp
        leal    24(%esp), %edi
        .p2align 4,,7
        .p2align 3
.L10:
        movl    %ebx, (%esp)
        movl    %ebp, 8(%esp)
        movl    %edi, 4(%esp)
        call    _cpuid_call
        addl    %eax, %ebx
        mov     $201, %eax
        int     $0x80
        subl    $1, %esi
        jne     .L10
        addl    $44, %esp
        .cfi_def_cfa_offset 20
        movl    %ebx, %eax
        popl    %ebx
        .cfi_restore 3
        .cfi_def_cfa_offset 16
        popl    %esi
        .cfi_restore 6
        .cfi_def_cfa_offset 12
        popl    %edi
        .cfi_restore 7
        .cfi_def_cfa_offset 8
        popl    %ebp
        .cfi_restore 5
        .cfi_def_cfa_offset 4
        ret
        .cfi_endproc
        .size   cpuid_loop, .-cpuid_loop
#elif defined(__x86_64__)
        .text
        .p2align 4,,15
        .globl cpuid_call
        .type  cpuid_call, @function
cpuid_call:
_cpuid_call:
        pushq %rbx
        /* Call CPUID twice, once under a conditional.  */
        xorl %eax, %eax
        cpuid
        cmpl $4, %eax
        jbe 1f
        movl $1, %eax
        cpuid
1:
        popq %rbx
        ret
        .size  cpuid_call, .-cpuid_call

        .p2align 4,,15
        .globl cpuid_loop
        .type  cpuid_loop, @function
cpuid_loop:
        pushq %rbx
        mov %rdi, %rbx
        xor %r11d, %r11d
1:
        call _cpuid_call
        addq %rax, %r11
        mov $107, %rax
        syscall
        subq $1, %rbx
        jne 1b
        movq %r11, %rax
        popq %rbx
        ret
        .size  cpuid_loop, .-cpuid_loop
#else
#error unknown CPU architecture
#endif /* __i386__/__x86_64__ */
        .section        .note.GNU-stack,"",@progbits
