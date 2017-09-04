        .set preload_thread_locals,0x70001000

        .global _syscallbuf_code_start
        .hidden _syscallbuf_code_start

        .global _syscallbuf_final_exit_instruction
        .hidden _syscallbuf_final_exit_instruction
        .type _syscallbuf_final_exit_instruction, @function

#if defined(__i386__)
/**
 * Jump to this hook from |__kernel_vsyscall()|, to buffer syscalls that
 * we otherwise couldn't wrap through LD_PRELOAD helpers.  Return the
 * *RAW* kernel return value, not the -1/errno mandated by POSIX.
 *
 * Remember, this function runs *below* the level of libc.  libc can't
 * know that its call to |__kernel_vsyscall()| has been re-routed to
 * us.
 */
        .global __morestack
        .hidden __morestack
        .type __morestack, @function

        .text

        .set syscallbuf_stub_alt_stack, preload_thread_locals
        .set stub_scratch_1, preload_thread_locals + 8
        .set alt_stack_nesting_level, preload_thread_locals + 12

        .p2align 4
_syscallbuf_code_start:
/* Insert a NOP here so no symbol has the same address as __morestack. Otherwise
   in some configurations (gdb 7.7.1, Ubuntu 14.04) gdb sometimes maps the
   __morestack address to _syscallbuf_code_start which defeats the morestack
   hack. */
        nop

/* See comments about morestack below. For x86-32 our setup doesn't need to be
   as elaborate since we really only care about one entry function. */
__morestack:
        .cfi_startproc
        call _switch_stack_vsyscall
        popl (stub_scratch_1)
        jmp _syscallbuf_final_exit_instruction
        .cfi_endproc

        .global _switch_stack_vsyscall
        .hidden _switch_stack_vsyscall
        .type _switch_stack_vsyscall, @function
_switch_stack_vsyscall:
        .cfi_startproc
        movl %esp,(stub_scratch_1)
        incl (alt_stack_nesting_level)
        cmpl $1,(alt_stack_nesting_level)
        jne 1f
        movl (syscallbuf_stub_alt_stack),%esp
1:
        /* Set up stack frame so CFI stack walking works.
           Push before-call ESP.
         */
        pushl (stub_scratch_1)
        addl $4,(%esp)
        /* Push return address EIP. */
        mov %edi,(stub_scratch_1)
        mov (%esp),%edi /* EDI == before-call ESP */
        push -4(%edi)
        mov (stub_scratch_1),%edi

       .cfi_def_cfa_offset 0
       .cfi_offset %eip, 0
       .cfi_offset %esp, 4
        call _syscall_hook_trampoline

        /* Pop previous EIP */
        lea 4(%esp),%esp
        /* Restore previous ESP */
        subl $4,(%esp)
        pop %esp
        ret
        .cfi_endproc

_syscallbuf_final_exit_instruction:
        jmp *(stub_scratch_1)

_syscall_hook_trampoline:
        .cfi_startproc
        /* Build a |struct syscall_info| by pushing all the syscall
         * args and the number onto the stack. */
                          /* struct syscall_info info; */
        pushl %ebp        /* info.args[5] = $ebp; */
        .cfi_adjust_cfa_offset 4
        .cfi_rel_offset %ebp, 0
        pushl %edi        /* info.args[4] = $edi; */
        .cfi_adjust_cfa_offset 4
        .cfi_rel_offset %edi, 0
        pushl %esi        /* info.args[3] = $esi; */
        .cfi_adjust_cfa_offset 4
        .cfi_rel_offset %esi, 0
        pushl %edx        /* info.args[2] = $edx; */
        .cfi_adjust_cfa_offset 4
        .cfi_rel_offset %edx, 0
        pushl %ecx        /* info.args[1] = $ecx; */
        .cfi_adjust_cfa_offset 4
        .cfi_rel_offset %ecx, 0
        pushl %ebx        /* info.args[0] = $ebx; */
        .cfi_adjust_cfa_offset 4
        .cfi_rel_offset %ebx, 0
        pushl %eax        /* info.no = $eax; */
        .cfi_adjust_cfa_offset 4

        /* $esp points at &info.  Push that pointer on the stack as
         * our arg for vsyscall_hook().
         * Use %ebp as our temporary CFA register here. Don't use %ebx or
         * any other GP register, since x86-64 gdb 7.7 (at least) treats all GP
         * regs other than %esp/%ebp as *signed* and sign-extends their values.
         * Having some CFA values sign-extended and others not breaks gdb
         * stack walking.
         */
        movl %esp, %ebp
        .cfi_def_cfa_register %ebp

        /* Align stack to 16 bytes */
        and $0xfffffff0,%esp

        sub $12,%esp
        pushl %ebp

        call syscall_hook
        /* $eax = vsyscall_hook(&info); */

        /* Restore ESP */
        mov %ebp, %esp
        .cfi_def_cfa_register %esp

        /* $eax is now the syscall return value.  Erase |info.no| from the
         * stack so that we can restore the other registers we saved. */
        addl $4,%esp
        .cfi_adjust_cfa_offset -4

        /* Contract of __kernel_vsyscall() and real syscalls is that even
         * callee-save registers aren't touched, so we restore everything
         * here. */
        popl %ebx
        .cfi_adjust_cfa_offset -4
        .cfi_restore %ebx
        popl %ecx
        .cfi_adjust_cfa_offset -4
        .cfi_restore %ecx
        popl %edx
        .cfi_adjust_cfa_offset -4
        .cfi_restore %edx
        popl %esi
        .cfi_adjust_cfa_offset -4
        .cfi_restore %esi
        popl %edi
        .cfi_adjust_cfa_offset -4
        .cfi_restore %edi
        mov (alt_stack_nesting_level),%ebp
        lea -1(%ebp),%ebp
        mov %ebp,(alt_stack_nesting_level)
        popl %ebp
        .cfi_adjust_cfa_offset -4
        .cfi_restore %ebp

        ret
        .cfi_endproc
        .size _syscall_hook_trampoline, .-_syscall_hook_trampoline

#define SYSCALLHOOK_START(name) \
       .global name;            \
       .hidden name;            \
       .type name, @function;   \
name:                           \
       .cfi_startproc;          \
       .cfi_def_cfa_offset 0;   \
       .cfi_offset %eip, 0;     \
       .cfi_offset %esp, 4

#define SYSCALLHOOK_END(name)                                   \
        pop (stub_scratch_1);                                   \
        .cfi_adjust_cfa_offset -4;                              \
        pop %esp;                                               \
        .cfi_same_value %esp;                                   \
        .cfi_escape 0x10, /* DW_CFA_expression */               \
                    0x08, /* %eip */                            \
                    0x05, /* 5 byte expression follows */       \
                    0x03, /* DW_OP_addr */                      \
                    /* Individually place bytes */              \
                    stub_scratch_1 & 0xFF,                      \
                    (stub_scratch_1 & (0xFF <<  0x8)) >>  0x8,  \
                    (stub_scratch_1 & (0xFF << 0x10)) >> 0x10,  \
                    (stub_scratch_1 & (0xFF << 0x18)) >> 0x18;  \
        jmp _syscallbuf_final_exit_instruction;                 \
       .cfi_endproc;                                            \
       .size name, .-name

SYSCALLHOOK_START(_syscall_hook_trampoline_3d_01_f0_ff_ff)
        call _syscall_hook_trampoline
        cmpl $0xfffff001,%eax
SYSCALLHOOK_END(_syscall_hook_trampoline_3d_01_f0_ff_ff)

SYSCALLHOOK_START(_syscall_hook_trampoline_90_90_90)
        call _syscall_hook_trampoline
SYSCALLHOOK_END(_syscall_hook_trampoline_90_90_90)

/* Declare gcc get_pc thunks here so they're in a known region of code */

        .global _get_pc_thunks_start
        .hidden _get_pc_thunks_start
_get_pc_thunks_start:

#define THUNK(name, reg) \
        .section        .text.__x86.get_pc_thunk.name,"axG",@progbits,__x86.get_pc_thunk.name,comdat; \
        .global  __x86.get_pc_thunk.name; \
        .hidden __x86.get_pc_thunk.name; \
        .type   __x86.get_pc_thunk.name, @function; \
__x86.get_pc_thunk.name: \
        .cfi_startproc; \
        movl    (%esp), %reg; \
        ret; \
        .cfi_endproc

THUNK(ax, eax)
THUNK(bx, ebx)
THUNK(cx, ecx)
THUNK(dx, edx)
THUNK(si, esi)
THUNK(di, edi)
THUNK(bp, ebp)

        .global _get_pc_thunks_end
        .hidden _get_pc_thunks_end
_get_pc_thunks_end:

#elif defined(__x86_64__)
        .text

        .set stub_scratch_1, preload_thread_locals + 16
        .set alt_stack_nesting_level, preload_thread_locals + 24

        .p2align 4
_syscallbuf_code_start:

_syscall_hook_trampoline:
        .cfi_startproc
        /* Save RBX because we need a callee-saves register */
        pushq %rbx
        .cfi_adjust_cfa_offset 8
        .cfi_rel_offset %rbx, 0

        /* Build a |struct syscall_info| on the stack by pushing the arguments
           and syscall number. */
        pushq %r9
        .cfi_adjust_cfa_offset 8
        .cfi_rel_offset %r9, 0
        pushq %r8
        .cfi_adjust_cfa_offset 8
        .cfi_rel_offset %r8, 0
        pushq %r10
        .cfi_adjust_cfa_offset 8
        .cfi_rel_offset %r10, 0
        pushq %rdx
        .cfi_adjust_cfa_offset 8
        .cfi_rel_offset %rdx, 0
        pushq %rsi
        .cfi_adjust_cfa_offset 8
        .cfi_rel_offset %rsi, 0
        pushq %rdi
        .cfi_adjust_cfa_offset 8
        .cfi_rel_offset %rdi, 0
        pushq %rax
        .cfi_adjust_cfa_offset 8
        .cfi_rel_offset %rax, 0

        /* Align stack */
        mov %rsp,%rbx
        .cfi_def_cfa_register %rbx
        and $0xfffffffffffffff0,%rsp

        /* Call our hook. */
        mov %rbx,%rdi
        callq syscall_hook

        mov %rbx,%rsp
        .cfi_def_cfa_register %rsp

        /* On entrance, we pushed the %rax, the syscall number. But we don't
           want to |pop %rax|, as that will overwrite our return value. Pop
           into %r11 instead. */
        pop %r11
        .cfi_adjust_cfa_offset -8

        /* We don't really *need* to restore these, since the kernel could have
           trashed them all anyway. But it seems reasonable to do so. */
        pop %rdi
        .cfi_adjust_cfa_offset -8
        .cfi_restore %rdi
        pop %rsi
        .cfi_adjust_cfa_offset -8
        .cfi_restore %rsi
        pop %rdx
        .cfi_adjust_cfa_offset -8
        .cfi_restore %rdx
        pop %r10
        .cfi_adjust_cfa_offset -8
        .cfi_restore %r10
        pop %r8
        .cfi_adjust_cfa_offset -8
        .cfi_restore %r8
        mov (alt_stack_nesting_level),%r9d
        lea -1(%r9),%r9
        mov %r9d,(alt_stack_nesting_level)
        pop %r9
        .cfi_adjust_cfa_offset -8
        .cfi_restore %r9

        pop %rbx
        .cfi_adjust_cfa_offset -8
        .cfi_restore %rbx

        /* ...and we're done. */
        ret
        .cfi_endproc
        .size _syscall_hook_trampoline, . - _syscall_hook_trampoline

_syscallbuf_final_exit_instruction:
        jmp *(stub_scratch_1)

/**
 * Ok, bear with me here. When gdb sees our stack switch, it gets suspicious and if
 * we're unlucky may decide that our unwind info is broken and abort the unwind. However,
 * it decides to allow the unwind to proceed anyway if we happen to be in a function called
 * __morestack (because that's what gcc calls its stack switching mechanism). Now,
 * GDB does the stack switching comparison based on the CFA. What we thus need to do is keep the
 * CFA pointing to the old stack until we get to a function named __morestack. We set the CFA for every
 * syscallhook to what it will be at the end of the function (which, well, is an ok definition
 * of the CFA). Then, we insert a __morestack function (still with the old CFA) that just jumps
 * through to the trampoline. This way, we can force gdb's stack switch detection to think the
 * stack switch happens between the hook and the common trampoline code (and add a __morestack
 * local symbol to the trampoline code to avoid GDB messing with our stack trace).
 */
#define CFA_AT_RSP_OFFSET(offset) \
.cfi_escape 0x0f, /* DW_CFA_def_cfa_expression */\
        0x03, /* 3 bytes follow */\
        0x77, offset, /* DW_OP_breg7, offset */\
        0x06; /* DW_OP_deref */

#define RSP_IS_CFA \
.cfi_escape 0x16, /* DW_CFA_val_expression */\
            0x7,  /* %rsp */\
            0;     /* 0 bytes follow */

#define RSP_IS_CFA_PLUS_OFFSET(offset) \
.cfi_escape 0x16, /* DW_CFA_val_expression */\
            0x7,  /* %rsp */\
            2,     /* 2 bytes follow */\
            0x23, /* DW_OP_plus_uconst */\
            offset;

#define RSP_IS_RSP_PLUS_OFFSET(offset) \
.cfi_escape 0x16, /* DW_CFA_val_expression */\
            0x07, /* %rsp */\
            0x02, /* 2 bytes follow */\
            0x77, offset; /* DW_OP_breg7, offset */

#define RIP_IS_DEREF_RSP(offset) \
.cfi_escape 0x10, /* DW_CFA_expression */\
            0x10, /* %rip */\
            0x02, /* 2 bytes follow */\
            0x77, offset; /* DW_OP_breg7, 0 */

/**
 * On syscallhook entry, the stack has been switched to the end of per-task
 * scratch space, then the old RSP and the return address have been pushed.
 */
#define SYSCALLHOOK_START(name)    \
        .global name;              \
        .hidden name;              \
        .type name, @function;     \
name:                              \
        .cfi_startproc;            \
        CFA_AT_RSP_OFFSET(8)       \
        RSP_IS_CFA                 \
        RIP_IS_DEREF_RSP(0)

#define SYSCALLHOOK_END(name)                                   \
        pop (stub_scratch_1);                                   \
        CFA_AT_RSP_OFFSET(0)                                    \
        .cfi_escape 0x10, /* DW_CFA_expression */               \
                    0x10, /* %rip */                            \
                    0x09, /* 9 byte expression follows */       \
                    0x03, /* DW_OP_addr */                      \
                    /* Individually place bytes */              \
                    stub_scratch_1 & 0xFF,                      \
                    (stub_scratch_1 & (0xFF <<  0x8)) >>  0x8,  \
                    (stub_scratch_1 & (0xFF << 0x10)) >> 0x10,  \
                    (stub_scratch_1 & (0xFF << 0x18)) >> 0x18,  \
                    (stub_scratch_1 & (0xFF << 0x20)) >> 0x20,  \
                    (stub_scratch_1 & (0xFF << 0x28)) >> 0x28,  \
                    (stub_scratch_1 & (0xFF << 0x30)) >> 0x30,  \
                    (stub_scratch_1 & (0xFF << 0x38)) >> 0x38;  \
        pop %rsp;                                               \
        .cfi_def_cfa %rsp, 0;                                   \
        jmp _syscallbuf_final_exit_instruction;                 \
        .cfi_endproc;                                           \
        .size name, .-name

/* See note above on what __morestack is for */
.global __morestack
.hidden __morestack
.type __morestack, @function
__morestack:
.cfi_startproc
CFA_AT_RSP_OFFSET(16)
RSP_IS_RSP_PLUS_OFFSET(8)
RIP_IS_DEREF_RSP(0)
callq _syscall_hook_trampoline
retq
.cfi_endproc
.size __morestack, .-__morestack

SYSCALLHOOK_START(_syscall_hook_trampoline_48_3d_01_f0_ff_ff)
        callq __morestack
        cmpq $0xfffffffffffff001,%rax
SYSCALLHOOK_END(_syscall_hook_trampoline_48_3d_01_f0_ff_ff)

SYSCALLHOOK_START(_syscall_hook_trampoline_48_3d_00_f0_ff_ff)
        callq __morestack
        cmpq $0xfffffffffffff000,%rax
SYSCALLHOOK_END(_syscall_hook_trampoline_48_3d_00_f0_ff_ff)

SYSCALLHOOK_START(_syscall_hook_trampoline_48_8b_3c_24)
         callq __morestack
         /* The original instruction after the syscall is movq (%rsp),%rdi. */
         movq 8(%rsp),%rdi
         movq (%rdi),%rdi
SYSCALLHOOK_END(_syscall_hook_trampoline_48_8b_3c_24)

SYSCALLHOOK_START(_syscall_hook_trampoline_5a_5e_c3)
        .cfi_offset %rip, 16
        RSP_IS_CFA_PLUS_OFFSET(24)
        callq __morestack
        /* The original instructions after the syscall are
           pop %rdx; pop %rsi; retq. */
        /* We're not returning to the dynamically generated stub, so
           we need to fix the stack pointer ourselves. */
        pop %rdx
        CFA_AT_RSP_OFFSET(0)
        pop %rsp
        .cfi_def_cfa %rsp, 0;
        pop %rdx
        .cfi_adjust_cfa_offset -8
        pop %rsi
        .cfi_adjust_cfa_offset -8
        pop (stub_scratch_1)
        .cfi_adjust_cfa_offset -8
        jmp _syscallbuf_final_exit_instruction

        .cfi_endproc
        .size _syscall_hook_trampoline_5a_5e_c3, .-_syscall_hook_trampoline_5a_5e_c3

SYSCALLHOOK_START(_syscall_hook_trampoline_89_c2_f7_da)
        call __morestack
        mov %eax,%edx
        neg %edx
SYSCALLHOOK_END(_syscall_hook_trampoline_89_c2_f7_da)

SYSCALLHOOK_START(_syscall_hook_trampoline_90_90_90)
        call __morestack
SYSCALLHOOK_END(_syscall_hook_trampoline_90_90_90)

SYSCALLHOOK_START(_syscall_hook_trampoline_ba_01_00_00_00)
        call __morestack
        mov $1,%edx
SYSCALLHOOK_END(_syscall_hook_trampoline_ba_01_00_00_00)

SYSCALLHOOK_START(_syscall_hook_trampoline_89_c1_31_d2)
        call __morestack
        mov %eax,%ecx
        xor %edx,%edx
SYSCALLHOOK_END(_syscall_hook_trampoline_89_c1_31_d2)

SYSCALLHOOK_START(_syscall_hook_trampoline_c3_0f_1f_84_00_00_00_00_00)
        .cfi_offset %rip, 16
        RSP_IS_CFA_PLUS_OFFSET(24)
        callq __morestack
        /* The original instructions after the syscall are
           retq; nopl 0x0(%rax,%rax,1) */
        /* We're not returning to the dynamically generated stub, so
           we need to fix the stack pointer ourselves. */
        pop %rdx
        CFA_AT_RSP_OFFSET(0)
        pop %rsp
        .cfi_def_cfa %rsp, 0;
        pop (stub_scratch_1)
        .cfi_adjust_cfa_offset -8
        jmp _syscallbuf_final_exit_instruction

        .cfi_endproc
        .size _syscall_hook_trampoline_c3_0f_1f_84_00_00_00_00_00, .-_syscall_hook_trampoline_c3_0f_1f_84_00_00_00_00_00

#endif /* __x86_64__ */

        .section .note.GNU-stack,"",@progbits
