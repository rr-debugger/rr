#if defined(__i386__) || defined(__x86_64__)
        .text
        .global _breakpoint_table_entry_start
        .hidden _breakpoint_table_entry_start
_breakpoint_table_entry_start:
        .cfi_startproc
        ret
        .global _breakpoint_table_entry_end
        .hidden _breakpoint_table_entry_end
_breakpoint_table_entry_end:
        .rept 131071 /* SYSCALLBUF_BUFFER_SIZE/8 - 1 */
        ret
        .endr
        .cfi_endproc
#else
#error unknown CPU architecture
#endif /* __i386__/__x86_64__ */

        .global _syscallbuf_code_end
        .hidden _syscallbuf_code_end
_syscallbuf_code_end:

        .section .note.GNU-stack,"",@progbits
        .previous
