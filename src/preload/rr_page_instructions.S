// See rr_page.S

#ifdef IS_REPLAY
#define REPLAY_ONLY_CALL CALL
#define RECORD_ONLY_CALL NOCALL
#else
#define REPLAY_ONLY_CALL NOCALL
#define RECORD_ONLY_CALL CALL
#endif

STARTPROC(syscall_traced)
    CALL
    CFI_ENDPROC
STARTPROC(syscall_priv_traced)
    CALL
    CFI_ENDPROC
STARTPROC(syscall_untraced)
    CALL
    CFI_ENDPROC
STARTPROC(syscall_untraced_replay_only)
    REPLAY_ONLY_CALL
    CFI_ENDPROC
STARTPROC(syscall_untraced_record_only)
    RECORD_ONLY_CALL
    CFI_ENDPROC
STARTPROC(syscall_priv_untraced)
    CALL
    CFI_ENDPROC
STARTPROC(syscall_priv_untraced_replay_only)
    REPLAY_ONLY_CALL
    CFI_ENDPROC
STARTPROC(syscall_priv_untraced_record_only)
    RECORD_ONLY_CALL
    CFI_ENDPROC
STARTPROC(syscall_untraced_replay_assist)
#ifdef IS_REPLAY
    TRAP
#else
    CALL
#endif
    CFI_ENDPROC

LABEL(in_replay_flag)
#ifdef IS_REPLAY
    .byte 0x01
#else
    .byte 0x00
#endif
.byte 0x00, 0x00, 0x00

// During replay, we put the breakpoint_value here. During record this remains
// as -1, giving us 8 ff bytes at a well known address during record. These are used
// during exit.
LABEL(breakpoint_value)
LABEL(ff_bytes)
.byte 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff

// ABI stability ends here.

#undef REPLAY_ONLY_CALL
#undef RECORD_ONLY_CALL
