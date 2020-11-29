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

#ifndef IS_REPLAY
// These 8 ff bytes are at a well known address during record and are used
// during exit. However, since they aren't used during replay, they are not
// currently part of the rr_page ABI. To ensure they don't unintentionally
// become part of the ABI, we only include them in the record page.
ff_bytes:
.byte 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
#endif

#undef REPLAY_ONLY_CALL
#undef RECORD_ONLY_CALL
