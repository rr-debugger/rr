/* "Magic" (rr-implemented) syscalls that we use to initialize the
 * syscallbuf.
 *
 * NB: magic syscalls must be positive, because with at least linux
 * 3.8.0 / eglibc 2.17, rr only gets a trap for the *entry* of invalid
 * syscalls, not the exit.  rr can't handle that yet. */
/* TODO: static_assert(LAST_SYSCALL < SYS_rrcall_init_buffers) */

#define RR_CALL_BASE 1000

/**
 * The preload library calls SYS_rrcall_init_preload during its
 * initialization.
 */
#define SYS_rrcall_init_preload RR_CALL_BASE
/**
 * The preload library calls SYS_rrcall_init_buffers in each thread that
 * gets created (including the initial main thread).
 */
#define SYS_rrcall_init_buffers (RR_CALL_BASE + 1)
/**
 * The preload library calls SYS_rrcall_notify_syscall_hook_exit when
 * unlocking the syscallbuf and notify_after_syscall_hook_exit has been set.
 * The word at 4/8(sp) is returned in the syscall result and the word at
 * 8/16(sp) is stored in original_syscallno.
 */
#define SYS_rrcall_notify_syscall_hook_exit (RR_CALL_BASE + 2)
/**
 * When the preload library detects that control data has been received in a
 * syscallbuf'ed recvmsg, it calls this syscall with a pointer to the
 * 'struct msg' returned.
 */
#define SYS_rrcall_notify_control_msg (RR_CALL_BASE + 3)
/**
 * When rr replay has restored the auxv vectors for a new process (completing
 * emulation of exec), it calls this syscall. It takes one parameter, the tid
 * of the task that it has restored auxv vectors for.
 */
#define SYS_rrcall_reload_auxv (RR_CALL_BASE + 4)
/**
 * When rr replay has flushed a syscallbuf 'mprotect' record, notify any outer
 * rr of that flush. The first parameter is the tid of the task, the second
 * parameter is the address, the third parameter is the length, and the
 * fourth parameter is the prot.
 */
#define SYS_rrcall_mprotect_record (RR_CALL_BASE + 5)
/**
 * The audit library calls SYS_rrcall_notify_stap_semaphore_added once a batch
 * of SystemTap semaphores have been incremented. The first parameter is the
 * beginning of an address interval containing semaphores (inclusive) and the
 * second parameter is the end of the address interval (exclusive).
 *
 * In practice a particular probe may be listed in an object's notes more than
 * once, so be prepared to handle overlapping or redundant intervals.
 */
#define SYS_rrcall_notify_stap_semaphore_added (RR_CALL_BASE + 6)
/**
 * The audit library calls SYS_rrcall_notify_stap_semaphore_removed once a
 * batch of previously-incremented SystemTap semaphores have been decremented.
 * The first parameter is the beginning of an address interval containing
 * semaphores (inclusive) and the second parameter is the end of the address
 * interval (exclusive).
 *
 * In practice a particular probe may be listed in an object's notes more than
 * once, so be prepared to handle overlapping or redundant intervals.
 */
#define SYS_rrcall_notify_stap_semaphore_removed (RR_CALL_BASE + 7)
/**
 * This syscall can be used be the application being recorded to check for the
 * presence of the rr recorder. It is used e.g. to enable nested recording of
 * rr itself. Use of this syscall should be limited to situations where it is
 * absolutely necessary to avoid deviation of behavior depending on the
 * presence of absence of rr.
 */
#define SYS_rrcall_check_presence (RR_CALL_BASE + 8)
/**
 * Requests that rr detach from this process and re-create outside of its
 * process tree, such that it may run without seccomp.
 */
#define SYS_rrcall_detach_teleport (RR_CALL_BASE + 9)
/**
 * Requests the current rr tick.
 */
#define SYS_rrcall_current_time (RR_CALL_BASE + 10)
