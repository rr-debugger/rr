/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_H_
#define RR_H_

/**
 * rr tracees can write data to this special fd that they want
 * verified across record/replay.  When it's written in recording, rr
 * saves the data.  During replay, the data are checked against the
 * recorded data.
 *
 * Tracees using this interface should take care that the buffers
 * storing the data are either not racy, or are synchronized by the
 * tracee.
 *
 * To simplify things, we make this a valid fd opened to /dev/null during
 * recording.
 *
 * Tracees may close this fd, or dup() something over it, etc. If that happens,
 * it will lose its magical properties.
 */
#define RR_MAGIC_SAVE_DATA_FD 999

/**
 * rr uses this fd to ensure the tracee has access to the original root
 * directory after a chroot(). Tracee close()es of this fd will be silently
 * ignored, and tracee dup()s to this fd will fail with EBADF.
 * This is set up during both recording and replay.
 */
#define RR_RESERVED_ROOT_DIR_FD 1000

/**
 * Tracees use this fd to send other fds to rr.
 * This is only set up during recording.
 * Only the outermost rr uses this. Inner rr replays will use a different fd.
 */
#define RR_RESERVED_SOCKET_FD 1001

/**
 * The preferred fd that rr uses to control tracee desched. Some software
 * (e.g. the chromium IPC code) wants to have the first few fds all to itself,
 * so we need to stay above some floor. Tracee close()es of the fd that is
 * actually assigned will be silently ignored, and tracee dup()s to that fd will
 * fail with EBADF.
 */
#define RR_DESCHED_EVENT_FLOOR_FD 100

#endif /* RR_H_ */
