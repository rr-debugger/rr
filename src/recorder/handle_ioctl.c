/* -*- Mode: C; tab-width: 8; c-basic-offset: 8; indent-tabs-mode: t; -*- */

//#define DEBUGTAG "ioctl"

#include "handle_ioctl.h"

#include <stddef.h>		/* broken DRM headers need these */
#include <stdint.h>

#include <assert.h>
#include <drm/drm.h>
#include <drm/i915_drm.h>
#include <drm/nouveau_drm.h>
#include <drm/radeon_drm.h>
#include <linux/arcfb.h>
#include <linux/fb.h>
#include <linux/ioctl.h>
#include <linux/perf_event.h>
#include <linux/soundcard.h>
#include <linux/udf_fs_i.h>
#include <stdio.h>
#include <syscall.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <termios.h>

#include "recorder.h"

#include "../share/dbg.h"
#include "../share/ipc.h"
#include "../share/sys.h"
#include "../share/task.h"
#include "../share/trace.h"
#include "../share/types.h"
#include "../share/util.h"

void handle_ioctl_request(struct task *t, int request)
{
	pid_t tid = t->tid;
	int syscall = SYS_ioctl;
	int type = _IOC_TYPE(request);
	int nr = _IOC_NR(request);
	int dir = _IOC_DIR(request);
	int size = _IOC_SIZE(request);
	struct user_regs_struct regs;

	debug("handling ioctl(0x%x): type:0x%x nr:0x%x dir:0x%x size:%d",
	      request, type, nr, dir, size);

	read_child_registers(tid, &regs);

	/* Some ioctl()s are irregular and don't follow the _IOC()
	 * conventions.  Special case them here. */
	switch (request) {
	case TCGETS:
		push_syscall(t, syscall);
		record_child_data(t, sizeof(struct termios), (void*)regs.edx);
		pop_syscall(t);
		return;
	}

	/* In ioctl language, "_IOC_WRITE" means "outparam".  Both
	 * READ and WRITE can be set for inout params. */
	if (!(_IOC_WRITE & dir)) {
		/* If the kernel isn't going to write any data back to
		 * us, we hope and pray that the result of the ioctl
		 * (observable to the tracee) is deterministic. */
		debug("  (deterministic ioctl, nothing to do)");
		return;
	}

	/* The following are thought to be "regular" ioctls, the
	 * processing of which is only known to (observably) write to
	 * the bytes in the structure passed to the kernel.  So all we
	 * need is to record |size| bytes.*/
	switch (request) {
	/* TODO: what are the 0x46 ioctls? */
	case 0xc020462b:
	case 0xc048464d:
	case 0xc0204637:
	case 0xc0304627:
		fatal("Unknown 0x46-series ioctl nr 0x%x", nr);
		break;	/* not reached */

	/* The following are ioctls for the linux Direct Rendering
	 * Manager (DRM).  The ioctl "type" is 0x64 (100, or ASCII 'd'
	 * as they docs helpfully declare it :/).  The ioctl numbers
	 * are allocated as follows
	 *
	 *  [0x00, 0x40) -- generic commands
	 *  [0x40, 0xa0) -- device-specific commands
	 *  [0xa0, 0xff) -- more generic commands
	 *
	 * Chasing down unknown ioctls is somewhat annoying in this
	 * scheme, but here's an example: request "0xc0406481".  "0xc"
	 * means it's a read/write ioctl, and "0x0040" is the size of
	 * the payload.  The actual ioctl request is "0x6481".
	 *
	 * As we saw above, "0x64" is the DRM type.  So now we need to
	 * see what command "0x81" is.  It's in the
	 * device-specific-command space, so we can start by
	 * subtracting "0x40" to get a command "0x41".  Then
	 *
	 *  $ cd 
	 *  $ grep -rn 0x41 *
	 *  nouveau_drm.h:200:#define DRM_NOUVEAU_GEM_PUSHBUF        0x41
	 *
	 * Well that was lucky!  So the command is
	 * DRM_NOUVEAU_GEM_PUSHBUF, and the parameters etc can be
	 * tracked down from that.
	 */

	/* TODO: At least one of these ioctl()s, most likely
	 * NOUVEAU_GEM_NEW, opens a file behind rr's back on behalf of
	 * the callee.  That wreaks havoc later on in execution, so we
	 * disable the whole lot for now until rr can handle that
	 * behavior (by recording access to shmem segments). */
	case DRM_IOCTL_VERSION:
	case DRM_IOCTL_NOUVEAU_GEM_NEW:
	case DRM_IOCTL_NOUVEAU_GEM_PUSHBUF:
		fatal("Intentionally unhandled DRM(0x64) ioctl nr 0x%x", nr);
		break;

	case DRM_IOCTL_GET_MAGIC:
	case DRM_IOCTL_RADEON_INFO:
	case DRM_IOCTL_I915_GEM_PWRITE:
	case DRM_IOCTL_GEM_OPEN:
	case DRM_IOCTL_I915_GEM_MMAP:
	case DRM_IOCTL_RADEON_GEM_CREATE:
	case DRM_IOCTL_RADEON_GEM_GET_TILING:
		fatal("Not-understood DRM(0x64) ioctl nr 0x%x", nr);
		break;	/* not reached */

	case 0x4010644d:
	case 0xc0186441:
	case 0x80086447:
	case 0xc0306449:
	case 0xc030644b:
		fatal("Unknown DRM(0x64) ioctl nr 0x%x", nr);
		break;	/* not reached */

	default:
		print_register_file_tid(t->tid);
		fatal("Unknown ioctl(0x%x): type:0x%x nr:0x%x dir:0x%x size:%d addr:%p",
		      request, type, nr, dir, size, (void*)regs.edx);
	}
}
