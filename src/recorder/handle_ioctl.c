#include <assert.h>
#include <termios.h>
#include <stdio.h>
#include <syscall.h>
#include <stdint.h>

#include <sys/ioctl.h>
#include <asm-generic/ioctl.h>
#include <linux/ioctl.h>
#include <linux/arcfb.h>
#include <linux/fb.h>

#include <drm/drm.h>
#include <drm/radeon_drm.h>
#include <drm/i915_drm.h>

#include <linux/udf_fs_i.h>


#include <linux/soundcard.h>
#include "recorder.h"

#include "../share/ipc.h"
#include "../share/sys.h"
#include "../share/trace.h"
#include "../share/types.h"
#include "../share/util.h"

void handle_ioctl_request(struct context *ctx, int request)
{
	pid_t tid = ctx->child_tid;
	int syscall = SYS_ioctl;
	struct user_regs_struct regs;
	read_child_registers(tid, &regs);
//	printf("request: %x\n", _IOC_NR(request));

	/* here writing means: write from OS to the process */
	if (request & _IOC_WRITE) {
		int size = _IOC_SIZE(request);
		switch (request) {

		case TCGETS: /* Get and Set Terminal Attributes (from: man 4 tty_ioctl) */
		{
			record_child_data(ctx, syscall, sizeof(struct termios), regs.edx);
			break;
		}


		case FIONREAD: /* Terminal Buffer count and flushing (from: man 4 tty_ioctl) */
		case TIOCGPGRP: /* Terminal process group and session ID (from: man 4 tty_ioctl) */
		{
			record_child_data(ctx, syscall, sizeof(int), regs.edx);
			break;
		}

		case 0xc020462b:
		case 0xc048464d:
		case 0xc0204637:
		case 0xc0304627:
		{
			record_child_data(ctx, syscall, _IOC_SIZE(request), regs.edx);
			break;
		}

		// Firefox ioctls FIXME: find out what these mean.
		case 0x4010644d:
		case 0xc0186441:
		case 0x80086447:
		case 0xc0306449:
		case 0xc030644b:
		{
			record_child_data(ctx, syscall, _IOC_SIZE(request), regs.edx);
			break;
		}

		/*if (request == FIONREAD) {
		 record_child_data(tid, syscall, sizeof(int), regs.edx);
		 } else if (request == TCGETS) {
		 record_child_data(tid, syscall, sizeof(struct termios), regs.edx);
		 } else if (request == TIOCGWINSZ) {
		 record_child_data(tid, syscall, sizeof(struct winsize), regs.edx);
		 } else {*/

		/* requests starting with '64' (= 'd') */
		case DRM_IOCTL_VERSION:
		{
			assert(1==0);

			assert(size == sizeof(struct drm_version));
			struct drm_version *version = read_child_data(ctx, sizeof(struct drm_version), regs.edx);

			record_child_data(ctx, syscall, sizeof(struct drm_version), regs.edx);
			record_child_data(ctx, syscall, version->name_len, (long int) version->name);
			record_child_data(ctx, syscall, version->date_len, (long int) version->date);
			record_child_data(ctx, syscall, version->desc_len, (long int) version->desc);

			sys_free((void**) &version);
			break;
		}

		case DRM_IOCTL_GET_MAGIC:
		{
			assert(1==0);

			assert(size == sizeof(struct drm_auth));
			record_child_data(ctx, syscall, sizeof(struct drm_auth), regs.edx);
			break;
		}

		case DRM_IOCTL_RADEON_INFO:
		{
			assert(1==0);

			assert(size == sizeof(struct drm_radeon_info));
			record_child_data(ctx, syscall, sizeof(struct drm_radeon_info), regs.esi);
			break;
		}

		case DRM_IOCTL_I915_GEM_PWRITE:
		{
			assert(1==0);

			assert(size == sizeof(struct drm_i915_gem_pwrite));
			struct drm_i915_gem_pwrite* tmp = read_child_data(ctx, size, regs.edx);
			record_child_data(ctx, syscall, sizeof(struct drm_i915_gem_pwrite), regs.edx);
			record_child_data(ctx, syscall, tmp->size, (long int) tmp->data_ptr);
			sys_free((void**) &tmp);
			break;
		}

		case DRM_IOCTL_RADEON_GEM_CREATE:
		{
			assert(1==0);

			assert(size == sizeof(struct drm_radeon_gem_create));
			record_child_data(ctx, syscall, sizeof(struct drm_radeon_gem_create), regs.edx);
			break;
		}

		case DRM_IOCTL_I915_GEM_MMAP:
		{
			assert(1==0);

			assert(size == sizeof(struct drm_i915_gem_mmap));
			struct drm_i915_gem_mmap* tmp = read_child_data_tid(tid, sizeof(struct drm_i915_gem_mmap), regs.edx);
			record_child_data(ctx, syscall, sizeof(struct drm_i915_gem_mmap), regs.edx);
			record_child_data(ctx, syscall, tmp->size, tmp->addr_ptr + tmp->offset);
			sys_free((void**) &tmp);
			break;
		}

		case DRM_IOCTL_GEM_OPEN:
		{
			assert(1==0);

			assert(size == sizeof(struct drm_gem_open));
			struct drm_gem_open* tmp = read_child_data_tid(tid, size, regs.edx);
			record_child_data(ctx, syscall, sizeof(struct drm_gem_open), regs.edx);
			record_child_data(ctx, syscall, tmp->size, tmp->handle);
			sys_free((void**) &tmp);
			break;
		}

		case DRM_IOCTL_RADEON_GEM_GET_TILING:
		{
			assert(1==0);

			assert(size == sizeof(struct drm_radeon_gem_get_tiling));
			record_child_data(ctx, syscall, sizeof(struct drm_radeon_gem_get_tiling), regs.edx);
			break;
		}

		case TIOCGWINSZ: /* request for a terminal device */
		{
			/* don't care what size asked, record the buffer at the return state */
			struct winsize* tmp = read_child_data_tid(tid, size, regs.edx);
			record_child_data(ctx, syscall, sizeof(struct winsize), regs.edx);
			sys_free((void**) &tmp);
			break;
		}

		default:
		{
			int test = UDF_RELOCATE_BLOCKS;
			fprintf(stderr, "Unknown ioctl request: %x -- bailing out\n", request);
			fprintf(stderr, "we're testing: %x\n", test);
			fprintf(stderr, "type bites: %x\n", _IOC_TYPE(request));
			fprintf(stderr, "size: %d\n", _IOC_SIZE(request));
			fprintf(stderr, "addr: %x\n", read_child_edx(ctx->child_tid));
			print_register_file_tid(ctx->child_tid);
			sys_exit();
			break;
		}
		}
	}
}
