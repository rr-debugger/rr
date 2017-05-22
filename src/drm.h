/* -*- Mode: C; tab-width: 8; c-basic-offset: 2; indent-tabs-mode: nil; -*- */

#ifndef RR_DRM_H
#define RR_DRM_H 1

#include <linux/ioctl.h>
#include <linux/types.h>
#include <stdint.h>

// TODO this should all move to kernel_abi.h

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The *drm.h headers don't play well when included by external code.
 * They don't compile without hacks when included by either C or C++
 * code, and additionally have version-specific quirks.  So we get
 * ourselves off that treadmill by creating a clean "shadow header".
 *
 * TODO: add checks that these shadow definitions are consistent with
 * the system headers'.
 */

/*---------------------------------------------------------------------------*/
typedef unsigned int drm_magic_t;

struct drm_version {
  int version_major;
  int version_minor;
  int version_patchlevel;
  size_t name_len;
  char* name;
  size_t date_len;
  char* date;
  size_t desc_len;
  char* desc;
};

struct drm_auth {
  drm_magic_t magic;
};

struct drm_get_cap {
  __u64 capability;
  __u64 value;
};

struct drm_gem_open {
  __u32 name;
  __u32 handle;
  __u64 size;
};

#define DRM_IOCTL_BASE 'd'
#define DRM_IO(nr) _IO(DRM_IOCTL_BASE, nr)
#define DRM_IOR(nr, type) _IOR(DRM_IOCTL_BASE, nr, type)
#define DRM_IOW(nr, type) _IOW(DRM_IOCTL_BASE, nr, type)
#define DRM_IOWR(nr, type) _IOWR(DRM_IOCTL_BASE, nr, type)

#define DRM_COMMAND_BASE 0x40

#define DRM_IOCTL_VERSION DRM_IOWR(0x00, struct drm_version)
#define DRM_IOCTL_GET_MAGIC DRM_IOR(0x02, struct drm_auth)
#define DRM_IOCTL_GEM_OPEN DRM_IOWR(0x0b, struct drm_gem_open)
#define DRM_IOCTL_GET_CAP DRM_IOWR(0x0c, struct drm_get_cap)

/*---------------------------------------------------------------------------*/
struct drm_i915_gem_pwrite {
  __u32 handle;
  __u32 pad;
  __u64 offset;
  __u64 size;
  __u64 data_ptr;
};

struct drm_i915_gem_mmap {
  __u32 handle;
  __u32 pad;
  __u64 offset;
  __u64 size;
  __u64 addr_ptr;
};

#define DRM_I915_GEM_PWRITE 0x1d
#define DRM_I915_GEM_MMAP 0x1e

#define DRM_IOCTL_I915_GEM_PWRITE                                              \
  DRM_IOW(DRM_COMMAND_BASE + DRM_I915_GEM_PWRITE, struct drm_i915_gem_pwrite)
#define DRM_IOCTL_I915_GEM_MMAP                                                \
  DRM_IOWR(DRM_COMMAND_BASE + DRM_I915_GEM_MMAP, struct drm_i915_gem_mmap)

/*---------------------------------------------------------------------------*/
struct drm_nouveau_gem_info {
  uint32_t handle;
  uint32_t domain;
  uint64_t size;
  uint64_t offset;
  uint64_t map_handle;
  uint32_t tile_mode;
  uint32_t tile_flags;
};

struct drm_nouveau_gem_new {
  struct drm_nouveau_gem_info info;
  uint32_t channel_hint;
  uint32_t align;
};

struct drm_nouveau_gem_pushbuf {
  uint32_t channel;
  uint32_t nr_buffers;
  uint64_t buffers;
  uint32_t nr_relocs;
  uint32_t nr_push;
  uint64_t relocs;
  uint64_t push;
  uint32_t suffix0;
  uint32_t suffix1;
  uint64_t vram_available;
  uint64_t gart_available;
};

#define DRM_NOUVEAU_GEM_NEW 0x40
#define DRM_NOUVEAU_GEM_PUSHBUF 0x41

#define DRM_IOCTL_NOUVEAU_GEM_NEW                                              \
  DRM_IOWR(DRM_COMMAND_BASE + DRM_NOUVEAU_GEM_NEW, struct drm_nouveau_gem_new)
#define DRM_IOCTL_NOUVEAU_GEM_PUSHBUF                                          \
  DRM_IOWR(DRM_COMMAND_BASE + DRM_NOUVEAU_GEM_PUSHBUF,                         \
           struct drm_nouveau_gem_pushbuf)

/*---------------------------------------------------------------------------*/
struct drm_radeon_info {
  uint32_t request;
  uint32_t pad;
  uint64_t value;
};

struct drm_radeon_gem_create {
  uint64_t size;
  uint64_t alignment;
  uint32_t handle;
  uint32_t initial_domain;
  uint32_t flags;
};

struct drm_radeon_gem_get_tiling {
  uint32_t handle;
  uint32_t tiling_flags;
  uint32_t pitch;
};

#define DRM_RADEON_INFO 0x27
#define DRM_RADEON_GEM_CREATE 0x1d
#define DRM_RADEON_GEM_GET_TILING 0x29

#define DRM_IOCTL_RADEON_INFO                                                  \
  DRM_IOWR(DRM_COMMAND_BASE + DRM_RADEON_INFO, struct drm_radeon_info)
#define DRM_IOCTL_RADEON_GEM_CREATE                                            \
  DRM_IOWR(DRM_COMMAND_BASE + DRM_RADEON_GEM_CREATE,                           \
           struct drm_radeon_gem_create)
#define DRM_IOCTL_RADEON_GEM_GET_TILING                                        \
  DRM_IOWR(DRM_COMMAND_BASE + DRM_RADEON_GEM_GET_TILING,                       \
           struct drm_radeon_gem_get_tiling)

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* RR_DRM_H */
