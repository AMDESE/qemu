/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2021-2022, NVIDIA CORPORATION & AFFILIATES.
 */
#ifndef _UAPI_AMD_VIOMMU_H_
#define _UAPI_AMD_VIOMMU_H_

#include <linux/types.h>
#include <linux/ioctl.h>

#define AMD_VIOMMU_TYPE (';')

enum iommufd_viommu_cmd {
	IOMMUFD_VIOMMU_CMD_BASE = 0x60,
	IOMMUFD_CMD_IOMMU_INIT = IOMMUFD_VIOMMU_CMD_BASE,
	IOMMUFD_CMD_IOMMU_DESTROY,
	IOMMUFD_CMD_DEVICE_ATTACH,
	IOMMUFD_CMD_DEVICE_DETACH,
	IOMMUFD_CMD_DOMAIN_ATTACH,
	IOMMUFD_CMD_DOMAIN_DETACH,
	IOMMUFD_CMD_MMIO_ACCESS,
	IOMMUFD_CMD_CMDBUF_UPDATE,
	IOMMUFD_CMD_GCR3_UPDATE,
};

struct amd_viommu_iommu_info {
	__u32	size;
	__u32	iommu_id;
	__u32	gid;
};
#define VIOMMU_IOMMU_INIT	_IO(AMD_VIOMMU_TYPE, IOMMUFD_CMD_IOMMU_INIT)
#define VIOMMU_IOMMU_DESTROY	_IO(AMD_VIOMMU_TYPE, IOMMUFD_CMD_IOMMU_DESTROY)

struct amd_viommu_dev_info {
	__u32	size;
	__u32	iommu_id;
	__u32	gid;
	__u16	hdev_id;
	__u16	gdev_id;
	__u16	queue_id;
};

#define VIOMMU_DEVICE_ATTACH	_IO(AMD_VIOMMU_TYPE, IOMMUFD_CMD_DEVICE_ATTACH)
#define VIOMMU_DEVICE_DETACH	_IO(AMD_VIOMMU_TYPE, IOMMUFD_CMD_DEVICE_DETACH)

struct amd_viommu_dom_info {
	__u32	size;
	__u32	iommu_id;
	__u32	gid;
	__u16	gdev_id;
	__u16	gdom_id;
};

#define VIOMMU_DOMAIN_ATTACH	_IO(AMD_VIOMMU_TYPE, IOMMUFD_CMD_DOMAIN_ATTACH)
#define VIOMMU_DOMAIN_DETACH	_IO(AMD_VIOMMU_TYPE, IOMMUFD_CMD_DOMAIN_DETACH)

struct amd_viommu_mmio_data {
	__u32	size;
	__u32	iommu_id;
	__u32	gid;
	__u32	offset;
	__u64	value;
	__u32	mmio_size;
	__u8	is_write;
};

#define VIOMMU_MMIO_ACCESS	_IO(AMD_VIOMMU_TYPE, IOMMUFD_CMD_MMIO_ACCESS)

struct amd_viommu_cmdbuf_data {
	__u32	size;
	__u32	iommu_id;
	__u32	gid;
	__u32	cmdbuf_size;
	__u64	hva;
};

#define VIOMMU_CMDBUF_UPDATE	_IO(AMD_VIOMMU_TYPE, IOMMUFD_CMD_CMDBUF_UPDATE)

struct amd_viommu_gcr3_data {
	__u32	size;
	__u32	iommu_id;
	__u32	gid;
	__u16	gdev_id;
	__u16	flags;
	__u64	gcr3;
	__u64	gcr3_va;
};

#define VIOMMU_GCR3_UPDATE	_IO(AMD_VIOMMU_TYPE, IOMMUFD_CMD_GCR3_UPDATE)
#endif
