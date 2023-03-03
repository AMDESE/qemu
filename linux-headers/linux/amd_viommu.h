/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * AMD Hardwaer Accelerated Virtualized IOMMU (HW-vIOMMU)
 *
 * Copyright (c) 2023, Advanced Micro Devices, Inc.
 *
 */
#ifndef _UAPI_AMD_VIOMMU_H_
#define _UAPI_AMD_VIOMMU_H_

#include <linux/types.h>
#include <linux/ioctl.h>

/**
 * The ioctl interfaces in this file are specific for AMD HW-vIOMMU.
 * They are an extension of extend the IOMMUFD ioctl interfaces.
 * Please see include/uapi/linux/iommufd.h for more detail.
 */
#include <linux/iommufd.h>

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
};

/**
 * struct amd_viommu_iommu_info - ioctl(VIOMMU_IOMMU_[INIT|DESTROY])
 * @size: sizeof(struct amd_viommu_iommu_info)
 * @iommu_id: PCI device ID of the AMD IOMMU instance
 * @gid: guest ID
 *
 * Initialize and destroy AMD HW-vIOMMU instances for the specified
 * guest ID.
 */
struct amd_viommu_iommu_info {
	__u32	size;
	__u32	iommu_id;
	__u32	gid;
};
#define VIOMMU_IOMMU_INIT	_IO(IOMMUFD_TYPE, IOMMUFD_CMD_IOMMU_INIT)
#define VIOMMU_IOMMU_DESTROY	_IO(IOMMUFD_TYPE, IOMMUFD_CMD_IOMMU_DESTROY)

/**
 * struct amd_viommu_dev_info - ioctl(VIOMMU_DEVICE_[ATTACH|DETACH])
 * @size: sizeof(struct amd_viommu_dev_info)
 * @iommu_id: PCI device ID of the AMD IOMMU instance
 * @gid: guest ID
 * @hdev_id: host PCI device ID
 * @gdev_id: guest PCI device ID
 * @queue_id: guest PCI device queue ID
 *
 * Attach / Detach PCI device to a HW-vIOMMU instance, and program
 * the IOMMU Device ID mapping table for the specified guest.
 */
struct amd_viommu_dev_info {
	__u32	size;
	__u32	iommu_id;
	__u32	gid;
	__u16	hdev_id;
	__u16	gdev_id;
	__u16	queue_id;
};

#define VIOMMU_DEVICE_ATTACH	_IO(IOMMUFD_TYPE, IOMMUFD_CMD_DEVICE_ATTACH)
#define VIOMMU_DEVICE_DETACH	_IO(IOMMUFD_TYPE, IOMMUFD_CMD_DEVICE_DETACH)

/**
 * struct amd_viommu_dom_info - ioctl(VIOMMU_DOMAIN_[ATTACH|DETACH])
 * @size: sizeof(struct amd_viommu_dom_info)
 * @iommu_id: PCI device ID of the AMD IOMMU instance
 * @gid: guest ID
 * @hdev_id: host PCI device ID
 * @gdev_id: guest PCI device ID
 * @gdom_id: guest domain ID
 *
 * Attach / Detach domain of a PCI device to a HW-vIOMMU instance, and program
 * the IOMMU Domain ID mapping table for the specified guest.
 */
struct amd_viommu_dom_info {
	__u32	size;
	__u32	iommu_id;
	__u32	gid;
	__u16	gdev_id;
	__u16	gdom_id;
};

#define VIOMMU_DOMAIN_ATTACH	_IO(IOMMUFD_TYPE, IOMMUFD_CMD_DOMAIN_ATTACH)
#define VIOMMU_DOMAIN_DETACH	_IO(IOMMUFD_TYPE, IOMMUFD_CMD_DOMAIN_DETACH)

/**
 * struct amd_viommu_mmio_data- ioctl(VIOMMU_MMIO_ACCESS)
 * @size: sizeof(struct amd_viommu_mmio_data)
 * @iommu_id: PCI device ID of the AMD IOMMU instance
 * @gid: guest ID
 * @offset: specify MMIO offset
 * @value: specify MMIO write value or retrieving MMIO read value
 * @mmio_size: specify MMIO size
 * @is_write: specify MMIO read (0) / write (1)
 *
 * - Trap guest IOMMU MMIO write to program HW-vIOMMU for the specified
 *   guest.
 * - Trap guest IOMMU MMIO read to emulate return value for the specified
 *   guest.
 */
struct amd_viommu_mmio_data {
	__u32	size;
	__u32	iommu_id;
	__u32	gid;
	__u32	offset;
	__u64	value;
	__u32	mmio_size;
	__u8	is_write;
};

#define VIOMMU_MMIO_ACCESS	_IO(IOMMUFD_TYPE, IOMMUFD_CMD_MMIO_ACCESS)

/**
 * struct amd_viommu_cmdbuf_data - ioctl(VIOMMU_CMDBUF_UPDATE)
 * @size: sizeof(struct amd_viommu_cmdbuf_data)
 * @iommu_id: PCI device ID of the AMD IOMMU instance
 * @gid: guest ID
 * @gcmdbuf_size: guest command buffer size
 * @hva: host virtual address for the guest command buffer
 *
 * Trap guest command buffer initialization to setup HW-vIOMMU command buffer
 * for the specified guest.
 */
struct amd_viommu_cmdbuf_data {
	__u32	size;
	__u32	iommu_id;
	__u32	gid;
	__u32	cmdbuf_size;
	__u64	hva;
};

#define VIOMMU_CMDBUF_UPDATE	_IO(IOMMUFD_TYPE, IOMMUFD_CMD_CMDBUF_UPDATE)

#endif
