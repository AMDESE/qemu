/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/* Copyright (c) 2021-2022, NVIDIA CORPORATION & AFFILIATES.
 */
#ifndef _IOMMUFD_H
#define _IOMMUFD_H

#include <linux/types.h>
#include <linux/ioctl.h>

#define IOMMUFD_TYPE (';')

/**
 * DOC: General ioctl format
 *
 * The ioctl interface follows a general format to allow for extensibility. Each
 * ioctl is passed in a structure pointer as the argument providing the size of
 * the structure in the first u32. The kernel checks that any structure space
 * beyond what it understands is 0. This allows userspace to use the backward
 * compatible portion while consistently using the newer, larger, structures.
 *
 * ioctls use a standard meaning for common errnos:
 *
 *  - ENOTTY: The IOCTL number itself is not supported at all
 *  - E2BIG: The IOCTL number is supported, but the provided structure has
 *    non-zero in a part the kernel does not understand.
 *  - EOPNOTSUPP: The IOCTL number is supported, and the structure is
 *    understood, however a known field has a value the kernel does not
 *    understand or support.
 *  - EINVAL: Everything about the IOCTL was understood, but a field is not
 *    correct.
 *  - ENOENT: An ID or IOVA provided does not exist.
 *  - ENOMEM: Out of memory.
 *  - EOVERFLOW: Mathematics overflowed.
 *
 * As well as additional errnos, within specific ioctls.
 */
enum {
	IOMMUFD_CMD_BASE = 0x80,
	IOMMUFD_CMD_DESTROY = IOMMUFD_CMD_BASE,
	IOMMUFD_CMD_IOAS_ALLOC,
	IOMMUFD_CMD_IOAS_ALLOW_IOVAS,
	IOMMUFD_CMD_IOAS_COPY,
	IOMMUFD_CMD_IOAS_IOVA_RANGES,
	IOMMUFD_CMD_IOAS_MAP,
	IOMMUFD_CMD_IOAS_UNMAP,
	IOMMUFD_CMD_OPTION,
	IOMMUFD_CMD_VFIO_IOAS,
	IOMMUFD_CMD_HWPT_ALLOC,
	IOMMUFD_CMD_GET_HW_INFO,
	IOMMUFD_CMD_HWPT_SET_DIRTY_TRACKING,
	IOMMUFD_CMD_HWPT_GET_DIRTY_BITMAP,
	IOMMUFD_CMD_HWPT_INVALIDATE,
	IOMMUFD_CMD_SET_IDEV_DATA,
	IOMMUFD_CMD_UNSET_IDEV_DATA,
};

/**
 * struct iommu_destroy - ioctl(IOMMU_DESTROY)
 * @size: sizeof(struct iommu_destroy)
 * @id: iommufd object ID to destroy. Can be any destroyable object type.
 *
 * Destroy any object held within iommufd.
 */
struct iommu_destroy {
	__u32 size;
	__u32 id;
};
#define IOMMU_DESTROY _IO(IOMMUFD_TYPE, IOMMUFD_CMD_DESTROY)

/**
 * struct iommu_ioas_alloc - ioctl(IOMMU_IOAS_ALLOC)
 * @size: sizeof(struct iommu_ioas_alloc)
 * @flags: Must be 0
 * @out_ioas_id: Output IOAS ID for the allocated object
 *
 * Allocate an IO Address Space (IOAS) which holds an IO Virtual Address (IOVA)
 * to memory mapping.
 */
struct iommu_ioas_alloc {
	__u32 size;
	__u32 flags;
	__u32 out_ioas_id;
};
#define IOMMU_IOAS_ALLOC _IO(IOMMUFD_TYPE, IOMMUFD_CMD_IOAS_ALLOC)

/**
 * struct iommu_iova_range - ioctl(IOMMU_IOVA_RANGE)
 * @start: First IOVA
 * @last: Inclusive last IOVA
 *
 * An interval in IOVA space.
 */
struct iommu_iova_range {
	__aligned_u64 start;
	__aligned_u64 last;
};

/**
 * struct iommu_ioas_iova_ranges - ioctl(IOMMU_IOAS_IOVA_RANGES)
 * @size: sizeof(struct iommu_ioas_iova_ranges)
 * @ioas_id: IOAS ID to read ranges from
 * @num_iovas: Input/Output total number of ranges in the IOAS
 * @__reserved: Must be 0
 * @allowed_iovas: Pointer to the output array of struct iommu_iova_range
 * @out_iova_alignment: Minimum alignment required for mapping IOVA
 *
 * Query an IOAS for ranges of allowed IOVAs. Mapping IOVA outside these ranges
 * is not allowed. num_iovas will be set to the total number of iovas and
 * the allowed_iovas[] will be filled in as space permits.
 *
 * The allowed ranges are dependent on the HW path the DMA operation takes, and
 * can change during the lifetime of the IOAS. A fresh empty IOAS will have a
 * full range, and each attached device will narrow the ranges based on that
 * device's HW restrictions. Detaching a device can widen the ranges. Userspace
 * should query ranges after every attach/detach to know what IOVAs are valid
 * for mapping.
 *
 * On input num_iovas is the length of the allowed_iovas array. On output it is
 * the total number of iovas filled in. The ioctl will return -EMSGSIZE and set
 * num_iovas to the required value if num_iovas is too small. In this case the
 * caller should allocate a larger output array and re-issue the ioctl.
 *
 * out_iova_alignment returns the minimum IOVA alignment that can be given
 * to IOMMU_IOAS_MAP/COPY. IOVA's must satisfy::
 *
 *   starting_iova % out_iova_alignment == 0
 *   (starting_iova + length) % out_iova_alignment == 0
 *
 * out_iova_alignment can be 1 indicating any IOVA is allowed. It cannot
 * be higher than the system PAGE_SIZE.
 */
struct iommu_ioas_iova_ranges {
	__u32 size;
	__u32 ioas_id;
	__u32 num_iovas;
	__u32 __reserved;
	__aligned_u64 allowed_iovas;
	__aligned_u64 out_iova_alignment;
};
#define IOMMU_IOAS_IOVA_RANGES _IO(IOMMUFD_TYPE, IOMMUFD_CMD_IOAS_IOVA_RANGES)

/**
 * struct iommu_ioas_allow_iovas - ioctl(IOMMU_IOAS_ALLOW_IOVAS)
 * @size: sizeof(struct iommu_ioas_allow_iovas)
 * @ioas_id: IOAS ID to allow IOVAs from
 * @num_iovas: Input/Output total number of ranges in the IOAS
 * @__reserved: Must be 0
 * @allowed_iovas: Pointer to array of struct iommu_iova_range
 *
 * Ensure a range of IOVAs are always available for allocation. If this call
 * succeeds then IOMMU_IOAS_IOVA_RANGES will never return a list of IOVA ranges
 * that are narrower than the ranges provided here. This call will fail if
 * IOMMU_IOAS_IOVA_RANGES is currently narrower than the given ranges.
 *
 * When an IOAS is first created the IOVA_RANGES will be maximally sized, and as
 * devices are attached the IOVA will narrow based on the device restrictions.
 * When an allowed range is specified any narrowing will be refused, ie device
 * attachment can fail if the device requires limiting within the allowed range.
 *
 * Automatic IOVA allocation is also impacted by this call. MAP will only
 * allocate within the allowed IOVAs if they are present.
 *
 * This call replaces the entire allowed list with the given list.
 */
struct iommu_ioas_allow_iovas {
	__u32 size;
	__u32 ioas_id;
	__u32 num_iovas;
	__u32 __reserved;
	__aligned_u64 allowed_iovas;
};
#define IOMMU_IOAS_ALLOW_IOVAS _IO(IOMMUFD_TYPE, IOMMUFD_CMD_IOAS_ALLOW_IOVAS)

/**
 * enum iommufd_ioas_map_flags - Flags for map and copy
 * @IOMMU_IOAS_MAP_FIXED_IOVA: If clear the kernel will compute an appropriate
 *                             IOVA to place the mapping at
 * @IOMMU_IOAS_MAP_WRITEABLE: DMA is allowed to write to this mapping
 * @IOMMU_IOAS_MAP_READABLE: DMA is allowed to read from this mapping
 */
enum iommufd_ioas_map_flags {
	IOMMU_IOAS_MAP_FIXED_IOVA = 1 << 0,
	IOMMU_IOAS_MAP_WRITEABLE = 1 << 1,
	IOMMU_IOAS_MAP_READABLE = 1 << 2,
};

/**
 * struct iommu_ioas_map - ioctl(IOMMU_IOAS_MAP)
 * @size: sizeof(struct iommu_ioas_map)
 * @flags: Combination of enum iommufd_ioas_map_flags
 * @ioas_id: IOAS ID to change the mapping of
 * @__reserved: Must be 0
 * @user_va: Userspace pointer to start mapping from
 * @length: Number of bytes to map
 * @iova: IOVA the mapping was placed at. If IOMMU_IOAS_MAP_FIXED_IOVA is set
 *        then this must be provided as input.
 *
 * Set an IOVA mapping from a user pointer. If FIXED_IOVA is specified then the
 * mapping will be established at iova, otherwise a suitable location based on
 * the reserved and allowed lists will be automatically selected and returned in
 * iova.
 *
 * If IOMMU_IOAS_MAP_FIXED_IOVA is specified then the iova range must currently
 * be unused, existing IOVA cannot be replaced.
 */
struct iommu_ioas_map {
	__u32 size;
	__u32 flags;
	__u32 ioas_id;
	__u32 __reserved;
	__aligned_u64 user_va;
	__aligned_u64 length;
	__aligned_u64 iova;
};
#define IOMMU_IOAS_MAP _IO(IOMMUFD_TYPE, IOMMUFD_CMD_IOAS_MAP)

/**
 * struct iommu_ioas_copy - ioctl(IOMMU_IOAS_COPY)
 * @size: sizeof(struct iommu_ioas_copy)
 * @flags: Combination of enum iommufd_ioas_map_flags
 * @dst_ioas_id: IOAS ID to change the mapping of
 * @src_ioas_id: IOAS ID to copy from
 * @length: Number of bytes to copy and map
 * @dst_iova: IOVA the mapping was placed at. If IOMMU_IOAS_MAP_FIXED_IOVA is
 *            set then this must be provided as input.
 * @src_iova: IOVA to start the copy
 *
 * Copy an already existing mapping from src_ioas_id and establish it in
 * dst_ioas_id. The src iova/length must exactly match a range used with
 * IOMMU_IOAS_MAP.
 *
 * This may be used to efficiently clone a subset of an IOAS to another, or as a
 * kind of 'cache' to speed up mapping. Copy has an efficiency advantage over
 * establishing equivalent new mappings, as internal resources are shared, and
 * the kernel will pin the user memory only once.
 */
struct iommu_ioas_copy {
	__u32 size;
	__u32 flags;
	__u32 dst_ioas_id;
	__u32 src_ioas_id;
	__aligned_u64 length;
	__aligned_u64 dst_iova;
	__aligned_u64 src_iova;
};
#define IOMMU_IOAS_COPY _IO(IOMMUFD_TYPE, IOMMUFD_CMD_IOAS_COPY)

/**
 * struct iommu_ioas_unmap - ioctl(IOMMU_IOAS_UNMAP)
 * @size: sizeof(struct iommu_ioas_unmap)
 * @ioas_id: IOAS ID to change the mapping of
 * @iova: IOVA to start the unmapping at
 * @length: Number of bytes to unmap, and return back the bytes unmapped
 *
 * Unmap an IOVA range. The iova/length must be a superset of a previously
 * mapped range used with IOMMU_IOAS_MAP or IOMMU_IOAS_COPY. Splitting or
 * truncating ranges is not allowed. The values 0 to U64_MAX will unmap
 * everything.
 */
struct iommu_ioas_unmap {
	__u32 size;
	__u32 ioas_id;
	__aligned_u64 iova;
	__aligned_u64 length;
};
#define IOMMU_IOAS_UNMAP _IO(IOMMUFD_TYPE, IOMMUFD_CMD_IOAS_UNMAP)

/**
 * enum iommufd_option - ioctl(IOMMU_OPTION_RLIMIT_MODE) and
 *                       ioctl(IOMMU_OPTION_HUGE_PAGES)
 * @IOMMU_OPTION_RLIMIT_MODE:
 *    Change how RLIMIT_MEMLOCK accounting works. The caller must have privilege
 *    to invoke this. Value 0 (default) is user based accouting, 1 uses process
 *    based accounting. Global option, object_id must be 0
 * @IOMMU_OPTION_HUGE_PAGES:
 *    Value 1 (default) allows contiguous pages to be combined when generating
 *    iommu mappings. Value 0 disables combining, everything is mapped to
 *    PAGE_SIZE. This can be useful for benchmarking.  This is a per-IOAS
 *    option, the object_id must be the IOAS ID.
 */
enum iommufd_option {
	IOMMU_OPTION_RLIMIT_MODE = 0,
	IOMMU_OPTION_HUGE_PAGES = 1,
};

/**
 * enum iommufd_option_ops - ioctl(IOMMU_OPTION_OP_SET) and
 *                           ioctl(IOMMU_OPTION_OP_GET)
 * @IOMMU_OPTION_OP_SET: Set the option's value
 * @IOMMU_OPTION_OP_GET: Get the option's value
 */
enum iommufd_option_ops {
	IOMMU_OPTION_OP_SET = 0,
	IOMMU_OPTION_OP_GET = 1,
};

/**
 * struct iommu_option - iommu option multiplexer
 * @size: sizeof(struct iommu_option)
 * @option_id: One of enum iommufd_option
 * @op: One of enum iommufd_option_ops
 * @__reserved: Must be 0
 * @object_id: ID of the object if required
 * @val64: Option value to set or value returned on get
 *
 * Change a simple option value. This multiplexor allows controlling options
 * on objects. IOMMU_OPTION_OP_SET will load an option and IOMMU_OPTION_OP_GET
 * will return the current value.
 */
struct iommu_option {
	__u32 size;
	__u32 option_id;
	__u16 op;
	__u16 __reserved;
	__u32 object_id;
	__aligned_u64 val64;
};
#define IOMMU_OPTION _IO(IOMMUFD_TYPE, IOMMUFD_CMD_OPTION)

/**
 * enum iommufd_vfio_ioas_op - IOMMU_VFIO_IOAS_* ioctls
 * @IOMMU_VFIO_IOAS_GET: Get the current compatibility IOAS
 * @IOMMU_VFIO_IOAS_SET: Change the current compatibility IOAS
 * @IOMMU_VFIO_IOAS_CLEAR: Disable VFIO compatibility
 */
enum iommufd_vfio_ioas_op {
	IOMMU_VFIO_IOAS_GET = 0,
	IOMMU_VFIO_IOAS_SET = 1,
	IOMMU_VFIO_IOAS_CLEAR = 2,
};

/**
 * struct iommu_vfio_ioas - ioctl(IOMMU_VFIO_IOAS)
 * @size: sizeof(struct iommu_vfio_ioas)
 * @ioas_id: For IOMMU_VFIO_IOAS_SET the input IOAS ID to set
 *           For IOMMU_VFIO_IOAS_GET will output the IOAS ID
 * @op: One of enum iommufd_vfio_ioas_op
 * @__reserved: Must be 0
 *
 * The VFIO compatibility support uses a single ioas because VFIO APIs do not
 * support the ID field. Set or Get the IOAS that VFIO compatibility will use.
 * When VFIO_GROUP_SET_CONTAINER is used on an iommufd it will get the
 * compatibility ioas, either by taking what is already set, or auto creating
 * one. From then on VFIO will continue to use that ioas and is not effected by
 * this ioctl. SET or CLEAR does not destroy any auto-created IOAS.
 */
struct iommu_vfio_ioas {
	__u32 size;
	__u32 ioas_id;
	__u16 op;
	__u16 __reserved;
};
#define IOMMU_VFIO_IOAS _IO(IOMMUFD_TYPE, IOMMUFD_CMD_VFIO_IOAS)

/**
 * struct iommu_hwpt_arm_smmuv3 - ARM SMMUv3 specific translation table info
 *                                (IOMMU_HWPT_DATA_ARM_SMMUV3)
 *
 * @flags: Translation table entry attributes
 * @ste_len: Length of the user Stream Table Entry
 * @ste_uptr: User pointer to a user Stream Table Entry
 * @event_len: Length of the returning event
 * @out_event_uptr: User pointer to a returning event, to report a C_BAD_STE
 *                  upon an STE configuration failure
 *
 * ARM SMMUv3 specific data to create page tables for a nested configuration.
 *
 * For a nested stage-1 translation table allocation, kernel will read all the
 * information of a user space stage-1 Context Descriptor table from the given
 * user space Stream Table Entry pointed by @ste_uptr. The @event_len and the
 * @out_event_uptr in pair are optional. If they are both provided, kernel will
 * report an STE error to the memory location pointed by @out_event_uptr, when
 * the allocation fails due to some problem in the user space STE.
 *
 * As long as the SMMUv3 hardware supports a stage-1 page table, the default
 * allocation of a page table in the kernel is always for a stage-1 type. So,
 * this data structure can be also used to allocate a kernel-managed stage-2
 * translation table, by setting IOMMU_SMMUV3_FLAG_S2 in the @flags, in which
 * case only this flag matters and the kernel will ignore all other inputs.
 */
struct iommu_hwpt_arm_smmuv3 {
#define IOMMU_SMMUV3_FLAG_S2   (1 << 0) /* if unset, stage-1 */
	__aligned_u64 flags;
	__aligned_u64 ste_len;
	__aligned_u64 ste_uptr;
	__aligned_u64 event_len;
	__aligned_u64 out_event_uptr;
};

/**
 * enum iommufd_hwpt_alloc_flags - Flags for HWPT allocation
 * @IOMMU_HWPT_ALLOC_NEST_PARENT: If set, allocate a HWPT that can serve as
 *                                the parent HWPT in a nesting configuration.
 * @IOMMU_HWPT_ALLOC_DIRTY_TRACKING: Dirty tracking support for device IOMMU is
 *                                   enforced on device attachment
 */
enum iommufd_hwpt_alloc_flags {
	IOMMU_HWPT_ALLOC_NEST_PARENT = 1 << 0,
	IOMMU_HWPT_ALLOC_DIRTY_TRACKING = 1 << 1,
};

/**
 * enum iommu_hwpt_vtd_s1_flags - Intel VT-d stage-1 page table
 *                                entry attributes
 * @IOMMU_VTD_S1_SRE: Supervisor request
 * @IOMMU_VTD_S1_EAFE: Extended access enable
 * @IOMMU_VTD_S1_WPE: Write protect enable
 */
enum iommu_hwpt_vtd_s1_flags {
	IOMMU_VTD_S1_SRE = 1 << 0,
	IOMMU_VTD_S1_EAFE = 1 << 1,
	IOMMU_VTD_S1_WPE = 1 << 2,
};

/**
 * struct iommu_hwpt_vtd_s1 - Intel VT-d stage-1 page table
 *                            info (IOMMU_HWPT_DATA_VTD_S1)
 * @flags: Combination of enum iommu_hwpt_vtd_s1_flags
 * @pgtbl_addr: The base address of the stage-1 page table.
 * @addr_width: The address width of the stage-1 page table
 * @__reserved: Must be 0
 */
struct iommu_hwpt_vtd_s1 {
	__aligned_u64 flags;
	__aligned_u64 pgtbl_addr;
	__u32 addr_width;
	__u32 __reserved;
};

/**
 * struct iommu_hwpt_amd_v2 - AMD IOMMU specific user-managed
 *                            v2 I/O page table data
 * @gcr3: GCR3 guest physical ddress
 * @flags.glx: GCR3 table levels
 * @flags.giov: GIOV mode
 * @flags.guest_paging_mode: Guest v2 page table paging mode
 * @flags.reserved : Must be 0
 * @gid: Guest ID
 * @gdom_id: Guest domain ID
 * @__reserved: Must be 0
 */
struct iommu_hwpt_amd_v2 {
	__aligned_u64 gcr3;
	__aligned_u64 gcr3_va;
	struct {
		__aligned_u64 glx  : 1,
			      giov : 1,
			      guest_paging_mode : 2,
			      reserved : 60;
	} flags;
	__u32 gdom_id;
	__u32 __reserved;
};

/**
 * enum iommu_hwpt_data_type - IOMMU HWPT Data Type
 * @IOMMU_HWPT_DATA_NONE: no data
 * @IOMMU_HWPT_DATA_VTD_S1: Intel VT-d stage-1 page table
 * @IOMMU_HWPT_DATA_ARM_SMMUV3: ARM SMMUv3 Context Descriptor Table
 * @IOMMU_HWPT_DATA_AMD_V2: AMD IOMMUv2 page table
 */
enum iommu_hwpt_data_type {
	IOMMU_HWPT_DATA_NONE,
	IOMMU_HWPT_DATA_VTD_S1,
//	IOMMU_HWPT_DATA_ARM_SMMUV3,
	IOMMU_HWPT_DATA_AMD_V2,
};

/**
 * struct iommu_hwpt_alloc - ioctl(IOMMU_HWPT_ALLOC)
 * @size: sizeof(struct iommu_hwpt_alloc)
 * @flags: Combination of enum iommufd_hwpt_alloc_flags
 * @dev_id: The device to allocate this HWPT for
 * @pt_id: The IOAS or HWPT to connect this HWPT to
 * @out_hwpt_id: The ID of the new HWPT
 * @__reserved: Must be 0
 * @data_type: One of enum iommu_hwpt_data_type
 * @data_len: Length of the type specific data
 * @data_uptr: User pointer to the type specific data
 *
 * Explicitly allocate a hardware page table object. This is the same object
 * type that is returned by iommufd_device_attach() and represents the
 * underlying iommu driver's iommu_domain kernel object.
 *
 * A kernel-managed HWPT will be created with the mappings from the given
 * IOAS via the @pt_id. The @data_type for this allocation must be set to
 * IOMMU_HWPT_DATA_NONE. The HWPT can be allocated as a parent HWPT for a
 * nesting configuration by passing IOMMU_HWPT_ALLOC_NEST_PARENT via @flags.
 *
 * A user-managed nested HWPT will be created from a given parent HWPT via
 * @pt_id, in which the parent HWPT must be allocated previously via the
 * same ioctl from a given IOAS (@pt_id). In this case, the @data_type
 * must be set to a pre-defined type corresponding to an I/O page table
 * type supported by the underlying IOMMU hardware.
 *
 * If the @data_type is set to IOMMU_HWPT_DATA_NONE, @data_len and
 * @data_uptr should be zero. Otherwise, both @data_len and @data_uptr
 * must be given.
 */
struct iommu_hwpt_alloc {
	__u32 size;
	__u32 flags;
	__u32 dev_id;
	__u32 pt_id;
	__u32 out_hwpt_id;
	__u32 __reserved;
	__u32 data_type;
	__u32 data_len;
	__aligned_u64 data_uptr;
};
#define IOMMU_HWPT_ALLOC _IO(IOMMUFD_TYPE, IOMMUFD_CMD_HWPT_ALLOC)

/**
 * enum iommu_hw_info_vtd_flags - Flags for VT-d hw_info
 * @IOMMU_HW_INFO_VTD_ERRATA_772415_SPR17: If set, disallow read-only mappings
 *                                         on a nested_parent domain.
 *                                         https://www.intel.com/content/www/us/en/content-details/772415/content-details.html
 */
enum iommu_hw_info_vtd_flags {
	IOMMU_HW_INFO_VTD_ERRATA_772415_SPR17 = 1 << 0,
};

/**
 * struct iommu_hw_info_vtd - Intel VT-d hardware information
 *
 * @flags: Combination of enum iommu_hw_info_vtd_flags
 * @__reserved: Must be 0
 *
 * @cap_reg: Value of Intel VT-d capability register defined in VT-d spec
 *           section 11.4.2 Capability Register.
 * @ecap_reg: Value of Intel VT-d capability register defined in VT-d spec
 *            section 11.4.3 Extended Capability Register.
 *
 * User needs to understand the Intel VT-d specification to decode the
 * register value.
 */
struct iommu_hw_info_vtd {
	__u32 flags;
	__u32 __reserved;
	__aligned_u64 cap_reg;
	__aligned_u64 ecap_reg;
};

/**
 * struct iommu_hw_info_arm_smmuv3 - ARM SMMUv3 hardware information
 *                                   (IOMMU_HW_INFO_TYPE_ARM_SMMUV3)
 *
 * @flags: Must be set to 0
 * @__reserved: Must be 0
 * @idr: Implemented features for ARM SMMU Non-secure programming interface
 * @iidr: Information about the implementation and implementer of ARM SMMU,
 *        and architecture version supported
 * @aidr: ARM SMMU architecture version
 *
 * For the details of @idr, @iidr and @aidr, please refer to the chapters
 * from 6.3.1 to 6.3.6 in the SMMUv3 Spec.
 *
 * User space should read the underlying ARM SMMUv3 hardware information for
 * the list of supported features.
 */
struct iommu_hw_info_arm_smmuv3 {
	__u32 flags;
	__u32 __reserved;
	__u32 idr[6];
	__u32 iidr;
	__u32 aidr;
};

/**
 * struct iommu_hw_info_amd - AMD IOMMU device info
 *
 * @efr : Value of AMD IOMMU Extended Feature Register (EFR)
 * @efr2: Value of AMD IOMMU Extended Feature 2 Register (EFR2)
 *
 * Please See description of these registers in the following sections of
 * the AMD I/O Virtualization Technology (IOMMU) Specification.
 * (https://www.amd.com/content/dam/amd/en/documents/processor-tech-docs/specifications/48882_IOMMU.pdf)
 *
 * - MMIO Offset 0030h IOMMU Extended Feature Register
 * - MMIO Offset 01A0h IOMMU Extended Feature 2 Register
 */
struct iommu_hw_info_amd {
	__aligned_u64 efr;
	__aligned_u64 efr2;
};

/**
 * enum iommu_hw_info_type - IOMMU Hardware Info Types
 * @IOMMU_HW_INFO_TYPE_NONE: Used by the drivers that do not report hardware
 *                           info
 * @IOMMU_HW_INFO_TYPE_INTEL_VTD: Intel VT-d iommu info type
 * @IOMMU_HW_INFO_TYPE_ARM_SMMUV3: ARM SMMUv3 iommu info type
 * @IOMMU_HW_INFO_TYPE_AMD: AMD IOMMU info type
 */
enum iommu_hw_info_type {
	IOMMU_HW_INFO_TYPE_NONE,
	IOMMU_HW_INFO_TYPE_INTEL_VTD,
//	IOMMU_HW_INFO_TYPE_ARM_SMMUV3,
	IOMMU_HW_INFO_TYPE_AMD,
};

/**
 * enum iommufd_hw_capabilities
 * @IOMMU_HW_CAP_DIRTY_TRACKING: IOMMU hardware support for dirty tracking
 *                               If available, it means the following APIs
 *                               are supported:
 *
 *                                   IOMMU_HWPT_GET_DIRTY_BITMAP
 *                                   IOMMU_HWPT_SET_DIRTY_TRACKING
 *
 */
enum iommufd_hw_capabilities {
	IOMMU_HW_CAP_DIRTY_TRACKING = 1 << 0,
};

/**
 * struct iommu_hw_info - ioctl(IOMMU_GET_HW_INFO)
 * @size: sizeof(struct iommu_hw_info)
 * @flags: Must be 0
 * @dev_id: The device bound to the iommufd
 * @data_len: Input the length of a user buffer in bytes. Output the length of
 *            data that kernel supports
 * @data_uptr: User pointer to a user-space buffer used by the kernel to fill
 *             the iommu type specific hardware information data
 * @out_data_type: Output the iommu hardware info type as defined in the enum
 *                 iommu_hw_info_type.
 * @out_capabilities: Output the generic iommu capability info type as defined
 *                    in the enum iommu_hw_capabilities.
 * @__reserved: Must be 0
 *
 * Query an iommu type specific hardware information data from an iommu behind
 * a given device that has been bound to iommufd. This hardware info data will
 * be used to sync capabilities between the virtual iommu and the physical
 * iommu, e.g. a nested translation setup needs to check the hardware info, so
 * a guest stage-1 page table can be compatible with the physical iommu.
 *
 * To capture an iommu type specific hardware information data, @data_uptr and
 * its length @data_len must be provided. Trailing bytes will be zeroed if the
 * user buffer is larger than the data that kernel has. Otherwise, kernel only
 * fills the buffer using the given length in @data_len. If the ioctl succeeds,
 * @data_len will be updated to the length that kernel actually supports,
 * @out_data_type will be filled to decode the data filled in the buffer
 * pointed by @data_uptr. Input @data_len == zero is allowed.
 */
struct iommu_hw_info {
	__u32 size;
	__u32 flags;
	__u32 dev_id;
	__u32 data_len;
	__aligned_u64 data_uptr;
	__u32 out_data_type;
	__u32 __reserved;
	__aligned_u64 out_capabilities;
};
#define IOMMU_GET_HW_INFO _IO(IOMMUFD_TYPE, IOMMUFD_CMD_GET_HW_INFO)

/*
 * enum iommufd_hwpt_set_dirty_tracking_flags - Flags for steering dirty
 *                                              tracking
 * @IOMMU_HWPT_DIRTY_TRACKING_ENABLE: Enable dirty tracking
 */
enum iommufd_hwpt_set_dirty_tracking_flags {
	IOMMU_HWPT_DIRTY_TRACKING_ENABLE = 1,
};

/**
 * struct iommu_hwpt_set_dirty_tracking - ioctl(IOMMU_HWPT_SET_DIRTY_TRACKING)
 * @size: sizeof(struct iommu_hwpt_set_dirty_tracking)
 * @flags: Combination of enum iommufd_hwpt_set_dirty_tracking_flags
 * @hwpt_id: HW pagetable ID that represents the IOMMU domain
 * @__reserved: Must be 0
 *
 * Toggle dirty tracking on an HW pagetable.
 */
struct iommu_hwpt_set_dirty_tracking {
	__u32 size;
	__u32 flags;
	__u32 hwpt_id;
	__u32 __reserved;
};
#define IOMMU_HWPT_SET_DIRTY_TRACKING _IO(IOMMUFD_TYPE, \
					  IOMMUFD_CMD_HWPT_SET_DIRTY_TRACKING)

/**
 * enum iommufd_hwpt_get_dirty_bitmap_flags - Flags for getting dirty bits
 * @IOMMU_HWPT_GET_DIRTY_BITMAP_NO_CLEAR: Just read the PTEs without clearing
 *                                        any dirty bits metadata. This flag
 *                                        can be passed in the expectation
 *                                        where the next operation is an unmap
 *                                        of the same IOVA range.
 *
 */
enum iommufd_hwpt_get_dirty_bitmap_flags {
	IOMMU_HWPT_GET_DIRTY_BITMAP_NO_CLEAR = 1,
};

/**
 * struct iommu_hwpt_get_dirty_bitmap - ioctl(IOMMU_HWPT_GET_DIRTY_BITMAP)
 * @size: sizeof(struct iommu_hwpt_get_dirty_bitmap)
 * @hwpt_id: HW pagetable ID that represents the IOMMU domain
 * @flags: Combination of enum iommufd_hwpt_get_dirty_bitmap_flags
 * @__reserved: Must be 0
 * @iova: base IOVA of the bitmap first bit
 * @length: IOVA range size
 * @page_size: page size granularity of each bit in the bitmap
 * @data: bitmap where to set the dirty bits. The bitmap bits each
 *        represent a page_size which you deviate from an arbitrary iova.
 *
 * Checking a given IOVA is dirty:
 *
 *  data[(iova / page_size) / 64] & (1ULL << ((iova / page_size) % 64))
 *
 * Walk the IOMMU pagetables for a given IOVA range to return a bitmap
 * with the dirty IOVAs. In doing so it will also by default clear any
 * dirty bit metadata set in the IOPTE.
 */
struct iommu_hwpt_get_dirty_bitmap {
	__u32 size;
	__u32 hwpt_id;
	__u32 flags;
	__u32 __reserved;
	__aligned_u64 iova;
	__aligned_u64 length;
	__aligned_u64 page_size;
	__aligned_u64 data;
};
#define IOMMU_HWPT_GET_DIRTY_BITMAP _IO(IOMMUFD_TYPE, \
					IOMMUFD_CMD_HWPT_GET_DIRTY_BITMAP)

/**
 * enum iommu_hwpt_vtd_s1_invalidate_flags - Flags for Intel VT-d
 *                                           stage-1 cache invalidation
 * @IOMMU_VTD_INV_FLAGS_LEAF: The LEAF flag indicates whether only the
 *                            leaf PTE caching needs to be invalidated
 *                            and other paging structure caches can be
 *                            preserved.
 */
enum iommu_hwpt_vtd_s1_invalidate_flags {
	IOMMU_VTD_INV_FLAGS_LEAF = 1 << 0,
};

/**
 * struct iommu_hwpt_vtd_s1_invalidate - Intel VT-d cache invalidation
 *                                       (IOMMU_HWPT_DATA_VTD_S1)
 * @addr: The start address of the addresses to be invalidated. It needs
 *        to be 4KB aligned.
 * @npages: Number of contiguous 4K pages to be invalidated.
 * @flags: Combination of enum iommu_hwpt_vtd_s1_invalidate_flags
 * @__reserved: Must be 0
 *
 * The Intel VT-d specific invalidation data for user-managed stage-1 cache
 * invalidation in nested translation. Userspace uses this structure to
 * tell the impacted cache scope after modifying the stage-1 page table.
 *
 * Invalidating all the caches related to the page table by setting @addr
 * to be 0 and @npages to be __aligned_u64(-1). This includes the
 * corresponding device-TLB if ATS is enabled on the attached devices.
 */
struct iommu_hwpt_vtd_s1_invalidate {
	__aligned_u64 addr;
	__aligned_u64 npages;
	__u32 flags;
	__u32 __reserved;
};

/**
 * struct iommu_hwpt_arm_smmuv3_invalidate - ARM SMMUv3 cahce invalidation
 *                                           (IOMMU_HWPT_DATA_ARM_SMMUV3)
 * @cmd: 128-bit cache invalidation command that runs in SMMU CMDQ
 *
 * Supported command list:
 *     CMDQ_OP_TLBI_NSNH_ALL
 *     CMDQ_OP_TLBI_NH_VA
 *     CMDQ_OP_TLBI_NH_VAA
 *     CMDQ_OP_TLBI_NH_ALL
 *     CMDQ_OP_TLBI_NH_ASID
 *     CMDQ_OP_ATC_INV
 *     CMDQ_OP_CFGI_CD
 *     CMDQ_OP_CFGI_CD_ALL
 */
struct iommu_hwpt_arm_smmuv3_invalidate {
	__aligned_u64 cmd[2];
};

/**
 * struct iommu_hwpt_invalidate - ioctl(IOMMU_HWPT_INVALIDATE)
 * @size: sizeof(struct iommu_hwpt_invalidate)
 * @hwpt_id: HWPT ID of a nested HWPT for cache invalidation
 * @reqs_uptr: User pointer to an array having @req_num of cache invalidation
 *             requests. The request entries in the array are of fixed width
 *             @req_len, and contain a user data structure for invalidation
 *             request specific to the given hardware page table.
 * @req_type: One of enum iommu_hwpt_data_type, defining the data type of all
 *            the entries in the invalidation request array. It should suit
 *            with the data_type passed per the allocation of the hwpt pointed
 *            by @hwpt_id.
 * @req_len: Length (in bytes) of a request entry in the request array
 * @req_num: Input the number of cache invalidation requests in the array.
 *           Output the number of requests successfully handled by kernel.
 * @out_driver_error_code: Report a driver speicifc error code upon failure.
 *                         It's optional, driver has a choice to fill it or
 *                         not.
 *
 * Invalidate the iommu cache for user-managed page table. Modifications on a
 * user-managed page table should be followed by this operation to sync cache.
 * Each ioctl can support one or more cache invalidation requests in the array
 * that has a total size of @req_len * @req_num.
 */
struct iommu_hwpt_invalidate {
	__u32 size;
	__u32 hwpt_id;
	__aligned_u64 reqs_uptr;
	__u32 req_type;
	__u32 req_len;
	__u32 req_num;
	__u32 out_driver_error_code;
};
#define IOMMU_HWPT_INVALIDATE _IO(IOMMUFD_TYPE, IOMMUFD_CMD_HWPT_INVALIDATE)

/**
 * enum iommu_idev_data_type - Data Type for a Device behind an IOMMU
 * @IOMMU_IDEV_DATA_NONE: no data
 */
enum iommu_idev_data_type {
	IOMMU_IDEV_DATA_NONE,
	IOMMU_IDEV_DATA_ARM_SMMUV3,
};

/**
 * struct iommu_idev_data_arm_smmuv3 - ARM SMMUv3 specific device data
 * @sid: The Stream ID that is assigned in the user space
 *
 * The SMMUv3 specific user space data for a device that is behind an SMMU HW.
 * The guest-level user data should be linked to the host-level kernel data,
 * which will be used by user space cache invalidation commands.
 */
struct iommu_idev_data_arm_smmuv3 {
	__u32 sid;
};

/**
 * struct iommu_set_idev_data - ioctl(IOMMU_SET_IDEV_DATA)
 * @size: sizeof(struct iommu_set_idev_data)
 * @dev_id: The device to set an iommu specific device data
 * @data_uptr: User pointer of the device user data
 * @data_type: One of enum iommu_idev_data_type
 * @data_len: Length of the device user data
 *
 * The device data must be unset using ioctl(IOMMU_UNSET_IDEV_DATA), before
 * another ioctl(IOMMU_SET_IDEV_DATA) call or before the device itself gets
 * unbind'd from the iommufd context.
 */
struct iommu_set_idev_data {
	__u32 size;
	__u32 dev_id;
	__aligned_u64 data_uptr;
	__u32 data_type;
	__u32 data_len;
};
#define IOMMU_SET_IDEV_DATA _IO(IOMMUFD_TYPE, IOMMUFD_CMD_SET_IDEV_DATA)

/**
 * struct iommu_unset_idev_data - ioctl(IOMMU_UNSET_IDEV_DATA)
 * @size: sizeof(struct iommu_unset_idev_data)
 * @dev_id: The device to unset its device user data
 */
struct iommu_unset_idev_data {
	__u32 size;
	__u32 dev_id;
};
#define IOMMU_UNSET_IDEV_DATA _IO(IOMMUFD_TYPE, IOMMUFD_CMD_UNSET_IDEV_DATA)
#endif
