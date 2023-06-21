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
	IOMMUFD_CMD_DEVICE_GET_HW_INFO,
	IOMMUFD_CMD_HWPT_INVALIDATE,
	IOMMUFD_CMD_DEVICE_SET_DATA,
	IOMMUFD_CMD_DEVICE_UNSET_DATA,
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
 * enum iommu_hwpt_type - IOMMU HWPT Type
 * @IOMMU_HWPT_TYPE_DEFAULT: default
 * @IOMMU_HWPT_TYPE_VTD_S1: Intel VT-d stage-1 page table
 * @IOMMU_HWPT_TYPE_ARM_SMMUV3: ARM SMMUv3 stage-1 Context Descriptor table
 */
enum iommu_hwpt_type {
	IOMMU_HWPT_TYPE_DEFAULT,
	IOMMU_HWPT_TYPE_VTD_S1,
	IOMMU_HWPT_TYPE_ARM_SMMUV3,
	IOMMU_HWPT_TYPE_AMD_V2,
};

/**
 * enum iommu_hwpt_intel_vtd_flags - Intel VT-d stage-1 page
 *				     table entry attributes
 * @IOMMU_VTD_PGTBL_SRE: Supervisor request
 * @IOMMU_VTD_PGTBL_EAFE: Extended access enable
 * @IOMMU_VTD_PGTBL_PCD: Page-level cache disable
 * @IOMMU_VTD_PGTBL_PWT: Page-level write through
 * @IOMMU_VTD_PGTBL_EMTE: Extended mem type enable
 * @IOMMU_VTD_PGTBL_CD: PASID-level cache disable
 * @IOMMU_VTD_PGTBL_WPE: Write protect enable
 */
enum iommu_hwpt_intel_vtd_flags {
	IOMMU_VTD_PGTBL_SRE = 1 << 0,
	IOMMU_VTD_PGTBL_EAFE = 1 << 1,
	IOMMU_VTD_PGTBL_PCD = 1 << 2,
	IOMMU_VTD_PGTBL_PWT = 1 << 3,
	IOMMU_VTD_PGTBL_EMTE = 1 << 4,
	IOMMU_VTD_PGTBL_CD = 1 << 5,
	IOMMU_VTD_PGTBL_WPE = 1 << 6,
	IOMMU_VTD_PGTBL_LAST = 1 << 7,
};

/**
 * struct iommu_hwpt_intel_vtd - Intel VT-d specific user-managed
 *                               stage-1 page table info
 * @flags: Combination of enum iommu_hwpt_intel_vtd_flags
 * @pgtbl_addr: The base address of the user-managed stage-1 page table.
 * @pat: Page attribute table data to compute effective memory type
 * @emt: Extended memory type
 * @addr_width: The address width of the untranslated addresses that are
 *              subjected to the user-managed stage-1 page table.
 * @__reserved: Must be 0
 *
 * The Intel VT-d specific data for creating hw_pagetable to represent
 * the user-managed stage-1 page table that is used in nested translation.
 *
 * In nested translation, the stage-1 page table locates in the address
 * space that defined by the corresponding stage-2 page table. Hence the
 * stage-1 page table base address value should not be higher than the
 * maximum untranslated address of stage-2 page table.
 *
 * The paging level of the stage-1 page table should be compatible with
 * the hardware iommu. Otherwise, the allocation would be failed.
 */
struct iommu_hwpt_intel_vtd {
	__u64 flags;
	__u64 pgtbl_addr;
	__u32 pat;
	__u32 emt;
	__u32 addr_width;
	__u32 __reserved;
};

/**
 * struct iommu_hwpt_arm_smmuv3 - ARM SMMUv3 specific page table data
 *
 * @flags: Page table entry attributes
 * @event_len: Length of the user Stream Table Entry
 * @ste_uptr: User pointer to a user Stream Table Entry
 * @event_len: Length of the returning event
 * @out_event_uptr: User pointer to a returning event, to report a C_BAD_STE upon
 *                  an STE configuration failure
 *
 * If event_len or out_event_uptr is unset, remainning at value 0, an STE
 * configuration failure during the hwpt allocation will not be reported.
 */
struct iommu_hwpt_arm_smmuv3 {
#define IOMMU_SMMUV3_FLAG_S2	(1 << 0) /* if unset, stage-1 */
	__u64 flags;
	__u64 ste_len;
	__aligned_u64 ste_uptr;
	__u64 event_len;
	__aligned_u64 out_event_uptr;
};

/**
 * struct iommu_hwpt_amd_v2 - AMD IOMMU specific user-managed
 *                            v2 I/O page table data
 * @gcr3: GCR3 guest physical ddress
 * @gcr3_va: GCR3 host virtual address
 * @gid: Guest ID
 * @iommu_id: IOMMU host device ID
 * @gdev_id: Guest device ID
 */
struct iommu_hwpt_amd_v2 {
	__u64 gcr3;
	__u64 gcr3_va;
	__u32 gid;
	__u32 iommu_id;
	__u16 gdev_id;
};

/**
 * struct iommu_hwpt_alloc - ioctl(IOMMU_HWPT_ALLOC)
 * @size: sizeof(struct iommu_hwpt_alloc)
 * @flags: Must be 0
 * @dev_id: The device to allocate this HWPT for
 * @pt_id: The IOAS to connect this HWPT to
 * @out_hwpt_id: The ID of the new HWPT
 * @__reserved: Must be 0
 * @hwpt_type: One of enum iommu_hwpt_type
 * @data_len: Length of the type specific data
 * @data_uptr: User pointer to the type specific data
 *
 * Explicitly allocate a hardware page table object. This is the same object
 * type that is returned by iommufd_device_attach() and represents the
 * underlying iommu driver's iommu_domain kernel object.
 *
 * A kernel-managed HWPT will be created with the mappings from the given IOAS.
 * The @hwpt_type for its allocation can be set to IOMMU_HWPT_TYPE_DEFAULT, or
 * another type (being listed below) to specialize a kernel-managed HWPT.
 *
 * A user-managed HWPT will be created from a given parent HWPT via @pt_id, in
 * which the parent HWPT must be allocated previously via the same ioctl from a
 * given IOAS. The @hwpt_type must not be set to IOMMU_HWPT_TYPE_DEFAULT but a
 * pre-defined type corresponding to the underlying IOMMU hardware.
 *
 * If the @hwpt_type is set to IOMMU_HWPT_TYPE_DEFAULT, both the @data_len and
 * the @data_uptr will be ignored. Otherwise, both of them must be given.
 *
 * +==============================+=====================================+===========+
 * | @hwpt_type                   |    Data structure in @data_uptr     |   @pt_id  |
 * +------------------------------+-------------------------------------+-----------+
 * | IOMMU_HWPT_TYPE_DEFAULT      |               N/A                   |    IOAS   |
 * +------------------------------+-------------------------------------+-----------+
 * | IOMMU_HWPT_TYPE_VTD_S1       |      struct iommu_hwpt_intel_vtd    |    HWPT   |
 * +------------------------------+-------------------------------------+-----------+
 * | IOMMU_HWPT_TYPE_ARM_SMMUV3   |      struct iommu_hwpt_arm_smmuv3   | IOAS/HWPT |
 * +------------------------------+-------------------------------------------------+
 * | IOMMU_HWPT_TYPE_AMD_V2       |      struct iommu_hwpt_amd_v2       | IOAS/HWPT |
 * +------------------------------+-------------------------------------------------+
 */
struct iommu_hwpt_alloc {
	__u32 size;
	__u32 flags;
	__u32 dev_id;
	__u32 pt_id;
	__u32 out_hwpt_id;
	__u32 __reserved;
	__u32 hwpt_type;
	__u32 data_len;
	__aligned_u64 data_uptr;
};
#define IOMMU_HWPT_ALLOC _IO(IOMMUFD_TYPE, IOMMUFD_CMD_HWPT_ALLOC)

/**
 * enum iommu_hw_info_type - IOMMU Hardware Info Types
 * @IOMMU_HW_INFO_TYPE_INTEL_VTD: Intel VT-d iommu info type
 * @IOMMU_HW_INFO_TYPE_ARM_SMMUV3: ARM SMMUv3 iommu info type
 * @IOMMU_HW_INFO_TYPE_AMD: AMD IOMMU info type
 */
enum iommu_hw_info_type {
	IOMMU_HW_INFO_TYPE_NONE,
	IOMMU_HW_INFO_TYPE_INTEL_VTD,
	IOMMU_HW_INFO_TYPE_ARM_SMMUV3,
	IOMMU_HW_INFO_TYPE_AMD,
};

/**
 * enum iommu_hw_info_vtd_flags - Flags for VT-d hw_info
 * @IOMMU_HW_INFO_VTD_ERRATA_772415: If set, disallow nesting on domains
 *                                   with read-only mapping.
 *                                   https://www.intel.com/content/www/us/en/content-details/772415/content-details.html
 */
enum iommu_hw_info_vtd_flags {
	IOMMU_HW_INFO_VTD_ERRATA_772415 = 1 << 0,
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
 * struct iommu_hw_info_smmuv3 - ARM SMMUv3 device info
 *
 * @flags: Must be set to 0
 * @__reserved: Must be 0
 * @idr: Implemented features for the SMMU Non-secure programming interface.
 *       Please refer to the chapters from 6.3.1 to 6.3.6 in the SMMUv3 Spec.
 */
struct iommu_hw_info_smmuv3 {
	__u32 flags;
	__u32 __reserved;
	__u32 idr[6];
};

/**
 * struct iommu_hw_info_amd - AMD IOMMU device info
 *
 */
struct iommu_hw_info_amd {
	__u64 efr;
	__u64 efr2;
};

/**
 * struct iommu_hw_info - ioctl(IOMMU_DEVICE_GET_HW_INFO)
 * @size: sizeof(struct iommu_hw_info)
 * @flags: Must be 0
 * @dev_id: The device bound to the iommufd
 * @data_len: Input the length of the user buffer in bytes. Output the
 *            length of data filled in the user buffer.
 * @data_ptr: Pointer to the user buffer
 * @out_data_type: Output the iommu hardware info type as defined by
 *                 enum iommu_hw_info_type.
 * @__reserved: Must be 0
 * @out_hwpt_type_bitmap: Output the supported page table type. Each
 *                        bit is defined in enum iommu_hwpt_type.
 *
 * Query the hardware iommu information for given device which has been
 * bound to iommufd. @data_len is the size of the buffer which captures
 * iommu type specific data and the data will be filled. Trailing bytes
 * are zeroed if the user buffer is larger than the data kernel has.
 *
 * The type specific data would be used to sync capability between the
 * virtual IOMMU and the hardware IOMMU. e.g. nested translation requires
 * to check the hardware IOMMU capability so guest stage-1 page table
 * uses a format compatible to the hardware IOMMU.
 *
 * The @out_data_type will be filled if the ioctl succeeds. It would
 * be used to decode the data filled in the buffer pointed by @data_ptr.
 *
 * @out_hwpt_type_bitmap reports the supported hwpt types. This differs
 * per the @out_data_type. Userspace should check it before allocating
 * hw_pagetable for a device that are bound to iommufd.
 *
 */
struct iommu_hw_info {
	__u32 size;
	__u32 flags;
	__u32 dev_id;
	__u32 data_len;
	__aligned_u64 data_ptr;
	__u32 out_data_type;
	__u32 __reserved;
	__aligned_u64 out_hwpt_type_bitmap;
};
#define IOMMU_DEVICE_GET_HW_INFO _IO(IOMMUFD_TYPE, IOMMUFD_CMD_DEVICE_GET_HW_INFO)

/**
 * struct iommu_device_data_arm_smmuv3 - ARM SMMUv3 specific device data
 * @sid: The Stream ID that is assigned in the user space
 *
 * This should be passed via the VFIO_DEVICE_BIND_IOMMUFD ioctl.
 */
struct iommu_device_data_arm_smmuv3 {
	__u32 sid;
};

/**
 * enum iommu_hwpt_intel_vtd_invalidate_flags - Flags for Intel VT-d
 *                                              stage-1 page table cache
 *                                              invalidation
 * @IOMMU_VTD_QI_FLAGS_LEAF: The LEAF flag indicates whether only the
 *                           leaf PTE caching needs to be invalidated
 *                           and other paging structure caches can be
 *                           preserved.
 */
enum iommu_hwpt_intel_vtd_invalidate_flags {
	IOMMU_VTD_QI_FLAGS_LEAF = 1 << 0,
};

/**
 * struct iommu_hwpt_invalidate_request_intel_vtd - Intel VT-d cache invalidation request
 * @addr: The start address of the addresses to be invalidated.
 * @nb_pages: Number of contiguous 4K pages to be invalidated.
 * @flags: Combination of enum iommu_hwpt_intel_vtd_invalidate_flags
 * @__reserved: Must be 0
 *
 * The Intel VT-d specific invalidation data for user-managed stage-1 cache
 * invalidation under nested translation. Userspace uses this structure to
 * tell host about the impacted caches after modifying the stage-1 page table.
 *
 * Invalidating all the caches related to the hw_pagetable by setting
 * @addr==0 and @nb_pages==__u64(-1).
 */
struct iommu_hwpt_invalidate_request_intel_vtd {
	__u64 addr;
	__u64 nb_pages;
	__u32 flags;
	__u32 __reserved;
};

/**
 * struct iommu_hwpt_invalidate_intel_vtd - Intel VT-d cache invalidation info
 * @flags: Must be 0
 * @entry_size: Size in bytes of each cache invalidation request
 * @entry_nr_uptr: User pointer to the number of invalidation requests.
 *                 Kernel reads it to get the number of requests and
 *                 updates the buffer with the number of requests that
 *                 have been processed successfully. This pointer must
 *                 point to a __u32 type of memory location.
 * @inv_data_uptr: Pointer to the cache invalidation requests
 *
 * The Intel VT-d specific invalidation data for a set of cache invalidation
 * requests. Kernel loops the requests one-by-one and stops when failure
 * is encountered. The number of handled requests is reported to user by
 * writing the buffer pointed by @entry_nr_uptr.
 */
struct iommu_hwpt_invalidate_intel_vtd {
	__u32 flags;
	__u32 entry_size;
	__u64 entry_nr_uptr;
	__u64 inv_data_uptr;
};

/**
 * struct iommu_hwpt_invalidate_arm_smmuv3 - ARM SMMUv3 cahce invalidation info
 * @cmdq_uptr: User pointer to a user command queue
 * @cmdq_cons_uptr: User pointer to the consumer index of a user command queue,
 *                  allowing kernel to read and also update the consumer index
 *                  for a successful call or a failure with a CERROR_ILL code.
 *                  This pointer must point to a __u32 type of memory location.
 * @cmdq_prod: Producer index of user command queues
 * @cmdq_entry_size: Entry size of a user command queue
 * @cmdq_log2size: Queue size as log2(entries). Refer to 6.3.25 SMMU_CMDQ_BASE
 * @__reserved: Must be 0
 */
struct iommu_hwpt_invalidate_arm_smmuv3 {
	__aligned_u64 cmdq_uptr;
	__aligned_u64 cmdq_cons_uptr;
	__u32 cmdq_prod;
	__u32 cmdq_entry_size;
	__u32 cmdq_log2size;
	__u32 __reserved;
};

/**
 * struct iommu_hwpt_invalidate - ioctl(IOMMU_HWPT_INVALIDATE)
 * @size: sizeof(struct iommu_hwpt_invalidate)
 * @hwpt_id: HWPT ID of target hardware page table for the invalidation
 * @data_len: Length of the type specific data
 * @__reserved: Must be 0
 * @data_uptr: User pointer to the type specific data
 *
 * Invalidate the iommu cache for user-managed page table. Modifications
 * on user-managed page table should be followed with this operation to
 * sync the IOTLB. The data in @data_uptr differs per the hwpt type.
 *
 * +==============================+========================================+
 * | @hwpt_type                   |     Data structure in @data_uptr       |
 * +------------------------------+----------------------------------------+
 * | IOMMU_HWPT_TYPE_VTD_S1       | struct iommu_hwpt_invalidate_intel_vtd |
 * +------------------------------+----------------------------------------+
 * | IOMMU_HWPT_TYPE_ARM_SMMUV3   | struct iommu_hwpt_invalidate_arm_smmuv3|
 * +------------------------------+----------------------------------------+
 */
struct iommu_hwpt_invalidate {
	__u32 size;
	__u32 hwpt_id;
	__u32 data_len;
	__u32 __reserved;
	__aligned_u64 data_uptr;
};
#define IOMMU_HWPT_INVALIDATE _IO(IOMMUFD_TYPE, IOMMUFD_CMD_HWPT_INVALIDATE)

/**
 * struct iommu_device_set_data - ioctl(IOMMU_DEVICE_SET_DATA)
 * @size: sizeof(struct iommu_device_set_data)
 * @dev_id: The device to set an iommu specific device data
 * @data_uptr: User pointer of the device user data
 * @data_len: Length of the device user data
 *
 * The device data must be unset using ioctl(IOMMU_DEVICE_UNSET_DATA), before
 * another ioctl(IOMMU_DEVICE_SET_DATA) call or before the device itself gets
 * unbind'd from the iommufd context.
 */
struct iommu_device_set_data {
	__u32 size;
	__u32 dev_id;
	__aligned_u64 data_uptr;
	__u32 data_len;
};
#define IOMMU_DEVICE_SET_DATA _IO(IOMMUFD_TYPE, IOMMUFD_CMD_DEVICE_SET_DATA)

/**
 * struct iommu_device_unset_data - ioctl(IOMMU_DEVICE_UNSET_DATA)
 * @size: sizeof(struct iommu_device_unset_data)
 * @dev_id: The device to unset its device user data
 */
struct iommu_device_unset_data {
	__u32 size;
	__u32 dev_id;
};
#define IOMMU_DEVICE_UNSET_DATA _IO(IOMMUFD_TYPE, IOMMUFD_CMD_DEVICE_UNSET_DATA)
#endif
