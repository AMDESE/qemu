/*
 * QEMU support of AMD HW-assisted VIOMMU
 *
 * Copyright (C) 2021 Suravee Suthikulpanit <suravee.suthikulpanit@amd.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License along
 * with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 * Implementation inspired by hw/i386/intel_iommu.c
 *
 */

#include <sys/ioctl.h>
#include <linux/amd_viommu.h>

#include "qemu/osdep.h"
#include "hw/i386/pc.h"
#include "hw/pci/msi.h"
#include "hw/pci/pci_bus.h"
#include "hw/qdev-properties.h"
#include "hw/qdev-properties-system.h"
#include "migration/vmstate.h"
#include "amd_iommu.h"
#include "amd_iommu_helper.h"
#include "qapi/error.h"
#include "qemu/error-report.h"
#include "hw/i386/apic_internal.h"
#include "trace.h"
#include "hw/i386/apic-msidef.h"
#include "exec/memory.h"
#include "sysemu/kvm_int.h"

#include "exec/ram_addr.h"
#include "sysemu/iommufd.h"

struct amd_as_key {
    PCIBus *bus;
    uint8_t devfn;
    uint32_t pasid;
};

static int amd_viommu_ioctl_init(AMDVIState *s, Error **errp);

static int amd_viommu_mmio_write(AMDVIState *s, __u32 offset,
                                 __u32 size, __u64 value);

static int amd_viommu_mmio_read(AMDVIState *s, __u32 offset,
                                __u32 size, __u64 *value);

static void* gpa2hva(hwaddr addr, uint64_t size)
{
    MemoryRegionSection mrs = memory_region_find(get_system_memory(), addr, size);

    if (!mrs.mr) {
        error_report("No memory is mapped at address 0x%" HWADDR_PRIx, addr);
        return NULL;
    }

    return qemu_map_ram_ptr(mrs.mr->ram_block, mrs.offset_within_region);
}

/* ------------- IOCTL helpers  -------------*/

static int amd_viommu_iommu_init(AMDVIState *s)
{
    int ret;
    struct amd_viommu_iommu_info arg = {
        .size = sizeof(arg),
    };
    uint16_t bdf = PCI_BUILD_BDF((s->iommu.host.bus),
				PCI_DEVFN(s->iommu.host.slot,
					  s->iommu.host.function));
    arg.iommu_id = bdf;
    arg.trans_devid = s->translate_id;

    ret = ioctl(s->iommufd->fd, VIOMMU_IOMMU_INIT, &arg);
    if (ret)
	goto err_out;

    s->gid = arg.gid;
err_out:
    return ret;
}

static int amd_viommu_iommu_uninit(AMDVIState *s)
{
    int ret;
    struct amd_viommu_iommu_info arg = {
        .size = sizeof(arg),
    };
    uint16_t bdf = PCI_BUILD_BDF((s->iommu.host.bus),
				PCI_DEVFN(s->iommu.host.slot,
					  s->iommu.host.function));
    arg.iommu_id = bdf;
    arg.gid = s->gid;

    ret = ioctl(s->iommufd->fd, VIOMMU_IOMMU_DESTROY, &arg);
    return ret;
}

static int amd_viommu_mmio_write(AMDVIState *s, __u32 offset,
                                 __u32 size, __u64 value)
{
    int ret;
    struct amd_viommu_mmio_data arg = {
        .size = sizeof(arg),
    };
    uint16_t bdf = PCI_BUILD_BDF((s->iommu.host.bus),
				PCI_DEVFN(s->iommu.host.slot,
					  s->iommu.host.function));
    arg.iommu_id = bdf;
    arg.gid = s->gid;
    arg.offset = offset;
    arg.mmio_size = size;
    arg.value = value;
    arg.is_write = true;

    return ret = ioctl(s->iommufd->fd, VIOMMU_MMIO_ACCESS, &arg);
}

static int amd_viommu_mmio_read(AMDVIState *s, __u32 offset,
                                __u32 size, __u64 *value)
{
    int ret;
    struct amd_viommu_mmio_data arg = {
        .size = sizeof(arg),
    };
    uint16_t bdf = PCI_BUILD_BDF((s->iommu.host.bus),
				PCI_DEVFN(s->iommu.host.slot,
					  s->iommu.host.function));
    arg.iommu_id = bdf;
    arg.gid = s->gid;
    arg.offset = offset;
    arg.mmio_size = size;
    arg.value = 0;
    arg.is_write = false;

    ret = ioctl(s->iommufd->fd, VIOMMU_MMIO_ACCESS, &arg);
    if (!ret && value)
        *value = arg.value;

    return ret;
}

static int amd_viommu_ioctl_init(AMDVIState *s, Error **errp)
{
    if (s->iommufd)
        iommufd_backend_connect(s->iommufd, errp);

    if (*errp)
        return -1;

    return 0;
}

static uint64_t amdvi_mmio_read(void *opaque, hwaddr addr, unsigned size)
{
    AMDVIState *s = opaque;
    uint64_t val = -1;
    int ret;

    if (addr + size > AMD_VIOMMU_MMIO_SIZE) {
        trace_amdvi_mmio_read_invalid(AMD_VIOMMU_MMIO_SIZE, addr, size);
        return (uint64_t)-1;
    }

    ret = amd_viommu_mmio_read(s, (addr & ~0x07), size, (__u64 *)&val);
    if (ret)
        val = -1;

    return val;
}

static int amd_viommu_update_domain_id(AMDVIState *s, uint32_t devid, uint16_t domid, bool set)
{
    struct amd_viommu_dom_info arg = {
        .size = sizeof(arg),
    };
    uint32_t bdf= PCI_BUILD_BDF(s->iommu.host.bus,
                                PCI_DEVFN(s->iommu.host.slot,
                                          s->iommu.host.function));

    arg.iommu_id = bdf;
    arg.gid = s->gid;
    arg.gdom_id = domid;
    arg.gdev_id = devid;

    if (set)
        return ioctl(s->iommufd->fd, VIOMMU_DOMAIN_ATTACH, &arg);
    else
        return ioctl(s->iommufd->fd, VIOMMU_DOMAIN_DETACH, &arg);
}

static int amd_viommu_update_gcr3(AMDVIState *s, uint64_t gcr3, uint64_t gcr3_va,
                                  uint16_t flags, uint16_t dev_id,
                                  uint16_t guest_paging_mode)
{
    int ret = -EINVAL;
    uint32_t hwpt_id;
    AMDIOMMUFDDevice *dev;
    struct iommu_hwpt_amd_v2 hwpt;
    struct amd_as_key key = {
        .bus = pci_get_bus(&s->pci.dev),
        .devfn = dev_id & 0xFF,
    };
    uint32_t bdf= PCI_BUILD_BDF(s->iommu.host.bus,
                                PCI_DEVFN(s->iommu.host.slot,
                                          s->iommu.host.function));

    hwpt.iommu_id = bdf;
    hwpt.gcr3 = gcr3;
    hwpt.gcr3_va = gcr3_va;
    hwpt.gid = s->gid;
    hwpt.gdev_id = dev_id;
    hwpt.glx = (flags >> 4) & 0x3 ;
    hwpt.guest_paging_mode = guest_paging_mode;

    dev = g_hash_table_lookup(s->amd_iommufd_dev, &key);
    if (!dev || !dev->idev) {
        goto out;
    }

    ret = iommufd_backend_alloc_hwpt(s->iommufd->fd,
                                     dev->idev->dev_id,
                                     dev->v1_hwpt.hwpt_id,
                                     IOMMU_HWPT_TYPE_AMD_V2,
                                     sizeof(hwpt),
                                     &hwpt,
                                     &hwpt_id);
out:
    return ret;
}

static uint64_t amd_viommu_dte_read(void *opaque, hwaddr offset, unsigned size)
{
    uint64_t val = 0;
    AMDVIState *s = opaque;

    if (size ==  2) {
        val = lduw_le_p(&s->devtab[offset]);
    } else if (size == 4) {
        val = ldl_le_p(&s->devtab[offset]);
    } else if (size == 8) {
        val = ldq_le_p(&s->devtab[offset]);
    }

    return val;
}

static int amd_viommu_get_v1_hwpt(AMDIOMMUFDDevice *dev, AMDVIState *s)
{
    int ret;
    uint32_t hwpt_id, ioas_id;

    ret = iommufd_backend_get_ioas(dev->iommu_state->iommufd, &ioas_id);
    if (ret < 0) {
        return ret;
    }

    ret = iommufd_backend_alloc_hwpt(dev->iommu_state->iommufd->fd,
                                     dev->idev->dev_id,
                                     ioas_id,
                                     IOMMU_HWPT_TYPE_DEFAULT,
                                     0, NULL,
                                     &hwpt_id);
    if (!ret) {
        dev->v1_hwpt.hwpt_id = hwpt_id;
        dev->v1_hwpt.parent_ioas_id = ioas_id;
    }
    return ret;
}

static void amd_viommu_dte_write(void *opaque, hwaddr offset, uint64_t val,
                             unsigned size)
{
    uint64_t dte0, dte1, dte2, offset0, offset1, offset2 = 0, gcr3tbl;
    AMDVIState *s = opaque;
    AMDIOMMUFDDevice *dev;
    uint16_t flags, guest_paging_mode = 0;
    uint32_t devid;
    struct amd_as_key key = {
        .bus = pci_get_bus(&s->pci.dev),
    };

    if (size ==  2) {
        stw_le_p(&s->devtab[offset], val);
    } else if (size == 4) {
        stl_le_p(&s->devtab[offset], val);
    } else if (size == 8) {
        stq_le_p(&s->devtab[offset], val);
    }

    devid = offset >> 5;
    if (devid >= AMDVI_DEVID_MAX) {
	error_printf("amd_viommu: Invalid device id (%#x)", devid);
        return;
    }

    /*
     * Note:
     * For now, we only care about the case when writing to
     * DTE[1] (for DomainID, GCR3 Table Root Pointer)
     * DTE[2] (for GuestPagingMode).
     */
    if (offset % 0x20 == 0) {
        return; /* Ignore DTE[0] */
    } else if (offset % 0x20 == 0x8) {
	fprintf(stderr, "DEBUG: %s offset1=%#llx\n", __func__, (unsigned long long )offset);
	offset1 = offset;
	offset0 = offset - 0x8;
    } else if (offset % 0x20 == 0x10) {
	fprintf(stderr, "DEBUG: %s offset2=%#llx\n", __func__, (unsigned long long )offset);
	offset2 = offset;
	offset1 = offset - 0x8;
	offset0 = offset - 0x10;
    } else if (offset % 0x20 == 0x18) {
        return; /* Ignore DTE[3] */
    }

    dte0 = amd_viommu_dte_read(opaque, offset0, size);
    dte1 = amd_viommu_dte_read(opaque, offset1, size);
    if (offset2)
        dte2 = amd_viommu_dte_read(opaque, offset2, size);

    if (dte0 & 0xE03ULL) {
        int domid = dte1 & 0xFFFFULL;
        int tmp = s->dev_domid[devid];

	if (tmp == domid)
		return;

	s->dev_domid[devid] = domid;
	trace_amd_viommu_dte(s->devtab_base + offset0, s->devtab_base + offset1,
                             size, val, devid, domid);

        /* TODO: handle detach */
	amd_viommu_update_domain_id(s, devid, domid, true);
    }

    key.devfn = devid & 0xFF;
    dev = g_hash_table_lookup(s->amd_iommufd_dev, &key);
    amd_viommu_get_v1_hwpt(dev, s);

    /* Setting gCR3 */
    gcr3tbl = (((dte0 >> 58) & 7ULL) << 12) |
                 (((dte1 >> 16) & 0xFFFFULL) << 15) |
                 (((dte1 >> 43) & 0x1FFFFFULL) << 31);
    flags = (dte0 >> 52) & 0x3F;

    if (gcr3tbl) {
        uint64_t gcr30 = gcr3tbl;
        void *gcr30_va = gpa2hva(gcr30, 0x1000);

        if (offset2)
            guest_paging_mode = (dte2 >> 54) & 0x3ULL;

        //trace_amd_viommu_gcr3(gcr3tbl, (uint64_t)gcr3tbl_va, gcr30, (uint64_t)gcr30_va, flags);
	fprintf(stderr, "DEBUG: %s: gcr3=%#lx, gcr3_va=%#lx\n", __func__, (uint64_t)gcr30, (uint64_t)gcr30_va);
        amd_viommu_update_gcr3(s, (uint64_t)gcr30, (uint64_t)gcr30_va, flags,
                               devid, guest_paging_mode);
    }
}

static const MemoryRegionOps dte_ops = {
    .read = amd_viommu_dte_read,
    .write = amd_viommu_dte_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl = {
        .min_access_size = 1,
        .max_access_size = 8,
        .unaligned = false,
    },
    .valid = {
        .min_access_size = 1,
        .max_access_size = 8,
    }
};

static inline void amdvi_handle_devtab_mmio_write(AMDVIState *s)
{
    uint64_t val = amdvi_readq(s, AMDVI_MMIO_DEVICE_TABLE);
    s->devtab_base = (val & AMDVI_MMIO_DEVTAB_BASE_MASK);

    /* set device table length */
    s->devtab_len = ((val & AMDVI_MMIO_DEVTAB_SIZE_MASK) + 1) *
                    AMDVI_MMIO_DEVTAB_SIZE_UNIT;
    trace_amd_viommu_devtab_mmio(val, s->devtab_base, s->devtab_len,
                                 s->pci.dev.devfn,
                                 pci_dev_bus_num(&s->pci.dev));
    /*
     * Set up memory notifier for IOMMU Device Table
     */
    memory_region_init_io(&s->devtab_mr, OBJECT(s),
                          &dte_ops, s, "amd-iommu-devtab",
                          s->devtab_len);
    memory_region_add_subregion_overlap(get_system_memory(),
                               s->devtab_base,
                               &s->devtab_mr, 1);

    amd_viommu_mmio_write(s, AMDVI_MMIO_DEVICE_TABLE, 8, val);
}

static inline void amdvi_handle_control_write(AMDVIState *s)
{
    unsigned long val = amdvi_readq(s, AMDVI_MMIO_CONTROL);

    amd_viommu_mmio_write(s, AMDVI_MMIO_CONTROL, 8, val);
}

static inline void amdvi_handle_cmdbase_write(AMDVIState *s)
{
    uint64_t val = amdvi_readq(s, AMDVI_MMIO_COMMAND_BASE);

    amd_viommu_mmio_write(s, AMDVI_MMIO_COMMAND_BASE, 8, val);
}

static inline void amdvi_handle_cmdhead_write(AMDVIState *s)
{
    uint64_t val = amdvi_readq(s, AMDVI_MMIO_COMMAND_HEAD);

    amd_viommu_mmio_write(s, AMDVI_MMIO_COMMAND_HEAD, 8, val);
}

static inline void amdvi_handle_cmdtail_write(AMDVIState *s)
{
    uint64_t val = amdvi_readq(s, AMDVI_MMIO_COMMAND_TAIL);

    amd_viommu_mmio_write(s, AMDVI_MMIO_COMMAND_TAIL, 8, val);
}

static inline void amdvi_handle_evtbase_write(AMDVIState *s)
{
    uint64_t val = amdvi_readq(s, AMDVI_MMIO_EVENT_BASE);

    amd_viommu_mmio_write(s, AMDVI_MMIO_EVENT_BASE, 8, val);
}

static inline void amdvi_handle_evthead_write(AMDVIState *s)
{
    uint64_t val = amdvi_readq(s, AMDVI_MMIO_EVENT_HEAD);

    amd_viommu_mmio_write(s, AMDVI_MMIO_EVENT_HEAD, 8, val);
}

static inline void amdvi_handle_evttail_write(AMDVIState *s)
{
    uint64_t val = amdvi_readq(s, AMDVI_MMIO_EVENT_TAIL);

    amd_viommu_mmio_write(s, AMDVI_MMIO_EVENT_TAIL, 8, val);
}

static inline void amdvi_handle_pprbase_write(AMDVIState *s)
{
    uint64_t val = amdvi_readq(s, AMDVI_MMIO_PPR_BASE);

    amd_viommu_mmio_write(s, AMDVI_MMIO_PPR_BASE, 8, val);
}

static inline void amdvi_handle_pprhead_write(AMDVIState *s)
{
    uint64_t val = amdvi_readq(s, AMDVI_MMIO_PPR_HEAD);

    amd_viommu_mmio_write(s, AMDVI_MMIO_PPR_HEAD, 8, val);
}

static inline void amdvi_handle_pprtail_write(AMDVIState *s)
{
    uint64_t val = amdvi_readq(s, AMDVI_MMIO_PPR_TAIL);

    amd_viommu_mmio_write(s, AMDVI_MMIO_PPR_TAIL, 8, val);
}

/* FIXME: something might go wrong if System Software writes in chunks
 * of one byte but linux writes in chunks of 4 bytes so currently it
 * works correctly with linux but will definitely be busted if software
 * reads/writes 8 bytes
 */
static void amdvi_mmio_reg_write(AMDVIState *s, unsigned size, uint64_t val,
                                 hwaddr addr)
{
    if (size == 2) {
        amdvi_writew(s, addr, val);
    } else if (size == 4) {
        amdvi_writel(s, addr, val);
    } else if (size == 8) {
        amdvi_writeq(s, addr, val);
    }
}

static void amdvi_mmio_write(void *opaque, hwaddr addr, uint64_t val,
                             unsigned size)
{
    AMDVIState *s = opaque;
    unsigned long offset = addr & 0x07;

    if (addr + size > AMD_VIOMMU_MMIO_SIZE) {
        trace_amdvi_mmio_write("error: addr outside region: max ",
                (uint64_t)AMD_VIOMMU_MMIO_SIZE, size, val, offset);
        return;
    }

    switch (addr & ~0x07) {
    case AMDVI_MMIO_CONTROL:
        amdvi_mmio_reg_write(s, size, val, addr);
        amdvi_handle_control_write(s);
        break;
    case AMDVI_MMIO_DEVICE_TABLE:
        amdvi_mmio_reg_write(s, size, val, addr);
       /*  set device table address
        *   This also suffers from inability to tell whether software
        *   is done writing
        */
        if (offset || (size == 8)) {
            amdvi_handle_devtab_mmio_write(s);
        }
        break;
    case AMDVI_MMIO_COMMAND_BASE:
        amdvi_mmio_reg_write(s, size, val, addr);
        /* FIXME - make sure System Software has finished writing incase
         * it writes in chucks less than 8 bytes in a robust way.As for
         * now, this hacks works for the linux driver
         */
        if (offset || (size == 8)) {
            amdvi_handle_cmdbase_write(s);
        }
        break;
    case AMDVI_MMIO_COMMAND_HEAD:
        amdvi_mmio_reg_write(s, size, val, addr);
        amdvi_handle_cmdhead_write(s);
        break;
    case AMDVI_MMIO_COMMAND_TAIL:
        amdvi_mmio_reg_write(s, size, val, addr);
        amdvi_handle_cmdtail_write(s);
        break;
    case AMDVI_MMIO_EVENT_BASE:
        amdvi_mmio_reg_write(s, size, val, addr);
        if (offset || (size == 8)) {
            amdvi_handle_evtbase_write(s);
        }
        break;
    case AMDVI_MMIO_PPR_BASE:
        amdvi_mmio_reg_write(s, size, val, addr);
        if (offset || (size == 8)) {
            amdvi_handle_pprbase_write(s);
        }
        break;
        /* PPR log head - also unused for now */
    }
}

static AddressSpace *amd_viommu_host_dma_iommu(PCIBus *bus, void *opaque, int devfn)
{
    char name[128];
    AMDVIState *s = opaque;
    AMDVIAddressSpace **iommu_as, *amdvi_dev_as;
    int bus_num = pci_bus_num(bus);

    iommu_as = s->address_spaces[bus_num];

    /* allocate memory during the first run */
    if (!iommu_as) {
        iommu_as = g_malloc0(sizeof(AMDVIAddressSpace *) * PCI_DEVFN_MAX);
        s->address_spaces[bus_num] = iommu_as;
    }

    /* set up AMD-Vi region */
    if (!iommu_as[devfn]) {
        snprintf(name, sizeof(name), "amd_iommu_devfn_%d", devfn);

        iommu_as[devfn] = g_malloc0(sizeof(AMDVIAddressSpace));
        iommu_as[devfn]->bus_num = (uint8_t)bus_num;
        iommu_as[devfn]->devfn = (uint8_t)devfn;
        iommu_as[devfn]->iommu_state = s;

        amdvi_dev_as = iommu_as[devfn];

        /*
         * Memory region relationships looks like (Address range shows
         * only lower 32 bits to make it short in length...):
         *
         * |-----------------+-------------------+----------|
         * | Name            | Address range     | Priority |
         * |-----------------+-------------------+----------+
         * | amdvi_root      | 00000000-ffffffff |        0 |
         * |  amdvi_iommu    | 00000000-ffffffff |        1 |
         * |  amdvi_iommu_ir | fee00000-feefffff |       64 |
         * |-----------------+-------------------+----------|
         */
        memory_region_init_iommu(&amdvi_dev_as->iommu,
                                 sizeof(amdvi_dev_as->iommu),
                                 TYPE_AMD_VIOMMU_MEMORY_REGION,
                                 OBJECT(s),
                                 "amd_iommu", UINT64_MAX);
        memory_region_init(&amdvi_dev_as->root, OBJECT(s),
                           "amdvi_root", UINT64_MAX);
        address_space_init(&amdvi_dev_as->as, &amdvi_dev_as->root, name);
        memory_region_add_subregion_overlap(&amdvi_dev_as->root, 0,
                                            MEMORY_REGION(&amdvi_dev_as->iommu),
                                            1);
    }

    return &iommu_as[devfn]->as;
}

static const MemoryRegionOps mmio_mem_ops = {
    .read = amdvi_mmio_read,
    .write = amdvi_mmio_write,
    .endianness = DEVICE_LITTLE_ENDIAN,
    .impl = {
        .min_access_size = 1,
        .max_access_size = 8,
        .unaligned = false,
    },
    .valid = {
        .min_access_size = 1,
        .max_access_size = 8,
    }
};

/*
 * TODO: We need to commnicate to VFIO/IOMMU driver to initialize the vIOMMU
 */
static void amd_viommu_init(AMDVIState *s)
{
    int i;

    s->devtab_len = 0;
    s->cmdbuf_len = 0;
    s->cmdbuf_head = 0;
    s->cmdbuf_tail = 0;
    s->evtlog_head = 0;
    s->evtlog_tail = 0;
    s->excl_enabled = false;
    s->excl_allow = false;
    s->mmio_enabled = false;
    s->enabled = false;
    s->ats_enabled = false;
    s->cmdbuf_enabled = false;

    for (i = 0; i < AMDVI_DEVID_MAX; i++)
	s->dev_domid[i] = -1;

    /* reset MMIO */
    memset(s->mmior, 0, AMD_VIOMMU_MMIO_SIZE);
    amdvi_set_quad(s, AMDVI_MMIO_EXT_FEATURES, AMDVI_EXT_FEATURES,
            0xffffffffffffffef, 0);
    amdvi_set_quad(s, AMDVI_MMIO_STATUS, 0, 0x98, 0x67);

    /* reset device ident */
    pci_config_set_vendor_id(s->pci.dev.config, PCI_VENDOR_ID_AMD);
    pci_config_set_prog_interface(s->pci.dev.config, 00);
    pci_config_set_class(s->pci.dev.config, 0x0806);

    /* reset AMDVI specific capabilities, all r/o */
    pci_set_long(s->pci.dev.config + s->pci.capab_offset, AMDVI_CAPAB_FEATURES);
    pci_set_long(s->pci.dev.config + s->pci.capab_offset + AMDVI_CAPAB_BAR_LOW,
                 s->mmio.addr & ~(0xffff0000));
    pci_set_long(s->pci.dev.config + s->pci.capab_offset + AMDVI_CAPAB_BAR_HIGH,
                (s->mmio.addr & ~(0xffff)) >> 16);
    pci_set_long(s->pci.dev.config + s->pci.capab_offset + AMDVI_CAPAB_RANGE,
                 0xff000000);
    pci_set_long(s->pci.dev.config + s->pci.capab_offset + AMDVI_CAPAB_MISC, 0);
    pci_set_long(s->pci.dev.config + s->pci.capab_offset + AMDVI_CAPAB_MISC,
            AMDVI_MAX_PH_ADDR | AMDVI_MAX_GVA_ADDR | AMDVI_MAX_VA_ADDR);

    amd_viommu_iommu_init(s);
}

static void amd_viommu_uninit(AMDVIState *s)
{
    amd_viommu_iommu_uninit(s);
}

/* Note: This happens after attach device. */
static void amdvi_reset(DeviceState *dev)
{
    AMDVIState *s = AMD_VIOMMU_DEVICE(dev);

    msi_reset(&s->pci.dev);
}

#define FEATURE_PPR            (1ULL << 1)
#define FEATURE_GT             (1ULL << 4)
#define FEATURE_GIO            (1ULL << 48)

#define FEATURE_GATS_SHIFT     12
#define FEATURE_GATS_MASK      0x03ULL
#define FEATURE_GATS_5LEVEL    ((1ULL & FEATURE_GATS_MASK) << FEATURE_GATS_SHIFT)

#define FEATURE_GLX_SHIFT      14
#define FEATURE_GLX_MASK       0x03ULL
#define FEATURE_GLX_3LEVEL     ((0ULL & FEATURE_GLX_MASK) << FEATURE_GLX_SHIFT)

#define FEATURE_PASMAX_SHIFT   32
#define FEATURE_PASMAX_MASK    0x1FULL
#define FEATURE_PASMAX_16      ((0xFULL & FEATURE_PASMAX_MASK) << FEATURE_PASMAX_SHIFT)

#define SUPPORTED_EFR	(FEATURE_GT | FEATURE_PPR | FEATURE_GIO | FEATURE_GATS_5LEVEL | \
			 FEATURE_GLX_3LEVEL | FEATURE_PASMAX_16)

static bool amdvi_get_hw_info(AMDVIState *s, IOMMUFDDevice *idev)
{
    enum iommu_hw_info_type type = IOMMU_HW_INFO_TYPE_AMD;

    if (iommufd_device_get_info(idev, &type, sizeof(s->hwinfo), &s->hwinfo)) {
        error_report("Failed to get AMD IOMMU hardware info!!!");
        return false;
    }

    if (type != IOMMU_HW_INFO_TYPE_AMD) {
        error_report("IOMMU hardware is not compatible!!!");
        return false;
    }

    /* Check EFR for v2 PASMAX, GLX, GATS */
    if (s->hwinfo.efr != SUPPORTED_EFR) {
        error_report("Unable to support AMD IOMMU feature (efr=%#llx)!!", s->hwinfo.efr);
        s->hwinfo.efr = 0;
        return false;
    }

    return true;
}

static int amdvi_set_iommu_device(PCIBus *bus, void *opaque,
                                  int devfn, PCIDevice *dev,
                                  IOMMUFDDevice *idev)
{
    AMDVIState *s = opaque;
    AMDIOMMUFDDevice *amd_idev;
    struct amd_as_key key = {
        .bus = bus,
        .devfn = devfn,
    };
    struct amd_as_key *new_key;

    assert(0 <= devfn && devfn < PCI_DEVFN_MAX);

    if (dev && !strcmp(dev->name, "vfio-pci")) {
        bus = pci_get_bus(dev);
        devfn = dev->devfn;
        key.bus = bus;
        key.devfn = devfn;
    }

    if (!amdvi_get_hw_info(s, idev))
        return -ENOENT;

    amd_idev = g_hash_table_lookup(s->amd_iommufd_dev, &key);

    assert(!amd_idev);

    new_key = g_malloc(sizeof(*new_key));
    new_key->bus = bus;
    new_key->devfn = devfn;

    amd_idev = g_malloc0(sizeof(AMDIOMMUFDDevice));
    amd_idev->bus = bus;
    amd_idev->devfn = (uint8_t)devfn;
    amd_idev->iommu_state = s;
    amd_idev->idev = idev;

    g_hash_table_insert(s->amd_iommufd_dev, new_key, amd_idev);

    return 0;
}

static void amdvi_unset_iommu_device(PCIBus *bus, void *opaque,
                                     int devfn, PCIDevice *dev)
{
}

static PCIIOMMUOps amdvi_iommu_ops = {
    .set_iommu_device = amdvi_set_iommu_device,
    .unset_iommu_device = amdvi_unset_iommu_device,
};

static gboolean amd_as_equal(gconstpointer v1, gconstpointer v2)
{
    const struct amd_as_key *key1 = v1;
    const struct amd_as_key *key2 = v2;

    return (key1->bus == key2->bus) && (key1->devfn == key2->devfn) &&
           (key1->pasid == key2->pasid);
}

/*
 * Note that we use pointer to PCIBus as the key, so hashing/shifting
 * based on the pointer value is intended. Note that we deal with
 * collisions through amd_as_equal().
 */
static guint amd_as_hash(gconstpointer v)
{
    const struct amd_as_key *key = v;
    guint value = (guint)(uintptr_t)key->bus;

    return (guint)(value << 8 | key->devfn);
}

static void amd_viommu_realize(DeviceState *dev, Error **errp)
{
    int ret = 0;
    AMDVIState *s = AMD_VIOMMU_DEVICE(dev);
    X86IOMMUState *x86_iommu = X86_IOMMU_DEVICE(dev);
    MachineState *ms = MACHINE(qdev_get_machine());
    PCMachineState *pcms = PC_MACHINE(ms);
    PCIBus *bus = pcms->bus;

    /* This device should take care of IOMMU PCI properties */
    qdev_set_parent_bus(DEVICE(&s->pci), &bus->qbus, &error_abort);
    object_property_set_bool(OBJECT(&s->pci), "realized", true, errp);
    ret = pci_add_capability(&s->pci.dev, AMDVI_CAPAB_ID_SEC, 0,
                                         AMDVI_CAPAB_SIZE, errp);
    if (ret < 0) {
        return;
    }
    s->pci.capab_offset = ret;

    ret = pci_add_capability(&s->pci.dev, PCI_CAP_ID_MSI, 0,
                             AMDVI_CAPAB_REG_SIZE, errp);
    if (ret < 0) {
        return;
    }
    ret = pci_add_capability(&s->pci.dev, PCI_CAP_ID_HT, 0,
                             AMDVI_CAPAB_REG_SIZE, errp);
    if (ret < 0) {
        return;
    }

    /* setup IOMMU PCI device ID in the guest. */
    amd_viommu_host_dma_iommu(bus, s, s->pci.dev.devfn);

    /* set up MMIO */
    memory_region_init_io(&s->mmio, OBJECT(s), &mmio_mem_ops, s, "amdvi-mmio",
                          AMD_VIOMMU_MMIO_SIZE);

    sysbus_init_mmio(SYS_BUS_DEVICE(s), &s->mmio);
    sysbus_mmio_map(SYS_BUS_DEVICE(s), 0, AMDVI_BASE_ADDR + (x86_iommu->index * AMD_VIOMMU_MMIO_SIZE));

    /*
     * Setup vIOMMU for the device w/o specifying the iommu_fn to avoid
     * calling amdvi_host_dma_iommu(). See pci_device_iommu_addres_space()
     * on calling of iommu_fn().
     */
    pci_setup_iommu(bus, &amdvi_iommu_ops, s);

    msi_init(&s->pci.dev, 0, 1, true, false, errp);

    amd_viommu_ioctl_init(s, errp);
    amd_viommu_init(s);

    s->amd_iommufd_dev = g_hash_table_new_full(amd_as_hash, amd_as_equal,
                                      g_free, g_free);
}

static const VMStateDescription vmstate_amdvi = {
    .name = "amd-viommu",
    .unmigratable = 1
};

static void amd_viommu_instance_init(Object *obj)
{
    AMDVIState *s = AMD_VIOMMU_DEVICE(obj);

    object_initialize(&s->pci, sizeof(s->pci), TYPE_AMD_VIOMMU_PCI);
}

static void amd_viommu_instance_finalize(Object *obj)
{
    AMDVIState *s = AMD_VIOMMU_DEVICE(obj);

    amd_viommu_uninit(s);
}

static Property amd_viommu_properties[] = {
    DEFINE_PROP_LINK("iommufd", AMDVIState, iommufd,
                     TYPE_IOMMUFD_BACKEND, IOMMUFDBackend *),
    DEFINE_PROP_UINT32("translate-id", AMDVIState, translate_id, 0),
    DEFINE_PROP_END_OF_LIST(),
};

static void amd_viommu_class_init(ObjectClass *klass, void* data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    X86IOMMUClass *dc_class = X86_IOMMU_DEVICE_CLASS(klass);

    dc->reset = amdvi_reset;
    dc->vmsd = &vmstate_amdvi;
    device_class_set_props(dc, amd_viommu_properties);
    dc->hotpluggable = false;
    dc_class->realize = amd_viommu_realize;

    /* Supported by the pc-q35-* machine types */
    dc->user_creatable = true;
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
    dc->desc = "AMD VIOMMU device";
}

static const TypeInfo AmdViommu = {
    .name = TYPE_AMD_VIOMMU_DEVICE,
    .parent = TYPE_X86_IOMMU_DEVICE,
    .instance_size = sizeof(AMDVIState),
    .instance_finalize = amd_viommu_instance_finalize,
    .instance_init = amd_viommu_instance_init,
    .class_init = amd_viommu_class_init
};

static const TypeInfo AmdViommuPCI = {
    .name = "AMD-VIOMMU-PCI",
    .parent = TYPE_PCI_DEVICE,
    .instance_size = sizeof(AMDVIPCIState),
    .interfaces = (InterfaceInfo[]) {
        { INTERFACE_CONVENTIONAL_PCI_DEVICE },
        { },
    },
};

static const TypeInfo amd_viommu_memory_region_info = {
    .parent = TYPE_IOMMU_MEMORY_REGION,
    .name = TYPE_AMD_VIOMMU_MEMORY_REGION,
};

static void amd_viommu_pci_register_types(void)
{
    type_register_static(&AmdViommuPCI);
    type_register_static(&AmdViommu);
    type_register_static(&amd_viommu_memory_region_info);
}

type_init(amd_viommu_pci_register_types);
