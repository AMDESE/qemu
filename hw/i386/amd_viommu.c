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

static int amd_viommu_ioctl_init(AMDVIState *s, Error **errp);

static int amd_viommu_mmio_write(AMDVIState *s, __u32 offset,
                                 __u32 size, __u64 value);

static int amd_viommu_cmdbuf_update(AMDVIState *s, __u64 val);

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

static int amd_viommu_cmdbuf_update(AMDVIState *s, __u64 val)
{
    struct amd_viommu_cmdbuf_data arg = {
        .size = sizeof(arg),
    };
    uint64_t gpa = val & 0xFFFFFFFFFF000ULL;
    void *hva = gpa2hva(gpa, 0x1000);
    int size = (1 << ((val >> 56) & 0xF)) * 16;
    uint16_t bdf = PCI_BUILD_BDF((s->iommu.host.bus),
				PCI_DEVFN(s->iommu.host.slot,
					  s->iommu.host.function));

    arg.iommu_id = bdf;
    arg.gid = s->gid;
    arg.cmdbuf_size = size;
    arg.hva = (__u64) hva;
    return ioctl(s->iommufd->fd , VIOMMU_CMDBUF_UPDATE, &arg);
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
                                  uint16_t flags, uint16_t dev_id)
{
    struct amd_viommu_gcr3_data arg = {
        .size = sizeof(arg),
    };
    uint32_t bdf= PCI_BUILD_BDF(s->iommu.host.bus,
                                PCI_DEVFN(s->iommu.host.slot,
                                          s->iommu.host.function));

    arg.iommu_id = bdf;
    arg.gcr3 = gcr3;
    arg.gcr3_va = gcr3_va;
    arg.flags = flags;
    arg.gid = s->gid;
    arg.gdev_id= dev_id;

    return ioctl(s->iommufd->fd, VIOMMU_GCR3_UPDATE, &arg);
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

static void amd_viommu_dte_write(void *opaque, hwaddr offset, uint64_t val,
                             unsigned size)
{
    uint64_t lo, hi, offset_lo, offset_hi, gcr3tbl;
    AMDVIState *s = opaque;
    uint16_t flags;
    uint32_t devid;

    if (size ==  2) {
        stw_le_p(&s->devtab[offset], val);
    } else if (size == 4) {
        stl_le_p(&s->devtab[offset], val);
    } else if (size == 8) {
        stq_le_p(&s->devtab[offset], val);
    }

    if (offset % 0x20 != 0x8)
        return;

    offset_lo = offset - 8;
    offset_hi = offset;

    devid = offset_lo >> 5;

    lo = amd_viommu_dte_read(opaque, offset_lo, size);
    hi = amd_viommu_dte_read(opaque, offset_hi, size);
    if (lo & 0xE03ULL) {
        int domid = hi & 0xFFFFULL;
        int tmp = s->dev_domid[devid & 0xFF];

	if (tmp == domid)
		return;

	s->dev_domid[devid & 0xFF] = domid;
	trace_amd_viommu_dte(s->devtab_base + offset_lo, s->devtab_base + offset_hi,
                             size, val, devid, domid);

        /* TODO: handle detach */
	amd_viommu_update_domain_id(s, devid, domid, true);
    }

    /* Setting gCR3 */
    gcr3tbl = (((lo >> 58) & 7ULL) << 12) |
                 (((hi >> 16) & 0xFFFFULL) << 15) |
                 (((hi >> 43) & 0x1FFFFFULL) << 31);
    flags = (lo >> 52) & 0x3F;

    if (gcr3tbl) {
        void *gcr3tbl_va = gpa2hva(gcr3tbl, 0x1000);
        uint64_t gcr30 = *((__u64*)gcr3tbl_va);
        void *gcr30_va = gpa2hva(gcr30, 0x1000);

        trace_amd_viommu_gcr3(gcr3tbl, (uint64_t)gcr3tbl_va, gcr30, (uint64_t)gcr30_va, flags);
        amd_viommu_update_gcr3(s, (uint64_t)gcr30, (uint64_t)gcr30_va, flags, devid);
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

    amd_viommu_cmdbuf_update(s, val);
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

    for (i = 0; i < 256; i++)
	s->dev_domid[i] = -1;

    /* reset MMIO */
    memset(s->mmior, 0, AMD_VIOMMU_MMIO_SIZE);
    amdvi_set_quad(s, AMDVI_MMIO_EXT_FEATURES, AMDVI_EXT_FEATURES,
            0xffffffffffffffef, 0);
    amdvi_set_quad(s, AMDVI_MMIO_STATUS, 0, 0x98, 0x67);

    /* reset device ident */
    pci_config_set_vendor_id(s->pci.dev.config, PCI_VENDOR_ID_AMD);
    pci_config_set_prog_interface(s->pci.dev.config, 00);
    pci_config_set_device_id(s->pci.dev.config, s->devid);
    pci_config_set_class(s->pci.dev.config, 0x0806);

    /* reset AMDVI specific capabilities, all r/o */
    pci_set_long(s->pci.dev.config + s->capab_offset, AMDVI_CAPAB_FEATURES);
    pci_set_long(s->pci.dev.config + s->capab_offset + AMDVI_CAPAB_BAR_LOW,
                 s->mmio.addr & ~(0xffff0000));
    pci_set_long(s->pci.dev.config + s->capab_offset + AMDVI_CAPAB_BAR_HIGH,
                (s->mmio.addr & ~(0xffff)) >> 16);
    pci_set_long(s->pci.dev.config + s->capab_offset + AMDVI_CAPAB_RANGE,
                 0xff000000);
    pci_set_long(s->pci.dev.config + s->capab_offset + AMDVI_CAPAB_MISC, 0);
    pci_set_long(s->pci.dev.config + s->capab_offset + AMDVI_CAPAB_MISC,
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
    s->capab_offset = ret;

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
    pci_setup_iommu(bus, NULL, s);
    s->devid = object_property_get_int(OBJECT(&s->pci), "addr", errp);
    msi_init(&s->pci.dev, 0, 1, true, false, errp);

    amd_viommu_ioctl_init(s, errp);
    amd_viommu_init(s);
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
