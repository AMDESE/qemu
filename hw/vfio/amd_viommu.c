#include <sys/ioctl.h>
//#include <linux/iommufd.h>
#include <linux/amd_viommu.h>

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/error-report.h"
#include "trace.h"

#include "hw/pci/pci_bus.h"
#include "amd_viommu.h"
#include "sysemu/iommufd.h"

int amd_viommu_attach_vfio_device(VFIOPCIDevice *vdev)
{
    struct amd_viommu_dev_info arg = {
        .size = sizeof(arg),
    };
    PCIDevice *pdev = &vdev->pdev;
    PCIBus *bus = pci_get_bus(&vdev->pdev);
    /* Note see hw/pci/pci.c: pci_setup_iommu() */
    AMDVIState *s = (AMDVIState *)bus->iommu_opaque;
    uint16_t host_bdf = PCI_BUILD_BDF((vdev->host.bus),
                                      PCI_DEVFN(vdev->host.slot,
                                                vdev->host.function));
    uint16_t iommu_bdf;

    if (!s)
        return 0;

    iommu_bdf = PCI_BUILD_BDF((s->iommu.host.bus),
                              PCI_DEVFN(s->iommu.host.slot,
                              s->iommu.host.function));

    /*
     * Attaching VFIO PCI device to AMD vIOMMU device
     * using the specified parent IOMMU ID. This ID is used
     * when creating the IVRS table for AMD vIOMMU device.
     */
    pdev->parent_iommu_id = vdev->parent_iommu_id;

    /* TODO: Hardcode queue_id to zero for now */
    arg.queue_id = 0; 
    arg.iommu_id = iommu_bdf;
    arg.gid = s->gid;
    arg.gdev_id = vdev->pdev.devfn;
    arg.hdev_id = host_bdf;

    return ioctl(s->iommufd->fd, VIOMMU_DEVICE_ATTACH, &arg);
}

int amd_viommu_detach_vfio_device(VFIOPCIDevice *vdev)
{
    struct amd_viommu_dev_info arg = {
        .size = sizeof(arg),
    };
    PCIBus *bus = pci_get_bus(&vdev->pdev);
    /* Note see hw/pci/pci.c: pci_setup_iommu() */
    AMDVIState *s = (AMDVIState *)bus->iommu_opaque;
    uint16_t iommu_bdf = PCI_BUILD_BDF((s->iommu.host.bus),
                                       PCI_DEVFN(s->iommu.host.slot,
                                                 s->iommu.host.function));

    if (!s) {
        return 0;
    }

    /* TODO: Hardcode for now */
    arg.queue_id = 0;
    arg.iommu_id = iommu_bdf;
    arg.gid = s->gid;
    arg.gdev_id = vdev->pdev.devfn;

    return ioctl(s->iommufd->fd, VIOMMU_DEVICE_DETACH, &arg);
}
