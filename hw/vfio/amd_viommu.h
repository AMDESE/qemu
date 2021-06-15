#ifndef VFIO_AMD_IOMMU_H
#define VFIO_AMD_IOMMU_H

#include "hw/i386/amd_iommu.h"

int amd_viommu_attach_vfio_device(VFIOPCIDevice *vdev);
int amd_viommu_detach_vfio_device(VFIOPCIDevice *vdev);

#endif /*VFIO_AMD_IOMMU_H*/
