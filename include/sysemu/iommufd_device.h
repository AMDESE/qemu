/*
 * IOMMU Device
 *
 * Copyright (C) 2022 Intel Corporation.
 *
 * Authors: Yi Liu <yi.l.liu@intel.com>
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
 */

#ifndef SYSEMU_IOMMUFD_DEVICE_H
#define SYSEMU_IOMMUFD_DEVICE_H

#include "qemu/queue.h"
#include "qemu/thread.h"
#include "qom/object.h"
#ifndef CONFIG_USER_ONLY
#include "exec/hwaddr.h"
#endif
#include <linux/iommufd.h>
#include "sysemu/iommufd.h"

#define TYPE_IOMMUFD_DEVICE "qemu:iommufd-device"
#define IOMMU_DEVICE(obj) \
        OBJECT_CHECK(IOMMUFDDevice, (obj), TYPE_IOMMUFD_DEVICE)
#define IOMMU_DEVICE_GET_CLASS(obj) \
        OBJECT_GET_CLASS(IOMMUFDDeviceClass, (obj), \
                         TYPE_IOMMUFD_DEVICE)
#define IOMMU_DEVICE_CLASS(klass) \
        OBJECT_CLASS_CHECK(IOMMUFDDeviceClass, (klass), \
                           TYPE_IOMMUFD_DEVICE)

typedef struct IOMMUFDDevice IOMMUFDDevice;

typedef struct IOMMUFDDeviceClass {
    /* private */
    ObjectClass parent_class;

    int (*attach_hwpt)(IOMMUFDDevice *idev,
                       uint32_t hwpt_id);
    int (*detach_hwpt)(IOMMUFDDevice *idev);
} IOMMUFDDeviceClass;

/*
 * This is an abstraction of host IOMMU with dual-stage capability
 */
struct IOMMUFDDevice {
    Object parent_obj;
    IOMMUFDBackend *iommufd;
    uint32_t dev_id;
    bool initialized;
};

int iommufd_device_attach_hwpt(IOMMUFDDevice *idev,
                               uint32_t hwpt_id);
int iommufd_device_detach_hwpt(IOMMUFDDevice *idev);
int iommufd_device_get_info(IOMMUFDDevice *idev,
                            enum iommu_hw_info_type *type,
                            uint32_t len, void *data);
int iommufd_device_get_resv_iova(IOMMUFDDevice *idev,
                                 struct iommu_resv_iova_range **resv);
void iommufd_device_init(void *_idev, size_t instance_size,
                         const char *mrtypename, IOMMUFDBackend *iommufd,
                         uint32_t dev_id);
void iommufd_device_destroy(IOMMUFDDevice *idev);

#endif
