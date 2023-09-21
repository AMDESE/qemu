/*
 * QEMU abstract of Host IOMMU
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

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qom/object.h"
#include "qapi/visitor.h"
#include "sysemu/iommufd_device.h"
#include <sys/ioctl.h>
#include "qemu/error-report.h"

int iommufd_device_attach_hwpt(IOMMUFDDevice *idev, uint32_t hwpt_id)
{
    IOMMUFDDeviceClass *idevc;

    idevc = IOMMU_DEVICE_GET_CLASS(idev);

    if (!idevc->attach_hwpt) {
        return -EINVAL;
    }

    return idevc->attach_hwpt(idev, hwpt_id);
}

int iommufd_device_detach_hwpt(IOMMUFDDevice *idev)
{
    IOMMUFDDeviceClass *idevc;

    idevc = IOMMU_DEVICE_GET_CLASS(idev);

    if (!idevc->detach_hwpt) {
        return -EINVAL;
    }

    return idevc->detach_hwpt(idev);
}

int iommufd_device_get_info(IOMMUFDDevice *idev,
                            enum iommu_hw_info_type *type,
                            uint32_t len, void *data)
{
    struct iommu_hw_info info = {
        .size = sizeof(info),
        .flags = 0,
        .dev_id = idev->dev_id,
        .data_len = len,
        .__reserved = 0,
        .data_uptr = (uint64_t)data,
    };
    int ret;

    ret = ioctl(idev->iommufd->fd, IOMMU_GET_HW_INFO, &info);
    if (ret) {
        error_report("Failed to get info %m");
    } else {
        *type = info.out_data_type;
    }

    return ret;
}

void iommufd_device_init(void *_idev, size_t instance_size,
                         const char *mrtypename, IOMMUFDBackend *iommufd,
                         uint32_t dev_id, uint32_t hwpt_id)
{
    IOMMUFDDevice *idev;

    object_initialize(_idev, instance_size, mrtypename);
    idev = IOMMU_DEVICE(_idev);
    idev->iommufd = iommufd;
    idev->dev_id = dev_id;
    idev->def_hwpt_id = hwpt_id;
    idev->initialized = true;
}

static void iommufd_device_finalize_fn(Object *obj)
{
#if 0
    IOMMUFDDevice *idev = IOMMU_DEVICE(obj);
#endif
}

static const TypeInfo iommufd_device_device = {
    .parent             = TYPE_OBJECT,
    .name               = TYPE_IOMMUFD_DEVICE,
    .class_size         = sizeof(IOMMUFDDeviceClass),
    .instance_size      = sizeof(IOMMUFDDevice),
    .instance_finalize  = iommufd_device_finalize_fn,
    .abstract           = true,
};

static void iommufd_device_register_types(void)
{
    type_register_static(&iommufd_device_device);
}

type_init(iommufd_device_register_types)
