/*
 * QEMU guest_memfd memory backend
 *
 * Copyright (C) 2026 AMD Inc.
 *
 * Authors:
 *
 *   Michael Roth <michael.roth@amd.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "system/hostmem.h"
#include "qom/object_interfaces.h"
#include "qemu/memfd.h"
#include "qemu/module.h"
#include "qapi/error.h"
#include "qom/object.h"
#include "migration/cpr.h"
#include "system/kvm.h"

OBJECT_DECLARE_SIMPLE_TYPE(HostMemoryBackendGuestMemfd, MEMORY_BACKEND_GUEST_MEMFD)

struct HostMemoryBackendGuestMemfd {
    HostMemoryBackend parent_obj;
};


static bool
guest_memfd_backend_memory_alloc(HostMemoryBackend *backend, Error **errp)
{
    g_autofree char *name = host_memory_backend_get_name(backend);
    int fd = cpr_find_fd(name, 0);
    uint32_t ram_flags;

    if (!backend->size) {
        error_setg(errp, "can't create backend with size 0");
        return false;
    }

    if (fd >= 0) {
        goto have_fd;
    }
    fd = kvm_create_guest_memfd_shared(backend->size, errp);
    if (fd == -1) {
        return false;
    }
    cpr_save_fd(name, 0, fd);

have_fd:
    backend->aligned = true;
    ram_flags = backend->share ? RAM_SHARED : RAM_PRIVATE;
    ram_flags |= backend->reserve ? 0 : RAM_NORESERVE;
    ram_flags |= backend->guest_memfd ? RAM_GUEST_MEMFD : 0;
    return memory_region_init_ram_from_fd(&backend->mr, OBJECT(backend), name,
                                          backend->size, ram_flags, fd, 0, errp);
}

static void
guest_memfd_backend_instance_init(Object *obj)
{
    HostMemoryBackendGuestMemfd *m = MEMORY_BACKEND_GUEST_MEMFD(obj);

    MEMORY_BACKEND(m)->share = true;
}

static void
guest_memfd_backend_class_init(ObjectClass *oc, const void *data)
{
    HostMemoryBackendClass *bc = MEMORY_BACKEND_CLASS(oc);

    bc->alloc = guest_memfd_backend_memory_alloc;
}

static const TypeInfo guest_memfd_backend_info = {
    .name = TYPE_MEMORY_BACKEND_GUEST_MEMFD,
    .parent = TYPE_MEMORY_BACKEND,
    .instance_init = guest_memfd_backend_instance_init,
    .class_init = guest_memfd_backend_class_init,
    .instance_size = sizeof(HostMemoryBackendGuestMemfd),
};

static void register_types(void)
{
    type_register_static(&guest_memfd_backend_info);
}

type_init(register_types);
