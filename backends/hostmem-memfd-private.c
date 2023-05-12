/*
 * QEMU host private memfd memory backend
 *
 * Copyright (C) 2021 Intel Corporation
 *
 * Authors:
 *   Chao Peng <chao.p.peng@linux.intel.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "sysemu/hostmem.h"
#include "hw/boards.h"
#include "qom/object_interfaces.h"
#include "qemu/memfd.h"
#include "qemu/module.h"
#include "qemu/units.h"
#include "qapi/error.h"
#include "qom/object.h"
#include "exec/confidential-guest-support.h"

#define MIN_DISCARD_SZ 4096

struct HostMemoryBackendPrivateMemfd {
    HostMemoryBackend parent_obj;

    bool hugetlb;
    uint64_t hugetlbsize;

    unsigned long *discard_bitmap;
    int64_t discard_bitmap_size;

    QLIST_HEAD(, RamDiscardListener) rdl_list;
};

static void
priv_memfd_backend_memory_alloc(HostMemoryBackend *backend, Error **errp)
{
    HostMemoryBackendPrivateMemfd *m = MEMORY_BACKEND_MEMFD_PRIVATE(backend);
    MachineState *machine = MACHINE(qdev_get_machine());
    ConfidentialGuestSupport *cgs = machine->cgs;
    Error *local_err = NULL;
    uint32_t ram_flags;
    char *name;
    int fd;

    if (!backend->size) {
        error_setg(errp, "can't create backend with size 0");
        return;
    }

    fd = qemu_memfd_create("memory-backend-memfd-shared", backend->size,
                           m->hugetlb, m->hugetlbsize, 0, errp);
    if (fd == -1) {
        return;
    }

    name = host_memory_backend_get_name(backend);
    ram_flags = backend->share ? RAM_SHARED : 0;
    ram_flags |= backend->reserve ? 0 : RAM_NORESERVE;
    memory_region_init_ram_from_fd(&backend->mr, OBJECT(backend), name,
                                   backend->size, ram_flags, fd, 0, errp);
    g_free(name);

    memory_region_set_restricted_fd(&backend->mr, backend->size, &local_err);
    if (local_err) {
        error_propagate(errp, local_err);
        return;
    }

    machine->ram_size = backend->size;

#define DISCARD_NONE 3
    if (cgs->discard != DISCARD_NONE) {
        g_warning("Registering RAM discard manager for private memfd backend.");
        m->discard_bitmap_size = backend->size / MIN_DISCARD_SZ;
        m->discard_bitmap = bitmap_new(m->discard_bitmap_size);
        memory_region_set_ram_discard_manager(host_memory_backend_get_memory(backend),
                                              RAM_DISCARD_MANAGER(m));
    }
}

static bool
priv_memfd_backend_get_hugetlb(Object *o, Error **errp)
{
    return MEMORY_BACKEND_MEMFD_PRIVATE(o)->hugetlb;
}

static void
priv_memfd_backend_set_hugetlb(Object *o, bool value, Error **errp)
{
    MEMORY_BACKEND_MEMFD_PRIVATE(o)->hugetlb = value;
}

static void
priv_memfd_backend_set_hugetlbsize(Object *obj, Visitor *v, const char *name,
                                   void *opaque, Error **errp)
{
    HostMemoryBackendPrivateMemfd *m = MEMORY_BACKEND_MEMFD_PRIVATE(obj);
    uint64_t value;

    if (host_memory_backend_mr_inited(MEMORY_BACKEND(obj))) {
        error_setg(errp, "cannot change property value");
        return;
    }

    if (!visit_type_size(v, name, &value, errp)) {
        return;
    }
    if (!value) {
        error_setg(errp, "Property '%s.%s' doesn't take value '%" PRIu64 "'",
                   object_get_typename(obj), name, value);
        return;
    }
    m->hugetlbsize = value;
}

static void
priv_memfd_backend_get_hugetlbsize(Object *obj, Visitor *v, const char *name,
                                   void *opaque, Error **errp)
{
    HostMemoryBackendPrivateMemfd *m = MEMORY_BACKEND_MEMFD_PRIVATE(obj);
    uint64_t value = m->hugetlbsize;

    visit_type_size(v, name, &value, errp);
}

static void
priv_memfd_backend_instance_init(Object *obj)
{
    HostMemoryBackendPrivateMemfd *m = MEMORY_BACKEND_MEMFD_PRIVATE(obj);

    MEMORY_BACKEND(obj)->reserve = false;
    QLIST_INIT(&m->rdl_list);
}

static uint64_t priv_memfd_rdm_get_min_granularity(const RamDiscardManager *rdm,
                                                   const MemoryRegion *mr)
{
    return MIN_DISCARD_SZ;
}

static bool priv_memfd_rdm_is_populated(const RamDiscardManager *rdm,
                                        const MemoryRegionSection *s)
{
    const HostMemoryBackendPrivateMemfd *m = MEMORY_BACKEND_MEMFD_PRIVATE(rdm);
    const unsigned long first_bit = s->offset_within_region / MIN_DISCARD_SZ;
    const unsigned long last_bit = first_bit + int128_get64(s->size) / MIN_DISCARD_SZ;
    unsigned long first_populated_bit;

    first_populated_bit = find_next_zero_bit(m->discard_bitmap, last_bit + 1,
                                             first_bit);

    return first_populated_bit > last_bit;
}

static bool priv_memfd_rdm_find_intersect(const HostMemoryBackendPrivateMemfd *m,
                                          MemoryRegionSection *s,
                                          uint64_t offset, uint64_t size)
{
    uint64_t start = MAX(s->offset_within_region, offset);
    uint64_t end = MIN(s->offset_within_region + int128_get64(s->size),
                       offset + size);

    if (end <= start) {
        return false;
    }

    s->offset_within_address_space += start - s->offset_within_region;
    s->offset_within_region = start;
    s->size = int128_make64(end - start);

    return true;
}

typedef int (*priv_memfd_section_cb)(MemoryRegionSection *s, void *arg);

static int priv_memfd_notify_populate_cb(MemoryRegionSection *s, void *arg)
{
    RamDiscardListener *rdl = arg;

    return rdl->notify_populate(rdl, s);
}

static int priv_memfd_notify_discard_cb(MemoryRegionSection *s, void *arg)
{
    RamDiscardListener *rdl = arg;

    rdl->notify_discard(rdl, s);

    return 0;
}

static int priv_memfd_for_each_populated_range(const HostMemoryBackendPrivateMemfd *m,
                                               MemoryRegionSection *s,
                                               void *arg,
                                               priv_memfd_section_cb cb)
{
    unsigned long first_zero_bit, last_zero_bit;
    int ret;

    first_zero_bit = find_first_zero_bit(m->discard_bitmap,
                                         m->discard_bitmap_size);
    while (first_zero_bit < m->discard_bitmap_size) {
        MemoryRegionSection tmp = *s;
        uint64_t offset, size;

        offset = first_zero_bit * MIN_DISCARD_SZ;
        last_zero_bit = find_next_bit(m->discard_bitmap, m->discard_bitmap_size,
                                      first_zero_bit + 1) - 1;
        size = (last_zero_bit - first_zero_bit + 1) * MIN_DISCARD_SZ;

        if (!priv_memfd_rdm_find_intersect(m, &tmp, offset, size)) {
            break;
        }

        ret = cb(&tmp, arg);
        if (ret) {
            break;
        }

        first_zero_bit = find_next_zero_bit(m->discard_bitmap,
                                            m->discard_bitmap_size,
                                            last_zero_bit + 2);
    }

    return false;
}

static int priv_memfd_for_each_discarded_range(const HostMemoryBackendPrivateMemfd *m,
                                               MemoryRegionSection *s,
                                               void *arg,
                                               priv_memfd_section_cb cb)
{
    unsigned long first_bit, last_bit;
    int ret;

    first_bit = find_first_bit(m->discard_bitmap, m->discard_bitmap_size);
    while (first_bit < m->discard_bitmap_size) {
        MemoryRegionSection tmp = *s;
        uint64_t offset, size;

        offset = first_bit * MIN_DISCARD_SZ;
        last_bit = find_next_zero_bit(m->discard_bitmap, m->discard_bitmap_size,
                                      first_bit + 1) - 1;
        size = (last_bit - first_bit + 1) * MIN_DISCARD_SZ;

        if (!priv_memfd_rdm_find_intersect(m, &tmp, offset, size)) {
            break;
        }

        ret = cb(&tmp, arg);
        if (ret) {
            break;
        }

        first_bit = find_next_bit(m->discard_bitmap,
                                  m->discard_bitmap_size, last_bit + 2);
    }

    return false;
}

typedef struct PrivateMemfdReplayData {
    void *fn;
    void *opaque;
} PrivateMemfdReplayData;

static int priv_memfd_rdm_replay_populated_cb(MemoryRegionSection *s, void *arg)
{
    PrivateMemfdReplayData *data = arg;

    return ((ReplayRamPopulate)data->fn)(s, data->opaque);
}

static int priv_memfd_rdm_replay_populated(const RamDiscardManager *rdm,
                                           MemoryRegionSection *s,
                                           ReplayRamPopulate replay_fn,
                                           void *opaque)
{
    const HostMemoryBackendPrivateMemfd *m = MEMORY_BACKEND_MEMFD_PRIVATE(rdm);
    struct PrivateMemfdReplayData data = {
        .fn = replay_fn,
        .opaque = opaque,
    };

    g_assert(s->mr == host_memory_backend_get_memory(MEMORY_BACKEND(m)));
    return priv_memfd_for_each_populated_range(m, s, &data,
                                               priv_memfd_rdm_replay_populated_cb);

}

static int priv_memfd_rdm_replay_discarded_cb(MemoryRegionSection *s, void *arg)
{
    PrivateMemfdReplayData *data = arg;

    return ((ReplayRamPopulate)data->fn)(s, data->opaque);
}

static void priv_memfd_rdm_replay_discarded(const RamDiscardManager *rdm,
                                           MemoryRegionSection *s,
                                           ReplayRamDiscard replay_fn,
                                           void *opaque)
{
    const HostMemoryBackendPrivateMemfd *m = MEMORY_BACKEND_MEMFD_PRIVATE(rdm);
    struct PrivateMemfdReplayData data = {
        .fn = replay_fn,
        .opaque = opaque,
    };

    g_assert(s->mr == host_memory_backend_get_memory(MEMORY_BACKEND(m)));
    priv_memfd_for_each_discarded_range(m, s, &data,
                                        priv_memfd_rdm_replay_discarded_cb);
}

static void priv_memfd_rdm_register_listener(RamDiscardManager *rdm,
                                             RamDiscardListener *rdl,
                                             MemoryRegionSection *s)
{
    HostMemoryBackendPrivateMemfd *m = MEMORY_BACKEND_MEMFD_PRIVATE(rdm);
    int ret;

    g_assert(s->mr == host_memory_backend_get_memory(MEMORY_BACKEND(m)));

    rdl->section = memory_region_section_new_copy(s);
    QLIST_INSERT_HEAD(&m->rdl_list, rdl, next);

    ret = priv_memfd_for_each_populated_range(m, s, rdl, priv_memfd_notify_populate_cb);
    if (ret) {
        g_warning("failed to register RAM discard listener: %d", ret);
        return;
    }
}

static void priv_memfd_rdm_unregister_listener(RamDiscardManager *rdm,
                                               RamDiscardListener *rdl)
{
    HostMemoryBackendPrivateMemfd *m = MEMORY_BACKEND_MEMFD_PRIVATE(rdm);
    int ret;

    g_assert(rdl->section->mr == host_memory_backend_get_memory(MEMORY_BACKEND(m)));

    ret = priv_memfd_for_each_populated_range(m, rdl->section, rdl, priv_memfd_notify_discard_cb);
    if (ret) {
        g_warning("failed to unregister RAM discard listener: %d", ret);
        return;
    }

    memory_region_section_free_copy(rdl->section);
    rdl->section = NULL;
    QLIST_REMOVE(rdl, next);
}

static int priv_memfd_discard(Object *backend, RAMBlock *rb, uint64_t offset, uint64_t size, bool shared_to_private)
{
    HostMemoryBackendPrivateMemfd *m = MEMORY_BACKEND_MEMFD_PRIVATE(backend);
    RamDiscardListener *rdl, *rdl2;
    int ret = 0;

    assert((size % MIN_DISCARD_SZ) == 0);

    QLIST_FOREACH(rdl, &m->rdl_list, next) {
        MemoryRegionSection tmp = *rdl->section;

        if (!priv_memfd_rdm_find_intersect(m, &tmp, offset, size)) {
            continue;
        }

        if (shared_to_private) {
            rdl->notify_discard(rdl, &tmp);
        } else {
            ret = rdl->notify_populate(rdl, &tmp);
        }

        if (ret) {
            break;
        }
    }

    if (!ret) {
        const unsigned long first_bit = offset / MIN_DISCARD_SZ;
        const unsigned long nbits = size / MIN_DISCARD_SZ;

        assert((first_bit + nbits) <= m->discard_bitmap_size);

        ret = ram_block_convert_range(rb, offset, size, shared_to_private);
        if (ret) {
            goto rollback;
        }

        if (shared_to_private) {
            bitmap_set(m->discard_bitmap, first_bit, nbits);
        } else {
            bitmap_clear(m->discard_bitmap, first_bit, nbits);
        }

        return 0;
    }

rollback:
    /* Something went wrong, roll back listener updates. */
    QLIST_FOREACH(rdl2, &m->rdl_list, next) {
        MemoryRegionSection tmp = *rdl2->section;

        if (rdl2 == rdl) {
            break;
        }

        if (!priv_memfd_rdm_find_intersect(m, &tmp, offset, size)) {
            continue;
        }

        if (shared_to_private) {
            rdl2->notify_populate(rdl, &tmp);
        } else {
            rdl2->notify_discard(rdl, &tmp);
        }
    }

    return ret;
}

static void
priv_memfd_backend_class_init(ObjectClass *oc, void *data)
{
    HostMemoryBackendClass *bc = MEMORY_BACKEND_CLASS(oc);
    HostMemoryBackendPrivateMemfdClass *pbc = MEMORY_BACKEND_MEMFD_PRIVATE_CLASS(bc);
    RamDiscardManagerClass *rdmc = RAM_DISCARD_MANAGER_CLASS(pbc);

    bc->alloc = priv_memfd_backend_memory_alloc;
    pbc->discard = priv_memfd_discard;

    if (qemu_memfd_check(MFD_HUGETLB)) {
        object_class_property_add_bool(oc, "hugetlb",
                                       priv_memfd_backend_get_hugetlb,
                                       priv_memfd_backend_set_hugetlb);
        object_class_property_set_description(oc, "hugetlb",
                                              "Use huge pages");
        object_class_property_add(oc, "hugetlbsize", "int",
                                  priv_memfd_backend_get_hugetlbsize,
                                  priv_memfd_backend_set_hugetlbsize,
                                  NULL, NULL);
        object_class_property_set_description(oc, "hugetlbsize",
                                              "Huge pages size (ex: 2M, 1G)");
    }

    rdmc->get_min_granularity = priv_memfd_rdm_get_min_granularity;
    rdmc->is_populated = priv_memfd_rdm_is_populated;
    rdmc->replay_populated = priv_memfd_rdm_replay_populated;
    rdmc->replay_discarded = priv_memfd_rdm_replay_discarded;
    rdmc->register_listener = priv_memfd_rdm_register_listener;
    rdmc->unregister_listener = priv_memfd_rdm_unregister_listener;
}

static const TypeInfo priv_memfd_backend_info = {
    .name = TYPE_MEMORY_BACKEND_MEMFD_PRIVATE,
    .parent = TYPE_MEMORY_BACKEND,
    .instance_init = priv_memfd_backend_instance_init,
    .class_init = priv_memfd_backend_class_init,
    .instance_size = sizeof(HostMemoryBackendPrivateMemfd),
    .interfaces = (InterfaceInfo[]) {
        { TYPE_RAM_DISCARD_MANAGER },
        { }
    },
};

static void register_types(void)
{
    if (qemu_memfd_check(MFD_ALLOW_SEALING)) {
        type_register_static(&priv_memfd_backend_info);
    }
}

type_init(register_types);
