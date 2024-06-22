/*
 * QEMU host memfd memory backend
 *
 * Copyright (C) 2018 Red Hat Inc
 *
 * Authors:
 *   Marc-André Lureau <marcandre.lureau@redhat.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 */

#include "qemu/osdep.h"
#include "system/hostmem.h"
#include "hw/boards.h"
#include "qom/object_interfaces.h"
#include "qemu/memfd.h"
#include "qemu/module.h"
#include "qemu/units.h"
#include "qapi/error.h"
#include "qom/object.h"
#include "migration/cpr.h"
#include "system/confidential-guest-support.h"

#define TYPE_MEMORY_BACKEND_MEMFD "memory-backend-memfd"

#define MEMFD_MIN_DISCARD_SIZE 4096

struct HostMemoryBackendMemfd {
    HostMemoryBackend parent_obj;

    bool hugetlb;
    uint64_t hugetlbsize;
    bool seal;
    bool discard_shared;

    unsigned long *discard_bitmap;
    int64_t discard_bitmap_size;
    QLIST_HEAD(, RamDiscardListener) rdl_list;
};

static bool
memfd_backend_memory_alloc(HostMemoryBackend *backend, Error **errp)
{
    HostMemoryBackendMemfd *m = MEMORY_BACKEND_MEMFD(backend);
    g_autofree char *name = host_memory_backend_get_name(backend);
    int fd = cpr_find_fd(name, 0);
    uint32_t ram_flags;
    MachineState *machine = MACHINE(qdev_get_machine());
    ConfidentialGuestSupport *cgs = machine->cgs;
    bool ret;

    if (!backend->size) {
        error_setg(errp, "can't create backend with size 0");
        return false;
    }

    if (fd >= 0) {
        goto have_fd;
    }

    fd = qemu_memfd_create(TYPE_MEMORY_BACKEND_MEMFD, backend->size,
                           m->hugetlb, m->hugetlbsize, m->seal ?
                           F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL : 0,
                           errp);
    if (fd == -1) {
        return false;
    }
    cpr_save_fd(name, 0, fd);

have_fd:
    backend->aligned = true;
    ram_flags = backend->share ? RAM_SHARED : RAM_PRIVATE;
    ram_flags |= backend->reserve ? 0 : RAM_NORESERVE;
    ram_flags |= backend->guest_memfd ? RAM_GUEST_MEMFD : 0;
    ret = memory_region_init_ram_from_fd(&backend->mr, OBJECT(backend), name,
                                   backend->size, ram_flags, fd, 0, errp);
    if (!ret) {
        return ret;
    }

    machine->ram_size = backend->size;
    if (backend->guest_memfd && cgs->discard != DISCARD_NONE) {
        m->discard_bitmap_size = backend->size / MEMFD_MIN_DISCARD_SIZE;
        m->discard_bitmap = bitmap_new(m->discard_bitmap_size);
        bitmap_fill(m->discard_bitmap, m->discard_bitmap_size);
        memory_region_set_ram_discard_manager(
                        host_memory_backend_get_memory(backend),
                        RAM_DISCARD_MANAGER(m));
    }

    return ret;
}

static bool
memfd_backend_get_hugetlb(Object *o, Error **errp)
{
    return MEMORY_BACKEND_MEMFD(o)->hugetlb;
}

static void
memfd_backend_set_hugetlb(Object *o, bool value, Error **errp)
{
    MEMORY_BACKEND_MEMFD(o)->hugetlb = value;
}

static void
memfd_backend_set_hugetlbsize(Object *obj, Visitor *v, const char *name,
                              void *opaque, Error **errp)
{
    HostMemoryBackendMemfd *m = MEMORY_BACKEND_MEMFD(obj);
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
memfd_backend_get_hugetlbsize(Object *obj, Visitor *v, const char *name,
                              void *opaque, Error **errp)
{
    HostMemoryBackendMemfd *m = MEMORY_BACKEND_MEMFD(obj);
    uint64_t value = m->hugetlbsize;

    visit_type_size(v, name, &value, errp);
}

static bool
memfd_backend_get_seal(Object *o, Error **errp)
{
    return MEMORY_BACKEND_MEMFD(o)->seal;
}

static void
memfd_backend_set_seal(Object *o, bool value, Error **errp)
{
    MEMORY_BACKEND_MEMFD(o)->seal = value;
}

static void
memfd_backend_instance_init(Object *obj)
{
    HostMemoryBackendMemfd *m = MEMORY_BACKEND_MEMFD(obj);

    /* default to sealed file */
    m->seal = true;
    MEMORY_BACKEND(m)->share = true;
    QLIST_INIT(&m->rdl_list);
}

static uint64_t
memfd_rdm_get_min_granularity(const RamDiscardManager *rdm,
                              const MemoryRegion *mr)
{
    return MEMFD_MIN_DISCARD_SIZE;
}

static bool
memfd_rdm_is_populated(const RamDiscardManager *rdm,
                       const MemoryRegionSection *s)
{
    const HostMemoryBackendMemfd *m = MEMORY_BACKEND_MEMFD(rdm);
    const unsigned long first_bit = s->offset_within_region /
                                    MEMFD_MIN_DISCARD_SIZE;
    const unsigned long last_bit = first_bit +
                                   int128_get64(s->size) /
                                   MEMFD_MIN_DISCARD_SIZE - 1;
    unsigned long first_populated_bit;

    first_populated_bit = find_next_zero_bit(m->discard_bitmap, last_bit + 1,
                                             first_bit);

    return first_populated_bit > last_bit;
}

static bool
memfd_rdm_find_intersect(const HostMemoryBackendMemfd *m,
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

typedef int (*memfd_section_cb)(MemoryRegionSection *s, void *arg);

static int
memfd_notify_populate_cb(MemoryRegionSection *s, void *arg)
{
    RamDiscardListener *rdl = arg;
    int ret;

    ret = rdl->notify_populate(rdl, s);
    return ret;
}

static int
memfd_notify_discard_cb(MemoryRegionSection *s, void *arg)
{
    RamDiscardListener *rdl = arg;
    int ret;

    ret = rdl->notify_discard(rdl, s);

    return ret;
}

static int
memfd_for_each_populated_range(const HostMemoryBackendMemfd *m,
                               MemoryRegionSection *s,
                               void *arg,
                               memfd_section_cb cb)
{
    unsigned long first_zero_bit, last_zero_bit;
    int ret;

    first_zero_bit = find_first_zero_bit(m->discard_bitmap,
                                         m->discard_bitmap_size);
    while (first_zero_bit < m->discard_bitmap_size) {
        MemoryRegionSection tmp = *s;
        uint64_t offset, size;

        offset = first_zero_bit * MEMFD_MIN_DISCARD_SIZE;
        last_zero_bit = find_next_bit(m->discard_bitmap, m->discard_bitmap_size,
                                      first_zero_bit + 1) - 1;
        size = (last_zero_bit - first_zero_bit + 1) * MEMFD_MIN_DISCARD_SIZE;

        if (memfd_rdm_find_intersect(m, &tmp, offset, size)) {
            ret = cb(&tmp, arg);
            if (ret) {
                break;
            }
        }

        first_zero_bit = find_next_zero_bit(m->discard_bitmap,
                                            m->discard_bitmap_size,
                                            last_zero_bit + 2);
    }

    return false;
}

static int
memfd_for_each_discarded_range(const HostMemoryBackendMemfd *m,
                               MemoryRegionSection *s,
                               void *arg,
                               memfd_section_cb cb)
{
    unsigned long first_bit, last_bit;
    int ret;

    first_bit = find_first_bit(m->discard_bitmap, m->discard_bitmap_size);
    while (first_bit < m->discard_bitmap_size) {
        MemoryRegionSection tmp = *s;
        uint64_t offset, size;

        offset = first_bit * MEMFD_MIN_DISCARD_SIZE;
        last_bit = find_next_zero_bit(m->discard_bitmap, m->discard_bitmap_size,
                                      first_bit + 1) - 1;
        size = (last_bit - first_bit + 1) * MEMFD_MIN_DISCARD_SIZE;

        if (memfd_rdm_find_intersect(m, &tmp, offset, size)) {
            ret = cb(&tmp, arg);
            if (ret) {
                break;
            }
        }

        first_bit = find_next_bit(m->discard_bitmap,
                                  m->discard_bitmap_size, last_bit + 2);
    }

    return false;
}

typedef struct MemfdReplayData {
    void *fn;
    void *opaque;
} MemfdReplayData;

static int
memfd_rdm_replay_populated_cb(MemoryRegionSection *s, void *arg)
{
    MemfdReplayData *data = arg;

    return ((ReplayRamPopulate)data->fn)(s, data->opaque);
}

static int
memfd_rdm_replay_populated(const RamDiscardManager *rdm,
                           MemoryRegionSection *s,
                           ReplayRamPopulate replay_fn,
                           void *opaque)
{
    const HostMemoryBackendMemfd *m = MEMORY_BACKEND_MEMFD(rdm);
    struct MemfdReplayData data = {
        .fn = replay_fn,
        .opaque = opaque,
    };

    g_assert(s->mr == host_memory_backend_get_memory(MEMORY_BACKEND(m)));
    return memfd_for_each_populated_range(m, s, &data,
                                          memfd_rdm_replay_populated_cb);
}

static int
memfd_rdm_replay_discarded_cb(MemoryRegionSection *s, void *arg)
{
    MemfdReplayData *data = arg;

    return ((ReplayRamPopulate)data->fn)(s, data->opaque);
}

static void
memfd_rdm_replay_discarded(const RamDiscardManager *rdm,
                           MemoryRegionSection *s,
                           ReplayRamDiscard replay_fn,
                           void *opaque)
{
    const HostMemoryBackendMemfd *m = MEMORY_BACKEND_MEMFD(rdm);
    struct MemfdReplayData data = {
        .fn = replay_fn,
        .opaque = opaque,
    };

    g_assert(s->mr == host_memory_backend_get_memory(MEMORY_BACKEND(m)));
    memfd_for_each_discarded_range(m, s, &data,
                                   memfd_rdm_replay_discarded_cb);
}

static void
memfd_rdm_register_listener(RamDiscardManager *rdm,
                            RamDiscardListener *rdl,
                            MemoryRegionSection *s,
                            bool discard_shared)
{
    HostMemoryBackendMemfd *m = MEMORY_BACKEND_MEMFD(rdm);
    int ret;

    g_assert(s->mr == host_memory_backend_get_memory(MEMORY_BACKEND(m)));

    rdl->section = memory_region_section_new_copy(s);
    QLIST_INSERT_HEAD(&m->rdl_list, rdl, next);

    if (discard_shared) {
        ret = memfd_for_each_discarded_range(m, s, rdl, memfd_notify_discard_cb);
        m->discard_shared = true;
    } else {
        ret = memfd_for_each_populated_range(m, s, rdl, memfd_notify_populate_cb);
    }
    if (ret) {
        g_warning("failed to register RAM discard listener: %d", ret);
        return;
    }
}

static void
memfd_rdm_unregister_listener(RamDiscardManager *rdm, RamDiscardListener *rdl)
{
    HostMemoryBackendMemfd *m = MEMORY_BACKEND_MEMFD(rdm);
    int ret;

    g_assert(rdl->section->mr ==
             host_memory_backend_get_memory(MEMORY_BACKEND(m)));

    if (m->discard_shared) {
        ret = memfd_for_each_discarded_range(m, rdl->section, rdl,
                                             memfd_notify_populate_cb);
    } else {
        ret = memfd_for_each_populated_range(m, rdl->section, rdl,
                                             memfd_notify_discard_cb);
    }
    if (ret) {
        g_warning("failed to unregister RAM discard listener: %d", ret);
        return;
    }

    memory_region_section_free_copy(rdl->section);
    rdl->section = NULL;
    QLIST_REMOVE(rdl, next);
}

static int
memfd_discard(Object *backend, RAMBlock *rb, uint64_t offset, uint64_t size,
              bool shared_to_private)
{
    HostMemoryBackendMemfd *m = MEMORY_BACKEND_MEMFD(backend);
    RamDiscardListener *rdl, *rdl2;
    int ret = 0;

    assert((size % MEMFD_MIN_DISCARD_SIZE) == 0);

    QLIST_FOREACH(rdl, &m->rdl_list, next) {
        MemoryRegionSection tmp = *rdl->section;

        if (!memfd_rdm_find_intersect(m, &tmp, offset, size)) {
            continue;
        }

        if (shared_to_private) {
            ret = rdl->notify_discard(rdl, &tmp);
        } else {
            ret = rdl->notify_populate(rdl, &tmp);
        }

        if (ret) {
            break;
        }
    }

    if (!ret) {
        const unsigned long first_bit = offset / MEMFD_MIN_DISCARD_SIZE;
        const unsigned long nbits = size / MEMFD_MIN_DISCARD_SIZE;

        assert((first_bit + nbits) <= m->discard_bitmap_size);

        if (shared_to_private) {
            bitmap_set(m->discard_bitmap, first_bit, nbits);
        } else {
            bitmap_clear(m->discard_bitmap, first_bit, nbits);
        }

        return 0;
    }

    /* Something went wrong, roll back listener updates. */
    QLIST_FOREACH(rdl2, &m->rdl_list, next) {
        MemoryRegionSection tmp = *rdl2->section;

        if (rdl2 == rdl) {
            break;
        }

        if (!memfd_rdm_find_intersect(m, &tmp, offset, size)) {
            continue;
        }

        if (shared_to_private) {
            rdl2->notify_populate(rdl2, &tmp);
        } else {
            rdl2->notify_discard(rdl2, &tmp);
        }
    }

    return ret;
}

static void
memfd_backend_class_init(ObjectClass *oc, void *data)
{
    HostMemoryBackendClass *bc = MEMORY_BACKEND_CLASS(oc);
    HostMemoryBackendMemfdClass *mbc = MEMORY_BACKEND_MEMFD_CLASS(bc);
    RamDiscardManagerClass *rdmc = RAM_DISCARD_MANAGER_CLASS(mbc);

    bc->alloc = memfd_backend_memory_alloc;
    mbc->discard = memfd_discard;

    if (qemu_memfd_check(MFD_HUGETLB)) {
        object_class_property_add_bool(oc, "hugetlb",
                                       memfd_backend_get_hugetlb,
                                       memfd_backend_set_hugetlb);
        object_class_property_set_description(oc, "hugetlb",
                                              "Use huge pages");
        object_class_property_add(oc, "hugetlbsize", "int",
                                  memfd_backend_get_hugetlbsize,
                                  memfd_backend_set_hugetlbsize,
                                  NULL, NULL);
        object_class_property_set_description(oc, "hugetlbsize",
                                              "Huge pages size (ex: 2M, 1G)");
    }
    object_class_property_add_bool(oc, "seal",
                                   memfd_backend_get_seal,
                                   memfd_backend_set_seal);
    object_class_property_set_description(oc, "seal",
                                          "Seal growing & shrinking");

    rdmc->get_min_granularity = memfd_rdm_get_min_granularity;
    rdmc->is_populated = memfd_rdm_is_populated;
    rdmc->replay_populated = memfd_rdm_replay_populated;
    rdmc->replay_discarded = memfd_rdm_replay_discarded;
    rdmc->register_listener = memfd_rdm_register_listener;
    rdmc->unregister_listener = memfd_rdm_unregister_listener;
}

static const TypeInfo memfd_backend_info = {
    .name = TYPE_MEMORY_BACKEND_MEMFD,
    .parent = TYPE_MEMORY_BACKEND,
    .instance_init = memfd_backend_instance_init,
    .class_init = memfd_backend_class_init,
    .instance_size = sizeof(HostMemoryBackendMemfd),
    .interfaces = (InterfaceInfo[]) {
        { TYPE_RAM_DISCARD_MANAGER },
        { }
    },
};

static void register_types(void)
{
    if (qemu_memfd_check(MFD_ALLOW_SEALING)) {
        type_register_static(&memfd_backend_info);
    }
}

type_init(register_types);
