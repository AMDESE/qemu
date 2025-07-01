/*
 * QEMU Confidential Guest support
 *
 * Copyright Red Hat.
 *
 * Authors:
 *  David Gibson <david@gibson.dropbear.id.au>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * later.  See the COPYING file in the top-level directory.
 *
 */

#include "qemu/osdep.h"

#include "system/confidential-guest-support.h"

OBJECT_DEFINE_ABSTRACT_TYPE(ConfidentialGuestSupport,
                            confidential_guest_support,
                            CONFIDENTIAL_GUEST_SUPPORT,
                            OBJECT)

static bool
cgs_get_convert_in_place(Object *obj, Error **errp)
{
    return CONFIDENTIAL_GUEST_SUPPORT(obj)->convert_in_place;
}

static void
cgs_set_convert_in_place(Object *obj, bool value, Error **errp)
{
    CONFIDENTIAL_GUEST_SUPPORT(obj)->convert_in_place = value;
}

static void
cgs_get_gmem_allocator(Object *obj, Visitor *v, const char *name,
                       void *opaque, Error **errp)
{
    visit_type_GuestMemFdAllocator(v, name,
                                   &CONFIDENTIAL_GUEST_SUPPORT(obj)->gmem_allocator,
                                   errp);
}

static void
cgs_set_gmem_allocator(Object *obj, Visitor *v, const char *name,
                       void *opaque, Error **errp)
{
    visit_type_GuestMemFdAllocator(v, name,
                                   &CONFIDENTIAL_GUEST_SUPPORT(obj)->gmem_allocator,
                                   errp);
}

static void confidential_guest_support_class_init(ObjectClass *oc, void *data)
{
}

static void confidential_guest_support_init(Object *obj)
{
    ConfidentialGuestSupport *cgs = CONFIDENTIAL_GUEST_SUPPORT(obj);

    object_property_add_bool(obj, "convert-in-place", cgs_get_convert_in_place,
                             cgs_set_convert_in_place);
    object_property_add(obj, "gmem-allocator", "GuestMemFdAllocator",
                        cgs_get_gmem_allocator, cgs_set_gmem_allocator, NULL,
                        NULL);
    object_property_add_uint32_ptr(obj, "gmem-page-size", &cgs->gmem_page_size,
                                   OBJ_PROP_FLAG_READ | OBJ_PROP_FLAG_WRITE);

    cgs->convert_in_place = false;
    cgs->gmem_allocator = GUEST_MEM_FD_ALLOCATOR_NORMAL;
    cgs->gmem_page_size = qemu_real_host_page_size();
}

static void confidential_guest_support_finalize(Object *obj)
{
}
