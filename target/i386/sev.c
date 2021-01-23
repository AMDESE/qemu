/*
 * QEMU SEV support
 *
 * Copyright Advanced Micro Devices 2016-2018
 *
 * Author:
 *      Brijesh Singh <brijesh.singh@amd.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or later.
 * See the COPYING file in the top-level directory.
 *
 */

#include "qemu/osdep.h"

#include <linux/kvm.h>
#include <linux/psp-sev.h>

#include <sys/ioctl.h>

#include "qapi/error.h"
#include "qom/object_interfaces.h"
#include "qemu/base64.h"
#include "qemu/module.h"
#include "qemu/uuid.h"
#include "sysemu/kvm.h"
#include "sev_i386.h"
#include "sysemu/sysemu.h"
#include "sysemu/runstate.h"
#include "trace.h"
#include "migration/blocker.h"
#include "migration/qemu-file.h"
#include "migration/misc.h"
#include "qom/object.h"
#include "exec/address-spaces.h"
#include "monitor/monitor.h"
#include "hw/i386/pc.h"

#define TYPE_SEV_GUEST "sev-guest"
OBJECT_DECLARE_SIMPLE_TYPE(SevGuestState, SEV_GUEST)


/**
 * SevGuestState:
 *
 * The SevGuestState object is used for creating and managing a SEV
 * guest.
 *
 * # $QEMU \
 *         -object sev-guest,id=sev0 \
 *         -machine ...,memory-encryption=sev0
 */
struct SevGuestState {
    Object parent_obj;

    /* configuration parameters */
    char *sev_device;
    uint32_t policy;
    char *dh_cert_file;
    char *session_file;
    uint32_t cbitpos;
    uint32_t reduced_phys_bits;

    /* runtime state */
    uint32_t handle;
    uint8_t api_major;
    uint8_t api_minor;
    uint8_t build_id;
    uint64_t me_mask;
    int sev_fd;
    SevState state;
    gchar *measurement;
    guchar *remote_pdh;
    size_t remote_pdh_len;
    guchar *remote_plat_cert;
    size_t remote_plat_cert_len;
    guchar *amd_cert;
    size_t amd_cert_len;
    gchar *send_packet_hdr;
    size_t send_packet_hdr_len;
};

#define DEFAULT_GUEST_POLICY    0x1 /* disable debug */
#define DEFAULT_SEV_DEVICE      "/dev/sev"

#define SEV_INFO_BLOCK_GUID     "00f771de-1a7e-4fcb-890e-68c77e2fb44e"
typedef struct __attribute__((__packed__)) SevInfoBlock {
    /* SEV-ES Reset Vector Address */
    uint32_t reset_addr;
} SevInfoBlock;

static SevGuestState *sev_guest;

struct page_enc_status_array_entry {
	unsigned long gfn_start;
	unsigned long gfn_end;
};

static const char *const sev_fw_errlist[] = {
    "",
    "Platform state is invalid",
    "Guest state is invalid",
    "Platform configuration is invalid",
    "Buffer too small",
    "Platform is already owned",
    "Certificate is invalid",
    "Policy is not allowed",
    "Guest is not active",
    "Invalid address",
    "Bad signature",
    "Bad measurement",
    "Asid is already owned",
    "Invalid ASID",
    "WBINVD is required",
    "DF_FLUSH is required",
    "Guest handle is invalid",
    "Invalid command",
    "Guest is active",
    "Hardware error",
    "Hardware unsafe",
    "Feature not supported",
    "Invalid parameter"
};

#define SEV_FW_MAX_ERROR      ARRAY_SIZE(sev_fw_errlist)

#define SEV_FW_BLOB_MAX_SIZE            0x4000          /* 16KB */
#define UNENCRYPT_REGIONS_LIST_START    0x1
#define UNENCRYPT_REGIONS_LIST_END      0x2

static int
sev_ioctl(int fd, int cmd, void *data, int *error)
{
    int r;
    struct kvm_sev_cmd input;

    memset(&input, 0x0, sizeof(input));

    input.id = cmd;
    input.sev_fd = fd;
    input.data = (__u64)(unsigned long)data;

    r = kvm_vm_ioctl(kvm_state, KVM_MEMORY_ENCRYPT_OP, &input);

    if (error) {
        *error = input.error;
    }

    return r;
}

static int
sev_platform_ioctl(int fd, int cmd, void *data, int *error)
{
    int r;
    struct sev_issue_cmd arg;

    arg.cmd = cmd;
    arg.data = (unsigned long)data;
    r = ioctl(fd, SEV_ISSUE_CMD, &arg);
    if (error) {
        *error = arg.error;
    }

    return r;
}

static const char *
fw_error_to_str(int code)
{
    if (code < 0 || code >= SEV_FW_MAX_ERROR) {
        return "unknown error";
    }

    return sev_fw_errlist[code];
}

static bool
sev_check_state(const SevGuestState *sev, SevState state)
{
    assert(sev);
    return sev->state == state ? true : false;
}

static void
sev_set_guest_state(SevGuestState *sev, SevState new_state)
{
    assert(new_state < SEV_STATE__MAX);
    assert(sev);

    trace_kvm_sev_change_state(SevState_str(sev->state),
                               SevState_str(new_state));
    sev->state = new_state;
}

static void
sev_ram_block_added(RAMBlockNotifier *n, void *host, size_t size)
{
    int r;
    struct kvm_enc_region range;
    ram_addr_t offset;
    MemoryRegion *mr;

    /*
     * The RAM device presents a memory region that should be treated
     * as IO region and should not be pinned.
     */
    mr = memory_region_from_host(host, &offset);
    if (mr && memory_region_is_ram_device(mr)) {
        return;
    }

    range.addr = (__u64)(unsigned long)host;
    range.size = size;

    trace_kvm_memcrypt_register_region(host, size);
    r = kvm_vm_ioctl(kvm_state, KVM_MEMORY_ENCRYPT_REG_REGION, &range);
    if (r) {
        error_report("%s: failed to register region (%p+%#zx) error '%s'",
                     __func__, host, size, strerror(errno));
        exit(1);
    }
}

static void
sev_ram_block_removed(RAMBlockNotifier *n, void *host, size_t size)
{
    int r;
    struct kvm_enc_region range;
    ram_addr_t offset;
    MemoryRegion *mr;

    /*
     * The RAM device presents a memory region that should be treated
     * as IO region and should not have been pinned.
     */
    mr = memory_region_from_host(host, &offset);
    if (mr && memory_region_is_ram_device(mr)) {
        return;
    }

    range.addr = (__u64)(unsigned long)host;
    range.size = size;

    trace_kvm_memcrypt_unregister_region(host, size);
    r = kvm_vm_ioctl(kvm_state, KVM_MEMORY_ENCRYPT_UNREG_REGION, &range);
    if (r) {
        error_report("%s: failed to unregister region (%p+%#zx)",
                     __func__, host, size);
    }
}

static struct RAMBlockNotifier sev_ram_notifier = {
    .ram_block_added = sev_ram_block_added,
    .ram_block_removed = sev_ram_block_removed,
};

static void
sev_guest_finalize(Object *obj)
{
}

static char *
sev_guest_get_session_file(Object *obj, Error **errp)
{
    SevGuestState *s = SEV_GUEST(obj);

    return s->session_file ? g_strdup(s->session_file) : NULL;
}

static void
sev_guest_set_session_file(Object *obj, const char *value, Error **errp)
{
    SevGuestState *s = SEV_GUEST(obj);

    s->session_file = g_strdup(value);
}

static char *
sev_guest_get_dh_cert_file(Object *obj, Error **errp)
{
    SevGuestState *s = SEV_GUEST(obj);

    return g_strdup(s->dh_cert_file);
}

static void
sev_guest_set_dh_cert_file(Object *obj, const char *value, Error **errp)
{
    SevGuestState *s = SEV_GUEST(obj);

    s->dh_cert_file = g_strdup(value);
}

static char *
sev_guest_get_sev_device(Object *obj, Error **errp)
{
    SevGuestState *sev = SEV_GUEST(obj);

    return g_strdup(sev->sev_device);
}

static void
sev_guest_set_sev_device(Object *obj, const char *value, Error **errp)
{
    SevGuestState *sev = SEV_GUEST(obj);

    sev->sev_device = g_strdup(value);
}

static void
sev_guest_class_init(ObjectClass *oc, void *data)
{
    object_class_property_add_str(oc, "sev-device",
                                  sev_guest_get_sev_device,
                                  sev_guest_set_sev_device);
    object_class_property_set_description(oc, "sev-device",
            "SEV device to use");
    object_class_property_add_str(oc, "dh-cert-file",
                                  sev_guest_get_dh_cert_file,
                                  sev_guest_set_dh_cert_file);
    object_class_property_set_description(oc, "dh-cert-file",
            "guest owners DH certificate (encoded with base64)");
    object_class_property_add_str(oc, "session-file",
                                  sev_guest_get_session_file,
                                  sev_guest_set_session_file);
    object_class_property_set_description(oc, "session-file",
            "guest owners session parameters (encoded with base64)");
}

static void
sev_guest_instance_init(Object *obj)
{
    SevGuestState *sev = SEV_GUEST(obj);

    sev->sev_device = g_strdup(DEFAULT_SEV_DEVICE);
    sev->policy = DEFAULT_GUEST_POLICY;
    object_property_add_uint32_ptr(obj, "policy", &sev->policy,
                                   OBJ_PROP_FLAG_READWRITE);
    object_property_add_uint32_ptr(obj, "handle", &sev->handle,
                                   OBJ_PROP_FLAG_READWRITE);
    object_property_add_uint32_ptr(obj, "cbitpos", &sev->cbitpos,
                                   OBJ_PROP_FLAG_READWRITE);
    object_property_add_uint32_ptr(obj, "reduced-phys-bits",
                                   &sev->reduced_phys_bits,
                                   OBJ_PROP_FLAG_READWRITE);
}

/* sev guest info */
static const TypeInfo sev_guest_info = {
    .parent = TYPE_OBJECT,
    .name = TYPE_SEV_GUEST,
    .instance_size = sizeof(SevGuestState),
    .instance_finalize = sev_guest_finalize,
    .class_init = sev_guest_class_init,
    .instance_init = sev_guest_instance_init,
    .interfaces = (InterfaceInfo[]) {
        { TYPE_USER_CREATABLE },
        { }
    }
};

static SevGuestState *
lookup_sev_guest_info(const char *id)
{
    Object *obj;
    SevGuestState *info;

    obj = object_resolve_path_component(object_get_objects_root(), id);
    if (!obj) {
        return NULL;
    }

    info = (SevGuestState *)
            object_dynamic_cast(obj, TYPE_SEV_GUEST);
    if (!info) {
        return NULL;
    }

    return info;
}

bool
sev_enabled(void)
{
    return !!sev_guest;
}

bool
sev_es_enabled(void)
{
    return sev_enabled() && (sev_guest->policy & SEV_POLICY_ES);
}

uint64_t
sev_get_me_mask(void)
{
    return sev_guest ? sev_guest->me_mask : ~0;
}

uint32_t
sev_get_cbit_position(void)
{
    return sev_guest ? sev_guest->cbitpos : 0;
}

uint32_t
sev_get_reduced_phys_bits(void)
{
    return sev_guest ? sev_guest->reduced_phys_bits : 0;
}

SevInfo *
sev_get_info(void)
{
    SevInfo *info;

    info = g_new0(SevInfo, 1);
    info->enabled = sev_enabled();

    if (info->enabled) {
        info->api_major = sev_guest->api_major;
        info->api_minor = sev_guest->api_minor;
        info->build_id = sev_guest->build_id;
        info->policy = sev_guest->policy;
        info->state = sev_guest->state;
        info->handle = sev_guest->handle;
    }

    return info;
}

static int
sev_get_pdh_info(int fd, guchar **pdh, size_t *pdh_len, guchar **cert_chain,
                 size_t *cert_chain_len, Error **errp)
{
    guchar *pdh_data = NULL;
    guchar *cert_chain_data = NULL;
    struct sev_user_data_pdh_cert_export export = {};
    int err, r;

    /* query the certificate length */
    r = sev_platform_ioctl(fd, SEV_PDH_CERT_EXPORT, &export, &err);
    if (r < 0) {
        if (err != SEV_RET_INVALID_LEN) {
            error_setg(errp, "failed to export PDH cert ret=%d fw_err=%d (%s)",
                       r, err, fw_error_to_str(err));
            return 1;
        }
    }

    pdh_data = g_new(guchar, export.pdh_cert_len);
    cert_chain_data = g_new(guchar, export.cert_chain_len);
    export.pdh_cert_address = (unsigned long)pdh_data;
    export.cert_chain_address = (unsigned long)cert_chain_data;

    r = sev_platform_ioctl(fd, SEV_PDH_CERT_EXPORT, &export, &err);
    if (r < 0) {
        error_setg(errp, "failed to export PDH cert ret=%d fw_err=%d (%s)",
                   r, err, fw_error_to_str(err));
        goto e_free;
    }

    *pdh = pdh_data;
    *pdh_len = export.pdh_cert_len;
    *cert_chain = cert_chain_data;
    *cert_chain_len = export.cert_chain_len;
    return 0;

e_free:
    g_free(pdh_data);
    g_free(cert_chain_data);
    return 1;
}

SevCapability *
sev_get_capabilities(Error **errp)
{
    SevCapability *cap = NULL;
    guchar *pdh_data = NULL;
    guchar *cert_chain_data = NULL;
    size_t pdh_len = 0, cert_chain_len = 0;
    uint32_t ebx;
    int fd;

    if (!kvm_enabled()) {
        error_setg(errp, "KVM not enabled");
        return NULL;
    }
    if (kvm_vm_ioctl(kvm_state, KVM_MEMORY_ENCRYPT_OP, NULL) < 0) {
        error_setg(errp, "SEV is not enabled in KVM");
        return NULL;
    }

    fd = open(DEFAULT_SEV_DEVICE, O_RDWR);
    if (fd < 0) {
        error_setg_errno(errp, errno, "Failed to open %s",
                         DEFAULT_SEV_DEVICE);
        return NULL;
    }

    if (sev_get_pdh_info(fd, &pdh_data, &pdh_len,
                         &cert_chain_data, &cert_chain_len, errp)) {
        goto out;
    }

    cap = g_new0(SevCapability, 1);
    cap->pdh = g_base64_encode(pdh_data, pdh_len);
    cap->cert_chain = g_base64_encode(cert_chain_data, cert_chain_len);

    host_cpuid(0x8000001F, 0, NULL, &ebx, NULL, NULL);
    cap->cbitpos = ebx & 0x3f;

    /*
     * When SEV feature is enabled, we loose one bit in guest physical
     * addressing.
     */
    cap->reduced_phys_bits = 1;

out:
    g_free(pdh_data);
    g_free(cert_chain_data);
    close(fd);
    return cap;
}

static int
sev_read_file_base64(const char *filename, guchar **data, gsize *len)
{
    gsize sz;
    gchar *base64;
    GError *error = NULL;

    if (!g_file_get_contents(filename, &base64, &sz, &error)) {
        error_report("failed to read '%s' (%s)", filename, error->message);
        g_error_free(error);
        return -1;
    }

    *data = g_base64_decode(base64, len);
    return 0;
}

static int
sev_launch_start(SevGuestState *sev)
{
    gsize sz;
    int ret = 1;
    int fw_error, rc;
    struct kvm_sev_launch_start *start;
    guchar *session = NULL, *dh_cert = NULL;

    start = g_new0(struct kvm_sev_launch_start, 1);

    start->handle = sev->handle;
    start->policy = sev->policy;
    if (sev->session_file) {
        if (sev_read_file_base64(sev->session_file, &session, &sz) < 0) {
            goto out;
        }
        start->session_uaddr = (unsigned long)session;
        start->session_len = sz;
    }

    if (sev->dh_cert_file) {
        if (sev_read_file_base64(sev->dh_cert_file, &dh_cert, &sz) < 0) {
            goto out;
        }
        start->dh_uaddr = (unsigned long)dh_cert;
        start->dh_len = sz;
    }

    trace_kvm_sev_launch_start(start->policy, session, dh_cert);
    rc = sev_ioctl(sev->sev_fd, KVM_SEV_LAUNCH_START, start, &fw_error);
    if (rc < 0) {
        error_report("%s: LAUNCH_START ret=%d fw_error=%d '%s'",
                __func__, ret, fw_error, fw_error_to_str(fw_error));
        goto out;
    }

    sev_set_guest_state(sev, SEV_STATE_LAUNCH_UPDATE);
    sev->handle = start->handle;
    ret = 0;

out:
    g_free(start);
    g_free(session);
    g_free(dh_cert);
    return ret;
}

static int
sev_launch_update_data(SevGuestState *sev, uint8_t *addr, uint64_t len)
{
    int ret, fw_error;
    struct kvm_sev_launch_update_data update;

    if (!addr || !len) {
        return 1;
    }

    update.uaddr = (__u64)(unsigned long)addr;
    update.len = len;
    trace_kvm_sev_launch_update_data(addr, len);
    ret = sev_ioctl(sev->sev_fd, KVM_SEV_LAUNCH_UPDATE_DATA,
                    &update, &fw_error);
    if (ret) {
        error_report("%s: LAUNCH_UPDATE ret=%d fw_error=%d '%s'",
                __func__, ret, fw_error, fw_error_to_str(fw_error));
    }

    return ret;
}

static int
sev_launch_update_vmsa(SevGuestState *sev)
{
    int ret, fw_error;

    ret = sev_ioctl(sev->sev_fd, KVM_SEV_LAUNCH_UPDATE_VMSA, NULL, &fw_error);
    if (ret) {
        error_report("%s: LAUNCH_UPDATE_VMSA ret=%d fw_error=%d '%s'",
                __func__, ret, fw_error, fw_error_to_str(fw_error));
    }

    return ret;
}

static void
sev_launch_get_measure(Notifier *notifier, void *unused)
{
    SevGuestState *sev = sev_guest;
    int ret, error;
    guchar *data;
    struct kvm_sev_launch_measure *measurement;

    if (!sev_check_state(sev, SEV_STATE_LAUNCH_UPDATE)) {
        return;
    }

    if (sev_es_enabled()) {
        /* measure all the VM save areas before getting launch_measure */
        ret = sev_launch_update_vmsa(sev);
        if (ret) {
            exit(1);
        }
    }

    measurement = g_new0(struct kvm_sev_launch_measure, 1);

    /* query the measurement blob length */
    ret = sev_ioctl(sev->sev_fd, KVM_SEV_LAUNCH_MEASURE,
                    measurement, &error);
    if (!measurement->len) {
        error_report("%s: LAUNCH_MEASURE ret=%d fw_error=%d '%s'",
                     __func__, ret, error, fw_error_to_str(errno));
        goto free_measurement;
    }

    data = g_new0(guchar, measurement->len);
    measurement->uaddr = (unsigned long)data;

    /* get the measurement blob */
    ret = sev_ioctl(sev->sev_fd, KVM_SEV_LAUNCH_MEASURE,
                    measurement, &error);
    if (ret) {
        error_report("%s: LAUNCH_MEASURE ret=%d fw_error=%d '%s'",
                     __func__, ret, error, fw_error_to_str(errno));
        goto free_data;
    }

    sev_set_guest_state(sev, SEV_STATE_LAUNCH_SECRET);

    /* encode the measurement value and emit the event */
    sev->measurement = g_base64_encode(data, measurement->len);
    trace_kvm_sev_launch_measurement(sev->measurement);

free_data:
    g_free(data);
free_measurement:
    g_free(measurement);
}

char *
sev_get_launch_measurement(void)
{
    if (sev_guest &&
        sev_guest->state >= SEV_STATE_LAUNCH_SECRET) {
        return g_strdup(sev_guest->measurement);
    }

    return NULL;
}

static Notifier sev_machine_done_notify = {
    .notify = sev_launch_get_measure,
};

static void
sev_launch_finish(SevGuestState *sev)
{
    int ret, error;

    trace_kvm_sev_launch_finish();
    ret = sev_ioctl(sev->sev_fd, KVM_SEV_LAUNCH_FINISH, 0, &error);
    if (ret) {
        error_report("%s: LAUNCH_FINISH ret=%d fw_error=%d '%s'",
                     __func__, ret, error, fw_error_to_str(error));
        exit(1);
    }

    sev_set_guest_state(sev, SEV_STATE_RUNNING);
}

static int
sev_receive_finish(SevGuestState *s)
{
    int error, ret = 1;

    trace_kvm_sev_receive_finish();
    ret = sev_ioctl(s->sev_fd, KVM_SEV_RECEIVE_FINISH, 0, &error);
    if (ret) {
        error_report("%s: RECEIVE_FINISH ret=%d fw_error=%d '%s'",
                __func__, ret, error, fw_error_to_str(error));
        goto err;
    }

    sev_set_guest_state(s, SEV_STATE_RUNNING);
err:
    return ret;
}

static void
sev_vm_state_change(void *opaque, int running, RunState state)
{
    SevGuestState *sev = opaque;

    if (running) {
        if (sev_check_state(sev, SEV_STATE_RECEIVE_UPDATE)) {
            sev_receive_finish(sev);
        } else if (!sev_check_state(sev, SEV_STATE_RUNNING)) {
            sev_launch_finish(sev);
        }
    }
}

static inline bool check_blob_length(size_t value)
{
    if (value > SEV_FW_BLOB_MAX_SIZE) {
        error_report("invalid length max=%d got=%ld",
                     SEV_FW_BLOB_MAX_SIZE, value);
        return false;
    }

    return true;
}

int sev_save_setup(void *handle, const char *pdh, const char *plat_cert,
                   const char *amd_cert)
{
    SevGuestState *s = handle;

    s->remote_pdh = g_base64_decode(pdh, &s->remote_pdh_len);
    if (!check_blob_length(s->remote_pdh_len)) {
        goto error;
    }

    s->remote_plat_cert = g_base64_decode(plat_cert,
                                          &s->remote_plat_cert_len);
    if (!check_blob_length(s->remote_plat_cert_len)) {
        goto error;
    }

    s->amd_cert = g_base64_decode(amd_cert, &s->amd_cert_len);
    if (!check_blob_length(s->amd_cert_len)) {
        goto error;
    }

    return 0;

error:
    g_free(s->remote_pdh);
    g_free(s->remote_plat_cert);
    g_free(s->amd_cert);

    return 1;
}

static void
sev_send_finish(void)
{
    int ret, error;

    trace_kvm_sev_send_finish();
    ret = sev_ioctl(sev_guest->sev_fd, KVM_SEV_SEND_FINISH, 0, &error);
    if (ret) {
        error_report("%s: SEND_FINISH ret=%d fw_error=%d '%s'",
                     __func__, ret, error, fw_error_to_str(error));
    }

    g_free(sev_guest->send_packet_hdr);
    sev_set_guest_state(sev_guest, SEV_STATE_RUNNING);
}

static void
sev_migration_state_notifier(Notifier *notifier, void *data)
{
    MigrationState *s = data;

    if (migration_has_finished(s) ||
        migration_in_postcopy_after_devices(s) ||
        migration_has_failed(s)) {
        if (sev_check_state(sev_guest, SEV_STATE_SEND_UPDATE)) {
            sev_send_finish();
        }
    }
}

static Notifier sev_migration_state_notify = {
    .notify = sev_migration_state_notifier,
};

void *
sev_guest_init(const char *id)
{
    SevGuestState *sev;
    char *devname;
    int ret, fw_error, cmd;
    uint32_t ebx;
    uint32_t host_cbitpos;
    struct sev_user_data_status status = {};

    ret = ram_block_discard_disable(true);
    if (ret) {
        error_report("%s: cannot disable RAM discard", __func__);
        return NULL;
    }

    sev = lookup_sev_guest_info(id);
    if (!sev) {
        error_report("%s: '%s' is not a valid '%s' object",
                     __func__, id, TYPE_SEV_GUEST);
        goto err;
    }

    sev_guest = sev;
    sev->state = SEV_STATE_UNINIT;

    host_cpuid(0x8000001F, 0, NULL, &ebx, NULL, NULL);
    host_cbitpos = ebx & 0x3f;

    if (host_cbitpos != sev->cbitpos) {
        error_report("%s: cbitpos check failed, host '%d' requested '%d'",
                     __func__, host_cbitpos, sev->cbitpos);
        goto err;
    }

    if (sev->reduced_phys_bits < 1) {
        error_report("%s: reduced_phys_bits check failed, it should be >=1,"
                     " requested '%d'", __func__, sev->reduced_phys_bits);
        goto err;
    }

    sev->me_mask = ~(1UL << sev->cbitpos);

    devname = object_property_get_str(OBJECT(sev), "sev-device", NULL);
    sev->sev_fd = open(devname, O_RDWR);
    if (sev->sev_fd < 0) {
        error_report("%s: Failed to open %s '%s'", __func__,
                     devname, strerror(errno));
    }
    g_free(devname);
    if (sev->sev_fd < 0) {
        goto err;
    }

    ret = sev_platform_ioctl(sev->sev_fd, SEV_PLATFORM_STATUS, &status,
                             &fw_error);
    if (ret) {
        error_report("%s: failed to get platform status ret=%d "
                     "fw_error='%d: %s'", __func__, ret, fw_error,
                     fw_error_to_str(fw_error));
        goto err;
    }
    sev->build_id = status.build;
    sev->api_major = status.api_major;
    sev->api_minor = status.api_minor;

    if (sev_es_enabled()) {
        if (!kvm_kernel_irqchip_allowed()) {
            error_report("%s: SEV-ES guests require in-kernel irqchip support",
                         __func__);
            goto err;
        }

        if (!(status.flags & SEV_STATUS_FLAGS_CONFIG_ES)) {
            error_report("%s: guest policy requires SEV-ES, but "
                         "host SEV-ES support unavailable",
                         __func__);
            goto err;
        }
        cmd = KVM_SEV_ES_INIT;
    } else {
        cmd = KVM_SEV_INIT;
    }

    trace_kvm_sev_init();
    ret = sev_ioctl(sev->sev_fd, cmd, NULL, &fw_error);
    if (ret) {
        error_report("%s: failed to initialize ret=%d fw_error=%d '%s'",
                     __func__, ret, fw_error, fw_error_to_str(fw_error));
        goto err;
    }

    ret = sev_launch_start(sev);
    if (ret) {
        error_report("%s: failed to create encryption context", __func__);
        goto err;
    }

    /*
     * The LAUNCH context is used for new guest, if its an incoming guest
     * then RECEIVE context will be created after the connection is established.
     */
    if (!runstate_check(RUN_STATE_INMIGRATE)) {
        ret = sev_launch_start(sev);
        if (ret) {
            error_report("%s: failed to create encryption context", __func__);
            goto err;
        }
    }
    ram_block_notifier_add(&sev_ram_notifier);
    qemu_add_machine_init_done_notifier(&sev_machine_done_notify);
    qemu_add_vm_change_state_handler(sev_vm_state_change, sev);
    add_migration_state_change_notifier(&sev_migration_state_notify);

    return sev;
err:
    sev_guest = NULL;
    ram_block_discard_disable(false);
    return NULL;
}

int
sev_encrypt_data(void *handle, uint8_t *ptr, uint64_t len)
{
    SevGuestState *sev = handle;

    assert(sev);

    /* if SEV is in update state then encrypt the data else do nothing */
    if (sev_check_state(sev, SEV_STATE_LAUNCH_UPDATE)) {
        return sev_launch_update_data(sev, ptr, len);
    }

    return 0;
}

int sev_inject_launch_secret(const char *packet_hdr, const char *secret,
                             uint64_t gpa, Error **errp)
{
    struct kvm_sev_launch_secret input;
    g_autofree guchar *data = NULL, *hdr = NULL;
    int error, ret = 1;
    void *hva;
    gsize hdr_sz = 0, data_sz = 0;
    MemoryRegion *mr = NULL;

    if (!sev_guest) {
        error_setg(errp, "SEV: SEV not enabled.");
        return 1;
    }

    /* secret can be injected only in this state */
    if (!sev_check_state(sev_guest, SEV_STATE_LAUNCH_SECRET)) {
        error_setg(errp, "SEV: Not in correct state. (LSECRET) %x",
                     sev_guest->state);
        return 1;
    }

    hdr = g_base64_decode(packet_hdr, &hdr_sz);
    if (!hdr || !hdr_sz) {
        error_setg(errp, "SEV: Failed to decode sequence header");
        return 1;
    }

    data = g_base64_decode(secret, &data_sz);
    if (!data || !data_sz) {
        error_setg(errp, "SEV: Failed to decode data");
        return 1;
    }

    hva = gpa2hva(&mr, gpa, data_sz, errp);
    if (!hva) {
        error_prepend(errp, "SEV: Failed to calculate guest address: ");
        return 1;
    }

    input.hdr_uaddr = (uint64_t)(unsigned long)hdr;
    input.hdr_len = hdr_sz;

    input.trans_uaddr = (uint64_t)(unsigned long)data;
    input.trans_len = data_sz;

    input.guest_uaddr = (uint64_t)(unsigned long)hva;
    input.guest_len = data_sz;

    trace_kvm_sev_launch_secret(gpa, input.guest_uaddr,
                                input.trans_uaddr, input.trans_len);

    ret = sev_ioctl(sev_guest->sev_fd, KVM_SEV_LAUNCH_SECRET,
                    &input, &error);
    if (ret) {
        error_setg(errp, "SEV: failed to inject secret ret=%d fw_error=%d '%s'",
                     ret, error, fw_error_to_str(error));
        return ret;
    }

    return 0;
}

static int
sev_es_parse_reset_block(SevInfoBlock *info, uint32_t *addr)
{
    if (!info->reset_addr) {
        error_report("SEV-ES reset address is zero");
        return 1;
    }

    *addr = info->reset_addr;

    return 0;
}

int
sev_es_save_reset_vector(void *handle, void *flash_ptr, uint64_t flash_size,
                         uint32_t *addr)
{
    QemuUUID info_guid, *guid;
    SevInfoBlock *info;
    uint8_t *data;
    uint16_t *len;

    assert(handle);

    /*
     * Initialize the address to zero. An address of zero with a successful
     * return code indicates that SEV-ES is not active.
     */
    *addr = 0;
    if (!sev_es_enabled()) {
        return 0;
    }

    /*
     * Extract the AP reset vector for SEV-ES guests by locating the SEV GUID.
     * The SEV GUID is located on its own (original implementation) or within
     * the Firmware GUID Table (new implementation), either of which are
     * located 32 bytes from the end of the flash.
     *
     * Check the Firmware GUID Table first.
     */
    if (pc_system_ovmf_table_find(SEV_INFO_BLOCK_GUID, &data, NULL)) {
        return sev_es_parse_reset_block((SevInfoBlock *)data, addr);
    }

    /*
     * SEV info block not found in the Firmware GUID Table (or there isn't
     * a Firmware GUID Table, fall back to the original implementation.
     */
    data = flash_ptr + flash_size - 0x20;

    qemu_uuid_parse(SEV_INFO_BLOCK_GUID, &info_guid);
    info_guid = qemu_uuid_bswap(info_guid); /* GUIDs are LE */

    guid = (QemuUUID *)(data - sizeof(info_guid));
    if (!qemu_uuid_is_equal(guid, &info_guid)) {
        error_report("SEV information block/Firmware GUID Table block not found in pflash rom");
        return 1;
    }

    len = (uint16_t *)((uint8_t *)guid - sizeof(*len));
    info = (SevInfoBlock *)(data - le16_to_cpu(*len));

    return sev_es_parse_reset_block(info, addr);
}

static int
sev_get_send_session_length(void)
{
    int ret, fw_err = 0;
    struct kvm_sev_send_start start = {};

    ret = sev_ioctl(sev_guest->sev_fd, KVM_SEV_SEND_START, &start, &fw_err);
    if (fw_err != SEV_RET_INVALID_LEN) {
        ret = -1;
        error_report("%s: failed to get session length ret=%d fw_error=%d '%s'",
                     __func__, ret, fw_err, fw_error_to_str(fw_err));
        goto err;
    }

    ret = start.session_len;
err:
    return ret;
}

static int
sev_send_start(SevGuestState *s, QEMUFile *f, uint64_t *bytes_sent, Error **errp)
{
    gsize pdh_len = 0, plat_cert_len;
    int session_len, ret, fw_error;
    struct kvm_sev_send_start start = { };
    guchar *pdh = NULL, *plat_cert = NULL, *session = NULL;

    if (!s->remote_pdh || !s->remote_plat_cert || !s->amd_cert_len) {
        error_report("%s: missing remote PDH or PLAT_CERT", __func__);
        return 1;
    }

    start.pdh_cert_uaddr = (uintptr_t) s->remote_pdh;
    start.pdh_cert_len = s->remote_pdh_len;

    start.plat_cert_uaddr = (uintptr_t)s->remote_plat_cert;
    start.plat_cert_len = s->remote_plat_cert_len;

    start.amd_cert_uaddr = (uintptr_t)s->amd_cert;
    start.amd_cert_len = s->amd_cert_len;

    /* get the session length */
    session_len = sev_get_send_session_length();
    if (session_len < 0) {
        ret = 1;
        goto err;
    }

    session = g_new0(guchar, session_len);
    start.session_uaddr = (unsigned long)session;
    start.session_len = session_len;

    /* Get our PDH certificate */
    ret = sev_get_pdh_info(s->sev_fd, &pdh, &pdh_len,
                           &plat_cert, &plat_cert_len, errp);
    if (ret) {
        error_report("Failed to get our PDH cert");
        goto err;
    }

    trace_kvm_sev_send_start(start.pdh_cert_uaddr, start.pdh_cert_len,
                             start.plat_cert_uaddr, start.plat_cert_len,
                             start.amd_cert_uaddr, start.amd_cert_len);

    ret = sev_ioctl(s->sev_fd, KVM_SEV_SEND_START, &start, &fw_error);
    if (ret < 0) {
        error_report("%s: SEND_START ret=%d fw_error=%d '%s'",
                __func__, ret, fw_error, fw_error_to_str(fw_error));
        goto err;
    }

    qemu_put_be32(f, start.policy);
    qemu_put_be32(f, pdh_len);
    qemu_put_buffer(f, (uint8_t *)pdh, pdh_len);
    qemu_put_be32(f, start.session_len);
    qemu_put_buffer(f, (uint8_t *)start.session_uaddr, start.session_len);
    *bytes_sent = 12 + pdh_len + start.session_len;

    sev_set_guest_state(s, SEV_STATE_SEND_UPDATE);

err:
    g_free(pdh);
    g_free(plat_cert);
    return ret;
}

static int
sev_send_get_packet_len(int *fw_err)
{
    int ret;
    struct kvm_sev_send_update_data update = {};

    ret = sev_ioctl(sev_guest->sev_fd, KVM_SEV_SEND_UPDATE_DATA,
                    &update, fw_err);
    if (*fw_err != SEV_RET_INVALID_LEN) {
        ret = -1;
        error_report("%s: failed to get session length ret=%d fw_error=%d '%s'",
                    __func__, ret, *fw_err, fw_error_to_str(*fw_err));
        goto err;
    }

    ret = update.hdr_len;

err:
    return ret;
}

static int
sev_send_update_data(SevGuestState *s, QEMUFile *f, uint8_t *ptr, uint32_t size,
                     uint64_t *bytes_sent)
{
    int ret, fw_error;
    guchar *trans;
    struct kvm_sev_send_update_data update = { };

    /*
     * If this is first call then query the packet header bytes and allocate
     * the packet buffer.
     */
    if (!s->send_packet_hdr) {
        s->send_packet_hdr_len = sev_send_get_packet_len(&fw_error);
        if (s->send_packet_hdr_len < 1) {
            error_report("%s: SEND_UPDATE fw_error=%d '%s'",
                    __func__, fw_error, fw_error_to_str(fw_error));
            return 1;
        }

        s->send_packet_hdr = g_new(gchar, s->send_packet_hdr_len);
    }

    /* allocate transport buffer */
    trans = g_new(guchar, size);

    update.hdr_uaddr = (uintptr_t)s->send_packet_hdr;
    update.hdr_len = s->send_packet_hdr_len;
    update.guest_uaddr = (uintptr_t)ptr;
    update.guest_len = size;
    update.trans_uaddr = (uintptr_t)trans;
    update.trans_len = size;

    trace_kvm_sev_send_update_data(ptr, trans, size);

    ret = sev_ioctl(s->sev_fd, KVM_SEV_SEND_UPDATE_DATA, &update, &fw_error);
    if (ret) {
        error_report("%s: SEND_UPDATE_DATA ret=%d fw_error=%d '%s'",
                __func__, ret, fw_error, fw_error_to_str(fw_error));
        goto err;
    }

    qemu_put_be32(f, update.hdr_len);
    qemu_put_buffer(f, (uint8_t *)update.hdr_uaddr, update.hdr_len);
    *bytes_sent = 4 + update.hdr_len;

    qemu_put_be32(f, update.trans_len);
    qemu_put_buffer(f, (uint8_t *)update.trans_uaddr, update.trans_len);
    *bytes_sent += (4 + update.trans_len);

err:
    g_free(trans);
    return ret;
}

int sev_save_outgoing_page(void *handle, QEMUFile *f, uint8_t *ptr,
                           uint32_t sz, uint64_t *bytes_sent, Error **errp)
{
    SevGuestState *s = sev_guest;

    /*
     * If this is a first buffer then create outgoing encryption context
     * and write our PDH, policy and session data.
     */
    if (!sev_check_state(s, SEV_STATE_SEND_UPDATE) &&
        sev_send_start(s, f, bytes_sent, errp)) {
        error_report("Failed to create outgoing context");
        return 1;
    }

    return sev_send_update_data(s, f, ptr, sz, bytes_sent);
}

static int
sev_receive_start(SevGuestState *sev, QEMUFile *f)
{
    int ret = 1;
    int fw_error;
    struct kvm_sev_receive_start start = { };
    gchar *session = NULL, *pdh_cert = NULL;

    /* get SEV guest handle */
    start.handle = object_property_get_int(OBJECT(sev), "handle",
                                           &error_abort);

    /* get the source policy */
    start.policy = qemu_get_be32(f);

    /* get source PDH key */
    start.pdh_len = qemu_get_be32(f);
    if (!check_blob_length(start.pdh_len)) {
        return 1;
    }

    pdh_cert = g_new(gchar, start.pdh_len);
    qemu_get_buffer(f, (uint8_t *)pdh_cert, start.pdh_len);
    start.pdh_uaddr = (uintptr_t)pdh_cert;

    /* get source session data */
    start.session_len = qemu_get_be32(f);
    if (!check_blob_length(start.session_len)) {
        return 1;
    }
    session = g_new(gchar, start.session_len);
    qemu_get_buffer(f, (uint8_t *)session, start.session_len);
    start.session_uaddr = (uintptr_t)session;

    trace_kvm_sev_receive_start(start.policy, session, pdh_cert);

    ret = sev_ioctl(sev_guest->sev_fd, KVM_SEV_RECEIVE_START,
                    &start, &fw_error);
    if (ret < 0) {
        error_report("Error RECEIVE_START ret=%d fw_error=%d '%s'",
                ret, fw_error, fw_error_to_str(fw_error));
        goto err;
    }

    object_property_set_int(OBJECT(sev), "handle", start.handle, &error_abort);
    sev_set_guest_state(sev, SEV_STATE_RECEIVE_UPDATE);
err:
    g_free(session);
    g_free(pdh_cert);

    return ret;
}

static int sev_receive_update_data(QEMUFile *f, uint8_t *ptr)
{
    int ret = 1, fw_error = 0;
    gchar *hdr = NULL, *trans = NULL;
    struct kvm_sev_receive_update_data update = {};

    /* get packet header */
    update.hdr_len = qemu_get_be32(f);
    if (!check_blob_length(update.hdr_len)) {
        return 1;
    }

    hdr = g_new(gchar, update.hdr_len);
    qemu_get_buffer(f, (uint8_t *)hdr, update.hdr_len);
    update.hdr_uaddr = (uintptr_t)hdr;

    /* get transport buffer */
    update.trans_len = qemu_get_be32(f);
    if (!check_blob_length(update.trans_len)) {
        goto err;
    }

    trans = g_new(gchar, update.trans_len);
    update.trans_uaddr = (uintptr_t)trans;
    qemu_get_buffer(f, (uint8_t *)update.trans_uaddr, update.trans_len);

    update.guest_uaddr = (uintptr_t) ptr;
    update.guest_len = update.trans_len;

    trace_kvm_sev_receive_update_data(trans, ptr, update.guest_len,
            hdr, update.hdr_len);

    ret = sev_ioctl(sev_guest->sev_fd, KVM_SEV_RECEIVE_UPDATE_DATA,
                    &update, &fw_error);
    if (ret) {
        error_report("Error RECEIVE_UPDATE_DATA ret=%d fw_error=%d '%s'",
                ret, fw_error, fw_error_to_str(fw_error));
        goto err;
    }
err:
    g_free(trans);
    g_free(hdr);
    return ret;
}

int sev_load_incoming_page(void *handle, QEMUFile *f, uint8_t *ptr)
{
    SevGuestState *s = handle;

    /*
     * If this is first buffer and SEV is not in recieiving state then
     * use RECEIVE_START command to create a encryption context.
     */
    if (!sev_check_state(s, SEV_STATE_RECEIVE_UPDATE) &&
        sev_receive_start(s, f)) {
        return 1;
    }

    return sev_receive_update_data(f, ptr);
}

int sev_load_incoming_unencrypt_regions_list(void *handle, QEMUFile *f)
{
    void *buffer;
    struct kvm_page_enc_list e = {};
    uint32_t size;
    int nents, status;

    status = qemu_get_be32(f);

    if (status != UNENCRYPT_REGIONS_LIST_START) {
        nents = qemu_get_be32(f);
        size = nents * sizeof(struct page_enc_status_array_entry);

        buffer = g_malloc0(size);
        qemu_get_buffer(f, (uint8_t *)buffer, size);

        e.pnents = &nents;
        e.size = size;
        e.buffer = buffer;
        if (kvm_vm_ioctl(kvm_state, KVM_SET_PAGE_ENC_LIST, &e) == -1) {
            error_report("KVM_SET_PAGE_ENC_BITMAP ioctl failed %d", errno);
            g_free(buffer);
            return 1;
        }

        g_free(buffer);

        status = qemu_get_be32(f);
    }

    return 0;
}

int sev_save_outgoing_unencrypt_regions_list(void *handle, QEMUFile *f)
{
    struct kvm_page_enc_list e = {};
    uint32_t size;
    int nents;

    e.pnents = &nents;
    e.size = TARGET_PAGE_SIZE;
    e.buffer = g_malloc0(TARGET_PAGE_SIZE);

    //trace_kvm_sev_save_bitmap(start, length);

    if (kvm_vm_ioctl(kvm_state, KVM_GET_PAGE_ENC_LIST, &e) == -1) {
        error_report("%s: KVM_GET_PAGE_ENC_BITMAP ioctl failed %d",
                    __func__, errno);
        g_free(e.buffer);
        return 1;
    }

    qemu_put_be32(f, UNENCRYPT_REGIONS_LIST_START);
    qemu_put_be32(f, nents);
    size = nents * sizeof(struct page_enc_status_array_entry);
    qemu_put_buffer(f, (uint8_t *)e.buffer, size);

    g_free(e.buffer);

    qemu_put_be32(f, UNENCRYPT_REGIONS_LIST_END);
    return 0;
}

static void
sev_register_types(void)
{
    type_register_static(&sev_guest_info);
}

type_init(sev_register_types);
