/*
 * QEMU PC System Firmware (OVMF specific)
 *
 * Copyright (c) 2003-2004 Fabrice Bellard
 * Copyright (c) 2011-2012 Intel Corporation
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "hw/i386/pc.h"
#include "cpu.h"

#define OVMF_SEV_META_DATA_GUID "dc886566-984a-4798-A75e-5585a7bf67cc"

typedef struct __attribute__((__packed__)) SevMetadataOffset {
    uint32_t offset;
} SevMetadataOffset;

typedef struct GuidParseInfo {
    uint8_t *table;
    int table_len;
    bool parsed;

    SevMetadataHeader *metadata;
} GuidParseInfo;

#define OVMF_TABLE_FOOTER_GUID "96b582de-1fb2-45f7-baea-a366c55a082d"
static GuidParseInfo ovmf_info;

static void guid_parse_init(uint8_t *ptr, size_t size, const char *guid_str,
                            GuidParseInfo *info)
{
    QemuUUID guid;
    int tot_len;

    qemu_uuid_parse(guid_str, &guid);
    guid = qemu_uuid_bswap(guid); /* GUIDs are LE */

    if (!qemu_uuid_is_equal((QemuUUID *)ptr, &guid)) {
        return;
    }

    /* If found, just before is two byte table length */
    ptr -= sizeof(uint16_t);
    tot_len = le16_to_cpu(*(uint16_t *)ptr) - sizeof(guid) - sizeof(uint16_t);

    if (tot_len <= 0) {
        return;
    }

    info->table = g_malloc(tot_len);
    info->table_len = tot_len;

    /*
     * ptr is the foot of the table, so copy it all to the newly allocated
     * table and then set the table pointer to the table foot.
     */
    memcpy(info->table, ptr - tot_len, tot_len);
    info->table += tot_len;
}

static bool guid_parse_find(const char *entry, uint8_t **data, int *data_len,
                            GuidParseInfo *info)
{
    uint8_t *ptr = info->table;
    int tot_len = info->table_len;
    QemuUUID entry_guid;

    assert(info->parsed);

    if (qemu_uuid_parse(entry, &entry_guid) < 0) {
        return false;
    }

    if (!ptr) {
        return false;
    }

    entry_guid = qemu_uuid_bswap(entry_guid); /* GUIDs are LE */
    while (tot_len >= sizeof(QemuUUID) + sizeof(uint16_t)) {
        int len;
        QemuUUID *guid;

        /*
         * The data structure is:
         *   arbitrary length data
         *   2 byte length of entire entry
         *   16 byte guid
         */
        guid = (QemuUUID *)(ptr - sizeof(QemuUUID));
        len = le16_to_cpu(*(uint16_t *)(ptr - sizeof(QemuUUID) -
                                        sizeof(uint16_t)));

        /*
         * Just in case the table is corrupt, wouldn't want to spin in
         * the zero case.
         */
        if (len < sizeof(QemuUUID) + sizeof(uint16_t)) {
            return false;
        } else if (len > tot_len) {
            return false;
        }

        ptr -= len;
        tot_len -= len;
        if (qemu_uuid_is_equal(guid, &entry_guid)) {
            if (data) {
                *data = ptr;
            }
            if (data_len) {
                *data_len = len - sizeof(QemuUUID) - sizeof(uint16_t);
            }
            return true;
        }
    }
    return false;
}

static void pc_system_parse_ovmf_sev_metadata(uint8_t *ptr, size_t size,
                                              GuidParseInfo *info)
{
    SevMetadataHeader *metadata;
    SevMetadataOffset *data;

    if (!guid_parse_find(OVMF_SEV_META_DATA_GUID, (uint8_t **)&data, NULL, info)) {
        return;
    }

    metadata = (SevMetadataHeader *)(ptr + size - data->offset);
    if (memcmp(metadata->signature, "ASEV", 4) != 0) {
        return;
    }

    info->metadata = g_malloc(metadata->len);
    memcpy(info->metadata, metadata, metadata->len);
}

OvmfSevMetadata *pc_system_get_ovmf_sev_metadata_ptr(void)
{
    return (OvmfSevMetadata *)ovmf_info.metadata;
}

/**
 * pc_system_parse_ovmf_flash - Find the GUIDed table within the OVMF flash and
 * prepare for locating entries within it.
 *
 * @ovmf_ptr: Pointer to the OVMF flash contents
 * @ovmf_size: Size of the OVMF flash contents
 */
void pc_system_parse_ovmf_flash(uint8_t *flash_ptr, size_t flash_size)
{
    /* Should only be called once */
    if (ovmf_info.parsed) {
        return;
    }

    ovmf_info.parsed = true;

    if (flash_size < TARGET_PAGE_SIZE) {
        return;
    }

    /*
     * If this is OVMF there will be a table footer GUID 48 bytes before the
     * end of the flash file. If it's not found, silently abort the flash
     * parsing.
     */
    guid_parse_init(flash_ptr + flash_size - 48, flash_size,
                    OVMF_TABLE_FOOTER_GUID, &ovmf_info);

    pc_system_parse_ovmf_sev_metadata(flash_ptr, flash_size, &ovmf_info);
}

/**
 * pc_system_ovmf_table_find - Find the data associated with an entry in OVMF's
 * reset vector GUIDed table.
 *
 * @entry: GUID string of the entry to lookup
 * @data: Filled with a pointer to the entry's value (if not NULL)
 * @data_len: Filled with the length of the entry's value (if not NULL). Pass
 *            NULL here if the length of data is known.
 *
 * Return: true if the entry was found in the OVMF table; false otherwise.
 */
bool pc_system_ovmf_table_find(const char *entry, uint8_t **data,
                               int *data_len)
{
    return guid_parse_find(entry, data, data_len, &ovmf_info);
}
