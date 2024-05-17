/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef __TSM_UAPI_H
#define __TSM_UAPI_H

#include <linux/types.h>

/**
 * struct tdisp_interface_id - TDISP INTERFACE_ID Definition
 *
 * @function_id: Identifies the function of the device hosting the TDI
 *   15:0: @rid: Requester ID
 *   23:16: @rseg: Requester Segment (Reserved if Requester Segment Valid is Clear)
 *   24: @rseg_valid: Requester Segment Valid
 *   31:25 – Reserved
 * 8B - Reserved
 */
struct tdisp_interface_id {
	__u32 function_id; /* TSM_TDISP_IID_xxxx */
	__u8 reserved[8];
} __attribute__((packed));

#define TSM_TDISP_IID_REQUESTER_ID	GENMASK(15, 0)
#define TSM_TDISP_IID_RSEG		GENMASK(23, 16)
#define TSM_TDISP_IID_RSEG_VALID	BIT(24)

#define SPDM_MEASUREMENTS_NONCE_LEN	32
typedef __u8 spdm_measurements_nonce_t[SPDM_MEASUREMENTS_NONCE_LEN];

/*
 * TDI Report Structure as defined in TDISP.
 */
struct tdi_report_header {
	__u16 interface_info; /* TSM_TDI_REPORT_xxx */
	__u16 reserved2;
	__u16 msi_x_message_control;
	__u16 lnr_control;
	__u32 tph_control;
	__u32 mmio_range_count;
} __attribute__((packed));

#define _BITSH(x)	(1 << (x))
#define TSM_TDI_REPORT_NO_FW_UPDATE	_BITSH(0)  /* not updates in CONFIG_LOCKED or RUN */
#define TSM_TDI_REPORT_DMA_NO_PASID	_BITSH(1)  /* TDI generates DMA requests without PASID */
#define TSM_TDI_REPORT_DMA_PASID	_BITSH(2)  /* TDI generates DMA requests with PASID */
#define TSM_TDI_REPORT_ATS		_BITSH(3)  /* ATS supported and enabled for the TDI */
#define TSM_TDI_REPORT_PRS		_BITSH(4)  /* PRS supported and enabled for the TDI */

/*
 * Each MMIO Range of the TDI is reported with the MMIO reporting offset added.
 * Base and size in units of 4K pages
 */
struct tdi_report_mmio_range {
	__u64 first_page; /* First 4K page with offset added */
	__u32 num;	/* Number of 4K pages in this range */
	__u32 range_attributes; /* TSM_TDI_REPORT_MMIO_xxx */
} __attribute__((packed));

#define TSM_TDI_REPORT_MMIO_MSIX_TABLE		BIT(0)
#define TSM_TDI_REPORT_MMIO_PBA			BIT(1)
#define TSM_TDI_REPORT_MMIO_IS_NON_TEE		BIT(2)
#define TSM_TDI_REPORT_MMIO_IS_UPDATABLE	BIT(3)
#define TSM_TDI_REPORT_MMIO_RESERVED		GENMASK(15, 4)
#define TSM_TDI_REPORT_MMIO_RANGE_ID		GENMASK(31, 16)

struct tdi_report_footer {
	__u32 device_specific_info_len;
	__u8 device_specific_info[];
} __attribute__((packed));

#define TDI_REPORT_HDR(rep)		((struct tdi_report_header *) ((rep)->data))
#define TDI_REPORT_MR_NUM(rep)		(TDI_REPORT_HDR(rep)->mmio_range_count)
#define TDI_REPORT_MR_OFF(rep)		((struct tdi_report_mmio_range *) (TDI_REPORT_HDR(rep) + 1))
#define TDI_REPORT_MR(rep, rangeid)	TDI_REPORT_MR_OFF(rep)[rangeid]
#define TDI_REPORT_FTR(rep)		((struct tdi_report_footer *) &TDI_REPORT_MR((rep), \
					TDI_REPORT_MR_NUM(rep)))

struct tsm_dsm_status {
	__u8 valid;
	__u8 ctx_state;
	__u8 tc_mask;
	__u8 certs_slot;
	__u8 no_fw_update;
	__u8 reserved[3]; /* padding */
	__u16 device_id;
	__u16 segment_id;
	__u16 ide_stream_id[8];
} __attribute__((packed));

enum tsm_spdm_algos {
	TSM_SPDM_ALGOS_DHE_SECP256R1,
	TSM_SPDM_ALGOS_DHE_SECP384R1,
	TSM_SPDM_ALGOS_AEAD_AES_128_GCM,
	TSM_SPDM_ALGOS_AEAD_AES_256_GCM,
	TSM_SPDM_ALGOS_ASYM_TPM_ALG_RSASSA_3072,
	TSM_SPDM_ALGOS_ASYM_TPM_ALG_ECDSA_ECC_NIST_P256,
	TSM_SPDM_ALGOS_ASYM_TPM_ALG_ECDSA_ECC_NIST_P384,
	TSM_SPDM_ALGOS_HASH_TPM_ALG_SHA_256,
	TSM_SPDM_ALGOS_HASH_TPM_ALG_SHA_384,
	TSM_SPDM_ALGOS_KEY_SCHED_SPDM_KEY_SCHEDULE,
};

enum tsm_tdisp_state {
	TDISP_STATE_CONFIG_UNLOCKED,
	TDISP_STATE_CONFIG_LOCKED,
	TDISP_STATE_RUN,
	TDISP_STATE_ERROR,
};

struct tsm_tdi_status {
	__u8 valid;
	__u8 state; /* enum tsm_tdisp_state */
	__u8 meas_digest_fresh;
	__u8 meas_digest_valid;
	__u8 all_request_redirect;
	__u8 bind_p2p;
	__u8 lock_msix;
	__u8 no_fw_update;
	__u16 cache_line_size;
	__u64 spdm_algos; /* Bitmask of TSM_SPDM_ALGOS */
	__u8 certs_digest[48];
	__u8 meas_digest[48];
	__u8 interface_report_digest[48];
	__u64 intf_report_counter;
	struct tdisp_interface_id id;
} __attribute__((packed));

#endif /* __TSM_UAPI_H */
