/*
 * hostapd / IEEE 802.11bn UHR
 *
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef UHR_LINK_RECONFIG_H
#define UHR_LINK_RECONFIG_H

#include "common/wpa_common.h"
#include "ap/uhr_iap.h"
#include "utils/common.h"
#include "utils/list.h"

/* UHR Link Reconfig Type field values (NEW in V25) */
#define UHR_LINK_RECONFIG_TYPE_PREP    0  /* ST Prep */
#define UHR_LINK_RECONFIG_TYPE_EXECUTE 1  /* ST Execute */

/* DL Drain Duration default (in TU) (NEW in V25) */
/* Default: ~10 seconds = 9765 TU (1 TU = 1024 microseconds) */
#define UHR_DL_DRAIN_DURATION_TU_DEFAULT 9765

/* Maximum DL Drain Duration (in TU) (NEW in V25) */
#define UHR_DL_DRAIN_DURATION_TU_MAX 65535

/* Default Tx power indication value until the actual value is retrieved */
#define UHR_TX_PWR_IND_DEFAULT_FVAL 19

/* Extract IEs from frame
 * Frame format: MAC header + Category + Action + Dialog Token + Type + IEs
 * Skip to IEs: 24 (MAC) + 1 (Category) + 1 (Action) + 1 (Dialog) + 1 (Type) = 28 bytes
 */
#define WLAN_ST_PREP_MIN_LEN 28

enum uhr_smd_st_type {
	UHR_SMD_ST_PREP_REQ  = 0,
	UHR_SMD_ST_PREP_RESP = 1,
	UHR_SMD_ST_EXEC_REQ  = 2,
	UHR_SMD_ST_EXEC_RESP = 3,
};

#define UHR_ST_IAP_TIMEOUT_USEC 5000000

#define UHR_ST_GET_CTX_TIMEOUT_USEC 50000

/* UHR ST preparation timeout fallback when smd_timeout is not configured (5 seconds) */
#define UHR_ST_PREP_TIMEOUT_SEC 5

struct uhr_smd_bss_transition_element {
	u16 listen_interval;
	u16 dl_drain_time;
	bool dl_sn_not_transferred;
	bool ul_sn_not_transferred;
	u8 num_scs_ids;
};

/**
 * struct uhr_reconfig_mle - Parsed UHR Reconfiguration ML-IE
 */
struct uhr_reconfig_mle {
	u8 mld_mac_addr[ETH_ALEN];
	u8 target_ap_mld_addr[ETH_ALEN];
	bool has_target_ap_mld_addr;
	u8 current_link_id;
};

/* Forward declarations */
struct hostapd_data;
struct sta_info;

/* Forward declarations for handlers (defined in patches 03 and 04) */
void uhr_tgt_ap_handle_st_prep_req(struct hostapd_data *hapd,
			       const struct uhr_iap_frame *iap,
			       u16 frame_len);

void uhr_cur_ap_handle_st_prep_resp(struct hostapd_data *hapd,
				const struct uhr_iap_frame *iap,
				u16 frame_len);

/* EHT-style data structures for Per-STA Profile management */
struct uhr_link_reconf_req_list;
struct uhr_link_reconf_req_info;

/* Cleanup function (EHT naming pattern) */
void uhr_deinit_link_reconf_req(struct uhr_link_reconf_req_list **req_list_ptr);

#define MAX_NUM_MLD_LINKS 15

int uhr_cur_start_iap_msg_timer(struct sta_info *sta, const u8 *ap_mld_addr);
void uhr_cancel_iap_timeout(struct sta_info *sta, const u8 *ap_mld_addr);

/* ST Execute - Current AP Functions */
int uhr_handle_st_exec_req(struct hostapd_data *hapd,
                                 struct sta_info *sta,
				  const u8 *buf, size_t len, struct sta_smd_ctx_info *smd_ctx);
void uhr_handle_get_smd_ctx_done(struct hostapd_data *hapd,
				 const u8 *sta_addr,
				 struct sta_smd_ctx_info *ctx);

void uhr_cur_ap_handle_st_exec_resp(struct hostapd_data *hapd,
                                    const struct uhr_iap_frame *iap,
                                    u16 frame_len);

/* ST Execute - Target AP Functions */
void uhr_tgt_ap_handle_st_exec_req(struct hostapd_data *hapd,
                                const struct uhr_iap_frame *iap,
                                u16 frame_len);

/* ST Roam Cleanup - Target AP handler */
void uhr_tgt_ap_handle_st_roam_cleanup(struct hostapd_data *hapd,
					const struct uhr_iap_frame *iap);


/* ST Execute via Target AP */
int uhr_handle_st_exec_req_tgt(struct hostapd_data *hapd,
				struct sta_info *sta,
				const u8 *buf, size_t len);

/* ST Ctx - Current AP handler (receives CTX REQUEST from target AP) */
void uhr_cur_ap_handle_st_ctx_request(struct hostapd_data *hapd,
				      const struct uhr_iap_frame *iap,
				      u16 frame_len);

/* ST Ctx - Target AP handler (receives CTX RESPONSE from current AP) */
void uhr_tgt_ap_handle_st_ctx_response(struct hostapd_data *hapd,
					const struct uhr_iap_frame *iap,
					u16 frame_len);

/* Current AP handler for ST EXEC VIA TGT DONE notification */
void uhr_cur_ap_handle_st_exec_via_tgt_done(struct hostapd_data *hapd,
					     const struct uhr_iap_frame *iap,
					     u16 frame_len);


/* Current AP Functions */
int uhr_handle_st_prep_req(struct hostapd_data *hapd,
				   struct sta_info *sta,
				   const u8 *frame, size_t frame_len, struct sta_smd_ctx_info *smd_ctx);

int uhr_parse_smd_bss_trans_elem(const struct ieee802_11_elems *elems,
				 u8 type,
				 struct uhr_smd_bss_transition_element *sbte);

/* ST Prep Timer at Target AP */
void uhr_tgt_st_prep_timer_cleanup(void *eloop_ctx, void *timeout_ctx);
void uhr_tgt_start_st_prep_timer(struct hostapd_data *hapd,
                                const u8 *sta_addr);
void uhr_tgt_cancel_st_prep_timer(struct hostapd_data *hapd, const u8 *sta_addr);

/* Basic Multi-Link IE max buffer size:
 * Element ID (1) + Length (1) + Extension ID (1) + Multi-Link Control (2) +
 * Common Info Length (1) + MLD MAC Address (ETH_ALEN) + Link ID Info (1) +
 * BSS Parameters Change Count (1) + Medium Sync Delay Info (2) +
 * EML Capabilities (2) + MLD Capabilities (2) + AP MLD ID (1) +
 * Extended MLD Capabilities (2) + Enhanced Critical Update (1) +
 * Age of BSS Load (1) + Future Extensions (8)
 */
#define UHR_BMLIE_BUF_LEN  (1 + 1 + 1 + 2 + 1 + ETH_ALEN + 1 + 1 + 2 + 2 + 2 + 1 + 2 + 1 + 1 + 8)

size_t hostapd_uhr_eid_bmlie_from_rmlie(const struct wpabuf *mlbuf,
						u8 link_id,
						u8 *bmlie);
/* Function declarations */
int uhr_parse_reconfig_mle(const struct ieee802_11_elems *elems,
			   struct uhr_reconfig_mle *mle);


/* Timeout management functions */
int uhr_cur_start_st_prep_timer(struct sta_info *sta, const u8 *ap_mld_addr, u32 seconds);
void uhr_cancel_st_prep_timeout(struct sta_info *sta, const u8 *ap_mld_addr);

/* AP list management functions */
struct smd_roam_ap_info *uhr_find_ap_in_list(struct sta_info *sta, const u8 *ap_mld_addr);
int uhr_remove_ap_from_list(struct sta_info *sta, const u8 *ap_mld_addr);

/* Cleanup function for sta_info.c */
void uhr_cleanup_sta_roam_contexts(struct hostapd_data *hapd, struct sta_info *sta);

/* Target AP IAP receive handlers */
void uhr_tgt_ap_handle_st_prep_ctx(struct hostapd_data *hapd,
				    const struct uhr_iap_frame *iap);
/* ---- SMD counter failure reason enums --------------------------------- */

#ifdef CONFIG_IEEE80211BN

enum sap_prep_parse_fail_reason {
	SAP_PREP_PARSE_FAIL_NONE = 0,
	SAP_PREP_PARSE_FAIL_SHORT_FRAME,
	SAP_PREP_PARSE_FAIL_IE_PARSE,
	SAP_PREP_PARSE_FAIL_ML_IE,
	SAP_PREP_PARSE_FAIL_SBTE,
	SAP_PREP_PARSE_FAIL_NO_TARGET_ADDR,
	SAP_PREP_PARSE_FAIL_ALLOC,
};

enum sap_prep_iap_fail_reason {
	SAP_PREP_IAP_FAIL_NONE = 0,
	SAP_PREP_IAP_FAIL_OUI_PEER_UNKNOWN,
	SAP_PREP_IAP_FAIL_ENCRYPT,
	SAP_PREP_IAP_FAIL_TRANSPORT,
};

enum smd_iap_tx_fail_reason {
	SMD_IAP_TX_FAIL_NONE = 0,
	SMD_IAP_TX_FAIL_ENCRYPT,
	SMD_IAP_TX_FAIL_BUF_ALLOC,
	SMD_IAP_TX_FAIL_L2_SEND,
	SMD_IAP_TX_FAIL_INVALID_PARAMS,
	SMD_IAP_TX_FAIL_FRAME_TOO_LARGE,
	SMD_IAP_TX_FAIL_PEER_NOT_FOUND,
	SMD_IAP_TX_FAIL_NO_AP_INFO,
	SMD_IAP_TX_FAIL_ALLOC,
	SMD_IAP_TX_FAIL_SEC_CTX,
};

enum smd_iap_rx_fail_reason {
	SMD_IAP_RX_FAIL_NONE = 0,
	SMD_IAP_RX_FAIL_PEER_UNKNOWN,
	SMD_IAP_RX_FAIL_DECRYPT,
	SMD_IAP_RX_FAIL_UNKNOWN_TYPE,
};

enum tap_prep_fail_reason {
	TAP_PREP_FAIL_NONE = 0,
	TAP_PREP_FAIL_FRAME_INVALID,
	TAP_PREP_FAIL_FRAME_SHORT,
	TAP_PREP_FAIL_IE_PARSE,
	TAP_PREP_FAIL_NO_ML_IE,
	TAP_PREP_FAIL_ML_PARSE,
	TAP_PREP_FAIL_NO_STA,
	TAP_PREP_FAIL_CTX_SET,
	TAP_PREP_FAIL_ASSOC,
	TAP_PREP_FAIL_KEY_INSTALL,
	TAP_PREP_FAIL_IAP_SEND,
};

enum sap_prep_resp_fail_reason {
	SAP_PREP_RESP_FAIL_NONE = 0,
	SAP_PREP_RESP_FAIL_LINK,
	SAP_PREP_RESP_FAIL_NO_STA,
	SAP_PREP_RESP_FAIL_NO_APINFO,
	SAP_PREP_RESP_FAIL_TAP_REJECTED,
	SAP_PREP_RESP_FAIL_EMPTY_FRAME,
	SAP_PREP_RESP_FAIL_SHORT_FRAME,
	SAP_PREP_RESP_FAIL_MLME,
};

enum sap_exec_parse_fail_reason {
	SAP_EXEC_PARSE_FAIL_NONE = 0,
	SAP_EXEC_PARSE_FAIL_SHORT_FRAME,
	SAP_EXEC_PARSE_FAIL_IE_PARSE,
	SAP_EXEC_PARSE_FAIL_ML_IE,
	SAP_EXEC_PARSE_FAIL_NO_TARGET_ADDR,
};

enum tap_exec_fail_reason {
	TAP_EXEC_FAIL_NONE = 0,
	TAP_EXEC_FAIL_STA_NOT_FOUND,
	TAP_EXEC_FAIL_CTX_SET,
	TAP_EXEC_FAIL_AUTH,
	TAP_EXEC_FAIL_GROUP_KEY,
	TAP_EXEC_FAIL_ALLOC,
};

enum sap_exec_resp_fail_reason {
	SAP_EXEC_RESP_FAIL_NONE = 0,
	SAP_EXEC_RESP_FAIL_LINK,
	SAP_EXEC_RESP_FAIL_NO_STA,
	SAP_EXEC_RESP_FAIL_NO_APINFO,
	SAP_EXEC_RESP_FAIL_BAD_STATE,
	SAP_EXEC_RESP_FAIL_TAP_REJECTED,
	SAP_EXEC_RESP_FAIL_MLME,
};

/* ---- SAP role counters ------------------------------------------------- */

/**
 * struct smd_sap_roam_stats - SAP-role SMD counters per client STA
 *
 * Tracks all steps where this AP acted as the Serving AP for this client.
 * Embedded in smd_info.sap_stats.
 * Folded into hostapd_mld.smd_sta_roam_records at ap_free_sta().
 */
struct smd_sap_roam_stats {
	/* PREP-03: SAP validates OTA Prep Req + sends IAP */
	u16 sap_prep_req_rx;           /* OTA ST Prep Req frames received */
	u16 sap_prep_req_parse_fail;   /* frames rejected at parse stage */
	enum sap_prep_parse_fail_reason sap_prep_parse_fail_reasons[5]; /* newest-first ring */
	u8 sap_prep_parse_fail_reasons_head;  /* circular write index 0-4 */
	u16 sap_prep_iap_sent;               /* IAP Prep Req transmit attempts */
	u16 sap_prep_iap_timer_fail;         /* IAP response timer start failures */
	u16 sap_prep_iap_send_fail;          /* l2_packet send failures */
	enum sap_prep_iap_fail_reason sap_prep_iap_fail_reasons[5]; /* newest-first ring */
	u8 sap_prep_iap_fail_reasons_head;  /* circular write index 0-4 */

	/* PREP-04/05: IAP Prep Req l2_packet TX outcome */
	u16 sap_iap_prep_req_tx_fail;  /* OUI transport TX failures */
	enum smd_iap_tx_fail_reason sap_iap_prep_req_tx_fail_reasons[5]; /* newest-first ring */
	u8 sap_iap_prep_req_tx_fail_reasons_head;  /* circular write index 0-4 */

	/* PREP-09/10: IAP Prep Resp l2_packet RX outcome */
	u16 sap_iap_prep_resp_rx_ok;   /* IAP Prep Resp received successfully */
	u16 sap_iap_prep_resp_rx_fail; /* IAP Prep Resp receive failures */
	enum smd_iap_rx_fail_reason sap_iap_prep_resp_rx_fail_reasons[5]; /* newest-first ring */
	u8 sap_iap_prep_resp_rx_fail_reasons_head;  /* circular write index 0-4 */

	/* PREP-12: SAP sends OTA Prep Response + timers */
	u16 sap_prep_ota_resp_sent;    /* OTA ST Prep Resp frames sent */
	u16 sap_prep_ota_resp_fail;    /* OTA ST Prep Resp send failures */
	enum sap_prep_resp_fail_reason sap_prep_resp_fail_reasons[5]; /* newest-first ring */
	u8 sap_prep_resp_fail_reasons_head;  /* circular write index 0-4 */
	u16 sap_prep_roam_notify_fail;    /* Roam notify failures (non-fatal, roam may still proceed) */
	u16 sap_prep_exec_timer_fail;  /* Exec-phase watchdog timer start failures */
	u16 sap_prep_clone_fail;       /* peer context clone failures */

	/* Timeouts */
	u16 sap_prep_iap_timeout;      /* IAP Prep Resp wait timed out */
	u16 sap_prep_exec_timeout;     /* Exec phase did not arrive within deadline */

	/* EXEC-03: SAP validates OTA Exec Req + sends IAP */
	u16 sap_exec_req_rx;           /* OTA ST Exec Req frames received */
	u16 sap_exec_req_parse_fail;   /* frames rejected at parse stage */
	enum sap_exec_parse_fail_reason sap_exec_parse_fail_reasons[5]; /* newest-first ring */
	u8 sap_exec_parse_fail_reasons_head;  /* circular write index 0-4 */
	u16 sap_exec_req_no_apinfo;    /* no target AP info found for Exec Req */
	u16 sap_exec_req_bad_state;    /* Exec Req arrived in wrong roam state */
	u16 sap_exec_iap_sent;         /* IAP Exec Req transmit attempts */
	u16 sap_exec_iap_send_fail;    /* l2_packet send failures */
	u16 sap_exec_iap_timer_fail;   /* IAP Exec response timer start failures */

	/* EXEC-04/05: IAP Exec Req l2_packet TX outcome */
	u16 sap_iap_exec_req_tx_fail;  /* OUI transport TX failures */
	enum smd_iap_tx_fail_reason sap_iap_exec_req_tx_fail_reasons[5]; /* newest-first ring */
	u8 sap_iap_exec_req_tx_fail_reasons_head;  /* circular write index 0-4 */

	/* EXEC-09/10: IAP Exec Resp l2_packet RX outcome */
	u16 sap_iap_exec_resp_rx_ok;   /* IAP Exec Resp received successfully */
	u16 sap_iap_exec_resp_rx_fail; /* IAP Exec Resp receive failures */
	enum smd_iap_rx_fail_reason sap_iap_exec_resp_rx_fail_reasons[5]; /* newest-first ring */
	u8 sap_iap_exec_resp_rx_fail_reasons_head;  /* circular write index 0-4 */

	/* EXEC-11/12: SAP sends OTA Exec Response */
	u16 sap_exec_iap_resp_rx;      /* IAP Exec Resp received (triggers OTA send) */
	u16 sap_exec_ota_resp_sent;    /* OTA ST Exec Resp frames sent */
	u16 sap_exec_ota_resp_fail;    /* OTA ST Exec Resp send failures */
	enum sap_exec_resp_fail_reason sap_exec_resp_fail_reasons[5]; /* newest-first ring */
	u8 sap_exec_resp_fail_reasons_head;  /* circular write index 0-4 */
	u16 sap_exec_roam_notify_fail;    /* Roam notify failures (non-fatal) */
	u16 sap_exec_drain_timer_fail; /* DL drain timer start failures */

	u16 sap_exec_iap_timeout;      /* IAP Exec Resp wait timed out */

	/* DL Drain */
	u16 dl_drain_started;          /* DL drain phase initiated */
	u16 dl_drain_no_sta;           /* drain skipped — STA not found */
	u16 dl_drain_bad_state;        /* drain skipped — wrong roam state */
	u16 dl_drain_complete;         /* DL drain completed successfully */

	u16 roam_success;              /* full SAP-side roam completed successfully */

	/* Timestamps (µs since boot, newest-first rings) */
	struct smd_ts_ring sap_prep_iap_sent_ts;        /* when IAP Prep Req was sent */
	struct smd_ts_ring sap_iap_prep_resp_rx_ok_ts;  /* when IAP Prep Resp was received */
	struct smd_ts_ring sap_exec_iap_sent_ts;        /* when IAP Exec Req was sent */
	struct smd_ts_ring sap_iap_exec_resp_rx_ok_ts;  /* when IAP Exec Resp was received */
	struct smd_ts_ring sap_prep_exec_timeout_ts;    /* when Exec-phase timeout fired */
	struct smd_ts_ring sap_exec_iap_timeout_ts;     /* when IAP Exec Resp timeout fired */
	struct smd_ts_ring roam_success_ts;             /* when roam completed successfully */
};

/* ---- TAP role counters ------------------------------------------------- */

/**
 * struct smd_tap_roam_stats - TAP-role SMD counters per client STA
 *
 * Tracks all steps where this AP acted as the Target AP for this client.
 * Embedded in smd_info.tap_stats.
 * Folded into hostapd_mld.smd_sta_roam_records at ap_free_sta().
 */
struct smd_tap_roam_stats {
	/* PREP-04/05: IAP Prep Req l2_packet RX */
	u16 tap_iap_prep_req_rx_ok;    /* IAP Prep Req received successfully */
	u16 tap_iap_prep_req_rx_fail;  /* IAP Prep Req receive failures */
	enum smd_iap_rx_fail_reason tap_iap_prep_req_rx_fail_reasons[5]; /* newest-first ring */
	u8 tap_iap_prep_req_rx_fail_reasons_head;  /* circular write index 0-4 */

	/* PREP-07: TAP sets up prepared peer */
	u16 tap_prep_iap_rx;           /* IAP Prep Req handed to prep handler */
	u16 tap_prep_ok;               /* peer prepared successfully */
	u16 tap_prep_fail;             /* peer preparation failures */
	enum tap_prep_fail_reason tap_prep_fail_reasons[5]; /* newest-first ring */
	u8 tap_prep_fail_reasons_head;  /* circular write index 0-4 */

	/* PREP-08/09: TAP sends IAP Prep Response */
	u16 tap_iap_prep_resp_tx_ok;         /* IAP Prep Resp sent successfully */
	u16 tap_iap_prep_resp_tx_fail;       /* IAP Prep Resp send failures */
	enum smd_iap_tx_fail_reason tap_iap_prep_resp_tx_fail_reasons[5]; /* newest-first ring */
	u8 tap_iap_prep_resp_tx_fail_reasons_head;  /* circular write index 0-4 */
	u16 tap_prep_timer_started;           /* Exec-phase watchdog timer started */
	u16 tap_prep_timer_start_fail;        /* Exec-phase watchdog timer start failures */
	u16 tap_prep_exec_timeout;            /* Exec phase did not arrive within deadline */

	/* EXEC-04/05: IAP Exec Req l2_packet RX */
	u16 tap_iap_exec_req_rx_ok;    /* IAP Exec Req received successfully */
	u16 tap_iap_exec_req_rx_fail;  /* IAP Exec Req receive failures */
	enum smd_iap_rx_fail_reason tap_iap_exec_req_rx_fail_reasons[5]; /* newest-first ring */
	u8 tap_iap_exec_req_rx_fail_reasons_head;  /* circular write index 0-4 */

	/* EXEC-06: TAP handles IAP Exec Req, authorizes peer */
	u16 tap_exec_ok;               /* peer authorized successfully */
	u16 tap_exec_fail;             /* peer authorization failures */
	enum tap_exec_fail_reason tap_exec_fail_reasons[5]; /* newest-first ring */
	u8 tap_exec_fail_reasons_head;  /* circular write index 0-4 */

	/* EXEC-07: Key installation */
	u16 ptk_install_ok;            /* PTK installed successfully */
	u16 ptk_install_fail;          /* PTK installation failures */
	u16 gtk_install_ok;            /* GTK installed successfully */

	/* EXEC-08/09: TAP sends IAP Exec Response */
	u16 tap_iap_exec_resp_tx_ok;         /* IAP Exec Resp sent successfully */
	u16 tap_iap_exec_resp_tx_fail;       /* IAP Exec Resp send failures */
	enum smd_iap_tx_fail_reason tap_iap_exec_resp_tx_fail_reasons[5]; /* newest-first ring */
	u8 tap_iap_exec_resp_tx_fail_reasons_head;  /* circular write index 0-4 */
	u16 tap_exec_prep_timer_cancel_fail;  /* failed to cancel Exec-phase watchdog */

	/* Timestamps (µs since boot, newest-first rings) */
	struct smd_ts_ring tap_prep_ok_ts;              /* when peer was prepared */
	struct smd_ts_ring tap_exec_ok_ts;              /* when peer was authorized */
	struct smd_ts_ring tap_iap_prep_req_rx_ok_ts;   /* when IAP Prep Req was received */
	struct smd_ts_ring tap_iap_prep_resp_tx_ok_ts;  /* when IAP Prep Resp was sent */
	struct smd_ts_ring tap_iap_exec_req_rx_ok_ts;   /* when IAP Exec Req was received */
	struct smd_ts_ring tap_iap_exec_resp_tx_ok_ts;  /* when IAP Exec Resp was sent */
};

/* ---- Archive record ---------------------------------------------------- */

/** SMD_ARCHIVE_MAX_RECORDS - max per-VIF/MLD archive entries kept (oldest evicted) */
#define SMD_ARCHIVE_MAX_RECORDS  2

/**
 * struct smd_sta_roam_record - per-STA persistent archive entry
 *
 * Folded from smd_info at ap_free_sta() (before uhr_cleanup_sta_roam_contexts).
 * Keyed by (sta_mld_addr, link_id = hapd->mld_link_id at fold time).
 * Multiple roams by the same STA on the same link accumulate into one record.
 * Stored on hostapd_mld.smd_sta_roam_records (dl_list).
 */
struct smd_sta_roam_record {
	struct dl_list            list;
	u8                        sta_mld_addr[ETH_ALEN]; /* STA MLD address (archive key) */
	u8                        link_id;                /* link ID at fold time */
	struct os_reltime         last_updated;           /* time of most recent fold */
	struct smd_sap_roam_stats sap;                    /* accumulated SAP-role counters */
	struct smd_tap_roam_stats tap;                    /* accumulated TAP-role counters */
};

#endif /* CONFIG_IEEE80211BN */

void uhr_cur_get_ctx_timeout(void *eloop_ctx, void *timeout_ctx);

#endif /* UHR_LINK_RECONFIG_H */
