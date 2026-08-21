/*
 * SMD (Seamless Mobility Domain) roaming debug counter framework
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#ifndef UHR_STATS_H
#define UHR_STATS_H

#include "utils/common.h"
#include "common/wpa_common.h"
#include "drivers/nl80211_copy.h"

/* ---- SAP failure reason enums ----------------------------------------- */

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
 * Folded into hapd_interfaces.smd_sta_roam_records at ap_free_sta().
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
 * Folded into hapd_interfaces.smd_sta_roam_records at ap_free_sta().
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

/** SMD_ARCHIVE_MAX_RECORDS - max per-interfaces archive entries kept (oldest evicted) */
#define SMD_ARCHIVE_MAX_RECORDS  2

/**
 * struct smd_sta_roam_record - per-STA persistent archive entry
 *
 * Folded from smd_info at ap_free_sta() (before uhr_cleanup_sta_roam_contexts).
 * Keyed by (sta_mld_addr, ap_mld_addr).
 * Multiple roams by the same STA on the same AP accumulate into one record.
 * Stored on hapd_interfaces.smd_sta_roam_records (dl_list).
 */
struct smd_sta_roam_record {
	struct dl_list            list;
	u8                        sta_mld_addr[ETH_ALEN]; /* STA MLD address (archive key) */
	u8                        ap_mld_addr[ETH_ALEN];  /* AP MLD address (for per-MLD filtering) */
	u8                        link_id;                /* link ID at fold time */
	struct os_reltime         last_updated;           /* time of most recent fold */
	struct smd_sap_roam_stats sap;                    /* accumulated SAP-role counters */
	struct smd_tap_roam_stats tap;                    /* accumulated TAP-role counters */
};

/* ---- STA-side (wpa_supplicant) counter structs ------------------------- */

/**
 * struct wpa_smd_sta_stats - STA-side SMD roaming debug counters
 *
 * Per-interface, accumulates across all roam attempts and all target APs.
 * Embedded as wpa_supplicant.smd_stats.
 *
 * Timestamp rings store the last 8 µs-since-boot values.
 * Acquisition: struct os_reltime t; os_get_reltime(&t);
 *              u64 ts = (u64)t.sec * 1000000ULL + t.usec;
 */
struct wpa_smd_sta_stats {
	/* PREP request to driver */
	u32 prep_req_tx;               /* wpa_drv_uhr_reconfig_req() succeeded */
	u32 prep_req_tx_fail;          /* driver call returned error */

	/* PREP response from AP */
	u32 prep_resp_rx;
	u32 prep_resp_fail_no_target;  /* no prepared target matches response */
	u32 prep_resp_fail_rejected;   /* AP status code != SUCCESS */
	u32 prep_resp_ok;              /* target → SMD_TARGET_PREPARED */
	u32 prep_exec_timeout;         /* exec window expired before EXEC was sent */

	/* EXEC request to driver */
	u32 exec_req_tx;
	u32 exec_req_tx_fail_not_in_prep_list; /* wpas_smd_get_prepared_target returned NULL */
	u32 exec_req_tx_fail_not_prepared; /* target not in SMD_TARGET_PREPARED state */
	u32 exec_req_tx_fail_alloc;        /* os_zalloc for work ctx failed */
	u32 exec_req_tx_fail_drv;

	/* EXEC response from AP */
	u32 exec_resp_rx;
	u32 exec_resp_fail_no_target;
	u32 exec_resp_fail_rejected;
	u32 exec_resp_ok;              /* target → SMD_TARGET_EXEC_PENDING */

	/* Final outcome */
	u32 transition_complete;       /* port authorized, roam done */
	u32 transition_abort;          /* any phase failure terminated the roam */

	/* Timestamps (µs since boot, last 8 events each) */
	struct smd_ts_ring transition_complete_ts;
	struct smd_ts_ring transition_abort_ts;
};

enum wpa_smd_roam_outcome {
	WPAS_SMD_OUTCOME_COMPLETE     = 0, /* firmware TRANSITION_COMPLETE */
	WPAS_SMD_OUTCOME_ABORT,            /* firmware TRANSITION_ABORT */
	WPAS_SMD_OUTCOME_EXEC_REJECTED,    /* TAP rejected EXEC response */
	WPAS_SMD_OUTCOME_EXEC_TIMEOUT,     /* exec window expired */
	WPAS_SMD_OUTCOME_DRAIN_TIMEOUT,    /* DL drain watchdog fired */
	WPAS_SMD_OUTCOME_EXEC_FAIL,        /* driver send failure at exec phase */
};

#define WPAS_SMD_ROAM_RECORD_MAX  2

struct wpa_smd_roam_record {
	struct dl_list             list;
	u8                         sap_mld_addr[ETH_ALEN];
	u8                         tap_mld_addr[ETH_ALEN];
	enum wpa_smd_roam_outcome  outcome;
};

/* ---- Display macros (AP side) ----------------------------------------- */

/*
 * SMD_REASONS(pos, end, ring, head, str_arr)
 * Appends "(reason1,reason2,...)" directly after a counter value when the
 * ring has entries.  Writes nothing when the ring is empty (all zeros).
 */
#define SMD_REASONS(pos, end, ring, head, str_arr) do {              \
	int _i, _n = 0;                                              \
	int _vals[SMD_REASON_SIZE];                                  \
	for (_i = 0; _i < SMD_REASON_SIZE; _i++) {                  \
		int _slot = ((int)(head) - 1 - _i +                 \
			     SMD_REASON_SIZE * 2) % SMD_REASON_SIZE; \
		unsigned int _v = (unsigned int)(ring)[_slot];       \
		if (_v == 0) break;                                  \
		_vals[_n++] = (int)_v;                               \
	}                                                            \
	if (_n > 0 && (pos) < (end)) {                               \
		(pos) += os_snprintf((pos), (size_t)((end) - (pos)),\
				     "(");                           \
		for (_i = 0; _i < _n && (pos) < (end); _i++) {      \
			unsigned int _v = (unsigned int)_vals[_i];   \
			const char *_s = (_v < ARRAY_SIZE(str_arr))  \
					 ? (str_arr)[_v] : "?";      \
			(pos) += os_snprintf((pos),                  \
					     (size_t)((end) - (pos)),\
					     "%s%s",                 \
					     _i ? "," : "", _s);     \
		}                                                    \
		(pos) += os_snprintf((pos), (size_t)((end) - (pos)),\
				     ")");                           \
	}                                                            \
} while (0)

/**
 * __SMD_INLINE_TS - core body to write timestamps of different types
 * @pos: position in the output buffer
 * @end: max size of the output buffer
 * @r: ring entry
 * @ts_expr: expression that evaluates to a single timestamp for index _slot
 *
 * Appends "(ts1 ts2 ...)" newest-first directly after a counter value.
 * Writes nothing when the ring is empty.
 * Shared print core. ts must evaluate to a u64 for index _slot.
 */
#define __SMD_INLINE_TS(pos, end, r, ts_expr) do {                  \
	if ((r).count > 0 && (pos) < (end)) {                           \
		int _i;                                                  \
		(pos) += os_snprintf((pos), (size_t)((end) - (pos)),    \
				     "(");                               \
		for (_i = 0; _i < (r).count && (pos) < (end); _i++) {   \
			int _slot = ((int)(r).head - 1 - _i +           \
				     SMD_TS_RING_SIZE * 2)               \
				    % SMD_TS_RING_SIZE;                  \
			(pos) += os_snprintf((pos),                      \
					     (size_t)((end) - (pos)),    \
					     "%s%llu",                   \
					     _i ? " " : "",              \
					     (unsigned long long)        \
					     (ts_expr));                 \
		}                                                        \
		(pos) += os_snprintf((pos), (size_t)((end) - (pos)),    \
				     ")");                               \
	}                                                                \
} while (0)

/**
 * SMD_INLINE_TS - wrapper for timestamps of type &struct smd_ts_ring
 */
#define SMD_INLINE_TS(pos, end, r) \
	__SMD_INLINE_TS(pos, end, r, (r).ts[_slot])

/**
 * SMD_INLINE_TS_DRV: wrapper for timestamps of type &struct nl80211_smd_ts_ring
 */
#define SMD_INLINE_TS_DRV(pos, end, r) \
	__SMD_INLINE_TS(pos, end, r, SMD_DRVTS2USR((r).ts[_slot]))

/* ---- Display macros (STA side / wpa_supplicant) ----------------------- */

/* Append "(reason1,reason2,...)" from a reason ring directly after a counter.
 * Writes nothing if the ring is empty. */
#define WPAS_DISP_REASONS(buf, len, buflen, ring, head, str_arr) do {    \
	int _i, _n = 0;                                                  \
	int _vals[SMD_REASON_SIZE];                                      \
	for (_i = 0; _i < SMD_REASON_SIZE; _i++) {                       \
		int _sl = ((int)(head) - 1 - _i +                       \
			   SMD_REASON_SIZE * 2) % SMD_REASON_SIZE;       \
		unsigned int _v = (unsigned int)(ring)[_sl];             \
		if (_v == 0) break;                                      \
		_vals[_n++] = (int)_v;                                   \
	}                                                                \
	if (_n > 0) {                                                    \
		int _r = os_snprintf((buf) + (len), (buflen) - (len),   \
				     "(");                               \
		if (_r > 0 && (size_t)_r < (buflen) - (len)) (len) += _r;\
		for (_i = 0; _i < _n; _i++) {                            \
			unsigned int _v = (unsigned int)_vals[_i];       \
			const char *_s = (_v < ARRAY_SIZE(str_arr))      \
					 ? (str_arr)[_v] : "?";          \
			_r = os_snprintf((buf) + (len), (buflen) - (len),\
					 "%s%s", _i ? "," : "", _s);    \
			if (_r > 0 && (size_t)_r < (buflen) - (len))    \
				(len) += _r;                             \
		}                                                        \
		_r = os_snprintf((buf) + (len), (buflen) - (len), ")"); \
		if (_r > 0 && (size_t)_r < (buflen) - (len)) (len) += _r;\
	}                                                                \
} while (0)

/**
 * __WPAS_DISP_TS - core body to write timestamps of different types
 * @buf: output buffer
 * @len: current write offset into buf
 * @buflen: total size of buf
 * @ring: ring entry
 * @ts_expr: expression that evaluates to a single timestamp for index _sl
 *
 * Appends "(ts1 ts2 ...)" newest-first directly after a counter value.
 * Writes nothing when the ring is empty.
 * Shared print core. ts_expr must evaluate to a u64 for index _sl.
 */
#define __WPAS_DISP_TS(buf, len, buflen, ring, ts_expr) do {             \
	if ((ring).count > 0) {                                          \
		int _i;                                                  \
		int _r = os_snprintf((buf) + (len), (buflen) - (len),   \
				     "(");                               \
		if (_r > 0 && (size_t)_r < (buflen) - (len)) (len) += _r;\
		for (_i = 0; _i < (ring).count; _i++) {                  \
			int _sl = ((int)(ring).head - 1 - _i +           \
				   SMD_TS_RING_SIZE * 2)                 \
				  % SMD_TS_RING_SIZE;                    \
			_r = os_snprintf((buf) + (len), (buflen) - (len),\
					 "%s%llu", _i ? " " : "",       \
					 (unsigned long long)(ts_expr)); \
			if (_r > 0 && (size_t)_r < (buflen) - (len))    \
				(len) += _r;                             \
		}                                                        \
		_r = os_snprintf((buf) + (len), (buflen) - (len), ")"); \
		if (_r > 0 && (size_t)_r < (buflen) - (len)) (len) += _r;\
	}                                                                \
} while (0)

/**
 * WPAS_DISP_TS - wrapper for timestamps of type &struct smd_ts_ring
 */
#define WPAS_DISP_TS(buf, len, buflen, ring) \
	__WPAS_DISP_TS(buf, len, buflen, ring, (ring).ts[_sl])

/**
 * WPAS_DISP_TS_DRV - wrapper for timestamps of type &struct nl80211_smd_ts_ring
 */
#define WPAS_DISP_TS_DRV(buf, len, buflen, ring) \
	__WPAS_DISP_TS(buf, len, buflen, ring, SMD_DRVTS2USR((ring).ts[_sl]))

/* Append a fixed string, advancing len. */
#define WPAS_DISP_W(buf, len, buflen, ...) do {                          \
	int _r = os_snprintf((buf) + (len), (buflen) - (len),           \
			     __VA_ARGS__);                               \
	if (_r > 0 && (size_t)_r < (buflen) - (len)) (len) += _r;      \
} while (0)

/* ---- AP-side archive lifecycle API ------------------------------------ */

/* Forward declarations — avoid pulling in full AP headers */
struct hapd_interfaces;
struct hostapd_data;
struct sta_info;

/* Fold departing STA's counters into the process-lifetime archive. */
void smd_fold_sta_roam_record(struct hostapd_data *hapd, struct sta_info *sta);

/* Free all archive records (called at process exit). */
void hostapd_interfaces_smd_archive_free(struct hapd_interfaces *interfaces);

/* Free archive records belonging to a specific AP MLD (called by SMD_STATS_RESET). */
void smd_archive_free_for_mld(struct hapd_interfaces *interfaces,
			      const u8 *ap_mld_addr);

/* Format SAP+TAP counters into a ctrl-iface reply buffer. */
void smd_write_sap_tap_stats(char **pos, char *end,
			     const struct smd_sap_roam_stats *sap,
			     const struct smd_tap_roam_stats *tap,
			     const struct nl80211_smd_stats *k);

#endif /* UHR_STATS_H */
