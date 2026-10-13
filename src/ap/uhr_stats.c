/*
 * SMD (Seamless Mobility Domain) roaming debug counter framework
 * AP-side implementation: archive lifecycle and display helpers.
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "utils/includes.h"
#include "utils/common.h"
#include "hostapd.h"
#include "sta_info.h"
#include "common/uhr_stats.h"

#ifdef CONFIG_IEEE80211BN

/* ---- Archive lifecycle ------------------------------------------------- */

void smd_fold_sta_roam_record(struct hostapd_data *hapd, struct sta_info *sta)
{
	struct hapd_interfaces *interfaces = hapd->iface->interfaces;
	struct smd_sta_roam_record *rec;
	const u8 *addr;

	if (!interfaces)
		return;

	/* Use MLD address as the record key so counters from any link
	 * are folded into the same record regardless of which link
	 * carried the PREP/EXEC frame. */
	if (sta->mld_info.mld_sta)
		addr = sta->mld_info.common_info.mld_addr;
	else
		addr = sta->addr;

	dl_list_for_each(rec, &interfaces->smd_sta_roam_records,
			 struct smd_sta_roam_record, list) {
		if (os_memcmp(rec->sta_mld_addr, addr, ETH_ALEN) != 0)
			continue;
		if (hapd->mld &&
		    os_memcmp(rec->ap_mld_addr, hapd->mld->mld_addr, ETH_ALEN) != 0)
			continue;
		goto found;
	}

	if (interfaces->smd_sta_roam_record_count >= interfaces->smd_sta_roam_max_records) {
		struct smd_sta_roam_record *oldest =
			dl_list_first(&interfaces->smd_sta_roam_records,
				      struct smd_sta_roam_record, list);
		dl_list_del(&oldest->list);
		os_free(oldest);
		interfaces->smd_sta_roam_record_count--;
	}

	rec = os_zalloc(sizeof(*rec));
	if (!rec)
		return;
	os_memcpy(rec->sta_mld_addr, addr, ETH_ALEN);
	if (hapd->mld)
		os_memcpy(rec->ap_mld_addr, hapd->mld->mld_addr, ETH_ALEN);
	dl_list_add_tail(&interfaces->smd_sta_roam_records, &rec->list);
	interfaces->smd_sta_roam_record_count++;

found:
	os_get_reltime(&rec->last_updated);

#define SAP_ACC(f) rec->sap.f += sta->smd_info.sap_stats.f
	SAP_ACC(sap_prep_req_rx);
	SAP_ACC(sap_prep_req_parse_fail);
	SAP_ACC(sap_prep_iap_sent);
	SAP_ACC(sap_prep_iap_send_fail);
	SAP_ACC(sap_prep_iap_timer_fail);
	SAP_ACC(sap_iap_prep_req_tx_fail);
	SAP_ACC(sap_iap_prep_resp_rx_ok);
	SAP_ACC(sap_iap_prep_resp_rx_fail);
	SAP_ACC(sap_prep_ota_resp_sent);
	SAP_ACC(sap_prep_ota_resp_fail);
	SAP_ACC(sap_prep_exec_timer_fail);
	SAP_ACC(sap_prep_clone_fail);
	SAP_ACC(sap_prep_iap_timeout);
	SAP_ACC(sap_prep_exec_timeout);
	SAP_ACC(sap_exec_req_rx);
	SAP_ACC(sap_exec_req_parse_fail);
	SAP_ACC(sap_exec_req_no_apinfo);
	SAP_ACC(sap_exec_req_bad_state);
	SAP_ACC(sap_exec_iap_sent);
	SAP_ACC(sap_exec_iap_send_fail);
	SAP_ACC(sap_exec_iap_timer_fail);
	SAP_ACC(sap_iap_exec_req_tx_fail);
	SAP_ACC(sap_iap_exec_resp_rx_ok);
	SAP_ACC(sap_iap_exec_resp_rx_fail);
	SAP_ACC(sap_exec_iap_resp_rx);
	SAP_ACC(sap_exec_ota_resp_sent);
	SAP_ACC(sap_exec_ota_resp_fail);
	SAP_ACC(sap_exec_drain_timer_fail);
	SAP_ACC(sap_exec_iap_timeout);
	SAP_ACC(dl_drain_started);
	SAP_ACC(dl_drain_no_sta);
	SAP_ACC(dl_drain_bad_state);
	SAP_ACC(dl_drain_complete);
	SAP_ACC(roam_success);
#undef SAP_ACC
	smd_ts_ring_merge(&rec->sap.sap_prep_iap_sent_ts,
			  &sta->smd_info.sap_stats.sap_prep_iap_sent_ts);
	smd_ts_ring_merge(&rec->sap.sap_iap_prep_resp_rx_ok_ts,
			  &sta->smd_info.sap_stats.sap_iap_prep_resp_rx_ok_ts);
	smd_ts_ring_merge(&rec->sap.sap_exec_iap_sent_ts,
			  &sta->smd_info.sap_stats.sap_exec_iap_sent_ts);
	smd_ts_ring_merge(&rec->sap.sap_iap_exec_resp_rx_ok_ts,
			  &sta->smd_info.sap_stats.sap_iap_exec_resp_rx_ok_ts);
	smd_ts_ring_merge(&rec->sap.sap_prep_exec_timeout_ts,
			  &sta->smd_info.sap_stats.sap_prep_exec_timeout_ts);
	smd_ts_ring_merge(&rec->sap.sap_exec_iap_timeout_ts,
			  &sta->smd_info.sap_stats.sap_exec_iap_timeout_ts);
	smd_ts_ring_merge(&rec->sap.roam_success_ts,
			  &sta->smd_info.sap_stats.roam_success_ts);

#define TAP_ACC(f) rec->tap.f += sta->smd_info.tap_stats.f
	TAP_ACC(tap_iap_prep_req_rx_ok);
	TAP_ACC(tap_iap_prep_req_rx_fail);
	TAP_ACC(tap_prep_iap_rx);
	TAP_ACC(tap_prep_ok);
	TAP_ACC(tap_prep_fail);
	TAP_ACC(tap_iap_prep_resp_tx_ok);
	TAP_ACC(tap_iap_prep_resp_tx_fail);
	TAP_ACC(tap_prep_timer_started);
	TAP_ACC(tap_prep_timer_start_fail);
	TAP_ACC(tap_prep_exec_timeout);
	TAP_ACC(tap_iap_exec_req_rx_ok);
	TAP_ACC(tap_iap_exec_req_rx_fail);
	TAP_ACC(tap_exec_ok);
	TAP_ACC(tap_exec_fail);
	TAP_ACC(ptk_install_ok);
	TAP_ACC(ptk_install_fail);
	TAP_ACC(gtk_install_ok);
	TAP_ACC(tap_iap_exec_resp_tx_ok);
	TAP_ACC(tap_iap_exec_resp_tx_fail);
	TAP_ACC(tap_exec_prep_timer_cancel_fail);
#undef TAP_ACC
	smd_ts_ring_merge(&rec->tap.tap_prep_ok_ts,
			  &sta->smd_info.tap_stats.tap_prep_ok_ts);
	smd_ts_ring_merge(&rec->tap.tap_exec_ok_ts,
			  &sta->smd_info.tap_stats.tap_exec_ok_ts);
	smd_ts_ring_merge(&rec->tap.tap_iap_prep_req_rx_ok_ts,
			  &sta->smd_info.tap_stats.tap_iap_prep_req_rx_ok_ts);
	smd_ts_ring_merge(&rec->tap.tap_iap_prep_resp_tx_ok_ts,
			  &sta->smd_info.tap_stats.tap_iap_prep_resp_tx_ok_ts);
	smd_ts_ring_merge(&rec->tap.tap_iap_exec_req_rx_ok_ts,
			  &sta->smd_info.tap_stats.tap_iap_exec_req_rx_ok_ts);
	smd_ts_ring_merge(&rec->tap.tap_iap_exec_resp_tx_ok_ts,
			  &sta->smd_info.tap_stats.tap_iap_exec_resp_tx_ok_ts);
}


void hostapd_interfaces_smd_archive_free(struct hapd_interfaces *interfaces)
{
	struct smd_sta_roam_record *rec, *tmp;

	if (!interfaces)
		return;

	dl_list_for_each_safe(rec, tmp, &interfaces->smd_sta_roam_records,
			      struct smd_sta_roam_record, list) {
		dl_list_del(&rec->list);
		os_free(rec);
	}
	interfaces->smd_sta_roam_record_count = 0;
}


void smd_archive_free_for_mld(struct hapd_interfaces *interfaces,
			      const u8 *ap_mld_addr)
{
	struct smd_sta_roam_record *rec, *tmp;

	if (!interfaces || !ap_mld_addr)
		return;

	dl_list_for_each_safe(rec, tmp, &interfaces->smd_sta_roam_records,
			      struct smd_sta_roam_record, list) {
		if (os_memcmp(rec->ap_mld_addr, ap_mld_addr, ETH_ALEN) != 0)
			continue;
		dl_list_del(&rec->list);
		os_free(rec);
		interfaces->smd_sta_roam_record_count--;
	}
}


/* ---- Display helpers --------------------------------------------------- */

static const char * const sap_prep_parse_fail_str[] = {
	[SAP_PREP_PARSE_FAIL_NONE]           = "NONE",
	[SAP_PREP_PARSE_FAIL_SHORT_FRAME]    = "SHORT_FRAME",
	[SAP_PREP_PARSE_FAIL_IE_PARSE]       = "IE_PARSE",
	[SAP_PREP_PARSE_FAIL_ML_IE]          = "ML_IE",
	[SAP_PREP_PARSE_FAIL_SBTE]           = "SBTE",
	[SAP_PREP_PARSE_FAIL_NO_TARGET_ADDR] = "NO_TARGET_ADDR",
	[SAP_PREP_PARSE_FAIL_ALLOC]          = "ALLOC",
};
static const char * const sap_prep_iap_fail_str[] = {
	[SAP_PREP_IAP_FAIL_NONE]             = "NONE",
	[SAP_PREP_IAP_FAIL_OUI_PEER_UNKNOWN] = "OUI_PEER_UNKNOWN",
	[SAP_PREP_IAP_FAIL_ENCRYPT]          = "ENCRYPT",
	[SAP_PREP_IAP_FAIL_TRANSPORT]        = "TRANSPORT",
};
static const char * const smd_iap_tx_fail_str[] = {
	[SMD_IAP_TX_FAIL_NONE]           = "NONE",
	[SMD_IAP_TX_FAIL_ENCRYPT]        = "ENCRYPT",
	[SMD_IAP_TX_FAIL_BUF_ALLOC]      = "BUF_ALLOC",
	[SMD_IAP_TX_FAIL_L2_SEND]        = "L2_SEND",
	[SMD_IAP_TX_FAIL_INVALID_PARAMS] = "INVALID_PARAMS",
	[SMD_IAP_TX_FAIL_FRAME_TOO_LARGE]= "FRAME_TOO_LARGE",
	[SMD_IAP_TX_FAIL_PEER_NOT_FOUND] = "PEER_NOT_FOUND",
	[SMD_IAP_TX_FAIL_NO_AP_INFO]     = "NO_AP_INFO",
	[SMD_IAP_TX_FAIL_ALLOC]          = "ALLOC",
	[SMD_IAP_TX_FAIL_SEC_CTX]        = "SEC_CTX",
};
static const char * const smd_iap_rx_fail_str[] = {
	[SMD_IAP_RX_FAIL_NONE]         = "NONE",
	[SMD_IAP_RX_FAIL_PEER_UNKNOWN] = "PEER_UNKNOWN",
	[SMD_IAP_RX_FAIL_DECRYPT]      = "DECRYPT",
	[SMD_IAP_RX_FAIL_UNKNOWN_TYPE] = "UNKNOWN_TYPE",
};
static const char * const sap_prep_resp_fail_str[] = {
	[SAP_PREP_RESP_FAIL_NONE]        = "NONE",
	[SAP_PREP_RESP_FAIL_LINK]        = "LINK",
	[SAP_PREP_RESP_FAIL_NO_STA]      = "NO_STA",
	[SAP_PREP_RESP_FAIL_NO_APINFO]   = "NO_APINFO",
	[SAP_PREP_RESP_FAIL_TAP_REJECTED]= "TAP_REJECTED",
	[SAP_PREP_RESP_FAIL_EMPTY_FRAME] = "EMPTY_FRAME",
	[SAP_PREP_RESP_FAIL_SHORT_FRAME] = "SHORT_FRAME",
	[SAP_PREP_RESP_FAIL_MLME]        = "MLME",
};
static const char * const sap_exec_parse_fail_str[] = {
	[SAP_EXEC_PARSE_FAIL_NONE]           = "NONE",
	[SAP_EXEC_PARSE_FAIL_SHORT_FRAME]    = "SHORT_FRAME",
	[SAP_EXEC_PARSE_FAIL_IE_PARSE]       = "IE_PARSE",
	[SAP_EXEC_PARSE_FAIL_ML_IE]          = "ML_IE",
	[SAP_EXEC_PARSE_FAIL_NO_TARGET_ADDR] = "NO_TARGET_ADDR",
};
static const char * const tap_prep_fail_str[] = {
	[TAP_PREP_FAIL_NONE]         = "NONE",
	[TAP_PREP_FAIL_FRAME_INVALID]= "FRAME_INVALID",
	[TAP_PREP_FAIL_FRAME_SHORT]  = "FRAME_SHORT",
	[TAP_PREP_FAIL_IE_PARSE]     = "IE_PARSE",
	[TAP_PREP_FAIL_NO_ML_IE]     = "NO_ML_IE",
	[TAP_PREP_FAIL_ML_PARSE]     = "ML_PARSE",
	[TAP_PREP_FAIL_NO_STA]       = "NO_STA",
	[TAP_PREP_FAIL_CTX_SET]      = "CTX_SET",
	[TAP_PREP_FAIL_ASSOC]        = "ASSOC",
	[TAP_PREP_FAIL_KEY_INSTALL]  = "KEY_INSTALL",
	[TAP_PREP_FAIL_IAP_SEND]     = "IAP_SEND",
};
static const char * const tap_exec_fail_str[] = {
	[TAP_EXEC_FAIL_NONE]         = "NONE",
	[TAP_EXEC_FAIL_STA_NOT_FOUND]= "STA_NOT_FOUND",
	[TAP_EXEC_FAIL_CTX_SET]      = "CTX_SET",
	[TAP_EXEC_FAIL_AUTH]         = "AUTH",
	[TAP_EXEC_FAIL_GROUP_KEY]    = "GROUP_KEY",
	[TAP_EXEC_FAIL_ALLOC]        = "ALLOC",
};
static const char * const sap_exec_resp_fail_str[] = {
	[SAP_EXEC_RESP_FAIL_NONE]        = "NONE",
	[SAP_EXEC_RESP_FAIL_LINK]        = "LINK",
	[SAP_EXEC_RESP_FAIL_NO_STA]      = "NO_STA",
	[SAP_EXEC_RESP_FAIL_NO_APINFO]   = "NO_APINFO",
	[SAP_EXEC_RESP_FAIL_BAD_STATE]   = "BAD_STATE",
	[SAP_EXEC_RESP_FAIL_TAP_REJECTED]= "TAP_REJECTED",
	[SAP_EXEC_RESP_FAIL_MLME]        = "MLME",
};

/* reason strings to capture rx_fail reasons at driver level */
static const char * const smd_drv_rx_fail_str[] = {
	[0] = "NONE",
	[1] = "STA_NOT_FOUND",
	[2] = "NOT_SMD_STA",
	[3] = "NOT_SERVING_AP",
	[4] = "NO_SMD_IE",
	[5] = "ALLOC",
};

/* reason strings to capture ctx collection failure */
static const char * const smd_drv_ctx_fail_str[] = {
	[0] = "NONE",
	[1] = "NO_HANDLER",
	[2] = "INFLIGHT_BLOCKED",
	[3] = "FW_HANG",
	[4] = "PEER_GONE",
	[5] = "SKB_EXT_ALLOC",
};

#ifdef CONFIG_ATH12K_SMD_DP_DEBUG
static void smd_write_ctx_snapshot(char **pos, char *end,
				   const char *label,
				   const struct nl80211_smd_ctx_snapshot *snap)
{
	unsigned int tid, b;

	if (!snap || !snap->valid)
		return;

	*pos += os_snprintf(*pos, (size_t)(end - *pos),
			    "  [ath12k-snap] %s: valid_ctx=0x%02x pn_len=%u\n",
			    label, snap->valid_ctx_bmap, snap->pn_len);

	*pos += os_snprintf(*pos, (size_t)(end - *pos), "    dl_sn:");
	for (tid = 0; tid < 8; tid++)
		*pos += os_snprintf(*pos, (size_t)(end - *pos), " %u", snap->dl_sn[tid]);
	*pos += os_snprintf(*pos, (size_t)(end - *pos), "\n");

	*pos += os_snprintf(*pos, (size_t)(end - *pos), "    dl_pn: ");
	for (b = 0; b < snap->pn_len && b < 16; b++)
		*pos += os_snprintf(*pos, (size_t)(end - *pos), "%02x", snap->dl_pn[b]);
	*pos += os_snprintf(*pos, (size_t)(end - *pos), "\n");

	*pos += os_snprintf(*pos, (size_t)(end - *pos), "    dl_ba_bufsz:");
	for (tid = 0; tid < 8; tid++)
		*pos += os_snprintf(*pos, (size_t)(end - *pos), " %u", snap->dl_ba_buf_size[tid]);
	*pos += os_snprintf(*pos, (size_t)(end - *pos), "\n");

	*pos += os_snprintf(*pos, (size_t)(end - *pos), "    ul_sn:");
	for (tid = 0; tid < 8; tid++)
		*pos += os_snprintf(*pos, (size_t)(end - *pos), " %u", snap->ul_sn[tid]);
	*pos += os_snprintf(*pos, (size_t)(end - *pos), "\n");

	for (tid = 0; tid < 8; tid++) {
		*pos += os_snprintf(*pos, (size_t)(end - *pos), "    ul_pn[%u]: ", tid);
		for (b = 0; b < snap->pn_len && b < 16; b++)
			*pos += os_snprintf(*pos, (size_t)(end - *pos), "%02x",
					    snap->ul_pn[tid][b]);
		*pos += os_snprintf(*pos, (size_t)(end - *pos), "\n");
	}

	*pos += os_snprintf(*pos, (size_t)(end - *pos), "    ul_ba_bufsz:");
	for (tid = 0; tid < 8; tid++)
		*pos += os_snprintf(*pos, (size_t)(end - *pos), " %u", snap->ul_ba_buf_size[tid]);
	*pos += os_snprintf(*pos, (size_t)(end - *pos), "\n");

	if (snap->vendor.version == 1) {
		*pos += os_snprintf(*pos, (size_t)(end - *pos),
				    "    vendor: dl_mgmt_sn=%u ul_mgmt_sn=%u\n",
				    snap->vendor.dl_mgmt_sn, snap->vendor.ul_mgmt_sn);
		*pos += os_snprintf(*pos, (size_t)(end - *pos), "    dl_lsn_off:");
		for (tid = 0; tid < 8; tid++)
			*pos += os_snprintf(*pos, (size_t)(end - *pos), " %u",
					    snap->vendor.dl_data_lsn_offset[tid]);
		*pos += os_snprintf(*pos, (size_t)(end - *pos), "\n");
	}
}
#endif /* CONFIG_ATH12K_SMD_DP_DEBUG */

void smd_write_sap_tap_stats(char **pos, char *end,
			     const struct smd_sap_roam_stats *sap,
			     const struct smd_tap_roam_stats *tap,
			     const struct nl80211_smd_stats *k)
{
	bool was_sap = sap->sap_prep_req_rx > 0;
	bool was_tap = tap->tap_iap_prep_req_rx_ok > 0;

	if (!was_sap && !was_tap) {
		*pos += os_snprintf(*pos, (size_t)(end - *pos),
				    "[no SMD activity recorded]\n");
		return;
	}

	/* ---- SAP role block ---- */
	if (was_sap) {
		*pos += os_snprintf(*pos, (size_t)(end - *pos), "[role: SAP]\n");
		*pos += os_snprintf(*pos, (size_t)(end - *pos), "--- PREP ---\n");

		/* [ath12k-rx]: OTA PREP frame received + context pipeline */
		if (k) {
			*pos += os_snprintf(*pos, (size_t)(end - *pos),
					    "  [ath12k-rx]   prep_rx=%u",
					    k->drv_sap_prep_rx);
			SMD_INLINE_TS_DRV(*pos, end, k->drv_ap_prep_rx_ts);
			*pos += os_snprintf(*pos, (size_t)(end - *pos),
					    "  prep_rx_fail=%u",
					    k->drv_sap_prep_rx_fail);
			if (k->drv_sap_prep_rx_fail)
				SMD_REASONS(*pos, end,
					    k->drv_sap_prep_rx_fail_reasons.reasons,
					    k->drv_sap_prep_rx_fail_reasons.head,
					    smd_drv_rx_fail_str);
			*pos += os_snprintf(*pos, (size_t)(end - *pos), "\n");
			*pos += os_snprintf(*pos, (size_t)(end - *pos),
					    "               prep_ctx_queued=%u"
					    "  prep_ctx_cache_hit=%u"
					    "  prep_ctx_fail=%u",
					    k->drv_sap_prep_ctx_queued,
					    k->drv_sap_prep_ctx_cache_hit,
					    k->drv_sap_prep_ctx_fail);
			if (k->drv_sap_prep_ctx_fail)
				SMD_REASONS(*pos, end,
					    k->drv_sap_prep_ctx_fail_reasons.reasons,
					    k->drv_sap_prep_ctx_fail_reasons.head,
					    smd_drv_ctx_fail_str);
			*pos += os_snprintf(*pos, (size_t)(end - *pos), "\n");
			*pos += os_snprintf(*pos, (size_t)(end - *pos),
					    "               prep_ctx_rx_ni_called=%u",
					    k->drv_sap_prep_ctx_rx_ni_called);
			SMD_INLINE_TS_DRV(*pos, end, k->drv_ap_prep_ctx_rx_ni_called_ts);
			*pos += os_snprintf(*pos, (size_t)(end - *pos), "\n");
			*pos += os_snprintf(*pos, (size_t)(end - *pos),
					    "               prep_ctx_rx_tid ok=0x%08x"
					    "  fail=0x%08x"
					    "  tx_tid ok=0x%04x  fail=0x%04x\n",
					    k->drv_sap_prep_ctx_rx_tid_ok_bmap,
					    k->drv_sap_prep_ctx_rx_tid_fail_bmap,
					    k->drv_sap_prep_ctx_tx_tid_ok_bmap,
					    k->drv_sap_prep_ctx_tx_tid_fail_bmap);
#ifdef CONFIG_ATH12K_SMD_DP_DEBUG
			smd_write_ctx_snapshot(pos, end, "SAP-PREP", &k->sap_prep_ctx);
#endif /* CONFIG_ATH12K_SMD_DP_DEBUG */
		}

		/* [mac80211-rx]: frame delivered to hostapd */
		if (k) {
			*pos += os_snprintf(*pos, (size_t)(end - *pos),
					    "  [mac80211-rx] prep_delivered_with_ctx=%u"
					    "  prep_delivered_no_ctx=%u"
					    "  prep_delivery_fail=%u\n",
					    k->mac_ap_prep_delivered_with_ctx,
					    k->mac_ap_prep_delivered_no_ctx,
					    k->mac_ap_prep_delivery_fail);
		}

		/* [hapd-parse]: hostapd validates OTA PREP request */
		*pos += os_snprintf(*pos, (size_t)(end - *pos),
				    "  [hapd-parse]  sap_prep_req_rx=%u"
				    "  sap_prep_req_parse_fail=%u",
				    sap->sap_prep_req_rx,
				    sap->sap_prep_req_parse_fail);
		SMD_REASONS(*pos, end, sap->sap_prep_parse_fail_reasons,
			    sap->sap_prep_parse_fail_reasons_head,
			    sap_prep_parse_fail_str);
		*pos += os_snprintf(*pos, (size_t)(end - *pos), "\n");

		/* [hapd-iap tx]: SAP sends IAP PREP request to TAP */
		*pos += os_snprintf(*pos, (size_t)(end - *pos),
				    "  [hapd-iap tx] sap_prep_iap_sent=%u",
				    sap->sap_prep_iap_sent);
		SMD_INLINE_TS(*pos, end, sap->sap_prep_iap_sent_ts);
		*pos += os_snprintf(*pos, (size_t)(end - *pos),
				    "  sap_prep_iap_send_fail=%u",
				    sap->sap_prep_iap_send_fail);
		SMD_REASONS(*pos, end, sap->sap_prep_iap_fail_reasons,
			    sap->sap_prep_iap_fail_reasons_head,
			    sap_prep_iap_fail_str);
		*pos += os_snprintf(*pos, (size_t)(end - *pos),
				    "  sap_iap_prep_req_tx_fail=%u",
				    sap->sap_iap_prep_req_tx_fail);
		SMD_REASONS(*pos, end, sap->sap_iap_prep_req_tx_fail_reasons,
			    sap->sap_iap_prep_req_tx_fail_reasons_head,
			    smd_iap_tx_fail_str);
		*pos += os_snprintf(*pos, (size_t)(end - *pos), "\n");

		/* [hapd-iap rx]: SAP receives IAP PREP response from TAP */
		*pos += os_snprintf(*pos, (size_t)(end - *pos),
				    "  [hapd-iap rx] sap_iap_prep_resp_rx_ok=%u",
				    sap->sap_iap_prep_resp_rx_ok);
		SMD_INLINE_TS(*pos, end, sap->sap_iap_prep_resp_rx_ok_ts);
		*pos += os_snprintf(*pos, (size_t)(end - *pos),
				    "  sap_iap_prep_resp_rx_fail=%u",
				    sap->sap_iap_prep_resp_rx_fail);
		SMD_REASONS(*pos, end, sap->sap_iap_prep_resp_rx_fail_reasons,
			    sap->sap_iap_prep_resp_rx_fail_reasons_head,
			    smd_iap_rx_fail_str);
		*pos += os_snprintf(*pos, (size_t)(end - *pos), "\n");

		/* [hapd-ota tx]: SAP sends OTA PREP response to STA */
		*pos += os_snprintf(*pos, (size_t)(end - *pos),
				    "  [hapd-ota tx] sap_prep_ota_resp_sent=%u",
				    sap->sap_prep_ota_resp_sent);
		*pos += os_snprintf(*pos, (size_t)(end - *pos),
				    "  sap_prep_ota_resp_fail=%u",
				    sap->sap_prep_ota_resp_fail);
		SMD_REASONS(*pos, end, sap->sap_prep_resp_fail_reasons,
			    sap->sap_prep_resp_fail_reasons_head,
			    sap_prep_resp_fail_str);
		*pos += os_snprintf(*pos, (size_t)(end - *pos), "\n");
		if (k) {
			*pos += os_snprintf(*pos, (size_t)(end - *pos),
					    "  [ath12k-tx]   prep_resp_wmi_send_ok=%u",
					    k->drv_sap_prep_resp_wmi_send_ok);
			SMD_INLINE_TS_DRV(*pos, end, k->drv_sap_prep_resp_wmi_send_ok_ts);
			*pos += os_snprintf(*pos, (size_t)(end - *pos), "\n");
		}

		/* [hapd-timer]: PREP phase timers */
		*pos += os_snprintf(*pos, (size_t)(end - *pos),
				    "  [hapd-timer] sap_prep_iap_timeout=%u"
				    "  sap_prep_exec_timeout=%u",
				    sap->sap_prep_iap_timeout,
				    sap->sap_prep_exec_timeout);
		SMD_INLINE_TS(*pos, end, sap->sap_prep_exec_timeout_ts);
		*pos += os_snprintf(*pos, (size_t)(end - *pos), "\n");

		*pos += os_snprintf(*pos, (size_t)(end - *pos), "--- EXEC ---\n");

		/* [ath12k-rx]: OTA EXEC frame received + context pipeline */
		if (k) {
			*pos += os_snprintf(*pos, (size_t)(end - *pos),
					    "  [ath12k-rx]   exec_rx=%u",
					    k->drv_sap_exec_rx);
			SMD_INLINE_TS_DRV(*pos, end, k->drv_ap_exec_rx_ts);
			*pos += os_snprintf(*pos, (size_t)(end - *pos),
					    "  exec_rx_fail=%u",
					    k->drv_sap_exec_rx_fail);
			if (k->drv_sap_exec_rx_fail)
				SMD_REASONS(*pos, end,
					    k->drv_sap_exec_rx_fail_reasons.reasons,
					    k->drv_sap_exec_rx_fail_reasons.head,
					    smd_drv_rx_fail_str);
			*pos += os_snprintf(*pos, (size_t)(end - *pos), "\n");
			*pos += os_snprintf(*pos, (size_t)(end - *pos),
					    "               exec_ctx_queued=%u"
					    "  exec_ctx_fail=%u",
					    k->drv_sap_exec_ctx_queued,
					    k->drv_sap_exec_ctx_fail);
			if (k->drv_sap_exec_ctx_fail)
				SMD_REASONS(*pos, end,
					    k->drv_sap_exec_ctx_fail_reasons.reasons,
					    k->drv_sap_exec_ctx_fail_reasons.head,
					    smd_drv_ctx_fail_str);
			*pos += os_snprintf(*pos, (size_t)(end - *pos), "\n");
			*pos += os_snprintf(*pos, (size_t)(end - *pos),
					    "               exec_ctx_rx_ni_called=%u",
					    k->drv_sap_exec_ctx_rx_ni_called);
			SMD_INLINE_TS_DRV(*pos, end, k->drv_ap_exec_ctx_rx_ni_called_ts);
			*pos += os_snprintf(*pos, (size_t)(end - *pos), "\n");
			*pos += os_snprintf(*pos, (size_t)(end - *pos),
					    "               exec_ctx_rx_tid ok=0x%08x"
					    "  fail=0x%08x"
					    "  tx_tid ok=0x%04x  fail=0x%04x\n",
					    k->drv_sap_exec_ctx_rx_tid_ok_bmap,
					    k->drv_sap_exec_ctx_rx_tid_fail_bmap,
					    k->drv_sap_exec_ctx_tx_tid_ok_bmap,
					    k->drv_sap_exec_ctx_tx_tid_fail_bmap);
#ifdef CONFIG_ATH12K_SMD_DP_DEBUG
			smd_write_ctx_snapshot(pos, end, "SAP-EXEC", &k->sap_exec_ctx);
#endif /* CONFIG_ATH12K_SMD_DP_DEBUG */
		}

		/* [mac80211-rx]: frame delivered to hostapd */
		if (k) {
			*pos += os_snprintf(*pos, (size_t)(end - *pos),
					    "  [mac80211-rx] exec_delivered_with_ctx=%u"
					    "  exec_delivered_no_ctx=%u"
					    "  exec_delivery_fail=%u\n",
					    k->mac_ap_exec_delivered_with_ctx,
					    k->mac_ap_exec_delivered_no_ctx,
					    k->mac_ap_exec_delivery_fail);
		}

		/* [hapd-parse]: hostapd validates OTA EXEC request */
		*pos += os_snprintf(*pos, (size_t)(end - *pos),
				    "  [hapd-parse]  sap_exec_req_rx=%u"
				    "  sap_exec_req_parse_fail=%u"
				    "  sap_exec_req_no_apinfo=%u"
				    "  sap_exec_req_bad_state=%u",
				    sap->sap_exec_req_rx,
				    sap->sap_exec_req_parse_fail,
				    sap->sap_exec_req_no_apinfo,
				    sap->sap_exec_req_bad_state);
		SMD_REASONS(*pos, end, sap->sap_exec_parse_fail_reasons,
			    sap->sap_exec_parse_fail_reasons_head,
			    sap_exec_parse_fail_str);
		*pos += os_snprintf(*pos, (size_t)(end - *pos), "\n");

		/* [hapd-iap tx]: SAP sends IAP EXEC request to TAP */
		*pos += os_snprintf(*pos, (size_t)(end - *pos),
				    "  [hapd-iap tx] sap_exec_iap_sent=%u",
				    sap->sap_exec_iap_sent);
		SMD_INLINE_TS(*pos, end, sap->sap_exec_iap_sent_ts);
		*pos += os_snprintf(*pos, (size_t)(end - *pos),
				    "  sap_exec_iap_send_fail=%u"
				    "  sap_iap_exec_req_tx_fail=%u",
				    sap->sap_exec_iap_send_fail,
				    sap->sap_iap_exec_req_tx_fail);
		SMD_REASONS(*pos, end, sap->sap_iap_exec_req_tx_fail_reasons,
			    sap->sap_iap_exec_req_tx_fail_reasons_head,
			    smd_iap_tx_fail_str);
		*pos += os_snprintf(*pos, (size_t)(end - *pos), "\n");

		/* [hapd-iap rx]: SAP receives IAP EXEC response from TAP */
		*pos += os_snprintf(*pos, (size_t)(end - *pos),
				    "  [hapd-iap rx] sap_iap_exec_resp_rx_ok=%u",
				    sap->sap_iap_exec_resp_rx_ok);
		SMD_INLINE_TS(*pos, end, sap->sap_iap_exec_resp_rx_ok_ts);
		*pos += os_snprintf(*pos, (size_t)(end - *pos),
				    "  sap_iap_exec_resp_rx_fail=%u",
				    sap->sap_iap_exec_resp_rx_fail);
		SMD_REASONS(*pos, end, sap->sap_iap_exec_resp_rx_fail_reasons,
			    sap->sap_iap_exec_resp_rx_fail_reasons_head,
			    smd_iap_rx_fail_str);
		*pos += os_snprintf(*pos, (size_t)(end - *pos), "\n");

		/* [hapd-ota tx]: SAP sends OTA EXEC response to STA */
		*pos += os_snprintf(*pos, (size_t)(end - *pos),
				    "  [hapd-ota tx] sap_exec_ota_resp_sent=%u",
				    sap->sap_exec_ota_resp_sent);
		*pos += os_snprintf(*pos, (size_t)(end - *pos),
				    "  sap_exec_ota_resp_fail=%u",
				    sap->sap_exec_ota_resp_fail);
		SMD_REASONS(*pos, end, sap->sap_exec_resp_fail_reasons,
			    sap->sap_exec_resp_fail_reasons_head,
			    sap_exec_resp_fail_str);
		*pos += os_snprintf(*pos, (size_t)(end - *pos), "\n");
		if (k) {
			*pos += os_snprintf(*pos, (size_t)(end - *pos),
					    "  [ath12k-tx]   exec_resp_wmi_send_ok=%u",
					    k->drv_sap_exec_resp_wmi_send_ok);
			SMD_INLINE_TS_DRV(*pos, end, k->drv_sap_exec_resp_wmi_send_ok_ts);
			*pos += os_snprintf(*pos, (size_t)(end - *pos), "\n");
		}

		/* [hapd-timer]: EXEC phase timer */
		*pos += os_snprintf(*pos, (size_t)(end - *pos),
				    "  [hapd-timer] sap_exec_iap_timeout=%u",
				    sap->sap_exec_iap_timeout);
		SMD_INLINE_TS(*pos, end, sap->sap_exec_iap_timeout_ts);
		*pos += os_snprintf(*pos, (size_t)(end - *pos), "\n");

		/* [hapd-drain]: downlink drain before handoff */
		*pos += os_snprintf(*pos, (size_t)(end - *pos),
				    "  [hapd-drain] dl_drain_started=%u"
				    "  dl_drain_complete=%u"
				    "  dl_drain_bad_state=%u\n",
				    sap->dl_drain_started,
				    sap->dl_drain_complete,
				    sap->dl_drain_bad_state);

		*pos += os_snprintf(*pos, (size_t)(end - *pos), "--- OUTCOME ---\n");
		*pos += os_snprintf(*pos, (size_t)(end - *pos),
				    "  roam_success=%u",
				    sap->roam_success);
		SMD_INLINE_TS(*pos, end, sap->roam_success_ts);
		*pos += os_snprintf(*pos, (size_t)(end - *pos), "\n");
		if (k) {
			*pos += os_snprintf(*pos, (size_t)(end - *pos),
					    "  [bridge]    drv_sap_fdb_event_rx=%u",
					    k->drv_sap_fdb_event_rx);
			SMD_INLINE_TS_DRV(*pos, end, k->drv_sap_fdb_event_rx_ts);
			*pos += os_snprintf(*pos, (size_t)(end - *pos), "\n");
		}
	} else {
		*pos += os_snprintf(*pos, (size_t)(end - *pos),
				    "[role: SAP - not serving AP for this STA]\n");
	}

	/* ---- TAP role block ---- */
	if (was_tap) {
		*pos += os_snprintf(*pos, (size_t)(end - *pos), "[role: TAP]\n");
		*pos += os_snprintf(*pos, (size_t)(end - *pos), "--- PREP ---\n");

		/* [hapd-iap rx]: TAP receives IAP PREP request from SAP */
		*pos += os_snprintf(*pos, (size_t)(end - *pos),
				    "  [hapd-iap rx] tap_iap_prep_req_rx_ok=%u",
				    tap->tap_iap_prep_req_rx_ok);
		SMD_INLINE_TS(*pos, end, tap->tap_iap_prep_req_rx_ok_ts);
		*pos += os_snprintf(*pos, (size_t)(end - *pos),
				    "  tap_iap_prep_req_rx_fail=%u",
				    tap->tap_iap_prep_req_rx_fail);
		SMD_REASONS(*pos, end, tap->tap_iap_prep_req_rx_fail_reasons,
			    tap->tap_iap_prep_req_rx_fail_reasons_head,
			    smd_iap_rx_fail_str);
		*pos += os_snprintf(*pos, (size_t)(end - *pos), "\n");

		/* [hapd-key]: MLD-level PTK installed during ML parse */
		*pos += os_snprintf(*pos, (size_t)(end - *pos),
				    "  [hapd-key]    ptk_install_ok=%u"
				    "  ptk_install_fail=%u\n",
				    tap->ptk_install_ok,
				    tap->ptk_install_fail);

		/* [ath12k-ctx]: per-TID context installed in driver (PREP phase) */
		if (k) {
			*pos += os_snprintf(*pos, (size_t)(end - *pos),
					    "  [ath12k-ctx]  tap_prep_ctx_rx_tid ok=0x%08x"
					    "  fail=0x%08x\n"
					    "                tap_prep_ctx_tx_tid ok=0x%04x"
					    "  fail=0x%04x\n"
					    "                tap_ctx_vendor_ok=%u"
					    "  tap_ctx_vendor_fail=%u\n",
					    k->drv_tap_prep_ctx_rx_tid_ok_bmap,
					    k->drv_tap_prep_ctx_rx_tid_fail_bmap,
					    k->drv_tap_prep_ctx_tx_tid_ok_bmap,
					    k->drv_tap_prep_ctx_tx_tid_fail_bmap,
					    k->drv_tap_ctx_vendor_ok,
					    k->drv_tap_ctx_vendor_fail);
#ifdef CONFIG_ATH12K_SMD_DP_DEBUG
			smd_write_ctx_snapshot(pos, end, "TAP-PREP", &k->tap_prep_ctx);
#endif /* CONFIG_ATH12K_SMD_DP_DEBUG */
		}

		/* [hapd-iap tx]: TAP sends IAP PREP response to SAP */
		*pos += os_snprintf(*pos, (size_t)(end - *pos),
				    "  [hapd-iap tx] tap_iap_prep_resp_tx_ok=%u",
				    tap->tap_iap_prep_resp_tx_ok);
		SMD_INLINE_TS(*pos, end, tap->tap_iap_prep_resp_tx_ok_ts);
		*pos += os_snprintf(*pos, (size_t)(end - *pos),
				    "  tap_iap_prep_resp_tx_fail=%u",
				    tap->tap_iap_prep_resp_tx_fail);
		SMD_REASONS(*pos, end, tap->tap_iap_prep_resp_tx_fail_reasons,
			    tap->tap_iap_prep_resp_tx_fail_reasons_head,
			    smd_iap_tx_fail_str);
		*pos += os_snprintf(*pos, (size_t)(end - *pos), "\n");

		/* [hapd-proc]: TAP marks PREP complete */
		*pos += os_snprintf(*pos, (size_t)(end - *pos),
				    "  [hapd-proc]   tap_prep_ok=%u",
				    tap->tap_prep_ok);
		SMD_INLINE_TS(*pos, end, tap->tap_prep_ok_ts);
		*pos += os_snprintf(*pos, (size_t)(end - *pos),
				    "  tap_prep_fail=%u",
				    tap->tap_prep_fail);
		SMD_REASONS(*pos, end, tap->tap_prep_fail_reasons,
			    tap->tap_prep_fail_reasons_head,
			    tap_prep_fail_str);
		*pos += os_snprintf(*pos, (size_t)(end - *pos), "\n");

		/* [hapd-timer]: PREP exec window timeout */
		*pos += os_snprintf(*pos, (size_t)(end - *pos),
				    "  [hapd-timer] tap_prep_exec_timeout=%u\n",
				    tap->tap_prep_exec_timeout);

		*pos += os_snprintf(*pos, (size_t)(end - *pos), "--- EXEC ---\n");

		/* [hapd-iap rx]: TAP receives IAP EXEC request from SAP */
		*pos += os_snprintf(*pos, (size_t)(end - *pos),
				    "  [hapd-iap rx] tap_iap_exec_req_rx_ok=%u",
				    tap->tap_iap_exec_req_rx_ok);
		SMD_INLINE_TS(*pos, end, tap->tap_iap_exec_req_rx_ok_ts);
		*pos += os_snprintf(*pos, (size_t)(end - *pos),
				    "  tap_iap_exec_req_rx_fail=%u",
				    tap->tap_iap_exec_req_rx_fail);
		SMD_REASONS(*pos, end, tap->tap_iap_exec_req_rx_fail_reasons,
			    tap->tap_iap_exec_req_rx_fail_reasons_head,
			    smd_iap_rx_fail_str);
		*pos += os_snprintf(*pos, (size_t)(end - *pos), "\n");

		/* [hapd-key]: GTK delivered in EXEC response */
		*pos += os_snprintf(*pos, (size_t)(end - *pos),
				    "  [hapd-key]    gtk_install_ok=%u\n",
				    tap->gtk_install_ok);

		/* [ath12k-ctx]: per-TID context installed in driver (EXEC phase) */
		if (k) {
			*pos += os_snprintf(*pos, (size_t)(end - *pos),
					    "  [ath12k-ctx]  tap_exec_ctx_rx_tid ok=0x%08x"
					    "  fail=0x%08x\n"
					    "                tap_exec_ctx_tx_tid ok=0x%04x"
					    "  fail=0x%04x\n",
					    k->drv_tap_exec_ctx_rx_tid_ok_bmap,
					    k->drv_tap_exec_ctx_rx_tid_fail_bmap,
					    k->drv_tap_exec_ctx_tx_tid_ok_bmap,
					    k->drv_tap_exec_ctx_tx_tid_fail_bmap);
#ifdef CONFIG_ATH12K_SMD_DP_DEBUG
			smd_write_ctx_snapshot(pos, end, "TAP-EXEC", &k->tap_exec_ctx);
#endif /* CONFIG_ATH12K_SMD_DP_DEBUG */
		}

		/* [hapd-proc]: TAP marks EXEC complete */
		*pos += os_snprintf(*pos, (size_t)(end - *pos),
				    "  [hapd-proc]   tap_exec_ok=%u",
				    tap->tap_exec_ok);
		SMD_INLINE_TS(*pos, end, tap->tap_exec_ok_ts);
		*pos += os_snprintf(*pos, (size_t)(end - *pos),
				    "  tap_exec_fail=%u",
				    tap->tap_exec_fail);
		SMD_REASONS(*pos, end, tap->tap_exec_fail_reasons,
			    tap->tap_exec_fail_reasons_head,
			    tap_exec_fail_str);
		*pos += os_snprintf(*pos, (size_t)(end - *pos), "\n");

		/* [hapd-iap tx]: TAP sends IAP EXEC response to SAP */
		*pos += os_snprintf(*pos, (size_t)(end - *pos),
				    "  [hapd-iap tx] tap_iap_exec_resp_tx_ok=%u",
				    tap->tap_iap_exec_resp_tx_ok);
		SMD_INLINE_TS(*pos, end, tap->tap_iap_exec_resp_tx_ok_ts);
		*pos += os_snprintf(*pos, (size_t)(end - *pos),
				    "  tap_iap_exec_resp_tx_fail=%u",
				    tap->tap_iap_exec_resp_tx_fail);
		SMD_REASONS(*pos, end, tap->tap_iap_exec_resp_tx_fail_reasons,
			    tap->tap_iap_exec_resp_tx_fail_reasons_head,
			    smd_iap_tx_fail_str);
		*pos += os_snprintf(*pos, (size_t)(end - *pos), "\n");

		*pos += os_snprintf(*pos, (size_t)(end - *pos), "--- OUTCOME ---\n");
		*pos += os_snprintf(*pos, (size_t)(end - *pos),
				    "  tap_exec_ok=%u",
				    tap->tap_exec_ok);
		SMD_INLINE_TS(*pos, end, tap->tap_exec_ok_ts);
		*pos += os_snprintf(*pos, (size_t)(end - *pos), "\n");
		if (k) {
			*pos += os_snprintf(*pos, (size_t)(end - *pos),
					    "  [mac80211]  mac_ap_l2_update_sent=%u",
					    k->mac_ap_l2_update_sent);
			SMD_INLINE_TS_DRV(*pos, end, k->mac_ap_l2_update_sent_ts);
			*pos += os_snprintf(*pos, (size_t)(end - *pos), "\n");
		}
	} else {
		*pos += os_snprintf(*pos, (size_t)(end - *pos),
				    "[role: TAP - not target AP for this STA]\n");
	}
}

#endif /* CONFIG_IEEE80211BN */
