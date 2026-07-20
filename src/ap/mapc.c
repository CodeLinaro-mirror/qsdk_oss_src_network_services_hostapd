/*
 * hostapd / Multi-AP Coordination (MAPC) - IEEE 802.11bn
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"
#include "utils/common.h"
#include "utils/eloop.h"
#include "utils/wpabuf.h"
#include "common/ieee802_11_defs.h"
#include "common/qca-vendor.h"
#include "sta_info.h"
#include "ap_drv_ops.h"
#include "ieee802_11.h"
#include "mapc.h"

/* Capability bit for each scheme type (matches MAPC_CAPABILITY_* defines) */
static const u8 mapc_scheme_cap_bit[MAPC_SCHEME_MAX] = {
	[MAPC_SCHEME_CO_BF]   = MAPC_CAPABILITY_COBF_SUPPORT,
	[MAPC_SCHEME_CO_SR]   = MAPC_CAPABILITY_COSR_SUPPORT,
	[MAPC_SCHEME_CO_TDMA] = MAPC_CAPABILITY_COTDMA_SUPPORT,
	[MAPC_SCHEME_CO_RTWT] = MAPC_CAPABILITY_CORTWT_SUPPORT,
	[MAPC_SCHEME_CO_CR]   = MAPC_CAPABILITY_COCR_SUPPORT,
};

/* Parameter enable bit for each scheme type (matches MAPC_PARAMETER_* defines) */
static const u8 mapc_scheme_param_bit[MAPC_SCHEME_MAX] = {
	[MAPC_SCHEME_CO_BF]   = MAPC_PARAMETER_COBF_ENABLED,
	[MAPC_SCHEME_CO_SR]   = MAPC_PARAMETER_COSR_ENABLED,
	[MAPC_SCHEME_CO_TDMA] = MAPC_PARAMETER_COTDMA_ENABLED,
	[MAPC_SCHEME_CO_RTWT] = MAPC_PARAMETER_CORTWT_ENABLED,
	[MAPC_SCHEME_CO_CR]   = MAPC_PARAMETER_COCR_ENABLED,
};

/* Maximum agreements per scheme per peer (IEEE P802.11bn §37.14.1.3.2.2).*/
static const u8 mapc_scheme_max_agr[MAPC_SCHEME_MAX] = {
	[MAPC_SCHEME_CO_BF]   = 1,
	[MAPC_SCHEME_CO_SR]   = 1,
	[MAPC_SCHEME_CO_TDMA] = 1,
	[MAPC_SCHEME_CO_RTWT] = 0,
	[MAPC_SCHEME_CO_CR]   = 0,
};
static int  cotdma_build_scheme_ap_param_set(struct wpabuf *buf,
					     const struct hostapd_data *hapd);
static int  cotdma_parse_scheme_profile(const u8 *body, size_t len,
					struct sta_info *sta);
static bool cotdma_accept_criteria(const struct hostapd_data *hapd,
				   const struct sta_info *sta);
static void cotdma_fill_peer_params(const struct sta_info *sta,
				    struct mapc_parameters *params);
static bool cotdma_has_params_changed(const struct hostapd_data *hapd,
				      const struct sta_info *sta);

static const struct mapc_scheme_ops mapc_cotdma_ops = {
	.scheme_type               = MAPC_SCHEME_CO_TDMA,
	.name                      = "Co-TDMA",
	.build_scheme_ap_param_set = cotdma_build_scheme_ap_param_set,
	.parse_scheme_profile      = cotdma_parse_scheme_profile,
	.accept_criteria           = cotdma_accept_criteria,
	.fill_peer_params          = cotdma_fill_peer_params,
	.has_params_changed        = cotdma_has_params_changed,
};

static const struct mapc_scheme_ops *mapc_scheme_ops_register[] = {
	&mapc_cotdma_ops,
	NULL, /* Co-BF: future */
	NULL, /* Co-SR: future */
};

static void mapc_snapshot_local_cotdma(const struct hostapd_data *hapd,
					struct sta_info *sta);
static void mapc_inactivity_cb(void *eloop_data, void *user_data);
static void mapc_negotiation_timeout_cb(void *eloop_data, void *user_data);
static void mapc_delete_active_peer(struct hostapd_data *hapd,
				    struct sta_info *sta);

static bool mapc_dialog_token_in_use(struct hostapd_data *hapd, u8 token)
{
	struct mapc_discovery_req *req;
	dl_list_for_each(req, &hapd->mapc_discovery_reqs,
					 struct mapc_discovery_req, list) {
		if (req->dialog_token == token)
			return true;
	}
	return false;
}

static u8 mapc_alloc_dialog_token(struct hostapd_data *hapd)
{
	u8 token;
	int tries = 0;

	do {
		hapd->mapc_dialog_token_count++;
		if (hapd->mapc_dialog_token_count == 0)
			hapd->mapc_dialog_token_count = 1;
		token = hapd->mapc_dialog_token_count;
		tries++;
	} while (tries < 255 && mapc_dialog_token_in_use(hapd, token));

	/* All 255 slots in use — return 0 so callers can detect exhaustion. */
	if (mapc_dialog_token_in_use(hapd, token))
		return 0;

	return token;
}

static void mapc_release_aid(struct hostapd_data *hapd, struct sta_info *sta)
{
	if (!sta || sta->aid == 0)
		return;
	hapd->sta_aid[sta->aid / 32] &= ~BIT(sta->aid % 32);
	sta->aid = 0;
	sta->mapc_params.apid = 0;
}


/*
 * mapc_check_cotdma_disallow - Returns true when Co-TDMA new-agreement requests should
 * be blocked.
 */
static bool mapc_check_cotdma_disallow(const struct hostapd_data *hapd)
{
	const struct hostapd_iface   *iface = hapd->iface;
	const struct mapc_bss_config *mapc_conf    = hapd->conf->mapc_conf;

	if (!mapc_conf)
		return true;

	/* Gate 1: global limit.
	 * 0 means no reported limit yet — treat as no limit (pass),
	 * consistent with mapc_check_co_ordination_allow() Gate 1 semantics. */
	if (iface->mapc_max_ctdma_peers > 0 &&
	    iface->mapc_cotdma_active_count >= iface->mapc_max_ctdma_peers)
		return true;

	/* Gate 2: per-BSS operator ceiling — 0 means disabled for this BSS */
	if (mapc_conf->max_mapc_ctdma_peer == 0)
		return true;
	if (hapd->bss_cotdma_active_count >= mapc_conf->max_mapc_ctdma_peer)
		return true;

	return false;
}

/*
 * mapc_check_co_ordination_allow - Returns true when promoting a new ACTIVE peer
 * should be blocked due to the coordinating-AP peer limit being reached.
 */
static bool mapc_check_co_ordination_allow(const struct hostapd_data *hapd)
{
	const struct hostapd_iface   *iface = hapd->iface;
	const struct mapc_bss_config *mapc_conf    = hapd->conf->mapc_conf;

	if (!mapc_conf)
		return true; /* no config — treat as disabled */

	if (mapc_conf->max_mapc_co_ap_peer == 0)
		return true;
	if (hapd->bss_active_peer_count >= (u16)mapc_conf->max_mapc_co_ap_peer)
		return true;

	return false;
}


static struct sta_info *
mapc_create_discovered_peer(struct hostapd_data *hapd, const u8 *peer_bssid)
{
	struct sta_info *sta;
	struct mapc_bss_config *mapc_conf = hapd->conf->mapc_conf;

	if (hapd->mapc_discovered_ap_count >= (u16)mapc_conf->max_mapc_discovered_ap_peer) {
		wpa_printf(MSG_INFO,
			   "MAPC: DISCOVERED cap (%d) reached, dropping " MACSTR,
			   hapd->mapc_discovered_ap_count, MAC2STR(peer_bssid));
		return NULL;
	}

	sta = ap_sta_add(hapd, peer_bssid);
	if (!sta) {
		wpa_printf(MSG_ERROR, "MAPC: ap_sta_add failed for " MACSTR,
			   MAC2STR(peer_bssid));
		return NULL;
	}

	sta->is_mapc_peer = true;
	sta->mapc_params.peer_state = MAPC_PEER_STATE_DISCOVERED;
	eloop_cancel_timeout(ap_handle_timer, hapd, sta);
	ap_sta_clear_assoc_timeout(hapd, sta);
	hapd->mapc_discovered_ap_count++;

	if (mapc_conf->max_mapc_ap_inactivity > 0) {
		eloop_register_timeout(mapc_conf->max_mapc_ap_inactivity, 0,
				       mapc_inactivity_cb, hapd, sta);
	} else {
		wpa_printf(MSG_DEBUG,
			   "MAPC: inactivity timer disabled (max_mapc_ap_inactivity=0)"
			   " — DISCOVERED peers will not be evicted automatically");
	}

	wpa_printf(MSG_INFO, "MAPC: DISCOVERED peer add " MACSTR,
		   MAC2STR(peer_bssid));
	return sta;
}

static void mapc_inactivity_cb(void *eloop_data, void *user_data)
{
	struct hostapd_data *hapd = eloop_data;
	struct sta_info     *sta  = user_data;
	struct mapc_scheme_nego_req reqs[MAPC_SCHEME_MAX];
	int i;

	if (!hapd || !sta || !sta->is_mapc_peer)
		return;

	if (sta->mapc_params.peer_state == MAPC_PEER_STATE_ACTIVE) {
		wpa_printf(MSG_INFO,
			   "MAPC: ACTIVE peer inactivity timeout " MACSTR
			   " — sending TEARDOWN and deleting peer",
			   MAC2STR(sta->addr));
		/* Cancel any in-flight negotiation and force neg_state to IDLE
		 * so mapc_send_negotiation_request() does not return -EBUSY.
		 * Mirrors the same pattern in mapc_deinit() and
		 * mapc_handle_primary_channel_change(). */
		eloop_cancel_timeout(mapc_negotiation_timeout_cb, hapd, sta);
		sta->mapc_params.neg_state               = MAPC_NEG_IDLE;
		sta->mapc_params.negotiation_dialog_token = 0;
		os_memset(reqs, 0, sizeof(reqs));
		for (i = MAPC_SCHEME_CO_BF; i < MAPC_SCHEME_MAX; i++) {
			if (sta->mapc_params.agreement_cnt[i] > 0) {
				reqs[i].include = true;
				reqs[i].op_type = MAPC_OP_AGREEMENT_TEARDOWN;
			}
		}
		if (mapc_send_negotiation_request(hapd, sta->addr, reqs) < 0)
			wpa_printf(MSG_WARNING,
				   "MAPC: inactivity TEARDOWN TX failed for "
				   MACSTR " — deleting peer without protocol"
				   " teardown; remote may retain stale agreement",
				   MAC2STR(sta->addr));
		mapc_delete_active_peer(hapd, sta);
	} else {
		wpa_printf(MSG_DEBUG,
			   "MAPC: DISCOVERED peer inactivity timeout " MACSTR
			   " — removing",
			   MAC2STR(sta->addr));
		if (hapd->mapc_discovered_ap_count > 0)
			hapd->mapc_discovered_ap_count--;
		ap_free_sta(hapd, sta);
	}
}

static void mapc_discovery_timeout_cb(void *eloop_data, void *user_data)
{
	struct hostapd_data *hapd = (struct hostapd_data *)eloop_data;
	struct mapc_discovery_req *req = user_data;

	wpa_printf(MSG_DEBUG, "MAPC: Discovery timeout for token %d", req->dialog_token);
	dl_list_del(&req->list);
	os_free(req);
	(void)hapd;
}

static void mapc_negotiation_timeout_cb(void *eloop_data, void *user_data)
{
	struct hostapd_data *hapd = eloop_data;
	struct sta_info *sta = user_data;

	if (!hapd || !sta)
		return;

	wpa_printf(MSG_WARNING,
		   "MAPC: Negotiation timeout peer=" MACSTR " state=%d",
		   MAC2STR(sta->addr), sta->mapc_params.neg_state);

	if (sta->mapc_params.neg_state == MAPC_NEG_AGR_TEARDOWN_INPROGRESS &&
	    sta->mapc_params.peer_state == MAPC_PEER_STATE_ACTIVE) {
		wpa_printf(MSG_WARNING,
			   "MAPC: Teardown timeout — no response from " MACSTR
			   ", force deleting peer", MAC2STR(sta->addr));
		mapc_delete_active_peer(hapd, sta);
		return;
	}

	if (sta->mapc_params.peer_state == MAPC_PEER_STATE_DISCOVERED) {
		if (sta->mapc_params.apid != 0)
			mapc_release_aid(hapd, sta);
	}

	/* ACTIVE peer: AID and vendor AID remain valid; only reset neg_state. */
	sta->mapc_params.neg_state               = MAPC_NEG_IDLE;
	sta->mapc_params.negotiation_dialog_token = 0;
}

static void mapc_delete_active_peer(struct hostapd_data *hapd, struct sta_info *sta)
{
	if (!sta || !sta->is_mapc_peer)
		return;

	wpa_printf(MSG_INFO, "MAPC: DEL_STATION peer=" MACSTR " apid=%u",
		   MAC2STR(sta->addr), sta->mapc_params.apid);

	eloop_cancel_timeout(mapc_inactivity_cb, hapd, sta);
	eloop_cancel_timeout(mapc_negotiation_timeout_cb, hapd, sta);


	if (hapd->iface->mapc_active_peer_count > 0)
		hapd->iface->mapc_active_peer_count--;
	if (hapd->bss_active_peer_count > 0)
		hapd->bss_active_peer_count--;
	if (sta->mapc_params.agreement_cnt[MAPC_SCHEME_CO_TDMA] > 0) {
		if (hapd->iface->mapc_cotdma_active_count > 0)
			hapd->iface->mapc_cotdma_active_count--;
		if (hapd->bss_cotdma_active_count > 0)
			hapd->bss_cotdma_active_count--;
	}

	{
		struct mapc_parameters zero_params;

		os_memset(&zero_params, 0, sizeof(zero_params));
		hostapd_sta_set_mapc_params(hapd, sta->addr, &zero_params);
	}

	ap_free_sta(hapd, sta);
}

int mapc_handle_negotiation_update(struct hostapd_data *hapd,
				   ieee80211_mapc_scheme_type_t scheme_type)
{
	struct sta_info *sta;
	struct mapc_scheme_nego_req reqs[MAPC_SCHEME_MAX];
	const struct mapc_scheme_ops *ops = NULL;
	int sent = 0;
	int i, ret;

	if (!hapd || !hapd->conf || !hapd->conf->mapc_conf)
		return -EINVAL;

	if ((int)scheme_type < 0 || scheme_type >= MAPC_SCHEME_MAX)
		return -EINVAL;

	for (i = 0; mapc_scheme_ops_register[i]; i++) {
		if (mapc_scheme_ops_register[i]->scheme_type == scheme_type) {
			ops = mapc_scheme_ops_register[i];
			break;
		}
	}
	if (!ops || !ops->has_params_changed) {
		wpa_printf(MSG_DEBUG,
			   "MAPC: negotiation_update: scheme %d not in vtable "
			   "or has_params_changed not implemented", scheme_type);
		return -ENOTSUP;
	}

	/* Iterate over all ACTIVE MAPC peers */
	for (sta = hapd->sta_list; sta; sta = sta->next) {
		if (!sta->is_mapc_peer)
			continue;
		if (sta->mapc_params.peer_state != MAPC_PEER_STATE_ACTIVE)
			continue;
		if (sta->mapc_params.agreement_cnt[scheme_type] == 0)
			continue; /* no agreement for this scheme with this peer */

		if (!ops->has_params_changed(hapd, sta))
			continue; /* no parameter change detected */

		wpa_printf(MSG_INFO,
			   "MAPC: negotiation_update: scheme %d params changed "
			   "for " MACSTR " — initiating AGREEMENT_UPDATE",
			   scheme_type, MAC2STR(sta->addr));

		os_memset(reqs, 0, sizeof(reqs));
		reqs[scheme_type].include = true;
		reqs[scheme_type].op_type = MAPC_OP_AGREEMENT_UPDATE;

		ret = mapc_send_negotiation_request(hapd, sta->addr, reqs);
		if (ret < 0) {
			wpa_printf(MSG_ERROR,
				   "MAPC: negotiation_update: failed to send "
				   "UPDATE to " MACSTR " (ret=%d)",
				   MAC2STR(sta->addr), ret);
		} else {
			sent++;
		}
	}

	wpa_printf(MSG_DEBUG,
		   "MAPC: negotiation_update: scheme %d — sent %d UPDATE request(s)",
		   scheme_type, sent);
	return sent;
}


static int mapc_add_drv_sta(struct hostapd_data *hapd,
		struct sta_info *sta,
		u8 accepted_scheme_bitmask)
{
	int freq, i;
	struct mapc_bss_config *mapc_conf = hapd->conf->mapc_conf;
	static const u8 mapc_rates_5g[] = {
		0x8c, 0x12, 0x98, 0x24, 0xb0, 0x48, 0x60, 0x6c,
	};
	static const u8 mapc_rates_6g[] = {
		0x8c, 0x12, 0x98, 0x24, 0xb0, 0x48, 0x60, 0x6c,
	};
	static const u8 mapc_rates_2g[] = {
		0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24,
		0x30, 0x48, 0x60, 0x6c,
	};
	const u8 *band_rates;
	size_t band_rates_len;
	struct ieee80211_uhr_capabilities uhr_cap;
	bool use_uhr = false;

	if (!sta || sta->mapc_params.peer_state != MAPC_PEER_STATE_DISCOVERED) {
		wpa_printf(MSG_ERROR,
			   "MAPC: promote: " MACSTR " not in DISCOVERED state",
			   MAC2STR(sta ? sta->addr : (const u8 *)"\0\0\0\0\0\0"));
		return -EINVAL;
	}

	if (mapc_check_co_ordination_allow(hapd)) {
		wpa_printf(MSG_INFO,
			   "MAPC: max active peers reached (iface=%u bss=%u/%d)"
			   ", cannot promote " MACSTR,
			   hapd->iface->mapc_active_peer_count,
			   hapd->bss_active_peer_count,
			   mapc_conf->max_mapc_co_ap_peer,
			   MAC2STR(sta->addr));
		mapc_release_aid(hapd, sta);
		return -ENOSPC;
	}

	if ((accepted_scheme_bitmask & BIT(MAPC_SCHEME_CO_TDMA)) &&
	    mapc_check_cotdma_disallow(hapd)) {
		wpa_printf(MSG_INFO,
			   "MAPC: Co-TDMA capacity reached"
			   " (iface=%u/%u bss=%u/%u), cannot promote " MACSTR,
			   hapd->iface->mapc_cotdma_active_count,
			   hapd->iface->mapc_max_ctdma_peers,
			   hapd->bss_cotdma_active_count,
			   mapc_conf->max_mapc_ctdma_peer,
			   MAC2STR(sta->addr));
		mapc_release_aid(hapd, sta);
		return -ENOSPC;
	}

	sta->capability = WLAN_CAPABILITY_ESS | WLAN_CAPABILITY_SHORT_PREAMBLE;
	sta->listen_interval = 10;

	freq = hapd->iface->freq;
	if (is_6ghz_freq(freq)) {
		band_rates = mapc_rates_6g;
		band_rates_len = ARRAY_SIZE(mapc_rates_6g);
	} else if (freq >= 5000) {
		band_rates = mapc_rates_5g;
		band_rates_len = ARRAY_SIZE(mapc_rates_5g);
	} else {
		band_rates = mapc_rates_2g;
		band_rates_len = ARRAY_SIZE(mapc_rates_2g);
	}
	if (band_rates_len > WLAN_SUPP_RATES_MAX)
		band_rates_len = WLAN_SUPP_RATES_MAX;
	os_memcpy(sta->supported_rates, band_rates, band_rates_len);
	sta->supported_rates_len = (int)band_rates_len;

	if (hapd->iconf->ieee80211bn && !hapd->conf->disable_11bn) {
		struct hostapd_hw_modes *hw_mode = hapd->iface->current_mode;

		if (!sta->he_capab) {
			sta->he_capab = os_zalloc(sizeof(struct ieee80211_he_capabilities));
			if (!sta->he_capab)
				return -ENOMEM;
		} else {
			os_memset(sta->he_capab, 0,
				  sizeof(struct ieee80211_he_capabilities));
		}
		sta->he_capab_len = sizeof(struct ieee80211_he_capabilities);

		if (!sta->eht_capab) {
			sta->eht_capab = os_zalloc(sizeof(struct ieee80211_eht_capabilities));
			if (!sta->eht_capab)
				return -ENOMEM;
		}
		if (hw_mode) {
			os_memcpy(sta->eht_capab, &hw_mode->eht_capab[IEEE80211_MODE_AP],
				  sizeof(hw_mode->eht_capab[IEEE80211_MODE_AP]));
			sta->eht_capab_len = NL80211_EHT_MIN_CAPABILITY_LEN + 4; /* 15 bytes */
		}

		if (!sta->uhr_capab) {
			sta->uhr_capab = os_zalloc(sizeof(struct ieee80211_uhr_capabilities));
			if (!sta->uhr_capab)
				return -ENOMEM;
		} else {
			os_memset(sta->uhr_capab, 0,
				  sizeof(struct ieee80211_uhr_capabilities));
		}
		sta->uhr_capab_len = sizeof(struct ieee80211_uhr_capabilities);

		if (hw_mode) {
			struct uhr_capabilities *ap_uhr = &hw_mode->uhr_capab[IEEE80211_MODE_AP];
			os_memcpy(sta->uhr_capab->mac_cap, ap_uhr->mac_cap,
				  sizeof(sta->uhr_capab->mac_cap));
			os_memcpy(sta->uhr_capab->phy_cap, ap_uhr->phy_cap,
				  sizeof(sta->uhr_capab->phy_cap));
		}
		hostapd_get_uhr_capab(sta->uhr_capab, &uhr_cap, sta->uhr_capab_len);
		use_uhr = true;
		sta->flags |= WLAN_STA_UHR;
	} else {
		sta->flags &= ~WLAN_STA_UHR;
		os_free(sta->uhr_capab);
		sta->uhr_capab = NULL;
		sta->uhr_capab_len = 0;
	}

	sta->flags |= WLAN_STA_AUTH | WLAN_STA_ASSOC | WLAN_STA_WMM;

	if (sta->mapc_params.apid != 0) {
		sta->aid = sta->mapc_params.apid;
	} else {
		if (hostapd_get_aid(hapd, sta) < 0) {
			wpa_printf(MSG_WARNING, "MAPC: no AID for " MACSTR,
				   MAC2STR(sta->addr));
			return -ENOSPC;
		}
		sta->mapc_params.apid = sta->aid;
	}

	wpa_printf(MSG_INFO, "MAPC: promote peer=" MACSTR " apid=%u aid=%u",
		   MAC2STR(sta->addr), sta->mapc_params.apid, sta->aid);

	/* Transition to ACTIVE state */
	sta->mapc_params.peer_state = MAPC_PEER_STATE_ACTIVE;
	if (hostapd_sta_add(hapd, sta->addr, sta->aid, sta->capability,
				sta->supported_rates, sta->supported_rates_len,
				sta->listen_interval, NULL, NULL,
				sta->he_capab, sta->he_capab_len,
				sta->eht_capab, sta->eht_capab_len,
				use_uhr ? &uhr_cap : NULL,
				use_uhr ? sta->uhr_capab_len : 0,
#ifdef CONFIG_QCN_EXTN
				(struct sta_info_extn *)&sta->sta_extn,
#endif
				NULL,
				sta->flags | WLAN_STA_ASSOC,
				sta->qosinfo, sta->vht_opmode, 0, 0,
				NULL, false, 0, LINK_PARSE_ASSOC,
				sta->control_mic_pad)) {
		wpa_printf(MSG_ERROR, "MAPC: hostapd_sta_add failed for " MACSTR,
			   MAC2STR(sta->addr));
		hapd->sta_aid[sta->aid / 32] &= ~BIT(sta->aid % 32);
		sta->aid = 0;
		sta->mapc_params.apid      = 0;
		sta->mapc_params.neg_state = MAPC_NEG_IDLE;
		sta->mapc_params.peer_state = MAPC_PEER_STATE_DISCOVERED;
		return -1;
	}

	hapd->iface->mapc_active_peer_count++;
	hapd->bss_active_peer_count++;
	if (hapd->mapc_discovered_ap_count > 0)
		hapd->mapc_discovered_ap_count--;

	sta->mapc_params.neg_state = MAPC_NEG_IDLE;
	for (i = MAPC_SCHEME_CO_BF; i < MAPC_SCHEME_MAX; i++) {
		if (accepted_scheme_bitmask & BIT(i))
			sta->mapc_params.agreement_cnt[i]++;
	}
	if (accepted_scheme_bitmask & BIT(MAPC_SCHEME_CO_TDMA)) {
		hapd->iface->mapc_cotdma_active_count++;
		hapd->bss_cotdma_active_count++;
	}

	if (hostapd_sta_set_mapc_params(hapd, sta->addr, &sta->mapc_params))
		wpa_printf(MSG_ERROR,
			   "MAPC: SET_STATION MAPC params failed for " MACSTR,
			   MAC2STR(sta->addr));

	/*
	 * Snapshot our current Co-TDMA params so cotdma_has_params_changed()
	 * can detect future changes in our own params relative to what we
	 * last communicated to this peer.
	 */
	mapc_snapshot_local_cotdma(hapd, sta);

	/* Re-arm inactivity timer — same callback, peer_state now ACTIVE */
	eloop_cancel_timeout(mapc_inactivity_cb, hapd, sta);
	if (mapc_conf->max_mapc_ap_inactivity > 0)
		eloop_register_timeout(mapc_conf->max_mapc_ap_inactivity, 0,
				       mapc_inactivity_cb, hapd, sta);

	return 0;
}

void mapc_get_common_info_bitmap(struct hostapd_data *hapd)
{
	struct mapc_bss_config *mapc_conf;
	u32 hw_cap;

	if (!hapd || !hapd->conf || !hapd->conf->mapc_conf) {
		wpa_printf(MSG_ERROR,
			   "MAPC: %s called with NULL hapd/conf/mapc_conf",
			   __func__);
		return;
	}
	mapc_conf = hapd->conf->mapc_conf;

	/* hw_cap is owned by the iface (radio), not by this BSS */
	hw_cap = hapd->iface->mapc_hw_capability_bitmap;

	/* Reset — rebuilt entirely from iface->mapc_hw_capability_bitmap. */
	mapc_conf->mapc_capability_bitmap  = 0;
	mapc_conf->mapc_parameter_bitmap   = 0;
	mapc_conf->cotdma.mapc_cotdma_info = 0;

	if ((hw_cap & BIT(MAPC_CAPABILITY_COTDMA_SUPPORT)) &&
	    (mapc_conf->mapc_usr_enabled_bitmap & BIT(MAPC_PARAMETER_COTDMA_ENABLED)) &&
	    mapc_conf->max_mapc_ctdma_peer > 0) {
		mapc_conf->mapc_capability_bitmap |= BIT(MAPC_CAPABILITY_COTDMA_SUPPORT);
		mapc_conf->mapc_parameter_bitmap  |= BIT(MAPC_PARAMETER_COTDMA_ENABLED);
		/* Suppress AE Enabled bit if we are already at capacity */
		if (mapc_check_cotdma_disallow(hapd))
			mapc_conf->mapc_parameter_bitmap &= ~BIT(MAPC_PARAMETER_COTDMA_ENABLED);
	}

	/* AP TB PPDU Response (bit 14): HW capability only; no user-enable knob */
	if (hw_cap & BIT(MAPC_CAPABILITY_AP_TB_PPDU_RESPONSE))
		mapc_conf->mapc_capability_bitmap |= BIT(MAPC_CAPABILITY_AP_TB_PPDU_RESPONSE);

	/* Rx TXOP Return (bit 16): drives Co-TDMA cotdma_info B0 */
	if (hw_cap & BIT(MAPC_HW_CAP_COTDMA_RX_TXOP_RETURN))
		mapc_conf->cotdma.mapc_cotdma_info |=
			BIT(MAPC_COTDMA_CAP_RX_TXOP_RETURN_SUPPORT);

	wpa_printf(MSG_DEBUG,
		   "MAPC: mapc_get_common_info_bitmap: "
		   "hw_cap=0x%08x usr_enabled=0x%04x => "
		   "cap=0x%04x param=0x%04x cotdma_info=0x%02x",
		   hw_cap, mapc_conf->mapc_usr_enabled_bitmap,
		   mapc_conf->mapc_capability_bitmap, mapc_conf->mapc_parameter_bitmap,
		   mapc_conf->cotdma.mapc_cotdma_info);
}

static u8 mapc_ctrl_bitmap_from_flags(bool has_establish, bool has_update,
				      bool has_teardown, bool include_apid)
{
	u8 bitmap = 0;

	if (has_establish) {
		bitmap |= BIT(MAPC_CTRL_CAPABILITIES_PRESENT) |
			  BIT(MAPC_CTRL_PARAMETERS_PRESENT);
		if (include_apid)
			bitmap |= BIT(MAPC_CTRL_APID_PRESENT);
	}
	/* Update and teardown both require PARAM_PRESENT; the Per-Scheme Profile
	 * op_type field distinguishes them on the wire. */
	if (has_update || has_teardown)
		bitmap |= BIT(MAPC_CTRL_PARAMETERS_PRESENT);
	return bitmap;
}

static u8 mapc_ctrl_bitmap_for_resp(const struct mapc_scheme_nego_resp *resps,
				    bool include_apid)
{
	bool has_establish = false, has_update = false, has_teardown = false;
	int i;

	for (i = MAPC_SCHEME_CO_BF; i < MAPC_SCHEME_MAX; i++) {
		if (!resps[i].include)
			continue;
		if (resps[i].req_op == MAPC_OP_AGREEMENT_ESTABLISHMENT)
			has_establish = true;
		if (resps[i].req_op == MAPC_OP_AGREEMENT_UPDATE)
			has_update    = true;
		if (resps[i].req_op == MAPC_OP_AGREEMENT_TEARDOWN)
			has_teardown  = true;
	}

	return mapc_ctrl_bitmap_from_flags(has_establish, has_update,
					   has_teardown, include_apid);
}

static bool mapc_is_first_cobf_cosr_cotdma_agreement(struct hostapd_data *hapd,
						      const u8 *peer_bssid,
						      const struct sta_info *existing_sta)
{
	const struct sta_info *sta = existing_sta ? existing_sta
						  : ap_get_sta(hapd, peer_bssid);

	if (sta && sta->is_mapc_peer) {
		/* Active peer: check if any Co-BF/SR/TDMA agreement already exists */
		return !(sta->mapc_params.agreement_cnt[MAPC_SCHEME_CO_BF]   > 0 ||
			 sta->mapc_params.agreement_cnt[MAPC_SCHEME_CO_SR]    > 0 ||
			 sta->mapc_params.agreement_cnt[MAPC_SCHEME_CO_TDMA]  > 0);
	}

	return true;
}

static void mapc_get_local_cotdma_channel_params(const struct hostapd_data *hapd,
						 struct mapc_ctdma_profile *prof)
{
	enum oper_chan_width chwidth = hostapd_get_oper_chwidth(hapd->iconf);

	switch (chwidth) {
	case CONF_OPER_CHWIDTH_USE_HT:
		prof->channel_width = (hapd->iconf->secondary_channel != 0)
				      ? MAPC_CHANNEL_WIDTH_40MHZ
				      : MAPC_CHANNEL_WIDTH_20MHZ;
		break;
	case CONF_OPER_CHWIDTH_80MHZ:
		prof->channel_width = MAPC_CHANNEL_WIDTH_80MHZ;
		break;
	case CONF_OPER_CHWIDTH_160MHZ:
	case CONF_OPER_CHWIDTH_80P80MHZ:
		prof->channel_width = MAPC_CHANNEL_WIDTH_160MHZ;
		break;
	case CONF_OPER_CHWIDTH_40MHZ_6GHZ:
		prof->channel_width = MAPC_CHANNEL_WIDTH_40MHZ;
		break;
	case CONF_OPER_CHWIDTH_320MHZ:
		prof->channel_width = MAPC_CHANNEL_WIDTH_320MHZ;
		break;
	default:
		prof->channel_width = MAPC_CHANNEL_WIDTH_20MHZ;
		break;
	}
	prof->ccfs                      = hostapd_get_oper_centr_freq_seg0_idx(hapd->iconf);
	prof->disable_subchannel_bitmap = hapd->iconf->punct_bitmap;
	prof->bss_color                 = hapd->iconf->he_op.he_bss_color;
}

static int cotdma_build_scheme_ap_param_set(struct wpabuf *buf,
					   const struct hostapd_data *hapd)
{
	const struct mapc_bss_config *mapc_conf = hapd->conf->mapc_conf;
	struct mapc_ctdma_profile cur;
	u8 param_len = 0;
	u8 bw_info_hdr = 0;

	if (!mapc_conf->mapc_cotdma_enable)
		return 0;

	mapc_get_local_cotdma_channel_params(hapd, &cur);

	wpabuf_put_u8(buf, mapc_conf->cotdma.mapc_cotdma_info);
	param_len++;

	bw_info_hdr |= (cur.channel_width & MAPC_BW_INFO_CHANNEL_WIDTH_MASK);
	if (cur.disable_subchannel_bitmap)
		bw_info_hdr |= BIT(MAPC_BW_INFO_DSB_PRESENT);

	wpabuf_put_u8(buf, bw_info_hdr);
	wpabuf_put_u8(buf, cur.ccfs);
	param_len += 2;

	if (cur.disable_subchannel_bitmap) {
		wpabuf_put_le16(buf, cur.disable_subchannel_bitmap);
		param_len += MAPC_COTDMA_DISABLE_SUBCHAN_ELEMENT_LEN;
	}

	wpabuf_put_u8(buf, cur.bss_color & MAPC_BSS_COLOR_MASK);
	param_len++;

	return (int)param_len;
}

static int cotdma_parse_scheme_profile(const u8 *body, size_t len,
					   struct sta_info *sta)
{
	struct mapc_ctdma_profile *ct = &sta->mapc_params.cached[MAPC_SCHEME_CO_TDMA].cotdma;
	size_t offset = 0;
	u8 bw_hdr;
	bool dsb_present;

	if (len < (size_t)(MAPC_COTDMA_SUB_ELEM_MIN_LEN - 1))
		return -1;

	ct->rx_txop_return_support = !!(body[offset] & BIT(MAPC_COTDMA_CAP_RX_TXOP_RETURN_SUPPORT));
	offset++;

	bw_hdr = body[offset++];
	ct->channel_width = bw_hdr & MAPC_BW_INFO_CHANNEL_WIDTH_MASK;
	if (ct->channel_width > MAPC_CHANNEL_WIDTH_320MHZ) {
		wpa_printf(MSG_ERROR,
			   "MAPC: cotdma_parse: reserved channel_width=%u"
			   " (valid 0-%u) — rejecting profile",
			   ct->channel_width, MAPC_CHANNEL_WIDTH_320MHZ);
		return -1;
	}
	dsb_present = !!(bw_hdr & BIT(MAPC_BW_INFO_DSB_PRESENT));
	ct->ccfs = body[offset++];

	if (dsb_present) {
		if (offset + MAPC_COTDMA_DISABLE_SUBCHAN_ELEMENT_LEN > len)
			return -1;
		ct->disable_subchannel_bitmap = WPA_GET_LE16(&body[offset]);
		offset += MAPC_COTDMA_DISABLE_SUBCHAN_ELEMENT_LEN;
	}

	if (offset >= len)
		return -1;

	ct->bss_color = body[offset++] & MAPC_BSS_COLOR_MASK;
	sta->mapc_params.cached[MAPC_SCHEME_CO_TDMA].mapc_op_type = 0;

	if (offset < len) {
		u8 mapc_req_ctrl = body[offset++];
		u8 op_type = mapc_req_ctrl & 0x07;
		bool per_scheme_info_pres = !!(mapc_req_ctrl & BIT(3));

		if (op_type >= MAPC_OP_MAX) {
			wpa_printf(MSG_ERROR,
				   "MAPC: cotdma_parse: reserved op_type=%u"
				   " (valid 0-%u) — treating as Establish",
				   op_type, MAPC_OP_MAX - 1);
			op_type = MAPC_OP_AGREEMENT_ESTABLISHMENT;
		}
		sta->mapc_params.cached[MAPC_SCHEME_CO_TDMA].mapc_op_type = op_type;

		wpa_printf(MSG_DEBUG,
			   "MAPC: cotdma_parse: MAPC_Request_Control=0x%02x "
			   "op_type=%u (%s) per_scheme_info_present=%d",
			   mapc_req_ctrl, op_type,
			   op_type == 0 ? "Establish" :
			   op_type == 1 ? "Update" :
			   op_type == 2 ? "Teardown" :
			   op_type == 3 ? "Accept" :
			   op_type == 4 ? "Reject" :
			   op_type == 5 ? "Alternate" : "Unknown",
			   per_scheme_info_pres);
	}

	wpa_printf(MSG_DEBUG,
		   "MAPC: cotdma_parse: channel_width=%u ccfs=%u dsb=0x%04x "
		   "bss_color=%u rx_txop_support=%d op_type=%u",
		   ct->channel_width, ct->ccfs, ct->disable_subchannel_bitmap,
		   ct->bss_color, ct->rx_txop_return_support,
		   sta->mapc_params.cached[MAPC_SCHEME_CO_TDMA].mapc_op_type);

	sta->mapc_params.cached[MAPC_SCHEME_CO_TDMA].valid = true;
	return 0;
}

/* mapc_is_peer_in_valid_coap_list - Return true if src MAC is in the
 * configured valid_coap_list, or if no list is configured (valid_ap_count==0).
 * In discovery_mode=1 an empty list means "reject all". Callers must handle
 * that distinction themselves. */
static bool mapc_is_peer_in_valid_coap_list(const struct mapc_bss_config *mapc_conf,
					  const u8 *src)
{
	int i;

	for (i = 0; i < mapc_conf->valid_ap_count; i++) {
		if (os_memcmp(mapc_conf->valid_coap_list[i], src, ETH_ALEN) == 0)
			return true;
	}
	return false;
}

bool mapc_is_valid_coap_peer(const struct mapc_bss_config *mc, const u8 *mac)
{
	return mapc_is_peer_in_valid_coap_list(mc, mac);
}

void mapc_cancel_sta_timers(struct hostapd_data *hapd, struct sta_info *sta)
{
	eloop_cancel_timeout(mapc_inactivity_cb, hapd, sta);
	eloop_cancel_timeout(mapc_negotiation_timeout_cb, hapd, sta);
}

static bool cotdma_accept_criteria(const struct hostapd_data *hapd,
				   const struct sta_info *sta)
{
	const struct mapc_bss_config *mapc_conf = hapd->conf->mapc_conf;

	if (!mapc_conf->mapc_cotdma_enable)
		return false;

	if (mapc_check_cotdma_disallow(hapd))
		return false;

	/* Check capability intersection */
	if (!(sta->mapc_params.mapc_capability_bitmap & BIT(MAPC_CAPABILITY_COTDMA_SUPPORT)))
		return false;

	/* valid_coap_list is only enforced in manual mode (negotiation_mode=1).
	 * In auto mode the list is not consulted — all capable peers are accepted. */
	if (mapc_conf->negotiation_mode == 1) {
		if (mapc_conf->valid_ap_count == 0)
			return false; /* manual mode, empty list = block all */
		return mapc_is_peer_in_valid_coap_list(mapc_conf, sta->addr);
	}

	return true;
}

static void cotdma_fill_peer_params(const struct sta_info *sta,
					struct mapc_parameters *params)
{
	if (sta->mapc_params.cached[MAPC_SCHEME_CO_TDMA].valid)
		params->ctdma_profile = sta->mapc_params.cached[MAPC_SCHEME_CO_TDMA].cotdma;
}

/**
 * mapc_snapshot_local_cotdma - Snapshot our current Co-TDMA params into
 * sta->mapc_params.last_sent_cotdma.
 */
static void mapc_snapshot_local_cotdma(const struct hostapd_data *hapd,
				       struct sta_info *sta)
{
	struct mapc_ctdma_profile *snap = &sta->mapc_params.last_sent_cotdma;

	mapc_get_local_cotdma_channel_params(hapd, snap);

	wpa_printf(MSG_DEBUG,
		   "MAPC: snapshot local Co-TDMA for " MACSTR
		   " chwidth=%u ccfs=%u dsb=0x%04x bss_color=%u",
		   MAC2STR(sta->addr),
		   snap->channel_width, snap->ccfs,
		   snap->disable_subchannel_bitmap, snap->bss_color);
}

static bool cotdma_has_params_changed(const struct hostapd_data *hapd,
				      const struct sta_info *sta)
{
	const struct mapc_ctdma_profile *active = &sta->mapc_params.last_sent_cotdma;
	struct mapc_ctdma_profile cur;

	mapc_get_local_cotdma_channel_params(hapd, &cur);

	return (cur.channel_width             != active->channel_width)             ||
	       (cur.ccfs                      != active->ccfs)                      ||
	       (cur.disable_subchannel_bitmap != active->disable_subchannel_bitmap) ||
	       (cur.bss_color                 != active->bss_color);
}
