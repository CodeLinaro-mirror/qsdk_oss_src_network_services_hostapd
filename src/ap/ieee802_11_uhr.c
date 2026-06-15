
/*
 * hostapd / IEEE 802.11bn UHR
 *
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "utils/includes.h"
#include "utils/common.h"
#include "hostapd.h"
#include "sta_info.h"
#include "ieee802_11.h"

u8 * hostapd_eid_uhr_capab(struct hostapd_data *hapd, u8 *eid,
			    enum ieee80211_op_mode opmode)
{
	struct hostapd_hw_modes *mode;
	struct uhr_capabilities *uhr_cap;
	struct ieee80211_uhr_capabilities *cap;
	u8 *pos = eid, *length_pos;

	mode = hapd->iface->current_mode;
	if (!mode)
		return eid;

	uhr_cap = &mode->uhr_capab[opmode];
	if (!uhr_cap->uhr_supported)
		return eid;

	*pos++ = WLAN_EID_EXTENSION;
	length_pos = pos++;
	*pos++ = WLAN_EID_EXT_UHR_CAPABILITIES;

	cap = (struct ieee80211_uhr_capabilities *)pos;
	os_memset(cap, 0, sizeof(*cap));
	os_memcpy(cap->mac_cap, uhr_cap->mac_cap, sizeof(cap->mac_cap));

	/* Driver supports DPS Assist Support but disabled by user */
	if ((uhr_cap->mac_cap[0] & UHR_MACCAP_DPS_ASSIST) &&
	    hapd->conf->dps_assist == FEATURE_DISABLED)
		cap->mac_cap[0] &= ~UHR_MACCAP_DPS_ASSIST;

	cap->mac_cap[3] =
		(cap->mac_cap[3] &
		 ~UHR_MACCAP3_PARAM_UPD_ADV_NOTIF_INTV_MASK) |
		((hapd->conf->uhr_params_update.adv_notification_interval <<
		  UHR_MACCAP3_PARAM_UPD_ADV_NOTIF_INTV_SHIFT) &
		 UHR_MACCAP3_PARAM_UPD_ADV_NOTIF_INTV_MASK);

	cap->mac_cap[3] =
		(cap->mac_cap[3] &
		 ~UHR_MACCAP3_UPD_IND_TIM_INTV_LOW_MASK) |
		((hapd->conf->uhr_params_update.update_in_tim_interval <<
		  UHR_MACCAP3_UPD_IND_TIM_INTV_LOW_SHIFT) &
		 UHR_MACCAP3_UPD_IND_TIM_INTV_LOW_MASK);
	cap->mac_cap[4] =
		(cap->mac_cap[4] &
		 ~UHR_MACCAP4_UPD_IND_TIM_INTV_HIGH_MASK) |
		(((hapd->conf->uhr_params_update.update_in_tim_interval >> 1) <<
		  UHR_MACCAP4_UPD_IND_TIM_INTV_HIGH_SHIFT) &
		 UHR_MACCAP4_UPD_IND_TIM_INTV_HIGH_MASK);

	os_memcpy(cap->phy_cap, uhr_cap->phy_cap, sizeof(cap->phy_cap));
	pos += sizeof(struct ieee80211_uhr_capabilities);

	*length_pos = pos - (eid + 2);
	return pos;
}


u8 * hostapd_eid_uhr_operation(struct hostapd_data *hapd, u8 *eid, bool is_bcn)
{
	struct ieee80211_uhr_operation *oper;
	u8 *pos = eid, *length_pos;
	struct hostapd_hw_modes *mode;
	struct uhr_npca_info *npca_info;
	bool npca_present;
	int offs;

	mode = hapd->iface->current_mode;
	if (!mode)
		return eid;

	*pos++ = WLAN_EID_EXTENSION;
	length_pos = pos++;
	*pos++ = WLAN_EID_EXT_UHR_OPERATION;

	oper = (struct ieee80211_uhr_operation *)pos;
	os_memset(oper, 0, sizeof(*oper));

	npca_info = &mode->npca_info[IEEE80211_MODE_AP];
	npca_present = npca_info->npca_supported &&
		       hapd->iconf->npca_enable;
	offs = hapd->iconf->npca_primary_chan_offset;
	if (npca_present && offs < 0) {
		wpa_printf(MSG_DEBUG,
			   "NPCA: invalid primary channel %d for current BW, skipping NPCA params",
			   hapd->iconf->npca_primary_channel);
		npca_present = false;
	}
	if (npca_present)
		oper->uhr_oper_params |= UHR_OPER_NPCA_ENABLED;

	pos += sizeof(struct ieee80211_uhr_operation);

	if (is_bcn) {
		*length_pos = pos - (eid + 2);
		return pos;
	}


	if (npca_present) {
		u32 npca_params = 0;

		oper->uhr_oper_params |=
			host_to_le16(UHR_OPER_NPCA_OPER_PRESENT);

		npca_params |= (u32) offs & UHR_OPER_PARAMS_NPCA_PRIM_CHAN_OFFS;
		npca_params |= ((u32)npca_info->npca_min_dur_threshold << 4) &
			       UHR_OPER_PARAMS_NPCA_NPCA_MIN_DUR_THRESH;
		npca_params |= ((u32)npca_info->npca_switch_delay << 8) &
			       UHR_OPER_PARAMS_NPCA_NPCA_SWITCH_DELAY;
		npca_params |= ((u32)npca_info->npca_switch_back_delay << 14) &
			       UHR_OPER_PARAMS_NPCA_NPCA_SWITCH_BACK_DELAY;
		npca_params |= ((u32)npca_info->npca_initial_qsrc << 20) &
			       UHR_OPER_PARAMS_NPCA_INIT_NPCA_QRSC;
		npca_params |= ((u32)npca_info->npca_moplen << 22) &
			       UHR_OPER_PARAMS_NPCA_MOPLEN_NPCA;
		if (hapd->iconf->npca_punct_bitmap)
			npca_params |= UHR_OPER_PARAMS_NPCA_DIS_SUBCH_BITMAP_PRES;

		WPA_PUT_LE32(pos, npca_params);
		pos += sizeof(u32);

		if (hapd->iconf->npca_punct_bitmap) {
			WPA_PUT_LE16(pos, hapd->iconf->npca_punct_bitmap);
			pos += sizeof(u16);
		}
	}

	*length_pos = pos - (eid + 2);
	return pos;
}


void hostapd_get_uhr_capab(const struct ieee80211_uhr_capabilities *src,
			   struct ieee80211_uhr_capabilities *dest,
			   size_t len)
{
	if (!src || !dest)
		return;

	if (len > sizeof(*dest))
		len = sizeof(*dest);
	/* TODO: mask out unsupported features */

	os_memset(dest, 0, sizeof(*dest));
	os_memcpy(dest, src, len);
}


static bool ieee80211_invalid_uhr_cap_size(size_t len)
{
	return len < sizeof(struct ieee80211_uhr_capabilities);
}


u16 copy_sta_uhr_capab(struct hostapd_data *hapd, struct sta_info *sta,
		       const u8 *uhr_capab, size_t uhr_capab_len)
{
	if (!hostapd_is_uhr_enabled(hapd) ||
	    !uhr_capab ||
	    ieee80211_invalid_uhr_cap_size(uhr_capab_len)) {
		sta->flags &= ~WLAN_STA_UHR;
		os_free(sta->uhr_capab);
		sta->uhr_capab = NULL;
		return WLAN_STATUS_SUCCESS;
	}

	os_free(sta->uhr_capab);
	sta->uhr_capab = os_memdup(uhr_capab, uhr_capab_len);
	if (!sta->uhr_capab) {
		sta->uhr_capab_len = 0;
		return WLAN_STATUS_UNSPECIFIED_FAILURE;
	}

	sta->flags |= WLAN_STA_UHR;
	sta->uhr_capab_len = uhr_capab_len;

	return WLAN_STATUS_SUCCESS;
}


/* mode_ctrl(1) is always present; mode_len(1) is present when the mode
 * is enabled (mandatory even when mode_params_len == 0).
 * Per 9.4.2.362: Mode Length and Mode Specific Parameters fields are not
 * included if Mode Enable is 0 or the mode has no parameters.
 */
static size_t uhr_mode_tuple_hdr_len(bool enable, size_t mode_params_len)
{
	size_t len = 1; /* mode_ctrl */

	if (enable)
		len += 1; /* mode_len */

	return len;
}


static u8 * uhr_put_mode_tuple_hdr(u8 *pos, u8 mode_id, bool enable,
				    bool update, u8 mode_len)
{
	u8 mode_ctrl = mode_id & UHR_MODE_TUPLE_MODE_ID_MASK;

	if (enable)
		mode_ctrl |= UHR_MODE_TUPLE_MODE_ENABLE;
	if (enable && update)
		mode_ctrl |= UHR_MODE_TUPLE_MODE_UPDATE;
	*pos++ = mode_ctrl;

	if (enable)
		*pos++ = mode_len;

	return pos;
}


/* NPCA (Mode ID = 1): Mode Specific Parameters = NPCA Operation Parameters
 * field (9.4.2.355.2), 4 or 6 octets. Present only when Mode Enable = 1.
 */
static size_t uhr_npca_mode_tuple_len(const struct hostapd_bss_config *conf)
{
	const struct hostapd_uhr_npca_params *npca =
		&conf->uhr_params_update.npca;
	size_t params_len;

	params_len = 0;
	if (npca->enable) {
		params_len = 4;
		if (npca->params & UHR_OPER_PARAMS_NPCA_DIS_SUBCH_BITMAP_PRES)
			params_len += 2;
	}

	return uhr_mode_tuple_hdr_len(npca->enable, params_len) + params_len;
}


static u8 * uhr_put_npca_mode_tuple(u8 *pos,
				    const struct hostapd_bss_config *conf)
{
	const struct hostapd_uhr_npca_params *npca =
		&conf->uhr_params_update.npca;
	bool bitmap_present;
	u8 mode_len;

	bitmap_present = npca->enable &&
			 !!(npca->params &
				UHR_OPER_PARAMS_NPCA_DIS_SUBCH_BITMAP_PRES);
	mode_len = npca->enable ?
		4 + (bitmap_present ? 2 : 0) : 0;

	pos = uhr_put_mode_tuple_hdr(pos, UHR_PARAMS_UPDATE_MODE_ID_NPCA,
				     npca->enable, npca->update, mode_len);
	if (npca->enable) {
		WPA_PUT_LE32(pos, npca->params);
		pos += 4;
		if (bitmap_present) {
			WPA_PUT_LE16(pos, npca->disabled_subchan_bitmap);
			pos += 2;
		}
	}

	return pos;
}


size_t hostapd_eid_uhr_params_update_len(struct hostapd_data *hapd,
					 bool skip_post_phase)
{
	const struct hostapd_bss_config *conf = hapd->conf;
	size_t len;

	if (hapd->uhr_ecu.state == UHR_ECU_IDLE)
		return 0;

	/*
	 * Per 37.30.2.2: during the post-notification phase the element is
	 * included only in Beacon and Probe Response frames, not in
	 * (Re)Association Response or Link Reconfiguration Response frames.
	 */
	if (skip_post_phase &&
	    hapd->uhr_ecu.state >= UHR_ECU_POST_ADVANCE_NOTIFY)
		return 0;

	if (!conf->uhr_params_update.mode_changed)
		return 0;

	/* EID(1) + Length(1) + EID_EXT(1) + Countdown Timer(1) */
	len = 4;

	if (conf->uhr_params_update.mode_changed & BIT(UHR_PARAMS_UPDATE_MODE_ID_NPCA))
		len += uhr_npca_mode_tuple_len(conf);
	/* TODO: Add length for DPS, DUO, P-EDCA, DBE, AP PUO, ELR modes */

	if (len == 4)
		return 0;

	return len;
}


u8 * hostapd_eid_uhr_params_update(struct hostapd_data *hapd, u8 *eid,
				   bool skip_post_phase)
{
	const struct hostapd_bss_config *conf = hapd->conf;
	u8 *pos = eid;
	u8 *length_pos;

	if (hapd->uhr_ecu.state == UHR_ECU_IDLE)
		return eid;

	if (skip_post_phase &&
	    hapd->uhr_ecu.state >= UHR_ECU_POST_ADVANCE_NOTIFY)
		return eid;

	if (!conf->uhr_params_update.mode_changed)
		return eid;

	*pos++ = WLAN_EID_EXTENSION;
	length_pos = pos++;
	*pos++ = WLAN_EID_EXT_UHR_PARAMS_UPDATE;

	*pos++ = hapd->uhr_ecu.uhr_params_update_countdown;

	/* Mode Tuple List (9.4.2.362) */
	/* TODO: Add Mode Tuple for DPS (Mode ID = 0) */
	if (conf->uhr_params_update.mode_changed & BIT(UHR_PARAMS_UPDATE_MODE_ID_NPCA))
		pos = uhr_put_npca_mode_tuple(pos, conf);
	/* TODO: Add Mode Tuple for DUO (Mode ID = 2) */
	/* TODO: Add Mode Tuple for P-EDCA (Mode ID = 3) */
	/* TODO: Add Mode Tuple for DBE (Mode ID = 4) */
	/* TODO: Add Mode Tuple for AP PUO (Mode ID = 5) */
	/* TODO: Add Mode Tuple for ELR Reception (Mode ID = 6) */

	*length_pos = pos - (eid + 2);
	return pos;
}
