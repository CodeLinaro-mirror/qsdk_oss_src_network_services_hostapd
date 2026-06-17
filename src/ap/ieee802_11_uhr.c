
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
	/* TODO: Fill in appropriate UHR-MCS max NSS information */
	oper->basic_uhr_mcs_nss_set[0] = 0x11;

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
