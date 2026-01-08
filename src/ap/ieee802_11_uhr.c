
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
	os_memcpy(cap->phy_cap, uhr_cap->phy_cap, sizeof(cap->phy_cap));
	pos += sizeof(struct ieee80211_uhr_capabilities);

	*length_pos = pos - (eid + 2);
	return pos;
}


u8 * hostapd_eid_uhr_operation(struct hostapd_data *hapd, u8 *eid, bool is_bcn)
{
	struct ieee80211_uhr_operation *oper;
	u8 *pos = eid, *length_pos;

	if (!hapd->iface->current_mode)
		return eid;

	*pos++ = WLAN_EID_EXTENSION;
	length_pos = pos++;
	*pos++ = WLAN_EID_EXT_UHR_OPERATION;

	oper = (struct ieee80211_uhr_operation *)pos;
	os_memset(oper, 0, sizeof(*oper));
	/* TODO: Fill in appropriate UHR-MCS max NSS information */
	oper->basic_uhr_mcs_nss_set[0] = 0x11;
	pos += sizeof(struct ieee80211_uhr_operation);
	if (is_bcn)
		pos -= sizeof(oper->uhr_info) - sizeof(oper->dps_oper_param);

	*length_pos = pos - (eid + 2);

	/* TODO: Handle UHR operation parameters */

	if (is_bcn)
		return pos;

	/* TODO: Handle npca_info, p_edca_info and dbe_info here */

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
