/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: ISC
 */

#include "utils/includes.h"
#include "utils/common.h"
#include "common/ieee802_11_defs.h"
#include "common/ieee802_11_common.h"
#include "hostapd.h"
#include "ieee802_11.h"
#include "sta_info.h"
#include "ap_config.h"
#include "ap_drv_ops.h"
#include "dscp_policy.h"

void hostapd_check_dscp_policy_capability(struct sta_info *sta,
					  const u8 *ies, size_t ies_len)
{
	const u8 *pos = ies;
	const u8 *end = ies + ies_len;

	sta->dscp_policy_capable = false;

	if (!(sta->flags & WLAN_STA_MFP))
		return;

	while (pos + 1 < end) {
		u8 id = *pos++;
		u8 len = *pos++;
		if (pos + len > end)
			break;
		if (id == WLAN_EID_VENDOR_SPECIFIC && len >= 5 &&
		    WPA_GET_BE24(pos) == OUI_WFA && pos[3] == WFA_CAPA_OUI_TYPE) {
			u8 cap_len = pos[4];
			if (cap_len >= 1 && len >= 5 + cap_len) {
				u8 cap = pos[5];
				if (cap & WFA_CAPA_QM_DSCP_POLICY) {
					sta->dscp_policy_capable = true;
					wpa_printf(MSG_DEBUG, "DSCP: STA " MACSTR
						   " supports DSCP Policy", MAC2STR(sta->addr));
				}
			}
		}
		pos += len;
	}
}

size_t hostapd_dscp_cap_ie_len(struct hostapd_data *hapd)
{

	return DSCP_CAP_IE_HEADER_LEN +
	       DSCP_CAP_IE_OUI_LEN +
	       DSCP_CAP_IE_OUI_TYPE_LEN +
	       DSCP_CAP_IE_CAP_LEN_FIELD +
	       DSCP_CAPABILITIES_LEN;
}

u8 *hostapd_set_dscp_capabilities(struct hostapd_data *hapd, struct sta_info *sta, u8 *eid)
{
	struct wpabuf *dscp_ie = NULL;
	u8 dscp_cap = 0;
	size_t buf_len, dscp_ie_len;

	dscp_cap |= WFA_CAPA_QM_DSCP_POLICY;
	dscp_cap |= WFA_CAPA_QM_UNSOLIC_DSCP;

	if (!hapd->conf->enable_dscp_policy_capa || (sta && !sta->dscp_policy_capable))
		return eid;

	/* Wi-Fi Alliance element */
	buf_len = hostapd_dscp_cap_ie_len(hapd);

	dscp_ie = wpabuf_alloc(buf_len);
	if (!dscp_ie)
		return eid;

	wpabuf_put_u8(dscp_ie, WLAN_EID_VENDOR_SPECIFIC);
	wpabuf_put_u8(dscp_ie, buf_len - 2);
	wpabuf_put_be24(dscp_ie, OUI_WFA);
	wpabuf_put_u8(dscp_ie, WFA_CAPA_OUI_TYPE);
	wpabuf_put_u8(dscp_ie, sizeof(dscp_cap));
	wpabuf_put_u8(dscp_ie, dscp_cap);

	dscp_ie_len = wpabuf_len(dscp_ie);
	os_memcpy(eid, wpabuf_head(dscp_ie), dscp_ie_len);
	eid += dscp_ie_len;

	wpabuf_free(dscp_ie);
	return eid;
}

