/*
 * hostapd / Tid-to-link Mapping(TTLM)
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"
#include "utils/common.h"
#include "common/ieee802_11_defs.h"
#include "sta_info.h"
#include "hostapd.h"
#include "ap_drv_ops.h"
#include "drivers/driver.h"
#include "ttlm.h"


static int hostapd_get_ttlm_elem_len(struct ttlm_info *ttlm)
{
	u8 tid, num_tids;
	size_t elem_len;

	if (!ttlm || ttlm->direction == TTLM_DIRECTION_INVALID)
		return 0;

	elem_len = sizeof(struct tid_to_link_mapping_elem);

	if (ttlm->default_link_mapping) {
		elem_len += sizeof(u8);
	} else {
		elem_len += sizeof(u16);

		num_tids = 0;
		for (tid = 0; tid < NUM_MAX_TIDS; tid++) {
			if (!ttlm->ieee_link_map_tid[tid])
				continue;
			num_tids++;
		}

		elem_len += num_tids * (ttlm->link_mapping_size ? sizeof(u8) : sizeof(u16));
	}

	return elem_len;
}


static u8 *hostapd_add_ttlm_info_elem(u8 *pos, struct ttlm_info *ttlm)
{
	struct tid_to_link_mapping_elem *ttlm_elem;
	u8 link_mapping_presence_indicator = 0;
	u8 *link_mapping_of_tids;
	u8 tid, len;
	u16 ttlm_control = 0;
	u16 *ttlm_control_field;

	ttlm_elem = (struct tid_to_link_mapping_elem *)pos;
	ttlm_elem->elem_id = WLAN_EID_EXTENSION;
	ttlm_elem->elem_id_extn = WLAN_EID_EXT_TID_TO_LINK_MAPPING;
	len = hostapd_get_ttlm_elem_len(ttlm);
	ttlm_elem->elem_len = len - sizeof(struct elem_header);
	ttlm_control_field = (u16 *)(void *)ttlm_elem->data;

	ttlm_control |= (ttlm->direction << TTLM_CONTROL_DIRECTION_IDX)
			& TTLM_CONTROL_DIRECTION_MASK;

	ttlm_control |= (ttlm->default_link_mapping << TTLM_CONTROL_DEFAULT_LINK_MAPPING_IDX)
			& TTLM_CONTROL_DEFAULT_LINK_MAPPING_MASK;

	if (ttlm->default_link_mapping) {
		/* Link mapping of TIDs are not present when default mapping is
		 * set. Hence, the size of TID-To-Link mapping control is one
		 * octet.
		 */
		*ttlm_control_field = (u8)ttlm_control;

		wpa_printf(MSG_DEBUG, "TTLM IE added, dir:%d default_link_mapping:%d",
			   ttlm->direction, ttlm->default_link_mapping);
		pos += sizeof(*ttlm_elem) + sizeof(u8);

		return pos;
	}

	ttlm_control |= (ttlm->link_mapping_size << TTLM_CONTROL_LINK_MAPPING_SIZE_IDX)
			& TTLM_CONTROL_LINK_MAPPING_SIZE_MASK;

	for (tid = 0; tid < NUM_MAX_TIDS; tid++)
		if (ttlm->ieee_link_map_tid[tid])
			link_mapping_presence_indicator |= BIT(tid);

	ttlm_control |= (link_mapping_presence_indicator <<
			 TTLM_CONTROL_LINK_MAPPING_PRESENCE_INDICATOR_IDX)
			& TTLM_CONTROL_LINK_MAPPING_PRESENCE_INDICATOR_MASK;

	wpa_printf(MSG_DEBUG, "TTLM IE added, dir:%d link_mapping_presence_indicator:0x%x",
		   ttlm->direction, link_mapping_presence_indicator);

	/* The size of TID-To-Link mapping control is two octets when
	 * default link mapping is not set.
	 */
	*ttlm_control_field = host_to_le16(ttlm_control);
	pos += sizeof(*ttlm_elem) + sizeof(u16);

	link_mapping_of_tids = pos;

	for (tid = 0; tid < NUM_MAX_TIDS; tid++) {
		if (!ttlm->ieee_link_map_tid[tid])
			continue;
		if (!ttlm->link_mapping_size) {
			*(u16 *)link_mapping_of_tids =
				host_to_le16(ttlm->ieee_link_map_tid[tid]);
			wpa_printf(MSG_DEBUG, "link mapping of TID%d is %x",
				   tid, host_to_le16(ttlm->ieee_link_map_tid[tid]));
			link_mapping_of_tids += sizeof(u16);
		} else {
			*(u8 *)link_mapping_of_tids =
				ttlm->ieee_link_map_tid[tid];
			wpa_printf(MSG_DEBUG, "link mapping of TID%d is %x",
				   tid, ttlm->ieee_link_map_tid[tid]);
			link_mapping_of_tids += sizeof(u8);
		}
	}

	return link_mapping_of_tids;
}


int hostapd_build_ttlm_elem(struct ttlm_ongoing_negotiation_info *ttlm,
			    u8 **ttlm_elem, size_t *ttlm_elem_len)
{
	u8 *pos;
	u8 dir;

	if (!ttlm || !ttlm_elem || !ttlm_elem_len)
		return -1;

	*ttlm_elem_len = 0;

	if ((ttlm->ttlm_info[TTLM_DIRECTION_DL].direction == TTLM_DIRECTION_DL ||
	     ttlm->ttlm_info[TTLM_DIRECTION_UL].direction == TTLM_DIRECTION_UL) &&
	    ttlm->ttlm_info[TTLM_DIRECTION_BIDI].direction == TTLM_DIRECTION_BIDI) {
		wpa_printf(MSG_DEBUG, "Both DL/UL and BIDI TTLM IEs cannot exist at same time");
		return -1;
	}

	for (dir = 0; dir < TTLM_DIRECTION_MAX; dir++) {
		if (ttlm->ttlm_info[dir].direction != TTLM_DIRECTION_INVALID)
			*ttlm_elem_len += hostapd_get_ttlm_elem_len(&ttlm->ttlm_info[dir]);
	}

	if (*ttlm_elem_len == 0)
		return -1;

	*ttlm_elem = os_zalloc(*ttlm_elem_len);
	if (!*ttlm_elem)
		return -1;

	pos = *ttlm_elem;
	for (dir = 0; dir < TTLM_DIRECTION_MAX; dir++) {
		if (ttlm->ttlm_info[dir].direction != TTLM_DIRECTION_INVALID)
			pos = hostapd_add_ttlm_info_elem(pos, &ttlm->ttlm_info[dir]);
	}

	return 0;
}


static void hostapd_copy_configured_ttlm_to_sta_info(struct sta_info *sta,
						     struct hostapd_data *hapd,
						     struct ttlm_ongoing_negotiation_info
						     *ttlm_info, u8 dialog_token)
{
	struct ttlm_ongoing_negotiation_info *current_ttlm_info = NULL;
	struct ttlm_ongoing_negotiation_info *partner_ttlm_info = NULL;
	struct tid_to_link_map_info *partner_tid_map = NULL;
	struct hostapd_data *lhapd;
	struct sta_info *lsta;
	u8 dir;
	u8 tid;

	current_ttlm_info = &sta->mld_info.tid_map_info.ttlm_ongoing_negotiation_info;
	os_memcpy(current_ttlm_info, ttlm_info, sizeof(*current_ttlm_info));
	current_ttlm_info->dialog_token = dialog_token;

	for_each_mld_link(lhapd, hapd) {
		lsta = ap_get_sta(lhapd, sta->addr);
		if (lsta && lsta == sta)
			continue;

		if (lsta && lsta->mld_info.mld_sta) {
			partner_tid_map = &lsta->mld_info.tid_map_info;
			partner_ttlm_info = &partner_tid_map->ttlm_ongoing_negotiation_info;
			os_memcpy(partner_ttlm_info, ttlm_info, sizeof(*partner_ttlm_info));
			partner_ttlm_info->dialog_token = dialog_token;
		}
	}

	wpa_printf(MSG_DEBUG, "Ongoing TTLM:dialog_token:%d",
		   current_ttlm_info->dialog_token);

	for (dir = 0; dir < TTLM_DIRECTION_MAX; dir++) {
		wpa_printf(MSG_DEBUG, "dir:%d default_link_mapping:%d",
			   current_ttlm_info->ttlm_info[dir].direction,
			   current_ttlm_info->ttlm_info[dir].default_link_mapping);
		for (tid = 0; tid < NUM_MAX_TIDS; tid++) {
			wpa_printf(MSG_DEBUG, "ttlm_links[%d]:0x%x", tid,
				   current_ttlm_info->ttlm_info[dir].ieee_link_map_tid[tid]);
		}
	}
}


int hostapd_send_ttlm_req(struct hostapd_data *hapd, struct ttlm_ongoing_negotiation_info *ttlm,
			  struct sta_info *sta)
{
	struct hostapd_data *lhapd;
	size_t ttlm_elem_len;
	struct wpabuf *buf;
	u8 dialog_token;
	u8 *ttlm_elem;
	int ret;

	if (!ttlm)
		return -1;

	dialog_token = ++sta->mld_info.tid_map_info.ttlm_ongoing_negotiation_info.dialog_token;

	if (hostapd_build_ttlm_elem(ttlm, &ttlm_elem, &ttlm_elem_len) < 0)
		return -1;

	/* Allocate action frame buffer (3 bytes header + IE data) */
	buf = wpabuf_alloc(sizeof(u8) + sizeof(u16) + ttlm_elem_len);
	if (!buf) {
		os_free(ttlm_elem);
		return -1;
	}

	wpabuf_put_u8(buf, WLAN_ACTION_PROTECTED_EHT);
	wpabuf_put_u8(buf, WLAN_PROT_EHT_T2L_MAPPING_REQUEST);
	wpabuf_put_u8(buf, dialog_token);
	wpabuf_put_data(buf, ttlm_elem, ttlm_elem_len);

	if (hapd->mld_link_id != sta->mld_assoc_link_id) {
		for_each_mld_link(lhapd, hapd) {
			if (lhapd->mld_link_id != sta->mld_assoc_link_id)
				continue;
			hapd = lhapd;
			break;
		}
	}

	ret = hostapd_drv_send_action(hapd, hapd->iface->freq, 0, sta->addr,
				      wpabuf_head(buf), wpabuf_len(buf));

	if (ret == 0) {
		wpa_printf(MSG_DEBUG, "TTLM request frame is sent");
		hostapd_copy_configured_ttlm_to_sta_info(sta, hapd, ttlm, dialog_token);
	} else
		wpa_printf(MSG_ERROR, "Failed to send TTLM request frame");

	wpabuf_free(buf);
	os_free(ttlm_elem);

	return ret;
}


static void hostapd_reset_ttlm_info(struct ttlm_info *ttlm)
{
	u8 dir;

	for (dir = 0; dir < TTLM_DIRECTION_MAX; dir++) {
		ttlm[dir].default_link_mapping = true;
		os_memset(ttlm[dir].ieee_link_map_tid, 0,
			  sizeof(u16) * NUM_MAX_TIDS);
	}
}


static void hostapd_copy_negotiated_ttlm_info_to_sta(struct hostapd_data *hapd,
						     struct sta_info *sta,
						     struct ttlm_ongoing_negotiation_info
						     *ongoing_ttlm)
{
	struct ttlm_prev_negotiated_info *negotiated_ttlm = NULL;
	struct ttlm_info *negotiated_ttlm_of_tids = NULL;
	struct ttlm_info *ongoing_ttlm_of_tids = NULL;
	struct ttlm_ongoing_negotiation_info *lsta_ttlm;
	struct hostapd_data *lhapd;
	struct sta_info *lsta;
	int i, dir, tid;

	negotiated_ttlm = &sta->mld_info.tid_map_info.ttlm_prev_negotiated_info;
	negotiated_ttlm->dialog_token = ongoing_ttlm->dialog_token;

	for (i = 0; i < TTLM_DIRECTION_MAX; i++) {
		negotiated_ttlm->ttlm_info[i].direction = TTLM_DIRECTION_INVALID;
		if (ongoing_ttlm->ttlm_info[i].direction == TTLM_DIRECTION_INVALID)
			continue;

		dir = ongoing_ttlm->ttlm_info[i].direction;

		/* Populate the ongoing TTLM info into negotiated TTLM directions UL
		 * and DL when direction is BIDI
		 */
		if (dir == TTLM_DIRECTION_BIDI) {
			for (int j = 0; j < TTLM_DIRECTION_BIDI; j++) {
				negotiated_ttlm_of_tids = &negotiated_ttlm->ttlm_info[j];
				ongoing_ttlm_of_tids = &ongoing_ttlm->ttlm_info[dir];

				if (j == TTLM_DIRECTION_DL)
					negotiated_ttlm_of_tids->direction =
						TTLM_DIRECTION_DL;
				else
					negotiated_ttlm_of_tids->direction =
						TTLM_DIRECTION_UL;

				negotiated_ttlm_of_tids->default_link_mapping =
					ongoing_ttlm_of_tids->default_link_mapping;

				for (tid = 0; tid < NUM_MAX_TIDS; tid++) {
					negotiated_ttlm_of_tids->ieee_link_map_tid[tid] =
						ongoing_ttlm_of_tids->ieee_link_map_tid[tid];
				}

				negotiated_ttlm_of_tids->link_mapping_size =
					ongoing_ttlm_of_tids->link_mapping_size;
			}
		} else {
			negotiated_ttlm_of_tids = &negotiated_ttlm->ttlm_info[dir];
			ongoing_ttlm_of_tids = &ongoing_ttlm->ttlm_info[dir];

			negotiated_ttlm_of_tids->direction = ongoing_ttlm_of_tids->direction;
			negotiated_ttlm_of_tids->default_link_mapping =
				ongoing_ttlm_of_tids->default_link_mapping;

			for (tid = 0; tid < NUM_MAX_TIDS; tid++) {
				negotiated_ttlm_of_tids->ieee_link_map_tid[tid] =
					ongoing_ttlm_of_tids->ieee_link_map_tid[tid];
			}

			negotiated_ttlm_of_tids->link_mapping_size =
				ongoing_ttlm_of_tids->link_mapping_size;
		}
	}

	if ((negotiated_ttlm->ttlm_info[TTLM_DIRECTION_DL].direction ==
	     TTLM_DIRECTION_DL) ||
	    (negotiated_ttlm->ttlm_info[TTLM_DIRECTION_UL].direction ==
	     TTLM_DIRECTION_UL)) {
		os_memset(&negotiated_ttlm->ttlm_info[TTLM_DIRECTION_BIDI], 0,
			  sizeof(struct ttlm_info));
		negotiated_ttlm->ttlm_info[TTLM_DIRECTION_BIDI].direction =
			TTLM_DIRECTION_INVALID;
	}

	for_each_mld_link(lhapd, hapd) {
		lsta = ap_get_sta(lhapd, sta->addr);
		if (lsta && lsta->mld_info.mld_sta) {
			lsta_ttlm = &lsta->mld_info.tid_map_info.ttlm_ongoing_negotiation_info;
			lsta_ttlm->ttlm_resp_type = TTLM_RESP_TYPE_INVALID;
			lsta_ttlm->dialog_token = 0;
			hostapd_reset_ttlm_info(lsta_ttlm->ttlm_info);
		}
	}
}


static void hostapd_fill_ttlm_nl_params(struct driver_ttlm_info *driver_ttlm_info,
					struct ttlm_prev_negotiated_info *negotiated_ttlm)
{
	u8 dir_mask[3] = {BIT(TTLM_DIRECTION_DL), BIT(TTLM_DIRECTION_UL),
			  BIT(TTLM_DIRECTION_BIDI)};
	int i, dir;

	for (i = 0; i < TTLM_DIRECTION_MAX; i++) {
		if (negotiated_ttlm->ttlm_info[i].direction == TTLM_DIRECTION_INVALID)
			continue;

		dir = negotiated_ttlm->ttlm_info[i].direction;
		driver_ttlm_info->dir_bmap |= dir_mask[dir];

		/* As either DLINK or ULINK values can be sent via NL,
		 * when the direction is BIDI populated the ttlm info
		 * in both DL and UL directions and hence checking only
		 * UL/DL directions here to fill driver ttlm info params.
		 */
		if (dir == TTLM_DIRECTION_DL)
			os_memcpy(driver_ttlm_info->dlink,
				  negotiated_ttlm->ttlm_info[dir].ieee_link_map_tid,
				  sizeof(driver_ttlm_info->dlink));
		else if (dir == TTLM_DIRECTION_UL)
			os_memcpy(driver_ttlm_info->ulink,
				  negotiated_ttlm->ttlm_info[dir].ieee_link_map_tid,
				  sizeof(driver_ttlm_info->ulink));
	}
}


int hostapd_apply_ttlm_mapping_to_driver(struct hostapd_data *hapd, struct sta_info *sta)
{
	struct ttlm_ongoing_negotiation_info *ongoing_ttlm;
	struct driver_ttlm_info driver_ttlm_info = {};
	int ret;

	ongoing_ttlm = &sta->mld_info.tid_map_info.ttlm_ongoing_negotiation_info;
	hostapd_copy_negotiated_ttlm_info_to_sta(hapd, sta, ongoing_ttlm);
	hostapd_fill_ttlm_nl_params(&driver_ttlm_info,
				    &sta->mld_info.tid_map_info.ttlm_prev_negotiated_info);

	ret = hostapd_drv_set_ttlm_link_mapping(hapd, &driver_ttlm_info, sta->addr);
	if (ret)
		wpa_printf(MSG_ERROR, "Failed to send ttlm params to driver");

	return ret;
}


bool hostapd_is_mapping_homogeneous(struct ttlm_ongoing_negotiation_info *ongoing_ttlm)
{
	u8 tid, i;

	for (i = 0; i < TTLM_DIRECTION_MAX; i++) {
		for (tid = 1; tid < NUM_MAX_TIDS; tid++) {
			if (ongoing_ttlm->ttlm_info[i].direction == TTLM_DIRECTION_INVALID)
				break;

			if (ongoing_ttlm->ttlm_info[i].ieee_link_map_tid[tid] !=
			    ongoing_ttlm->ttlm_info[i].ieee_link_map_tid[0]) {
				wpa_printf(MSG_DEBUG, "Mapping is not homogeneous");
				return false;
			}
		}
	}

	return true;
}


int hostapd_handle_ttlm_resp(struct hostapd_data *hapd, struct sta_info *sta,
			     const u8 *buf, size_t len)
{
	const struct ieee80211_mgmt *mgmt = (const struct ieee80211_mgmt *) buf;
	struct ttlm_ongoing_negotiation_info *ongoing_ttlm;
	int ret = 0;

	if (!sta) {
		wpa_printf(MSG_ERROR, "Station is not found");
		return -1;
	}
	ongoing_ttlm = &sta->mld_info.tid_map_info.ttlm_ongoing_negotiation_info;

	if (ongoing_ttlm->dialog_token != mgmt->u.action.u.ttlm_resp.dialog_token) {
		wpa_printf(MSG_ERROR, "TTLM dialog token mismatch: expected:%d, received:%d",
			   ongoing_ttlm->dialog_token, mgmt->u.action.u.ttlm_resp.dialog_token);
		hostapd_send_ttlm_teardown(hapd, sta);
		return -1;
	}

	ongoing_ttlm->ttlm_resp_type = mgmt->u.action.u.ttlm_resp.status_code;
	wpa_printf(MSG_DEBUG, "TTLM response received: dialog_token:%d response_code:%d",
		   ongoing_ttlm->dialog_token, ongoing_ttlm->ttlm_resp_type);

	if (ongoing_ttlm->ttlm_resp_type == TTLM_RESP_TYPE_SUCCESS)
		ret = hostapd_apply_ttlm_mapping_to_driver(hapd, sta);
	else if (ongoing_ttlm->ttlm_resp_type == TTLM_RESP_TYPE_PREFERRED_TID_TO_LINK_MAPPING)
		wpa_printf(MSG_DEBUG, "Preferred mapping is suggested");
	else
		wpa_printf(MSG_DEBUG, "Denied Tid to link mapping");

	return ret;
}


static int hostapd_parse_ttlm_elem(struct hostapd_data *hapd,
				   const struct ieee80211_ttlm_elem *ttlm,
				   struct ttlm_info *ttlm_info)
{
	u8 control, tid, link_mapping_presence_ind, map_size;
	u8 *pos;
	enum ttlm_dir dir;

	if (!ttlm) {
		wpa_printf(MSG_ERROR, "IE buffer is NULL");
		return -1;
	}

	pos = (void *)ttlm->optional;
	control = ttlm->control;

	if (control == 0)
		return -1;

	if (control & (TTLM_CONTROL_MAPPING_SWITCH_TIME_PRESENT_MASK |
		       TTLM_CONTROL_EXPECTED_DURATION_PRESENT_MASK)) {
		wpa_printf(MSG_ERROR, "Invalid TTLM element");
		return -1;
	}

	dir = control & TTLM_CONTROL_DIRECTION_MASK;

	if (dir >= TTLM_DIRECTION_INVALID) {
		wpa_printf(MSG_ERROR, "Invalid direction");
		return -1;
	}

	ttlm_info->direction = dir;
	ttlm_info->default_link_mapping = control & TTLM_CONTROL_DEFAULT_LINK_MAPPING_MASK;

	if (ttlm_info->default_link_mapping) {
		wpa_printf(MSG_DEBUG, "Default link mapping");
		return 0;
	}

	ttlm_info->link_mapping_size = control & TTLM_CONTROL_LINK_MAPPING_SIZE_MASK;

	link_mapping_presence_ind = *pos;
	pos++;

	if (ttlm_info->link_mapping_size) {
		/* Link mapping of TIDs is 1 octet if link_mapping_size is set to 1*/
		map_size = 1;
	} else {
		/* Link mapping of TIDs is 2 octet if link_mapping_size is set to 0*/
		map_size = 2;
	}

	for (tid = 0; tid < NUM_MAX_TIDS; tid++) {
		if (!(link_mapping_presence_ind & BIT(tid)))
			continue;

		if (map_size == 1)
			ttlm_info->ieee_link_map_tid[tid] = *pos;
		else
			ttlm_info->ieee_link_map_tid[tid] = host_to_le16(*pos);

		pos += map_size;
	}

	return 0;
}


int hostapd_handle_ttlm_assoc_req(struct hostapd_data *hapd, const struct ieee80211_mgmt *mgmt,
				  size_t len, struct sta_info *sta, const u8 *elem,
				  size_t elem_len)
{
	struct ttlm_ongoing_negotiation_info *ongoing_ttlm;
	struct ieee802_11_elems elems;
	struct ttlm_info ttlm_info;
	enum ttlm_dir dir;
	int retval;
	u8 i;

	sta->mld_info.tid_map_info.ttlm_ongoing_negotiation_info.ttlm_resp_type = -1;
	if (!hapd->conf->ttlm_enable)
		return WLAN_STATUS_REQUEST_DECLINED;

	if (ieee802_11_parse_elems(elem, elem_len, &elems, 0) == ParseFailed) {
		wpa_printf(MSG_ERROR, "Could not parse assocReq from " MACSTR,
			   MAC2STR(mgmt->sa));
		return WLAN_STATUS_INVALID_IE;
	}

	ongoing_ttlm = os_zalloc(sizeof(struct ttlm_ongoing_negotiation_info));
	if (!ongoing_ttlm) {
		wpa_printf(MSG_ERROR, "Memory allocation for ongoing_ttlm failed");
		return -1;
	}

	if (!elems.ttlm_num) {
		wpa_printf(MSG_ERROR, "No TTLM elements present");
		os_free(ongoing_ttlm);
		return -1;
	}

	for (dir = 0; dir < TTLM_DIRECTION_MAX; dir++)
		ongoing_ttlm->ttlm_info[dir].direction = TTLM_DIRECTION_INVALID;

	for (i = 0; i < elems.ttlm_num; i++) {
		retval = hostapd_parse_ttlm_elem(hapd, elems.ttlm[i], &ttlm_info);
		if (!retval && ttlm_info.direction < TTLM_DIRECTION_MAX) {
			os_memcpy(&ongoing_ttlm->ttlm_info[ttlm_info.direction],
				  &ttlm_info, sizeof(struct ttlm_info));
		} else {
			wpa_printf(MSG_ERROR, "Failed to parse TTLM IE");
			os_free(ongoing_ttlm);
			return WLAN_STATUS_INVALID_IE;
		}
	}

	if ((ongoing_ttlm->ttlm_info[TTLM_DIRECTION_DL].direction == TTLM_DIRECTION_DL ||
	     ongoing_ttlm->ttlm_info[TTLM_DIRECTION_UL].direction == TTLM_DIRECTION_UL) &&
	    ongoing_ttlm->ttlm_info[TTLM_DIRECTION_BIDI].direction == TTLM_DIRECTION_BIDI) {
		wpa_printf(MSG_DEBUG, "Both DL/UL and BIDI TTLM IEs cannot exist at same time");
		os_memset(ongoing_ttlm, 0, sizeof(*ongoing_ttlm));
		ongoing_ttlm->ttlm_resp_type = WLAN_STATUS_DENIED_TID_TO_LINK_MAPPING;
	}

	os_memcpy(&sta->mld_info.tid_map_info.ttlm_ongoing_negotiation_info, ongoing_ttlm,
		  sizeof(struct ttlm_ongoing_negotiation_info));

	if (ongoing_ttlm->ttlm_resp_type != 0) {
		wpa_printf(MSG_DEBUG, "DENIED response type");
		ongoing_ttlm->ttlm_info[TTLM_DIRECTION_BIDI].direction = TTLM_DIRECTION_BIDI;
		ongoing_ttlm->ttlm_info[TTLM_DIRECTION_DL].direction = TTLM_DIRECTION_INVALID;
		ongoing_ttlm->ttlm_info[TTLM_DIRECTION_UL].direction = TTLM_DIRECTION_INVALID;
		ongoing_ttlm->ttlm_info->default_link_mapping = true;

		os_memcpy(&sta->mld_info.tid_map_info.ttlm_ongoing_negotiation_info, ongoing_ttlm,
			  sizeof(struct ttlm_ongoing_negotiation_info));

		sta->mld_info.tid_map_info.ttlm_ongoing_negotiation_info.ttlm_resp_type =
			WLAN_STATUS_DENIED_TID_TO_LINK_MAPPING;

		os_free(ongoing_ttlm);
		return WLAN_STATUS_DENIED_TID_TO_LINK_MAPPING;
	}

	sta->mld_info.tid_map_info.ttlm_ongoing_negotiation_info.ttlm_resp_type =
		WLAN_STATUS_SUCCESS;

	os_free(ongoing_ttlm);
	wpa_printf(MSG_DEBUG, "TTLM IE in assoc request has been parsed successfully");
	return WLAN_STATUS_SUCCESS;
}


int hostapd_send_ttlm_resp_action(struct hostapd_data *hapd,
				  struct sta_info *sta)
{
	struct ttlm_ongoing_negotiation_info *ongoing_ttlm;
	struct hostapd_data *lhapd;
	size_t ttlm_elem_len;
	struct wpabuf *buf;
	u8 *ttlm_elem;
	int ret;

	buf = wpabuf_alloc(sizeof(u32) + sizeof(u8));
	if (!buf)
		return -1;

	ongoing_ttlm = &sta->mld_info.tid_map_info.ttlm_ongoing_negotiation_info;
	wpabuf_put_u8(buf, WLAN_ACTION_PROTECTED_EHT);
	wpabuf_put_u8(buf, WLAN_PROT_EHT_T2L_MAPPING_RESPONSE);
	wpabuf_put_u8(buf, ongoing_ttlm->dialog_token);
	wpabuf_put_le16(buf, ongoing_ttlm->ttlm_resp_type);

	if (ongoing_ttlm->ttlm_resp_type == TTLM_RESP_TYPE_PREFERRED_TID_TO_LINK_MAPPING) {
		if (hostapd_build_ttlm_elem(ongoing_ttlm, &ttlm_elem, &ttlm_elem_len) < 0 ||
		    ttlm_elem_len == 0) {
			wpabuf_free(buf);
			return -1;
		}

		if (wpabuf_resize(&buf, ttlm_elem_len) != 0) {
			os_free(ttlm_elem);
			wpabuf_free(buf);
			return -1;
		}
		wpabuf_put_data(buf, ttlm_elem, ttlm_elem_len);
		os_free(ttlm_elem);
	}

	if (hapd->mld_link_id != sta->mld_assoc_link_id) {
		for_each_mld_link(lhapd, hapd) {
			if (lhapd->mld_link_id != sta->mld_assoc_link_id)
				continue;
			hapd = lhapd;
			break;
		}
	}

	ret = hostapd_drv_send_action(hapd, hapd->iface->freq, 0, sta->addr,
				      wpabuf_head(buf), wpabuf_len(buf));

	if (ret == 0) {
		wpa_printf(MSG_DEBUG, "TTLM response frame is sent");
		hostapd_copy_configured_ttlm_to_sta_info(sta, hapd, ongoing_ttlm,
							 ongoing_ttlm->dialog_token);
	} else
		wpa_printf(MSG_ERROR, "Failed to send TTLM response frame");

	wpabuf_free(buf);
	return ret;

}


void hostapd_handle_ttlm_req(struct hostapd_data *hapd, struct sta_info *sta,
			     const u8 *buf, size_t len)
{
	const struct ieee80211_mgmt *mgmt = (const struct ieee80211_mgmt *) buf;
	struct ttlm_ongoing_negotiation_info *ongoing_ttlm, *configured_ttlm;
	struct ieee802_11_elems elems;
	struct ttlm_info ttlm_info;
	bool homogeneous_map;
	enum ttlm_dir dir;
	const u8 *pos;
	size_t ie_len;
	int retval, i;

	if (!hapd->conf->ttlm_enable) {
		wpa_printf(MSG_ERROR, "TTLM negotiation support is disabled");
		return;
	}

	ongoing_ttlm = os_zalloc(sizeof(struct ttlm_ongoing_negotiation_info));
	if (!ongoing_ttlm) {
		wpa_printf(MSG_ERROR, "Memory allocation for ongoing_ttlm failed");
		return;
	}

	ongoing_ttlm->dialog_token = mgmt->u.action.u.ttlm_req.dialog_token;
	pos = mgmt->u.action.u.ttlm_req.variable;
	ie_len = buf + len - pos;

	if (ieee802_11_parse_elems(pos, ie_len, &elems, 0) == ParseFailed) {
		wpa_printf(MSG_ERROR, "Could not parse TTLM request frame received "
			   MACSTR, MAC2STR(mgmt->sa));
		os_free(ongoing_ttlm);
		return;
	}

	for (dir = 0; dir < TTLM_DIRECTION_MAX; dir++)
		ongoing_ttlm->ttlm_info[dir].direction = TTLM_DIRECTION_INVALID;

	for (i = 0; i < elems.ttlm_num; i++) {
		retval = hostapd_parse_ttlm_elem(hapd, elems.ttlm[i], &ttlm_info);
		if (!retval && ttlm_info.direction < TTLM_DIRECTION_MAX) {
			ongoing_ttlm->ttlm_resp_type = TTLM_RESP_TYPE_SUCCESS;
			os_memcpy(&ongoing_ttlm->ttlm_info[ttlm_info.direction],
				  &ttlm_info, sizeof(struct ttlm_info));
		} else {
			wpa_printf(MSG_ERROR, "Failed to parse TTLM IE");
			os_free(ongoing_ttlm);
			return;
		}
	}

	homogeneous_map = hostapd_is_mapping_homogeneous(ongoing_ttlm);
	if (homogeneous_map == false) {
		wpa_printf(MSG_DEBUG, "Request is with disjoint mapping");
		os_free(ongoing_ttlm);
		return;
	}

	if ((ongoing_ttlm->ttlm_info[TTLM_DIRECTION_DL].direction == TTLM_DIRECTION_DL ||
	     ongoing_ttlm->ttlm_info[TTLM_DIRECTION_UL].direction == TTLM_DIRECTION_UL) &&
	    ongoing_ttlm->ttlm_info[TTLM_DIRECTION_BIDI].direction == TTLM_DIRECTION_BIDI) {
		wpa_printf(MSG_DEBUG, "Both DL/UL and BIDI TTLM IEs cannot exist at same time");
		os_memset(ongoing_ttlm, 0, sizeof(*ongoing_ttlm));
		for (dir = 0; dir < TTLM_DIRECTION_MAX; dir++)
			ongoing_ttlm->ttlm_info[dir].direction = TTLM_DIRECTION_INVALID;
		ongoing_ttlm->ttlm_resp_type = TTLM_RESP_TYPE_DENIED_TID_TO_LINK_MAPPING;
	}

	configured_ttlm = &sta->mld_info.tid_map_info.ttlm_ongoing_negotiation_info;
	if (configured_ttlm->ttlm_resp_type !=
	    TTLM_RESP_TYPE_PREFERRED_TID_TO_LINK_MAPPING && configured_ttlm->ttlm_resp_type !=
	    TTLM_RESP_TYPE_DENIED_TID_TO_LINK_MAPPING) {
		os_memcpy(configured_ttlm, ongoing_ttlm,
			  sizeof(struct ttlm_ongoing_negotiation_info));
	}

	sta->mld_info.tid_map_info.ttlm_ongoing_negotiation_info.dialog_token =
		ongoing_ttlm->dialog_token;

	wpa_printf(MSG_DEBUG, "TTLM request has been parsed successfully");
	hostapd_send_ttlm_resp_action(hapd, sta);
	os_free(ongoing_ttlm);
}


int hostapd_ttlm_resp_tx_status(struct hostapd_data *hapd, struct sta_info *sta,
				int ok)
{
	int ret = 0;

	if (!sta) {
		wpa_printf(MSG_ERROR, "Station is not found");
		return -1;
	}

	wpa_printf(MSG_DEBUG, "TTLM response: TX status: ok=%d", ok);
	if (ok) {
		ret = hostapd_apply_ttlm_mapping_to_driver(hapd, sta);
		if (ret)
			wpa_printf(MSG_ERROR, "Failed to send ttlm params to driver");
	}

	return ret;
}
