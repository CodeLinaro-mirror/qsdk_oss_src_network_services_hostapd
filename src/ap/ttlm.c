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
