/*
 * hostapd / IEEE 802.11bn UHR SMD Neighborhood Update
 *
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: BSD-3-Clause-Clear
*/

#include "utils/includes.h"
#include "utils/common.h"
#include "utils/eloop.h"
#include "common/ieee802_11_defs.h"
#include "hostapd.h"
#include "neighbor_db.h"
#include "uhr_neighbor_update.h"

/*
 * Neighborhood Update TLV (payload carried in ETH_P_OUI)
 *
 * Element ID | Length | Update Type | BSSID | BSSID Info | OpClass | Channel |
 * PHY Type | Optional Subelements
 */
#define SMD_NEIGHBOR_TLV_EID 0xdd
/* Fixed body fields in nr->nr: BSSID + BSSID Info + Op Class + Channel + PHY Type */
#define NR_BODY_FIXED_LEN (ETH_ALEN + 4 + 1 + 1 + 1)
/* SMD TLV header: EID + Len + Update Type */
#define SMD_NEIGHBOR_TLV_HDR_LEN 3

static int smd_neighbor_update_build_tlv(struct hostapd_data *hapd,
					 enum smd_neighbor_update_type update_type,
					 struct wpabuf **tlv)
{
	struct hostapd_neighbor_entry *nr;
	struct wpabuf *buf;
	u8 *len_pos;

	/* Ensure own Neighbor Report entry is up-to-date */
	hostapd_neighbor_set_own_report(hapd);

	nr = hostapd_neighbor_get(hapd, hapd->own_addr, NULL);
	if (!nr || !nr->nr)
		return -1;

	if (wpabuf_len(nr->nr) < NR_BODY_FIXED_LEN)
		return -1;

	buf = wpabuf_alloc(SMD_NEIGHBOR_TLV_HDR_LEN + wpabuf_len(nr->nr));
	if (!buf)
		return -1;

	wpabuf_put_u8(buf, SMD_NEIGHBOR_TLV_EID);
	len_pos = wpabuf_put(buf, 1);
	wpabuf_put_u8(buf, update_type);
	wpabuf_put_buf(buf, nr->nr);

	*len_pos = wpabuf_len(buf) - 2;
	*tlv = buf;
	return 0;
}

int smd_neighbor_update_send(struct hostapd_data *hapd,
				  enum smd_neighbor_update_type update_type)
{
	struct wpabuf *tlv = NULL;
	int ret;

	ret = smd_neighbor_update_build_tlv(hapd, update_type, &tlv);
	if (ret < 0)
		return -1;

	/* TBD: send TLV via the transport mechanism. */
	wpabuf_free(tlv);
	return ret;
}

int smd_neighbor_update_init(struct hostapd_data *hapd)
{
	struct smd_neighbor_update_ctx *ctx;

	if (!hapd)
		return -1;

	if (hapd->smd_neighbor_update_ctx)
		return 0;

	ctx = os_zalloc(sizeof(*ctx));
	if (!ctx)
		return -1;

	ctx->hapd = hapd;
	dl_list_init(&ctx->entries);

	hapd->smd_neighbor_update_ctx = ctx;

	smd_neighbor_update_send(hapd, SMD_NEIGHBOR_UPDATE_NEW_AP);
	return 0;
}

void smd_neighbor_update_deinit(struct hostapd_data *hapd)
{
	struct smd_neighbor_update_ctx *ctx;
	struct smd_neighbor_update_entry *e, *prev;

	if (!hapd)
		return;

	ctx = hapd->smd_neighbor_update_ctx;
	if (!ctx)
		return;

	dl_list_for_each_safe(e, prev, &ctx->entries,
			      struct smd_neighbor_update_entry, list) {
		dl_list_del(&e->list);
		os_free(e);
	}

	hapd->smd_neighbor_update_ctx = NULL;
	os_free(ctx);
}
