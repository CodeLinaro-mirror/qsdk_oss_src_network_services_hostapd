/*
 * hostapd / IEEE 802.11bn UHR SMD Neighborhood Update
 *
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: BSD-3-Clause-Clear
*/

#ifndef SMD_NEIGHBOR_UPDATE_H
#define SMD_NEIGHBOR_UPDATE_H

#include "common/wpa_common.h"

/* Neighbor Update TLV types */
enum smd_neighbor_update_type {
	SMD_NEIGHBOR_UPDATE_NEW_AP = 0x01,
	SMD_NEIGHBOR_UPDATE_MODIFY_AP = 0x02,
	SMD_NEIGHBOR_UPDATE_REMOVE_AP = 0x03,
};

struct smd_neighbor_update_entry {
	struct dl_list list;
	u8 bssid[ETH_ALEN];
};

struct smd_neighbor_update_ctx {
	struct hostapd_data *hapd;
	struct dl_list entries; /* smd_neighbor_update_entry */
};

/* Hostapd-facing API */
int smd_neighbor_update_init(struct hostapd_data *hapd);
void smd_neighbor_update_deinit(struct hostapd_data *hapd);

int smd_neighbor_update_send(struct hostapd_data *hapd,
				  enum smd_neighbor_update_type update_type);

void smd_neighbor_update_rx(struct hostapd_data *hapd, const u8 *src_addr,
			    const u8 *dst_addr, const u8 *data, size_t data_len,
			    u8 oui_suffix);
#endif /* SMD_NEIGHBOR_UPDATE_H */
