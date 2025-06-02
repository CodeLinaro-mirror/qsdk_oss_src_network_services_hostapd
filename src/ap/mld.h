/*
 * hostapd / MLD related shared defines
 * Copyright (c) 2002-2014, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef MLD_H
#define MLD_H

#ifdef CONFIG_IEEE80211BE
#include "ttlm.h"
#endif /* CONFIG_IEEE80211BE */

/*
 * enum peer_epcs_state - EPCS states of peer
 */
enum peer_epcs_state {
	EPCS_STATE_DISABLED = 0, /* The default state */
	EPCS_STATE_ENABLE_REQ_SENT, /* EPCS request sent to the peer, waiting for EPCS response */
	EPCS_STATE_ENABLED, /* EPCS session established */
};

/*
 * struct wlan_epcs_info - EPCS information of frame
 */
struct wlan_epcs_info {
	u8 action_code;
	u8 dialog_token;
	u16 status_code;
};

/*
 * struct mld_peer_epcs_info - per mld-peer epcs info
 */
struct mld_peer_epcs_info {
	bool is_epcs_capable;
	enum peer_epcs_state state;
	u8 self_gen_dialog_token;
	bool timer_started;
};

struct mld_link_info {
	u8 valid:1;
	u8 nstr_bitmap_len:2;
	u8 local_addr[ETH_ALEN];
	u8 peer_addr[ETH_ALEN];

	u8 nstr_bitmap[2];

	u16 capability;

	u16 status;
	u16 resp_sta_profile_len;
	u8 *resp_sta_profile;
};

struct mld_info {
	bool mld_sta;

	struct ml_common_info {
		u8 mld_addr[ETH_ALEN];
		u16 medium_sync_delay;
		u16 eml_capa;
		u16 mld_capa;
	} common_info;

	struct mld_link_info links[MAX_NUM_MLD_LINKS];
	struct mld_peer_epcs_info epcs;
#ifdef CONFIG_IEEE80211BE
	struct tid_to_link_map_info tid_map_info;
#endif /* CONFIG_IEEE80211BE */
};

#endif /* MLD_H */
