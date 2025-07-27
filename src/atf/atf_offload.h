/*
 * Airtime Fairness offload feature wrappers and apis.
 *
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.*
 */

#ifndef ATF_OFFLOAD_H
#define ATF_OFFLOAD_H

#include <sys/un.h>
#include "utils/includes.h"
#include "utils/common.h"
#include "utils/list.h"

#define ATF_INVALID_GROUP_ID 0xFF
#define ATF_MAX_SSID_GROUP 16
#define WLAN_SSID_MAX 16
#define WLAN_SSID_MAX_LEN SSID_MAX_LEN
#define ATF_MAX_SSID 16
#define ATF_MAX_PEER 512

/**
 * enum atf_offload_update_flag - Airtime update flags for driver
 * @ATF_OFFLOAD_FULL_UPDATE: Full update and default update method
 * @ATF_OFFLOAD_PARTIAL_JOIN_UPDATE: Partial update method for peer join case
 * @ATF_OFFLOAD_PARTIAL_LEAVE_UPDATE: Partial update method for peer leave case
 * @ATF_OFFLOAD_NO_UPDATE: set when driver is updated with latest.
 */
enum atf_offload_update_flag {
	ATF_OFFLOAD_FULL_UPDATE,
	ATF_OFFLOAD_PARTIAL_JOIN_UPDATE,
	ATF_OFFLOAD_PARTIAL_LEAVE_UPDATE,
	ATF_OFFLOAD_NO_UPDATE,
};

#define ATF_OFFLOAD_SET_NO_UPDATE(algo) (algo->update_flag = ATF_OFFLOAD_NO_UPDATE)

#define ATF_OFFLOAD_SET_FULL_UPDATE(algo) (algo->update_flag = ATF_OFFLOAD_FULL_UPDATE)

#define ATF_OFFLOAD_IS_FULL_UPDATE(algo) (algo->update_flag == ATF_OFFLOAD_FULL_UPDATE)

#define ATF_OFFLOAD_IS_JOIN_UPDATE(algo)                                                 \
	(algo->update_flag == ATF_OFFLOAD_PARTIAL_JOIN_UPDATE)

#define ATF_OFFLOAD_IS_LEAVE_UPDATE(algo)                                                \
	(algo->update_flag == ATF_OFFLOAD_PARTIAL_LEAVE_UPDATE)

#define ATF_OFFLOAD_SET_JOIN_UPDATE(algo)                                                \
	do {                                                                             \
		if (!ATF_OFFLOAD_IS_FULL_UPDATE(algo))                                   \
			algo->update_flag = ATF_OFFLOAD_PARTIAL_JOIN_UPDATE;             \
	} while (0)

#define ATF_OFFLOAD_SET_LEAVE_UPDATE(algo)                                               \
	do {                                                                             \
		if (!ATF_OFFLOAD_IS_FULL_UPDATE(algo) &&                                 \
		    !ATF_OFFLOAD_IS_JOIN_UPDATE(algo))                                   \
			algo->update_flag = ATF_OFFLOAD_PARTIAL_LEAVE_UPDATE;            \
	} while (0)

#define ATF_SET_STA_TO_UPDATE(sta) (sta.is_updated = true)

#define ATF_CLEAR_STA_UPDATED(sta) (sta.is_updated = false)

#define ATF_IS_STA_UPDATED(sta) (sta.is_updated)

/**
 * @struct atf_peer_config - per sta config.
 */

struct atf_peer_config {
	struct atf_group *group;
	struct atf_algo *algo;
	u8 link_id;
	u32 user_cfg_airtime;
	u8 addr[ETH_ALEN];

	/* add this node to atf_algo */
	struct dl_list list;
	char group_name[WLAN_SSID_MAX_LEN];
};

/**
 * @struct atf_peer - atf peer config reference used in sta_info.
 */

struct atf_peer {
	bool atf_configured;
	struct atf_peer_config *peer_cfg_ref;
	struct sta_info *sta;
	u32 calculated_airtime;

	/* Flag to indicate whether it is updated to driver */
	bool is_updated;
};

/**
 * @struct atf_ssid_config - per ssid config when group is not enabled.
 */
struct atf_ssid_config {
	struct atf_algo *algo;
	struct atf_group *group;
	char ifname[IFNAMSIZ + 1];
	char name[WLAN_SSID_MAX_LEN + 1];
	u32 user_cfg_airtime;

	/* add this node to atf_algo */
	struct dl_list list;
};

/**
 * @struct atf_group - configurations of each atf group which
 * 		       consist one or more ssids.
 */

struct atf_group {
	struct atf_algo *algo;
	u8 index;
	char name[WLAN_SSID_MAX_LEN + 1];

	u32 num_of_ssid;
	char ssidname[WLAN_SSID_MAX][WLAN_SSID_MAX_LEN + 1];
	u32 user_cfg_airtime;

	/* add this node to atf_algo */
	struct dl_list list;
};

/**
 * @struct atf_algo - per-radio specific atf algorithm
 */

struct atf_algo {
	struct hostapd_iface *iface;

	/* This node will be added to atf_offload global structure's
	 * algo_list
	 */
	struct dl_list list;
	struct dl_list groups;
	u8 num_group_cfg;
	bool atf_enabled;
	struct dl_list ssid_cfgs;
	u8 num_ssid_cfg;
	struct dl_list peer_cfgs;
	u16 num_peer_cfg;

	/* Feature flags */
	bool ssid_group_enabled;
	bool atfstrictsched_enabled;

	/* used in ATF distribution logic*/
	enum atf_offload_update_flag update_flag;
	/*Flag to indicate update task scheduled */
	bool atf_tasksched;

	/* used for ATF config parsing*/
	struct atf_group *last_group;
	struct atf_ssid_config *last_ssid_cfg;
	struct atf_peer_config *last_peer_cfg;
};

/**
 * @struct atf_offload - Global structure to hold the state of atf_offload
 */
struct atf_offload {
	struct dl_list algo_list;
};

#ifdef CONFIG_ATF_OFFLOAD

void atf_offload_init(struct hapd_interfaces *ifaces);

void atf_offload_deinit(void);

void atf_init_algo(struct hostapd_iface *iface);

void atf_deinit_algo(struct hostapd_iface *iface);

struct atf_group *atf_allocate_group(const char *name, struct atf_algo *algo);

void atf_free_group(struct atf_group *group);

struct atf_group *atf_find_group_by_name(const char *name, struct atf_algo *algo);

void
atf_free_algo_configs(struct atf_algo *algo);

struct atf_ssid_config *atf_find_ssid_config_by_name(char *name, struct atf_algo *algo);

struct atf_ssid_config *atf_allocate_ssid_config(char *name, struct atf_algo *algo);

void atf_free_ssid_config(struct atf_ssid_config *ssid);

struct atf_peer_config *atf_find_peer_config_by_mac(u8 *mac, struct atf_algo *algo);

struct atf_peer_config *atf_allocate_peer_config(u8 *macaddr, struct atf_algo *algo);

void atf_free_peer_config(struct atf_peer_config *peer_config);

int atf_timer_start(struct hostapd_iface *iface);

void atf_timer_stop(struct hostapd_iface *iface);

void atf_trigger_config_timer(struct hostapd_iface *iface);

void atf_join_leave_update(struct hostapd_iface *iface, struct sta_info *sta,
                           bool is_join);

#else

static inline void atf_offload_init(struct hapd_interfaces *ifaces)
{
}

static inline void atf_offload_deinit(void)
{
}

static inline void atf_init_algo(struct hostapd_iface *iface)
{
}

static inline void atf_deinit_algo(struct hostapd_iface *iface)
{
}

static inline void atf_join_leave_update(struct hostapd_iface *iface, struct sta_info *sta,
					 bool is_join)
{
}

#endif /* CONFIG_ATF_OFFLOAD */
#endif /* ATF_OFFLOAD_H */
