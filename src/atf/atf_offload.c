/*
 * Airtime Fairness offload feature wrappers and apis.
 *
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.*
 */

#include <sys/un.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "utils/includes.h"

#include "utils/common.h"
#include "utils/eloop.h"
#include "ap/hostapd.h"
#include "ap/ap_drv_ops.h"
#include "ap/sta_info.h"

#include "atf_offload.h"
#include "atf_offload_config.h"

struct atf_offload *atf = NULL;

/* one second timeout for Airtime distribution */
#define ATF_ALGO_TIMEOUT 1

struct atf_peer_config *
atf_allocate_peer_config(u8 *macaddr, struct atf_algo *algo)
{
	struct atf_peer_config *peer_config;

	if (algo->num_peer_cfg >= ATF_MAX_PEER)
		return NULL;

	peer_config = os_zalloc(sizeof(*peer_config));
	if (!peer_config)
		return NULL;

	os_memcpy(peer_config->addr, macaddr, ETH_ALEN);
	dl_list_init(&peer_config->list);
	dl_list_add(&algo->peer_cfgs, &peer_config->list);
	peer_config->algo = algo;
	algo->num_peer_cfg++;

	wpa_printf(MSG_INFO, "ATF: Added peer config %d", algo->num_peer_cfg);

	return peer_config;
}


void
atf_free_peer_config(struct atf_peer_config *peer_config)
{
	struct atf_algo *algo = peer_config->algo;

	if (!algo->num_peer_cfg)
		return;

	algo->num_peer_cfg--;
	dl_list_del(&peer_config->list);
	os_free(peer_config);
}


struct atf_peer_config *
atf_find_peer_config_by_mac(u8 *mac, struct atf_algo *algo)
{
	struct atf_peer_config *peer = NULL;

	if (!algo) {
		wpa_printf(MSG_ERROR, "ATF: algo is null");
		return NULL;
	}

	if (dl_list_empty(&algo->peer_cfgs)) {
		wpa_printf(MSG_DEBUG, "ATF: peer list is empty");
		return NULL;
	}

	dl_list_for_each(peer, &algo->peer_cfgs, struct atf_peer_config, list)
	{
		if (os_memcmp(mac, peer->addr, ETH_ALEN) == 0)
			return peer;
	}

	return NULL;
}


void
atf_iterate_peer_config(struct atf_algo *algo,
                        void (*callback)(struct atf_algo *, struct atf_peer_config *))
{
	struct atf_peer_config *peer;

	if (!algo) {
		wpa_printf(MSG_ERROR, "ATF: algo is null");
		return;
	}

	dl_list_for_each(peer, &algo->peer_cfgs, struct atf_peer_config, list)
		callback(algo, peer);
}


struct atf_ssid_config *
atf_allocate_ssid_config(char *name, struct atf_algo *algo)
{
	struct atf_ssid_config *ssid_config;

	if (algo->num_ssid_cfg >= ATF_MAX_SSID)
		return NULL;

	ssid_config = os_zalloc(sizeof(struct atf_ssid_config));
	if (!ssid_config)
		return NULL;

	os_strlcpy(ssid_config->name, name, sizeof(ssid_config->name));
	dl_list_init(&ssid_config->list);
	dl_list_add(&algo->ssid_cfgs, &ssid_config->list);
	ssid_config->algo = algo;
	algo->num_ssid_cfg++;

	wpa_printf(MSG_INFO, "ATF: Added ssid config %s [%d]", ssid_config->name,
	           algo->num_ssid_cfg);

	return ssid_config;
}


void
atf_free_ssid_config(struct atf_ssid_config *ssid)
{
	struct atf_algo *algo;

	if (!ssid) {
		wpa_printf(MSG_INFO, "ATF: %s ssid_config is NULL", __func__);
		return;
	}

	algo = ssid->algo;
	if (!algo->num_ssid_cfg)
		return;

	algo->num_ssid_cfg--;
	dl_list_del(&ssid->list);
	os_free(ssid);
}


struct atf_ssid_config *
atf_find_ssid_config_by_name(char *name, struct atf_algo *algo)
{

	struct atf_ssid_config *ssid;

	if (!name || !algo) {
		wpa_printf(MSG_ERROR, "ATF: %s invalid arguments", __func__);
		return NULL;
	}

	if (dl_list_empty(&algo->ssid_cfgs))
		return NULL;

	dl_list_for_each(ssid, &algo->ssid_cfgs, struct atf_ssid_config, list)
	{
		size_t len = strlen(ssid->name);
		if (strlen(name) == len && os_strncmp(name, ssid->name, len) == 0)
			return ssid;
	}
	return NULL;
}


int
atf_add_ssid_to_group(struct atf_group *group, const char *name)
{
	if (group->num_of_ssid == WLAN_SSID_MAX)
		return -1;

	wpa_printf(MSG_INFO, "ATF: Adding %s  to group %s", name, group->name);
	os_strlcpy(group->ssidname[group->num_of_ssid], name, WLAN_SSID_MAX_LEN);
	group->num_of_ssid++;

	return 0;
}


void
atf_clear_candidate_list(struct atf_group *group)
{
	struct sta_info *sta, *tmp;

	if (!dl_list_empty(&group->implicit_peers)) {
		dl_list_for_each_safe(sta, tmp, &group->implicit_peers, struct sta_info,
		                      atf_candidate_list)
		{
			dl_list_del(&sta->atf_candidate_list);
		}
	}

	if (!dl_list_empty(&group->explicit_peers)) {
		dl_list_for_each_safe(sta, tmp, &group->explicit_peers, struct sta_info,
		                      atf_candidate_list)
		{
			dl_list_del(&sta->atf_candidate_list);
		}
	}
}


void
atf_reset_group_values(struct atf_group *group)
{
	group->calculated_airtime = 0;
	group->total_explicit_airtime = 0;

	atf_clear_candidate_list(group);
	if (!dl_list_empty(&group->implicit_peers) ||
	    !dl_list_empty(&group->explicit_peers)) {
		wpa_printf(MSG_ERROR, "ATF: Unexpected! peer candidate list was not cleared\n");
	}
	dl_list_init(&group->implicit_peers);
	dl_list_init(&group->explicit_peers);
	group->num_impl_peers = 0;
	group->num_expl_peers = 0;
}


struct atf_group *
atf_allocate_group(const char *name, struct atf_algo *algo)
{
	struct atf_group *group;

	if (algo->num_group_cfg >= ATF_MAX_SSID_GROUP)
		return NULL;

	group = os_zalloc(sizeof(struct atf_group));
	if (!group)
		return NULL;

	group->index = algo->num_group_cfg;
	os_strlcpy(group->name, name, sizeof(group->name));

	dl_list_init(&group->list);
	dl_list_add(&algo->groups, &group->list);
	group->algo = algo;
	algo->num_group_cfg++;

	dl_list_init(&group->implicit_peers);
	dl_list_init(&group->explicit_peers);
	atf_reset_group_values(group);

	wpa_printf(MSG_INFO, "ATF: Added group %s [%d], no of groups %d", group->name,
	           group->index, algo->num_group_cfg);

	return group;
}


void
atf_free_group(struct atf_group *group)
{
	struct atf_algo *algo = group->algo;

	if (!algo->num_group_cfg)
		return;

	atf_reset_group_values(group);
	algo->num_group_cfg--;
	dl_list_del(&group->list);
	os_free(group);
	group = NULL;
}


static void
atf_free_peer_configs(struct atf_algo *algo)
{
	struct atf_peer_config *peer, *tmp;

	if (dl_list_empty(&algo->peer_cfgs))
		return;

	dl_list_for_each_safe(peer, tmp, &algo->peer_cfgs, struct atf_peer_config, list)
		atf_free_peer_config(peer);
}


static void
atf_free_ssid_configs(struct atf_algo *algo)
{
	struct atf_ssid_config *ssid_cfg, *tmp;

	if (dl_list_empty(&algo->ssid_cfgs))
		return;

	dl_list_for_each_safe(ssid_cfg, tmp, &algo->ssid_cfgs,
			      struct atf_ssid_config, list) {
		atf_free_ssid_config(ssid_cfg);
	}
}


static void
atf_free_group_configs(struct atf_algo *algo)
{
	struct atf_group *group, *tmp;

	if (dl_list_empty(&algo->groups))
		return;

	dl_list_for_each_safe(group, tmp, &algo->groups, struct atf_group, list)
		atf_free_group(group);
}


void
atf_free_algo_configs(struct atf_algo *algo)
{
	atf_free_peer_configs(algo);

	/* Ensure all peer config is cleared by checking list is empty.
	 * if list is not empty, its corrupted.
	 */
	if (!dl_list_empty(&algo->peer_cfgs)) {
		wpa_printf(MSG_ERROR, "ATF: peer config is not cleared!\n");
	}
	algo->num_peer_cfg = 0;
	dl_list_init(&algo->peer_cfgs);

	atf_free_ssid_configs(algo);

	/* Ensure ssid config list is empty after the cleanup.
	 * if list is not empty, list is corrupted.
	 */
	if (!dl_list_empty(&algo->ssid_cfgs)) {
		wpa_printf(MSG_ERROR, "ATF: Unexpected! ssid config is not cleared!\n");
	}
	algo->num_ssid_cfg = 0;
	algo->user_cfg_airtime = 0;
	dl_list_init(&algo->ssid_cfgs);

	atf_free_group_configs(algo);

	/* Ensure list is empty after removing all group configs.
	 * if list is not empty, something is corrupted.
	 */
	if (!dl_list_empty(&algo->groups)) {
		wpa_printf(MSG_ERROR, "ATF: Unexpected! group config is not cleared.\n");
	}

	algo->num_group_cfg = 0;
	dl_list_init(&algo->groups);
}


struct atf_group *
atf_find_group_by_name(const char *name, struct atf_algo *algo)
{
	struct atf_group *group;

	if (!name)
		return NULL;

	if (!algo) {
		wpa_printf(MSG_ERROR, "ATF: %s: algo is NULL", __func__);
		return NULL;
	}

	if (dl_list_empty(&algo->groups)) {
		wpa_printf(MSG_ERROR, "ATF: %s: group list is empty", __func__);
		return NULL;
	}

	dl_list_for_each(group, &algo->groups, struct atf_group, list)
	{
		size_t len = strlen(group->name);
		if (strlen(name) == len && os_strncmp(name, group->name, len) == 0)
			return group;
	}

	return NULL;
}


void
atf_cleanup_algo(struct atf_algo *algo)
{
	if (!algo)
		return;

	atf_free_algo_configs(algo);
	dl_list_del(&algo->list);
	os_free(algo);
	algo = NULL;
}


struct atf_algo *
atf_allocate_algo()
{
	struct atf_algo *algo;

	algo = os_zalloc(sizeof(*algo));
	if (!algo)
		return NULL;

	wpa_printf(MSG_DEBUG, "ATF: Allocated new algo structure for atf offload\n");
	dl_list_init(&algo->list);
	dl_list_add(&atf->algo_list, &algo->list);
	algo->num_group_cfg = 0;
	dl_list_init(&algo->groups);
	algo->num_ssid_cfg = 0;
	dl_list_init(&algo->ssid_cfgs);
	algo->num_peer_cfg = 0;
	dl_list_init(&algo->peer_cfgs);

	return algo;
}


struct atf_algo *
atf_get_algo_entry(struct hostapd_iface *iface)
{
	struct atf_algo *algo = NULL;

	algo = iface->atf_algo;
	if (!algo) {
		algo = atf_allocate_algo();
		if (!algo)
			return NULL;
	}

	return algo;
}


void
atf_join_leave_update(struct hostapd_iface *iface, struct sta_info *sta, bool is_join)
{
	if (!iface || !iface->atf_algo || !sta)
		return;

	ATF_SET_STA_TO_UPDATE(sta->atf_peer);
	if (is_join)
		ATF_OFFLOAD_SET_JOIN_UPDATE(iface->atf_algo);
	else
		ATF_OFFLOAD_SET_LEAVE_UPDATE(iface->atf_algo);

	atf_trigger_config_timer(iface);
}


void
atf_trigger_config_timer(struct hostapd_iface *iface)
{

	wpa_printf(MSG_INFO, "ATF: Trigger distribution of airtime for iface %p", iface);
	if (iface->atf_algo->atf_tasksched == 0) {
		iface->atf_algo->atf_tasksched = 1;
		atf_timer_start(iface);
	}
}


void
atf_reset_groups(struct atf_algo *algo)
{
	struct atf_group *group;

	algo->no_of_peers = 0;

	if (dl_list_empty(&algo->groups))
		return;

	dl_list_for_each(group, &algo->groups, struct atf_group, list)
		atf_reset_group_values(group);
}


struct atf_group *
atf_is_ssid_in_default_group(const char *name, struct atf_algo *algo, bool update)
{
	int i;
	struct atf_group *group;

	if (!name || !algo) {
		return NULL;
	}

	group = atf_find_group_by_name("default-group", algo);
	if (!group) {
		wpa_printf(MSG_ERROR, "ATF: default-group is not found in %p", algo);
		return NULL;
	}

	for (i = 0; i < group->num_of_ssid; i++) {
		size_t len = strlen(group->ssidname[i]);
		if (strlen(name) == len && !os_strncmp(name, group->ssidname[i], len))
			return group;
	}

	/* SSID is not found in default-group.
	 * if update == true, then update the ssid to default-group.
	 * if update == false, return NULL.
	 */
	if (update) {
		if (atf_add_ssid_to_group(group, name)) {
			wpa_printf(MSG_ERROR, "ATF: Failed to add ssid to group");
			return NULL;
		}

		return group;
	}

	return NULL;
}


struct atf_group *
atf_find_group_if_ssid_exist(const char *name, struct atf_algo *algo)
{
	int i;
	struct atf_group *group;

	if (!algo) {
		wpa_printf(MSG_ERROR, "ATF: Algo is null");
		return NULL;
	}

	if (dl_list_empty(&algo->groups)) {
		wpa_printf(MSG_ERROR, "ATF: %s: group is empty", __func__);
		return NULL;
	}

	dl_list_for_each(group, &algo->groups, struct atf_group, list)
	{
		for (i = 0; i < group->num_of_ssid; i++) {
			size_t len = strlen(group->ssidname[i]);
			if (strlen(name) == len &&
			    !os_strncmp(name, group->ssidname[i], len))
				return group;
		}
	}

	return NULL;
}


struct atf_group *
atf_find_group(struct atf_algo *algo, const char *name)
{
	size_t name_len;
	if (!algo || !name) {
		wpa_printf(MSG_ERROR, "ATF: Invalid parameters to find_group");
		return NULL;
	}

	name_len = os_strlen(name);
	if (name_len == 0 || name_len > WLAN_SSID_MAX_LEN) {
		wpa_printf(MSG_ERROR, "ATF: Invalid name length in find_group: %zu", name_len);
		return NULL;
	}

	if (algo->ssid_group_enabled) {
		wpa_printf(MSG_DEBUG, "ATF: find group with ssid name %s %p", name, algo);
		return atf_find_group_if_ssid_exist(name, algo);
	}

	/* In case of non-ssid group, group name is same as ssid */
	return atf_find_group_by_name(name, algo);
}


/**
 * atf_update_interfaces_to_group - update all the ssid to its corresponding
 * group.
 */
static int
atf_update_interfaces_to_group(struct atf_algo *algo)
{
	struct hostapd_iface *iface = algo->iface;
	struct atf_group *group = NULL;
	struct hostapd_data *bss;
	struct hostapd_ssid *ssid;
	char ssid_buf[SSID_MAX_LEN + 1];
	int i;
	int ret = 0;

	for (i = 0; i < iface->num_bss; i++) {
		bss = iface->bss[i];
		if (!bss->started)
			continue;

		ssid = &bss->conf->ssid;
		os_memset(ssid_buf, 0, sizeof(ssid_buf));
		os_memcpy(ssid_buf, ssid->ssid, ssid->ssid_len);
		ssid_buf[ssid->ssid_len] = '\0';

		group = atf_find_group(algo, ssid_buf);
		if (!group) {
			wpa_printf(MSG_DEBUG, "ATF:ssid %s is not linked with any configured group",
			           ssid_buf);

			/* check if the ssid is in default group already, if
			 * not add it to default-group
			 */
			group = atf_is_ssid_in_default_group(ssid_buf, algo, true);
			if (!group) {
				wpa_printf(MSG_DEBUG, "ATF: Not able to update  %s to default-group",
					   ssid_buf);
				ret = 1;
				continue;
			}
			bss->atf_configured = 0;
		} else {
			group->is_configured = 1;
			bss->atf_configured = 1;
		}

		/* copy the scheduling policy of ssid in case of ATF based on ssid */
		if (!algo->ssid_group_enabled)
			group->sched_policy = bss->conf->atf_ssid_sched;
	}

	return ret;
}


struct atf_group *
atf_get_peer_group(struct hostapd_data *hapd)
{
	struct atf_group *group;
	struct atf_algo *algo;
	char ssid_buf[SSID_MAX_LEN + 1];

	if (!hapd->conf->ssid.ssid_len) {
		wpa_printf(MSG_ERROR, "ATF: Unexpected! conf doesnt have ssid");
		return NULL;
	}

	if (!hapd->iface || !hapd->iface->atf_algo)
		return NULL;

	algo = hapd->iface->atf_algo;

	os_memcpy(ssid_buf, hapd->conf->ssid.ssid, hapd->conf->ssid.ssid_len);
	ssid_buf[hapd->conf->ssid.ssid_len] = '\0';

	group = atf_find_group(algo, ssid_buf);
	if (!group) {
		/* check if it is in default group */
		return atf_is_ssid_in_default_group(ssid_buf, algo, false);
	}

	return group;
}


int
atf_update_peer(struct hostapd_data *hapd, struct sta_info *sta, void *ctx)
{
	struct atf_group *group = NULL;
	struct atf_algo *algo;

	if (!sta) {
		wpa_printf(MSG_ERROR, "ATF: %s: sta is null", __func__);
		return -1;
	}

	/* consider only the authorized sta */
	if (sta && !ap_sta_is_authorized(sta))
		return 0;

	if (!hapd || !hapd->iface || !hapd->iface->atf_algo) {
		wpa_printf(MSG_ERROR, "ATF: unexpected, interface is not proper");
		return -1;
	}

	algo = hapd->iface->atf_algo;

	if (ATF_OFFLOAD_IS_FULL_UPDATE(algo) ||
	    (ATF_OFFLOAD_IS_JOIN_UPDATE(algo) && ATF_IS_STA_UPDATED(sta->atf_peer)))
		algo->no_of_peers++;

	wpa_printf(MSG_DEBUG, "ATF: update peer " MACSTR "peer->is_configured %d",
			MAC2STR(sta->addr), sta->atf_peer.atf_configured);

	if (!sta->atf_peer.atf_configured) {
		/* add it to implicit peer list */
		group = atf_get_peer_group(hapd);
		if (!group) {
			wpa_printf(MSG_ERROR,
			           "ATF: Unexpected! peer" MACSTR "should be associated with a group",
				   MAC2STR(sta->addr));
			return -1;
		}

		dl_list_add(&group->implicit_peers, &sta->atf_candidate_list);
		group->num_impl_peers++;
	} else {
		group = sta->atf_peer.peer_cfg_ref->group;
		if (!group) {
                        wpa_printf(MSG_ERROR,
                                   "ATF: peer" MACSTR "should be associated with configured group",
                                   MAC2STR(sta->addr));

			return -1;
		}
		group->num_expl_peers++;
	}

	return 0;
}


void
atf_update_peer_cfg_to_peer(struct atf_algo *algo, struct atf_peer_config *peer_cfg)
{
	struct hostapd_iface *iface = algo->iface;
	struct hostapd_data *bss;
	struct sta_info *sta = NULL;
	int i;

	if (!peer_cfg)
		return;

	if (!peer_cfg->group) {
		wpa_printf(MSG_ERROR, "ATF: Peer should always be associated with group");
		return;
	}

	for (i = 0; i < iface->num_bss; i++) {
		bss = iface->bss[i];
		if (!bss->started || !bss->atf_configured)
			continue;

		sta = ap_get_sta(bss, peer_cfg->addr);
		if (sta && ap_sta_is_authorized(sta))
			break;
	}

	if (sta == NULL) {
		wpa_printf(MSG_DEBUG,
		           "ATF: Station " MACSTR " not found "
		           "for ATF Configuration",
		           MAC2STR(peer_cfg->addr));
		return;
	}

	sta->atf_peer.atf_configured = true;
	sta->atf_peer.peer_cfg_ref = peer_cfg;

	/*update to the group candidate list*/
	dl_list_add(&peer_cfg->group->explicit_peers, &sta->atf_candidate_list);

	return;
}


static int
atf_build_candidate_list(struct hostapd_iface *iface)
{
	struct atf_algo *algo;
	struct hostapd_data *hapd;
	int i;

	if (!iface || !iface->atf_algo)
		return -1;

	algo = iface->atf_algo;

	/* reset the previous group values */
	atf_reset_groups(algo);
	if (atf_update_interfaces_to_group(algo) != 0) {
		wpa_printf(MSG_ERROR, "ATF: could not map the interfaces to group");
		return -1;
	}

	if (!dl_list_empty(&algo->peer_cfgs)) {
		atf_iterate_peer_config(algo, atf_update_peer_cfg_to_peer);
	}

	for (i = 0; i < iface->num_bss; i++) {
		hapd = iface->bss[i];
		if (!hapd->started)
			continue;

		if (ap_for_each_sta(hapd, atf_update_peer, NULL))
			return -1;
	}

	return 0;
}


static void
atf_cfg_timeout_handler(void *eloop_ctx, void *timeout_ctx)
{
	struct hostapd_iface *iface = (struct hostapd_iface *)eloop_ctx;
	struct atf_algo *algo;

	if (!iface || !iface->atf_algo) {
		wpa_printf(MSG_ERROR, "ATF: Something is wrong, check iface");
		return;
	}

	algo = iface->atf_algo;

	if (!algo->atf_enabled) {
		wpa_printf(MSG_ERROR, "ATF not enabled. skip distribution");
		goto out;
	}

	wpa_printf(MSG_DEBUG, "ATF: Hitting the timeout handler for iface %p", iface);

	if (!hostapd_iface_num_sta(iface)) {
		wpa_printf(MSG_INFO,
			   "ATF: There is no peer associated in this iface, Skip distribution");
		goto out;
	}

	if (atf_build_candidate_list(iface) != 0) {
		wpa_printf(MSG_ERROR, "ATF: couldnt build the candidate list");
		goto out;
	}

out:
	algo->atf_tasksched = 0;
	return;
}


int
atf_timer_start(struct hostapd_iface *iface)
{
	wpa_printf(MSG_ERROR, "ATF: Trigger algo for iface %p", iface);
	eloop_register_timeout(ATF_ALGO_TIMEOUT, 0, atf_cfg_timeout_handler, iface, NULL);
	return 0;
}


void
atf_timer_stop(struct hostapd_iface *iface)
{
	wpa_printf(MSG_DEBUG, "ATF: cancelling timeout");
	if (!iface->atf_algo)
		return;

	iface->atf_algo->atf_tasksched = 0;
	eloop_cancel_timeout(atf_cfg_timeout_handler, iface, NULL);
}


void
atf_init_algo(struct hostapd_iface *iface)
{
	struct atf_algo *algo;
	struct atf_group *group;

	if (!iface->conf->atf_offload)
		return;

	algo = atf_get_algo_entry(iface);
	if (!algo) {
		wpa_printf(MSG_ERROR, "ATF: %s: atf algo entry is not found", __func__);
		return;
	}

	iface->atf_algo = algo;
	algo->iface = iface;
	algo->atf_enabled = iface->conf->commitatf;
	algo->ssid_group_enabled = iface->conf->atf_ssid_grp;
	algo->atfstrictsched_enabled = iface->conf->atf_strict_sched;

	if (iface->conf->atf_offload_config)
		if (atf_read_config(algo, iface->conf->atf_offload_config))
			wpa_printf(MSG_DEBUG, "ATF: could not read %s, expect issues",
			           iface->conf->atf_offload_config);

	wpa_printf(MSG_DEBUG, "ATF: allocating default group for %p", algo);
	group = atf_allocate_group("default-group", algo);
	if (!group) {
		wpa_printf(MSG_ERROR, "ATF: Could not allocate default group");
		return;
	}
	/* Default group is always configured */
	group->is_configured = 1;
}


void
atf_deinit_algo(struct hostapd_iface *iface)
{
	if (!iface->atf_algo)
		return;

	atf_cleanup_algo(iface->atf_algo);
}


void
atf_offload_deinit(void)
{
	struct atf_algo *algo, *tmp;

	if (!atf)
		return;

	wpa_printf(MSG_DEBUG, "%s : ATF Service stopping", __func__);

	if (dl_list_empty(&atf->algo_list))
		return;

	dl_list_for_each_safe(algo, tmp, &atf->algo_list, struct atf_algo, list)
	{
		atf_cleanup_algo(algo);
	}

	dl_list_init(&atf->algo_list);

	atf = NULL;
}


void
atf_offload_init(struct hapd_interfaces *ifaces)
{
	if (!ifaces)
		return;

	if (atf) {
		wpa_printf(MSG_INFO, "%s : ATF already enabled", __func__);
		return;
	}

	wpa_printf(MSG_DEBUG, "%s : Enabling ATF offload feature", __func__);
	atf = &ifaces->atf;
	dl_list_init(&atf->algo_list);

	return;
}
