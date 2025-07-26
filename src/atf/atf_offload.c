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

	algo->num_group_cfg--;
	dl_list_del(&group->list);
	os_free(group);
	group = NULL;
}


static void
atf_free_ssid_configs(struct atf_algo *algo)
{
	struct atf_ssid_config *ssid_cfg, *tmp;

	if (dl_list_empty(&algo->ssid_cfgs))
		return;

	dl_list_for_each_safe(ssid_cfg, tmp, &algo->ssid_cfgs, struct atf_ssid_config,
	                      list)
	{
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

	atf_free_ssid_configs(algo);

	/* Ensure ssid config list is empty after the cleanup.
	 * if list is not empty, list is corrupted.
	 */
	if (!dl_list_empty(&algo->ssid_cfgs)) {
		wpa_printf(MSG_ERROR, "ATF: Unexpected! ssid config is not cleared!\n");
	}
	algo->num_ssid_cfg = 0;
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
