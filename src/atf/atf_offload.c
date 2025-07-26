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

struct atf_offload *atf = NULL;

void
atf_cleanup_algo(struct atf_algo *algo)
{
	if (!algo)
		return;

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

	if (!iface->conf->atf_offload)
		return;

	algo = atf_get_algo_entry(iface);
	if (!algo) {
		wpa_printf(MSG_ERROR, "ATF: %s: atf algo entry is not found", __func__);
		return;
	}

	iface->atf_algo = algo;
	algo->iface = iface;
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
