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

/**
 * @struct atf_algo - per-radio specific atf algorithm
 */

struct atf_algo {
	struct hostapd_iface *iface;

	/* This node will be added to atf_offload global structure's
	 * algo_list
	 */
	struct dl_list list;
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

#endif /* CONFIG_ATF_OFFLOAD */
#endif /* ATF_OFFLOAD_H */
