/*
 * hostapd_log - per-BSS structured logging for hostapd
 *
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#ifndef HOSTAPD_LOG_H
#define HOSTAPD_LOG_H

#include "utils/common.h"

/*
 * Contiguous module indices for per-BSS log level filtering.
 * These are separate from HOSTAPD_MODULE_* bitmasks in wpa_debug.h,
 * which are preserved for logger_stdout/logger_syslog output routing.
 */
enum hostapd_mod {
	HOSTAPD_MOD_CORE     = 0,
	HOSTAPD_MOD_IEEE80211,
	HOSTAPD_MOD_IEEE8021X,
	HOSTAPD_MOD_RADIUS,
	HOSTAPD_MOD_WPA,
	HOSTAPD_MOD_DRIVER,
	HOSTAPD_MOD_MLME,
	HOSTAPD_MOD_DFS,
	HOSTAPD_MOD_BEACON,
	HOSTAPD_MOD_MAX
};

struct hostapd_data;

#ifdef CONFIG_NO_HOSTAPD_LOGGER
#define hostapd_log(hapd, addr, module, level, fmt, ...) do { } while (0)
#else
void hostapd_log(struct hostapd_data *hapd, const u8 *addr,
		 unsigned int module, int level,
		 const char *fmt, ...) PRINTF_FORMAT(5, 6);
#endif /* CONFIG_NO_HOSTAPD_LOGGER */

#endif /* HOSTAPD_LOG_H */
