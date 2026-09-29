/*
 * hostapd_log - per-BSS structured logging for hostapd
 * Copyright (c) 2026, Qualcomm Innovation Center, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"
#include "utils/common.h"
#include "utils/wpa_debug.h"
#include "ap_config.h"
#include "hostapd.h"
#include "hostapd_log.h"

/* Returns hapd_log_module index, or -1 if str is not a known module name. */
int hostapd_mod_str_to_idx(const char *str)
{
	if (os_strcmp(str, "core") == 0)
		return HAPD_MOD_CORE;
	if (os_strcmp(str, "sta") == 0)
		return HAPD_MOD_STA;
	if (os_strcmp(str, "drv") == 0)
		return HAPD_MOD_DRV;
	if (os_strcmp(str, "hw") == 0)
		return HAPD_MOD_HW;
	if (os_strcmp(str, "mlme") == 0)
		return HAPD_MOD_MLME;
	if (os_strcmp(str, "auth") == 0)
		return HAPD_MOD_AUTH;
	if (os_strcmp(str, "assoc") == 0)
		return HAPD_MOD_ASSOC;
	if (os_strcmp(str, "probe") == 0)
		return HAPD_MOD_PROBE;
	if (os_strcmp(str, "beacon") == 0)
		return HAPD_MOD_BEACON;
	if (os_strcmp(str, "wpa") == 0)
		return HAPD_MOD_WPA;
	if (os_strcmp(str, "ft") == 0)
		return HAPD_MOD_FT;
	if (os_strcmp(str, "preauth") == 0)
		return HAPD_MOD_PREAUTH;
	if (os_strcmp(str, "8021x") == 0)
		return HAPD_MOD_8021X;
	if (os_strcmp(str, "fils") == 0)
		return HAPD_MOD_FILS;
	if (os_strcmp(str, "macsec") == 0)
		return HAPD_MOD_MACSEC;
	if (os_strcmp(str, "dfs") == 0)
		return HAPD_MOD_DFS;
	if (os_strcmp(str, "acs") == 0)
		return HAPD_MOD_ACS;
	if (os_strcmp(str, "wnm") == 0)
		return HAPD_MOD_WNM;
	if (os_strcmp(str, "rrm") == 0)
		return HAPD_MOD_RRM;
	if (os_strcmp(str, "gas") == 0)
		return HAPD_MOD_GAS;
	if (os_strcmp(str, "radius") == 0)
		return HAPD_MOD_RADIUS;
	if (os_strcmp(str, "dpp") == 0)
		return HAPD_MOD_DPP;
	if (os_strcmp(str, "wps") == 0)
		return HAPD_MOD_WPS;
	if (os_strcmp(str, "p2p") == 0)
		return HAPD_MOD_P2P;
	if (os_strcmp(str, "mlo") == 0)
		return HAPD_MOD_MLO;
	if (os_strcmp(str, "vlan") == 0)
		return HAPD_MOD_VLAN;
	if (os_strcmp(str, "wmm") == 0)
		return HAPD_MOD_WMM;
	return -1;
}


const char * hostapd_mod_idx_to_str(int idx)
{
	switch (idx) {
	case HAPD_MOD_CORE:
		return "core";
	case HAPD_MOD_STA:
		return "sta";
	case HAPD_MOD_DRV:
		return "drv";
	case HAPD_MOD_HW:
		return "hw";
	case HAPD_MOD_MLME:
		return "mlme";
	case HAPD_MOD_AUTH:
		return "auth";
	case HAPD_MOD_ASSOC:
		return "assoc";
	case HAPD_MOD_PROBE:
		return "probe";
	case HAPD_MOD_BEACON:
		return "beacon";
	case HAPD_MOD_WPA:
		return "wpa";
	case HAPD_MOD_FT:
		return "ft";
	case HAPD_MOD_PREAUTH:
		return "preauth";
	case HAPD_MOD_8021X:
		return "8021x";
	case HAPD_MOD_FILS:
		return "fils";
	case HAPD_MOD_MACSEC:
		return "macsec";
	case HAPD_MOD_DFS:
		return "dfs";
	case HAPD_MOD_ACS:
		return "acs";
	case HAPD_MOD_WNM:
		return "wnm";
	case HAPD_MOD_RRM:
		return "rrm";
	case HAPD_MOD_GAS:
		return "gas";
	case HAPD_MOD_RADIUS:
		return "radius";
	case HAPD_MOD_DPP:
		return "dpp";
	case HAPD_MOD_WPS:
		return "wps";
	case HAPD_MOD_P2P:
		return "p2p";
	case HAPD_MOD_MLO:
		return "mlo";
	case HAPD_MOD_VLAN:
		return "vlan";
	case HAPD_MOD_WMM:
		return "wmm";
	default:
		return "unknown";
	}
}


/* Returns HOSTAPD_LEVEL_* value, or -1 if str is not a known level name. */
int hostapd_level_str_to_val(const char *str)
{
	if (os_strcmp(str, "excessive") == 0)
		return HOSTAPD_LEVEL_EXCESSIVE;
	if (os_strcmp(str, "debug") == 0)
		return HOSTAPD_LEVEL_DEBUG;
	if (os_strcmp(str, "info") == 0)
		return HOSTAPD_LEVEL_INFO;
	if (os_strcmp(str, "notice") == 0)
		return HOSTAPD_LEVEL_NOTICE;
	if (os_strcmp(str, "warning") == 0)
		return HOSTAPD_LEVEL_WARNING;
	return -1;
}


const char * hostapd_level_val_to_str(int level)
{
	switch (level) {
	case HOSTAPD_LEVEL_EXCESSIVE:
		return "excessive";
	case HOSTAPD_LEVEL_DEBUG:
		return "debug";
	case HOSTAPD_LEVEL_INFO:
		return "info";
	case HOSTAPD_LEVEL_NOTICE:
		return "notice";
	case HOSTAPD_LEVEL_WARNING:
		return "warning";
	default:
		return "unknown";
	}
}


/*
 * Map a module argument to a hapd_log_module index.
 *
 * Legacy call sites pass a HOSTAPD_MODULE_* bitmask (0x01, 0x02, 0x04,
 * 0x08, 0x10, 0x40).  New call sites pass a HAPD_MOD_* index directly.
 * The legacy bitmasks are matched first; anything not recognised falls
 * through to the HAPD_MOD_* range check.
 *
 * Keep in sync with hostapd_mod_str_to_idx().
 */
static int module_to_idx(unsigned int module)
{
	switch (module) {
	case HOSTAPD_MODULE_IEEE80211:
		return HAPD_MOD_MLME;
	case HOSTAPD_MODULE_IEEE8021X:
		return HAPD_MOD_8021X;
	case HOSTAPD_MODULE_RADIUS:
		return HAPD_MOD_RADIUS;
	case HOSTAPD_MODULE_WPA:
		return HAPD_MOD_WPA;
	case HOSTAPD_MODULE_DRIVER:
		return HAPD_MOD_DRV;
	case HOSTAPD_MODULE_MLME:
		return HAPD_MOD_MLME;
	default:
		/* New-API call site: module is a HAPD_MOD_* index. */
		if (module < HAPD_MOD_MAX)
			return (int)module;
		return HAPD_MOD_CORE;
	}
}


/*
 * Map HOSTAPD_LEVEL_* to MSG_* for the global wpa_debug_level comparison.
 * Default maps to MSG_INFO (conservative: unknown levels are not suppressed
 * by the global floor unless the threshold is set above INFO).
 */
static int level_to_msg(int level)
{
	switch (level) {
	case HOSTAPD_LEVEL_EXCESSIVE:
		return MSG_EXCESSIVE;
	case HOSTAPD_LEVEL_DEBUG:
		return MSG_DEBUG;
	case HOSTAPD_LEVEL_INFO:
		return MSG_INFO;
	case HOSTAPD_LEVEL_NOTICE:
		return MSG_INFO;  /* NOTICE maps to MSG_INFO: same as hostapd_logger() */
	case HOSTAPD_LEVEL_WARNING:
		return MSG_WARNING;
	default:
		return MSG_INFO;
	}
}


/*
 * Detect if a module value is a legacy HOSTAPD_MODULE_* bitmask.
 * Legacy bitmasks are powers of 2 (or combinations): 0x01, 0x02, 0x04, 0x08, 0x10, 0x40.
 * New-API indices are contiguous: 0..HAPD_MOD_MAX-1.
 * This helper distinguishes them by checking if the value is a power of 2 and <= 0x40.
 */
static int is_legacy_module(unsigned int module)
{
	/* Power of 2 check: (x & (x-1)) == 0 iff x is a power of 2 */
	return module != 0 && (module & (module - 1)) == 0 && module <= 0x40;
}


int hostapd_log_is_enabled(struct hostapd_data *hapd,
				  const u8 *addr,
				  unsigned int module, int level)
{
	int idx;

	/* 1. Global floor - checked before any BSS context work. */
	if (level_to_msg(level) < wpa_debug_level)
		return 0;

	/* Guard against NULL hapd (early init or error path). */
	if (!hapd || !hapd->conf)
		return 1;  /* BSS not yet configured; global floor is sufficient */

	/* Validate level is in range [0, HOSTAPD_LEVEL_WARNING]. */
	if (level < 0 || level > HOSTAPD_LEVEL_WARNING)
		return 0;

	/* 2. Peer MAC filter - if set, non-matching addr is suppressed.
	 *    BSS-level messages (addr == NULL) bypass the peer filter. */
	if (hapd->log_peer_filter_set && addr &&
	    os_memcmp(hapd->log_peer_addr, addr, ETH_ALEN) != 0)
		return 0;

	/*
	 * 3. Per-module bitmask: each bit position matches a HOSTAPD_LEVEL_*
	 *    value.  A cleared bit suppresses that level for the module.
	 *    Only applies to new-API indices (HAPD_MOD_*); legacy modules
	 *    skip this check and use step 5 routing instead.
	 */
	idx = module_to_idx(module);
	if (!is_legacy_module(module)) {
		if (!(hapd->log_module_mask[idx] & (1U << (unsigned int)level)))
			return 0;
	}

	if(hapd->log_module_mask[idx] & (1U << (unsigned int)level))
		return 1;

	if (level < hapd->conf->logger_stdout_level &&
	    level < hapd->conf->logger_syslog_level)
		return 0;

	/*
	 * 5. Module output routing via existing logger_stdout/logger_syslog
	 *    bitmasks.  Only applies to legacy HOSTAPD_MODULE_* bitmask values.
	 *    New call sites that pass a HAPD_MOD_* index bypass this check;
	 *    their filtering is fully covered by the per-module mask in step 3.
	 */
	if (is_legacy_module(module) &&
	    !(hapd->conf->logger_stdout & module) &&
	    !(hapd->conf->logger_syslog & module))
		return 0;

	return 1;
}


void hostapd_log(struct hostapd_data *hapd, const u8 *addr,
		 unsigned int module, int level,
		 const char *fmt, ...)
{
	char buf[512];
	va_list ap;
	if (!hostapd_log_is_enabled(hapd, addr, module, level))
		return;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);

	/*
	 * Route through hostapd_logger() to preserve existing output
	 * formatting (iface name, module name, syslog routing) until
	 * hostapd_logger() is removed in a later patch.
	 *
	 * Messages longer than 511 bytes are silently truncated; this
	 * matches wpa_printf() behaviour and avoids heap allocation on
	 * the hot path.  hostapd_logger() will re-allocate exactly the
	 * truncated string, so no further truncation occurs.
	 */
	hostapd_logger(hapd, addr, module, level, "%s", buf);

}

/*
 * Set per-module log mask for hapd.
 *
 * level == HAPD_LOG_SET_DEFAULT (-1): reset to HAPD_LOG_DEFAULT_MASK
 * level == HAPD_LOG_SET_NONE    (-2): disable all levels (mask = 0x0000)
 * level == HAPD_LOG_SET_ALL     (-3): enable all levels (mask = 0xFFFF)
 * level >= 0:                         set the single bit for that level
 *                                     (additive; call with NONE first to
 *                                      replace rather than extend)
 */
void hostapd_log_set_module(struct hostapd_data *hapd,
                           enum hapd_log_module mod, int level)
{
       if (!hapd || mod >= HAPD_MOD_MAX)
               return;

       if (level == HAPD_LOG_SET_DEFAULT) {
               hapd->log_module_mask[mod] = HAPD_LOG_DEFAULT_MASK;
       } else if (level == HAPD_LOG_SET_NONE) {
               hapd->log_module_mask[mod] = 0x0000u;
       } else if (level == HAPD_LOG_SET_ALL) {
               hapd->log_module_mask[mod] = 0xFFFFu;
       } else if (level >= 0 && level <= HOSTAPD_LEVEL_WARNING) {
               hapd->log_module_mask[mod] |= (u16)(1U << (unsigned int)level);
       }
}

unsigned int nl80211_fc_to_hostapd_logs(u16 fc)
{
	switch (WLAN_FC_GET_TYPE(fc)) {
	case WLAN_FC_TYPE_CTRL:
		return HAPD_MOD_DRV;
	case WLAN_FC_TYPE_DATA:
		return HAPD_MOD_STA;
	case WLAN_FC_TYPE_EXT:
		return HAPD_MOD_HW;
	case WLAN_FC_TYPE_MGMT:
	default:
		break;
	}

	switch (WLAN_FC_GET_STYPE(fc)) {
	case WLAN_FC_STYPE_AUTH:
	case WLAN_FC_STYPE_DEAUTH:
		return HAPD_MOD_AUTH;
	case WLAN_FC_STYPE_ASSOC_RESP:
	case WLAN_FC_STYPE_REASSOC_RESP:
	case WLAN_FC_STYPE_DISASSOC:
		return HAPD_MOD_ASSOC;
	case WLAN_FC_STYPE_PROBE_RESP:
		return HAPD_MOD_PROBE;
	case WLAN_FC_STYPE_BEACON:
		return HAPD_MOD_BEACON;
	default:
		return HAPD_MOD_8021X;
	}
}
