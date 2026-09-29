/*
 * hostapd_log - per-BSS structured logging for hostapd
 * Copyright (c) 2026, Qualcomm Innovation Center, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef HOSTAPD_LOG_H
#define HOSTAPD_LOG_H

#include "utils/common.h"

/*
 * Contiguous module indices for per-BSS log level filtering.
 * These are separate from HOSTAPD_MODULE_* bitmasks in wpa_debug.h,
 * which are preserved for logger_stdout/logger_syslog output routing.
 * Tier 1: core infrastructure
 * Tier 2: MLME
 * Tier 3: security
 * Tier 4: channel/spectrum
 * Tier 5: service protocols
 * Tier 6: newer/optional
 */
enum hostapd_mod {
	HOSTAPD_MOD_CORE = 0,
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

enum hapd_log_module {
       /* Tier 1: core infrastructure */
       HAPD_MOD_CORE           = 0,
       HAPD_MOD_STA            = 1,
       HAPD_MOD_DRV            = 2,
       HAPD_MOD_HW             = 3,
       /* Tier 2: MLME */
       HAPD_MOD_MLME           = 4,
       HAPD_MOD_AUTH           = 5,
       HAPD_MOD_ASSOC          = 6,
       HAPD_MOD_PROBE          = 7,
       HAPD_MOD_BEACON         = 8,
       /* Tier 3: security */
       HAPD_MOD_WPA            = 9,
       HAPD_MOD_FT             = 10,
       HAPD_MOD_PREAUTH        = 11,
       HAPD_MOD_8021X          = 12,
       HAPD_MOD_FILS           = 13,
       HAPD_MOD_MACSEC         = 14,
       /* Tier 4: channel/spectrum */
       HAPD_MOD_DFS            = 15,
       HAPD_MOD_ACS            = 16,
       /* Tier 5: service protocols */
       HAPD_MOD_WNM            = 17,
       HAPD_MOD_RRM            = 18,
       HAPD_MOD_GAS            = 19,
       HAPD_MOD_RADIUS         = 20,
       HAPD_MOD_DPP            = 21,
       HAPD_MOD_WPS            = 22,
       HAPD_MOD_P2P            = 23,
       /* Tier 6: newer/optional */
       HAPD_MOD_MLO            = 24,
       HAPD_MOD_VLAN           = 25,
       HAPD_MOD_WMM            = 26,
       HAPD_MOD_MAX            = 27
};

/*
 * Default per-module log mask: bits 2-4 set → INFO, NOTICE, WARNING enabled.
 * Bit positions correspond to HOSTAPD_LEVEL_* values:
 *   0=DEBUG_VERBOSE  1=DEBUG  2=INFO  3=NOTICE  4=WARNING
 */
#define HAPD_LOG_DEFAULT_MASK  0x001Cu

/*
 * Sentinel values for hostapd_log_set_module() level parameter.
 * Negative values are never valid HOSTAPD_LEVEL_* constants.
 */
#define HAPD_LOG_SET_DEFAULT   (-1)    /* reset to HAPD_LOG_DEFAULT_MASK */
#define HAPD_LOG_SET_NONE      (-2)    /* disable all levels (mask = 0) */
#define HAPD_LOG_SET_ALL       (-3)    /* enable all levels (mask = 0xFFFF) */


struct hostapd_data;

/* Returns hapd_log_module index, or -1 if str is not a known module name. */
int hostapd_mod_str_to_idx(const char *str);
const char *hostapd_mod_idx_to_str(int idx);

/* Returns HOSTAPD_LEVEL_* value, or -1 if str is not a known level name. */
int hostapd_level_str_to_val(const char *str);
const char *hostapd_level_val_to_str(int level);

/* Check if logging is enabled for a module/level combination */
int hostapd_log_is_enabled(struct hostapd_data *hapd, const u8 *addr,
			   unsigned int module, int level);

/*
 * Hexdump support: binary data visualization for debugging frames, keys, IEs.
 * Wraps wpa_hexdump() with module-aware filtering.
 * Controlled by wpa_debug_level and wpa_debug_show_keys.
 */

/* Hexdump with module filtering - wraps wpa_hexdump() */
#define hostapd_log_hexdump_debug(hapd, addr, module, title, data, len) \
	do { \
		if (hostapd_log_is_enabled(hapd, addr, module, HOSTAPD_LEVEL_DEBUG)) { \
			wpa_hexdump(MSG_DEBUG, title, data, len); \
		} \
	} while (0)

#define hostapd_log_hexdump_verbose(hapd, addr, module, title, data, len) \
	do { \
		if (hostapd_log_is_enabled(hapd, addr, module, HOSTAPD_LEVEL_EXCESSIVE)) { \
			wpa_hexdump(MSG_EXCESSIVE, title, data, len); \
		} \
	} while (0)

/* Hexdump only if -K flag is set (for sensitive data like keys) */
#define hostapd_log_hexdump_key(hapd, addr, module, title, key, len) \
	do { \
		if (wpa_debug_show_keys && \
		    hostapd_log_is_enabled(hapd, addr, module, HOSTAPD_LEVEL_DEBUG)) { \
			wpa_hexdump_key(MSG_DEBUG, title, key, len); \
		} \
	} while (0)

#ifdef CONFIG_NO_HOSTAPD_LOGGER
#define hostapd_log(args...) do { } while (0)
#define hostapd_log_set_module(hapd, mod, level) do { } while (0)
#define hostapd_log_hexdump_debug(hapd, addr, module, title, data, len) do { } while (0)
#define hostapd_log_hexdump_verbose(hapd, addr, module, title, data, len) do { } while (0)
#define hostapd_log_hexdump_key(hapd, addr, module, title, key, len) do { } while (0)
#else
void hostapd_log(struct hostapd_data *hapd, const u8 *addr,
		 unsigned int module, int level,
		 const char *fmt, ...) PRINTF_FORMAT(5, 6);
void hostapd_log_set_module(struct hostapd_data *hapd,
			    enum hapd_log_module mod, int level);
#endif /* CONFIG_NO_HOSTAPD_LOGGER */

#ifdef CONFIG_QCN_EXTN
#define HOSTAPD_LOG_TRIG_AUTH_REJECT    "auth_reject"
#define HOSTAPD_LOG_TRIG_ASSOC_REJECT   "assoc_reject"
#define HOSTAPD_LOG_TRIG_4WAY_FAIL      "4way_fail"
#define HOSTAPD_LOG_TRIG_VAP_CREATE_FAIL "vap_create_fail"
#define HOSTAPD_LOG_TRIG_VAP_UP_FAIL    "vap_up_fail"
#define HOSTAPD_LOG_TRIG_AUTH_TX_FAIL   "auth_tx_fail"
#define HOSTAPD_LOG_TRIG_ASSOC_RESP_TX_FAIL   "assoc_resp_tx_fail"
#define HOSTAPD_LOG_TRIG_REASSOC_RESP_TX_FAIL "reassoc_resp_tx_fail"
#define HOSTAPD_LOG_TRIG_PROBE_RESP_TX_FAIL   "probe_resp_tx_fail"
#define HOSTAPD_LOG_TRIG_DEAUTH_TX_FAIL "deauth_tx_fail"
#define HOSTAPD_LOG_TRIG_DISASSOC_TX_FAIL "disassoc_tx_fail"
#define HOSTAPD_LOG_TRIG_ACTION_TX_FAIL "action_tx_fail"

void hostapd_log_extn_init(struct hostapd_data *hapd);
void hostapd_log_extn_deinit(struct hostapd_data *hapd);
void hostapd_log_trigger_emit(struct hostapd_data *hapd, const u8 *addr,
			      const char *event_type);
void hostapd_log_trigger_clear(struct hostapd_data *hapd, const u8 *addr);
#endif /* CONFIG_QCN_EXTN */

unsigned int nl80211_fc_to_hostapd_module(u16 fc);
unsigned int nl80211_fc_to_hostapd_logs(u16 fc);
#endif /* HOSTAPD_LOG_H */

