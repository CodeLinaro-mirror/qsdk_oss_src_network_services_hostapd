/*
 * Airtime Fairness offload config parsing and cli apis
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

bool atf_validate_group_configured_airtime(struct atf_algo *algo,
					   struct atf_group *group,
					   u32 airtime)
{
	if ((algo->user_cfg_airtime - group->user_cfg_airtime) +
	    airtime > ATF_RADIO_DEFAULT_AIRTIME) {
		wpa_printf(MSG_ERROR, "ATF: Air time should be between 0 and %d\n",
			   100 - (algo->user_cfg_airtime / 10));
		return false;
	}

	return true;
}


static int
parse_ssid_set(struct atf_group *group, char *buf, int line)
{
	char ssid_list[WLAN_SSID_MAX][WLAN_SSID_MAX_LEN + 1] = { 0 };
	int count = 0;
	char *p;
	int i;

	if (!buf)
		return -1;

	p = buf;
	while (*p != '\0') {
		while (*p == ' ')
			p++;

		if (*p == '\0')
			break;

		i = 0;
		while (*p != ' ' && *p != '\0' && i < WLAN_SSID_MAX_LEN) {
			ssid_list[count][i++] = *p++;
		}
		ssid_list[count][i] = '\0';

		count++;
		if (count >= WLAN_SSID_MAX) {
			wpa_printf(MSG_ERROR, "ATF: Line %d: Too many SSIDs in '%s'",
				   line, buf);
			return -1;
		}
	}

	for (i = 0; i < count; i++) {
		os_strlcpy(group->ssidname[i], ssid_list[i], WLAN_SSID_MAX_LEN);
	}

	group->num_of_ssid = count;

	return 0;
}


int
atf_read_config(struct atf_algo *algo, const char *conf_file)
{
	FILE *file;
	char buffer[4096], *pos;
	int line = 0, invalid_config = 0, error = 0;
	struct atf_group *atf_group;
	struct atf_ssid_config *ssid_config;
	struct atf_peer_config *peer_config;
	u8 sta_mac[ETH_ALEN];
	int val;
	u32 scaled_airtime;

	if (!conf_file || !algo)
		return 0;

	file = fopen(conf_file, "r");
	if (!file) {
		wpa_printf(MSG_ERROR, "ATF: atf_offload_config file '%s' not found.", conf_file);
		return -1;
	}

	while (fgets(buffer, sizeof(buffer), file)) {
		line++;

		/* skip any commented config */
		if (buffer[0] == '#')
			continue;

		pos = buffer;

		/* Remove the new line character */
		while (*pos != '\0') {
			if (*pos == '\n') {
				*pos = '\0';
				break;
			}
			pos++;
		}

		/* if the string is empty continue. */
		if (buffer[0] == '\0')
			continue;

		pos = os_strchr(buffer, '=');
		if (!pos) {
			wpa_printf(MSG_ERROR, "ATF: Line %d: Invalid line '%s'", line,
			           buffer);
			invalid_config++;
			continue;
		}

		/* Replaces the '=' character with a null terminator. */
		*pos = '\0';
		pos++;

		if (os_strcmp(buffer, "atf-group") == 0) {
			if (!algo->ssid_group_enabled) {
				wpa_printf(MSG_ERROR, "ATF: ssid group config is not enabled");
				invalid_config++;
				continue;
			}

			atf_group = atf_find_group_by_name(pos, algo);
			if (!atf_group) {
				atf_group = atf_allocate_group(pos, algo);
				if (!atf_group) {
					wpa_printf(MSG_ERROR, "ATF: could not create group");
					error++;
					goto exit;
				}
			}
			algo->last_group = atf_group;

		} else if (os_strcmp(buffer, "atf-group-ssid") == 0) {
			if (!algo->ssid_group_enabled) {
				wpa_printf(MSG_ERROR, "ATF: ssid group config is not enabled");
				invalid_config++;
				continue;
			}

			if (*pos == '\0') {
				invalid_config++;
				continue;
			}

			if (parse_ssid_set(algo->last_group, pos, line) < 0) {
				invalid_config++;
				goto exit;
			}

		} else if (os_strcmp(buffer, "atf-group-airtime") == 0) {
			if (!algo->ssid_group_enabled) {
				wpa_printf(MSG_ERROR, "ATF: ssid group config is not enabled");
				invalid_config++;
				continue;
			}

			val = atoi(pos);
			atf_group = algo->last_group;

			if (val < 0 || val > 100) {
				wpa_printf(MSG_ERROR, "ATF: invalid airtime. Valid values (0 - 100)");
				invalid_config++;
				continue;
			}

			scaled_airtime = SCALE_PERCENTAGE_TO_U32(val);

			if (!atf_validate_group_configured_airtime(algo, atf_group,
								   scaled_airtime)) {
				invalid_config++;
				goto exit;
			}

			algo->user_cfg_airtime -= atf_group->user_cfg_airtime;
			algo->user_cfg_airtime += scaled_airtime;
			atf_group->user_cfg_airtime = scaled_airtime;
		} else if (os_strcmp(buffer, "atf-del-group") == 0) {
			if (!algo->ssid_group_enabled) {
				wpa_printf(MSG_ERROR, "ATF: ssid group config is not enabled");
				invalid_config++;
				continue;
			}

			if (*pos == '\0') {
				invalid_config++;
				continue;
			}

			atf_group = atf_find_group_by_name(pos, algo);
			if (!atf_group) {
				wpa_printf(MSG_ERROR, "ATF: group not found for %s", pos);
				error++;
				continue;
			}
			algo->user_cfg_airtime -= atf_group->user_cfg_airtime;
			atf_free_group(atf_group);
		} else if (os_strcmp(buffer, "atf-ssid") == 0) {

			if (algo->ssid_group_enabled) {
				wpa_printf(MSG_ERROR, "ATF: ssid config is not allowed when ssid group is enabled");
				invalid_config++;
				continue;
			}

			ssid_config = atf_find_ssid_config_by_name(pos, algo);
			if (!ssid_config) {
				ssid_config = atf_allocate_ssid_config(pos, algo);
				if (!ssid_config) {
					wpa_printf(MSG_ERROR, "ATF: could not allocate ssid config");
					error++;
					goto exit;
				}

				/* Add group for each ssid, this group
				 * will be used in distribution algorithm
				 */
				atf_group = atf_allocate_group(pos, algo);
				if (!atf_group) {
					wpa_printf(MSG_ERROR, "ATF: could not allocate group for ssid config");
					error++;
					goto exit;
				}
			} else {
				atf_group = atf_find_group_by_name(pos, algo);
				if (!atf_group) {
					wpa_printf(MSG_ERROR, "ATF: group not found for %s", pos);
					error++;
					goto exit;
				}
			}
			algo->last_ssid_cfg = ssid_config;
			algo->last_group = atf_group;
		} else if (os_strcmp(buffer, "atf-ssid-airtime") == 0) {
			if (algo->ssid_group_enabled) {
				wpa_printf(MSG_ERROR, "ATF: ssid config is not allowed when ssid group is enabled");
				invalid_config++;
				continue;
			}

			val = atoi(pos);
			if (val < 0 || val > 100) {
				wpa_printf(MSG_ERROR, "ATF: incorrect airtime");
				invalid_config++;
				continue;
			}
			algo->last_ssid_cfg->user_cfg_airtime = algo->last_group->user_cfg_airtime = val;
		} else if (os_strcmp(buffer, "atf-del-ssid") == 0) {
			if (algo->ssid_group_enabled) {
				wpa_printf(MSG_ERROR, "ATF: ssid config is not allowed when ssid group is enabled");
				invalid_config++;
				continue;
			}

			atf_group = atf_find_group_by_name(pos, algo);
			if (!atf_group) {
				wpa_printf(MSG_ERROR, "ATF: group not found for %s", pos);
				invalid_config++;
				continue;
			}
			atf_free_group(atf_group);

			ssid_config = atf_find_ssid_config_by_name(pos, algo);
			if (!ssid_config) {
				wpa_printf(MSG_ERROR, "ATF: could not find ssid_config");
				invalid_config++;
				continue;
			}
			atf_free_ssid_config(ssid_config);
		} else if (os_strcmp(buffer, "atf-sta") == 0) {
			if (hwaddr_aton(pos, sta_mac)) {
				wpa_printf(MSG_ERROR,
				           "ATF: Line %d: invalid sta mac address", line);
				invalid_config++;
				goto exit;
			}
			peer_config = atf_find_peer_config_by_mac(sta_mac, algo);
			if (!peer_config) {
				peer_config = atf_allocate_peer_config(sta_mac, algo);
				if (!peer_config) {
					wpa_printf(MSG_ERROR,
					           "ATF: could not allocate peer config");
					error++;
					goto exit;
				}
			}
			algo->last_peer_cfg = peer_config;
		} else if (os_strcmp(buffer, "atf-sta-airtime") == 0) {
			val = atoi(pos);
			if (val < 0 || val > 100) {
				wpa_printf(MSG_ERROR,
				           "ATF: invalid airtime %d (valid range 0 -100)",
				           val);
				invalid_config++;
				continue;
			}
			algo->last_peer_cfg->user_cfg_airtime = val;
		} else if (os_strcmp(buffer, "atf-sta-ssid") == 0) {
			if (*pos != '\0') {
				atf_group = atf_find_group_by_name(pos, algo);
				if (!atf_group) {
					wpa_printf(MSG_ERROR,
					           "ATF: ssid/group %s not found for "
					           "station" MACSTR " ",
					           pos,
					           MAC2STR(algo->last_peer_cfg->addr));
					error++;
					goto exit;
				}

				os_strlcpy(algo->last_peer_cfg->group_name, pos,
				           WLAN_SSID_MAX_LEN);
			}
		} else if (os_strcmp(buffer, "atf-del-sta") == 0) {
			if (hwaddr_aton(pos, sta_mac)) {
				wpa_printf(MSG_ERROR,
				           "ATF: Line %d: invalid sta mac address", line);
				invalid_config++;
				continue;
			}
			peer_config = atf_find_peer_config_by_mac(sta_mac, algo);
			if (!peer_config) {
				wpa_printf(MSG_ERROR,
				           "ATF: could not find the station " MACSTR
				           " config",
				           MAC2STR(sta_mac));
				invalid_config++;
				continue;
			}
			atf_free_peer_config(peer_config);
		}
	}

	if (invalid_config)
		wpa_printf(MSG_ERROR, "ATF: Ignoring %d minor errors in config file", invalid_config);
	fclose(file);
	return 0;

exit:
	wpa_printf(MSG_ERROR, "ATF: Fatal error %d occurred, clean up algo configs", error);
	fclose(file);

	/* In case of fatal error, clean up all configurations */
	atf_free_algo_configs(algo);

	return -1;
}


static int
hostapd_ctrl_iface_atf_offload_commitatf(struct hostapd_data *hapd,
					 const char *cmd)
{
	struct hostapd_iface *iface = hapd->iface;
	struct atf_algo *algo;
	u8 enabled, radio_index;
	int ret;

	if (!iface || !iface->atf_algo) {
		wpa_printf(MSG_ERROR, "ATF: Missing atf algo\n");
		return -1;
	}

	if (!hapd->drv_priv) {
		wpa_printf(MSG_ERROR, "ATF: Invalid hapd data %s\n", __func__);
		return -1;
	}

	algo = iface->atf_algo;
	enabled = atoi(cmd);

	if (enabled != 0 && enabled != 1) {
		wpa_printf(MSG_ERROR, "ATF: Invalid input for atf enabled\n");
		return -1;
	}

	radio_index = atf_get_hw_idx(iface);
	if (algo->atf_enabled != enabled) {
		ret = nl80211_atf_offload_enable_disable(hapd->drv_priv, radio_index, enabled);
		if (ret) {
			wpa_printf(MSG_ERROR, "ATF: Failed to enable ATF\n");
			return -1;
		}
	}

	algo->atf_enabled = enabled;
	iface->conf->commitatf = enabled;

	if (algo->atf_enabled) {
		ATF_OFFLOAD_SET_FULL_UPDATE(algo);
		atf_trigger_config_timer(iface);
	}

	return 0;
}


static int
hostapd_ctrl_iface_atf_offload_get_commitatf(struct hostapd_data *hapd, char *buf, size_t buflen)
{
	struct hostapd_iface *iface = hapd->iface;
	struct atf_algo *algo;
	int ret, len = 0;

	if (!iface || !iface->atf_algo) {
		wpa_printf(MSG_ERROR, "ATF: Missing atf algo\n");
		return -1;
	}

	algo = iface->atf_algo;

	ret = os_snprintf(buf, buflen, "ATF is %s\n",
			  algo->atf_enabled ? "enabled" : "disabled");
	if (!os_snprintf_error(buflen, ret))
		len += ret;

	return len;
}


static int
hostapd_ctrl_iface_atf_offload_atfstrictsched(struct hostapd_data *hapd,
					      const char *cmd, char *buf, size_t buflen)
{
	struct hostapd_iface *iface = hapd->iface;
	struct atf_algo *algo;
	u8 atf_scheduling, radio_index;
	int ret;

	if (!iface || !iface->atf_algo) {
		wpa_printf(MSG_ERROR, "ATF: Missing atf algo\n");
		return -1;
	}

	algo = iface->atf_algo;

	if (!hapd->drv_priv) {
		wpa_printf(MSG_ERROR, "ATF: Invalid hapd data %s\n", __func__);
		return -1;
	}

	atf_scheduling = atoi(cmd);

	if (algo->atfstrictsched_enabled == atf_scheduling) {
		wpa_printf(MSG_ERROR, "ATF: Current ATF scheduling is %d\n",
			   algo->atfstrictsched_enabled);
		return -1;
	}

	if (atf_scheduling > 1) {
		wpa_printf(MSG_ERROR, "ATF: Invalid atf sctrict scheduling\n");
		return -1;
	}

	radio_index = atf_get_hw_idx(iface);

	ret = nl80211_atf_offload_strict_scheduling_enable_disable(hapd->drv_priv,
								   radio_index,
								   atf_scheduling);
	if (ret) {
		wpa_printf(MSG_ERROR, "ATF: Failed to enable strict scheduling\n");
		return ret;
	}

	algo->atfstrictsched_enabled = atf_scheduling;

	wpa_printf(MSG_INFO, "ATF: ATF strict scheduling is %s",
		   algo->atfstrictsched_enabled ? "enabled" : "disabled");

	return 0;
}


static int
hostapd_ctrl_iface_atf_offload_gatfstrictsched(struct hostapd_data *hapd, char *buf, size_t buflen)
{
	struct hostapd_iface *iface = hapd->iface;
	struct atf_algo *algo;
	int ret, len = 0;

	if (!iface || !iface->atf_algo) {
		wpa_printf(MSG_ERROR, "ATF: Missing atf algo\n");
		return -1;
	}

	algo = iface->atf_algo;

	ret = os_snprintf(buf, buflen, "ATF scheduling is %s\n",
			  algo->atfstrictsched_enabled ? "strict" : "fair");
	if (!os_snprintf_error(buflen, ret))
		len += ret;

	return len;
}


static int
hostapd_ctrl_iface_atf_offload_atfssidgroup(struct hostapd_data *hapd,
					    const char *cmd, char *buf, size_t buflen)
{
	struct hostapd_iface *iface = hapd->iface;
	struct atf_algo *algo;
	u8 atf_ssid_group;

	if (!iface || !iface->atf_algo) {
		wpa_printf(MSG_ERROR, "ATF: Missing atf algo\n");
		return -1;
	}

	algo = iface->atf_algo;
	atf_ssid_group = atoi(cmd);

	if (atf_ssid_group != 0 && atf_ssid_group != 1) {
		wpa_printf(MSG_ERROR, "ATF: Invalid input for atfssidgroup\n");
		return -1;
	}

	algo->ssid_group_enabled = atf_ssid_group;
	iface->conf->atf_ssid_grp = atf_ssid_group;

	wpa_printf(MSG_INFO, "ATF: ATF SSID group is %s\n",
		   algo->ssid_group_enabled ? "enabled" : "disabled");

	return 0;
}


static int
hostapd_ctrl_iface_atf_offload_g_atfssidgroup(struct hostapd_data *hapd,
					      char *buf, size_t buflen)
{
	struct hostapd_iface *iface = hapd->iface;
	struct atf_algo *algo;
	int ret, len = 0;

	if (!iface || !iface->atf_algo) {
		wpa_printf(MSG_ERROR, "ATF: Missing atf algo\n");
		return -1;
	}

	algo = iface->atf_algo;

	ret = os_snprintf(buf, buflen, "ATF SSID group is %s\n",
			  algo->ssid_group_enabled ? "enabled" : "disabled");
	if (!os_snprintf_error(buflen, ret))
		len += ret;

	return len;
}


static int
hostapd_ctrl_iface_atf_offload_addatfgroup(struct hostapd_data *hapd,
					   const char *cmd, char *buf, size_t buflen)
{
	struct hostapd_iface *iface = hapd->iface;
	struct atf_algo *algo;
	char *input, *group_name, *ssid_name, *context = NULL;
	struct atf_group *group;

	if (!iface || !iface->atf_algo) {
		wpa_printf(MSG_ERROR, "ATF: Missing atf algo\n");
		return -1;
	}

	algo = iface->atf_algo;

	if (!algo->ssid_group_enabled) {
		wpa_printf(MSG_ERROR, "ATF: ATF ssid group is not enabled\n");
		return -1;
	}

	input = os_strdup(cmd);
	if (!input)
		return -1;

	group_name = str_token(input, " ", &context);
	if (!group_name) {
		wpa_printf(MSG_ERROR, "ATF: Group name not found\n");
		goto fail;
	}

	if (os_strlen(group_name) > WLAN_SSID_MAX_LEN) {
		wpa_printf(MSG_ERROR, "ATF: Group length exceeds the allowed limit");
		goto fail;
	}

	ssid_name = str_token(input, " ", &context);
	if (!ssid_name) {
		wpa_printf(MSG_ERROR, "ATF: SSID name not found\n");
		goto fail;
	}

	if (os_strlen(ssid_name) > WLAN_SSID_MAX_LEN) {
		wpa_printf(MSG_ERROR, "ATF: SSID length exceeds the allowed limit");
		goto fail;
	}

	group = atf_find_group_by_name(group_name, algo);
	if (group) {
		if (group->num_of_ssid == WLAN_SSID_MAX) {
			wpa_printf(MSG_ERROR, "ATF: group has maximum allowed number of SSIDs\n");
			return -1;
		}

		atf_delete_ssid_from_group(algo, ssid_name);
		atf_add_ssid_to_group(group, ssid_name);
	} else {
		group = atf_allocate_group(group_name, algo);
		if (!group) {
			wpa_printf(MSG_ERROR, "ATF: Failed to allocate greoup config\n");
			goto fail;
		}
		atf_delete_ssid_from_group(algo, ssid_name);
		atf_add_ssid_to_group(group, ssid_name);
		wpa_printf(MSG_INFO, "ATF: group name %s num_of_ssid %d\n",
			   group->name, group->num_of_ssid);
	}

	os_free(input);
	return 0;
fail:
	os_free(input);
	return -1;
}


static int
hostapd_ctrl_iface_atf_offload_configatfgroup(struct hostapd_data *hapd,
					      const char *cmd, char *buf, size_t buflen)
{
	struct hostapd_iface *iface = hapd->iface;
	struct atf_algo *algo;
	struct atf_group *group;
	char *input, *group_name, *a_time, *context = NULL;
	int airtime;
	u32 scaled_airtime;

	if (!iface || !iface->atf_algo) {
		wpa_printf(MSG_ERROR, "ATF: Missing atf algo\n");
		return -1;
	}

	algo = iface->atf_algo;

	if (!algo->ssid_group_enabled) {
		wpa_printf(MSG_ERROR, "ATF: ATF ssid group is not enabled\n");
		return -1;
	}

	input = os_strdup(cmd);
	if (!input)
		return -1;

	group_name = str_token(input, " ", &context);
	if (!group_name) {
		wpa_printf(MSG_ERROR, "ATF: Group name not found\n");
		goto fail;
	}

	if (os_strlen(group_name) > WLAN_SSID_MAX_LEN) {
		wpa_printf(MSG_ERROR, "ATF: Group length exceeds the allowed limit");
		goto fail;
	}

	a_time = str_token(input, " ", &context);
	if (!a_time) {
		wpa_printf(MSG_ERROR, "ATF: airtime not found\n");
		goto fail;
	}

	airtime = atoi(a_time);
	scaled_airtime = SCALE_PERCENTAGE_TO_U32(airtime);

	group = atf_find_group_by_name(group_name, algo);
	if (!group) {
		wpa_printf(MSG_ERROR, "ATF: Group not found\n");
		goto fail;
	}

	if (!atf_validate_group_configured_airtime(algo, group, scaled_airtime))
		goto fail;

	algo->user_cfg_airtime -= group->user_cfg_airtime;
	algo->user_cfg_airtime += scaled_airtime;
	group->user_cfg_airtime = scaled_airtime;

	os_free(input);
	return 0;
fail:
	wpa_printf(MSG_ERROR, "ATF: Failed to config SSID group\n");
	os_free(input);
	return -1;
}


static int
hostapd_ctrl_iface_atf_offload_delatfgroup(struct hostapd_data *hapd,
					   const char *cmd, char *buf, size_t buflen)
{
	struct hostapd_iface *iface = hapd->iface;
	struct atf_algo *algo;
	struct atf_group *group;
	char group_name[WLAN_SSID_MAX_LEN + 1];

	if (!iface || !iface->atf_algo) {
		wpa_printf(MSG_ERROR, "ATF: Missing atf algo\n");
		return -1;
	}

	algo = iface->atf_algo;

	if (!algo->ssid_group_enabled) {
		wpa_printf(MSG_ERROR, "ATF: ATF ssid group is not enabled\n");
		return -1;
	}

	if (os_strlen(cmd) > WLAN_SSID_MAX_LEN) {
		wpa_printf(MSG_ERROR, "ATF: Group length exceeds the allowed limit");
		return -1;
	}

	os_strlcpy(group_name, cmd, sizeof(group_name));
	group_name[sizeof(group_name) - 1] = '\0';

	group = atf_find_group_by_name(group_name, algo);
	if (!group) {
		wpa_printf(MSG_ERROR, "ATF: Group not found\n");
		return -1;
	}

	algo->user_cfg_airtime -= group->user_cfg_airtime;
	atf_free_group(group);

	return 0;
}


static int
hostapd_ctrl_iface_atf_offload_showatfgroup(struct hostapd_data *hapd, char *buf, size_t buflen)
{
	struct hostapd_iface *iface = hapd->iface;
	struct atf_algo *algo;
	struct atf_group *group;
	int len = 0, j, ret;

	if (!iface || !iface->atf_algo) {
		wpa_printf(MSG_ERROR, "ATF: Missing atf algo\n");
		return -1;
	}

	algo = iface->atf_algo;

	if (!iface->conf->atf_offload) {
		wpa_printf(MSG_ERROR, "ATF: ATF is not enabled\n");
		return -1;
	}

	if (!algo->ssid_group_enabled) {
		wpa_printf(MSG_ERROR, "ATF: ATF Group is not enabled\n");
		return -1;
	}

	if (dl_list_empty(&algo->groups)) {
		wpa_printf(MSG_DEBUG, "ATF: No entry is present in list\n");
		return -1;
	}

	ret = os_snprintf(buf, buflen, "\n%-20s%-12s%s", "Group", "Airtime", "SSID List");
	if (!os_snprintf_error(buflen, ret))
		len += ret;

	dl_list_for_each(group, &algo->groups, struct atf_group, list)
	{
		ret = os_snprintf(buf + len, buflen - len, "\n%-20s",
				  group->name);
		if (!os_snprintf_error(buflen - len, ret))
			len += ret;

		ret = os_snprintf(buf + len, buflen - len, "%-10d",
				  group->user_cfg_airtime / 10);
		if (!os_snprintf_error(buflen - len, ret))
			len += ret;

		for (j = 0; j < group->num_of_ssid; j++) {
			ret = os_snprintf(buf + len, buflen - len, "%-2s ",
					  group->ssidname[j]);
			if (!os_snprintf_error(buflen - len, ret))
				len += ret;
		}
	}
	ret = os_snprintf(buf + len, buflen - len, "\n");
	if (!os_snprintf_error(buflen - len, ret))
		len += ret;

	return len;
}


int
hostapd_ctrl_iface_config_atf_offload(struct hostapd_data *hapd,
		const char *cmd, char *buf, size_t buflen)
{
	if (os_strncmp(cmd, "commitatf ", 10) == 0)
		return hostapd_ctrl_iface_atf_offload_commitatf(hapd, cmd + 10);
	else if (os_strncmp(cmd, "get_commitatf", 13) == 0)
		return hostapd_ctrl_iface_atf_offload_get_commitatf(hapd, buf, buflen);
	else if (os_strncmp(cmd, "atfstrictsched ", 15) == 0)
		return hostapd_ctrl_iface_atf_offload_atfstrictsched(hapd, cmd + 15, buf, buflen);
	else if (os_strncmp(cmd, "gatfstrictsched", 15) == 0)
		return hostapd_ctrl_iface_atf_offload_gatfstrictsched(hapd, buf, buflen);
	else if (os_strncmp(cmd, "atfssidgroup ", 13) == 0)
		return hostapd_ctrl_iface_atf_offload_atfssidgroup(hapd, cmd + 13, buf, buflen);
	else if (os_strncmp(cmd, "g_atfssidgroup", 14) == 0)
		return hostapd_ctrl_iface_atf_offload_g_atfssidgroup(hapd, buf, buflen);
	else if (os_strncmp(cmd, "addatfgroup ", 12) == 0)
		return hostapd_ctrl_iface_atf_offload_addatfgroup(hapd, cmd + 12, buf, buflen);
	else if (os_strncmp(cmd, "configatfgroup ", 15) == 0)
		return hostapd_ctrl_iface_atf_offload_configatfgroup(hapd, cmd + 15, buf, buflen);
	else if (os_strncmp(cmd, "delatfgroup ", 12) == 0)
		return hostapd_ctrl_iface_atf_offload_delatfgroup(hapd, cmd + 12, buf, buflen);
	else if (os_strncmp(cmd, "showatfgroup", 12) == 0)
		return hostapd_ctrl_iface_atf_offload_showatfgroup(hapd, buf, buflen);

	return -1;
}

