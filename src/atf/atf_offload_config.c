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
	int val;

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

			if (val < 0 || val > 100) {
				wpa_printf(MSG_ERROR, "ATF: invalid airtime. Valid values (0 - 100)");
				invalid_config++;
				continue;
			}

			algo->last_group->user_cfg_airtime = val;
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
			atf_free_group(atf_group);
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
