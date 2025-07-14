/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: ISC
 */

#include "utils/includes.h"
#include "utils/common.h"
#include "common/ieee802_11_defs.h"
#include "common/ieee802_11_common.h"
#include "hostapd.h"
#include "ieee802_11.h"
#include "sta_info.h"

#define DSCP_CAP_IE_HEADER_LEN          2
#define DSCP_CAP_IE_OUI_LEN	3
#define DSCP_CAP_IE_OUI_TYPE_LEN	1
#define DSCP_CAP_IE_CAP_LEN_FIELD	1
#define DSCP_CAPABILITIES_LEN	1

size_t hostapd_dscp_cap_ie_len(struct hostapd_data *hapd);
u8 *hostapd_set_dscp_capabilities(struct hostapd_data *hapd,
				  struct sta_info *sta, u8 *eid);
void hostapd_check_dscp_policy_capability(struct sta_info *sta,
					  const u8 *ies, size_t ies_len);
