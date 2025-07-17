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

#define CLASSIFIER_TYPE_4	4
#define IP_VERSION_4	4
#define IP_VERSION_6	6

/* Bit positions for classifier mask */
#define MASK_SRC_IP	BIT(1)
#define MASK_DST_IP	BIT(2)
#define MASK_SRC_PORT	BIT(3)
#define MASK_DST_PORT	BIT(4)
#define MASK_PROTOCOL	BIT(6)

#define IPV4_CLASSIFIER_LEN 18
#define IPV6_CLASSIFIER_LEN 44
/* Field sizes */
#define IPV4_ADDR_LEN	4
#define IPV6_ADDR_LEN	16
#define PORT_LEN	2
#define PROTOCOL_LEN	1
#define HEADER_LEN	3

#include "robust_av.h"

size_t hostapd_dscp_cap_ie_len(struct hostapd_data *hapd);
u8 *hostapd_set_dscp_capabilities(struct hostapd_data *hapd,
				  struct sta_info *sta, u8 *eid);
void hostapd_check_dscp_policy_capability(struct sta_info *sta,
					  const u8 *ies, size_t ies_len);
int validate_dscp_policy(struct hostapd_dscp_policy *policy);
int parse_dscp_policy_string(struct sta_info *sta, struct hostapd_dscp_policy *policy, const char *params);
int build_frame_classifier(struct hostapd_dscp_policy *policy);
int add_dscp_policy_to_sta(struct sta_info *sta,
			   const struct hostapd_dscp_policy *new_policy);
void free_dscp_policies(struct sta_info *sta);
