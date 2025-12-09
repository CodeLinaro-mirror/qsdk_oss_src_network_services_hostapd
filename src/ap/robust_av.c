/*
 * hostapd / DSCP Policy
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "common/ieee802_11_defs.h"
#include "common/ieee802_11_common.h"
#include "hostapd.h"
#include "ieee802_11.h"
#include "sta_info.h"
#include "ap_config.h"
#include "ap_drv_ops.h"
#include "robust_av.h"
#include "sta_info.h"
#include "ap_drv_ops.h"
#include <linux/netfilter.h>


#ifdef CONFIG_ROBUST_AV
/*
 * Update DSCP policy capabilities for a STA based on the received Capabilities
 * field of a WFA Capabilities element.
 */
void hostapd_update_dscp_policy_capability(struct hostapd_data *hapd,
					   struct sta_info *sta,
					   const u8 *pos, size_t len)
{

	sta->flags &= ~WLAN_STA_DSCP_POLICY;

	if (!(sta->flags & WLAN_STA_MFP))
		return;

	if (!pos || len < 1)
		return;

	if (pos[0] & WFA_CAPA_QM_DSCP_POLICY) {
		sta->flags |= WLAN_STA_DSCP_POLICY;
		wpa_printf(MSG_DEBUG, "DSCP: STA " MACSTR
			   " supports DSCP Policy", MAC2STR(sta->addr));
	}
}


static int parse_ipv4_params(struct hostapd_dscp_policy *policy,
			     const char *token)
{
	if (os_strncmp(token, "dst_ip=", 7) == 0) {
		if (inet_pton(AF_INET, token + 7,
			      &policy->type4_param.ip_params.v4.dst_ip) <= 0)
			return -EINVAL;
	} else if (os_strncmp(token, "src_ip=", 7) == 0) {
		if (inet_pton(AF_INET, token + 7,
			      &policy->type4_param.ip_params.v4.src_ip) <= 0)
			return -EINVAL;
	} else if (os_strncmp(token, "dst_port=", 9) == 0) {
		policy->type4_param.ip_params.v4.dst_port = atoi(token + 9);
	} else if (os_strncmp(token, "src_port=", 9) == 0) {
		policy->type4_param.ip_params.v4.src_port = atoi(token + 9);
	} else if (os_strncmp(token, "protocol=", 9) == 0) {
		policy->type4_param.ip_params.v4.protocol = atoi(token + 9);
	}
	return 0;
}


static int parse_ipv6_params(struct hostapd_dscp_policy *policy,
			     const char *token)
{
	if (os_strncmp(token, "dst_ip=", 7) == 0) {
		if (inet_pton(AF_INET6, token + 7,
			      &policy->type4_param.ip_params.v6.dst_ip) <= 0)
			return -EINVAL;
	} else if (os_strncmp(token, "src_ip=", 7) == 0) {
		if (inet_pton(AF_INET6, token + 7,
			      &policy->type4_param.ip_params.v6.src_ip) <= 0)
			return -EINVAL;
	} else if (os_strncmp(token, "dst_port=", 9) == 0) {
		policy->type4_param.ip_params.v6.dst_port = atoi(token + 9);
	} else if (os_strncmp(token, "src_port=", 9) == 0) {
		policy->type4_param.ip_params.v6.src_port = atoi(token + 9);
	} else if (os_strncmp(token, "protocol=", 9) == 0) {
		policy->type4_param.ip_params.v6.next_header = atoi(token + 9);
	}

	return 0;
}


static int parse_dscp_value(struct hostapd_dscp_policy *policy,
			    const char *token)
{
	if (os_strncmp(token, "policy_id=", 10) == 0) {
		int policy_id = atoi(token + 10);

		if (policy_id > 0 && policy_id < 256) {
			policy->policy_id = policy_id;
		} else {
			wpa_printf(MSG_INFO, "Invalid policy id value: %d",
				   policy_id);
			return -EINVAL;
		}
	} else if (os_strncmp(token, "request_type=", 13) == 0) {
		const char *val = token + 13;

		if (os_strcasecmp(val, "add") == 0 ||
		    os_strcasecmp(val, "update") == 0) {
			policy->req_type = DSCP_POLICY_REQ_ADD;
		} else if (os_strcasecmp(val, "remove") == 0) {
			policy->req_type = DSCP_POLICY_REQ_REMOVE;
		} else {
			wpa_printf(MSG_INFO, "Invalid request_type: %s", val);
			return -EINVAL;
		}
	} else if (os_strncmp(token, "dscp=", 5) == 0) {
		unsigned long dscp = strtoul(token + 5, NULL, 0);

		if (dscp <= 63) {
			policy->dscp = dscp;
			policy->dscp_info = true;
		} else {
			wpa_printf(MSG_INFO, "Invalid DSCP value: %lu", dscp);
			return -EINVAL;
		}
	}

	return 0;
}


static int parse_domain_name(struct hostapd_dscp_policy *policy,
			     const char *token)
{
	const char *name;

	if (os_strncmp(token, "domain_name=", 12) == 0) {
		name = token + 12;
		if (os_strlen(name) <= 255) {
			os_free(policy->domain_name);
			policy->domain_name = os_strdup(name);
			if (!policy->domain_name)
				return -ENOMEM;
			policy->domain_name_len =
				os_strlen(policy->domain_name);
		} else {
			wpa_printf(MSG_INFO, "Domain name too long");
			return -EINVAL;
		}
	}
	return 0;
}


static int parse_port_range(struct hostapd_dscp_policy *policy,
			    const char *token)
{
	int port;

	if (os_strncmp(token, "start_port=", 11) == 0) {
		port = atoi(token + 11);
		if (port >= 0 && port <= 65535) {
			policy->start_port = port;
			policy->port_range_info = true;
		} else {
			wpa_printf(MSG_INFO, "Invalid start port: %d", port);
			return -EINVAL;
		}
	} else if (os_strncmp(token, "end_port=", 9) == 0) {
		port = atoi(token + 9);
		if (port >= 0 && port <= 65535) {
			policy->end_port = port;
			policy->port_range_info = true;
		} else {
			wpa_printf(MSG_INFO, "Invalid end port: %d", port);
			return -EINVAL;
		}
	}
	return 0;
}


int validate_dscp_policy(struct hostapd_dscp_policy *policy)
{
	if (!policy)
		return -1;

	if (policy->policy_id < 1) {
		wpa_printf(MSG_INFO, "DSCP Invalid policy_id");
		return -EINVAL;
	}

	/* Domain name + destination IP not allowed */
	if (policy->domain_name &&
	    (policy->type4_param.classifier_mask & TCLAS_MASK_DST_IP)) {
		wpa_printf(MSG_INFO,
			   "DSCP: Both domain name and destination IP address not expected");
		return -EINVAL;
	}

	/* Port range + Destination port not allowed */
	if ((policy->type4_param.classifier_mask & TCLAS_MASK_DST_PORT) &&
	    policy->port_range_info) {
		wpa_printf(MSG_INFO,
			   "DSCP: Both port range and destination port not expected");
		return -EINVAL;
	}
	return 0;
}


void free_dscp_policy(struct hostapd_dscp_policy *policy)
{
	if (!policy)
		return;
	os_free(policy->domain_name);
	policy->domain_name = NULL;
	os_free(policy->frame_classifier);
	policy->frame_classifier = NULL;
}


int parse_dscp_policy_string(struct sta_info *sta,
			     struct hostapd_dscp_policy *policy,
			     const char *params)
{
	char *token, *buf;
	char *context;
	int ret = 0;

	buf = os_strdup(params);
	if (!buf)
		return -1;

	os_memset(policy, 0, sizeof(*policy));
	context = buf;

	while ((token = str_token(buf, " ", &context))) {
		if (os_strncmp(token, "classifier_mask=", 16) == 0) {
			policy->type4_param.classifier_mask =
				strtoul(token + 16, NULL, 0);
		} else if (os_strncmp(token, "ip_version=", 11) == 0) {
			policy->type4_param.ip_version = atoi(token + 11);
		} else if (os_strncmp(token, "policy_id=", 10) == 0 ||
			   os_strncmp(token, "request_type=", 13) == 0 ||
			   os_strncmp(token, "dscp=", 5) == 0) {
			ret = parse_dscp_value(policy, token);
			if (ret < 0)
				break;
		} else if (os_strncmp(token, "domain_name=", 12) == 0) {
			ret = parse_domain_name(policy, token);
			if (ret < 0)
				break;
		} else if (os_strncmp(token, "start_port=", 11) == 0 ||
			   os_strncmp(token, "end_port=", 9) == 0) {
			ret = parse_port_range(policy, token);
			if (ret < 0)
				break;
		} else if (policy->type4_param.ip_version == 4) {
			ret = parse_ipv4_params(policy, token);
			if (ret < 0)
				break;
		} else if (policy->type4_param.ip_version == 6) {
			ret = parse_ipv6_params(policy, token);
			if (ret < 0)
				break;
		} else {
			wpa_printf(MSG_DEBUG,
				   "DSCP: Unknown attribute '%s' skipped",
				   token);
			ret = -EINVAL;
			break;
		}
	}

	os_free(buf);
	if (ret)
		free_dscp_policy(policy);
	return ret;
}


static int build_frame_classifier_type4_ipv4(struct hostapd_dscp_policy *policy)
{
	u8 *buf;
	u8 classifier_mask;
	size_t len = IPV4_CLASSIFIER_LEN;

	if (!policy)
		return -1;

	classifier_mask = policy->type4_param.classifier_mask;
	buf = os_zalloc(len);
	if (!buf)
		return -1;

	buf[0] = CLASSIFIER_TYPE_4;
	buf[1] = classifier_mask;
	buf[2] = IPV4;

	if (classifier_mask & TCLAS_MASK_SRC_IP)
		os_memcpy(&buf[3], &policy->type4_param.ip_params.v4.src_ip,
			  IPV4_ADDR_LEN);

	if (classifier_mask & TCLAS_MASK_DST_IP)
		os_memcpy(&buf[7], &policy->type4_param.ip_params.v4.dst_ip,
			  IPV4_ADDR_LEN);

	if (classifier_mask & TCLAS_MASK_SRC_PORT)
		WPA_PUT_BE16(&buf[11],
			     policy->type4_param.ip_params.v4.src_port);

	if (classifier_mask & TCLAS_MASK_DST_PORT)
		WPA_PUT_BE16(&buf[13],
			     policy->type4_param.ip_params.v4.dst_port);

	if (classifier_mask & TCLAS_MASK_PROTOCOL)
		buf[16] = policy->type4_param.ip_params.v4.protocol;

	os_free(policy->frame_classifier);
	policy->frame_classifier = buf;
	policy->frame_classifier_len = len;
	return 0;
}


static int build_frame_classifier_type4_ipv6(struct hostapd_dscp_policy *policy)
{
	u8 *buf;
	u8 classifier_mask;
	size_t len = IPV6_CLASSIFIER_LEN;

	if (!policy)
		return -EINVAL;

	classifier_mask = policy->type4_param.classifier_mask;
	buf = os_zalloc(len);
	if (!buf)
		return -ENOMEM;

	buf[0] = CLASSIFIER_TYPE_4;
	buf[1] = classifier_mask;
	buf[2] = IPV6;

	if (classifier_mask & TCLAS_MASK_SRC_IP)
		os_memcpy(&buf[3], &policy->type4_param.ip_params.v6.src_ip,
			  IPV6_ADDR_LEN);

	if (classifier_mask & TCLAS_MASK_DST_IP)
		os_memcpy(&buf[19], &policy->type4_param.ip_params.v6.dst_ip,
			  IPV6_ADDR_LEN);

	if (classifier_mask & TCLAS_MASK_SRC_PORT)
		WPA_PUT_BE16(&buf[35],
			     policy->type4_param.ip_params.v6.src_port);

	if (classifier_mask & TCLAS_MASK_DST_PORT)
		WPA_PUT_BE16(&buf[37],
			     policy->type4_param.ip_params.v6.dst_port);

	if (classifier_mask & TCLAS_MASK_PROTOCOL)
		buf[40] = policy->type4_param.ip_params.v6.next_header;

	os_free(policy->frame_classifier);
	policy->frame_classifier = buf;
	policy->frame_classifier_len = len;

	return 0;
}


int build_frame_classifier(struct hostapd_dscp_policy *policy)
{
	switch (policy->type4_param.ip_version) {
	case IPV4:
		return build_frame_classifier_type4_ipv4(policy);
	case IPV6:
		return build_frame_classifier_type4_ipv6(policy);
	default:
		wpa_printf(MSG_DEBUG, "IP version not specified");
		return 0;
	}
}


int add_dscp_policy_to_sta(struct sta_info *sta,
			   const struct hostapd_dscp_policy *new_policy)
{
	struct hostapd_dscp_policy **updated_policy_list;
	struct hostapd_dscp_policy *copy;
	unsigned int i;

	/* Check for existing policy_id and update */
	for (i = 0; i < sta->num_dscp_policies; i++) {
		struct hostapd_dscp_policy *existing = sta->policies[i];
		char *new_domain = NULL;
		u8 *new_fc = NULL;

		if (!existing || existing->policy_id != new_policy->policy_id)
			continue;

		wpa_printf(MSG_DEBUG, "DSCP: Updating policy ID %u for STA "
			   MACSTR, new_policy->policy_id, MAC2STR(sta->addr));
		if (new_policy->domain_name) {
			new_domain = os_strdup(new_policy->domain_name);
			if (!new_domain)
				return -ENOMEM;
		}

		if (new_policy->frame_classifier &&
		    new_policy->frame_classifier_len > 0) {
			new_fc = os_memdup(new_policy->frame_classifier,
					   new_policy->frame_classifier_len);
			if (!new_fc) {
				os_free(new_domain);
				return -ENOMEM;
			}
		}
		free_dscp_policy(existing);
		os_memcpy(existing, new_policy, sizeof(*existing));
		existing->domain_name = new_domain;
		existing->frame_classifier = new_fc;
		return 0;
	}

	copy = os_memdup(new_policy, sizeof(*copy));
	if (!copy)
		return -ENOMEM;

	copy->domain_name = NULL;
	copy->frame_classifier = NULL;

	if (new_policy->domain_name) {
		copy->domain_name = os_strdup(new_policy->domain_name);
		if (!copy->domain_name) {
			os_free(copy);
			return -ENOMEM;
		}
	}

	if (new_policy->frame_classifier &&
	    new_policy->frame_classifier_len > 0) {
		copy->frame_classifier =
			os_memdup(new_policy->frame_classifier,
				  new_policy->frame_classifier_len);
		if (!copy->frame_classifier) {
			free_dscp_policy(copy);
			os_free(copy);
			return -ENOMEM;
		}
	}

	updated_policy_list = os_realloc_array(sta->policies,
					       sta->num_dscp_policies + 1,
					       sizeof(*sta->policies));
	if (!updated_policy_list) {
		free_dscp_policy(copy);
		os_free(copy);
		return -1;
	}

	sta->policies = updated_policy_list;
	sta->policies[sta->num_dscp_policies++] = copy;

	return 0;
}


void free_dscp_policies(struct sta_info *sta)
{
	unsigned int i;

	if (!sta || !sta->policies)
		return;

	for (i = 0; i < sta->num_dscp_policies; i++) {
		free_dscp_policy(sta->policies[i]);
		os_free(sta->policies[i]);
	}

	os_free(sta->policies);
	sta->policies = NULL;
	sta->num_dscp_policies = 0;
}


static u8 get_next_unsolicited_dialog_token(struct sta_info *sta)
{
	sta->unsolicited_dialog_token++;
	if (sta->unsolicited_dialog_token == 0)
		sta->unsolicited_dialog_token = 1;
	return sta->unsolicited_dialog_token;
}


static struct hostapd_dscp_policy *
hostapd_get_dscp_policy_by_id(struct sta_info *sta, int id)
{
	unsigned int i;

	for (i = 0; i < sta->num_dscp_policies; i++) {
		if (sta->policies[i] && sta->policies[i]->policy_id == id)
			return sta->policies[i];
	}

	return NULL;
}


static struct wpabuf *
hostapd_build_qos_element(struct hostapd_dscp_policy *policy)
{
	struct wpabuf *elem;
	size_t domain_len;

	elem = wpabuf_alloc(512);
	if (!elem)
		return NULL;

	wpabuf_put_be32(elem, QM_IE_VENDOR_TYPE);
	wpabuf_put_u8(elem, QM_ATTR_DSCP_POLICY);
	wpabuf_put_u8(elem, QM_ATTR_DSCP_POLICY_LEN);
	wpabuf_put_u8(elem, policy->policy_id);
	wpabuf_put_u8(elem, policy->req_type);
	wpabuf_put_u8(elem, policy->req_type == DSCP_POLICY_REQ_REMOVE ?
		      255 : policy->dscp);

	if (policy->frame_classifier && policy->frame_classifier_len > 0) {
		wpabuf_put_u8(elem, QM_ATTR_TCLAS);
		wpabuf_put_u8(elem, policy->frame_classifier_len);
		wpabuf_put_data(elem, policy->frame_classifier,
				policy->frame_classifier_len);
	}

	if (policy->domain_name) {
		domain_len = os_strlen(policy->domain_name);
		if (domain_len < 256) {
			wpabuf_put_u8(elem, QM_ATTR_DOMAIN_NAME);
			wpabuf_put_u8(elem, domain_len);
			wpabuf_put_data(elem, policy->domain_name, domain_len);
		}
	}

	if (policy->port_range_info) {
		wpabuf_put_u8(elem, QM_ATTR_PORT_RANGE);
		wpabuf_put_u8(elem, 4);
		wpabuf_put_be16(elem, policy->start_port);
		wpabuf_put_be16(elem, policy->end_port);
	}

	return elem;
}


static struct wpabuf * new_dscp_policy_req_frame(struct hostapd_data *hapd,
						 struct sta_info *sta,
						 u8 dialog_token,
						 u8 reset, u8 more)
{
	u8 request_control = 0;
	struct wpabuf *frame;

	frame = wpabuf_alloc(MAX_DSCP_REQ_SIZE);
	if (!frame)
		return NULL;

	wpabuf_put_u8(frame, WLAN_ACTION_VENDOR_SPECIFIC_PROTECTED);
	wpabuf_put_be32(frame, QM_ACTION_VENDOR_TYPE);
	wpabuf_put_u8(frame, QM_DSCP_POLICY_REQ);
	wpabuf_put_u8(frame, dialog_token);

	if (reset)
		request_control |= DSCP_POLICY_CTRL_RESET;
	if (more)
		request_control |= DSCP_POLICY_CTRL_MORE;

	wpabuf_put_u8(frame, request_control);

	return frame;
}


int hostapd_send_unsolicited_dscp_policy_request(struct hostapd_data *hapd,
						 struct sta_info *sta,
						 u8 reset,
						 const int *policy_ids,
						 unsigned int num_policies)
{
	struct wpabuf *frame = NULL;
	u8 dialog_token;
	size_t i;
	size_t frame_len;
	bool more = false;

	/* TODO: When sending a request, if this is not a resync (reset == 0),
	 * start a response timer bound to dialog_token. If no DSCP Policy
	 * Response frame with the same token is received before timeout, set a
	 * per-STA flag (e.g, sta->dscp_state.force_reset = 1). The next time
	 * this function is called for this STA, force reset = 1 and include all
	 * policies relevant to the STA to resynchronize state.
	 */

	if (!(sta->flags & WLAN_STA_DSCP_POLICY))
		return -1;

	dialog_token = get_next_unsolicited_dialog_token(sta);
	frame = new_dscp_policy_req_frame(hapd, sta, dialog_token, reset, more);
	if (!frame)
		return -1;

	frame_len = wpabuf_len(frame);

	for (i = 0; i < num_policies; i++) {
		struct hostapd_dscp_policy *policy;
		struct wpabuf *elem;

		policy = hostapd_get_dscp_policy_by_id(sta, policy_ids[i]);
		if (!policy)
			continue;

		if (reset && policy->req_type == DSCP_POLICY_REQ_REMOVE)
			continue;

		elem = hostapd_build_qos_element(policy);
		if (!elem)
			continue;

		if (frame_len + 2 + wpabuf_len(elem) > MAX_DSCP_REQ_SIZE) {
			more = true;
			wpabuf_free(elem);
			break;
		}

		wpabuf_put_u8(frame, WLAN_EID_VENDOR_SPECIFIC);
		wpabuf_put_u8(frame, wpabuf_len(elem));
		wpabuf_put_buf(frame, elem);
		wpabuf_free(elem);
		frame_len = wpabuf_len(frame);
	}

	if (more) {
		u8 *buf = wpabuf_mhead_u8(frame);

		buf[7] |= DSCP_POLICY_CTRL_MORE;
	}

	/* Only send if the frame contains at least one QoS element beyond the
	 * header */
	if (frame && wpabuf_len(frame) > 5 &&
	    hostapd_drv_send_action(hapd, hapd->iface->freq, 0, sta->addr,
				    wpabuf_head(frame), wpabuf_len(frame))) {
		wpa_printf(MSG_DEBUG, "DSCP: Failed to send policy request to "
			   MACSTR, MAC2STR(sta->addr));
		wpabuf_free(frame);
		return -1;
	}

	wpabuf_free(frame);

	sta->dscp_state.offset = i;
	sta->dscp_state.last_dialog_token = dialog_token;
	sta->dscp_state.pending_more = more;
	return 0;
}


static bool is_valid_qm_elem(const u8 *ie, size_t rem_len)
{
	return ie && rem_len >= 6 &&
		ie[0] == WLAN_EID_VENDOR_SPECIFIC && ie[1] >= 4 &&
		WPA_GET_BE32(&ie[2]) == QM_IE_VENDOR_TYPE;
}


static int set_frame_classifier_type4_ipv4(struct hostapd_dscp_policy *policy)
{
	u8 classifier_mask;
	const u8 *frame_classifier = policy->frame_classifier;
	struct type4_params *type4_param = &policy->type4_param;

	if (policy->frame_classifier_len < IPV4_CLASSIFIER_LEN) {
		wpa_printf(MSG_INFO,
			   "QM: Received IPv4 frame classifier with insufficient length %d",
			   policy->frame_classifier_len);
		return -1;
	}

	classifier_mask = frame_classifier[1];

	/* Classifier Mask - bit 1 = Source IP Address */
	if (classifier_mask & TCLAS_MASK_SRC_IP) {
		type4_param->classifier_mask |= TCLAS_MASK_SRC_IP;
		os_memcpy(&type4_param->ip_params.v4.src_ip,
			  &frame_classifier[3], IPV4_ADDR_LEN);
	}

	/* Classifier Mask - bit 2 = Destination IP Address */
	if (classifier_mask & TCLAS_MASK_DST_IP) {
		if (policy->domain_name) {
			wpa_printf(MSG_INFO,
				   "QM: IPv4: Both domain name and destination IP address not expected");
			return -1;
		}

		type4_param->classifier_mask |= TCLAS_MASK_DST_IP;
		os_memcpy(&type4_param->ip_params.v4.dst_ip,
			  &frame_classifier[7], IPV4_ADDR_LEN);
	}

	/* Classifier Mask - bit 3 = Source Port */
	if (classifier_mask & TCLAS_MASK_SRC_PORT) {
		type4_param->classifier_mask |= TCLAS_MASK_SRC_PORT;
		type4_param->ip_params.v4.src_port =
			WPA_GET_BE16(&frame_classifier[11]);
	}

	/* Classifier Mask - bit 4 = Destination Port */
	if (classifier_mask & TCLAS_MASK_DST_PORT) {
		if (policy->port_range_info) {
			wpa_printf(MSG_INFO,
				   "QM: IPv4: Both port range and destination port not expected");
			return -1;
		}

		type4_param->classifier_mask |= TCLAS_MASK_DST_PORT;
		type4_param->ip_params.v4.dst_port =
			WPA_GET_BE16(&frame_classifier[13]);
	}

	/* Classifier Mask - bit 5 = DSCP (ignored) */

	/* Classifier Mask - bit 6 = Protocol */
	if (classifier_mask & TCLAS_MASK_PROTOCOL) {
		type4_param->classifier_mask |= TCLAS_MASK_PROTOCOL;
		type4_param->ip_params.v4.protocol = frame_classifier[16];
	}

	return 0;
}


static int set_frame_classifier_type4_ipv6(struct hostapd_dscp_policy *policy)
{
	u8 classifier_mask;
	const u8 *frame_classifier = policy->frame_classifier;
	struct type4_params *type4_param = &policy->type4_param;

	if (policy->frame_classifier_len < IPV6_CLASSIFIER_LEN) {
		wpa_printf(MSG_INFO,
			   "QM: Received IPv6 frame classifier with insufficient length %d",
			   policy->frame_classifier_len);
		return -1;
	}

	classifier_mask = frame_classifier[1];

	/* Classifier Mask - bit 1 = Source IP Address */
	if (classifier_mask & TCLAS_MASK_SRC_IP) {
		type4_param->classifier_mask |= TCLAS_MASK_SRC_IP;
		os_memcpy(&type4_param->ip_params.v6.src_ip,
			  &frame_classifier[3], IPV6_ADDR_LEN);
	}

	/* Classifier Mask - bit 2 = Destination IP Address */
	if (classifier_mask & TCLAS_MASK_DST_IP) {
		if (policy->domain_name) {
			wpa_printf(MSG_INFO,
				   "QM: IPv6: Both domain name and destination IP address not expected");
			return -1;
		}
		type4_param->classifier_mask |= TCLAS_MASK_DST_IP;
		os_memcpy(&type4_param->ip_params.v6.dst_ip,
			  &frame_classifier[19], IPV6_ADDR_LEN);
	}

	/* Classifier Mask - bit 3 = Source Port */
	if (classifier_mask & TCLAS_MASK_SRC_PORT) {
		type4_param->classifier_mask |= TCLAS_MASK_SRC_PORT;
		type4_param->ip_params.v6.src_port =
			WPA_GET_BE16(&frame_classifier[35]);
	}

	/* Classifier Mask - bit 4 = Destination Port */
	if (classifier_mask & TCLAS_MASK_DST_PORT) {
		if (policy->port_range_info) {
			wpa_printf(MSG_INFO,
				   "IPv6: Both port range and destination port not expected");
			return -1;
		}

		type4_param->classifier_mask |= TCLAS_MASK_DST_PORT;
		type4_param->ip_params.v6.dst_port =
			WPA_GET_BE16(&frame_classifier[37]);
	}

	/* Classifier Mask - bit 5 = DSCP (ignored) */

	/* Classifier Mask - bit 6 = Next Header */
	if (classifier_mask & BIT(6)) {
		type4_param->classifier_mask |= BIT(6);
		type4_param->ip_params.v6.next_header = frame_classifier[40];
	}

	return 0;
}


static int ap_set_frame_classifier_params(struct hostapd_dscp_policy *policy)
{
	const u8 *frame_classifier = policy->frame_classifier;
	u8 frame_classifier_len = policy->frame_classifier_len;

	if (frame_classifier_len < 3) {
		wpa_printf(MSG_INFO,
			   "QM: Received frame classifier with insufficient length %d",
			   frame_classifier_len);
		return -1;
	}

	/* Only allowed Classifier Type: IP and higher layer parameters (4) */
	if (frame_classifier[0] != CLASSIFIER_TYPE_4) {
		wpa_printf(MSG_INFO,
			   "QM: Received frame classifier with invalid classifier type %d",
			   frame_classifier[0]);
		return -1;
	}

	/* Classifier Mask - bit 0 = Version */
	if (!(frame_classifier[1] & TCLAS_MASK_VERSION)) {
		wpa_printf(MSG_INFO,
			   "QM: Received frame classifier without IP version");
		return -1;
	}

	/* Version (4 or 6) */
	if (frame_classifier[2] == IPV4) {
		if (set_frame_classifier_type4_ipv4(policy)) {
			wpa_printf(MSG_INFO,
				   "QM: Failed to set IPv4 parameters");
			return -1;
		}

		policy->type4_param.ip_version = IPV4;
	} else if (frame_classifier[2] == IPV6) {
		if (set_frame_classifier_type4_ipv6(policy)) {
			wpa_printf(MSG_INFO,
				   "QM: Failed to set IPv6 parameters");
			return -1;
		}

		policy->type4_param.ip_version = IPV6;
	} else {
		wpa_printf(MSG_INFO, "QM: Received unknown IP version %d",
			   frame_classifier[2]);
		return -1;
	}

	return 0;
}


static int hostapd_parse_query_elements(struct hostapd_dscp_policy *query,
					u8 attr_id, u8 attr_len,
					const u8 *attr_data)
{
	switch (attr_id) {
	case QM_ATTR_PORT_RANGE:
		if (attr_len < 4) {
			wpa_printf(MSG_INFO,
				   "DSCP: Received Port Range attribute with insufficient length %d",
				   attr_len);
			return -EINVAL;
		}
		if (query->port_range_info) {
			wpa_printf(MSG_INFO,
				   "DSCP Policy: Duplicate Port Range");
			return -EINVAL;
		}
		query->start_port = WPA_GET_BE16(attr_data);
		query->end_port = WPA_GET_BE16(attr_data + 2);
		query->port_range_info = true;
		break;
	case QM_ATTR_TCLAS:
		if (attr_len < 1) {
			wpa_printf(MSG_INFO,
				   "DSCP: Received TCLAS attribute with insufficient length %d",
				   attr_len);
			return -EINVAL;
		}
		if (query->frame_classifier) {
			wpa_printf(MSG_DEBUG, "DSCP Policy: Duplicate TCLAS");
			return -EINVAL;
		}
		query->frame_classifier = (u8 *) attr_data;
		query->frame_classifier_len = attr_len;

		if (ap_set_frame_classifier_params(query)) {
			wpa_printf(MSG_INFO,
				   "DSCP: Failed to set frame classifier parameters");
			return -EINVAL;
		}
		break;
	case QM_ATTR_DOMAIN_NAME:
		if (attr_len < 1) {
			wpa_printf(MSG_INFO,
				   "DSCP: Received domain name attribute with insufficient length %d",
				   attr_len);
			return -EINVAL;
		}
		if (query->domain_name) {
			wpa_printf(MSG_DEBUG,
				   "DSCP Policy: Duplicate Domain Name");
			return -EINVAL;
		}
		query->domain_name = (char *) attr_data;
		query->domain_name_len = attr_len;
		break;
	default:
		break;
	}
	return 0;
}


static int parse_single_policy(const u8 *ie, size_t ie_len,
			       struct hostapd_dscp_policy **el_out,
			       unsigned int index)
{
	const u8 *attr;
	int rem_attrs;
	struct hostapd_dscp_policy *el;

	if (!ie || ie_len < 6 || ie[1] < 4)
		return -EINVAL;

	el = os_zalloc(sizeof(*el));
	if (!el)
		return -ENOMEM;

	attr = ie + 6;
	rem_attrs = ie[1] - 4;

	while (rem_attrs >= 2 && rem_attrs >= 2 + attr[1]) {
		u8 id = attr[0];

		if (id == QM_ATTR_DSCP_POLICY) {
			wpa_printf(MSG_INFO,
				   "DSCP Query: DSCP Policy attribute not allowed");
			os_free(el);
			return -EINVAL;
		}

		if (hostapd_parse_query_elements(el, attr[0], attr[1],
						 &attr[2])) {
			os_free(el);
			return -EINVAL;
		}

		rem_attrs -= 2 + attr[1];
		attr += 2 + attr[1];
	}

	*el_out = el;
	return 0;
}


static int parse_dscp_query(const u8 *data, size_t len,
			    struct dscp_context *ctx)
{
	const u8 *pos, *end;
	struct hostapd_dscp_policy **parsed;
	unsigned int count = 0, i = 0, j;
	int ie_len;

	if (!data || len < 1 || !ctx)
		return -EINVAL;

	pos = data + 1;
	end = data + len;

	ctx->dialog_token = data[0];

	if (ctx->dialog_token == 0) {
		wpa_printf(MSG_INFO, "DSCP: Invalid dialog_token in query");
		return -EINVAL;
	}

	/* First pass: count valid elements */
	while (end - pos >= 2) {
		ie_len = 2 + pos[1];
		if (end - pos < ie_len)
			break;

		if (is_valid_qm_elem(pos, ie_len))
			count++;

		pos += ie_len;
	}

	if (count == 0) {
		ctx->is_wildcard = true;
		return 0;
	}

	parsed = os_calloc(count, sizeof(*parsed));
	if (!parsed)
		return -ENOMEM;

	/* Second pass: parse and populate */
	pos = data + 1;
	while (end - pos >= 2 && i < count) {
		ie_len = 2 + pos[1];
		if (end - pos < ie_len)
			break;

		if (!is_valid_qm_elem(pos, ie_len)) {
			pos += ie_len;
			continue;
		}

		if (parse_single_policy(pos, ie_len, &parsed[i], i) != 0)
			goto error;
		i++;

		pos += ie_len;
	}

	ctx->query_policy = parsed;
	ctx->num_query_policies = i;
	return 0;

error:
	for (j = 0; j < i; j++)
		os_free(parsed[j]);
	os_free(parsed);
	return -1;
}


static bool match_ipv4_classifier(const struct type4_params *query,
				  const struct type4_params *policy)
{
	if ((query->classifier_mask & TCLAS_MASK_SRC_IP) &&
	    os_memcmp(&query->ip_params.v4.src_ip,
		      &policy->ip_params.v4.src_ip, 4) != 0)
		return false;

	if ((query->classifier_mask & TCLAS_MASK_DST_IP) &&
	    os_memcmp(&query->ip_params.v4.dst_ip,
		      &policy->ip_params.v4.dst_ip, 4) != 0)
		return false;

	if ((query->classifier_mask & TCLAS_MASK_SRC_PORT) &&
	    query->ip_params.v4.src_port != policy->ip_params.v4.src_port)
		return false;

	if ((query->classifier_mask & TCLAS_MASK_DST_PORT) &&
	    query->ip_params.v4.dst_port != policy->ip_params.v4.dst_port)
		return false;

	if ((query->classifier_mask & TCLAS_MASK_PROTOCOL) &&
	    query->ip_params.v4.protocol != policy->ip_params.v4.protocol)
		return false;

	return true;
}


static bool match_ipv6_classifier(const struct type4_params *query,
				  const struct type4_params *policy)
{
	if ((query->classifier_mask & TCLAS_MASK_SRC_IP) &&
	    os_memcmp(&query->ip_params.v6.src_ip,
		      &policy->ip_params.v6.src_ip, 16) != 0)
		return false;

	if ((query->classifier_mask & TCLAS_MASK_DST_IP) &&
	    os_memcmp(&query->ip_params.v6.dst_ip,
		      &policy->ip_params.v6.dst_ip, 16) != 0)
		return false;

	if ((query->classifier_mask & TCLAS_MASK_SRC_PORT) &&
	    query->ip_params.v6.src_port != policy->ip_params.v6.src_port)
		return false;

	if ((query->classifier_mask & TCLAS_MASK_DST_PORT) &&
	    query->ip_params.v6.dst_port != policy->ip_params.v6.dst_port)
		return false;

	if ((query->classifier_mask & BIT(6)) &&
	    query->ip_params.v6.next_header != policy->ip_params.v6.next_header)
		return false;

	return true;
}


static bool match_type4_classifier(const struct type4_params *query,
				   const struct type4_params *policy,
				   u8 ip_version)
{
	if (query->classifier_mask != policy->classifier_mask)
		return false;

	switch (ip_version) {
	case IPV4:
		if (!match_ipv4_classifier(query, policy))
			return false;
		break;
	case IPV6:
		if (!match_ipv6_classifier(query, policy))
			return false;
		break;
	default:
		return false;
	}

	return true;
}


static int policy_matches_query(struct dscp_context *ctx)
{
	struct hostapd_dscp_policy *policy, *query;
	struct hostapd_dscp_policy **tmp;
	unsigned int max_policies = 0, i, j;

	ctx->num_req_policies = 0;
	ctx->req_policy = NULL;

	/* Wildcard query: match all policies for the STA */
	if (ctx->is_wildcard) {
		max_policies = ctx->sta->num_dscp_policies;
		ctx->req_policy = os_calloc(max_policies,
					    sizeof(*ctx->req_policy));
		if (!ctx->req_policy)
			return 0;

		for (j = 0; j < max_policies; j++) {
			policy = ctx->sta->policies[j];
			ctx->req_policy[ctx->num_req_policies++] = policy;
		}
		return ctx->num_req_policies;
	}

	for (i = 0; i < ctx->num_query_policies; i++) {
		query = ctx->query_policy[i];

		for (j = 0; j < ctx->sta->num_dscp_policies; j++) {
			bool match = false;

			policy = ctx->sta->policies[j];

			/* Match port range */
			if (query->port_range_info && policy->port_range_info) {
				if (policy->start_port <= query->end_port &&
				    policy->end_port >= query->start_port)
					match = true;
			}


			if (!match && query->domain_name &&
			    policy->domain_name &&
			    query->domain_name_len == policy->domain_name_len &&
			    os_memcmp(query->domain_name, policy->domain_name,
				      query->domain_name_len) == 0)
				match = true;

			if (!match && query->frame_classifier &&
			    policy->frame_classifier) {
				u8 ip_version = query->type4_param.ip_version;
				u8 classifier_mask =
					query->type4_param.classifier_mask;

				if (ip_version ==
				    policy->type4_param.ip_version &&
				    classifier_mask ==
				    policy->type4_param.classifier_mask &&
				    match_type4_classifier(&query->type4_param,
							   &policy->type4_param,
							   ip_version))
					match = true;
			}

			if (!match)
				continue;

			tmp = os_realloc_array(ctx->req_policy,
					       ctx->num_req_policies + 1,
					       sizeof(*ctx->req_policy));
			if (!tmp)
				continue;

			ctx->req_policy = tmp;
			ctx->req_policy[ctx->num_req_policies++] = policy;
		}
	}

	return ctx->num_req_policies;
}


static size_t policy_element_len(const struct hostapd_dscp_policy *policy)
{
	size_t len = 0;

	/* QoS Management element header: Element ID (1), Length (1), OUI (3),
	 * OUI Type (1) */
	len += 6;

	/* DSCP Policy attribute:Attr ID(1) + Len(1) + Policy ID(1) +
	 * Req Type(1) + DSCP (1) */
	len += 5;

	/* Classifier attributes */
	if (policy->frame_classifier_len)
		len += 2 + policy->frame_classifier_len;

	/* Port Range attribute: Attribute ID (1) + Length (1) +
	 * Start Port (2) + End Port (2) */
	if (policy->port_range_info)
		len += 6;

	/* Domain Name attribute: Attribute ID (1) + Length (1) +
	 * domain_name_len */
	if (policy->domain_name_len)
		len += 2 + policy->domain_name_len;

	return len;
}


static void add_policy_element(struct wpabuf *buf,
			       const struct hostapd_dscp_policy *policy)
{
	struct wpabuf *elem;

	elem = wpabuf_alloc(policy_element_len(policy));
	if (!elem)
		return;

	wpabuf_put_be32(elem, QM_IE_VENDOR_TYPE);

	/* DSCP Policy attribute */
	wpabuf_put_u8(elem, QM_ATTR_DSCP_POLICY);
	wpabuf_put_u8(elem, 3);
	wpabuf_put_u8(elem, policy->policy_id);
	wpabuf_put_u8(elem, policy->req_type);

	if (policy->req_type == DSCP_POLICY_REQ_REMOVE)
		wpabuf_put_u8(elem, 255); /* DSCP = 255 for REMOVE */
	else
		wpabuf_put_u8(elem, policy->dscp);

	if (policy->frame_classifier && policy->frame_classifier_len) {
		wpabuf_put_u8(elem, QM_ATTR_TCLAS);
		wpabuf_put_u8(elem, policy->frame_classifier_len);
		wpabuf_put_data(elem, policy->frame_classifier,
				policy->frame_classifier_len);
	}

	/* Classifier: Domain Name */
	if (policy->domain_name && policy->domain_name_len > 0) {
		wpabuf_put_u8(elem, QM_ATTR_DOMAIN_NAME);
		wpabuf_put_u8(elem, policy->domain_name_len);
		wpabuf_put_data(elem, policy->domain_name,
				policy->domain_name_len);
	}

	if (policy->port_range_info) {
		wpabuf_put_u8(elem, QM_ATTR_PORT_RANGE);
		wpabuf_put_u8(elem, 4);
		wpabuf_put_be16(elem, policy->start_port);
		wpabuf_put_be16(elem, policy->end_port);
	}

	wpabuf_put_u8(buf, WLAN_EID_VENDOR_SPECIFIC);
	wpabuf_put_u8(buf, wpabuf_len(elem));
	wpabuf_put_buf(buf, elem);

	wpabuf_free(elem);
}


/* Build DSCP Policy Request frame */
static struct wpabuf * build_dscp_policy_request(struct hostapd_data *hapd,
						 struct sta_info *sta,
						 const struct dscp_context *ctx,
						 size_t offset,
						 size_t *policies_used,
						 u8 dialog_token,
						 bool *more)
{
	struct wpabuf *buf;
	u8 *rc_field;
	size_t i;

	buf = wpabuf_alloc(MAX_DSCP_REQ_SIZE);
	if (!buf)
		return NULL;

	/* Action frame header */
	wpabuf_put_u8(buf, WLAN_ACTION_VENDOR_SPECIFIC_PROTECTED);
	wpabuf_put_be32(buf, QM_ACTION_VENDOR_TYPE);
	wpabuf_put_u8(buf, QM_DSCP_POLICY_REQ);

	/* Dialog Token */
	wpabuf_put_u8(buf, dialog_token);

	/* Request Control */
	rc_field = wpabuf_put(buf, 1);
	*rc_field = sta->dscp_reset ? DSCP_POLICY_CTRL_RESET : 0x00;
	*more = false;

	for (i = offset; i < ctx->num_req_policies; i++) {
		const struct hostapd_dscp_policy *policy = ctx->req_policy[i];

		if (sta->dscp_reset &&
		    policy->req_type == DSCP_POLICY_REQ_REMOVE)
			continue;

		if (wpabuf_len(buf) + policy_element_len(policy) >
		    MAX_DSCP_REQ_SIZE) {
			*rc_field |= DSCP_POLICY_CTRL_MORE;
			*more = true;
			break;
		}

		add_policy_element(buf, policy);
	}

	if (policies_used)
		*policies_used = i - offset;

	/* If no matching policies, leave QoS Management element list empty */
	if (ctx->num_req_policies == 0 && sta->dscp_reset == 0)
		wpa_printf(MSG_DEBUG,
			   "QM: No matching policies - sending empty response");

	return buf;
}


int hostapd_handle_dscp_policy_query(struct hostapd_data *hapd,
				     struct sta_info *sta,
				     const u8 *data, size_t len)
{
	struct wpabuf *resp;
	struct dscp_context ctx;
	size_t offset = 0, used;
	u8 dialog_token;
	bool more = false;
	unsigned int i;

	if (!sta || !(sta->flags & WLAN_STA_AUTHORIZED)) {
		wpa_printf(MSG_DEBUG, "DSCP Policy: STA not authorized");
		return -1;
	}

	if (!(sta->flags & WLAN_STA_DSCP_POLICY)) {
		wpa_printf(MSG_DEBUG, "DSCP: STA " MACSTR " not capable",
			   MAC2STR(sta->addr));
		return -1;
	}

	if (len == 0)
		return -1;

	os_memset(&ctx, 0, sizeof(ctx));
	ctx.hapd = hapd;
	ctx.sta = sta;

	if (parse_dscp_query(data, len, &ctx) < 0) {
		wpa_printf(MSG_DEBUG, "DSCP: Failed to parse query from "
			   MACSTR,
			   MAC2STR(sta->addr));
		return -1;
	}

	if (policy_matches_query(&ctx) <= 0)
		wpa_printf(MSG_DEBUG, "QM: No matching DSCP policies found");

	dialog_token = ctx.dialog_token;

	resp = build_dscp_policy_request(hapd, sta, &ctx, offset, &used,
					 dialog_token, &more);
	if (!resp)
		goto cleanup;

	if (hostapd_drv_send_action(hapd, hapd->iface->freq, 0, sta->addr,
				    wpabuf_head(resp), wpabuf_len(resp))) {

		wpa_printf(MSG_DEBUG, "DSCP: Failed to send policy request to "
			   MACSTR, MAC2STR(sta->addr));
		wpabuf_free(resp);
		goto cleanup;
	}

	wpabuf_free(resp);

	if (used && more) {
		sta->dscp_state.offset = offset + used;
		sta->dscp_state.last_dialog_token = dialog_token;
		sta->dscp_state.pending_more = true;
	}

cleanup:
	for (i = 0; i < ctx.num_query_policies; i++)
		os_free(ctx.query_policy[i]);
	os_free(ctx.query_policy);
	os_free(ctx.req_policy);
	return 0;
}


static void update_policy_status(struct sta_info *sta, u8 policy_id,
				 enum dscp_policy_status status)
{
	unsigned int i;

	if (!sta || !sta->policies)
		return;

	for (i = 0; i < sta->num_dscp_policies; i++) {
		if (!sta->policies[i] ||
		    sta->policies[i]->policy_id != policy_id)
			continue;

		sta->policies[i]->status = status;

		if (status == DSCP_STATUS_SUCCESS) {
			wpa_printf(MSG_DEBUG,
				   "DSCP: Policy %u marked as accepted",
				   policy_id);
		} else {
			wpa_printf(MSG_DEBUG,
				   "DSCP: Policy %u marked as rejected %u",
				   policy_id, status);
		}
		return;
	}

	wpa_printf(MSG_DEBUG, "DSCP: Policy %u not found to update status",
		   policy_id);
}


static void invalidate_policy_by_id(struct sta_info *sta, u8 policy_id)
{
	unsigned int i;

	for (i = 0; i < sta->num_dscp_policies; i++) {
		struct hostapd_dscp_policy *policy = sta->policies[i];

		if (policy && policy->policy_id == policy_id) {
			wpa_printf(MSG_DEBUG, "DSCP: Invalidating policy %u",
				   policy_id);
			free_dscp_policy(policy);
			sta->policies[i] = NULL;
			break;
		}
	}
}


static void reset_dscp_state(struct sta_info *sta)
{
	if (sta) {
		sta->dscp_state.offset = 0;
		sta->dscp_state.last_dialog_token = 0;
		sta->dscp_state.pending_more = false;
	}
}


static struct wpabuf *
hostapd_build_dscp_policy_request_from_offset(struct hostapd_data *hapd,
					      struct sta_info *sta,
					      u8 dialog_token,
					      u8 reset, size_t offset,
					      size_t *next_offset,
					      bool *more)
{
	struct wpabuf *buf;
	size_t i, frame_len;

	buf = new_dscp_policy_req_frame(hapd, sta, dialog_token, reset, 0);
	if (!buf)
		return NULL;

	frame_len = wpabuf_len(buf);
	*more = false;

	for (i = offset; i < sta->num_dscp_policies; i++) {
		struct hostapd_dscp_policy *policy = sta->policies[i];
		struct wpabuf *elem;

		if (!policy)
			continue;

		elem = hostapd_build_qos_element(policy);
		if (!elem)
			continue;

		if (frame_len + 2 + wpabuf_len(elem) > MAX_DSCP_REQ_SIZE) {
			wpabuf_free(elem);
			*more = true;
			break;
		}

		wpabuf_put_u8(buf, WLAN_EID_VENDOR_SPECIFIC);
		wpabuf_put_u8(buf, wpabuf_len(elem));
		wpabuf_put_buf(buf, elem);
		wpabuf_free(elem);
		frame_len = wpabuf_len(buf);
	}

	if (*more) {
		u8 *buf_ptr = wpabuf_mhead_u8(buf);

		buf_ptr[7] |= DSCP_POLICY_CTRL_MORE;
	}

	if (next_offset)
		*next_offset = i;

	return buf;
}


static void hostapd_send_next_dscp_policy_batch(struct hostapd_data *hapd,
						struct sta_info *sta,
						size_t start_offset)
{
	struct wpabuf *frame;
	size_t next_offset = 0;
	u8 dialog_token;
	bool more = false;

	if (!hapd || !sta || !sta->policies || sta->num_dscp_policies == 0)
		return;

	dialog_token = get_next_unsolicited_dialog_token(sta);

	frame = hostapd_build_dscp_policy_request_from_offset(hapd, sta,
							      dialog_token,
							      0, start_offset,
							      &next_offset,
							      &more);
	if (!frame)
		return;

	if (hostapd_drv_send_action(hapd, hapd->iface->freq, 0, sta->addr,
				    wpabuf_head(frame), wpabuf_len(frame)) < 0)
	{
		wpa_printf(MSG_INFO,
			   "DSCP: Failed to send next policy frame to " MACSTR,
			   MAC2STR(sta->addr));
	}

	wpabuf_free(frame);

	sta->dscp_state.offset = next_offset;
	sta->dscp_state.last_dialog_token = dialog_token;
	sta->dscp_state.pending_more = more;
}


/* Handle DSCP Policy Response frame */
int hostapd_handle_dscp_policy_response(struct hostapd_data *hapd,
					struct sta_info *sta,
					const u8 *data, size_t len)
{
	const u8 *pos = data, *end = data + len;
	u8 dialog_token;
	u8 response_control;
	u8 count;

	if (!sta || !(sta->flags & WLAN_STA_DSCP_POLICY)) {
		wpa_printf(MSG_DEBUG, "DSCP: STA " MACSTR " not capable",
			   MAC2STR(sta->addr));
		return -1;
	}

	if (len < 2)
		return -1;

	dialog_token = *pos++;
	response_control = *pos++;

	/* Handle reset case */
	if (response_control & DSCP_POLICY_CTRL_RESET) {
		free_dscp_policies(sta);
		reset_dscp_state(sta);
	}

	/* Unsolicited Response (Dialog Token 0) */
	if (dialog_token == 0 && (response_control & DSCP_POLICY_CTRL_RESET)) {
		wpa_printf(MSG_DEBUG, "DSCP: STA " MACSTR
			   " issued unsolicited reset", MAC2STR(sta->addr));
		free_dscp_policies(sta);
		reset_dscp_state(sta);
		return 0;
	}

	if (len < 3)
		return -1;
	count = *pos++;

	/* Process status duples */
	while (count > 0 && end - pos >= 2) {
		struct hostapd_dscp_policy *policy = NULL;
		u8 policy_id = *pos++;
		u8 status = *pos++;
		unsigned int i;

		count--;

		for (i = 0; i < sta->num_dscp_policies; i++) {
			if (sta->policies[i]->policy_id == policy_id) {
				policy = sta->policies[i];
				break;
			}
		}

		if (!policy) {
			wpa_printf(MSG_DEBUG,
				   "DSCP: Unknown policy ID %u in response",
				   policy_id);
			continue;
		}

		switch (status) {
		case DSCP_STATUS_SUCCESS:
			if (policy->req_type == DSCP_POLICY_REQ_REMOVE)
				invalidate_policy_by_id(sta, policy_id);
			else
				update_policy_status(sta, policy_id, status);
			break;
		case DSCP_STATUS_CLASSIFIER_NOT_SUPPORTED:
		case DSCP_STATUS_REQUEST_DECLINED:
		case DSCP_STATUS_INSUFFICIENT_RESOURCES:
			invalidate_policy_by_id(sta, policy_id);
			break;
		default:
			wpa_printf(MSG_DEBUG,
				   "DSCP: Unknown status %u for policy %u",
				   status, policy_id);
			break;
		}
	}

	/* If More bit is set, STA wants more policies */
	if ((response_control & DSCP_POLICY_CTRL_MORE) &&
	    sta->dscp_state.pending_more) {
		wpa_printf(MSG_DEBUG,
			   "DSCP: STA " MACSTR
			   " requested additional policy batch",
			   MAC2STR(sta->addr));
		hostapd_send_next_dscp_policy_batch(hapd, sta,
						    sta->dscp_state.offset);
	}

	return 0;
}

#endif

#ifdef CONFIG_IEEE80211AX
u8 *hostapd_add_scs_ie(u8 *frm, bool scs)
{
	/* Element ID */
	*frm++ = WLAN_EID_VENDOR_SPECIFIC;
	/* SCS WFA IE length - [Elem ID(1) + Length(1)] */
	*frm++ = SCS_WFA_IE_LEN - 2;

	/* WFA OUI */
	*frm++ = (OUI_WFA >> 16) & 0xFF;
	*frm++ = (OUI_WFA >> 8) & 0xFF;
	*frm++ = OUI_WFA & 0xFF;

	/* OUI Type */
	*frm++ = WFA_CAPA_OUI_TYPE;

	/* Capabilities length */
	*frm++ = 1;

	/* SCS capability */
	if (scs)
		*frm++ = (1 << HOSTAPD_SCS_DESCR_CAP_BIT);
	else
		*frm++ = (0 << HOSTAPD_SCS_DESCR_CAP_BIT);

	return frm;
}


static u8 hostapd_get_scs_index(struct sta_info *sta, u8 scs_id)
{
	u8 idx = 0;

	if (!sta || !sta->scs_session_count)
		return HOSTAPD_SCS_MAX_DESCRIPTORS_PER_PEER;

	while (idx < sta->scs_session_count) {
		if (!sta->scs_req_desc[idx])
			return HOSTAPD_SCS_MAX_DESCRIPTORS_PER_PEER;
		if (scs_id == sta->scs_req_desc[idx]->scs_id)
			return idx;
		idx++;
	}

	return HOSTAPD_SCS_MAX_DESCRIPTORS_PER_PEER;
}


static bool hostapd_is_scs_present(struct sta_info *sta, u8 scs_id)
{
	if (hostapd_get_scs_index(sta, scs_id) >=
				HOSTAPD_SCS_MAX_DESCRIPTORS_PER_PEER)
		return false;

	return true;
}


static int hostapd_parse_tclas4_params(const u8 **payload,
				       union tclas_elem *tclas_elem)
{
	enum qm_ip_ver ip_version;

	tclas_elem->type4_params.classifier_mask = *(*payload)++;
	tclas_elem->type4_params.ip_ver = *(*payload)++;
	ip_version = tclas_elem->type4_params.ip_ver;

	switch (ip_version) {
	case IP_VERSION_4:
		os_memcpy(tclas_elem->type4_params.src_ip.ipv4, *payload,
			  IPV4_LEN);
		*payload += IPV4_LEN;
		os_memcpy(tclas_elem->type4_params.dst_ip.ipv4, *payload,
			  IPV4_LEN);
		*payload += IPV4_LEN;
		break;

	case IP_VERSION_6:
		os_memcpy(tclas_elem->type4_params.src_ip.ipv6, *payload,
			  IPV6_LEN);
		*payload += IPV6_LEN;
		os_memcpy(tclas_elem->type4_params.dst_ip.ipv6, *payload,
			  IPV6_LEN);
		*payload += IPV6_LEN;
		break;

	default:
		wpa_printf(MSG_ERROR, "Invalid TCLAS4 IP version");
		return HOSTAPD_QM_STATUS_E_INVAL;
	}

	tclas_elem->type4_params.src_port = WPA_GET_BE16(*payload);
	*payload += 2;
	tclas_elem->type4_params.dst_port = WPA_GET_BE16(*payload);
	*payload += 2;
	tclas_elem->type4_params.dscp = *(*payload)++;

	if (ip_version == IP_VERSION_4) {
		tclas_elem->type4_params.protocol = *(*payload)++;
		/* Reserved octet */
		*payload += 1;
	} else if (ip_version == IP_VERSION_6) {
		tclas_elem->type4_params.next_header = *(*payload)++;
		os_memcpy(tclas_elem->type4_params.flow_label, *payload,
			  HOSTAPD_TCLAS_FLOW_LABEL_SIZE);
		*payload += HOSTAPD_TCLAS_FLOW_LABEL_SIZE;
	}

	wpa_printf(MSG_DEBUG, "TCLAS4 element parsing complete");
	return HOSTAPD_QM_STATUS_SUCCESS;
}


static int hostapd_parse_tclas10_params(const u8 **payload,
					union tclas_elem *tclas_elem,
					u8 tclas_len)
{
	u8 filter_len;

	tclas_elem->type10_params.protocol_instance = *(*payload)++;
	tclas_elem->type10_params.protocol_number = *(*payload)++;

	/* Calculating filter length from total Tclas element length.
	 * tclas_len contains length of Elem ID (1) + Length (1) + UP (1) +
	 * Classifier type (1) + Proto Instance (1) + Protocol number (1) +
	 * Filter mask (Variable) + Filter value (Variable).
	 * Subtracting fixed length field (6) from tclas_len to calculate
	 * filter length value for filter_value and filter_mask
	 */
	filter_len = (tclas_len - 6) / 2;
	if ((filter_len < 0) || (filter_len > HOSTAPD_TCLAS10_FILTER_LEN)) {
		wpa_printf(MSG_ERROR, "TCLAS10 filter length Invalid");
		return HOSTAPD_QM_STATUS_E_INVAL;
	}

	tclas_elem->type10_params.filter_len = filter_len;
	os_memcpy(tclas_elem->type10_params.filter_value, *payload, filter_len);
	*payload += filter_len;
	os_memcpy(tclas_elem->type10_params.filter_mask, *payload, filter_len);
	*payload += filter_len;

	wpa_printf(MSG_DEBUG, "TCLAS10 element parsing complete");
	return HOSTAPD_QM_STATUS_SUCCESS;
}


static int hostapd_parse_scs_tclas_elements(
			const u8 **payload,
			struct hostapd_scs_req_desc_data *scs_req_desc, u8 *len)
{
	struct hostapd_tclas_elements *tclas_tuple = NULL;
	union tclas_elem *tclas_elem = NULL;
	int ret = HOSTAPD_QM_STATUS_SUCCESS;
	u8 elem_id, type, tclas_len;
	u8 tclas_idx = 0;

	while (*len > 0) {
		elem_id = **payload;
		/* Process only TCLAS element(s) and TCLAS Processing element
		 * in this loop
		 */
		if (elem_id != WLAN_EID_TCLAS &&
		    elem_id != WLAN_EID_TCLAS_PROCESSING)
			break;

		*payload += 1;
		if (elem_id == WLAN_EID_TCLAS) {

			if (tclas_idx >=
			    HOSTAPD_SCS_MAX_TCLAS_ELEMENTS_PER_DESCRIPTOR) {
				wpa_printf(MSG_ERROR, "TCLAS: Max elements per "
					   "request exceeded");
				ret = HOSTAPD_QM_STATUS_E_NOSUPPORT;
				goto fail;
			}

			tclas_len = *(*payload)++;

			/* Add elem_id, length to tclas_len */
			tclas_len += 2;

			if (*len < tclas_len) {
				wpa_printf(MSG_ERROR, "Invalid TCLAS length:%d",
					   tclas_len);
				ret = HOSTAPD_QM_STATUS_E_INVAL;
				goto fail;
			}

			tclas_tuple = &scs_req_desc->tclas[tclas_idx];
			tclas_elem = &tclas_tuple->tclas_elem;
			tclas_tuple->up = *(*payload)++;
			tclas_tuple->classifier_type = *(*payload)++;
			type = tclas_tuple->classifier_type;

			switch (type) {
			case QM_TCLAS_CLASSIFIER_TYPE4:
				ret = hostapd_parse_tclas4_params(payload,
								  tclas_elem);
				if (ret)
					goto fail;
				break;
			case QM_TCLAS_CLASSIFIER_TYPE10:
				ret = hostapd_parse_tclas10_params(payload,
								   tclas_elem,
								   tclas_len);
				if (ret)
					goto fail;
				break;
			default:
				wpa_printf(MSG_ERROR, "Unknown tclas "
					   "classifier: %d", type);
				ret = HOSTAPD_QM_STATUS_E_INVAL;
				goto fail;
			}

			tclas_idx++;
			*len -= tclas_len;

		} else if (elem_id == WLAN_EID_TCLAS_PROCESSING) {
			/* TCLAS processing element length */
			*payload += 1;
			scs_req_desc->tclas_processing = *(*payload)++;
			/* Length of Element ID, len, TCLAS processing field */
			*len -= 3;
			wpa_printf(MSG_DEBUG, "Tclas processing value:%d",
				   scs_req_desc->tclas_processing);
		}

		scs_req_desc->num_tclas_elements = tclas_idx;
	}

fail:
	return ret;
}


#ifdef CONFIG_IEEE80211BE
static int hostapd_parse_scs_qos_attributes(
				const u8 *payload,
				struct hostapd_scs_req_desc_data *scs_req_desc,
				u8 *len)
{
	struct hostapd_scs_qos_attributes *qos_attr;
	u8 elem_id, elem_id_extension;
	u8 qos_length, temp_length;
	u8 msdu_delivery_info;
	u16 bitmap;
	u32 control_info;
	int ret = HOSTAPD_QM_STATUS_SUCCESS;

	if (*len < HOSTAPD_SCS_QOS_ATTR_MIN_LEN)
		return ret;

	elem_id = *payload++;
	if (elem_id != WLAN_EID_EXTENSION)
		return ret;

	qos_length = *payload++;
	temp_length = qos_length;
	elem_id_extension = *payload++;

	if (elem_id_extension != WLAN_EID_EXT_QOS_CHARACTERISTICS) {
		wpa_printf(MSG_ERROR, "Invalid QoS characteristics element ID:%d",
			   elem_id_extension);
		ret = HOSTAPD_QM_STATUS_E_INVAL;
		goto fail;
	}

	/* Subtract length of elemid_extension */
	qos_length -= 1;

	qos_attr = &scs_req_desc->qos_attr;

	/* Parse QoS attributes - Mandatory parameters*/
	/* Control Info */
	HOSTAPD_GET_QOS_ATTR(control_info, payload, CTRL_INFO, 32);

	qos_attr->direction = HOSTAPD_GET_QOS_ATTR_CTRL_INFO(control_info,
							     DIRECTION);
	if (qos_attr->direction == SCS_DIRECTION_DIRECT) {
		wpa_printf(MSG_ERROR, "SCS for direct link is not supported "
			   "by AP");
		ret = HOSTAPD_QM_STATUS_E_NOSUPPORT;
		goto fail;
	}
	qos_attr->tid = HOSTAPD_GET_QOS_ATTR_CTRL_INFO(control_info, TID);
	qos_attr->up = HOSTAPD_GET_QOS_ATTR_CTRL_INFO(control_info, UP);
	qos_attr->bitmap = HOSTAPD_GET_QOS_ATTR_CTRL_INFO(control_info, BITMAP);
	qos_attr->link_id = HOSTAPD_GET_QOS_ATTR_CTRL_INFO(control_info,
							   LINK_ID);
	qos_length -= HOSTAPD_SCS_QOS_ATTR_CTRL_INFO_LEN;

	/* Min Service Interval */
	HOSTAPD_GET_QOS_ATTR(qos_attr->min_service_interval, payload,
			     SERVICE_INTERVAL, 32);
	qos_length -= HOSTAPD_SCS_QOS_ATTR_SERVICE_INTERVAL_LEN;

	/* Max Service Interval */
	HOSTAPD_GET_QOS_ATTR(qos_attr->max_service_interval, payload,
			     SERVICE_INTERVAL, 32);
	qos_length -= HOSTAPD_SCS_QOS_ATTR_SERVICE_INTERVAL_LEN;

	/* Min Data rate */
	os_memcpy(&qos_attr->min_data_rate, payload,
		  HOSTAPD_SCS_QOS_ATTR_MIN_DATA_RATE_LEN);
	HOSTAPD_GET_QOS_ATTR_ACTUAL(qos_attr->min_data_rate, payload,
				    &qos_attr->min_data_rate, MIN_DATA_RATE,
				    32);
	qos_length -= HOSTAPD_SCS_QOS_ATTR_MIN_DATA_RATE_LEN;

	/* Delay Bound */
	os_memcpy(&qos_attr->delay_bound, payload,
		  HOSTAPD_SCS_QOS_ATTR_DELAY_BOULND_LEN);
	HOSTAPD_GET_QOS_ATTR_ACTUAL(qos_attr->delay_bound, payload,
				    &qos_attr->delay_bound, DELAY_BOULND, 32);
	qos_length -= HOSTAPD_SCS_QOS_ATTR_DELAY_BOULND_LEN;

	/* Parse QoS attributes - Optional parameters */
	bitmap = scs_req_desc->qos_attr.bitmap;

	/* Max MSDU Size */
	if ((qos_length > 0) &&
	    HOSTAPD_SCS_IS_QOS_ATTR_PRESENT(bitmap, MAX_MSDU_SIZE)) {
		HOSTAPD_GET_QOS_ATTR(qos_attr->max_msdu_size, payload,
				     MAX_MSDU_SIZE, 16);
		qos_length -= HOSTAPD_SCS_QOS_ATTR_MAX_MSDU_SIZE_LEN;
	}

	/* Service Start Time */
	if ((qos_length > 0) &&
	    HOSTAPD_SCS_IS_QOS_ATTR_PRESENT(bitmap, SERVICE_START_TIME)) {
		HOSTAPD_GET_QOS_ATTR(qos_attr->service_start_time, payload,
				     SERVICE_START_TIME, 32);
		qos_length -= HOSTAPD_SCS_QOS_ATTR_SERVICE_START_TIME_LEN;
	}

	/* Service Start Time Link ID */
	if ((qos_length > 0) &&
	    HOSTAPD_SCS_IS_QOS_ATTR_PRESENT(bitmap,
					    SERVICE_START_TIME_LINK_ID)) {
		HOSTAPD_GET_QOS_ATTR(qos_attr->service_start_time_link_id,
				     payload, SERVICE_START_TIME_LINK_ID, 8);
		qos_length -=
			HOSTAPD_SCS_QOS_ATTR_SERVICE_START_TIME_LINK_ID_LEN;
	}

	/* Mean Data Rate */
	if ((qos_length > 0) &&
	    HOSTAPD_SCS_IS_QOS_ATTR_PRESENT(bitmap, MEAN_DATA_RATE)) {
		os_memcpy(&qos_attr->mean_data_rate, payload,
			  HOSTAPD_SCS_QOS_ATTR_MEAN_DATA_RATE_LEN);
		HOSTAPD_GET_QOS_ATTR_ACTUAL(qos_attr->mean_data_rate, payload,
					    &qos_attr->mean_data_rate,
					    MEAN_DATA_RATE, 32);
		qos_length -= HOSTAPD_SCS_QOS_ATTR_MEAN_DATA_RATE_LEN;
	}

	/* Burst Size */
	if ((qos_length > 0) &&
	    HOSTAPD_SCS_IS_QOS_ATTR_PRESENT(bitmap, BURST_SIZE)) {
		HOSTAPD_GET_QOS_ATTR(qos_attr->burst_size, payload,
				     BURST_SIZE, 32);
		qos_length -= HOSTAPD_SCS_QOS_ATTR_BURST_SIZE_LEN;
	}

	/* MSDU Lifetime */
	if ((qos_length > 0) &&
	    HOSTAPD_SCS_IS_QOS_ATTR_PRESENT(bitmap, MSDU_LIFETIME)) {
		HOSTAPD_GET_QOS_ATTR(qos_attr->msdu_lifetime, payload,
				     MSDU_LIFETIME, 16);
		qos_length -= HOSTAPD_SCS_QOS_ATTR_MSDU_LIFETIME_LEN;
	}

	/* MSDU Delivery Info */
	if ((qos_length > 0) &&
	    HOSTAPD_SCS_IS_QOS_ATTR_PRESENT(bitmap, MSDU_DELIVERY_INFO)) {
		HOSTAPD_GET_QOS_ATTR(msdu_delivery_info, payload,
				     MSDU_DELIVERY_INFO, 8);
		qos_length -= HOSTAPD_SCS_QOS_ATTR_MSDU_DELIVERY_INFO_LEN;

		/* MSDU Delivery Ratio */
		qos_attr->msdu_delivery_ratio =
			HOSTAPD_GET_QOS_ATTR_MSDU_DELIVERY_INFO(
					msdu_delivery_info, RATIO);

		/* MSDU Count Exponent */
		qos_attr->msdu_count_exponent =
			HOSTAPD_GET_QOS_ATTR_MSDU_DELIVERY_INFO(
					msdu_delivery_info, COUNT_EXPONENT);
	}

	/* Medium Time */
	if ((qos_length > 0) &&
	    HOSTAPD_SCS_IS_QOS_ATTR_PRESENT(bitmap, MEDIUM_TIME)) {
		HOSTAPD_GET_QOS_ATTR(qos_attr->medium_time, payload,
				     MEDIUM_TIME, 16);
		qos_length -= HOSTAPD_SCS_QOS_ATTR_MEDIUM_TIME_LEN;
	}

	scs_req_desc->is_qos_present = true;

	if (qos_length == 0)
		wpa_printf(MSG_INFO, "SCS QoS attributes parsing complete");

	/* Subtracting length of (Elem ID and length field) - 2 bytes and
	 * QOS attr length from the frm_length
	 */
	*len = *len - 2 - temp_length;

fail:
	return ret;
}
#endif /* CONFIG_IEEE80211BE */


static int hostapd_parse_scs_desc(
		struct hostapd_data *hapd, const u8 *payload,
		struct sta_info *sta,
		struct hostapd_scs_req_desc_data *scs_req_desc, u8 len)
{
	int ret = WLAN_STATUS_REQUEST_DECLINED;
	u8 scs_id, req_type;
	bool scs_avail;
	u8 elem_id;

	/* SCS ID */
	scs_req_desc->scs_id = *payload++;
	/* Request Type */
	scs_req_desc->request_type = *payload++;
	len -= 2;

	scs_id = scs_req_desc->scs_id;
	req_type = scs_req_desc->request_type;

	scs_avail = hostapd_is_scs_present(sta, scs_id);

	if (req_type == QM_REMOVE_REQ || req_type == QM_CHANGE_REQ) {
		if (!sta->scs_session_count) {
			wpa_printf(MSG_ERROR, "AP is declining this request: "
				   "SCS session inactive");
			goto decline;
		}

		if (!scs_avail) {
			wpa_printf(MSG_ERROR, "scs id %d is not present",
				   scs_id);
			goto decline;
		}

	} else if (req_type == QM_ADD_REQ) {
		if (sta->scs_session_count ==
				HOSTAPD_SCS_MAX_DESCRIPTORS_PER_PEER) {
			wpa_printf(MSG_ERROR, "AP has already configured "
				   "maximum supported SCS desc per peer");
			goto decline;
		}

		if (scs_avail) {
			wpa_printf(MSG_ERROR, "scs id %d is already present",
				   scs_id);
			goto decline;
		}
	}

	/* Only SCS ID and request type are present in Remove request */
	if (req_type == SCS_REQ_REMOVE)
		return WLAN_STATUS_SUCCESS;

	elem_id = *payload;
	/* Parse Intra-Access category */
	if (elem_id == WLAN_EID_INTRA_ACCESS_CATEGORY_PRIORITY) {
		/* Element ID */
		payload++;
		/* Length */
		payload++;
		scs_req_desc->intra_access_priority = *payload++;
		/* Length of Intra Access Category element */
		len -= 3;
	}

	elem_id = *payload;
	/* Check if TCLAS element or QOS attributes is present or not */
	if (elem_id != WLAN_EID_TCLAS && elem_id != WLAN_EID_EXTENSION) {
		wpa_printf(MSG_ERROR, "Declining this request: Both "
			   "TCLAS element & QOS attributes are absent");
		goto decline;
	}

	/* Parse TCLAS elements */
	ret = hostapd_parse_scs_tclas_elements(&payload, scs_req_desc, &len);
	if (ret != HOSTAPD_QM_STATUS_SUCCESS) {
		wpa_printf(MSG_ERROR, "SCS TCLAS element parse error");
		ret = WLAN_STATUS_REQUEST_DECLINED;
		goto decline;
	}

	scs_req_desc->is_qos_present = false;

	/* Parse QoS attributes */
#ifdef CONFIG_IEEE80211BE
	ret = hostapd_parse_scs_qos_attributes(payload, scs_req_desc, &len);
	if (ret != HOSTAPD_QM_STATUS_SUCCESS) {
		ret = WLAN_STATUS_REQUEST_DECLINED;
		goto decline;
	}
#endif /* CONFIG_IEEE80211BE */

	wpa_printf(MSG_DEBUG, "SCS descriptor is parsed successfully, id:%d",
		   scs_id);

	if (len != 0)
		wpa_printf(MSG_DEBUG, "Optional subelements are also present, "
			  "len:%d", len);

	return WLAN_STATUS_SUCCESS;

decline:
	wpa_printf(MSG_ERROR, "Decline SCS descriptor - id:%d, type:%d, ret:%d\n",
		   scs_id, req_type, ret);
	return ret;
}


static void
hostapd_copy_tclas4_elem(struct qm_tclas_type4_params *qm_tclas4,
			 struct hostapd_tclas4_params scs_tclas4)
{
	qm_tclas4->classifier_mask = scs_tclas4.classifier_mask;
	qm_tclas4->ip_ver = scs_tclas4.ip_ver;
	qm_tclas4->src_port = scs_tclas4.src_port;
	qm_tclas4->dst_port = scs_tclas4.dst_port;
	qm_tclas4->dscp = scs_tclas4.dscp;

	if (qm_tclas4->ip_ver == IP_VERSION_4) {
		os_memcpy(qm_tclas4->src_ip.ipv4, scs_tclas4.src_ip.ipv4,
			  IPV4_LEN);
		os_memcpy(qm_tclas4->dst_ip.ipv4, scs_tclas4.dst_ip.ipv4,
			  IPV4_LEN);
		qm_tclas4->protocol = scs_tclas4.protocol;

	} else if (qm_tclas4->ip_ver == IP_VERSION_6) {
		os_memcpy(qm_tclas4->src_ip.ipv4, scs_tclas4.src_ip.ipv4,
			  IPV6_LEN);
		os_memcpy(qm_tclas4->dst_ip.ipv4, scs_tclas4.dst_ip.ipv4,
			  IPV6_LEN);
		qm_tclas4->next_header = scs_tclas4.next_header;
		os_memcpy(qm_tclas4->flow_label, scs_tclas4.flow_label,
			  TCLAS4_FLOW_LABEL_SIZE);
	}
}


static void
hostapd_copy_tclas10_elem(struct qm_tclas_type10_params *qm_tclas10,
			  struct hostapd_tclas10_params scs_tclas10)
{
	u8 filter_len;

	qm_tclas10->protocol_instance = scs_tclas10.protocol_instance;
	qm_tclas10->protocol_number = scs_tclas10.protocol_number;
	qm_tclas10->filter_len = scs_tclas10.filter_len;
	filter_len = qm_tclas10->filter_len;

	/* For SCS protocol, filter_len is equal for filter mask and value.
	 * This filter_len is extracted from frame parsing.
	 */
	os_memcpy(qm_tclas10->filter_value, scs_tclas10.filter_value,
		  filter_len);
	os_memcpy(qm_tclas10->filter_mask, scs_tclas10.filter_mask, filter_len);
}


static void
hostapd_copy_scs_tclas_elem(struct qm_tclas_elements *qm_tclas,
			    struct hostapd_tclas_elements scs_tclas)
{
	u8 type;

	qm_tclas->up = scs_tclas.up;
	qm_tclas->classifier_type = scs_tclas.classifier_type;
	type = qm_tclas->classifier_type;

	switch (type) {
	case QM_TCLAS_CLASSIFIER_TYPE4:
		hostapd_copy_tclas4_elem(&qm_tclas->tclas_elem.type4_params,
					 scs_tclas.tclas_elem.type4_params);
		break;
	case QM_TCLAS_CLASSIFIER_TYPE10:
		hostapd_copy_tclas10_elem(&qm_tclas->tclas_elem.type10_params,
					  scs_tclas.tclas_elem.type10_params);
		break;
	default:
		wpa_printf(MSG_ERROR, "Unknown TCLAS classifier:%d", type);
		break;
	}
}


static void hostapd_copy_scs_qos_attr(
			struct qm_qos_attributes *qm_qos_attr,
			struct hostapd_scs_qos_attributes scs_qos_attr)
{
	/* Control Info */
	qm_qos_attr->direction = scs_qos_attr.direction;
	qm_qos_attr->tid = scs_qos_attr.tid;
	qm_qos_attr->up = scs_qos_attr.up;
	qm_qos_attr->bitmap = scs_qos_attr.bitmap;
	qm_qos_attr->link_id = scs_qos_attr.link_id;

	/* Mandatory QoS Parameters */
	qm_qos_attr->min_service_interval = scs_qos_attr.min_service_interval;
	qm_qos_attr->max_service_interval = scs_qos_attr.max_service_interval;
	qm_qos_attr->min_data_rate = scs_qos_attr.min_data_rate;
	qm_qos_attr->delay_bound = scs_qos_attr.delay_bound;

	/* Optional QoS Parameters */
	qm_qos_attr->max_msdu_size = scs_qos_attr.max_msdu_size;
	qm_qos_attr->service_start_time = scs_qos_attr.service_start_time;
	qm_qos_attr->service_start_time_link_id =
				scs_qos_attr.service_start_time_link_id;
	qm_qos_attr->mean_data_rate = scs_qos_attr.mean_data_rate;
	qm_qos_attr->burst_size = scs_qos_attr.burst_size;
	qm_qos_attr->msdu_lifetime = scs_qos_attr.msdu_lifetime;
	qm_qos_attr->msdu_delivery_ratio = scs_qos_attr.msdu_delivery_ratio;
	qm_qos_attr->msdu_count_exponent = scs_qos_attr.msdu_count_exponent;
	qm_qos_attr->medium_time = scs_qos_attr.medium_time;
}


static void hostapd_copy_scs_desc(struct qm_req_desc_data *qm_data,
				  struct hostapd_scs_req_desc_data scs_data)
{
	int tclas_idx;

	qm_data->qm_id = scs_data.scs_id;
	qm_data->request_type = scs_data.request_type;
	qm_data->priority = scs_data.intra_access_priority;
	qm_data->num_tclas_elements = scs_data.num_tclas_elements;

	/* Copy TCLAS elements if only present */
	for (tclas_idx = 0;
	     tclas_idx < qm_data->num_tclas_elements;
	     tclas_idx++) {
		hostapd_copy_scs_tclas_elem(&qm_data->tclas[tclas_idx],
					    scs_data.tclas[tclas_idx]);
	}

	/* Copy TCLAS Processing value if more than one TCLAS elem is present */
	if (qm_data->num_tclas_elements > 1)
		qm_data->tclas_processing = scs_data.tclas_processing;

	qm_data->is_qos_present = scs_data.is_qos_present;

#ifdef CONFIG_IEEE80211BE
	/* Copy QoS Attribute if only present */
	if (qm_data->is_qos_present)
		hostapd_copy_scs_qos_attr(&qm_data->qos_attr,
					  scs_data.qos_attr);
#endif
}


static void
hostapd_copy_scs_resp_desc(struct hostapd_scs_resp_desc_data *scs_resp_desc,
			   struct qm_resp_desc_data qm_resp_desc)
{
	scs_resp_desc->scs_id = qm_resp_desc.qm_id;
	scs_resp_desc->status = qm_resp_desc.status;
}


static void hostapd_copy_scs_resp(struct hostapd_scs_resp_data *scs_resp,
				  struct qm_resp_data qm_resp)
{
	int idx;

	scs_resp->dialog_token = qm_resp.dialog_token;
	scs_resp->num_scs_desc = qm_resp.num_qm_desc;

	for (idx = 0; idx < scs_resp->num_scs_desc; idx++)
		hostapd_copy_scs_resp_desc(&(scs_resp->scs_resp_desc[idx]),
					   qm_resp.qm_resp_desc[idx]);
}


static int
hostapd_copy_and_send_scs_data(struct hostapd_data *hapd, struct sta_info *sta,
			       struct hostapd_scs_req_data *scs_req,
			       struct hostapd_scs_resp_data *scs_resp)
{
	int ret = HOSTAPD_QM_STATUS_SUCCESS;
	struct qm_resp_data qm_resp = {0};
	struct qm_req_data qm_req = {0};
	int idx;

	if (!hapd->driver)
		return HOSTAPD_QM_STATUS_E_INVAL;

	os_memcpy(qm_req.peer_mac, scs_req->peer_mac, ETH_ALEN);

	qm_req.qm_type = HOSTAPD_QM_TYPE_SCS;
	qm_req.dialog_token = scs_req->dialog_token;
	qm_req.num_qm_desc = scs_req->num_scs_desc;

	for (idx = 0; idx < qm_req.num_qm_desc; idx++) {
		hostapd_copy_scs_desc(&qm_req.qm_req_desc[idx],
				      scs_req->scs_req_desc[idx]);
	}

	ret = hostapd_drv_set_qos(hapd, &qm_req, &qm_resp);
	if (ret == 0)
		hostapd_copy_scs_resp(scs_resp, qm_resp);
	else
		wpa_printf(MSG_ERROR, "set_qos failed, ret:%d", ret);

	return ret;
}

static void hostapd_qm_prepare_nft_rule(struct hostapd_data *hapd, struct sta_info *sta,
					struct hostapd_tclas_elements *te,
					struct hostapd_nft_rule_params *rule,
					u8 qm_id, u8 qm_tag)
{

	if (te->classifier_type == QM_TCLAS_CLASSIFIER_TYPE4) {
		if (te->tclas_elem.type4_params.classifier_mask & BIT(0)) {
			rule->ip_family = te->tclas_elem.type4_params.ip_ver;
		}

		if (te->tclas_elem.type4_params.classifier_mask & BIT(1)) {
			if (rule->ip_family == 4) {
				memcpy(&rule->saddr4, te->tclas_elem.type4_params.src_ip.ipv4, IPV4_LEN);
				htonl(rule->saddr4);
			} else {
				memcpy(rule->saddr6, te->tclas_elem.type4_params.src_ip.ipv6, IPV6_LEN);
			}
			rule->valid_flags |= NFT_RULE_PARAM_SADDR;
		}

		if (te->tclas_elem.type4_params.classifier_mask & BIT(2)) {
			if (rule->ip_family == 4) {
				memcpy(&rule->daddr4, te->tclas_elem.type4_params.dst_ip.ipv4, IPV4_LEN);
				htonl(rule->daddr4);
			} else {
				memcpy(rule->daddr6, te->tclas_elem.type4_params.dst_ip.ipv6, IPV6_LEN);
			}
			rule->valid_flags |= NFT_RULE_PARAM_DADDR;
		}

		if (te->tclas_elem.type4_params.classifier_mask & BIT(3)) {
			rule->sport = te->tclas_elem.type4_params.src_port;
			rule->valid_flags |= NFT_RULE_PARAM_SPORT;
		}

		if (te->tclas_elem.type4_params.classifier_mask & BIT(4)) {
			rule->dport = te->tclas_elem.type4_params.dst_port;
			rule->valid_flags |= NFT_RULE_PARAM_DPORT;
		}

		if (te->tclas_elem.type4_params.classifier_mask & BIT(6)) {
			if (rule->ip_family == 4) {
				rule->proto = te->tclas_elem.type4_params.protocol;
			} else {
				rule->proto = te->tclas_elem.type4_params.next_header;
			}
			rule->valid_flags |= NFT_RULE_PARAM_PROTO;
		}

		if (te->tclas_elem.type4_params.classifier_mask & BIT(5)) {
			rule->dscp = te->tclas_elem.type4_params.dscp;
			rule->valid_flags |= NFT_RULE_PARAM_DSCP;
		}

		wpa_printf(MSG_INFO, "qm_id : %d classifier_type : 0x%x classifier_mask : 0x%x\n", qm_id,
			   te->classifier_type, te->tclas_elem.type4_params.classifier_mask);

	} else if (te->classifier_type == QM_TCLAS_CLASSIFIER_TYPE10) {

		rule->valid_flags |= NFT_RULE_PARAM_PROTO;
		rule->proto = te->tclas_elem.type10_params.protocol_number;

		if (rule->proto == IPPROTO_UDP) {
			rule->valid_flags |= NFT_RULE_PARAM_DPORT;
			rule->dport = 4500;
		}

		rule->esp_spi =  ((te->tclas_elem.type10_params.filter_value[0]  & te->tclas_elem.type10_params.filter_mask[0]) << 24) | \
				  ((te->tclas_elem.type10_params.filter_value[1] & te->tclas_elem.type10_params.filter_mask[1]) << 16) | \
				  ((te->tclas_elem.type10_params.filter_value[2] & te->tclas_elem.type10_params.filter_mask[2]) << 8)  | \
				  ((te->tclas_elem.type10_params.filter_value[3] & te->tclas_elem.type10_params.filter_mask[3]) << 0);
	}

	memcpy(rule->dmac, sta->addr, ETH_ALEN);
	rule->valid_flags |= NFT_RULE_PARAM_DMAC;
	rule->mark = (qm_id << 8) | qm_tag;
	os_snprintf(rule->chain, sizeof(rule->chain), "%s_%s", CHAIN_NAME, hapd->conf->iface);
	os_snprintf(rule->table, sizeof(rule->table), "%s", TABLE_NAME);
	rule->nf_family = NFPROTO_NETDEV;
}

static int hostapd_scs_add_nft_rule(struct hostapd_data *hapd, struct sta_info *sta, int scs_idx)
{
	struct hostapd_scs_req_desc_data *scs_req_desc = sta->scs_req_desc[scs_idx];
	struct hostapd_tclas_elements te;
	int i = 0;

	struct hostapd_nft_rule_params rule = {0};

	for (i = 0; i < scs_req_desc->num_tclas_elements; i++) {

		os_memset(&rule, 0, sizeof(rule));

		te = scs_req_desc->tclas[i];

		hostapd_qm_prepare_nft_rule(hapd, sta, &te, &rule, scs_req_desc->scs_id, HOSTAPD_QOS_SCS_TAG);

		if ((rule.valid_flags & NFT_RULE_PARAM_DPORT ||
		    rule.valid_flags & NFT_RULE_PARAM_SPORT) &&
		    !(rule.valid_flags & NFT_RULE_PARAM_PROTO)) {

			rule.valid_flags |= NFT_RULE_PARAM_PROTO;

			rule.proto = IPPROTO_UDP;
			hostapd_ucode_config_nft_rule(hapd, &rule, true);

			rule.proto = IPPROTO_TCP;
		} else if (te.classifier_type == QM_TCLAS_CLASSIFIER_TYPE10) {
			rule.ip_family = 4;
			hostapd_ucode_config_nft_rule(hapd, &rule, true);
			rule.ip_family = 6;
		}

		hostapd_ucode_config_nft_rule(hapd, &rule, true);

		wpa_printf(MSG_INFO, "scs_id:%u rule valid flag : 0x%x ", scs_req_desc->scs_id, rule.valid_flags);
	}
	return 0;
}

static int hostapd_scs_delete_nft_rule(struct hostapd_data *hapd, struct sta_info *sta, int scs_idx)
{
	struct hostapd_scs_req_desc_data *scs_data;
	struct hostapd_tclas_elements te;
	struct hostapd_nft_rule_params rule = {0};
	int i = 0;

	scs_data = sta->scs_req_desc[scs_idx];

	for (i = 0; i < scs_data->num_tclas_elements; i++) {

		te = scs_data->tclas[i];

		hostapd_qm_prepare_nft_rule(hapd, sta, &te, &rule, scs_data->scs_id, HOSTAPD_QOS_SCS_TAG);

		hostapd_ucode_config_nft_rule(hapd, &rule, false);
		wpa_printf(MSG_INFO, "scs_id:%u rule deleted", scs_data->scs_id);
	}
	return 0;
}

static int
hostapd_process_scs_add(struct hostapd_data *hapd, struct sta_info *sta,
			struct hostapd_scs_req_desc_data *scs_req_desc_tmp,
			u8 status)
{
	struct hostapd_scs_req_desc_data *scs_req_desc;
	u8 scs_id = scs_req_desc_tmp->scs_id;
	int idx;

	if (status != HOSTAPD_QM_STATUS_SUCCESS) {
		wpa_printf(MSG_ERROR, "SCS add request failed for scs_id:%u, "
			   "status:%u", scs_id, status);
		return -EINVAL;
	}

	idx = sta->scs_session_count;

	if (idx >= HOSTAPD_SCS_MAX_DESCRIPTORS_PER_PEER) {
		wpa_printf(MSG_ERROR, "SCS add request failed for scs_id:%u, "
			   "maximum index exceeded", scs_id);
		return -EINVAL;
	}

	scs_req_desc = os_memdup(scs_req_desc_tmp, sizeof(*scs_req_desc_tmp));
	if (!scs_req_desc) {
		wpa_printf(MSG_ERROR, "scs_req mem alloc failure size %zu",
			   sizeof(*scs_req_desc));
		return -ENOMEM;
	}

	/* Attach SCS data to STA node */
	sta->scs_req_desc[idx] = scs_req_desc;
	sta->scs_session_count++;

	hostapd_scs_add_nft_rule(hapd, sta, idx);

	return 0;
}

static int
hostapd_process_scs_remove(struct hostapd_data *hapd, struct sta_info *sta,
			   struct hostapd_scs_req_desc_data *scs_req_desc,
			   u8 status)
{
	u8 scs_session_count = sta->scs_session_count;
	u8 scs_id = scs_req_desc->scs_id;
	int idx;

	if (status != HOSTAPD_QM_STATUS_SUCCESS) {
		wpa_printf(MSG_ERROR, "SCS del request failed for scs_id:%u, "
			   "status:%u - Declined in driver", scs_id, status);
	}

	idx = hostapd_get_scs_index(sta, scs_id);

	if (idx >= HOSTAPD_SCS_MAX_DESCRIPTORS_PER_PEER) {
		wpa_printf(MSG_ERROR, "SCS del request failed for scs_id:%u, "
			   "unable to find idx", scs_id);
		return -EINVAL;
	}

	hostapd_scs_delete_nft_rule(hapd, sta, idx);

	os_free(sta->scs_req_desc[idx]);

	while (idx < (scs_session_count - 1)) {
		sta->scs_req_desc[idx] = sta->scs_req_desc[idx + 1];
		idx++;
	}

	sta->scs_session_count--;
	sta->scs_req_desc[idx] = NULL;

	return 0;
}


static int
hostapd_process_scs_change(struct hostapd_data *hapd, struct sta_info *sta,
			   struct hostapd_scs_req_desc_data *scs_req_desc_tmp,
			   u8 status)
{
	int idx;
	u8 scs_id = scs_req_desc_tmp->scs_id;

	if (status != HOSTAPD_QM_STATUS_SUCCESS) {
		wpa_printf(MSG_ERROR, "SCS update request failed for scs_id:%u,"
			   " status:%u - Old SCS data retained", scs_id,
			   status);
		return -EINVAL;
	}

	idx = hostapd_get_scs_index(sta, scs_id);

	if (idx >= HOSTAPD_SCS_MAX_DESCRIPTORS_PER_PEER) {
		wpa_printf(MSG_ERROR, "SCS update request failed for scs_id:%u,"
			   " unable to find existing idx", scs_id);
		return -EINVAL;
	}

	hostapd_scs_delete_nft_rule(hapd, sta, idx);

	os_memcpy(sta->scs_req_desc[idx], scs_req_desc_tmp,
		  sizeof(*scs_req_desc_tmp));

	hostapd_scs_add_nft_rule(hapd, sta, idx);

	return 0;
}


static void hostapd_process_scs_req(struct hostapd_data *hapd,
				    struct sta_info *sta,
				    struct hostapd_scs_req_data *scs_req,
				    struct hostapd_scs_resp_data *scs_resp)
{
	struct hostapd_scs_resp_desc_data *scs_resp_desc;
	u8 scs_id_req, scs_id_resp, request_type, status;
	struct hostapd_scs_req_desc_data *scs_req_desc;
	int idx, idx1, scs_req_idx;
	bool idx_found;
	int ret;

	for (idx = 0; idx < scs_resp->num_scs_desc; idx++) {
		scs_resp_desc = &scs_resp->scs_resp_desc[idx];
		scs_id_resp = scs_resp_desc->scs_id;
		status = scs_resp_desc->status;

		/* Loop through SCS req desc to matching SCS ID */
		idx_found = false;
		for (idx1 = 0; idx1 < scs_req->num_scs_desc; idx1++) {
			scs_id_req = scs_req->scs_req_desc[idx1].scs_id;
			if (scs_id_resp == scs_id_req) {
				scs_req_idx = idx1;
				idx_found = true;
				break;
			}
		}

		if (idx_found != true) {
			scs_resp_desc->status = WLAN_STATUS_REQUEST_DECLINED;
			continue;
		}

		scs_req_desc = &scs_req->scs_req_desc[scs_req_idx];
		request_type = scs_req_desc->request_type;

		switch (request_type) {
		case QM_ADD_REQ:
			ret = hostapd_process_scs_add(hapd, sta, scs_req_desc,
						      status);
			if (!ret)
				scs_resp_desc->status = WLAN_STATUS_SUCCESS;
			else
				scs_resp_desc->status =
					WLAN_STATUS_REQUEST_DECLINED;

			break;

		case QM_REMOVE_REQ:
			ret = hostapd_process_scs_remove(hapd, sta, scs_req_desc,
							 status);
			if (!ret)
				scs_resp_desc->status =
					WLAN_STATUS_TCLAS_PROCESSING_TERMINATED;
			else
				scs_resp_desc->status =
					WLAN_STATUS_REQUEST_DECLINED;

			break;

		case QM_CHANGE_REQ:
			ret = hostapd_process_scs_change(hapd, sta, scs_req_desc,
							 status);
			if (!ret)
				scs_resp_desc->status = WLAN_STATUS_SUCCESS;
			else
				scs_resp_desc->status =
					WLAN_STATUS_REQUEST_DECLINED;

			break;

		default:
			wpa_printf(MSG_ERROR, "Invalid request type");
			scs_resp_desc->status = WLAN_STATUS_REQUEST_DECLINED;
		}

	}
}


static void hostapd_update_scs_resp_err(struct hostapd_scs_req_data *scs_req,
					struct hostapd_scs_resp_data *scs_resp)
{
	struct hostapd_scs_req_desc_data *scs_req_desc;
	struct hostapd_scs_resp_desc_data *scs_resp_desc;
	int idx;

	scs_resp->dialog_token = scs_req->dialog_token;
	scs_resp->num_scs_desc = scs_req->num_scs_desc;

	for (idx = 0; idx < scs_resp->num_scs_desc; idx++) {
		scs_req_desc = &scs_req->scs_req_desc[idx];
		scs_resp_desc = &scs_resp->scs_resp_desc[idx];

		scs_resp_desc->scs_id = scs_req_desc->scs_id;
		scs_resp_desc->status = WLAN_STATUS_REQUEST_DECLINED;
	}
}


static int hostapd_send_scs_response(struct hostapd_data *hapd,
				     struct sta_info *sta, const u8 *da,
				     struct hostapd_scs_resp_data *scs_resp)
{
	u8 scs_id, dialog_token, num_scs_desc, status;
	size_t len, scs_resp_len;
	struct wpabuf *buf;
	int idx = 0;
	int ret = 0;

	dialog_token = scs_resp->dialog_token;
	num_scs_desc = scs_resp->num_scs_desc;

	/* SCS ID (1), Status code (1) and padding (1) per descriptor */
	scs_resp_len = 3 * num_scs_desc;

	/* Header len and SCS response len */
	len = 16 + scs_resp_len;
	buf = wpabuf_alloc(len);
	if (!buf)
		return -1;

	wpabuf_put_u8(buf, WLAN_ACTION_ROBUST_AV_STREAMING);
	wpabuf_put_u8(buf, ROBUST_AV_SCS_RESP);
	wpabuf_put_u8(buf, dialog_token);
	wpabuf_put_u8(buf, num_scs_desc);

	while ((num_scs_desc) &&
	       (idx < HOSTAPD_SCS_MAX_DESCPRIPTORS_PER_REQUEST)) {
		scs_id = scs_resp->scs_resp_desc[idx].scs_id;
		wpabuf_put_u8(buf, scs_id);
		status = scs_resp->scs_resp_desc[idx].status;
		wpabuf_put_u8(buf, status);
		wpabuf_put_u8(buf, 0x00);
		num_scs_desc--;
		idx++;
	}

	len = wpabuf_len(buf);
	if (hostapd_drv_send_action(hapd, hapd->iface->freq, 0, da,
				    wpabuf_head(buf), len)) {
		wpa_printf(MSG_ERROR, "SCS response send action failed");
		ret = -1;
		goto error;
	}

	wpa_printf(MSG_DEBUG, "Successfully sent SCS response frame");

error:
	wpabuf_free(buf);
	return ret;
}

static int hostapd_copy_and_send_mscs_data(struct hostapd_data *hapd,
		struct sta_info *sta, u8 req_type, const u8 dialog_token)
{
	struct qm_req_data qm_req = {0};
	struct qm_resp_data qm_resp = {0};
	struct qm_req_desc_data qm_desc_data = {0};

	if (!hapd->driver)
		return HOSTAPD_QM_STATUS_E_INVAL;

	os_memcpy(qm_req.peer_mac, sta->addr, ETH_ALEN);

	qm_req.qm_type = HOSTAPD_QM_TYPE_MSCS;
	qm_req.dialog_token = dialog_token;
	qm_req.num_qm_desc = 1;

	qm_desc_data.qm_id = HOSTAPD_QM_DEFAULT_QM_ID;
	qm_desc_data.request_type = req_type;
	qm_desc_data.user_priority_bitmap = sta->mscs_ctxt->user_priority_bitmap;
	qm_desc_data.user_priority_limit = sta->mscs_ctxt->user_priority_limit;
	qm_desc_data.tclas_mask = sta->mscs_ctxt->tclas_mask;

	/* Support added to parse one MSCS descriptor
	 * per MSCS request
	 */
	qm_req.qm_req_desc[0] = qm_desc_data;
	wpa_printf(MSG_DEBUG,
		   "MSCS: mscs info qm_type 0x%x dialog_token 0x%x num_desc 0x%x\n",
		   qm_req.qm_type,
		   qm_req.dialog_token,
		   qm_req.num_qm_desc);

	wpa_printf(MSG_DEBUG,
		   "MSCS: mscs info params req %x bmap 0x%x limit 0x%x mask 0x%x\n",
		   req_type, qm_desc_data.user_priority_bitmap,
		   qm_desc_data.user_priority_limit, qm_desc_data.tclas_mask);

	return hostapd_drv_set_qos(hapd, &qm_req, &qm_resp);
}

static const u8 *hostapd_parse_mscs_desc(const u8 *payload,
		struct hostapd_mscs_desc *mscs)
{
	u8 elem_id, elem_id_ext, length;

	if (!payload || !mscs)
	    return NULL;

	elem_id = *payload++;

	if (elem_id != WLAN_EID_EXTENSION)
		return NULL;

	length = *payload++;

	if (length < IEEE80211_MSCS_DESC_MIN_LEN)
		return NULL;

	elem_id_ext = *payload++;
	if (elem_id_ext != WLAN_EID_EXT_MSCS_DESCRIPTOR) {
		wpa_printf(MSG_ERROR,
			   "MSCS:mscs elem %d is not available in this frame !!!\n",
			   WLAN_EID_EXT_MSCS_DESCRIPTOR);
		return NULL;
	}

	mscs->req_type = *payload++;
	mscs->user_priority_control.user_priority_bitmap = *payload++;
	mscs->user_priority_control.user_priority_limit = *payload++;
	os_memcpy(&mscs->stream_timeout, payload, sizeof(uint32_t));
	payload += sizeof(uint32_t);
	mscs->tclas_mask_elem.id = *payload++;
	mscs->tclas_mask_elem.ie_len = *payload++;

	wpa_printf(MSG_DEBUG, "%s:MSCS descriptors parsed successfully\n", __func__);
	return payload;

}

static const u8 *hostapd_parse_tclas_mask(const u8 *payload,
		struct hostapd_mscs_desc *mscs)
{
	if (!payload || !mscs)
		return NULL;

	mscs->tclas_mask_elem.id_ext = *payload++;
	mscs->tclas_mask_elem.classifier_type = *payload++;
	mscs->tclas_mask_elem.classifier_mask = *payload++;

	return payload;

}

static int hostapd_process_mscs_req(struct hostapd_data *hapd,
		struct sta_info *sta, const u8 *payload,
		struct hostapd_mscs_desc *mscs_desc, const u8 dialog_token)
{
	int ret = HOSTAPD_QM_STATUS_SUCCESS;
	int req_type = mscs_desc->req_type;

	if (req_type != QM_ADD_REQ && !sta->mscs_session_exists) {
		wpa_printf(MSG_ERROR, "MSCS: Session is inactive\n");
		goto decline;
	}

	if (req_type == QM_ADD_REQ && sta->mscs_session_exists) {
		wpa_printf(MSG_ERROR, "MSCS: Session already active\n");
		goto decline;
	}

	payload = hostapd_parse_tclas_mask(payload, mscs_desc);

	if (req_type != QM_REMOVE_REQ &&
		mscs_desc->tclas_mask_elem.id_ext != WLAN_EID_EXT_TCLAS_MASK) {
		wpa_printf(MSG_ERROR, "MSCS: TCLAS mask absent\n");
		goto decline;
	}

	/* Allocate MSCS context if request is ADD */
	if (req_type == QM_ADD_REQ) {
		sta->mscs_ctxt =
			(struct hostapd_mscs_ctxt *)os_zalloc(
					sizeof(struct hostapd_mscs_ctxt));
		if (!sta->mscs_ctxt)
		    goto decline;
	}

	switch (req_type) {
	case QM_ADD_REQ:
	case QM_CHANGE_REQ:
		sta->mscs_ctxt->user_priority_bitmap =
			mscs_desc->user_priority_control.user_priority_bitmap;
		sta->mscs_ctxt->user_priority_limit =
			mscs_desc->user_priority_control.user_priority_limit;
		sta->mscs_ctxt->tclas_mask =
			mscs_desc->tclas_mask_elem.classifier_mask;
		ret = hostapd_copy_and_send_mscs_data(hapd, sta, req_type,
			dialog_token);
		/**
		 * Set mscs session exists to true if
		 * driver returns SUCCESS.
		 * In case of CHANGE_REQ, the session
		 * would be present already, so it
		 * is okay to re-write it here.
		 * If drv returns an ADD failure, delete the
		 * context.
		 */
		if (ret == HOSTAPD_QM_STATUS_SUCCESS)
			sta->mscs_session_exists = true;
		else if (req_type == QM_ADD_REQ) {
			if (!sta->mscs_ctxt)
				goto decline;
			os_free(sta->mscs_ctxt);
			sta->mscs_ctxt = NULL;
		}
		break;
	case QM_REMOVE_REQ:
		if (!sta->mscs_ctxt)
		    goto decline;
		ret = hostapd_copy_and_send_mscs_data(hapd, sta, req_type,
						      dialog_token);
		sta->mscs_session_exists = false;
		os_free(sta->mscs_ctxt);
		sta->mscs_ctxt = NULL;
		ret = WLAN_STATUS_TCLAS_PROCESSING_TERMINATED;
		break;
	default:
		goto decline;
	}
	return ret;

decline:
	wpa_printf(MSG_ERROR, "MSCS: Decline Request %d", req_type);
	return HOSTAPD_QM_STATUS_DECLINED;
}

static int hostapd_send_mscs_response(struct hostapd_data *hapd,
		struct sta_info *sta, const u8 *da, u8 dialog_token, int status_code)
{
	struct wpabuf *buf;
	size_t len;

	/** exact needed size:
	 *  Action frm header (3 bytes) +
	 *  Status code (2 bytes) +
	 *  MSCS descriptor
	 **/
	len = 5 + sizeof(struct hostapd_mscs_desc);
	buf = wpabuf_alloc(len);
	if (!buf) {
		wpa_printf(MSG_ERROR, "Failed to allocate buffer for MSCS response");
		return -1;
	}

	wpabuf_put_u8(buf, WLAN_ACTION_ROBUST_AV_STREAMING);
	wpabuf_put_u8(buf, ROBUST_AV_MSCS_RESP);
	wpabuf_put_u8(buf, dialog_token);
	wpabuf_put_u8(buf, LOW_BYTE(status_code));
	wpabuf_put_u8(buf, HIGH_BYTE(status_code));

	len = wpabuf_len(buf);
	if (hostapd_drv_send_action(hapd, hapd->iface->freq, 0, da,
				    wpabuf_head(buf), len)) {
		wpa_printf(MSG_ERROR, "MSCS response send action failed");
		wpabuf_free(buf);
		return -1;
	}

	wpa_printf(MSG_INFO, "Successfully sent MSCS response frame len %d\n",
		   (int)len);
	wpabuf_free(buf);
	return 0;
}

static int hostapd_handle_mscs_req(struct hostapd_data *hapd,
		const u8 *buf, size_t frame_length)
{
	const struct ieee80211_mgmt *mgmt = (const struct ieee80211_mgmt *) buf;
	struct hostapd_mscs_desc mscs = {0};
	struct sta_info *sta;
	const u8 *payload, *payload_start;
	int ret = 0;
	u8 dialog_token;

	if (!hapd->conf->mscs) {
		wpa_printf(MSG_ERROR, "MSCS feature not enabled");
		return -1;
	}

	sta = ap_get_sta(hapd, mgmt->sa);
	if (!sta) {
		wpa_printf(MSG_ERROR, "%s: STA not found", __func__);
		return -1;
	}

	dialog_token = mgmt->u.action.u.robust_av_req.dialog_token;
	payload_start = mgmt->u.action.u.robust_av_req.variable;

	wpa_hexdump(MSG_DEBUG, "MSCS Request", payload_start, frame_length);
	wpa_printf(MSG_DEBUG, "frame_len:%zu", frame_length);

	payload = hostapd_parse_mscs_desc(payload_start, &mscs);
	if (!payload)
		return -1;

	ret = hostapd_process_mscs_req(hapd, sta, payload, &mscs, dialog_token);

	return hostapd_send_mscs_response(hapd, sta, mgmt->sa, dialog_token,
					  ret);
}

static int hostapd_handle_scs_req(struct hostapd_data *hapd, const u8 *buf,
				  size_t frame_length)
{
	const struct ieee80211_mgmt *mgmt = (const struct ieee80211_mgmt *) buf;
	struct hostapd_scs_resp_data scs_resp = {0};
	struct hostapd_scs_req_data scs_req = {0};
	const u8 *payload, *payload_start;
	struct sta_info *sta;
	u8 elem_id, elem_len;
	u8 index = 0;
	int ret = 0;
	u8 scs_id;

	if (!hapd->conf->scs) {
		wpa_printf(MSG_ERROR, "SCS feature not enabled");
		return -1;
	}

	sta = ap_get_sta(hapd, mgmt->sa);
	if (!sta) {
		wpa_printf(MSG_ERROR, "STA not found in scs_req handler");
		return -1;
	}

	os_memcpy(scs_req.peer_mac, mgmt->sa, ETH_ALEN);

	scs_req.dialog_token = mgmt->u.action.u.robust_av_req.dialog_token;
	payload_start = mgmt->u.action.u.robust_av_req.variable;

	while (frame_length > 0) {
		payload = payload_start;
		elem_id = *payload++;

		if (elem_id != WLAN_EID_SCS_DESCRIPTOR)
			break;

		if (index >= HOSTAPD_SCS_MAX_DESCPRIPTORS_PER_REQUEST) {
			wpa_printf(MSG_ERROR, "SCS Request: Max descriptors "
				   "per request exceeded");
			break;
		}

		elem_len = *payload++;
		scs_id = *payload;

		ret = hostapd_parse_scs_desc(hapd, payload, sta,
					     &scs_req.scs_req_desc[index],
					     elem_len);
		if (ret != HOSTAPD_QM_STATUS_SUCCESS) {
			wpa_printf(MSG_ERROR, "Parsing failure: ID:%d, "
				   "Index:%d, status:%d", scs_id, index, ret);
			return ret;
		}

		payload_start += (elem_len + 2);
		frame_length -= (elem_len + 2);

		index++;
	}

	scs_req.num_scs_desc = index;

	ret = hostapd_copy_and_send_scs_data(hapd, sta, &scs_req, &scs_resp);
	if (ret) {
		wpa_printf(MSG_ERROR, "Send SCS data failed, ret:%d", ret);
		hostapd_update_scs_resp_err(&scs_req, &scs_resp);
		goto send_error_resp;
	}

	hostapd_process_scs_req(hapd, sta, &scs_req, &scs_resp);

send_error_resp:
	ret = hostapd_send_scs_response(hapd, sta, mgmt->sa, &scs_resp);
	if (ret)
		wpa_printf(MSG_ERROR, "SCS response frame send failed, ret:%d",
			   ret);

	return ret;
}

void
hostapd_handle_robust_av(struct hostapd_data *hapd, const u8 *buf, size_t len)
{
	const struct ieee80211_mgmt *mgmt = (const struct ieee80211_mgmt *) buf;

	if (len < IEEE80211_HDRLEN + 3) {
		wpa_printf(MSG_ERROR, "Robust AV frame length error - len %zu",
			   len);
		return;
	}

	switch (mgmt->u.action.u.robust_av_req.action) {
	case ROBUST_AV_SCS_REQ:
		if (hostapd_handle_scs_req(hapd, buf, len))
			wpa_printf(MSG_ERROR, "SCS Request handling failed");
		break;
	case ROBUST_AV_MSCS_REQ:
		if (hostapd_handle_mscs_req(hapd, buf, len))
			wpa_printf(MSG_ERROR, "MSCS Request handling failed");
		break;
	default:
		break;
	}
}
#endif
