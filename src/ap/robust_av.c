/*
 * SPDX-License-Identifier: ISC
 */

#include "utils/includes.h"
#include "utils/common.h"
#include "common/ieee802_11_defs.h"
#include "common/ieee802_11_common.h"
#include "hostapd.h"
#include "robust_av.h"
#include "sta_info.h"
#include "ap_drv_ops.h"
#include <linux/netfilter.h>

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

static void hostapd_qm_prepare_nft_rule(struct hostapd_data *hapd,
					struct sta_info *sta,
					struct hostapd_tclas_elements *te,
					struct hostapd_nft_rule_params *rule,
					u8 qm_id, u8 qm_tag)
{
	struct hostapd_tclas4_params *type4_params = &te->tclas_elem.type4_params;
	struct hostapd_tclas10_params *type10_params = &te->tclas_elem.type10_params;

	if (te->classifier_type == QM_TCLAS_CLASSIFIER_TYPE4) {
		if (type4_params->classifier_mask & BIT(0)) {
			rule->ip_family = type4_params->ip_ver;
		}

		if (type4_params->classifier_mask & BIT(1)) {
			if (rule->ip_family == 4) {
				os_memcpy(&rule->saddr4,
					  type4_params->src_ip.ipv4,
					  IPV4_LEN);
				htonl(rule->saddr4);
			} else {
				os_memcpy(rule->saddr6,
					  type4_params->src_ip.ipv6,
					  IPV6_LEN);
			}
			rule->valid_flags |= NFT_RULE_PARAM_SADDR;
		}

		if (type4_params->classifier_mask & BIT(2)) {
			if (rule->ip_family == 4) {
				os_memcpy(&rule->daddr4,
					  type4_params->dst_ip.ipv4,
					  IPV4_LEN);
				htonl(rule->daddr4);
			} else {
				os_memcpy(rule->daddr6,
					  type4_params->dst_ip.ipv6,
					  IPV6_LEN);
			}
			rule->valid_flags |= NFT_RULE_PARAM_DADDR;
		}

		if (type4_params->classifier_mask & BIT(3)) {
			rule->sport = type4_params->src_port;
			rule->valid_flags |= NFT_RULE_PARAM_SPORT;
		}

		if (type4_params->classifier_mask & BIT(4)) {
			rule->dport = type4_params->dst_port;
			rule->valid_flags |= NFT_RULE_PARAM_DPORT;
		}

		if (type4_params->classifier_mask & BIT(6)) {
			if (rule->ip_family == 4) {
				rule->proto = type4_params->protocol;
			} else {
				rule->proto = type4_params->next_header;
			}
			rule->valid_flags |= NFT_RULE_PARAM_PROTO;
		}

		if (te->tclas_elem.type4_params.classifier_mask & BIT(5)) {
			rule->dscp = type4_params->dscp;
			rule->valid_flags |= NFT_RULE_PARAM_DSCP;
		}

		wpa_printf(MSG_INFO, "qm_id : %d classifier_type : 0x%x classifier_mask : 0x%x\n",
			   qm_id, te->classifier_type, type4_params->classifier_mask);

	} else if (te->classifier_type == QM_TCLAS_CLASSIFIER_TYPE10) {

		rule->valid_flags |= NFT_RULE_PARAM_PROTO;
		rule->proto = type10_params->protocol_number;

		if (rule->proto == IPPROTO_UDP) {
			rule->valid_flags |= NFT_RULE_PARAM_DPORT;
			rule->dport = 4500;
		}

		if (type10_params->filter_len == 4) {
			rule->esp_spi =  ((type10_params->filter_value[0] &
					  type10_params->filter_mask[0]) << 24) | \
					  ((type10_params->filter_value[1] &
					  type10_params->filter_mask[1]) << 16) | \
					  ((type10_params->filter_value[2] &
					  type10_params->filter_mask[2]) << 8)  | \
					  ((type10_params->filter_value[3] &
					  type10_params->filter_mask[3]) << 0);
		} else if (type10_params->filter_len == 12) {
			rule->esp_spi =  ((type10_params->filter_value[8]  &
					  type10_params->filter_mask[8]) << 24) | \
					  ((type10_params->filter_value[9] &
					  type10_params->filter_mask[9]) << 16) | \
					  ((type10_params->filter_value[10] &
					  type10_params->filter_mask[10]) << 8)  | \
					  ((type10_params->filter_value[11] &
					  type10_params->filter_mask[11]) << 0);
		}
	}

	memcpy(rule->dmac, sta->addr, ETH_ALEN);
	rule->valid_flags |= NFT_RULE_PARAM_DMAC;
	rule->mark = (qm_id << 8) | qm_tag;
	os_snprintf(rule->chain, sizeof(rule->chain), "%s_%s", CHAIN_NAME,
		    hapd->conf->iface);
	os_snprintf(rule->table, sizeof(rule->table), "%s", TABLE_NAME);
	rule->nf_family = NFPROTO_NETDEV;
}

static bool hostapd_mscs_flow_exists(struct hostapd_data *hapd,
				     struct sta_info *sta,
				     struct hostapd_tclas_elements *new_te)
{
	struct hostapd_tclas_elements te = {0};
	int idx;

	if (!sta || !sta->mscs_ctxt)
		return false;

	for (idx = 0; idx < sta->mscs_ctxt->available_idx; idx++) {
	     te = sta->mscs_ctxt->flow_info[idx];
	     if (!os_memcmp(new_te, &te, sizeof(struct hostapd_tclas_elements)))
		 return true;
	}

	return false;
}

static int hostapd_mscs_add_flow_info(struct sta_info *sta,
				      struct hostapd_tclas_elements *new_te)
{
	u8 available_idx;

	if (!sta)
		return -EINVAL;

	if (!sta->mscs_ctxt)
		return -EINVAL;

	available_idx = sta->mscs_ctxt->available_idx;

	if (available_idx >= HOSTAPD_MSCS_MAX_FLOW_ENTRIES)
	    return -EINVAL;

	os_memcpy(&sta->mscs_ctxt->flow_info[available_idx], new_te,
		  sizeof(struct hostapd_tclas_elements));
	sta->mscs_ctxt->available_idx++;

	return 0;
}

static int hostapd_mscs_add_nft_rule(struct hostapd_data *hapd,
				     struct sta_info *sta,
				     struct hostapd_tclas_elements *te)
{
	struct hostapd_nft_rule_params rule = {0};
	u8 tid = te->up;

	if (!sta || !sta->mscs_ctxt) {
		wpa_printf(MSG_ERROR, "MSCS: Missing context for STA");
		return -EINVAL;
	}

	if (hostapd_mscs_flow_exists(hapd, sta, te))
	    return -EEXIST;

	if (hostapd_mscs_add_flow_info(sta, te)) {
		wpa_printf(MSG_ERROR, "MSCS: Rule could not be programmed\n");
		return -EINVAL;
	}

	os_memset(&rule, 0, sizeof(rule));

	hostapd_qm_prepare_nft_rule(hapd, sta, te, &rule,
				    tid, HOSTAPD_QOS_MSCS_TAG);

	hostapd_ucode_config_nft_rule(hapd, &rule, true);

	wpa_printf(MSG_INFO, "tid:%u rule valid flag : 0x%x ", tid,
		   rule.valid_flags);

	return 0;
}

int hostapd_mscs_delete_all_rules(struct hostapd_data *hapd,
				       struct sta_info *sta)
{
	struct hostapd_tclas_elements te;
	struct hostapd_nft_rule_params rule = {0};
	int i = 0;

	if (!sta || !sta->mscs_ctxt)
	    return -EINVAL;

	for (i = 0; i < sta->mscs_ctxt->available_idx; i++) {

		te = sta->mscs_ctxt->flow_info[i];

		hostapd_qm_prepare_nft_rule(hapd, sta, &te, &rule,
					    te.up, HOSTAPD_QOS_MSCS_TAG);

		hostapd_ucode_config_nft_rule(hapd, &rule, false);
		os_memset(&sta->mscs_ctxt->flow_info[i], 0,
			  sizeof(struct hostapd_tclas_elements));
	}

	wpa_printf(MSG_INFO, "MSCS: # of rules deleted %u\n", i);

	return 0;
}

static int hostapd_scs_add_nft_rule(struct hostapd_data *hapd,
				    struct sta_info *sta, int scs_idx)
{
	struct hostapd_scs_req_desc_data *scs_req_desc = sta->scs_req_desc[scs_idx];
	struct hostapd_tclas_elements te;
	int i = 0;

	struct hostapd_nft_rule_params rule = {0};

	for (i = 0; i < scs_req_desc->num_tclas_elements; i++) {

		te = scs_req_desc->tclas[i];

		hostapd_qm_prepare_nft_rule(hapd, sta, &te, &rule,
					    scs_req_desc->scs_id,
					    HOSTAPD_QOS_SCS_TAG);

		if (scs_req_desc->tclas_processing != 0) {
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

			os_memset(&rule, 0, sizeof(rule));
		}

		wpa_printf(MSG_INFO, "scs_id:%u rule valid flag : 0x%x ",
			   scs_req_desc->scs_id, rule.valid_flags);
	}

	if (scs_req_desc->tclas_processing == 0) {
		if ((rule.valid_flags & NFT_RULE_PARAM_DPORT ||
		    rule.valid_flags & NFT_RULE_PARAM_SPORT) &&
		    !(rule.valid_flags & NFT_RULE_PARAM_PROTO)) {

			rule.valid_flags |= NFT_RULE_PARAM_PROTO;

			rule.proto = IPPROTO_UDP;
			hostapd_ucode_config_nft_rule(hapd, &rule, true);

			rule.proto = IPPROTO_TCP;
		} else if (!rule.ip_family) {
			rule.ip_family = 4;
			hostapd_ucode_config_nft_rule(hapd, &rule, true);
			rule.ip_family = 6;
		}

		hostapd_ucode_config_nft_rule(hapd, &rule, true);

		wpa_printf(MSG_INFO, "scs_id:%u rule valid flag : 0x%x ",
			   scs_req_desc->scs_id, rule.valid_flags);
	}
	return 0;
}

static int hostapd_scs_delete_nft_rule(struct hostapd_data *hapd,
				       struct sta_info *sta, int scs_idx)
{
	struct hostapd_scs_req_desc_data *scs_data;
	struct hostapd_tclas_elements te;
	struct hostapd_nft_rule_params rule = {0};
	int i = 0;

	scs_data = sta->scs_req_desc[scs_idx];

	for (i = 0; i < scs_data->num_tclas_elements; i++) {

		te = scs_data->tclas[i];

		hostapd_qm_prepare_nft_rule(hapd, sta, &te, &rule,
					    scs_data->scs_id,
					    HOSTAPD_QOS_SCS_TAG);

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
		hostapd_mscs_delete_all_rules(hapd, sta);
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

u8 hostapd_mscs_get_tid(struct hostapd_data *hapd, struct sta_info *sta, u8 tid)
{
	u8 up_bitmap, up_limit;

	if (!sta || !sta->mscs_ctxt) {
		wpa_printf(MSG_DEBUG, "MSCS: MSCS ctxt missing for" MACSTR "sta",
			   MAC2STR(sta->addr));
		return 0;
	}

	up_bitmap = sta->mscs_ctxt->user_priority_bitmap;
	up_limit = sta->mscs_ctxt->user_priority_limit;
	if (BIT(tid) & up_bitmap) {
		if (up_limit < tid)
			return up_limit;
		else
			return tid;
	}

	return 0;
}

void hostapd_process_mscs_flow(struct hostapd_data *hapd,
			       struct hostapd_tclas_elements *te,
			       u8 *addr, u8 tid)
{
	struct sta_info *sta;

	wpa_printf(MSG_DEBUG, "MSCS: Qos Flow received for " MACSTR " from driver"
		   , MAC2STR(addr));

	sta = ap_get_sta(hapd, addr);

	if (!sta) {
		os_free(addr);
		return;
	}

	if (!hapd->conf->mscs) {
		os_free(addr);
		return;
	}

	tid = hostapd_mscs_get_tid(hapd, sta, tid);
	te->classifier_type = QM_TCLAS_CLASSIFIER_TYPE4;
	te->tclas_elem.type4_params.classifier_mask = sta->mscs_ctxt->tclas_mask;
	te->up = tid;

	hostapd_mscs_add_nft_rule(hapd, sta, te);

	os_free(addr);
	return;
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
