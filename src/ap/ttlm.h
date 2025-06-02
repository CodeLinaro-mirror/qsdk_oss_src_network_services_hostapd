/*
 * hostapd / Tid-to-link Mapping(TTLM)
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef TTLM_H
#define TTLM_H

#define NUM_MAX_TIDS 8

/**
 * struct tid_to_link_map - TID-to-link mapping params
 * @tid_num: TID number
 * @link_map: TTLM link map for the given TID
 */
struct tid_to_link_map {
	u8 tid;
	u16 link_map;
};

/**
 * enum ttlm_dir - TID-to-link mapping direction
 * @TTLM_DIRECTION_DL: Downlink
 * @TTLM_DIRECTION_UL: Uplink
 * @TTLM_DIRECTION_BIDI: Bidirectional
 * @TTLM_DIRECTION_MAX: Max direction
 * @TTLM_DIRECTION_INVALID: Invalid direction
 */
enum ttlm_dir {
	TTLM_DIRECTION_DL,
	TTLM_DIRECTION_UL,
	TTLM_DIRECTION_BIDI,
	TTLM_DIRECTION_MAX,
	TTLM_DIRECTION_INVALID
};

/**
 * struct ttlm_info - TID-to-Link mapping information for the frames
 * transmitted on the uplink, downlink and bidirectional.
 *
 * @direction:  0 - Downlink, 1 - uplink 2 - Both uplink and downlink
 * @default_link_mapping: value 1 indicates the default TTLM, where all the TIDs
 *                        are mapped to all the links.
 *                        value 0 indicates the preferred TTLM mapping
 * @ieee_link_map_tid: Indicates ieee link id mapping of all the TIDS
 * @link_mapping_size: value 1 indicates the length of Link Mapping Of TIDn
 *                     field is 1 octet, value 0 indicates the length of the
 *                     Link Mapping of TIDn field is 2 octets
 */
struct ttlm_info {
	enum ttlm_dir direction;
	bool default_link_mapping;
	u16 ieee_link_map_tid[NUM_MAX_TIDS];
	u8 link_mapping_size;
};

/**
 * struct ttlm_onging_negotiation_info - Current ongoing TTLM negotiation
 * (information about transmitted TTLM request/response frame)
 *
 * @dialog_token: Save the dialog token used in TTLM request and response frame.
 * @ttlm_info: Provides the TID-to-link mapping info for UL/DL/BiDi
 */
struct ttlm_ongoing_negotiation_info {
	u8 dialog_token;
	struct ttlm_info ttlm_info[TTLM_DIRECTION_MAX];
};

/**
 * struct tid_to_link_map_info - TID-to-link mapping information
 *
 * @dialog_token: self generated dialog token used to send TTLM request
 * frame.
 * @ttlm_ongoing_negotiation_info: This has the ongoing TID-to-link mapping info
 * transmitted by this peer to the connected peer.
 */
struct tid_to_link_map_info {
	u8 dialog_token;
	struct ttlm_ongoing_negotiation_info ttlm_ongoing_negotiation_info;
};

/**
 * struct tid_to_link_mapping_elem - TID-to-link mapping IE
 * @elem_id: TTLM IE
 * @elem_len: TTLM IE len
 * @elem_id_extn: TTLM extension id
 * @data: Variable length data described below
 */
struct tid_to_link_mapping_elem {
	u8 elem_id;
	u8 elem_len;
	u8 elem_id_extn;
	u8 data[];
} STRUCT_PACKED;


int hostapd_send_ttlm_req(struct hostapd_data *hapd,
			  struct ttlm_ongoing_negotiation_info *ttlm_negotiation,
			  struct sta_info *sta);
int hostapd_build_ttlm_elem(struct ttlm_ongoing_negotiation_info *ttlm,
			    u8 **ttlm_elem, size_t *ttlm_elem_len);

#endif /* TTLM_H */
