/*
 * IEEE 802.11v WNM related functions and structures
 * Copyright (c) 2011-2012, Qualcomm Atheros, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef WNM_STA_H
#define WNM_STA_H

#define WNM_NEIGHBOR_WIDE_BW_CHAN_LEN 3
#define WNM_NEIGHBOR_UHR_CAPAB_LEN 6
#define WNM_NEIGHBOR_UHR_OPER_LEN 20
#define WNM_NEIGHBOR_SUPP_RATES_MAX 32

struct measurement_pilot {
	u8 measurement_pilot;
	u8 subelem_len;
	u8 subelems[255];
};

struct multiple_bssid {
	u8 max_bssid_indicator;
	u8 subelem_len;
	u8 subelems[255];
};

struct neighbor_report {
	u8 bssid[ETH_ALEN];
	u8 mld_addr[ETH_ALEN];
	u16 mld_links; /* may be zero if no link IDs were specified */
	u32 bssid_info;
	u8 regulatory_class;
	u8 channel_number;
	u8 phy_type;
	u8 wide_bw_chan_width;
	u8 wide_bw_chan_center_seg0;
	u8 wide_bw_chan_center_seg1;
	u8 preference; /* valid if preference_present=1 */
	u16 tsf_offset; /* valid if tsf_present=1 */
	u16 beacon_int; /* valid if tsf_present=1 */
	char country[2]; /* valid if country_present=1 */
	u8 rm_capab[5]; /* valid if rm_capab_present=1 */
	u8 supp_rates_len;
	u8 supp_rates[WNM_NEIGHBOR_SUPP_RATES_MAX];
	u8 uhr_capab_len;
	u8 uhr_capab[WNM_NEIGHBOR_UHR_CAPAB_LEN];
	u8 uhr_oper_len;
	u8 uhr_oper[WNM_NEIGHBOR_UHR_OPER_LEN];
	u16 bearing; /* valid if bearing_present=1 */
	u16 rel_height; /* valid if bearing_present=1 */
	u32 distance; /* valid if bearing_present=1 */
	u64 bss_term_tsf; /* valid if bss_term_present=1 */
	u16 bss_term_dur; /* valid if bss_term_present=1 */
	unsigned int disassoc_imminent:1;
	unsigned int preference_present:1;
	unsigned int tsf_present:1;
	unsigned int country_present:1;
	unsigned int rm_capab_present:1;
	unsigned int wide_bw_chan_present:1;
	unsigned int supp_rates_present:1;
	unsigned int uhr_capab_present:1;
	unsigned int uhr_oper_present:1;
	unsigned int bearing_present:1;
	unsigned int bss_term_present:1;
#ifdef CONFIG_MBO
	unsigned int drv_mbo_reject:1;
#endif /* CONFIG_MBO */

	unsigned int smd_capable:1;
	unsigned int smd_same_domain:1;
	struct measurement_pilot *meas_pilot;
	struct multiple_bssid *mul_bssid;
	int freq;
	u8 smd_id[ETH_ALEN];
	u8 smd_ptk_mode;
};


int ieee802_11_send_wnmsleep_req(struct wpa_supplicant *wpa_s,
				 u8 action, u16 intval, struct wpabuf *tfs_req);
int ieee802_11_send_wnm_tim_bcast_req(struct wpa_supplicant *wpa_s,
				       u8 interval);

/* Standalone WNM TFS Request (IEEE Std 802.11-2024, 9.4.2.78/9.4.2.79, 11.21.12) */

#define WNM_TFS_MAX_RULES        2   /* TFS Request elements per frame */
#define WNM_TFS_MAX_SUBELEMENTS  2   /* TFS subelements per rule */
#define WNM_TFS_MAX_TCLAS        2   /* TCLAS classifiers per subelement */
#define WNM_TFS_MAX_FILTER_LEN   125 /* Type 3 filter value/mask length */

/* One TCLAS classifier (IEEE 802.11-2024, 9.4.2.29). */
struct tfs_tclas {
	u8 type;               /* 1, 3, or 4 */
	u8 user_priority;      /* 0-7 */
	u8 classifier_mask;    /* opaque pass-through; AP/driver-interpreted */

	u8 ip_version;         /* 4 or 6; type == 1 || type == 4 */
	u8 src_ip[16];         /* all-zero = wildcard "match any" */
	u8 dst_ip[16];
	u16 src_port;          /* 0 = wildcard */
	u16 dst_port;
	u8 dscp;               /* type == 4 only, on the wire */
	u8 protocol;           /* IPv4 Protocol, or IPv6 Next Header (type == 4 only) */
	u8 flow_label[3];      /* IPv6 only */

	u16 filter_offset;     /* type == 3 */
	u8 filter_len;
	u8 filter_value[WNM_TFS_MAX_FILTER_LEN];
	u8 filter_mask[WNM_TFS_MAX_FILTER_LEN];
};

/* One TFS subelement (SubElemID=1, Figure 9-544). */
struct tfs_subelement {
	struct tfs_tclas tclas[WNM_TFS_MAX_TCLAS];
	u8 num_tclas;
	u8 tclas_process;      /* wire value: 0=AND, 1=OR (Table 9-210) */
};

/* One TFS Request element (Figure 9-543): one traffic filter set, one TFS ID. */
struct tfs_rule {
	u8 tfs_id;
	u8 delete_rule;        /* TFS Action Code bit 0 (Table 9-262) */
	u8 notify;              /* TFS Action Code bit 1 */
	struct tfs_subelement subelem[WNM_TFS_MAX_SUBELEMENTS];
	u8 num_subelem;
};

/* Sends a TFS Request action frame (Category=10, Action=13); 0 rules cancels all. */
int ieee802_11_send_wnm_tfs_req(struct wpa_supplicant *wpa_s,
				const struct tfs_rule *rules, u8 num_rules);

void ieee802_11_rx_wnm_action(struct wpa_supplicant *wpa_s,
			      const struct ieee80211_mgmt *mgmt, size_t len);

int wnm_send_bss_transition_mgmt_query(struct wpa_supplicant *wpa_s,
				       u8 query_reason,
				       const char *btm_candidates,
				       int cand_list);

int wnm_send_coloc_intf_report(struct wpa_supplicant *wpa_s, u8 dialog_token,
			       const struct wpabuf *elems);
void wnm_set_coloc_intf_elems(struct wpa_supplicant *wpa_s,
			      struct wpabuf *elems);

int wnm_btm_resp_tx_status(struct wpa_supplicant *wpa_s, const u8 *data,
			   size_t data_len);

#ifdef CONFIG_WNM

int wnm_scan_process(struct wpa_supplicant *wpa_s, bool pre_scan_check);
void wnm_clear_coloc_intf_reporting(struct wpa_supplicant *wpa_s);

bool wnm_is_bss_excluded(struct wpa_supplicant *wpa_s, struct wpa_bss *bss);

void wnm_btm_reset(struct wpa_supplicant *wpa_s);

static inline bool wnm_active_bss_trans_mgmt(struct wpa_supplicant *wpa_s)
{
	return !!wpa_s->wnm_dialog_token;
}

#else /* CONFIG_WNM */

static inline int wnm_scan_process(struct wpa_supplicant *wpa_s,
				   int reply_on_fail)
{
	return 0;
}

static inline void wnm_clear_coloc_intf_reporting(struct wpa_supplicant *wpa_s)
{
}

static inline bool
wnm_is_bss_excluded(struct wpa_supplicant *wpa_s, struct wpa_bss *bss)
{
	return false;
}

static inline void wnm_btm_reset(struct wpa_supplicant *wpa_s)
{
}

static inline bool wnm_active_bss_trans_mgmt(struct wpa_supplicant *wpa_s)
{
	return false;
}

#endif /* CONFIG_WNM */

#endif /* WNM_STA_H */
