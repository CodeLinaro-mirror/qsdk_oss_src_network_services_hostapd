/*
 * hostapd / Initialization and configuration
 * Copyright (c) 2002-2014, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef HOSTAPD_H
#define HOSTAPD_H

#ifdef CONFIG_SQLITE
#include <sqlite3.h>
#endif /* CONFIG_SQLITE */

#include "common/defs.h"
#include "common/dpp.h"
#include "utils/list.h"
#include "ap_config.h"
#include "drivers/driver.h"
#include "ubus.h"
#include "ucode.h"
#include "ttlm.h"
#include "atf/atf_offload.h"


#define OCE_STA_CFON_ENABLED(hapd) \
	((hapd->conf->oce & OCE_STA_CFON) && \
	 (hapd->iface->drv_flags & WPA_DRIVER_FLAGS_OCE_STA_CFON))
#define OCE_AP_ENABLED(hapd) \
	((hapd->conf->oce & OCE_AP) && \
	 (hapd->iface->drv_flags & WPA_DRIVER_FLAGS_OCE_AP))

#define TABLE_NAME "wifi_qos_table"
#define CHAIN_NAME "wifi_qos_chain"

struct wpa_ctrl_dst;
struct radius_server_data;
struct upnp_wps_device_sm;
struct hostapd_data;
struct sta_info;
struct ieee80211_ht_capabilities;
struct full_dynamic_vlan;
enum wps_event;
union wps_event_data;
#ifdef CONFIG_MESH
struct mesh_conf;
#endif /* CONFIG_MESH */

#ifdef CONFIG_CTRL_IFACE_UDP
#define CTRL_IFACE_COOKIE_LEN 8
#endif /* CONFIG_CTRL_IFACE_UDP */

struct hostapd_iface;
struct hostapd_mld;

struct hapd_interfaces {
	int (*reload_config)(struct hostapd_iface *iface);
	struct hostapd_config * (*config_read_cb)(const char *config_fname);
	int (*ctrl_iface_init)(struct hostapd_data *hapd);
	void (*ctrl_iface_deinit)(struct hostapd_data *hapd);
	int (*ctrl_iface_recv)(struct hostapd_data *hapd,
			       char *buf, char *reply, int reply_size,
			       struct sockaddr_storage *from,
			       socklen_t fromlen);
	int (*for_each_interface)(struct hapd_interfaces *interfaces,
				  int (*cb)(struct hostapd_iface *iface,
					    void *ctx), void *ctx);
	int (*driver_init)(struct hostapd_iface *iface);

	size_t count;
	int global_ctrl_sock;
	struct dl_list global_ctrl_dst;
	char *global_iface_path;
	char *global_iface_name;
#ifndef CONFIG_NATIVE_WINDOWS
	gid_t ctrl_iface_group;
#endif /* CONFIG_NATIVE_WINDOWS */
	struct hostapd_iface **iface;

	size_t terminate_on_error;
#ifndef CONFIG_NO_VLAN
	struct dynamic_iface *vlan_priv;
#endif /* CONFIG_NO_VLAN */
#ifdef CONFIG_ETH_P_OUI
	struct dl_list eth_p_oui; /* OUI Extended EtherType handlers */
#endif /* CONFIG_ETH_P_OUI */
	int eloop_initialized;

#ifdef CONFIG_DPP
	struct dpp_global *dpp;
#ifdef CONFIG_DPP3
	struct os_reltime dpp_pb_time;
	struct os_reltime dpp_pb_announce_time;
	struct dpp_pb_info dpp_pb[DPP_PB_INFO_COUNT];
	struct dpp_bootstrap_info *dpp_pb_bi;
	u8 dpp_pb_c_nonce[DPP_MAX_NONCE_LEN];
	u8 dpp_pb_resp_hash[SHA256_MAC_LEN];
	struct os_reltime dpp_pb_last_resp;
	bool dpp_pb_result_indicated;
	char *dpp_pb_cmd;
#endif /* CONFIG_DPP3 */
#endif /* CONFIG_DPP */

#ifdef CONFIG_CTRL_IFACE_UDP
       unsigned char ctrl_iface_cookie[CTRL_IFACE_COOKIE_LEN];
#endif /* CONFIG_CTRL_IFACE_UDP */

#ifdef CONFIG_IEEE80211BE
	struct hostapd_mld **mld;
	size_t mld_count;
	int (*mld_ctrl_iface_init)(struct hostapd_mld *mld);
	void (*mld_ctrl_iface_deinit)(struct hostapd_mld *mld);
#endif /* CONFIG_IEEE80211BE */

#ifdef CONFIG_ATF_OFFLOAD
	struct atf_offload atf;
#endif
};

enum hostapd_chan_status {
	HOSTAPD_CHAN_VALID = 0, /* channel is ready */
	HOSTAPD_CHAN_INVALID = 1, /* no usable channel found */
	HOSTAPD_CHAN_ACS = 2, /* ACS work being performed */
	HOSTAPD_CHAN_INVALID_NO_IR = 3, /* channel invalid due to AFC NO IR */
};

struct hostapd_probereq_cb {
	int (*cb)(void *ctx, const u8 *sa, const u8 *da, const u8 *bssid,
		  const u8 *ie, size_t ie_len, int ssi_signal);
	void *ctx;
};

#define HOSTAPD_RATE_BASIC 0x00000001

struct hostapd_rate_data {
	int rate; /* rate in 100 kbps */
	int flags; /* HOSTAPD_RATE_ flags */
};

struct hostapd_frame_info {
	unsigned int freq;
	u32 channel;
	u32 datarate;
	int ssi_signal; /* dBm */
};

enum wps_status {
	WPS_STATUS_SUCCESS = 1,
	WPS_STATUS_FAILURE
};

enum pbc_status {
	WPS_PBC_STATUS_DISABLE,
	WPS_PBC_STATUS_ACTIVE,
	WPS_PBC_STATUS_TIMEOUT,
	WPS_PBC_STATUS_OVERLAP
};

struct wps_stat {
	enum wps_status status;
	enum wps_error_indication failure_reason;
	enum pbc_status pbc_status;
	u8 peer_addr[ETH_ALEN];
};

struct hostapd_neighbor_entry {
	struct dl_list list;
	u8 bssid[ETH_ALEN];
	struct wpa_ssid_value ssid;
	struct wpabuf *nr;
	struct wpabuf *lci;
	struct wpabuf *civic;
	/* LCI update time */
	struct os_time lci_date;
	int stationary;
	u32 short_ssid;
	u8 bss_parameters;
};

struct hostapd_bcn_report_entry {
	struct dl_list list;
	u8 op_class;
	u8 channel;
	u64 start_time;
	u16 duration;
	u8 report_info;
	u8 rcpi;
	u8 rsni;
	u8 bssid[ETH_ALEN];
	u8 antenna_id;
	u32 parent_tsf;
	u8 *subelem;
	size_t subelem_len;
};

struct hostapd_sae_commit_queue {
	struct dl_list list;
	int rssi;
	size_t len;
	u8 msg[];
};

struct mld_link_info {
	u8 valid:1;
	u8 nstr_bitmap_len:2;
	u8 local_addr[ETH_ALEN];
	u8 peer_addr[ETH_ALEN];

	u8 nstr_bitmap[2];

	u16 capability;

	u16 status;
	u16 resp_sta_profile_len;
	u8 *resp_sta_profile;
};

/**
 * struct hostapd_openwrt_stats - OpenWrt custom STA/AP statistics
 */
struct hostapd_openwrt_stats {
	struct {
		u64 neighbor_report_tx;
	} rrm;

	struct {
		u64 bss_transition_query_rx;
		u64 bss_transition_request_tx;
		u64 bss_transition_response_rx;
	} wnm;
};

struct rx_critical_param {
	bool critical_flag;
	u8 bpcc;
	u8 switch_count;
};

/**
 * enum elemid_cu - used for detecting element id modification
 * category 2 critical update
 */
enum elemid_cu {
	ELEMID_CU_PARAM_EXT_EHTOP = 0,
	ELEMID_CU_PARAM_EXT_HEOP,
	ELEMID_CU_PARAM_VHTOP,
	ELEMID_CU_PARAM_HTOP,
	ELEMID_CU_PARAM_WMM,
	ELEMID_CU_PARAM_MU_EDCA,
	ELEMID_CU_PARAM_SPATIAL_REUSE,
	ELEMID_CU_PARAM_EXT_ML,

	ELEMID_CU_PARAM_MAX,
};

struct elemid_cu_param {
	u8 eid_len;
	u32 hash;
};

#define MAX_CHANNEL_USAGE_ELEMENTS 6
#define MAX_CHANNEL_ENTRIES_PER_ELEMENT 10

/**
 * struct channel_usage_entry - Represents a single channel entry in
 * Channel Usage element
 * @op_class: Operating Class of the channel
 * @channel : Channel Number
 */
struct channel_usage_entry {
	u8 op_class;
	u8 channel;
};

/**
 * struct channel_usage_elem - Represents a single Channel Usage element
 * @mode: Mode of operation for this Channel Usage element
 * @num_entries: Number of channel entries for this particular element
 * @entries: Array of channel entries for this element
 */
struct channel_usage_elem {
	u8 mode;
	u8 num_entries;
	struct channel_usage_entry entries[MAX_CHANNEL_ENTRIES_PER_ELEMENT];
};

/**
 * struct channel_usage_config - Represents the list of all Channel
 * Usage elements that have been configured
 * @num_elems: Number of Channel Usage elements configured
 * @elems: Array of Channel Usage elements
 */
struct channel_usage_config {
	u8 num_elems;
	struct channel_usage_elem elems[MAX_CHANNEL_USAGE_ELEMENTS];
};

/**
 * struct hostapd_data - hostapd per-BSS data structure
 */
struct hostapd_data {
	struct hostapd_iface *iface;
	struct hostapd_config *iconf;
	struct hostapd_bss_config *conf;
	struct hostapd_ubus_bss ubus;
	struct hostapd_ucode_bss ucode;
	int interface_added; /* virtual interface added for this BSS */
	unsigned int started:1;
	unsigned int disabled:1;
	unsigned int reenable_beacon:1;

	u8 own_addr[ETH_ALEN];

#ifdef CONFIG_QCN_EXTN
	/* Vendor BSSID derivation bookkeeping for non-MBSSID */
	u8 vendor_bss_index;
	bool vendor_bss_index_valid;
#endif /* CONFIG_QCN_EXTN */

	/* OpenWrt specific statistics */
	struct hostapd_openwrt_stats openwrt_stats;

	int num_sta; /* number of entries in sta_list */
	struct sta_info *sta_list; /* STA info list head */
#define STA_HASH_SIZE 256
#define STA_HASH(sta) (sta[5])
	struct sta_info *sta_hash[STA_HASH_SIZE];

	/*
	 * Bitfield for indicating which AIDs are allocated. Only AID values
	 * 1-2007 are used and as such, the bit at index 1 corresponds to AID
	 * 1.
	 */
#define AID_WORDS ((2008 + 31) / 32)
	u32 sta_aid[AID_WORDS];
	u32 wds_sta_uid[AID_WORDS];

	const struct wpa_driver_ops *driver;
	void *drv_priv;

	void (*new_assoc_sta_cb)(struct hostapd_data *hapd,
				 struct sta_info *sta, int reassoc);

	void *msg_ctx; /* ctx for wpa_msg() calls */
	void *msg_ctx_parent; /* parent interface ctx for wpa_msg() calls */

	int num_rates;
	struct hostapd_rate_data *current_rates;
	int *basic_rates;

	struct radius_client_data *radius;
	u64 acct_session_id;
	struct radius_das_data *radius_das;

	struct hostapd_cached_radius_acl *acl_cache;
	struct hostapd_acl_query_data *acl_queries;

	struct wpa_authenticator *wpa_auth;
	struct eapol_authenticator *eapol_auth;
	struct eap_config *eap_cfg;

	struct rsn_preauth_interface *preauth_iface;
	struct os_reltime michael_mic_failure;
	int michael_mic_failures;
	int tkip_countermeasures;

	int ctrl_sock;
	struct dl_list ctrl_dst;

	void *ssl_ctx;
	void *eap_sim_db_priv;
	struct crypto_rsa_key *imsi_privacy_key;
	struct radius_server_data *radius_srv;
	struct dl_list erp_keys; /* struct eap_server_erp_key */

	int parameter_set_count;

	/* Time Advertisement */
	u8 time_update_counter;
	struct wpabuf *time_adv;

#ifdef CONFIG_FULL_DYNAMIC_VLAN
	struct full_dynamic_vlan *full_dynamic_vlan;
#endif /* CONFIG_FULL_DYNAMIC_VLAN */

	struct l2_packet_data *l2;

#ifdef CONFIG_IEEE80211R_AP
	struct dl_list l2_queue;
	struct dl_list l2_oui_queue;
	struct eth_p_oui_ctx *oui_pull;
	struct eth_p_oui_ctx *oui_resp;
	struct eth_p_oui_ctx *oui_push;
	struct eth_p_oui_ctx *oui_sreq;
	struct eth_p_oui_ctx *oui_sresp;
	struct eth_p_oui_ctx *oui_rnotify;
#endif /* CONFIG_IEEE80211R_AP */

	struct wps_context *wps;

	int beacon_set_done;
	struct wpabuf *wps_beacon_ie;
	struct wpabuf *wps_probe_resp_ie;
	struct wpabuf *plugin_vendor_elements; /* Dynamic vendor IEs set by plugin */
#ifdef CONFIG_WPS
	unsigned int ap_pin_failures;
	unsigned int ap_pin_failures_consecutive;
	struct upnp_wps_device_sm *wps_upnp;
	unsigned int ap_pin_lockout_time;

	struct wps_stat wps_stats;
#endif /* CONFIG_WPS */

#ifdef CONFIG_MACSEC
	struct ieee802_1x_kay *kay;
#endif /* CONFIG_MACSEC */

	struct hostapd_probereq_cb *probereq_cb;
	size_t num_probereq_cb;

	void (*public_action_cb)(void *ctx, const u8 *buf, size_t len,
				 int freq);
	void *public_action_cb_ctx;
	void (*public_action_cb2)(void *ctx, const u8 *buf, size_t len,
				  int freq);
	void *public_action_cb2_ctx;

	int (*vendor_action_cb)(void *ctx, const u8 *buf, size_t len,
				int freq);
	void *vendor_action_cb_ctx;

	void (*wps_reg_success_cb)(void *ctx, const u8 *mac_addr,
				   const u8 *uuid_e);
	void *wps_reg_success_cb_ctx;

	void (*wps_event_cb)(void *ctx, enum wps_event event,
			     union wps_event_data *data);
	void *wps_event_cb_ctx;

	void (*sta_authorized_cb)(void *ctx, const u8 *mac_addr,
				  int authorized, const u8 *p2p_dev_addr,
				  const u8 *ip);
	void *sta_authorized_cb_ctx;

	void (*setup_complete_cb)(void *ctx);
	void *setup_complete_cb_ctx;

	void (*new_psk_cb)(void *ctx, const u8 *mac_addr,
			   const u8 *p2p_dev_addr, const u8 *psk,
			   size_t psk_len);
	void *new_psk_cb_ctx;

	/* channel switch parameters */
	struct hostapd_freq_params cs_freq_params;
	u8 cs_count;
	int cs_block_tx;
	unsigned int cs_c_off_beacon;
	unsigned int cs_c_off_proberesp;
	int csa_in_progress;
	unsigned int cs_c_off_ecsa_beacon;
	unsigned int cs_c_off_ecsa_proberesp;

#ifdef CONFIG_IEEE80211AX
	bool cca_in_progress;
	int no_free_color;
	u8 cca_count;
	u8 cca_color;
	unsigned int cca_c_off_beacon;
	unsigned int cca_c_off_proberesp;
	struct os_reltime first_color_collision;
	struct os_reltime last_color_collision;
	u64 color_collision_bitmap;
#endif /* CONFIG_IEEE80211AX */

#ifdef CONFIG_P2P
	struct p2p_data *p2p;
	struct p2p_group *p2p_group;
	struct wpabuf *p2p_beacon_ie;
	struct wpabuf *p2p_probe_resp_ie;

	/* Number of non-P2P association stations */
	int num_sta_no_p2p;

	/* Periodic NoA (used only when no non-P2P clients in the group) */
	int noa_enabled;
	int noa_start;
	int noa_duration;
#endif /* CONFIG_P2P */
#ifdef CONFIG_PROXYARP
	struct l2_packet_data *sock_dhcp;
	struct l2_packet_data *sock_ndisc;
	bool x_snoop_initialized;
#endif /* CONFIG_PROXYARP */
#ifdef CONFIG_MESH
	int num_plinks;
	int max_plinks;
	void (*mesh_sta_free_cb)(struct hostapd_data *hapd,
				 struct sta_info *sta);
	struct wpabuf *mesh_pending_auth;
	struct os_reltime mesh_pending_auth_time;
	u8 mesh_required_peer[ETH_ALEN];
#endif /* CONFIG_MESH */

#ifdef CONFIG_SQLITE
	struct hostapd_eap_user tmp_eap_user;
#endif /* CONFIG_SQLITE */

#ifdef CONFIG_SAE

#define COMEBACK_KEY_SIZE 8
#define COMEBACK_PENDING_IDX_SIZE 256

	/** Key used for generating SAE anti-clogging tokens */
	u8 comeback_key[COMEBACK_KEY_SIZE];
	struct os_reltime last_comeback_key_update;
	u16 comeback_idx;
	u16 comeback_pending_idx[COMEBACK_PENDING_IDX_SIZE];
	int dot11RSNASAERetransPeriod; /* msec */
	struct dl_list sae_commit_queue; /* struct hostapd_sae_commit_queue */
#endif /* CONFIG_SAE */

#ifdef CONFIG_TESTING_OPTIONS
	unsigned int ext_mgmt_frame_handling:1;
	unsigned int ext_eapol_frame_io:1;

	struct l2_packet_data *l2_test;

	enum wpa_alg last_gtk_alg;
	int last_gtk_key_idx;
	u8 last_gtk[WPA_GTK_MAX_LEN];
	size_t last_gtk_len;

	enum wpa_alg last_igtk_alg;
	int last_igtk_key_idx;
	u8 last_igtk[WPA_IGTK_MAX_LEN];
	size_t last_igtk_len;

	enum wpa_alg last_bigtk_alg;
	int last_bigtk_key_idx;
	u8 last_bigtk[WPA_BIGTK_MAX_LEN];
	size_t last_bigtk_len;

	bool force_backlog_bytes;
#endif /* CONFIG_TESTING_OPTIONS */

#ifdef CONFIG_MBO
	unsigned int mbo_assoc_disallow;
#endif /* CONFIG_MBO */

	struct dl_list nr_db;
	struct dl_list bcn_report_db;

	u8 beacon_req_token;
	u8 lci_req_token;
	u8 range_req_token;
	u8 link_measurement_req_token;
	unsigned int lci_req_active:1;
	unsigned int range_req_active:1;
	unsigned int link_mesr_req_active:1;

	int dhcp_sock; /* UDP socket used with the DHCP server */

	struct ptksa_cache *ptksa;

#ifdef CONFIG_DPP
	int dpp_init_done;
	struct dpp_authentication *dpp_auth;
	u8 dpp_allowed_roles;
	int dpp_qr_mutual;
	int dpp_auth_ok_on_ack;
	bool dpp_wps;
	int dpp_in_response_listen;
	struct gas_query_ap *gas;
	struct dpp_pkex *dpp_pkex;
	struct dpp_bootstrap_info *dpp_pkex_bi;
	char *dpp_pkex_code;
	size_t dpp_pkex_code_len;
	char *dpp_pkex_identifier;
	enum dpp_pkex_ver dpp_pkex_ver;
	char *dpp_pkex_auth_cmd;
	struct os_reltime dpp_last_init;
	struct os_reltime dpp_init_iter_start;
	unsigned int dpp_init_max_tries;
	unsigned int dpp_init_retry_time;
	unsigned int dpp_resp_wait_time;
	unsigned int dpp_resp_max_tries;
	unsigned int dpp_resp_retry_time;
#ifdef CONFIG_DPP2
	struct wpabuf *dpp_presence_announcement;
	struct dpp_bootstrap_info *dpp_chirp_bi;
	int dpp_chirp_freq;
	int *dpp_chirp_freqs;
	int dpp_chirp_iter;
	int dpp_chirp_round;
	int dpp_chirp_scan_done;
	int dpp_chirp_listen;
	struct os_reltime dpp_relay_last_needs_ctrl;
#endif /* CONFIG_DPP2 */
#ifdef CONFIG_TESTING_OPTIONS
	char *dpp_config_obj_override;
	char *dpp_discovery_override;
	char *dpp_groups_override;
	unsigned int dpp_ignore_netaccesskey_mismatch:1;
#endif /* CONFIG_TESTING_OPTIONS */
#endif /* CONFIG_DPP */

#ifdef CONFIG_AIRTIME_POLICY
	unsigned int num_backlogged_sta;
	unsigned int airtime_weight;
#endif /* CONFIG_AIRTIME_POLICY */
#ifdef CONFIG_ATF_OFFLOAD
        bool atf_configured;
#endif

	u8 last_1x_eapol_key_replay_counter[8];

#ifdef CONFIG_SQLITE
	sqlite3 *rad_attr_db;
#endif /* CONFIG_SQLITE */

#ifdef CONFIG_CTRL_IFACE_UDP
       unsigned char ctrl_iface_cookie[CTRL_IFACE_COOKIE_LEN];
#endif /* CONFIG_CTRL_IFACE_UDP */

       struct rx_critical_param rx_cu_param;
       /*Element ID critical update data*/
       struct elemid_cu_param cu_eid[ELEMID_CU_PARAM_MAX];
#ifdef CONFIG_IEEE80211BE
	u8 eht_mld_bss_param_change;
	struct hostapd_mld *mld;
	struct dl_list link;
	u8 mld_link_id;

	/* Cached partner info for ML probe response */
	struct mld_link_info partner_links[MAX_NUM_MLD_LINKS];

	/* 5 characters for "_link", up to 2 characters for <link ID>, so in
	 * total, additional 7 characters required. */
	char ctrl_sock_iface[IFNAMSIZ + 7 + 1];

	u8 eht_mld_link_removal_count;
	u8 eht_mld_link_removal_inprogress;
#endif /* CONFIG_IEEE80211BE */

#ifdef CONFIG_NAN_USD
	struct nan_de *nan_de;
#endif /* CONFIG_NAN_USD */

	u64 scan_cookie; /* Scan instance identifier for the ongoing HT40 scan
			  */
	bool disable_cu;
	struct hostapd_wmm_ac_params prev_wmm[4];
	size_t mbssid_idx;
	struct hostapd_multi_mbssid_group *mbssid_group;
	struct dl_list mbssid_bss;

	u16 mapping_switch_time;
	struct channel_usage_config chan_usage_config;
	void *hostapd_if_data; /* for per-interface/MLD frame_reg_table, opaque */
};


struct hostapd_sta_info {
	struct dl_list list;
	u8 addr[ETH_ALEN];
	struct os_reltime last_seen;
	int ssi_signal;
#ifdef CONFIG_TAXONOMY
	struct wpabuf *probe_ie_taxonomy;
#endif /* CONFIG_TAXONOMY */
};

#ifdef CONFIG_IEEE80211BE

/**
 * struct hostapd_ft_over_ds_ml_sta_entry - ft over ds ml sta structure
 */
struct hostapd_ft_over_ds_ml_sta_entry {
	struct dl_list list;
	u8 mld_mac[ETH_ALEN];
	struct wpa_state_machine *wpa_sm;
	struct wpa_authenticator *wpa_auth;
	struct hostapd_data *hapd;
};

/**
 * struct hostapd_mld - hostapd per-mld data structure
 */
struct hostapd_mld {
	char name[IFNAMSIZ + 1];
	u8 mld_addr[ETH_ALEN];
	u16 free_links;
	u8 num_links;
	/* Number of hostapd_data (hapd) referencing this. num_links cannot be
	 * used since num_links can go to 0 even when a BSS is disabled and
	 * when it is re-enabled, the MLD should exist and hence it cannot be
	 * freed when num_links is 0.
	 */
	u8 refcount;

	struct hostapd_data *fbss;
	struct dl_list links; /* List head of all affiliated links */
	struct dl_list ft_ds_ml_stas;

	int ctrl_sock;
	struct dl_list ctrl_dst;
	char *ctrl_interface; /* Directory for UNIX domain sockets */

#ifdef CONFIG_IEEE80211BE
	struct mac_acl_entry *epcs_authorized_mac;
	int num_epcs_authorized_mac;
#endif /* CONFIG_IEEE80211BE */
	struct ttlm_context ttlm_ctx;
};

#define HOSTAPD_MLD_MAX_REF_COUNT      0xFF
#endif /* CONFIG_IEEE80211BE */


/**
 * enum cac_completion_type - CAC completion context
 * @HAPD_CAC_COMPLETE_AFTER_BSS: CAC completed after a regular BSS
 *                               CAC procedure (non-CSA path).
 * @HAPD_CAC_COMPLETE_AFTER_CSA: CAC completed after CSA
 *                               on a DFS target channel.
 */
enum cac_completion_type {
	HAPD_CAC_COMPLETE_AFTER_BSS = 0,
	HAPD_CAC_COMPLETE_AFTER_CSA = 1,
};

/**
 * struct hostapd_iface - hostapd per-interface data structure
 */
struct hostapd_iface {
	struct hapd_interfaces *interfaces;
	struct hostapd_ucode_iface ucode;
	void *owner;
	char *config_fname;
	struct hostapd_config *conf;
	char phy[16]; /* Name of the PHY (radio) */

	enum hostapd_iface_state {
		HAPD_IFACE_UNINITIALIZED,
		HAPD_IFACE_DISABLED,
		HAPD_IFACE_COUNTRY_UPDATE,
		HAPD_IFACE_ACS,
		HAPD_IFACE_HT_SCAN,
		HAPD_IFACE_DFS,
		HAPD_IFACE_NO_IR,
		HAPD_IFACE_ENABLED
	} state;

#ifdef CONFIG_MESH
	struct mesh_conf *mconf;
#endif /* CONFIG_MESH */

	size_t num_bss;
	struct hostapd_data **bss;

#ifdef CONFIG_QCN_EXTN
	/* Bitmask of used vendor BSSID indices (non-MBSSID) */
	u32 vendor_bssid_used_mask;
#endif /* CONFIG_QCN_EXTN */

	unsigned int wait_channel_update:1;
	unsigned int cac_started:1;
#ifdef CONFIG_FST
	struct fst_iface *fst;
	const struct wpabuf *fst_ies;
#endif /* CONFIG_FST */

	/*
	 * When set, indicates that the driver will handle the AP
	 * teardown: delete global keys, station keys, and stations.
	 */
	unsigned int driver_ap_teardown:1;

	/*
	 * When set, indicates that this interface is part of list of
	 * interfaces that need to be started together (synchronously).
	 */
	unsigned int need_to_start_in_sync:1;

	/* Ready to start but waiting for other interfaces to become ready. */
	unsigned int ready_to_start_in_sync:1;

	int num_ap; /* number of entries in ap_list */
	struct ap_info *ap_list; /* AP info list head */
	struct ap_info *ap_hash[STA_HASH_SIZE];

	u64 drv_flags;
	u64 drv_flags2;
	unsigned int drv_rrm_flags;

	/*
	 * A bitmap of supported protocols for probe response offload. See
	 * struct wpa_driver_capa in driver.h
	 */
	unsigned int probe_resp_offloads;

	/* extended capabilities supported by the driver */
	const u8 *extended_capa, *extended_capa_mask;
	unsigned int extended_capa_len;

	u16 mld_eml_capa, mld_mld_capa, mld_ext_mld_capa;

	unsigned int drv_max_acl_mac_addrs;

	struct hostapd_hw_modes *hw_features;
	int num_hw_features;
	struct hostapd_hw_modes *current_mode;
	int freq;

	bool radar_detected;
	enum cac_completion_type cac_type;

	/* Background radar configuration */
	struct {
		int channel;
		int secondary_channel;
		int freq;
		int centr_freq_seg0_idx;
		int centr_freq_seg1_idx;
		/* Main chain is on temporary channel during
		 * CAC detection on radar offchain.
		 */
		unsigned int temp_ch:1;
		/* CAC started on radar offchain */
		unsigned int cac_started:1;
	} radar_background;

	u16 hw_flags;

	/* Number of associated Non-ERP stations (i.e., stations using 802.11b
	 * in 802.11g BSS) */
	int num_sta_non_erp;

	/* Number of associated stations that do not support Short Slot Time */
	int num_sta_no_short_slot_time;

	/* Number of associated stations that do not support Short Preamble */
	int num_sta_no_short_preamble;

	int olbc; /* Overlapping Legacy BSS Condition */

	/* Number of HT associated stations that do not support greenfield */
	int num_sta_ht_no_gf;

	/* Number of associated non-HT stations */
	int num_sta_no_ht;

	/* Number of HT associated stations 20 MHz */
	int num_sta_ht_20mhz;

	/* Number of HT40 intolerant stations */
	int num_sta_ht40_intolerant;

	/* Overlapping BSS information */
	int olbc_ht;

	u16 ht_op_mode;

	/* surveying helpers */

	/* number of channels surveyed */
	unsigned int chans_surveyed;

	/* lowest observed noise floor in dBm */
	s8 lowest_nf;

	/*
	 * User configured 6 GHz power mode
	 *
	 * No power mode change - -1
	 * Low power Indoor AP  -  0
	 * Standard power AP    -  1
	 * Very low power AP    -  2
	 *
	 */
	int power_mode_6ghz_before_change;

	/* channel utilization calculation */
	u64 last_channel_time;
	u64 last_channel_time_busy;
	u8 channel_utilization;

	unsigned int chan_util_samples_sum;
	unsigned int chan_util_num_sample_periods;
	unsigned int chan_util_average;

	/* eCSA IE will be added only if operating class is specified */
	u8 cs_oper_class;

	unsigned int dfs_cac_ms;
	struct os_reltime dfs_cac_start;

	/* Latched with the actual secondary channel information and will be
	 * used while juggling between HT20 and HT40 modes. */
	int secondary_ch;

#ifdef CONFIG_ACS
	unsigned int acs_num_completed_scans;
	unsigned int acs_num_retries;
#endif /* CONFIG_ACS */

	void (*scan_cb)(struct hostapd_iface *iface);
	int num_ht40_scan_tries;

	struct dl_list sta_seen; /* struct hostapd_sta_info */
	unsigned int num_sta_seen;

	u8 dfs_domain;
#ifdef CONFIG_AIRTIME_POLICY
	unsigned int airtime_quantum;
#endif /* CONFIG_AIRTIME_POLICY */

#ifdef CONFIG_ATF_OFFLOAD
        struct atf_algo *atf_algo;
#endif /* CONFIG_ATF_OFFLOAD */

	/* Previous WMM element information */
	struct hostapd_wmm_ac_params prev_wmm[WMM_AC_NUM];

	/* Maximum number of interfaces supported for MBSSID advertisement */
	unsigned int mbssid_max_interfaces;
	/* Maximum profile periodicity for enhanced MBSSID advertisement */
	unsigned int ema_max_periodicity;

	/* Radar infected sub channel bit pattern */
	u16 radar_bit_pattern;

	int (*enable_iface_cb)(struct hostapd_iface *iface);
	int (*disable_iface_cb)(struct hostapd_iface *iface);

	/* Configured freq of interface is NO_IR */
	bool is_no_ir;

	bool is_ch_switch_dfs; /* Channel switch from ACS to DFS */
	/* 6 GHz AFC information */
	struct afc_sp_reg_info *afc_rsp_info;
	bool is_afc_power_event_received;
	/* After receiving AFC power event in retail mode, this flag is to set to
	 * true to indicate that the channel change is pending. Channel is changed
	 * once NL8011_WIPHY_REG_CHANGE event is received.
	 */
	bool is_afc_channel_change_pending;
	/* Cached PSD value for RNR */
	s8 rnr_psd;

	struct hostapd_iface_extn iface_extn;

	struct hostapd_multi_hw_info *multi_hw_info;
	unsigned int num_multi_hws;
	struct hostapd_multi_hw_info *current_hw_info;
	/* Multi MBSSID group information */
	struct hostapd_multi_mbssid multi_mbssid;
	u32 mbssid_idx_bmap;
	size_t max_mgmt_frm_sz;
};


/*
 * enum peer_epcs_state - EPCS states of peer
 */
enum peer_epcs_state {
	EPCS_STATE_DISABLED = 0, /* The default state */
	EPCS_STATE_ENABLE_REQ_SENT, /* EPCS request sent to the peer, waiting for EPCS response */
	EPCS_STATE_ENABLED, /* EPCS session established */
};

/* TID value to be used when EPCS is enabled */
#define EPCS_TID_VALUE	7

/*
 * struct wlan_epcs_info - EPCS information of frame
 */
struct wlan_epcs_info {
	u8 action_code;
	u8 dialog_token;
	u16 status_code;
};

/*
 * struct mld_peer_epcs_info - per mld-peer epcs info
 */
struct mld_peer_epcs_info {
	bool is_epcs_capable;
	enum peer_epcs_state state;
	u8 self_gen_dialog_token;
	bool timer_started;
};


/* hostapd.c */
int hostapd_for_each_interface(struct hapd_interfaces *interfaces,
			       int (*cb)(struct hostapd_iface *iface,
					 void *ctx), void *ctx);
int hostapd_reload_config(struct hostapd_iface *iface);
int hostapd_reload_config_bss(struct hostapd_iface *iface,
                              const char *iface_name,
                              char *buf);
void hostapd_reconfig_encryption(struct hostapd_data *hapd);
struct hostapd_data *
hostapd_alloc_bss_data(struct hostapd_iface *hapd_iface,
		       struct hostapd_config *conf,
		       struct hostapd_bss_config *bss);
int hostapd_setup_interface(struct hostapd_iface *iface);
int hostapd_setup_interface_complete(struct hostapd_iface *iface, int err);
void hostapd_set_own_neighbor_report(struct hostapd_data *hapd);
void hostapd_interface_deinit(struct hostapd_iface *iface);
void hostapd_interface_free(struct hostapd_iface *iface);
struct hostapd_iface * hostapd_alloc_iface(void);
struct hostapd_iface * hostapd_init(struct hapd_interfaces *interfaces,
				    const char *config_file);
struct hostapd_iface *
hostapd_interface_init_bss(struct hapd_interfaces *interfaces, const char *phy,
			   const char *config_fname, int debug);
int hostapd_setup_bss(struct hostapd_data *hapd, int first, bool start_beacon);
void hostapd_bss_deinit(struct hostapd_data *hapd);
void hostapd_bss_setup_multi_link(struct hostapd_data *hapd,
				  struct hapd_interfaces *interfaces);
void hostapd_mbssid_setup_bss(struct hostapd_data *hapd);
void hostapd_new_assoc_sta(struct hostapd_data *hapd, struct sta_info *sta,
			   int reassoc);
void hostapd_interface_deinit_free(struct hostapd_iface *iface);
void hostapd_deauthenticate_stations(struct hapd_interfaces *interfaces);
int hostapd_iface_num_sta(struct hostapd_iface *iface);
int hostapd_enable_iface(struct hostapd_iface *hapd_iface);
int hostapd_reload_iface(struct hostapd_iface *hapd_iface);
int hostapd_reload_bss_only(struct hostapd_data *bss);
int hostapd_disable_iface(struct hostapd_iface *hapd_iface);
void hostapd_bss_deinit_no_free(struct hostapd_data *hapd);
void hostapd_free_hapd_data(struct hostapd_data *hapd);
void hostapd_cleanup_iface_partial(struct hostapd_iface *iface);
int hostapd_add_iface(struct hapd_interfaces *ifaces, char *buf);
int hostapd_remove_hapd_iface(struct hostapd_iface *hapd_iface);
int hostapd_remove_iface(struct hapd_interfaces *ifaces, char *buf);
void hostapd_channel_list_updated(struct hostapd_iface *iface, int initiator);
void hostapd_set_state(struct hostapd_iface *iface, enum hostapd_iface_state s);
const char * hostapd_state_text(enum hostapd_iface_state s);
int hostapd_csa_in_progress(struct hostapd_iface *iface);
void hostapd_chan_switch_config(struct hostapd_data *hapd,
				struct hostapd_freq_params *freq_params);
int hostapd_switch_channel(struct hostapd_data *hapd,
			   struct csa_settings *settings);
int hostapd_force_channel_switch(struct hostapd_iface *iface,
				 struct csa_settings *settings);
void
hostapd_switch_channel_fallback(struct hostapd_iface *iface,
				const struct hostapd_freq_params *freq_params);
void hostapd_cleanup_cs_params(struct hostapd_data *hapd);
void hostapd_periodic_iface(struct hostapd_iface *iface);
int hostapd_owe_trans_get_info(struct hostapd_data *hapd);
void hostapd_ocv_check_csa_sa_query(void *eloop_ctx, void *timeout_ctx);
int hostapd_check_max_sta(struct hostapd_data *hapd);
void hostapd_mac_auth_timeout(void *eloop_ctx, void *timeout_ctx);

bool hostapd_is_cca_in_progress(struct hostapd_iface *iface);
void hostapd_switch_color(struct hostapd_data *hapd, u64 bitmap);
void hostapd_cleanup_cca_params(struct hostapd_data *hapd);

void hostapd_free_afc_data(struct hostapd_iface *iface);
/* utils.c */
int hostapd_register_probereq_cb(struct hostapd_data *hapd,
				 int (*cb)(void *ctx, const u8 *sa,
					   const u8 *da, const u8 *bssid,
					   const u8 *ie, size_t ie_len,
					   int ssi_signal),
				 void *ctx);
void hostapd_prune_associations(struct hostapd_data *hapd, const u8 *addr,
				int mld_assoc_link_id);

/* drv_callbacks.c (TODO: move to somewhere else?) */
void hostapd_notify_assoc_fils_finish(struct hostapd_data *hapd,
				      struct sta_info *sta);
int hostapd_notif_assoc(struct hostapd_data *hapd, const u8 *addr,
			const u8 *req_ie, size_t req_ielen, const u8 *resp_ie,
			size_t resp_ielen, const u8 *link_addr, int reassoc);
void hostapd_notif_disassoc(struct hostapd_data *hapd, const u8 *addr);
void hostapd_notif_disassoc_mld(struct hostapd_data *assoc_hapd,
				struct sta_info *sta, const u8 *addr);
void hostapd_event_sta_low_ack(struct hostapd_data *hapd, const u8 *addr,
			       const u32 num_packets);
void hostapd_event_connect_failed_reason(struct hostapd_data *hapd,
					 const u8 *addr, int reason_code);
int hostapd_probe_req_rx(struct hostapd_data *hapd, const u8 *sa, const u8 *da,
			 const u8 *bssid, const u8 *ie, size_t ie_len,
			 int ssi_signal);
void hostapd_event_ch_switch(struct hostapd_data *hapd, int freq, int ht,
			     int offset, int width, int cf1, int cf2,
			     u16 punct_bitmap, u8 power_mode_6ghz,
			     int width_device, int cf_device, int finished);
struct survey_results;
void hostapd_event_get_survey(struct hostapd_iface *iface,
			      struct survey_results *survey_results);
void hostapd_acs_channel_selected(struct hostapd_data *hapd,
				  struct acs_selected_channels *acs_res);

const struct hostapd_eap_user *
hostapd_get_eap_user(struct hostapd_data *hapd, const u8 *identity,
		     size_t identity_len, int phase2);

struct hostapd_data * hostapd_get_iface(struct hapd_interfaces *interfaces,
					const char *ifname);
void hostapd_event_sta_opmode_changed(struct hostapd_data *hapd, const u8 *addr,
				      enum smps_mode smps_mode,
				      enum chan_width chan_width, u8 rx_nss);

int hostapd_change_config_freq(struct hostapd_data *hapd,
			       struct hostapd_config *conf,
			       struct hostapd_freq_params *params,
			       struct hostapd_freq_params *old_params);
#ifdef CONFIG_FST
void fst_hostapd_fill_iface_obj(struct hostapd_data *hapd,
				struct fst_wpa_obj *iface_obj);
#endif /* CONFIG_FST */

int hostapd_set_acl(struct hostapd_data *hapd);
int hostapd_tx_bss_only(struct hostapd_data *hapd, const char *op_name);
struct hostapd_data * hostapd_mbssid_get_tx_bss(struct hostapd_data *hapd);
unsigned int hostapd_mbssid_get_bss_index(struct hostapd_data *hapd);
struct hostapd_data * hostapd_mld_get_link_bss(struct hostapd_data *hapd,
					       u8 link_id);
int hostapd_link_remove(struct hostapd_data *hapd, u32 count);
struct hostapd_data *
hostapd_interfaces_get_hapd(struct hapd_interfaces *interfaces,
			    const char *ifname);
bool hostapd_is_ml_partner(struct hostapd_data *hapd1,
			   struct hostapd_data *hapd2);
u8 hostapd_get_mld_id(struct hostapd_data *hapd);
int hostapd_mld_add_link(struct hostapd_data *hapd);
int hostapd_mld_remove_link(struct hostapd_data *hapd);
u8 hostapd_get_active_links(struct hostapd_data *hapd);
struct hostapd_data * hostapd_mld_get_first_bss(struct hostapd_data *hapd);

int hostapd_build_beacon_data(struct hostapd_data *hapd,
			      struct beacon_data *beacon);
void free_beacon_data(struct beacon_data *beacon);
int hostapd_fill_cca_settings(struct hostapd_data *hapd,
			      struct cca_settings *settings);

#ifdef CONFIG_IEEE80211BE

void hostapd_set_ml_max_rec_links(struct hostapd_data *hapd, u8 ml_max_rec_links);
void hostapd_validate_update_ml_max_rec_links(struct hostapd_data *hapd);
bool hostapd_mld_is_first_bss(struct hostapd_data *hapd);
void hostapd_mld_interface_freed(struct hostapd_data *hapd);
int hostapd_wnm_add_multi_link_sub_elem(struct hostapd_data *hapd,
					u8 *links, u8 num_links,
					u8 *pos, size_t len);

#define for_each_mld_link(partner, self) \
	dl_list_for_each(partner, &self->mld->links, struct hostapd_data, link)

#else /* CONFIG_IEEE80211BE */

static inline bool hostapd_mld_is_first_bss(struct hostapd_data *hapd)
{
	return true;
}

#define for_each_mld_link(partner, self) \
	if (false)

#endif /* CONFIG_IEEE80211BE */

#define SP_AP_AND_CLIENT_POWER_DIFF            6
#define CONV_20MHZ_EIRP_TO_PSD_IN_DBM         13
#define SP_AP_AND_CLIENT_POWER_DIFF_IN_SCALE 600
#define TPE_NUM_POWER_SUPP_IN_11BE             5
#define TPE_NUM_EIRP_POWER_EXT_SUPPORTED       1
#define MAX_NUM_20_MHZ_IN_CURR_BW             16
#define EIRP_PWR_SCALE                       100
#define PSD_SCALE                            100
#define CHAN_MIN_TX_POWER                    -64
#define CHAN_MAX_TX_POWER                     63
#define CHAN_MIN_TWICE_TX_POWER              (CHAN_MIN_TX_POWER * 2)
#define CHAN_MAX_TWICE_TX_POWER              ((CHAN_MAX_TX_POWER * 2) + 1)

#define MAX_EIRP_THRESHOLD      33  /* A value above Max LPI and below Max SP */

#define NUM_20PP_PUNC_80MHZ      4
#define NUM_20PP_PUNC_160MHZ     8
#define NUM_40PP_PUNC_160MHZ     4
#define NUM_40PP_PUNC_320MHZ     8
#define NUM_80PP_PUNC_320MHZ     4
#define NUM_40P80PP_PUNC_320MHZ 12

/**
 * hostapd_iface_get_6ghz_chan_list() - Find the 6 GHz channel data for the given freq
 * @iface: Pointer to hostapd_iface
 * @freq: Frequency in MHz
 * @pwr_type: Power type
 * @num_channels_6ghz: Output pointer to number of 6 GHz channels
 * @chan_idx: Output pointer to channel index for the given frequency
 *
 * Return: Pointer to hostapd_channel_data
 */
struct hostapd_channel_data *
hostapd_iface_get_6ghz_chan_list(struct hostapd_iface *iface,
				 u16 freq, u8 pwr_type,
				 u8 *num_channels_6ghz, u8 *chan_idx);

/**
 * hostapd_get_eirp_pwr() - Get eirp power based on channel input
 *
 * This API calculats the EIRP based on the AP power type or client power mode.
 * The callers are supposed to set both ap_power_type and client power type for
 * querying AFC based SP Tx powers for a particular client type. For other
 * cases, either of the two can be set.
 *
 * @iface: Pointer to iface
 * @freq: Primary Frequency in MHz
 * @cen_freq: Band center frequency
 * @bw: Bandwidth in MHz
 * @client_type: Client power type
 *
 * Return: EIRP power
 */
s16 hostapd_get_eirp_pwr(struct hostapd_iface *iface, u16 freq, u16 center_freq,
			 u16 bw, u16 in_punc_pattern, u8 ap_pwr_type,
			 bool is_client_lookup, u8 client_type,
			 bool is_twice_pwr);

/**
 * hostapd_get_chan_width_from_oper_chan_width() - Get the channel width
 * @iconf: Pointer to hostapd_config
 *
 * Return: Channel width enum value for the given config's operating ch width.
 */
enum chan_width
hostapd_get_chan_width_from_oper_chan_width(struct hostapd_config *iconf);

/**
 * hostapd_allow_6ghz_dynamic_puncture() - Check if dynamic puncturing is allowed
 * @iface: Pointer to hostapd_iface
 * @freq: Frequency in MHz
 * @pwr_type: 6 GHz Power type.
 *
 * Return: true if dynamic puncturing is allowed, false otherwise.
 */
bool hostapd_allow_6ghz_dynamic_puncture(struct hostapd_iface *iface, u16 freq,
					 u8 pwr_type);

/**
 * hostapd_apply_6ghz_dynamic_puncturing() - Apply dynamic puncturing for 6 GHz
 * @iface: Pointer to hostapd_iface
 *
 * This function applies dynamic puncturing for 6 GHz channels in SP power mode.
 * It updates the puncturing pattern which gives the highest EIRP
 * for the given channel parameters.
 *
 * Return: None
 */
void hostapd_apply_6ghz_dynamic_puncturing(struct hostapd_iface *iface);

/**
 * hostapd_get_6ghz_best_pp() - Get the best 6 GHz Puncturing Pattern
 * @iface: Pointer to hostapd_iface
 * @freq: Frequency in MHz
 * @center_freq: Band center frequency
 * @bw: Bandwidth in MHz
 * @pp: Output pointer to the best Puncturing Pattern
 * @is_bpm_enabled: Flag to indicate if the best power mode is enabled
 *
 * Return: 0 on success, -1 on failure.
 */
s8 hostapd_get_6ghz_best_pp(struct hostapd_iface *iface, u16 freq,
			    u16 center_freq, u16 bw, u16 *pp,
			    bool is_bpm_enabled);

/**
 * hostapd_get_best_ap_6ghz_power_mode() - Get the best 6 GHz AP power mode
 * @iface: Pointer to hostapd_iface
 * @freq: Frequency in MHz
 * @center_freq: Band center frequency
 * @bw: Bandwidth in MHz
 * @in_punc_pattern: Puncturing pattern
 *
 * Return: Best AP power mode for the given channel parameters.
 */
u8
hostapd_get_best_ap_6ghz_power_mode(struct hostapd_iface *iface,
				    u16 freq, u16 center_freq,
				    u16 bw,
				    u16 in_punc_pattern);

/**
 * hostapd_get_best_ap_6ghz_power_mode_for_iface() - Get the best 6 GHz power mode
 * @iface: Pointer to hostapd_iface
 *
 * Return: Best AP power mode for the iface's channel parameters
 */
u8
hostapd_get_best_ap_6ghz_power_mode_for_iface(struct hostapd_iface *iface);

/**
 * hostapd_get_bonded_chan_center_freq() - Get the bonded channel center freq
 *
 * This API returns the center frequency of the bonded channel based on the
 * frequency, bandwidth, 320 MHz BW center frequency and secondary channel offset.
 *
 * @freq: Frequency in MHz
 * @bw: Bandwidth in MHz
 * @cen320_freq: Center frequency for 320 MHz
 * @sec_chan_offset: Secondary channel offset
 *
 * Return: Center frequency in MHz for the bonded channel or 0 if not found.
 */
u16
hostapd_get_bonded_chan_center_freq(u16 freq, u16 bw, u16 cen320_freq,
				    s8 sec_chan_offset);

/**
 * hostapd_switch_power_mode() - Switch the power mode of the AP interface.
 *
 * This function switches the power mode of the AP interface and stores
 * the target power mode in the iface structure.
 *
 * @hapd: Pointer to hostapd_data
 *
 * Return: 0 on success, -1 on failure.
 */
int hostapd_switch_power_mode(struct hostapd_data *hapd);

u16 hostapd_get_punct_bitmap(struct hostapd_data *hapd);
bool hostapd_is_usable_punct_bitmap(struct hostapd_iface *iface);
void hostapd_gen_per_sta_profiles(struct hostapd_data *hapd);
size_t hostapd_eid_eht_ml_reconfig_len(struct hostapd_data *hapd);
u8 * hostapd_eid_eht_reconf_ml(struct hostapd_data *hapd, u8 *eid);
int hostapd_remove_bss(struct hostapd_iface *iface, unsigned int idx,
		       bool is_link_remove);
void hostapd_refresh_all_iface_beacons(struct hostapd_iface *hapd_iface);

static inline bool ap_pmf_enabled(struct hostapd_bss_config *conf)
{
	return conf->ieee80211w != NO_MGMT_FRAME_PROTECTION ||
		conf->rsn_override_mfp != NO_MGMT_FRAME_PROTECTION ||
		conf->rsn_override_mfp_2 != NO_MGMT_FRAME_PROTECTION;
}

enum oper_chan_width
hostapd_chan_width_from_freq_params(struct hostapd_freq_params *freq_params);

struct hostapd_data *
hostapd_get_mbssid_bss_by_idx(struct hostapd_data *hapd, size_t idx);

struct hostapd_data *
hostapd_get_multi_group_bss(struct hostapd_multi_mbssid_group *group,
                           int bss_idx);
u8 hostapd_max_bssid_indicator(struct hostapd_data *hapd);

int hostapd_allocate_mbssid_idx(struct hostapd_data *hapd);
int hostapd_get_mbssid_index(u32 *bmap);
void hostapd_free_mbssid_idx(struct hostapd_data *hapd);
void hostapd_interface_update_fils_ubpr(struct hostapd_iface *iface,
					bool iface_enabled);
/**
 * hostapd_set_no_ir_state - Set the NO_IR state for the interface
 * and bring down the corresponding 6 GHz link.
 * @iface: Pointer to hostapd interface data
 *
 * Return: None
 */
#ifdef HOSTAPD
void hostapd_set_no_ir_state(struct hostapd_iface *iface);
#else
static inline void
hostapd_set_no_ir_state(struct hostapd_iface *iface)
{
	/* No-op if hostapd is not defined */
}
#endif
void hostapd_no_ir_cleanup(struct hostapd_data *bss);

/**
 * hostapd_handle_afc_channel_change - Handle retail AFC channel change.
 *
 * Following are the steps:
 * 1. Fetch the updated channel list from the kernel using
 * NL8011_WIPHY_REG_CHANGE event.
 * 2. Randomly select a channel from the updated channel list.
 * 3. Apply best power mode on the selected channel and then set the
 * channel to the driver using drv_switch_channel.
 * 4. If channel change fails, move hostapd to NO_IR state.
 *
 * @iface: Pointer to hostapd interface data
 *
 * Returns: 0 on success, -1 on failure.
 */
#ifdef HOSTAPD
int hostapd_handle_afc_channel_change(struct hostapd_iface *iface);
#else
static inline int
hostapd_handle_afc_channel_change(struct hostapd_iface *iface)
{
	/* No-op if hostapd is not defined */
	return 0;
}
#endif

/**
 * afc_channel_change_timeout - Timeout handler for AFC channel change
 *
 * This function is called when the timeout for AFC channel change occurs.
 * After AFC response is received by the hostapd, it waits for
 * NL8011_WIPHY_REG_CHANGE event to get the updated channel list. If this
 * event is not received within the timeout period, this function
 * is invoked to set the hostapd state to no IR and clean up the AFC data.
 *
 * @eloop_ctx: Pointer to hostapd_iface structure
 * @timeout_ctx: Pointer to timeout context (not used)
 */
#ifdef HOSTAPD
void
afc_channel_change_timeout(void *eloop_ctx, void *timeout_ctx);
#else
static inline void
afc_channel_change_timeout(void *eloop_ctx, void *timeout_ctx)
{
	/* No-op if hostapd is not defined */
}
#endif
#ifdef CONFIG_IEEE80211BE
int hostapd_epcs_handle_and_send_action_frame(struct hostapd_data *hapd,
					      struct wlan_epcs_info *epcs_info,
					      struct sta_info *sta,
					      bool is_rx_frame);

void hostapd_handle_epcs_action(struct hostapd_data *hapd,
				const u8 *buf,
				size_t len);

void hostapd_get_epcs_capab(struct hostapd_data *hapd, struct sta_info *sta);

int hostapd_epcs_handle_cli(struct hostapd_data *hapd, char *pos,
			    char *buf, size_t buflen);
int hostapd_ctrl_iface_negotiated_ttlm_capabilities(struct hostapd_data *hapd,
						    char *buf, size_t buflen);
int hostapd_ctrl_iface_negotiated_ttlm_config(struct hostapd_data *hapd, const char *cmd,
					      char *buf, size_t buflen);
#endif /* CONFIG_IEEE80211BE */
bool
hostapd_verify_action_frame_has_min_length(const struct ieee80211_mgmt *mgmt,
					   size_t len);

/**
 * hostapd_find_eirp_in_afc_chan_obj() - Get AFC eirp power
 *
 * This API get the SP EIRP power from the AFC channel object based on the
 * channel center frequency and operating class.
 *
 * @chan_obj: Pointer to chan_obj
 * @freq: Frequency in MHz
 * @center_freq: Band center Frequency
 * @op_class: Operating class
 * @afc_eirp: Output pointer to AFC EIRP power
 *
 * Return: 0 on success, -1 on failure
 */
int
hostapd_find_eirp_in_afc_chan_obj(struct afc_chan_obj *chan_obj, u16 freq,
				  u16 center_freq, u8 op_class, s16 *afc_eirp);

/**
 * hostapd_reg_get_psd_from_chan_list() - Get the regulatory PSD for the freq
 * @iface: Pointer to hostapd_iface
 * @freq: Frequency in MHz
 * @center_freq: Band center frequency
 * @bw: Bandwidth in MHz
 * @in_punc_pattern: Puncturing pattern
 * @ap_pwr_type: AP power type
 * @client_type: Client type
 * @is_client_lookup: Whether the lookup is for client
 * @is_twice_pwr: Flag to indicate twice power
 * @psd_pwr: Output pointer to PSD power
 *
 * Return: 0 on success, -1 on failure
 */
int
hostapd_reg_get_psd_from_chan_list(struct hostapd_iface *iface, u16 freq,
				   u16 center_freq, u16 bw, u16 in_punc_pattern,
				   u8 ap_pwr_type, u8 client_type,
				   bool is_client_lookup, bool is_twice_pwr,
				   s16 *psd_pwr);

/**
 * hostapd_get_valid_puncture_pattern_arr() - Get the valid puncture pattern array
 * @bw: Bandwidth in MHz
 * @num_pp: Output pointer to store the number of valid puncture patterns
 * @pp_mask: Output pointer to store the puncture pattern mask for the given bandwidth
 *
 * Return: Pointer to the valid puncture pattern array or NULL if not found
 */
const u16 *
hostapd_get_valid_puncture_pattern_arr(u16 bw, u16 *num_pp, u16 *pp_mask);

/*
 * hostapd_afc_handle_cli - This CLI handler to set or get the afc channel
 * selection config
 *
 * @hapd: Pointer to hostapd data structure
 * @pos: Starting position of the buffer
 * @buf: Data buffer
 * @buflen: Data buffer length
 *
 * Return: Response length
 */
int hostapd_afc_handle_cli(struct hostapd_data *hapd, char *pos,
			   char *buf, size_t buflen);

/**
 * hostapd_get_tpe_11ax_count() - Validate the input Tx power count
 *
 * This API checks if the input Tx power count and Interpretation are valid
 *
 * @tx_pwr_intrpn: Tx power interpretation
 * @tx_pwr_count: Tx power count
 *
 * Return: Total Tx power count for the given interpretation
 */
int
hostapd_get_tpe_11ax_count(u8 tx_pwr_intrpn, u8 tx_pwr_count);

/**
 * hostapd_validate_chan_bw_in_pwr_mode() - Validate the input channel parameters
 *
 * This API checks if the input channel parameters are valid in the given
 * power mode.
 *
 * @iface: Pointer to hostapd interface data
 * @freq: Frequency of the channel
 * @center_freq: Center frequency of the channel
 * @bw: Bandwidth of the channel
 * @pp: Puncturing bitmap
 * @pwr_type: Power type
 *
 * Return: true if valid, false otherwise
 */
bool
hostapd_validate_chan_bw_in_pwr_mode(struct hostapd_iface *iface, u16 freq,
				     u16 center_freq, u16 bw, u16 pp,
				     u8 pwr_type);
#endif /* HOSTAPD_H */
