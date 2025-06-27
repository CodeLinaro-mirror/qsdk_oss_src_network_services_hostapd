/*
 * hostapd / IEEE 802.11 Management
 * Copyright (c) 2002-2009, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef IEEE802_11_H
#define IEEE802_11_H

#include "utils/list.h"
#include "hostapd.h"

struct hostapd_iface;
struct hostapd_data;
struct sta_info;
struct hostapd_frame_info;
struct ieee80211_ht_capabilities;
struct ieee80211_vht_capabilities;
struct ieee80211_mgmt;
struct radius_sta;
enum ieee80211_op_mode;
struct mac_acl_entry;
enum oper_chan_width;
struct ieee802_11_elems;
struct sae_pk;
struct sae_pt;
struct sae_password_entry;
struct mld_info;
struct mld_link_info;

enum colocation_mode {
	NO_COLOCATED_6GHZ,
	STANDALONE_6GHZ,
	COLOCATED_6GHZ,
	COLOCATED_LOWER_BAND,
};

enum colocation_mode get_colocation_mode(struct hostapd_data *hapd);

enum link_parse_type {
	LINK_PARSE_ASSOC,
	LINK_PARSE_REASSOC,
	LINK_PARSE_RECONF,
};

#define LINK_RECONF_GROUP_KDE_MAX_LEN 255

struct link_reconf_req_info {
	struct dl_list list;
	u16 status;
	u8 link_id;
	u8 local_addr[ETH_ALEN];
	u8 peer_addr[ETH_ALEN];
	size_t sta_prof_len;
	u8 sta_prof[];
};

struct link_reconf_req_list {
	u8 sta_mld_addr[ETH_ALEN];
	u8 dialog_token;
	u16 links_add_ok;
	u16 links_del_ok;
	u16 new_valid_links;
	struct dl_list del_req; /* list of struct link_reconf_req_info */
	struct dl_list add_req; /* list of struct link_reconf_req_info */
};

int ieee802_11_mgmt(struct hostapd_data *hapd, const u8 *buf, size_t len,
		    struct hostapd_frame_info *fi);
void ieee802_11_mgmt_cb(struct hostapd_data *hapd, const u8 *buf, size_t len,
			u16 stype, int ok);
void hostapd_2040_coex_action(struct hostapd_data *hapd,
			      const struct ieee80211_mgmt *mgmt, size_t len);

int hostapd_config_read_maclist(const char *fname,
				struct mac_acl_entry **acl, int *num);
#ifdef NEED_AP_MLME
int ieee802_11_get_mib(struct hostapd_data *hapd, char *buf, size_t buflen);
int ieee802_11_get_mib_sta(struct hostapd_data *hapd, struct sta_info *sta,
			   char *buf, size_t buflen);
#else /* NEED_AP_MLME */
static inline int ieee802_11_get_mib(struct hostapd_data *hapd, char *buf,
				     size_t buflen)
{
	return 0;
}

static inline int ieee802_11_get_mib_sta(struct hostapd_data *hapd,
					 struct sta_info *sta,
					 char *buf, size_t buflen)
{
	return 0;
}
#endif /* NEED_AP_MLME */
u16 hostapd_own_capab_info(struct hostapd_data *hapd);
void ap_ht2040_timeout(void *eloop_data, void *user_data);
u8 * hostapd_eid_ext_capab(struct hostapd_data *hapd, u8 *eid,
			   bool mbssid_complete);
u8 * hostapd_eid_qos_map_set(struct hostapd_data *hapd, u8 *eid);
u8 * hostapd_eid_supp_rates(struct hostapd_data *hapd, u8 *eid);
u8 * hostapd_eid_ext_supp_rates(struct hostapd_data *hapd, u8 *eid);
u8 * hostapd_eid_rm_enabled_capab(struct hostapd_data *hapd, u8 *eid,
				  size_t len);
u8 * hostapd_eid_ht_capabilities(struct hostapd_data *hapd, u8 *eid);
u8 * hostapd_eid_ht_operation(struct hostapd_data *hapd, u8 *eid);
u8 * hostapd_eid_vht_capabilities(struct hostapd_data *hapd, u8 *eid, u32 nsts);
u8 * hostapd_eid_vht_operation(struct hostapd_data *hapd, u8 *eid);
u8 * hostapd_eid_vendor_vht(struct hostapd_data *hapd, u8 *eid);
u8 * hostapd_eid_chsw_wrapper(struct hostapd_data *hapd, u8 *eid);
u8 * hostapd_eid_txpower_envelope(struct hostapd_data *hapd, u8 *eid);
u8 * hostapd_eid_he_capab(struct hostapd_data *hapd, u8 *eid,
			  enum ieee80211_op_mode opmode);
u8 * hostapd_eid_he_operation(struct hostapd_data *hapd, u8 *eid);
u8 * hostapd_eid_he_mu_edca_parameter_set(struct hostapd_data *hapd, u8 *eid,
					  bool is_epcs);
u8 * hostapd_eid_spatial_reuse(struct hostapd_data *hapd, u8 *eid);
u8 * hostapd_eid_he_6ghz_band_cap(struct hostapd_data *hapd, u8 *eid);

int hostapd_ht_operation_update(struct hostapd_iface *iface);
void ieee802_11_send_sa_query_req(struct hostapd_data *hapd,
				  const u8 *addr, const u8 *trans_id);
void hostapd_get_ht_capab(struct hostapd_data *hapd,
			  struct ieee80211_ht_capabilities *ht_cap,
			  struct ieee80211_ht_capabilities *neg_ht_cap);
void hostapd_get_vht_capab(struct hostapd_data *hapd,
			   struct ieee80211_vht_capabilities *vht_cap,
			   struct ieee80211_vht_capabilities *neg_vht_cap);
void hostapd_get_he_capab(struct hostapd_data *hapd,
			  const struct ieee80211_he_capabilities *he_cap,
			  struct ieee80211_he_capabilities *neg_he_cap,
			  size_t he_capab_len);
void hostapd_get_eht_capab(struct hostapd_data *hapd,
			   const struct ieee80211_eht_capabilities *src,
			   struct ieee80211_eht_capabilities *dest,
			   size_t len);
u8 * hostapd_eid_eht_ml_beacon(struct hostapd_data *hapd,
			       struct mld_info *mld_info,
			       u8 *eid, bool include_mld_id);
u8 * hostapd_eid_eht_ml_assoc(struct hostapd_data *hapd, struct sta_info *info,
			      u8 *eid);
u8 * hostapd_eid_eht_basic_ml_common(struct hostapd_data *hapd,
				     u8 *eid, struct mld_info *mld_info,
				     bool include_mld_id, bool include_bpcc);
size_t hostapd_eid_eht_basic_ml_len(struct hostapd_data *hapd,
				    struct sta_info *info,
				    bool include_mld_id, bool include_pbcc);
size_t hostapd_eid_eht_ml_beacon_len(struct hostapd_data *hapd,
				     struct mld_info *info,
				     bool include_mld_id);
struct wpabuf * hostapd_ml_auth_resp(struct hostapd_data *hapd);
const u8 * hostapd_process_ml_auth(struct hostapd_data *hapd,
				   const struct ieee80211_mgmt *mgmt,
				   size_t len);
u16 hostapd_process_ml_assoc_req(struct hostapd_data *hapd,
				 struct ieee802_11_elems *elems,
				 struct sta_info *sta);
int hostapd_process_ml_assoc_req_addr(struct hostapd_data *hapd,
				      const u8 *basic_mle, size_t basic_mle_len,
				      u8 *mld_addr);
int hostapd_get_aid(struct hostapd_data *hapd, struct sta_info *sta);
int hostapd_get_wds_mld_sta_uid(struct hostapd_data *hapd, struct sta_info *sta);
u16 copy_sta_ht_capab(struct hostapd_data *hapd, struct sta_info *sta,
		      const u8 *ht_capab);
u16 copy_sta_vendor_vht(struct hostapd_data *hapd, struct sta_info *sta,
			const u8 *ie, size_t len);

int update_ht_state(struct hostapd_data *hapd, struct sta_info *sta);
void ht40_intolerant_add(struct hostapd_iface *iface, struct sta_info *sta);
void ht40_intolerant_remove(struct hostapd_iface *iface, struct sta_info *sta);
u16 copy_sta_vht_capab(struct hostapd_data *hapd, struct sta_info *sta,
		       const u8 *vht_capab);
u16 copy_sta_vht_oper(struct hostapd_data *hapd, struct sta_info *sta,
		      const u8 *vht_oper);
u16 set_sta_vht_opmode(struct hostapd_data *hapd, struct sta_info *sta,
		       const u8 *vht_opmode);
u16 copy_sta_he_capab(struct hostapd_data *hapd, struct sta_info *sta,
		      enum ieee80211_op_mode opmode, const u8 *he_capab,
		      size_t he_capab_len);
u16 copy_sta_he_6ghz_capab(struct hostapd_data *hapd, struct sta_info *sta,
			   const u8 *he_6ghz_capab);
int hostapd_get_he_twt_responder(struct hostapd_data *hapd,
				 enum ieee80211_op_mode mode);
bool hostapd_get_ht_vht_twt_responder(struct hostapd_data *hapd);
void hostapd_wfa_capab(struct hostapd_data *hapd, struct sta_info *sta,
		       const u8 *pos, const u8 *end);
u8 * hostapd_eid_cca(struct hostapd_data *hapd, u8 *eid);
void hostapd_tx_status(struct hostapd_data *hapd, const u8 *addr,
		       const u8 *buf, size_t len, int ack);
void ieee802_11_rx_from_unknown(struct hostapd_data *hapd, const u8 *src,
				int wds);
u8 * hostapd_eid_assoc_comeback_time(struct hostapd_data *hapd,
				     struct sta_info *sta, u8 *eid);
void ieee802_11_sa_query_action(struct hostapd_data *hapd,
				const struct ieee80211_mgmt *mgmt,
				size_t len);
u8 * hostapd_eid_interworking(struct hostapd_data *hapd, u8 *eid);
u8 * hostapd_eid_adv_proto(struct hostapd_data *hapd, u8 *eid);
u8 * hostapd_eid_roaming_consortium(struct hostapd_data *hapd, u8 *eid);
u8 * hostapd_eid_time_adv(struct hostapd_data *hapd, u8 *eid);
u8 * hostapd_eid_time_zone(struct hostapd_data *hapd, u8 *eid);
int hostapd_update_time_adv(struct hostapd_data *hapd);
void hostapd_client_poll_ok(struct hostapd_data *hapd, const u8 *addr);
u8 * hostapd_eid_bss_max_idle_period(struct hostapd_data *hapd, u8 *eid,
				     u16 value);

int auth_sae_init_committed(struct hostapd_data *hapd, struct sta_info *sta);
#ifdef CONFIG_SAE
void sae_clear_retransmit_timer(struct hostapd_data *hapd,
				struct sta_info *sta);
void sae_accept_sta(struct hostapd_data *hapd, struct sta_info *sta);
#else /* CONFIG_SAE */
static inline void sae_clear_retransmit_timer(struct hostapd_data *hapd,
					      struct sta_info *sta)
{
}
#endif /* CONFIG_SAE */

void hostap_ft_ds_ml_sta_timeout(void *eloop_ctx, void *timeout_ctx);

u8 * hostapd_eid_rm_enabled_capab(struct hostapd_data *hapd,
						 u8 *eid, size_t len);

#ifdef CONFIG_MBO

u8 * hostapd_eid_mbo(struct hostapd_data *hapd, u8 *eid, size_t len);

u8 hostapd_mbo_ie_len(struct hostapd_data *hapd);

u8 * hostapd_eid_mbo_rssi_assoc_rej(struct hostapd_data *hapd, u8 *eid,
				    size_t len, int delta);

#else /* CONFIG_MBO */

static inline u8 * hostapd_eid_mbo(struct hostapd_data *hapd, u8 *eid,
				   size_t len)
{
	return eid;
}

static inline u8 hostapd_mbo_ie_len(struct hostapd_data *hapd)
{
	return 0;
}

#endif /* CONFIG_MBO */

#define INVALID_EDGE 0xFFF
#define INVALID_DBR    100
#define INVALID_PSD (-1270) /* -127 multiplied by 10 */

/* Have the entire 6Ghz band as single range */
#define DEFAULT_LOW_6GFREQ     5925
#define DEFAULT_HIGH_6GFREQ    7125
#define MAX_PUNC_MASK_LIMITS      3

/* in the bitmap 0 indicates no puncturing and 1 indicated that sub channel is
 * punctured
 */
#define PUNCTURE_INVALID     0xFFFF
#define PUNCTURE_NONE        0x0000
#define PUNCTURE_80MHZ_MASK  0x000F
#define PUNCTURE_160MHZ_MASK 0x00FF
#define PUNCTURE_320MHZ_MASK 0xFFFF
#define PUNCTURE_40MHZ_MASK  0x0003

/**
 * struct punct_mask - Structure to hold puncture mask limits
 * @offset: Array of offsets for puncture mask limits
 * @dbr: Array of dbr values corresponding to the offsets
 *
 * This structure is used to define the puncture mask limits for different
 * bandwidths. The `offset` array holds the offset values, and the `dbr` array
 * holds the corresponding dbr values. The size of both arrays is defined by
 * `MAX_PUNC_MASK_LIMITS`.
 */
struct punct_mask {
	s16 offset[MAX_PUNC_MASK_LIMITS];
	s16 dbr[MAX_PUNC_MASK_LIMITS];
};

/**
 * enum puncture_type - Enumeration of puncture types
 * @PUNCTURE_TYPE_EDGE: Represents edge puncture type
 * @PUNCTURE_TYPE_INTERIM_20_PLUS: Represents interim puncture type with 20 MHz
 * plus
 * @PUNCTURE_TYPE_INTERIM_20: Represents interim puncture type with 20 MHz
 * @PUNCTURE_TYPE_INVALID: Represents an invalid puncture type
 *
 * This enumeration defines the different types of punctures that can occur
 * within a given bandwidth. Each type specifies a unique puncture pattern
 * and is used to determine the appropriate mask limits for the puncture.
 */
enum puncture_type {
	PUNCTURE_TYPE_EDGE = 0,
	PUNCTURE_TYPE_INTERIM_20_PLUS,
	PUNCTURE_TYPE_INTERIM_20,
	PUNCTURE_TYPE_INVALID,
};

/**
 * pdbm1, pdbm2 and pdbm3 - Array of dbr values for puncture mask type
 * PUNCTURE_TYPE_EDGE, PUNCTURE_TYPE_INTERIM_20_PLUS and
 * PUNCTURE_TYPE_INTERIM_20 respectively.
 */
static const s16 pdbm1[3] = {0, -200, -280};
static const s16 pdbm2[3] = {0, -200, -250};
static const s16 pdbm3[3] = {0, -200, -230};

#define CHAN_MAX_PSD_POWER   127

/**
 * get_psd_limit - Get the minimum PSD limit for a given frequency
 * @freq: Frequency for which the PSD limit is to be determined
 * @num_freq_obj: Number of frequency objects in the AFC response
 * @afc_freq_info: Pointer to the array of AFC frequency objects
 *
 * This function calculates the minimum PSD (Power Spectral Density) limit for
 * a given frequency by iterating through the AFC frequency objects. It returns
 * the minimum PSD limit found within the range of the frequency objects.
 *
 * Return: Minimum PSD limit for the given frequency, or INVALID_PSD if the
 * frequency is not found within the AFC frequency objects.
 */
s16 get_psd_limit(u16 freq, u8 num_freq_obj,
		  struct afc_freq_obj *afc_freq_info);

/**
 * get_y_val - Calculate the interpolated y-value for a given x-value
 * @x1: First x-coordinate
 * @x2: Second x-coordinate
 * @y1: y-coordinate corresponding to x1
 * @y2: y-coordinate corresponding to x2
 * @x: x-coordinate for which the interpolated y-value is to be calculated
 *
 * This function calculates the interpolated y-value for a given x-value using
 * linear interpolation between two points (x1, y1) and (x2, y2). The function
 * returns the interpolated y-value based on the input x-coordinate.
 *
 * Return: The interpolated y-value for the given x-coordinate.
 */
s16 get_y_val(s16 x1, s16 x2, s16 y1, s16 y2, s16 x);

/**
 * get_regmask_non_puncture - Calculate the regulatory mask for non-punctured
 * channels.
 * @offset: Offset value for the frequency
 * @bw: Bandwidth of the channel
 *
 * This function calculates the regulatory mask for non-punctured channels based
 * on the given offset and bandwidth. The mask value is determined by the offset
 * relative to the bandwidth and predefined thresholds.
 *
 * Return: The calculated regulatory mask value.
 */
s16 get_regmask_non_puncture(s16 offset, u16 bw);

/**
 * handle_edge_puncture - Populate puncture mask values for edge puncture type
 * @pu_mask_l_edge: Pointer to the left edge puncture mask structure
 * @pu_mask_r_edge: Pointer to the right edge puncture mask structure
 * @pu_l_edge: Offset value for the left edge of the puncture
 * region (in 0.01 MHz units)
 * @pu_r_edge: Offset value for the right edge of the puncture
 * region (in 0.01 MHz units)
 * @pdbm1: Pointer to an array of dB reduction values used to populate the mask
 *
 * This function sets the offset and dB reduction (dbr) values in the left and
 * right edge puncture mask structures for the PUNCTURE_TYPE_EDGE case. It uses
 * the provided edge offsets and a predefined dB mask array (typically pdbm1) to
 * define the regulatory mask shape on both sides of the punctured region.
 *
 * The mask is symmetric and ensures a smooth transition from the edge of the
 * punctured region to the adjacent usable spectrum.
 */
void
handle_edge_puncture(struct punct_mask *pu_mask_l_edge,
		     struct punct_mask *pu_mask_r_edge, s16 pu_l_edge,
		     s16 pu_r_edge, const s16 *pdbm1);

/**
 * handle_interim_20_plus - Populate puncture mask values for INTERIM_20_PLUS
 * type.
 * @pu_mask_l_edge: Pointer to the left edge puncture mask structure
 * @pu_mask_r_edge: Pointer to the right edge puncture mask structure
 * @pu_mask_l: Pointer to the left interim puncture mask structure
 * @pu_mask_r: Pointer to the right interim puncture mask structure
 * @pu_l_edge: Offset value for the left edge of the puncture
 * region (in 0.01 MHz units)
 * @pu_r_edge: Offset value for the right edge of the puncture
 * region (in 0.01 MHz units)
 * @l_edge: Logical left edge of the channel (in 0.01 MHz units)
 * @r_edge: Logical right edge of the channel (in 0.01 MHz units)
 * @pu_edge1: Start offset of the interim puncture region (in 0.01 MHz units)
 * @pu_edge2: End offset of the interim puncture region (in 0.01 MHz units)
 * @pdbm1: Pointer to dB reduction values for edge shaping
 * @pdbm2: Pointer to dB reduction values for interim shaping
 *
 * This function sets the offset and dB reduction (dbr) values in the puncture
 * mask structures for the PUNCTURE_TYPE_INTERIM_20_PLUS case. It handles both
 * edge and interim puncture shaping, ensuring smooth transitions in the
 * regulatory mask across the punctured and adjacent usable spectrum.
 *
 * The function uses predefined dB masks (pdbm1 and pdbm2) to shape the
 * attenuation profile for both edge and interim regions.
 */
void
handle_interim_20_plus(struct punct_mask *pu_mask_l_edge,
		       struct punct_mask *pu_mask_r_edge,
		       struct punct_mask *pu_mask_l,
		       struct punct_mask *pu_mask_r,
		       s16 pu_l_edge, s16 pu_r_edge, s16 l_edge, s16 r_edge,
		       s16 pu_edge1, s16 pu_edge2, const s16 *pdbm1,
		       const s16 *pdbm2);

/**
 * handle_interim_20 - Populate puncture mask values for INTERIM_20 type
 * @pu_mask_l: Pointer to the left interim puncture mask structure
 * @pu_mask_r: Pointer to the right interim puncture mask structure
 * @pu_edge1: Start offset of the interim puncture region (in 0.01 MHz units)
 * @pu_edge2: End offset of the interim puncture region (in 0.01 MHz units)
 * @pdbm3: Pointer to dB reduction values used to shape the interim mask
 *
 * This function sets the offset and dB reduction (dbr) values in the left and
 * right interim puncture mask structures for the PUNCTURE_TYPE_INTERIM_20 case.
 * It defines a symmetric attenuation profile across the punctured region using
 * the provided dB mask array (typically pdbm3).
 *
 * The mask ensures a smooth regulatory transition across the 20 MHz interim
 * puncture region, helping to meet spectral emission constraints.
 */
void
handle_interim_20(struct punct_mask *pu_mask_l, struct punct_mask *pu_mask_r,
		  s16 pu_edge1, s16 pu_edge2, const s16 *pdbm3);

/**
 * get_regmask - Calculate the regulatory mask for a given offset and bandwidth
 * @offset: Offset value for the frequency
 * @bw: Bandwidth of the channel
 * @punc_type: Type of puncture (enum puncture_type)
 * @pu_mask_l_edge: Pointer to the left edge puncture mask structure
 * @pu_mask_l: Pointer to the left interim puncture mask structure
 * @pu_mask_r: Pointer to the right interim puncture mask structure
 * @pu_mask_r_edge: Pointer to the right edge puncture mask structure
 *
 * This function calculates the regulatory mask for a given offset and bandwidth
 * based on the puncture type and the puncture mask limits defined in the pmask
 * structures. It determines the appropriate mask value by comparing the
 * non-puncture mask and puncture mask values.
 *
 * Return: The calculated regulatory mask value.
 */
s16 get_regmask(s16 offset, u16 bw, enum puncture_type punc_type,
		struct punct_mask *pu_mask_l_edge, struct punct_mask *pu_mask_l,
		struct punct_mask *pu_mask_r,
		struct punct_mask *pu_mask_r_edge);

/**
 * get_puncture_type_and_masks - Determine the puncture mask limits for a given
 * bandwidth and puncture bitmap
 * @bw: Bandwidth for which the puncture mask limits are to be determined
 * @puncture_bitmap: Bitmap indicating the punctured sub-channels
 * @pu_mask_l_edge: Pointer to the left edge puncture mask structure
 * @pu_mask_l: Pointer to the left interim puncture mask structure
 * @pu_mask_r: Pointer to the right interim puncture mask structure
 * @pu_mask_r_edge: Pointer to the right edge puncture mask structure
 *
 * This function calculates the puncture mask limits for a given bandwidth and
 * puncture bitmap. It determines the type of puncture (edge, interim 20 MHz,
 * interim 20 MHz plus, or invalid) and sets the appropriate offset and dbr
 * values in the provided pmask structures.
 *
 * Return: The type of puncture determined (enum puncture_type).
 */
enum puncture_type
get_puncture_type_and_masks(u16 bw, u16 puncture_bitmap,
			    struct punct_mask *pu_mask_l_edge,
			    struct punct_mask *pu_mask_l,
			    struct punct_mask *pu_mask_r,
			    struct punct_mask *pu_mask_r_edge);


void ap_copy_sta_supp_op_classes(struct sta_info *sta,
				 const u8 *supp_op_classes,
				 size_t supp_op_classes_len);

u8 * hostapd_eid_fils_indic(struct hostapd_data *hapd, u8 *eid, int hessid);
void ieee802_11_finish_fils_auth(struct hostapd_data *hapd,
				 struct sta_info *sta, int success,
				 struct wpabuf *erp_resp,
				 const u8 *msk, size_t msk_len);
u8 * owe_assoc_req_process(struct hostapd_data *hapd, struct sta_info *sta,
			   const u8 *owe_dh, u8 owe_dh_len,
			   u8 *owe_buf, size_t owe_buf_len, u16 *status);
u16 owe_process_rsn_ie(struct hostapd_data *hapd, struct sta_info *sta,
		       const u8 *rsn_ie, size_t rsn_ie_len,
		       const u8 *owe_dh, size_t owe_dh_len,
		       const u8 *link_addr);
u16 owe_validate_request(struct hostapd_data *hapd, const u8 *peer,
			 const u8 *rsn_ie, size_t rsn_ie_len,
			 const u8 *owe_dh, size_t owe_dh_len);
void fils_hlp_timeout(void *eloop_ctx, void *eloop_data);
void fils_hlp_finish_assoc(struct hostapd_data *hapd, struct sta_info *sta);
void handle_auth_fils(struct hostapd_data *hapd, struct sta_info *sta,
		      const u8 *pos, size_t len, u16 auth_alg,
		      u16 auth_transaction, u16 status_code,
		      void (*cb)(struct hostapd_data *hapd,
				 struct sta_info *sta,
				 u16 resp, struct wpabuf *data, int pub));

size_t hostapd_eid_owe_trans_len(struct hostapd_data *hapd);
u8 * hostapd_eid_owe_trans(struct hostapd_data *hapd, u8 *eid, size_t len);

size_t hostapd_eid_dpp_cc_len(struct hostapd_data *hapd);
u8 * hostapd_eid_dpp_cc(struct hostapd_data *hapd, u8 *eid, size_t len);

int get_tx_parameters(struct sta_info *sta, int ap_max_chanwidth,
		      int ap_seg1_idx, int *bandwidth, int *seg1_idx);

void auth_sae_process_commit(void *eloop_ctx, void *user_ctx);
u8 * hostapd_eid_rsnxe(struct hostapd_data *hapd, u8 *eid, size_t len);
u16 check_ext_capab(struct hostapd_data *hapd, struct sta_info *sta,
		    const u8 *ext_capab_ie, size_t ext_capab_ie_len);
size_t hostapd_eid_rnr_len(struct hostapd_data *hapd, u32 type,
			   bool include_mld_params);
u8 * hostapd_eid_rnr(struct hostapd_data *hapd, u8 *eid, u32 type,
		     bool include_mld_params);
int ieee802_11_set_radius_info(struct hostapd_data *hapd, struct sta_info *sta,
			       int res, struct radius_sta *info);
size_t hostapd_eid_eht_capab_len(struct hostapd_data *hapd,
				 enum ieee80211_op_mode opmode);
u8 * hostapd_eid_eht_capab(struct hostapd_data *hapd, u8 *eid,
			   enum ieee80211_op_mode opmode);
u8 * hostapd_eid_eht_operation(struct hostapd_data *hapd, u8 *eid);
u16 copy_sta_eht_capab(struct hostapd_data *hapd, struct sta_info *sta,
		       enum ieee80211_op_mode opmode,
		       const u8 *he_capab, size_t he_capab_len,
		       const u8 *eht_capab, size_t eht_capab_len);
size_t hostapd_eid_mbssid_len(struct hostapd_data *hapd, u32 frame_type,
			      u8 *elem_count, const u8 *known_bss,
			      size_t known_bss_len, size_t *rnr_len);
u8 * hostapd_eid_mbssid(struct hostapd_data *hapd, u8 *eid, u8 *end,
			unsigned int frame_stype, u8 elem_count,
			u8 **elem_offset,
			const u8 *known_bss, size_t known_bss_len, u8 *rnr_eid,
			u8 *rnr_count, u8 **rnr_offset, size_t rnr_len,
			u32 *elemid_modified_bmap);
void hostapd_eid_update_cu_info(struct hostapd_data *hapd, u16 *elemid_modified,
				const u8 *eid_pos, size_t eid_len,
				enum elemid_cu eid_cu);
bool hostapd_is_multiple_link_mld(struct hostapd_data *hapd);
int sae_password_bind(struct hostapd_data *hapd, const u8 *addr,
		      const char *password);
u16 hostapd_critical_update_capab(struct hostapd_data *hapd);
const char * sae_get_password(struct hostapd_data *hapd,
			      struct sta_info *sta, const u8 *rx_id,
			      size_t rx_id_len,
			      struct sae_password_entry **pw_entry,
			      struct sae_pt **s_pt, const struct sae_pk **s_pk);
struct sta_info * hostapd_ml_get_assoc_sta(struct hostapd_data *hapd,
					   struct sta_info *sta,
					   struct hostapd_data **assoc_hapd);
int hostapd_process_assoc_ml_info(struct hostapd_data *hapd,
				  struct sta_info *sta,
				  const u8 *ies, size_t ies_len,
				  bool reassoc, int tx_link_status,
				  bool offload,
				  bool *set_beacon);

void ml_deinit_link_reconf_req(struct link_reconf_req_list **req_list_ptr);
int ieee80211_ml_process_link(struct hostapd_data *hapd,
			      struct hostapd_data *phapd,
			      struct sta_info *origin_sta,
			      struct mld_link_info *link,
			      const u8 *ies, size_t ies_len,
			      enum link_parse_type type,
			      bool offload,
			      bool *set_beacon);

void ieee80211_ml_build_assoc_resp(struct hostapd_data *hapd,
				   struct hostapd_data *phapd,
				   struct sta_info *sta,
				   struct mld_link_info *link);

void ieee802_11_rx_protected_eht_action(struct hostapd_data *hapd,
					struct sta_info *sta,
					const struct ieee80211_mgmt *mgmt,
					size_t len);
void hostapd_link_reconf_resp_tx_status(struct hostapd_data *hapd,
					struct sta_info *sta,
					const struct ieee80211_mgmt *mgmt,
					size_t len, int ok);

#ifdef CONFIG_IEEE80211BE
void hostapd_epcs_timeout_handler(void *eloop_ctx, void *timeout_ctx);
#endif /* CONFIG_IEEE80211BE */
u8 * hostapd_fragment_multi_link_element(struct wpabuf *buf, u8 *pos);
#endif /* IEEE802_11_H */
