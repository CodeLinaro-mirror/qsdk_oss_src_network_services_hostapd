/*
 * Common hostapd/wpa_supplicant HW features
 * Copyright (c) 2002-2013, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2015, Qualcomm Atheros, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef HW_FEATURES_COMMON_H
#define HW_FEATURES_COMMON_H

#include "drivers/driver.h"

struct hostapd_channel_data * hw_get_channel_chan(struct hostapd_hw_modes *mode,
						  int chan, int *freq);
struct hostapd_channel_data *
hw_mode_get_channel(struct hostapd_hw_modes *mode, int freq, int *chan);

/**
 * hw_mode_get_6ghz_power_mode_channel() - Find the 6 GHz channel data for the given freq
 * @hw_features: Pointer to HW features
 * @num_hw_features: Number of HW features present
 * @freq: Frequency in MHz
 * @pwr_type: Power type
 * @num_channels_6ghz: Output pointer to number of 6 GHz channels
 * @chan_idx: Output pointer to channel index for the given frequency
 * @fallback: Whether to get base 6 GHz channel data if power mode channel are not
 * present
 *
 * Return: Pointer to hostapd_channel_data
 */
struct hostapd_channel_data *
hw_mode_get_6ghz_power_mode_channel(struct hostapd_hw_modes *hw_features,
				    int num_hw_features,
				    u16 freq, u8 pwr_type,
				    u8 *num_channels_6ghz, u8 *chan_idx,
				    bool fallback);

struct hostapd_channel_data *
hw_get_channel_freq(enum hostapd_hw_mode mode, int freq, int *chan,
		    struct hostapd_hw_modes *hw_features, int num_hw_features);

int hw_get_freq(struct hostapd_hw_modes *mode, int chan);
int hw_get_chan(enum hostapd_hw_mode mode, int freq,
		struct hostapd_hw_modes *hw_features, int num_hw_features);

int allowed_ht40_channel_pair(enum hostapd_hw_mode mode,
			      struct hostapd_channel_data *p_chan,
			      struct hostapd_channel_data *s_chan);
void get_pri_sec_chan(struct wpa_scan_res *bss, int *pri_chan, int *sec_chan);
int check_40mhz_5g(struct wpa_scan_results *scan_res,
		   struct hostapd_channel_data *pri_chan,
		   struct hostapd_channel_data *sec_chan);
#ifdef CONFIG_QCN_EXTN
struct check_40mhz_2g4_extn_args;
#endif /* CONFIG_QCN_EXTN */

int check_40mhz_2g4(struct hostapd_hw_modes *mode,
		    struct wpa_scan_results *scan_res, int pri_chan,
		    int sec_chan
#ifdef CONFIG_QCN_EXTN
		    , const struct check_40mhz_2g4_extn_args *extn_args
#endif /* CONFIG_QCN_EXTN */
		    );
void punct_update_legacy_bw(u16 bitmap, u8 pri_chan,
			    enum oper_chan_width *width, u8 *seg0, u8 *seg1);

/* Channel information to derive frequency parameters from */
struct hostapd_channel_info {
	enum hostapd_hw_mode mode;

	int freq;
	int channel;
	enum oper_chan_width oper_chwidth;

	/* EDMG */
	struct {
		int enabled;
		u8 channel;
	} edmg;

	struct {
		int enabled;
		int sec_channel_offset;
	} ht;

	int center_segment0;

	/* Only valid for 80+80 */
	int center_segment1;

	struct {
		int enabled;
		u32 caps;
	} vht;

	struct {
		int enabled;
		const struct he_capabilities *cap;
	} he;

	struct {
		int enabled;
		const struct eht_capabilities *cap;
		u16 punct_bitmap;
	} eht;

	/**
	 * he_6ghz_reg_pwr_type - 6 GHz regulatory power mode.
	 */
	u8 he_6ghz_reg_pwr_type;

	struct {
		bool enabled;
		const struct uhr_capabilities *cap;
		u8 dbe_bandwidth;
		u16 dbe_punct_bitmap;
		int npca_freq;
		u16 npca_punct_bitmap;
	} uhr;
	int bandwidth_device;
	int center_freq_device;
};

int hostapd_set_freq_params(struct hostapd_freq_params *data,
				    const struct hostapd_channel_info *info);
void set_disable_ht40(struct ieee80211_ht_capabilities *htcaps,
		      int disabled);
int ieee80211ac_cap_check(u32 hw, u32 conf);

u32 num_chan_to_bw(int num_chans);
int chan_bw_allowed(const struct hostapd_channel_data *chan, u32 bw,
		    int ht40_plus, int pri);
int chan_pri_allowed(const struct hostapd_channel_data *chan);
u16 hostapd_get_num_pp(u16 bw);
bool is_punct_bitmap_valid(u16 bw, u16 pri_ch_bit_pos, u16 punct_bitmap);
bool chan_in_current_hw_info(struct hostapd_multi_hw_info *current_hw_info,
			     struct hostapd_channel_data *chan);

#endif /* HW_FEATURES_COMMON_H */
