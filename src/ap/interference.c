/*
 * AWGN - Additive white Gaussian Noise
 * Copyright (c) 2002-2013, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2013-2017, Qualcomm Atheros, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

/*
 * Copyright (c) 2021 Qualcomm Innovation Center, Inc. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted (subject to the limitations in the disclaimer below) provided that
 * the following conditions are met:
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation and/or
 *   other materials provided with the distribution.
 * * Neither the name of Qualcomm Innovation Center, Inc. nor the names of its contributors
 *   may be used to endorse or promote products derived from this software without specific
 *   prior written permission.
 * NO EXPRESS OR IMPLIED LICENSES TO ANY PARTY'S PATENT RIGHTS ARE GRANTED BY THIS LICENSE.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "common/ieee802_11_defs.h"
#include "common/hw_features_common.h"
#include "common/wpa_ctrl.h"
#include "hostapd.h"
#include "ap_drv_ops.h"
#include "drivers/driver.h"
#include "beacon.h"
#include "eloop.h"
#include "hw_features.h"

static bool is_chan_disabled(struct hostapd_hw_modes *mode, int chan_num)
{
	int chan_disabled = 1;
	int i;
	struct hostapd_channel_data *temp_chan;

	for (i = 0; i < mode->num_channels; i++) {
		temp_chan = &mode->channels[i];
		if (temp_chan->chan == chan_num &&
		    (!(temp_chan->flag & HOSTAPD_CHAN_DISABLED))) {
			chan_disabled = 0;
			break;
		}
	}
	return chan_disabled;
}

/*
 * intf_awgn_chan_range_available - check whether the channel can operate
 * in the given bandwidth in 6Ghz
 * @first_chan_idx - channel index of the first 20Mhz channel in a segment
 * @num_chans - number of 20Mhz channels needed for the operating bandwidth
 */
static int intf_awgn_chan_range_available(struct hostapd_hw_modes *mode,
                                         int first_chan_idx, int num_chans)
{
	struct hostapd_channel_data *first_chan = NULL;
	int allowed_40_6g[] = {1, 9, 17, 25, 33, 41, 49, 57, 65, 73, 81, 89, 97, 105,
			       113, 121, 129, 137, 145, 153, 161, 169, 177, 185, 193,
			       201, 209, 217, 225, 233};
	int allowed_80_6g[] = {1, 17, 33, 49, 65, 81, 97, 113, 129, 145, 161, 177,
			       193, 209};
	int allowed_160_6g[] = {1, 33, 65, 97, 129, 161, 193};
	int allowed_320_6g[] = {1, 65, 129, 33, 97, 161};
	int allowed_arr_size = 0;
	int *allowed_arr = NULL;
	int i;

	first_chan = &mode->channels[first_chan_idx];

	if (!first_chan || !chan_pri_allowed(first_chan)) {
		wpa_printf(MSG_DEBUG, "AWGN: primary channel not allowed");
		return 0;
	}

	/* 20Mhz channel, so no need to check the range */
	if (num_chans == 1)
		return 1;

	switch (num_chans) {
	case 2:
		allowed_arr_size = ARRAY_SIZE(allowed_40_6g);
		allowed_arr = allowed_40_6g;
		break;
	case 4:
		allowed_arr_size = ARRAY_SIZE(allowed_80_6g);
		allowed_arr = allowed_80_6g;
		break;
	case 8:
		allowed_arr_size = ARRAY_SIZE(allowed_160_6g);
		allowed_arr = allowed_160_6g;
		break;
	case 16:
		allowed_arr_size = ARRAY_SIZE(allowed_320_6g);
		allowed_arr = allowed_320_6g;
		break;
	default:
		allowed_arr_size = 0;
		break;
	}

	for (i = 0; i < allowed_arr_size; i++) {
		if (first_chan->chan == allowed_arr[i])
			break;
	}

	if (i == allowed_arr_size)
		return 0;
	/* check whether all the 20 MHz channels in the given operating range is enabled */
	for (i = 1; i <= num_chans - 1; i++) {
		if (is_chan_disabled(mode, first_chan->chan + i * 4))
			return 0;
	}
	return 1;
}

/*
 * intf_afc_chan_range_available - check whether the channel can operate
 * in the given bandwidth in 6Ghz and is available in regulatory channel list
 * if its not available than mark as punctured in afc_bitmap
 * @num_chans - number of 20Mhz channels needed for the operating bandwidth
 * @afc_bitmap - pointer to afc puncture_bitmap, will carry punctured info
 * for unavailable channels.
 */
static void intf_afc_chan_range_available(struct hostapd_channel_data *chan_6ghz,
					  int num_chans, u16 *afc_bitmap)
{
	int i;

	for (i = 0; i < num_chans; i++) {
		if ((chan_6ghz->flag & HOSTAPD_CHAN_DISABLED) ||
		    (chan_6ghz->flag & HOSTAPD_CHAN_NO_IR)) {
			*afc_bitmap |= 1 << i;
			wpa_printf(MSG_DEBUG, "Freq [%d] is punctured. Flag: %x",
				   chan_6ghz->freq, chan_6ghz->flag);
		}
		chan_6ghz++;
	}
}

static int is_in_chanlist(struct hostapd_iface *iface,
			  struct hostapd_channel_data *chan)
{
	if (!iface->conf->acs_ch_list.num)
		return 1;

	return freq_range_list_includes(&iface->conf->acs_ch_list, chan->chan);
}

#define BASE_6G_FREQ 5950

int get_centre_freq_6g(int chan_idx, int chan_width, int *centre_freq)
{
	if (!centre_freq)
		return -1;

	*centre_freq = 0;

	switch (chan_width) {
	case CHAN_WIDTH_20:
		if (chan_idx >= 1 && chan_idx <= 233)
			*centre_freq = ((chan_idx / 4) * 4 + 1) * 5 + BASE_6G_FREQ;
		break;
	case CHAN_WIDTH_40:
		if (chan_idx >= 1 && chan_idx <= 229)
			*centre_freq = ((chan_idx / 8) * 8 + 3) * 5 + BASE_6G_FREQ;
		break;
	case CHAN_WIDTH_80:
		if (chan_idx >= 1 && chan_idx <= 221)
			*centre_freq = ((chan_idx / 16) * 16 + 7) * 5 + BASE_6G_FREQ;
		break;
	case CHAN_WIDTH_160:
		if (chan_idx >= 1 && chan_idx <= 221)
			*centre_freq = ((chan_idx / 32) * 32 + 15) * 5 + BASE_6G_FREQ;
		break;
	case CHAN_WIDTH_320:
		if (chan_idx >= 1 && chan_idx <= 221)
			*centre_freq = ((chan_idx / 32) * 32 + 31) * 5 + BASE_6G_FREQ;
	default:
		break;
	}

	if (*centre_freq == 0)
		return -1;

	return 0;
}

static int is_interference_in_chanlist(int freq_start, int freq_end,
					int *awgn_interference_freqs)
{
	int i, j;

	for (i = freq_start; i <= freq_end; i += 20) {
		for (j = 0; j < BW_INTERFERENCE_MAXBITS; j++) {
			if (awgn_interference_freqs[j] == i)
				return 1;
		}
	}
	return 0;
}

/*
 * intf_awgn_find_channel_list - find the list of channels that can operate with
   channel width chan_width and not present within the range of current operating range.
   returns the total number of available chandefs that supports the provided bandwidth
 * @chan_width - channel width to be checked
 * @chandef_list - pointer array to hold the list of valid available chandef
 */
static int intf_awgn_find_channel_list(struct hostapd_iface *iface, int chan_width,
				       struct hostapd_channel_data ***chandef_list,
				       int *awgn_interference_freqs)
{
	struct hostapd_hw_modes *mode = iface->current_mode;
	struct hostapd_channel_data *chan;
	int i, channel_idx = 0, n_chans;
	int new_centre_freq;
	int new_start_freq;
	int new_end_freq;
	int ret;

	switch (chan_width) {
	case CHAN_WIDTH_20_NOHT:
	case CHAN_WIDTH_20:
		n_chans = 1;
		break;
	case CHAN_WIDTH_40:
		n_chans = 2;
		break;
	case CHAN_WIDTH_80:
		n_chans = 4;
		break;
	case CHAN_WIDTH_80P80:
	case CHAN_WIDTH_160:
		n_chans = 8;
		break;
	case CHAN_WIDTH_320:
		n_chans = 16;
		break;
	default:
		n_chans = 1;
		break;
	}

	for (i = 0; i < mode->num_channels; i++) {
		chan = &mode->channels[i];

		if (!chan_in_current_hw_info(iface->current_hw_info, chan)) {
			wpa_printf(MSG_DEBUG,
				   "AWGN: channel %d (%d) is not under current hardware index",
				   chan->freq, chan->chan);
			continue;
		}

		/* Skip incompatible chandefs */
		if (!intf_awgn_chan_range_available(mode, i, n_chans)) {
			wpa_printf(MSG_DEBUG,
				   "AWGN: range not available for %d (%d)",
				   chan->freq, chan->chan);
			continue;
		}

		if (!is_in_chanlist(iface, chan)) {
			wpa_printf(MSG_DEBUG,
				   "AWGN: channel %d (%d) not in chanlist",
				   chan->freq, chan->chan);
			continue;
		}

		ret = get_centre_freq_6g(chan->chan, chan_width,
					 &new_centre_freq);
		if (ret) {
			wpa_printf(MSG_ERROR,
				   "AWGN : couldn't find centre freq for chan : %d"
				   " chan_width : %d", chan->chan, chan_width);
			return 0;
		}

               new_start_freq = (new_centre_freq - channel_width_to_int(chan_width) / 2) + 10;
               new_end_freq = (new_centre_freq + channel_width_to_int(chan_width) / 2) - 10;

               if (is_interference_in_chanlist(new_start_freq, new_end_freq,
                                                   awgn_interference_freqs)) {
			wpa_printf(MSG_DEBUG,
				   "AWGN: found frequency which has interference in channel (%d)",
				   chan->chan);
			continue;
		}

		wpa_printf(MSG_DEBUG, "AWGN: Adding channel %d (%d) to valid chandef list",
			   chan->freq, chan->chan);
		(*chandef_list)[channel_idx] = chan;
		channel_idx++;
	}
	return channel_idx;
}

static int convert_chwidth_to_20MHz_nchans(enum chan_width chan_width)
{
	int n_chans;

	switch (chan_width) {
	case CHAN_WIDTH_20_NOHT:
	case CHAN_WIDTH_20:
		n_chans = 1;
		break;
	case CHAN_WIDTH_40:
		n_chans = 2;
		break;
	case CHAN_WIDTH_80:
		n_chans = 4;
		break;
	case CHAN_WIDTH_80P80:
	case CHAN_WIDTH_160:
		n_chans = 8;
		break;
	case CHAN_WIDTH_320:
		n_chans = 16;
		break;
	default:
		n_chans = 1;
		break;
	}

	return n_chans;
}

int get_next_max_width(int chan_width)
{
	int next_max_width;

	switch (chan_width) {
	case CHAN_WIDTH_320:
		next_max_width = CHAN_WIDTH_160;
		break;
	case CHAN_WIDTH_160:
		next_max_width = CHAN_WIDTH_80;
		break;
	case CHAN_WIDTH_80:
		next_max_width = CHAN_WIDTH_40;
		break;
	case CHAN_WIDTH_40:
		next_max_width = CHAN_WIDTH_20;
		break;
	default:
		next_max_width = CHAN_WIDTH_20_NOHT;
		break;
	}

	return next_max_width;
}

/*
 * find_6g_chan_20_40 - When AFC response will recieve than this function
 * will fill 6GHz band 40 MHz and 20 MHz available channels.
 * If afc_bitmap is nonzero then the 40 MHz channel has a NO_IR (non-Tx)
 * subchannel. So ignore it. The reduced bandwidth channel (20 MHz channel)
 * is picked up when the 20MHz bandwidth channel is process by the caller.
 */
static void find_6g_chan_20_40(struct hostapd_channel_data *chan,
			       u16 afc_bitmap, int *channel_idx,
			       struct hostapd_channel_data **chandef_list)
{
	if (!afc_bitmap) {
		wpa_printf(MSG_DEBUG,
			   "AFC: Adding channel %d (%d) to valid chandef list with puncture pattern 0x%x",
			   chan->freq, chan->chan, chan->punct_bitmap);
		(*chandef_list)[*channel_idx] = *chan;
		(*channel_idx)++;
	}
}

/*
 * find_6g_chan_gt_40 - When AFC response will recieve than this function
 * will fill 6GHz band 80, 160, 320 MHz available channels with puncture
 * patterns.
 */
static void find_6g_chan_gt_40(struct hostapd_channel_data *chan,
			       int new_start_freq, int channel_width,
			       u16 afc_bitmap, int *channel_idx,
			       struct hostapd_channel_data **chandef_list)
{
	u16 pri_chan_pos;
	const u16 *bw_pp_arr;
	u16 num_pp, pp_mask;
	int i;

	pri_chan_pos = (chan->freq - new_start_freq) / 20;
	bw_pp_arr = hostapd_get_valid_puncture_pattern_arr(channel_width,
							   &num_pp, &pp_mask);
	if (!bw_pp_arr) {
		wpa_printf(MSG_ERROR,
			   "No valid puncture pattern array for bw %d", channel_width);
		return;
	}

	for (i = 0; i < num_pp; i++) {
		u16 temp_bitmap;

		temp_bitmap = ((afc_bitmap | bw_pp_arr[i]) & pp_mask);
		if (!is_punct_bitmap_valid(channel_width, pri_chan_pos, temp_bitmap)) {
			wpa_printf(MSG_DEBUG,
				   "Invalid PP: 0x%x, bw: %d, pri_chan_pos: %d",
				   temp_bitmap, channel_width, pri_chan_pos);
			continue;
		}

		wpa_printf(MSG_DEBUG,
			   "AFC: Adding channel %d (%d) to valid chandef list with puncture pattern 0x%x",
			   chan->freq, chan->chan, temp_bitmap);
		(*chandef_list)[*channel_idx] = *chan;
		(*chandef_list)[*channel_idx].punct_bitmap = temp_bitmap;
		(*channel_idx)++;
	}
}

static int find_6g_enabled_chans(struct hostapd_iface *iface,
				 int chan_width,
				 struct hostapd_channel_data **chandef_list,
				 struct hostapd_hw_modes *mode,
				 struct hostapd_channel_data **chan_6ghz,
				 int n_chans, int power_type)
{
	int i, channel_idx = 0;

	for (i = 0; i < mode->num_channels; i++) {
		struct hostapd_channel_data *chan;
		struct hostapd_channel_data *chan_6ghz_list;
		int channel_width;
		int new_centre_freq, new_start_freq, ret;
		u8 num_channels_6ghz, chan_idx;
		u16 afc_bitmap = 0;

		chan = &chan_6ghz[power_type][i];

		if (!chan_in_current_hw_info(iface->current_hw_info, chan)) {
			wpa_printf(MSG_DEBUG,
				   "AFC: channel %d (%d) is not under current hardware index",
				   chan->freq, chan->chan);
			continue;
		}

		if (!is_in_chanlist(iface, chan)) {
			wpa_printf(MSG_DEBUG, "AFC: channel %d (%d) not in chanlist",
				   chan->freq, chan->chan);
			continue;
		}

		ret = get_centre_freq_6g(chan->chan, chan_width, &new_centre_freq);
		if (ret) {
			wpa_printf(MSG_ERROR,
				   "AFC : couldn't find centre freq for chan : %d chan_width : %d",
				   chan->chan, chan_width);
			continue;
		}

		channel_width = channel_width_to_int(chan_width);
		new_start_freq = (channel_width == 20) ?
			chan->freq : new_centre_freq - (channel_width / 2) + 10;
		chan_6ghz_list = hostapd_iface_get_6ghz_chan_list(iface,
								  new_start_freq,
								  power_type,
								  &num_channels_6ghz,
								  &chan_idx);
		if (!chan_6ghz_list) {
			wpa_printf(MSG_ERROR, "Failed to get a 6ghz channel list");
			continue;
		}

		if (chan_idx + n_chans > num_channels_6ghz) {
			wpa_printf(MSG_ERROR, "Invalid channel index");
			continue;
		}

		intf_afc_chan_range_available(chan_6ghz_list, n_chans, &afc_bitmap);
		if (channel_width < 80) {
			find_6g_chan_20_40(chan, afc_bitmap,
					   &channel_idx, chandef_list);
		} else {
			find_6g_chan_gt_40(chan, new_start_freq, channel_width,
					   afc_bitmap, &channel_idx, chandef_list);
		}
	}

	return channel_idx;
}

/*
 * intf_afc_find_channel_list - find the list of channels that can operate with
   channel width chan_width and present within the range ofi regulatory channel
   list. returns the total number of available chandefs that supports the
   provided bandwidth
 * @chan_width - pointer to current channel width
 * @chandef_list - array to hold the list of valid available chandef
 * @best_ap_pwr_mode - pointer to best power mode
 */
static int intf_afc_find_channel_list(struct hostapd_iface *iface,
				      int *chan_width,
				      struct hostapd_channel_data **chandef_list,
				      int *best_ap_pwr_mode)
{
	struct hostapd_hw_modes *mode = iface->current_mode;
	struct hostapd_channel_data_6ghz *channels_6g_data = &mode->channels_6ghz;
	struct hostapd_channel_data **chan_6ghz  = channels_6g_data->chans_6ghz;
	static const enum nl80211_regulatory_power_modes pwr_mode_order[] = {
		NL80211_REG_AP_SP,
		NL80211_REG_AP_LPI,
		NL80211_REG_AP_VLP};
	int i, n_chans;
	int start_chan_width = *chan_width;

	for (i = 0; i < ARRAY_SIZE(pwr_mode_order); i++) {
		enum nl80211_regulatory_power_modes pwr_mode;
		int n_en_chans;

		*chan_width = start_chan_width;
		pwr_mode = pwr_mode_order[i];
		while (*chan_width > CHAN_WIDTH_20_NOHT) {
			n_chans = convert_chwidth_to_20MHz_nchans(*chan_width);
			n_en_chans = find_6g_enabled_chans(iface, *chan_width, chandef_list,
							   mode, chan_6ghz, n_chans, pwr_mode);
			if (n_en_chans > 0)
				break;
			*chan_width = get_next_max_width(*chan_width);
		}
		if (!n_en_chans)
			continue;
		*best_ap_pwr_mode = pwr_mode;

		return n_en_chans;
	}

	return 0;
}

enum chan_seg {
	SEG_PRI20		  = 0x1,
	SEG_SEC20		  = 0x2,
	SEG_SEC40_LOW		  = 0x4,
	SEG_SEC40_UP		  = 0x8,
	SEG_SEC40		  = 0xC,
	SEG_SEC80_LOW		  = 0x10,
	SEG_SEC80_LOW_UP	  = 0x20,
	SEG_SEC80_UP_LOW	  = 0x40,
	SEG_SEC80_UP		  = 0x80,
	SEG_SEC80		  = 0xF0,
	SEG_SEC160_LOW		  = 0x0100,
	SEG_SEC160_LOW_UP	  = 0x0200,
	SEG_SEC160_LOW_UP_UP	  = 0x0400,
	SEG_SEC160_LOW_UP_UP_UP   = 0x0800,
	SEG_SEC160_UP_LOW_LOW_LOW = 0x1000,
	SEG_SEC160_UP_LOW_LOW	  = 0x2000,
	SEG_SEC160_UP_LOW	  = 0x4000,
	SEG_SEC160_UP		  = 0x8000,
	SEG_SEC160		  = 0xFF00,
};

/*
 * hostapd_intf_awgn_detected - awgn interference is detected in the operating channel.
 * The interference channel information is available as a
 * bitmap(chan_bw_interference_bitmap). If interference has occurred in the
 * primary channel, do a complete channel switch to a different channel else
 * reduce the operating bandwidth and continue ap operation in the same channel.
 */
int hostapd_intf_awgn_detected(struct hostapd_iface *iface, int freq, int chan_width,
			       int cf1, int cf2, u32 chan_bw_interference_bitmap)
{
	struct csa_settings settings;
	struct hostapd_channel_data *chan_data = NULL;
	struct hostapd_channel_data *chan_temp = NULL;
	struct hostapd_channel_data **available_chandef_list = NULL;
	int ret;
	unsigned int i;
	u32 _rand;
	u32 chan_idx;
	int num_available_chandefs = 0;
	u8 channel_switch = 0;
	int new_chan_width;
	int new_centre_freq;
	int current_start_freq;
	int temp_width;
	struct hostapd_hw_modes *mode = iface->current_mode;
	int awgn_interference_freqs[BW_INTERFERENCE_MAXBITS] = {};

	wpa_printf(MSG_DEBUG,
		   "input freq=%d, chan_width=%d, cf1=%d cf2=%d"
		   " chan_bw_interference_bitmap=0x%x",
		   freq,
		   chan_width,
		   cf1, cf2, chan_bw_interference_bitmap);

	if (iface->conf->discard_6g_awgn_event) {
		wpa_printf(MSG_DEBUG, "discard_6g_awgn_event set ignoring"
			   " AWGN DETECT event from driver");
		return 0;
	}

	/* check whether interference has occurred in primary 20Mhz channel */
	if (!chan_bw_interference_bitmap || (chan_bw_interference_bitmap & SEG_PRI20))
		channel_switch = 1;

	available_chandef_list = os_zalloc(sizeof(struct hostapd_channel_data *) *
					   mode->num_channels);
	if (!available_chandef_list) {
		wpa_printf(MSG_ERROR, "available_chandef_list memory allocation failed");
		goto exit;
	}

	if (channel_switch) {
		/* store frequencies with interference in awgn_interference_freqs */
		current_start_freq = (cf1 - channel_width_to_int(chan_width) / 2) + 10;
		for (i = 0; i < BW_INTERFERENCE_MAXBITS; i++) {
			if ((1 << i) & chan_bw_interference_bitmap) {
				wpa_printf(MSG_DEBUG,
					   "AWGN: found awgn interference in frequency %d",
					   current_start_freq + (20 * i));
				awgn_interference_freqs[i] = current_start_freq + (20 * i);
			}
		}
		/* find a random channel to be switched */
		temp_width = chan_width;

		while (temp_width > CHAN_WIDTH_20_NOHT) {
			num_available_chandefs = intf_awgn_find_channel_list(iface, temp_width,
									     &available_chandef_list,
									     awgn_interference_freqs);
			if (num_available_chandefs > 0)
				break;
			temp_width = get_next_max_width(temp_width);
		}

		if (num_available_chandefs == 0) {
			wpa_printf(MSG_ERROR, "AWGN: no available_chandefs");
			goto exit;
		}

		if (os_get_random((u8 *)&_rand, sizeof(_rand)) < 0) {
			wpa_printf(MSG_ERROR, "AWGN: couldn't get random number");
			goto exit;
		}

		chan_idx = _rand % num_available_chandefs;

		chan_data = available_chandef_list[chan_idx];

		if (!chan_data) {
			wpa_printf(MSG_ERROR, "AWGN: channel info not available for chan_idx : %d",
				   chan_idx);
			goto exit;
		}

		new_chan_width = temp_width;

		wpa_printf(MSG_DEBUG, "AWGN: got random channel %d (%d)",
			   chan_data->freq, chan_data->chan);
	} else {
		/* interference is not present in the primary 20Mhz, so reduce bandwidth*/
		for (i = 0; i < mode->num_channels; i++) {
			chan_temp = &mode->channels[i];
			if (chan_temp->freq == freq)
				chan_data = chan_temp;
		}
		if (!chan_data) {
			wpa_printf(MSG_ERROR, "AWGN : no channel found");
			goto exit;
		}

		if ((chan_width > CHAN_WIDTH_160) &&
		    !(chan_bw_interference_bitmap & SEG_SEC80) &&
		    !(chan_bw_interference_bitmap & SEG_SEC40) &&
		    !(chan_bw_interference_bitmap & SEG_SEC20))
			new_chan_width = CHAN_WIDTH_160;
		else if ((chan_width > CHAN_WIDTH_80) &&
		    !(chan_bw_interference_bitmap & SEG_SEC40) &&
		    !(chan_bw_interference_bitmap & SEG_SEC20))
			new_chan_width = CHAN_WIDTH_80;
		else if (chan_width > CHAN_WIDTH_40 &&
			 !(chan_bw_interference_bitmap & SEG_SEC20))
			new_chan_width = CHAN_WIDTH_40;
		else
			new_chan_width = CHAN_WIDTH_20;
	}

	if (new_chan_width > CHAN_WIDTH_20) {
		ret = get_centre_freq_6g(chan_data->chan, new_chan_width,
					 &new_centre_freq);
		if (ret) {
			wpa_printf(MSG_ERROR,
				   "AWGN : couldn't find centre freq for chan : %d"
				   " chan_width : %d", chan_data->chan, new_chan_width);
			goto exit;
		}
	} else {
		new_centre_freq = chan_data->freq;
	}

	os_memset(&settings, 0, sizeof(settings));
	settings.cs_count = 5;
	settings.freq_params.freq = chan_data->freq;

	switch (new_chan_width) {
	case CHAN_WIDTH_40:
		settings.freq_params.bandwidth = 40;
		break;
	case CHAN_WIDTH_80P80:
	case CHAN_WIDTH_80:
		settings.freq_params.bandwidth = 80;
		break;
	case CHAN_WIDTH_160:
		settings.freq_params.bandwidth = 160;
		break;
	case CHAN_WIDTH_320:
		settings.freq_params.bandwidth = 320;
		break;
	default:
		settings.freq_params.bandwidth = 20;
		break;
	}

	settings.freq_params.center_freq1 = new_centre_freq;
	settings.freq_params.ht_enabled = iface->conf->ieee80211n;
	settings.freq_params.vht_enabled = iface->conf->ieee80211ac;
	settings.freq_params.he_enabled = iface->conf->ieee80211ax;
	settings.freq_params.eht_enabled= iface->conf->ieee80211be;
	settings.power_mode = -1;

	for (i = 0; i < iface->num_bss; i++) {
		/* Save CHAN_SWITCH VHT and HE config */
		hostapd_chan_switch_config(iface->bss[i],
					   &settings.freq_params);

		wpa_printf(MSG_DEBUG,
			   "channel=%u, freq=%d, bw=%d, center_freq1=%d",
			   settings.freq_params.channel,
			   settings.freq_params.freq,
			   settings.freq_params.bandwidth,
			   settings.freq_params.center_freq1);

		ret = hostapd_switch_channel(iface->bss[i], &settings);
		if (ret) {
			/* FIX: What do we do if CSA fails in the middle of
			 * submitting multi-BSS CSA requests?
			 */
			return ret;
		}
	}

exit:
	os_free(available_chandef_list);
	return 0;
}

static int get_random_channel(struct hostapd_channel_data *chan_data,
			      struct hostapd_channel_data *available_chandef_list,
			      int *chan_idx, int num_available_chandefs)
{
	u32 _rand;

	if (os_get_random((u8 *)&_rand, sizeof(_rand)) < 0) {
		wpa_printf(MSG_ERROR, "AFC: couldn't get random number");
		return  -1;
	}

	*chan_idx = _rand % num_available_chandefs;
	*chan_data = available_chandef_list[*chan_idx];

	return 0;
}

static int get_new_center_freq(struct hostapd_channel_data *chan_data,
			       int chan_width, int *new_centre_freq)
{
	int ret = 0;

	if (chan_width > CHAN_WIDTH_20) {
		ret = get_centre_freq_6g(chan_data->chan, chan_width, new_centre_freq);
		if (ret) {
			wpa_printf(MSG_ERROR,
				   "AFC : couldn't find centre freq for chan : %d chan_width : %d",
				   chan_data->chan, chan_width);
			return ret;
		}
	} else {
		*new_centre_freq = chan_data->freq;
	}

	return ret;
}

static void set_csa_param(struct csa_settings *settings,
			  struct hostapd_channel_data *chan_data,
			  struct hostapd_iface *iface, int chan_width,
			  int centre_freq)
{
	os_memset(settings, 0, sizeof(*settings));
	settings->cs_count = 5;
	settings->freq_params.freq = chan_data->freq;
	settings->freq_params.bandwidth = channel_width_to_int(chan_width);
	settings->freq_params.center_freq1 = centre_freq;
	settings->freq_params.punct_bitmap = chan_data->punct_bitmap;
	settings->freq_params.ht_enabled = iface->conf->ieee80211n;
	settings->freq_params.vht_enabled = iface->conf->ieee80211ac;
	settings->freq_params.he_enabled = iface->conf->ieee80211ax;
	settings->freq_params.eht_enabled = iface->conf->ieee80211be;
	settings->power_mode = -1;

	if (is_6ghz_freq(settings->freq_params.freq) &&
	    iface->conf->enable_best_power_mode) {
		int best_power_mode;

		best_power_mode =
			hostapd_get_best_ap_6ghz_power_mode(iface,
							    settings->freq_params.freq,
							    settings->freq_params.center_freq1,
							    settings->freq_params.bandwidth,
							    settings->freq_params.punct_bitmap);
		if (best_power_mode != NL80211_REG_NUM_POWER_MODES) {
			settings->power_mode = best_power_mode;
			iface->power_mode_6ghz_before_change = best_power_mode;
			wpa_printf(MSG_DEBUG, "%s: Best power mode for Freq %d is %d",
				   __func__,
				   settings->freq_params.freq,
				   settings->power_mode);
		}
	}
}

/*
 * @ACT_FIND_EIRPMAX   : Action of  finding maximum EIRP from an array of EIRPs
 * @ACT_FILTER_MAXEIRP : Action of  filtering an array and creating a new array
 *                       with a given value.
 */
enum eirp_array_action {
	ACT_FIND_EIRPMAX = 0,
	ACT_FILTER_MAXEIRP = 1
};

static int iterate_eirp_array(struct hostapd_iface *iface,
			      int chan_width, int best_ap_pwr_mode,
			      struct hostapd_channel_data *available_chandef_list,
			      int n_chans, int *max_eirp_pwr,
			      struct hostapd_channel_data **max_eirp_chandef_list,
			      int *max_eirp_nchans, int action)
{
	int i;
	int ret = 0;
	int channel_width;
	int channel_idx = 0;

	channel_width = channel_width_to_int(chan_width);
	for (i = 0; i < n_chans; i++) {
		int center_freq;
		int tmp_eirp_pwr;

		if (get_new_center_freq(&available_chandef_list[i], chan_width, &center_freq)) {
			ret = -1;
			return ret;
		}
		tmp_eirp_pwr = hostapd_get_eirp_pwr(iface,
						    available_chandef_list[i].freq,
						    center_freq, channel_width,
						    available_chandef_list[i].punct_bitmap,
						    best_ap_pwr_mode,
						    false,
						    NL80211_REG_NUM_POWER_MODES,
						    false);
		if (action == ACT_FIND_EIRPMAX) {
			if (tmp_eirp_pwr > *max_eirp_pwr)
				*max_eirp_pwr = tmp_eirp_pwr;
		} else if (action == ACT_FILTER_MAXEIRP) {
			if (tmp_eirp_pwr == *max_eirp_pwr) {
				(*max_eirp_chandef_list)[channel_idx] = available_chandef_list[i];
				channel_idx++;
			}
		}
	}

	if (action == ACT_FILTER_MAXEIRP)
		*max_eirp_nchans = channel_idx;

	return ret;
}

static int find_max_eirp_pwr(struct hostapd_iface *iface,
			     int chan_width, int best_ap_pwr_mode,
			     struct hostapd_channel_data *available_chandef_list,
			     int n_chans, int *max_eirp_pwr)
{
	return iterate_eirp_array(iface, chan_width, best_ap_pwr_mode,
				  available_chandef_list, n_chans,
				  max_eirp_pwr, NULL, NULL, ACT_FIND_EIRPMAX);
}

static int fill_max_eirp_chandef_list(struct hostapd_iface *iface,
				      int chan_width, int best_ap_pwr_mode,
				      struct hostapd_channel_data *available_chandef_list,
				      int n_chans,
				      struct hostapd_channel_data **max_eirp_chandef_list,
				      int *max_eirp_nchans, int max_eirp_pwr)
{
	return iterate_eirp_array(iface, chan_width, best_ap_pwr_mode,
				  available_chandef_list, n_chans,
				  &max_eirp_pwr, max_eirp_chandef_list,
				  max_eirp_nchans, ACT_FILTER_MAXEIRP);
}

static int find_afc_random_chan(struct hostapd_hw_modes *mode,
				struct hostapd_iface *iface, int *chan_width,
				struct hostapd_channel_data *chan_data, int *chan_idx)
{
	struct hostapd_channel_data *available_chandef_list;
	struct hostapd_channel_data *max_eirp_chandef_list;
	int num_available_chandefs;
	int max_eirp_pwr = CHAN_MIN_TX_POWER;
	int best_ap_pwr_mode = NL80211_REG_NUM_POWER_MODES;
	int max_eirp_nchans;
	int channel_width;
	int num_pp;
	int ret = 0;

	channel_width = channel_width_to_int(*chan_width);
	num_pp = hostapd_get_num_pp(channel_width);
	available_chandef_list = os_zalloc(sizeof(struct hostapd_channel_data) *
					   (mode->num_channels * num_pp));
	if (!available_chandef_list) {
		wpa_printf(MSG_ERROR, "available_chandef_list memory allocation failed");
		ret = -1;
		goto free_chandef_list;
	}

	num_available_chandefs = intf_afc_find_channel_list(iface, chan_width,
							    &available_chandef_list,
							    &best_ap_pwr_mode);
	if (num_available_chandefs == 0) {
		wpa_printf(MSG_ERROR, "AFC: no available_chandefs");
		ret = -1;
		goto free_chandef_list;
	}

	if (find_max_eirp_pwr(iface, *chan_width, best_ap_pwr_mode,
			      available_chandef_list, num_available_chandefs,
			      &max_eirp_pwr)) {
		wpa_printf(MSG_ERROR, "AFC: could not able to find max eirp power");
		ret = -1;
		goto free_chandef_list;
	}

	max_eirp_chandef_list = os_zalloc(sizeof(struct hostapd_channel_data) *
					  num_available_chandefs);
	if (!max_eirp_chandef_list) {
		wpa_printf(MSG_ERROR, "max_eirp_chandef_list memory allocation failed");
		ret = -1;
		goto free_eirp_list;
	}

	if (fill_max_eirp_chandef_list(iface, *chan_width, best_ap_pwr_mode,
				       available_chandef_list, num_available_chandefs,
				       &max_eirp_chandef_list, &max_eirp_nchans,
				       max_eirp_pwr)) {
		wpa_printf(MSG_ERROR, "AFC: could not able to fill max eirp chan list");
		ret = -1;
		goto free_eirp_list;
	}
	if (get_random_channel(chan_data, max_eirp_chandef_list, chan_idx,
			       max_eirp_nchans)) {
		ret = -1;
		goto free_eirp_list;
	}

free_eirp_list:
	os_free(max_eirp_chandef_list);
free_chandef_list:
	os_free(available_chandef_list);

	return ret;
}

/*
 * hostapd_intf_afc_received- afc request is recieved.
 * select random channel according to the availbilty .
 * starting with sp , if sp not possible than LPI, if LPI not
 * possible than vlp.
 * Do the CSA according to the selected channel.
 */
int hostapd_intf_afc_received(struct hostapd_iface *iface)
{
	struct csa_settings settings;
	struct hostapd_channel_data *chan_data;
	int ret = 0;
	unsigned int i;
	int chan_idx;
	int chan_width;
	int new_chan_width;
	int new_centre_freq;
	struct hostapd_hw_modes *mode = iface->current_mode;

	chan_width = hostapd_get_chan_width_from_oper_chan_width(iface->conf);
	wpa_printf(MSG_DEBUG, "chan_width=%d", chan_width);

	chan_data = os_zalloc(sizeof(struct hostapd_channel_data));
	if (!chan_data) {
		wpa_printf(MSG_ERROR, "chan_data memory allocation failed");
		ret = -1;
		goto free_chan_data;
	}

	if (find_afc_random_chan(mode, iface, &chan_width,
				 chan_data, &chan_idx)) {
		ret = -1;
		goto free_chan_data;
	}

	wpa_printf(MSG_DEBUG, "AFC: got random channel %d (%d)",
		   chan_data->freq, chan_data->chan);
	new_chan_width = chan_width;
	if (get_new_center_freq(chan_data, new_chan_width, &new_centre_freq)) {
		ret = -1;
		goto free_chan_data;
	}

	set_csa_param(&settings, chan_data, iface, new_chan_width, new_centre_freq);
	for (i = 0; i < iface->num_bss; i++) {
		/* Save CHAN_SWITCH VHT and HE config */
		hostapd_chan_switch_config(iface->bss[i], &settings.freq_params);
		wpa_printf(MSG_DEBUG,
			   "channel=%u, freq=%d, bw=%d, pp 0x%x, center_freq1=%d, power_mode=%d",
			   settings.freq_params.channel,
			   settings.freq_params.freq,
			   settings.freq_params.bandwidth,
			   settings.freq_params.punct_bitmap,
			   settings.freq_params.center_freq1,
			   settings.power_mode);

		ret = hostapd_switch_channel(iface->bss[i], &settings);
		if (ret) {
			/* FIX: What do we do if CSA fails in the middle of
			 * submitting multi-BSS CSA requests?
			 */
			break;
		}
	}

free_chan_data:
	os_free(chan_data);

	return ret;
}
