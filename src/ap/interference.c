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
