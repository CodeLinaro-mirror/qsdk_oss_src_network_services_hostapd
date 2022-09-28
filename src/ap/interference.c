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
	int chan_idx_match = 0;
	int i;

	first_chan = &mode->channels[first_chan_idx];

	if (!first_chan || !chan_pri_allowed(first_chan)) {
		wpa_printf(MSG_DEBUG, "AWGN: primary channel not allowed");
		return 0;
	}

	/* 20Mhz channel, so no need to check the range */
	if (num_chans == 1)
		return 1;

	if (num_chans == 2) { /* 40Mhz channel */
		for (i = 0; i < ARRAY_SIZE(allowed_40_6g); i++) {
			if (first_chan->chan == allowed_40_6g[i]) {
				chan_idx_match = 1;
				break;
			}
		}
	} else if (num_chans == 4) { /* 80Mhz channel */
		for (i = 0; i < ARRAY_SIZE(allowed_80_6g); i++) {
			if (first_chan->chan == allowed_80_6g[i]) {
				chan_idx_match = 1;
				break;
			}
		}
	} else if (num_chans == 8) { /* 160Mhz channel */
		for (i = 0; i < ARRAY_SIZE(allowed_160_6g); i++) {
			if (first_chan->chan == allowed_160_6g[i]) {
				chan_idx_match = 1;
				break;
			}
		}
	} else if (num_chans == 16) { /* 320Mhz channel */
		for (i = 0; i < ARRAY_SIZE(allowed_320_6g); i++) {
			if (first_chan->chan == allowed_320_6g[i]) {
				chan_idx_match = 1;
				break;
			}
		}
	}

	if (chan_idx_match == 1)
		return 1;

	return 0;
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


/*
 *intf_awgn_find_channel - find the channel that can operate with bandwidth chan_width.
  If idx doesn't match with index of any of the existing channel, then the api
  returns the total number of available chandefs that supports the provided bandwidth
 * @idx - index of the channel
 * @chan_width - bandwidth of the channel
 */
static int intf_awgn_find_channel(struct hostapd_iface *iface,
				  struct hostapd_channel_data **ret_chan,
				  int idx, int chan_width, int cs1)
{
	struct hostapd_hw_modes *mode = iface->current_mode;
	struct hostapd_channel_data *chan;
	int i, channel_idx = 0, n_chans;
	int temp_centre_freq;
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

		if (chan_width == CHAN_WIDTH_320) {
			ret = get_centre_freq_6g(chan->chan, CHAN_WIDTH_320,
						 &temp_centre_freq);
			if (ret) {
				wpa_printf(MSG_ERROR,
					   "AWGN : couldn't find centre freq for chan : %d"
					   " chan_width : %d", chan->chan, CHAN_WIDTH_320);
				return 0;
			}

			if (abs(temp_centre_freq - cs1) < 320) {
				wpa_printf(MSG_DEBUG,
					   "AWGN: channel %d is a overlapping channel so skipping",
					   chan->freq);
				continue;
			}
		}

		if (ret_chan && idx == channel_idx) {
			wpa_printf(MSG_DEBUG, "AWGN: Selected channel %d (%d)",
				   chan->freq, chan->chan);
			*ret_chan = chan;
			return idx;
		}

		wpa_printf(MSG_DEBUG, "AWGN: Adding channel %d (%d)",
			   chan->freq, chan->chan);
		channel_idx++;
	}
	return channel_idx;
}

enum chan_seg {
	SEG_PRI20		  =  0x1,
	SEG_SEC20		  =  0x2,
	SEG_SEC40_LOW		  =  0x4,
	SEG_SEC40_UP		  =  0x8,
	SEG_SEC40		  =  0xC,
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
	int ret;
	unsigned int i;
	u32 _rand;
	u32 chan_idx;
	int num_available_chandefs;
	u8 channel_switch = 0;
	int new_chan_width;
	int new_centre_freq;
	struct hostapd_hw_modes *mode = iface->current_mode;

	wpa_printf(MSG_DEBUG,
		   "input freq=%d, chan_width=%d, cf1=%d cf2=%d"
		   " chan_bw_interference_bitmap=0x%x",
		   freq,
		   chan_width,
		   cf1, cf2, chan_bw_interference_bitmap);

	if (iface->conf->discard_6g_awgn_event) {
		wpa_printf(MSG_DEBUG, "discard_6g_awgn_event set ignoring"
			   "AWGN DETECT event from driver");
		return 0;
	}

	/* check whether interference has occurred in primary 20Mhz channel */
	if (!chan_bw_interference_bitmap || (chan_bw_interference_bitmap & SEG_PRI20))
		channel_switch = 1;

	if (channel_switch) {
		/* Find a random channel to be switched */
		num_available_chandefs = intf_awgn_find_channel(iface, NULL, 0,
								chan_width, cf1);
		if (num_available_chandefs == 0) {
			wpa_printf(MSG_ERROR, "AWGN: no available_chandefs");
			return 0;
		}

		if (os_get_random((u8 *)&_rand, sizeof(_rand)) < 0) {
			wpa_printf(MSG_ERROR, "AWGN: couldn't get random number");
			return 0;
		}

		chan_idx = _rand % num_available_chandefs;
		intf_awgn_find_channel(iface, &chan_data, chan_idx, chan_width, cf1);

		if (!chan_data) {
			wpa_printf(MSG_ERROR, "AWGN: no random channel found, chan idx : %d",
				   chan_idx);
			return 0;
		}

		if(chan_data->freq == freq) {
			/* New random channel is same as operating channel
			 * so choose another channel
			 */
			chan_data = NULL;
			chan_idx = (chan_idx + 1) % num_available_chandefs;
			intf_awgn_find_channel(iface, &chan_data, chan_idx, chan_width, cf1);
			if (!chan_data) {
				wpa_printf(MSG_ERROR,
					   "AWGN: random channel not found, chan idx : %d",
					   chan_idx);
				return 0;
			}
		}

		wpa_printf(MSG_DEBUG, "AWGN: got random channel %d (%d)",
			   chan_data->freq, chan_data->chan);
		new_chan_width = chan_width;
	} else {
		/* interference is not present in the primary 20Mhz, so reduce bandwidth*/
		for (i = 0; i < mode->num_channels; i++) {
			chan_temp = &mode->channels[i];
			if (chan_temp->freq == freq)
				chan_data = chan_temp;
		}
		if (!chan_data) {
			wpa_printf(MSG_ERROR, "AWGN : no channel found");
			return 0;
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
			return 0;
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

	return 0;
}
