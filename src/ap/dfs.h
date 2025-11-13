/*
 * DFS - Dynamic Frequency Selection
 * Copyright (c) 2002-2013, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2013-2017, Qualcomm Atheros, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */
#ifndef DFS_H
#define DFS_H

/* Wait duration between radar detection and channel switch*/
#define HAPD_DFS_RADAR_CH_SWITCH_WAIT_DUR 500000

/*identify freq using channel number*/
#define BASE_FREQ_5G 5160
#define BASE_CHAN_5G 32
#define GET_FREQ_CHAN_5G(chan) (BASE_FREQ_5G + ((chan - BASE_CHAN_5G) * 5))

bool hostapd_is_freq_in_current_hw_info(struct hostapd_iface *iface, int freq);

int hostapd_handle_dfs(struct hostapd_iface *iface);

int hostapd_dfs_complete_cac(struct hostapd_iface *iface, int success, int freq,
			     int ht_enabled, int chan_offset, int chan_width,
			     int cf1, int cf2, bool is_background,
			     int chan_width_device, int cf_device);
int hostapd_dfs_pre_cac_expired(struct hostapd_iface *iface, int freq,
				int ht_enabled, int chan_offset, int chan_width,
				int cf1, int cf2,
				int chan_width_device, int cf_device);
int hostapd_dfs_radar_detected(struct hostapd_iface *iface, int freq,
			       int ht_enabled,
			       int chan_offset, int chan_width,
			       int cf1, int cf2, u16 radar_bitmap,
			       int chan_width_device, int cf_device);
int hostapd_dfs_nop_finished(struct hostapd_iface *iface, int freq,
			     int ht_enabled,
			     int chan_offset, int chan_width, int cf1, int cf2,
			     int chan_width_device, int cf_device);
int hostapd_is_dfs_required(struct hostapd_iface *iface);
int hostapd_is_dfs_chan_available(struct hostapd_iface *iface);
int hostapd_dfs_start_cac(struct hostapd_iface *iface, int freq,
			  int ht_enabled, int chan_offset, int chan_width,
			  int cf1, int cf2, bool is_background,
			  int chan_width_device, int cf_device);
int hostapd_handle_dfs_offload(struct hostapd_iface *iface);
int hostapd_is_dfs_overlap(struct hostapd_iface *iface, enum chan_width width,
			   int center_freq);
void hostapd_dfs_radar_handling_timeout(void *eloop_data, void *user_data);
void hostapd_start_device_cac_background(struct hostapd_iface *iface);
#endif /* DFS_H */
