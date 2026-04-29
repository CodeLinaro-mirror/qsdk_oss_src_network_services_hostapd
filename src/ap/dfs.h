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
int hostapd_dfs_start_channel_switch(struct hostapd_iface *iface);
int hostapd_dfs_start_cac(struct hostapd_iface *iface, int freq,
			  int ht_enabled, int chan_offset, int chan_width,
			  int cf1, int cf2, bool is_background,
			  int chan_width_device, int cf_device);
int hostapd_handle_dfs_offload(struct hostapd_iface *iface);
int hostapd_is_dfs_overlap(struct hostapd_iface *iface, enum chan_width width,
			   int center_freq);
void hostapd_dfs_radar_handling_timeout(void *eloop_data, void *user_data);
void hostapd_start_device_cac_background(struct hostapd_iface *iface);
int hostapd_start_background_cac(struct hostapd_iface *iface);
int hostapd_start_rcac_on_channel(struct hostapd_iface *iface, int chan, int bw_mhz);
int hostapd_dfs_agile_cac_switch(struct hostapd_iface *iface);
void hostapd_restart_agile_cac_after_ch_switch(struct hostapd_iface *iface);
void hostapd_abort_background_cac(struct hostapd_iface *iface);
enum oper_chan_width convert_to_oper_chan_width(int chan_width);

int set_dfs_state_freq(struct hostapd_iface *iface, int freq, u32 state);
bool hostapd_is_cac_required(struct hostapd_iface *iface);
bool hostapd_dfs_csa_target_has_unavailable_channel(struct hostapd_iface *iface,
						    struct hostapd_freq_params *freq_params,
						    enum chan_width width);
void hostapd_dfs_start_background_cac_deferred(struct hostapd_iface *iface);
int hostapd_dfs_count_precac_channels(struct hostapd_iface *iface);
int hostapd_dfs_start_precac(struct hostapd_iface *iface);
int hostapd_dfs_precac_restart_after_radar(struct hostapd_iface *iface,
					   int radar_freq);
/**
 * dfs_find_bw_reduced_channel - Try to reduce bandwidth on same channel
 * @iface: Pointer to interface data
 * @secondary_channel: Pointer to secondary channel offset (output)
 * @oper_centr_freq_seg0_idx: Pointer to center freq seg0 (output)
 * @oper_centr_freq_seg1_idx: Pointer to center freq seg1 (output)
 * Returns: Channel data pointer on success, NULL on failure
 */

struct hostapd_channel_data *
dfs_find_bw_reduced_channel(struct hostapd_iface *iface,
			   int *secondary_channel,
			   u8 *oper_centr_freq_seg0_idx,
			   u8 *oper_centr_freq_seg1_idx);

#endif /* DFS_H */
