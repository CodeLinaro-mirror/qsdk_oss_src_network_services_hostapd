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

/* CSA beacon duration in seconds for dfs testing mode */
#define HOSTAPD_DFS_TEST_MODE_CSA_DUR 1
/* Wait duration between radar detection and channel switch*/
#define HAPD_DFS_RADAR_CH_SWITCH_WAIT_DUR 500000

/*identify freq using channel number*/
#define BASE_FREQ_5G 5160
#define BASE_CHAN_5G 32
#define GET_FREQ_CHAN_5G(chan) (BASE_FREQ_5G + ((chan - BASE_CHAN_5G) * 5))

void hostapd_dfs_test_mode_csa_timeout(void *eloop_data, void *user_data);

int hostapd_handle_dfs(struct hostapd_iface *iface);

int hostapd_dfs_complete_cac(struct hostapd_iface *iface, int success, int freq,
			     int ht_enabled, int chan_offset, int chan_width,
			     int cf1, int cf2, bool is_background);
int hostapd_dfs_pre_cac_expired(struct hostapd_iface *iface, int freq,
				int ht_enabled, int chan_offset, int chan_width,
				int cf1, int cf2);
int hostapd_dfs_radar_detected(struct hostapd_iface *iface, int freq,
			       int ht_enabled,
			       int chan_offset, int chan_width,
			       int cf1, int cf2, u16 radar_bitmap);
int hostapd_dfs_nop_finished(struct hostapd_iface *iface, int freq,
			     int ht_enabled,
			     int chan_offset, int chan_width, int cf1, int cf2);
int hostapd_is_dfs_required(struct hostapd_iface *iface);
int hostapd_is_dfs_chan_available(struct hostapd_iface *iface);
int hostapd_dfs_start_cac(struct hostapd_iface *iface, int freq,
			  int ht_enabled, int chan_offset, int chan_width,
			  int cf1, int cf2, bool is_background);
int hostapd_handle_dfs_offload(struct hostapd_iface *iface);
int hostapd_is_dfs_overlap(struct hostapd_iface *iface, enum chan_width width,
			   int center_freq);
void hostapd_dfs_radar_handling_timeout(void *eloop_data, void *user_data);
#endif /* DFS_H */
