/*
 * Management of interference due to incumbent signals in 6 GHz band
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */
#ifndef INTERFERENCE_H
#define INTERFERENCE_H

struct hostapd_iface;

int hostapd_incumbt_sig_intf_detected(struct hostapd_iface *iface, int freq,
				      int chan_width,
				      int cf1, int cf2,
				      u32 chan_bw_interference_bitmap);

#endif /* INTERFERENCE_H */
int hostapd_intf_afc_received(struct hostapd_iface *iface);

bool hostapd_is_backhaul_sta_conn(struct hostapd_iface *iface);

/*
 * hostapd_afc_chan_sel_cond - enum to set channel selction config
 * values, which will use to validate afc request
 * @HOSTAPD_AFC_CHAN_SEL_CUR_PWR_LT_AFC_PWR - AFC request is valid
 * if current eirp is less than afc eirp.
 * @HOSTAPD_AFC_CHAN_SEL_CUR_PWR_EQ_AFC_PWR - AFC request is valid
 * if current eirp is equal to afc eirp.
 * @HOSTAPD_AFC_CHAN_SEL_CUR_PWR_GT_AFC_PWR - AFC request is valid
 * if current eirp is greater than afc eirp.
 * @HOSTAPD_AFC_CHAN_SEL_ALL - AFC request is valid in all cases.
 */
enum hostapd_afc_chan_sel_cond {
	HOSTAPD_AFC_CHAN_SEL_CUR_PWR_LT_AFC_PWR = BIT(0),
	HOSTAPD_AFC_CHAN_SEL_CUR_PWR_EQ_AFC_PWR = BIT(1),
	HOSTAPD_AFC_CHAN_SEL_CUR_PWR_GT_AFC_PWR = BIT(2),
	HOSTAPD_AFC_CHAN_SEL_ALL = (HOSTAPD_AFC_CHAN_SEL_CUR_PWR_LT_AFC_PWR |
				    HOSTAPD_AFC_CHAN_SEL_CUR_PWR_EQ_AFC_PWR |
				    HOSTAPD_AFC_CHAN_SEL_CUR_PWR_GT_AFC_PWR),
};
