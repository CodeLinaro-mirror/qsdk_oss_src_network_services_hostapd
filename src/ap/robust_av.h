/*
 * SPDX-License-Identifier: ISC
 */
#ifndef ROBUST_AV_H
#define ROBUST_AV_H

#define HOSTAPD_SCS_DESCR_CAP_BIT	2

struct hostapd_data;

u8 *hostapd_add_scs_ie(u8 *frm, bool scs);

#endif
