/*
 * SPDX-License-Identifier: ISC
 */

#include "utils/includes.h"
#include "utils/common.h"
#include "common/ieee802_11_defs.h"
#include "common/ieee802_11_common.h"
#include "hostapd.h"
#include "robust_av.h"

u8 *hostapd_add_scs_ie(u8 *frm, bool scs)
{
	/* Element ID */
	*frm++ = WLAN_EID_VENDOR_SPECIFIC;
	/* SCS WFA IE length - [Elem ID(1) + Length(1)] */
	*frm++ = SCS_WFA_IE_LEN - 2;

	/* WFA OUI */
	*frm++ = (OUI_WFA >> 16) & 0xFF;
	*frm++ = (OUI_WFA >> 8) & 0xFF;
	*frm++ = OUI_WFA & 0xFF;

	/* OUI Type */
	*frm++ = WFA_CAPA_OUI_TYPE;

	/* Capabilities length */
	*frm++ = 1;

	/* SCS capability */
	if (scs)
		*frm++ = (1 << HOSTAPD_SCS_DESCR_CAP_BIT);
	else
		*frm++ = (0 << HOSTAPD_SCS_DESCR_CAP_BIT);

	return frm;
}
