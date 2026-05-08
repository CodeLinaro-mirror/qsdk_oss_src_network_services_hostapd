/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "utils/bitfield.h"
#include "common/wpa_ctrl.h"
#include "ap/hostapd.h"
#include "ap/sta_info.h"
#include "ap/ieee802_11.h"
#include "ap/ieee802_1x.h"
#include "ap/ap_drv_ops.h"
#include "ap/wpa_auth.h"
#include "ap/beacon.h"
#include "ap/ap_mlme.h"
#include "eapol_auth/eapol_auth_sm.h"
#include "eapol_auth/eapol_auth_sm_i.h"

#ifdef HOSTAPD_EXTERNAL_PLUGIN
#include "../qcn_extns/hostapd_external_interface.h"
#endif
#include "hostapd_if.h"
#ifdef HOSTAPD_EXTERNAL_PLUGIN
#include "../qcn_extns/hostapd_if_eloop.h"
#endif
#include <stdlib.h>

/*
 * State and declarations for ASYNC dispatch system
 */
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include "utils/eloop.h"

/*
 * Max MPDU size excluding FCS for management frames
 */
#ifndef IEEE80211_MAX_MGMT_LEN_NO_FCS
#define IEEE80211_MAX_MGMT_LEN_NO_FCS 2300
#endif

static struct hapd_interfaces *hostapd_if_ifaces;

/*
 * Per-interface/MLD frame registration table, reference counted
 * for MLD sharing
 */
struct frame_reg_table {
	int ref_count;
	/*
	 * Per-mgmt registration
	 */
	enum hostapd_if_frame_policy mgmt[HOSTAPD_IF_FRAME_TYPE_MAX];
	/*
	 * Event registration bitfield
	 */
	struct bitfield *event_registration;
};

/*
 * Query API: Check if event notification is enabled for a specific
 * event type
 */
static bool hostapd_if_is_event_registered(struct hostapd_data *hapd,
				    enum hostapd_if_event_type type)
{
	struct frame_reg_table *table;
	struct bitfield *event_registration;

	if (!hapd || (type >= HOSTAPD_IF_EVENT_MAX))
		return false;

	table = (struct frame_reg_table *) hapd->hostapd_if_data;
	if(!table)
		return false;

	event_registration = table->event_registration;
	if (!event_registration)
		return false;

	return bitfield_is_set(event_registration, type);
}



#ifdef HOSTAPD_EXTERNAL_PLUGIN
static struct hostapd_external_app_object *hostapd_if_plugin;
#define HOSTAPD_EXTERNAL_PLUGIN_NOTIFY_EVENT(evt)			\
do {									\
	if (hostapd_if_plugin &&					\
	    hostapd_if_plugin->notify_event)				\
		hostapd_if_plugin->notify_event(&evt);			\
} while (0)

/*
 * inbound error event is triggered for all async inbound calls
 * those are not successfully carried out
 */
static void
__inbound_error_event(struct hostapd_data *hapd, const uint8_t *sta_mac,
		      enum HOSTAPD_IF_INBOUND_ERROR type,
		      const char *func,
		      int line_num)
{
	struct hostapd_if_event evt;

	if (!hostapd_if_is_event_registered(hapd,
				HOSTAPD_IF_EVENT_INBOUND_CALL_ERROR))
		return;

	os_memset(&evt, 0, sizeof(evt));
	evt.type = HOSTAPD_IF_EVENT_INBOUND_CALL_ERROR;
	os_strlcpy((char *) evt.ifname, hapd->conf->iface, sizeof(evt.ifname));
	if (sta_mac)
		os_memcpy(evt.sta_mac, sta_mac, sizeof(evt.sta_mac));
	evt.data.inbound_call_error.type = type;
	evt.data.inbound_call_error.func = func;
	evt.data.inbound_call_error.line_num = line_num;

	HOSTAPD_EXTERNAL_PLUGIN_NOTIFY_EVENT(evt);
}
#else
#define HOSTAPD_EXTERNAL_PLUGIN_NOTIFY_EVENT(evt)
static void
__inbound_error_event(struct hostapd_data *hapd, const uint8_t *sta_mac,
		      const char *func,
		      int line_num)
{
}
#endif

static struct hostapd_data *
__hostapd_get_link_iface(const char *ifname, int link_id)
{
	size_t i, j;

	for (i = 0; i < hostapd_if_ifaces->count; i++) {
		struct hostapd_iface *iface = hostapd_if_ifaces->iface[i];

		for (j = 0; j < iface->num_bss; j++) {
			struct hostapd_data *hapd = iface->bss[j];

			if (os_strcmp(ifname, hapd->conf->iface) != 0)
				continue;

			if (link_id < 0)
				return hapd;

			if (hapd->mld_link_id != link_id)
				continue;

			return hapd;
		}
	}

	return NULL;
}


static struct sta_info *__get_sta(const char *ifname,
				       const uint8_t *sta_addr,
				       int link_id,
				       bool assoc_link_required,
				       struct hostapd_data **hapd)
{
	struct hostapd_iface *iface;
        struct hostapd_data *bss;
        unsigned int i, j;
	struct sta_info *sta;
	 *hapd = NULL;

        for (i = 0; i < hostapd_if_ifaces->count; i++) {
                iface = hostapd_if_ifaces->iface[i];
                if (!iface)
                        continue;

                for (j = 0; j < iface->num_bss; j++) {
                        bss = iface->bss[j];

			if (os_strcmp(ifname, bss->conf->iface) != 0)
				continue;

			if ((bss->mld_link_id != link_id) && (link_id > 0))
				continue;

			sta = ap_get_sta(bss, sta_addr);
			if (!sta)
				continue;

			if ((!sta->mld_info.mld_sta) ||
			    !assoc_link_required ||
			    (sta->mld_assoc_link_id == bss->mld_link_id)) {
				*hapd = bss;
				return sta;
			}
                }
        }
	return NULL;
}

/*
 * Southbound: plugin call to resume EAPOL M3 given ifname and STA MAC
 * In case the STA is a 11be STA, the input mac has to be MLD mac
 */
void __hostapd_if_trigger_eapol_m3(char *ifname, uint8_t *sta_mac)
{
	struct sta_info *sta;
	struct hostapd_data *hapd;

	wpa_printf(MSG_MSGDUMP,
		   "%s: %s, " MACSTR "\n",
		   __func__, ifname, MAC2STR(sta_mac));

	sta = __get_sta(ifname, sta_mac, -1, true, &hapd);
	if (!sta) {
		if (hapd)
			__inbound_error_event(hapd, sta_mac,
				       HOSTAPD_IF_TRIGGER_EAPOL_M3_ERROR,
				       __func__, __LINE__);

		wpa_printf(MSG_ERROR, "%s: ERROR! No STA found with "MACSTR"\n",
				__func__, MAC2STR(sta_mac));
		goto __hostapd_if_trigger_eapol_m3_exit;
	}

	wpa_auth_trigger_m3(sta->wpa_sm);
__hostapd_if_trigger_eapol_m3_exit:
	return;
}

/*
 * Refactored TX path entry for OPEN authentication response.
 * Implemented in core hostapd; this file invokes it from auth_response.
 */
static int __send_open_auth_response(struct hostapd_data *hapd,
				     struct sta_info *sta,
				     struct hostapd_if_frame_ctx *ctx)
{
	const u8 *dst = ctx->data.auth_resp.sta_assoc_link_mac;
	int reply_res;

	if (ctx->status_code == WLAN_STATUS_SUCCESS) {
		sta->flags |= WLAN_STA_AUTH;
		wpa_auth_sm_event(sta->wpa_sm, WPA_AUTH);
		sta->auth_alg = WLAN_AUTH_OPEN;
		mlme_authenticate_indication(hapd, sta);
	}

	reply_res = send_auth_reply(hapd, sta, dst, WLAN_AUTH_OPEN,
				    ctx->data.auth_resp.auth_transaction,
				    ctx->status_code,
				    NULL, 0, "auth-open");

	if (sta && sta->added_unassoc &&
	    (ctx->status_code != WLAN_STATUS_SUCCESS ||
	     reply_res != WLAN_STATUS_SUCCESS)) {
		hostapd_drv_sta_remove(hapd, sta->addr);
		sta->added_unassoc = 0;
	}

	return reply_res;
}

/*
 * hostapd_if_register_frame implementation:
 * plugin "southbound" callback
 */
void hostapd_if_register_frame(void *ifname_ctx,
			       struct hostapd_if_frame_category *cat,
			       enum hostapd_if_frame_policy policy)
{
	/*
	 * Find correct hapd
	 */
	struct hostapd_data *hapd = NULL;
	struct frame_reg_table *table = NULL;

	hapd = (struct hostapd_data *)ifname_ctx;
	if (!hapd || !cat) {
		wpa_printf(MSG_ERROR, "%s: ERROR! NULL params %p %p\n", __func__, ifname_ctx, cat);
		return;
	}

	table = (struct frame_reg_table *) hapd->hostapd_if_data;
	if (!table) {
		wpa_printf(MSG_ERROR, "%s: ERROR! table not found\n", __func__);
		return;
	}

	if (cat->type >= HOSTAPD_IF_FRAME_TYPE_MAX) {
		wpa_printf(MSG_ERROR, "%s: ERROR! type invalid %d", __func__, cat->type);
		return;
	}
	table->mgmt[cat->type] = policy;
}

/*
 * hostapd_if_register_event implementation:
 * plugin "southbound" callback
 */
void hostapd_if_register_event(void *ifname_ctx,
			       enum hostapd_if_event_type type,
			       bool set)
{
	struct hostapd_data *hapd = NULL;
	struct frame_reg_table *table = NULL;

	if (!ifname_ctx || type >= HOSTAPD_IF_EVENT_MAX) {
		wpa_printf(MSG_ERROR, "%s! ERROR! invalid params %p %d", __func__,
				   ifname_ctx, type);
		return;
	}

	hapd = (struct hostapd_data *)ifname_ctx;
	table = (struct frame_reg_table *) hapd->hostapd_if_data;
	if (!table || !table->event_registration) {
		wpa_printf(MSG_ERROR, "%s: ERROR! table not found %p\n", __func__,
				   table);
		return;
	}

	if (set)
		bitfield_set(table->event_registration, type);
	else
		bitfield_clear(table->event_registration, type);

	wpa_printf(MSG_DEBUG,
			   "hostapd_if: Event registration enabled for event type=%u",
			   type);
}

#ifdef HOSTAPD_EXTERNAL_PLUGIN
enum hostapd_if_eloop_type hostapd_if_plugin_init(void *);
void hostapd_if_plugin_deinit(void);
#endif

const bool global_plugin_enable = false;
bool hostapd_if_plugin_enable = global_plugin_enable;
/*
 * Call this once at startup (from hostapd_if_init)
 */
int hostapd_if_init(struct hapd_interfaces *interfaces, bool plugin_enable)
{
	enum hostapd_if_eloop_type eloop_type = HOSTAPD_IF_ELOOP_ROUTING;
	wpa_printf(MSG_ERROR, "%s", __func__);
	hostapd_if_ifaces = interfaces;

#ifdef CONFIG_QCN_EXTN
#ifdef HOSTAPD_EXTERNAL_PLUGIN
#ifdef HOSTAPD_EXTERNAL_PLUGIN_TESTAPP
	hostapd_if_plugin_enable = (plugin_enable || global_plugin_enable);
	if (hostapd_if_plugin_enable)
		eloop_type = hostapd_if_plugin_init(interfaces);
#endif
	if (hostapd_if_eloop_init(eloop_type) < 0)
		return -1;
#endif
#endif

	return 0;
}

#ifdef CONFIG_QCN_EXTN
#ifdef HOSTAPD_EXTERNAL_PLUGIN
void hostapd_if_eloop_deinit(void);
#endif
#endif

int hostapd_if_deinit(void)
{
#ifdef CONFIG_QCN_EXTN
#ifdef HOSTAPD_EXTERNAL_PLUGIN
	hostapd_if_eloop_deinit();
#ifdef HOSTAPD_EXTERNAL_PLUGIN_TESTAPP
	if (hostapd_if_plugin_enable)
		hostapd_if_plugin_deinit();
#endif
#endif
#endif
	return 0;
}

int hostapd_if_interface_create(struct hostapd_data *hapd)
{
	struct hostapd_data *leader;
	struct frame_reg_table *table = NULL;

	if (!hapd->conf->external_plugin_enable)
		return 0;

	wpa_printf(MSG_ERROR, "%s:%s %d", __func__, hapd->conf->iface,
		hapd->mld_link_id);
	leader = hostapd_mld_get_first_bss(hapd);

	/*
	 * If in MLD and a table exists in the leader, share it
	 * (just refcount)
	 */
	if (leader && leader != hapd) {
		if (!leader->hostapd_if_data) {
			wpa_printf(MSG_ERROR, "%s: ERROR! leader BSS does not have table\n",
				__func__);
			return -1;
		}
		table = (struct frame_reg_table *) leader->hostapd_if_data;
		++table->ref_count;
		hapd->hostapd_if_data = (void *) table;

		wpa_printf(MSG_DEBUG, "%s! using table from leader bss\n", __func__);
		goto hostapd_if_interface_create_plugin_call;
	}

	table = (struct frame_reg_table *)
		calloc(1, sizeof(struct frame_reg_table));
	if (!table) {
		wpa_printf(MSG_ERROR, "%s! ERROR!! TABLE allocation failed\n",
			__func__);
		return -1;
	}

	table->ref_count = 1;
	/*
	 * Allocate bitfield for event registration tracking
	 */
	table->event_registration = bitfield_alloc(HOSTAPD_IF_EVENT_MAX);
	if (!table->event_registration) {
		wpa_printf(MSG_ERROR, "%s! ERROR! Event reg table allocation failed\n",
			__func__);
		free(table);
		return -1;
	}

	hapd->hostapd_if_data = (void *) table;
hostapd_if_interface_create_plugin_call:
#ifdef HOSTAPD_EXTERNAL_PLUGIN
	/*
	 * plugin->interface_init → interface_create
	 */
	if (hapd->conf->external_plugin_enable &&
	    hostapd_if_plugin &&
	    hostapd_if_plugin->interface_create)
		hostapd_if_plugin->interface_create(
			(char *) hapd->conf->iface, hapd);
#endif

	return 0;
}

/*
 * On per-BSS teardown: remove reference, free table only if last
 */
void hostapd_if_interface_remove(struct hostapd_data *hapd)
{
	struct frame_reg_table *table =
		(struct frame_reg_table *) hapd->hostapd_if_data;

	if (!table)
		return;

	wpa_printf(MSG_DEBUG, "%s:%s link-id:%d", __func__, hapd->conf->iface,
		hapd->mld_link_id);
	if (hapd->hostapd_if_data == (void *) table)
		hapd->hostapd_if_data = NULL;

	if (--table->ref_count == 0) {
		if (table->event_registration)
			bitfield_free(table->event_registration);
		free(table);
	}
}

static enum hostapd_if_frame_processing_decision
__get_frame_decision(enum hostapd_if_frame_policy *policy,
		     bool invoke_supported)
{
	if ((*policy == HOSTAPD_IF_FRAME_INVOKE) && !invoke_supported)
		*policy = HOSTAPD_IF_FRAME_NOTIFY;

	switch (*policy) {
	case HOSTAPD_IF_FRAME_INVOKE:
		return HOSTAPD_IF_FRAME_PROCESSING_WAIT;
	default:
		return HOSTAPD_IF_FRAME_PROCESSING_CONTINUE;
	}
}

enum hostapd_if_frame_processing_decision
hostapd_if_notify_auth(struct hostapd_data *hapd,
		       struct sta_info *sta,
		       const uint8_t *frame,
		       uint16_t frame_len,
		       u16 status_code,
		       u16 auth_transaction,
		       u8 allow_reuse,
		       u16 auth_alg,
		       const u8 *sa)
{
	bool invoke_supported = true;
	struct frame_reg_table *table;
	enum hostapd_if_frame_policy policy =
		HOSTAPD_IF_FRAME_DO_NOTHING;
	enum hostapd_if_frame_processing_decision decision =
		HOSTAPD_IF_FRAME_PROCESSING_CONTINUE;
	struct hostapd_if_frame_ctx ctx_req;

	table = (struct frame_reg_table *) hapd->hostapd_if_data;
	if (!table)
		return decision;

#ifdef CONFIG_IEEE80211R_AP
	if (auth_alg == WLAN_AUTH_FT)
		/*
		 * FT will be supported only in the next phase
		 */
		invoke_supported = false;
#endif /* CONFIG_IEEE80211R_AP */
#ifdef CONFIG_FILS
	if (auth_alg == WLAN_AUTH_FILS_SK ||
	    auth_alg == WLAN_AUTH_FILS_SK_PFS ||
	    auth_alg == WLAN_AUTH_FILS_PK)
		invoke_supported = false;
#endif /* CONFIG_FILS */

	policy = table->mgmt[HOSTAPD_IF_FRAME_TYPE_AUTH];

	/*
	 * Initialize and populate context structure
	 */

	os_memset(&ctx_req, 0, sizeof(ctx_req));
	ctx_req.status_code = status_code;
	ctx_req.data.auth_req.auth_transaction = auth_transaction;
	ctx_req.data.auth_req.allow_reuse = allow_reuse;
	ctx_req.data.auth_req.auth_alg = auth_alg;

	/*
	 * rx_link_id selection: 0 for non-MLD, otherwise
	 * hapd->mld_link_id
	 */
#ifdef CONFIG_IEEE80211BE
	if (hapd->conf && hapd->conf->mld_ap)
		ctx_req.rx_link_id = hapd->mld_link_id;
	else
#endif /* CONFIG_IEEE80211BE */
		ctx_req.rx_link_id = 0;

	/*
	 * Associated link id and per-link peer MAC
	 */

	os_memcpy(ctx_req.data.auth_req.sta_assoc_link_mac,
		  sa, ETH_ALEN);

	wpa_printf(MSG_DEBUG, "%s: policy-before:%d invoke_supported: %d",
		__func__, policy, invoke_supported);
	decision = __get_frame_decision(&policy, invoke_supported);
	wpa_printf(MSG_DEBUG, "%s: policy-after:%d decision: %d",
		__func__, policy, decision);

	if (policy == HOSTAPD_IF_FRAME_NOTIFY) {
#ifdef HOSTAPD_EXTERNAL_PLUGIN
		if (hostapd_if_plugin && hostapd_if_plugin->notify_auth) {
			hostapd_if_plugin->notify_auth(hapd->conf->iface,
					sta->addr, frame, frame_len, &ctx_req);
		}
#endif
	} else if (policy == HOSTAPD_IF_FRAME_INVOKE) {
#ifdef HOSTAPD_EXTERNAL_PLUGIN
		/*
		 * External invoke, hostapd must pause until
		 * auth_response
		 */
		if (hostapd_if_plugin &&
		    hostapd_if_plugin->invoke_auth) {
			/*
			 * Pass computed context by pointer
			 */
			hostapd_if_plugin->invoke_auth(hapd->conf->iface,
					sta->addr, frame, frame_len, &ctx_req);
		}
#endif
	}

	return decision;
}

/*
 * Notify/invoke external application for Association and return
 * processing decision.
 *
 * Policy:
 *  - DO_NOTHING: CONTINUE (no plugin call)
 *  - NOTIFY: CONTINUE (+ plugin->notify_assoc)
 *  - INVOKE: WAIT (+ plugin->invoke_assoc)
 */
enum hostapd_if_frame_processing_decision
hostapd_if_notify_assoc(struct hostapd_data *hapd,
			struct sta_info *sta,
			const uint8_t *frame,
			uint16_t frame_len,
			u16 status_code,
			int is_reassoc,
			int rssi,
			bool set_beacon,
			const u8 *sa)
{
	bool invoke_supported = true;
	struct frame_reg_table *table;
	enum hostapd_if_frame_policy policy =
		HOSTAPD_IF_FRAME_DO_NOTHING;
	enum hostapd_if_frame_processing_decision decision =
		HOSTAPD_IF_FRAME_PROCESSING_CONTINUE;
	struct hostapd_if_frame_ctx ctx_req;
	int i;

	table =
		(struct frame_reg_table *) hapd->hostapd_if_data;
	if (!table)
		return decision;

#ifdef CONFIG_IEEE80211R_AP
	if (sta->auth_alg == WLAN_AUTH_FT)
		/*
		 * FT will be supported only in the next phase
		 */
		invoke_supported = false;
#endif /* CONFIG_IEEE80211R_AP */
#ifdef CONFIG_FILS
	if (sta->auth_alg == WLAN_AUTH_FILS_SK ||
	    sta->auth_alg == WLAN_AUTH_FILS_SK_PFS ||
	    sta->auth_alg == WLAN_AUTH_FILS_PK)
		invoke_supported = false;
#endif /* CONFIG_FILS */

	policy = table->mgmt[HOSTAPD_IF_FRAME_TYPE_ASSOC];

	/*
	 * Initialize and populate context structure
	 */
	os_memset(&ctx_req, 0, sizeof(ctx_req));
	ctx_req.status_code = status_code;
	ctx_req.data.assoc_req.is_reassoc = is_reassoc;
	ctx_req.data.assoc_req.rssi = rssi;

	/*
	 * Prepare context (compute rx_link_id and MLD fields)
	 */

	/*
	 * rx_link_id: -1 for non-MLD, else current BSS link id
	 */
#ifdef CONFIG_IEEE80211BE
	if (hapd->conf && hapd->conf->mld_ap)
		ctx_req.rx_link_id = hapd->mld_link_id;
	else
#endif /* CONFIG_IEEE80211BE */
		ctx_req.rx_link_id = -1;

	/*
	 * Fill assoc_req MLD topology if running as MLD AP
	 */
	os_memcpy(ctx_req.data.assoc_req.sta_assoc_link_mac, sa, ETH_ALEN);

#ifdef CONFIG_IEEE80211BE
	if (hapd->conf && hapd->conf->mld_ap) {


		ctx_req.data.assoc_req.valid_link_bitmap = 0;

		for (i = 0; i < MAX_MLO_LINKS; i++) {
			if (i < MAX_NUM_MLD_LINKS &&
			    sta->mld_info.links[i].valid) {
				ctx_req.data.assoc_req.valid_link_bitmap |=
					(1U << i);

				os_memcpy(ctx_req.data.assoc_req.sta_link_mac[i],
					  sta->mld_info.links[i].peer_addr,
					  ETH_ALEN);
			} else {
				os_memset(
					ctx_req.data.assoc_req.sta_link_mac[i],
					0, ETH_ALEN);
			}
		}
	} else
#endif /* CONFIG_IEEE80211BE */
	{
		ctx_req.data.assoc_req.valid_link_bitmap = 0;

		for (i = 0; i < MAX_MLO_LINKS; i++)
			os_memset(ctx_req.data.assoc_req.sta_link_mac[i],
				  0, ETH_ALEN);
	}

	decision = __get_frame_decision(&policy, invoke_supported);

	if (policy == HOSTAPD_IF_FRAME_NOTIFY) {
#ifdef HOSTAPD_EXTERNAL_PLUGIN
		if (hostapd_if_plugin &&
		    hostapd_if_plugin->notify_assoc) {
			hostapd_if_plugin->notify_assoc(hapd->conf->iface,
					sta->addr, frame, frame_len, &ctx_req);
		}
#endif
	} else if (policy == HOSTAPD_IF_FRAME_INVOKE) {
		if (set_beacon)
			ieee802_11_update_beacons(hapd->iface);
#ifdef HOSTAPD_EXTERNAL_PLUGIN
		/*
		 * Pause hostapd until assoc_response arrives
		 */
		if (hostapd_if_plugin &&
		    hostapd_if_plugin->invoke_assoc) {
			hostapd_if_plugin->invoke_assoc(hapd->conf->iface,
					sta->addr, frame, frame_len,
					&ctx_req);
		}
#endif
	}

	return decision;
}

void hostapd_if_notify_disassoc(struct hostapd_data *hapd,
				struct sta_info *sta,
				const void *frame,
				size_t frame_len)
{
	struct frame_reg_table *table;
	enum hostapd_if_frame_policy policy =
		HOSTAPD_IF_FRAME_DO_NOTHING;
	struct hostapd_if_frame_ctx ctx_req;

	table =
		(struct frame_reg_table *) hapd->hostapd_if_data;

	if (!table)
		return;

	policy = table->mgmt[HOSTAPD_IF_FRAME_TYPE_DISASSOC];

	/*
	 * Initialize and populate context structure
	 */
	os_memset(&ctx_req, 0, sizeof(ctx_req));

	/*
	 * rx_link_id: -1 for non-MLD, else current BSS link id
	 */
#ifdef CONFIG_IEEE80211BE
	if (hapd->conf && hapd->conf->mld_ap)
		ctx_req.rx_link_id = hapd->mld_link_id;
	else
#endif /* CONFIG_IEEE80211BE */
		ctx_req.rx_link_id = -1;

	if ((policy != HOSTAPD_IF_FRAME_NOTIFY) &&
		(policy != HOSTAPD_IF_FRAME_INVOKE))
		return;

#ifdef HOSTAPD_EXTERNAL_PLUGIN
	if (hostapd_if_plugin && hostapd_if_plugin->notify_disassoc) {
		hostapd_if_plugin->notify_disassoc(hapd->conf->iface,
			sta->addr, frame, frame_len, &ctx_req);
	}
#endif
}

void hostapd_if_notify_deauth(struct hostapd_data *hapd,
			      struct sta_info *sta,
			      const void *frame,
			      size_t frame_len)
{
	struct frame_reg_table *table;
	enum hostapd_if_frame_policy policy =
		HOSTAPD_IF_FRAME_DO_NOTHING;
	struct hostapd_if_frame_ctx ctx_req;

	table =
		(struct frame_reg_table *) hapd->hostapd_if_data;

	if (!table)
		return;

	policy = table->mgmt[HOSTAPD_IF_FRAME_TYPE_DEAUTH];

	/*
	 * Initialize and populate context structure
	 */
	os_memset(&ctx_req, 0, sizeof(ctx_req));

	/*
	 * rx_link_id: -1 for non-MLD, else current BSS link id
	 */
#ifdef CONFIG_IEEE80211BE
	if (hapd->conf && hapd->conf->mld_ap)
		ctx_req.rx_link_id = hapd->mld_link_id;
	else
#endif /* CONFIG_IEEE80211BE */
		ctx_req.rx_link_id = -1;

	if ((policy != HOSTAPD_IF_FRAME_NOTIFY) &&
	    (policy != HOSTAPD_IF_FRAME_INVOKE))
		return;

#ifdef HOSTAPD_EXTERNAL_PLUGIN
	if (hostapd_if_plugin && hostapd_if_plugin->notify_deauth) {
		hostapd_if_plugin->notify_deauth(hapd->conf->iface, sta->addr,
			frame, frame_len, &ctx_req);
	}
#endif
}

void hostapd_if_eapol_rx(struct hostapd_data *hapd, const u8 *sa,
			 const u8 *data, u16 data_len)
{
	int link_id = -1;

#ifdef CONFIG_IEEE80211BE
	if (hapd->conf && hapd->conf->mld_ap)
		link_id = hapd->mld_link_id;
#endif
#ifdef HOSTAPD_EXTERNAL_PLUGIN
	if (hostapd_if_plugin && hostapd_if_plugin->eapol_rx) {
		wpa_printf(MSG_DEBUG, "%s: executing EAPOL RX through plugin",
			   __func__);
		hostapd_if_plugin->eapol_rx(hapd->conf->iface, link_id, sa,
					    (u8 *) data, data_len);
	}
#endif
}

/*
 * External app resumes Association flow:
 * Compose and send (Re)Association Response using ctx->status_code
 * and assoc_resp params.
 *
 * sta_mac: MAC address of the STA. Use MLD mac in case of 11be STA
 */
void __hostapd_if_assoc_response(char *ifname, uint8_t *sta_mac,
				 struct hostapd_if_frame_ctx *ctx)
{
	struct sta_info *sta;
	int omit_rsnxe = 0;
	struct hostapd_data *hapd;

	wpa_printf(MSG_MSGDUMP,
		   "%s: %s, " MACSTR " %d %d\n",
		   __func__, ifname, MAC2STR(sta_mac),
		   ctx->data.assoc_resp.is_reassoc,
		   ctx->data.assoc_resp.rssi);

	wpa_hexdump(MSG_EXCESSIVE,
		    "hostapd_if_assoc_response additional_ies",
		    ctx->data.assoc_resp.additional_ies,
		    ctx->data.assoc_resp.additional_ies_len);

	sta = __get_sta(ifname, sta_mac, ctx->rx_link_id, false, &hapd);
	if (!sta) {
		if (hapd)
			__inbound_error_event(hapd, sta_mac,
					HOSTAPD_IF_ASSOC_RESPONSE_ERROR,
					__func__, __LINE__);
		wpa_printf(MSG_ERROR,
			   "hostapd_if: assoc_response - STA " MACSTR " not found on %s",
			   MAC2STR(sta_mac), ifname);
		goto __hostapd_if_assoc_response_exit;
	}

	/*
	 * Stash a copy of plugin-provided additional IEs
	 * for Assoc Response into sta context. This copy
	 * will be appended exactly once in the TX path and
	 * then freed.
	 */
	if (ctx->data.assoc_resp.additional_ies &&
	    ctx->data.assoc_resp.additional_ies_len) {
		/*
		 * Use incoming buffer directly; TX path will free
		 * one-shot tail
		 */
		sta->ext_assoc_tail =
			ctx->data.assoc_resp.additional_ies;
		sta->ext_assoc_tail_len =
			ctx->data.assoc_resp.additional_ies_len;
	}

	if (hapd->conf->rsn_override_omit_rsnxe)
		omit_rsnxe = 1;

	if (ctx->data.assoc_resp.pmk.pmk) {
		wpa_auth_set_pmk_full(sta->wpa_sm,
				      ctx->data.assoc_resp.pmk.pmk,
				      ctx->data.assoc_resp.pmk.pmkid,
				      ctx->data.assoc_resp.pmk.pmk_len, 0,
				      NULL);
		os_free(ctx->data.assoc_resp.pmk.pmk);
		os_free(ctx->data.assoc_resp.pmk.pmkid);
	}

	initiate_assoc_response(hapd, sta, ctx->status_code,
				ctx->data.assoc_resp.is_reassoc,
				NULL, NULL, 0,
				omit_rsnxe,
				ctx->data.assoc_resp.sta_assoc_link_mac,
				ctx->data.assoc_resp.rssi,
				false);
	sta->ext_assoc_tail = NULL;
	sta->ext_assoc_tail_len = 0;
__hostapd_if_assoc_response_exit:
	os_free((void *)ctx->data.assoc_resp.additional_ies);
	/*
	 * Free ctx handed in from plugin
	 * (tail will be freed in TX path)
	 */
	os_free((void *)ctx);
}

static void
__send_sae_auth_response(struct hostapd_data *hapd, struct sta_info *sta,
			 struct hostapd_if_frame_ctx *ctx)
{
	int resp = WLAN_STATUS_SUCCESS;
	int sta_removed = 0;
	bool success_status;
	const u8 *dst = ctx->data.auth_resp.sta_assoc_link_mac;

	resp = sae_sm_step(hapd, sta, ctx->data.auth_resp.auth_transaction,
			   ctx->status_code, ctx->data.auth_resp.allow_reuse,
			   &sta_removed);

	if (!sta_removed && resp != WLAN_STATUS_SUCCESS) {

		send_auth_reply(hapd, sta, dst, WLAN_AUTH_SAE,
				ctx->data.auth_resp.auth_transaction,
				resp, NULL, 0, "auth-sae");
		sae_sme_send_external_auth_status(hapd, sta, resp);
	}

	if (ctx->data.auth_resp.auth_transaction == 1)
		success_status = sae_status_success(hapd, ctx->status_code);
	else
		success_status = ctx->status_code == WLAN_STATUS_SUCCESS;

	if (!sta_removed && sta->added_unassoc &&
	    (resp != WLAN_STATUS_SUCCESS || !success_status)) {
		hostapd_drv_sta_remove(hapd, sta->addr);
		sta->added_unassoc = 0;
	}
}


/*
 * Use MLD mac in sta_mac, in case the STA is 11be
 */
void __hostapd_if_auth_response(char *ifname, uint8_t *sta_mac,
				struct hostapd_if_frame_ctx *ctx)
{
	struct sta_info *sta;
	struct hostapd_data *hapd;


	wpa_printf(MSG_MSGDUMP,
		   "%s: %s, " MACSTR " status=%u auth_alg=%u "
		   "auth_transaction=%u\n",
		   __func__, ifname, MAC2STR(sta_mac), ctx->status_code,
		   ctx->data.auth_resp.auth_alg,
		   ctx->data.auth_resp.auth_transaction);

	wpa_hexdump(MSG_EXCESSIVE,
		    "hostapd_if_auth_response additional_ies",
		    ctx->data.auth_resp.additional_ies,
		    ctx->data.auth_resp.additional_ies_len);

	sta = __get_sta(ifname, sta_mac, ctx->rx_link_id, false, &hapd);
	if (!sta) {
		if (hapd)
			__inbound_error_event(hapd, sta_mac,
					HOSTAPD_IF_AUTH_RESPONSE_ERROR,
					__func__, __LINE__);
		wpa_printf(MSG_ERROR,
			   "hostapd_if: auth_response - STA " MACSTR " not found on %s",
			   MAC2STR(sta_mac), ifname);
		goto __hostapd_if_auth_response_exit;
	}

	/*
	 * Stash a copy of plugin-provided additional IEs
	 * for Auth Response into sta context. This copy
	 * will be appended exactly once in the TX path and
	 * then freed.
	 */
	if (ctx->data.auth_resp.additional_ies &&
	    ctx->data.auth_resp.additional_ies_len) {
		/*
		 * Use incoming buffer directly; TX path will free
		 * one-shot tail
		 */
		sta->ext_auth_tail =
			ctx->data.auth_resp.additional_ies;
		sta->ext_auth_tail_len =
			ctx->data.auth_resp.additional_ies_len;
	}

	/*
	 * Branch by current STA auth algorithm
	 */
	switch (ctx->data.auth_resp.auth_alg) {
	case WLAN_AUTH_OPEN:

		__send_open_auth_response(hapd, sta, ctx);
		break;
#ifdef CONFIG_SAE
	case WLAN_AUTH_SAE:

		__send_sae_auth_response(hapd, sta, ctx);
		break;
#endif /* CONFIG_SAE */
	default:
		wpa_printf(MSG_ERROR, "%s: ERROR! Unsupported algorithm\n",
			__func__);
		/*
		 * For other algorithms, no-op for now
		 */
		break;
	}
	sta->ext_auth_tail = NULL;
	sta->ext_auth_tail_len = 0;
__hostapd_if_auth_response_exit:
	/*
	 * Free ctx handed in from plugin
	 * (tail will be freed in TX path)
	 */
	if (ctx->data.auth_resp.additional_ies)
		os_free((void *)ctx->data.auth_resp.additional_ies);
	os_free((void *)ctx);
}

/*
 * Internal helper: build and transmit Deauth/Disassoc with optional
 * tail
 * for ML STA, pass the MLD mac of the STA as sta_mac
 */
static void __send_mgmt_disconnect(const char *ifname,
				  const u8 *sta_mac,
				  u16 reason_code,
				  int link_id,
				  const u8 *added_data,
				  size_t added_data_len,
				  int is_deauth)
{
	struct hostapd_data *hapd;
	struct sta_info *sta = NULL;
	struct ieee80211_mgmt *mgmt;
	size_t fixed_body_len;
	size_t send_len;
	u8 *buf;
	const u8 *own_addr;
	int drv_ret;
	bool is_bcast = false;

	if (sta_mac[0] == 0xff)
		is_bcast = true;

	sta = __get_sta(ifname, sta_mac, link_id, false, &hapd);
	if (!sta && !is_bcast) {
		if (hapd)
			__inbound_error_event(hapd, sta_mac,
					HOSTAPD_IF_SEND_DISCONNECT_ERROR,
					__func__, __LINE__);

		wpa_printf(MSG_ERROR,
			   "hostapd_if: %s - STA " MACSTR " not found on %s",
			   __func__, MAC2STR(sta_mac), ifname);
		goto __send_mgmt_disconnect_exit;
	}

	wpa_printf(MSG_MSGDUMP,
		   "%s: %s, " MACSTR " reason_code=%u is_deauth %d\n",
		   __func__, ifname, MAC2STR(sta_mac), reason_code, is_deauth);

	wpa_hexdump(MSG_EXCESSIVE, "__send_mgmt_disconnect",
			added_data, added_data_len);

	own_addr = hapd->own_addr;

	/*
	 * Calculate required buffer length
	 */
	if (is_deauth)
		fixed_body_len = sizeof(mgmt->u.deauth);
	else
		fixed_body_len = sizeof(mgmt->u.disassoc);

	send_len = IEEE80211_HDRLEN + fixed_body_len + added_data_len;
	if (send_len > IEEE80211_MAX_MGMT_LEN_NO_FCS) {
		__inbound_error_event(hapd, sta_mac,
				HOSTAPD_IF_SEND_DISCONNECT_ERROR,
				__func__, __LINE__);
		wpa_printf(MSG_ERROR,
			   "hostapd_if: - frame too large (send_len=%zu > max=%d) for %s "
			   MACSTR " reason=%u", send_len, IEEE80211_MAX_MGMT_LEN_NO_FCS,
			   ifname, MAC2STR(sta_mac), reason_code);
		goto __send_mgmt_disconnect_exit;
	}

	/*
	 * Allocate buffer for the entire frame
	 */
	buf = os_malloc(send_len);
	if (!buf) {
		__inbound_error_event(hapd, sta_mac,
				HOSTAPD_IF_SEND_DISCONNECT_ERROR,
				__func__, __LINE__);
		wpa_printf(MSG_ERROR,
			   "hostapd_if: %s - failed to allocate %zu bytes for frame",
			   __func__, send_len);
		goto __send_mgmt_disconnect_exit;
	}

	/*
	 * Point mgmt to the allocated buffer and fill headers directly
	 */
	mgmt = (struct ieee80211_mgmt *) buf;
	os_memset(mgmt, 0, IEEE80211_HDRLEN + fixed_body_len);

	if (is_deauth)
		mgmt->frame_control =
			IEEE80211_FC(WLAN_FC_TYPE_MGMT,
				     WLAN_FC_STYPE_DEAUTH);
	else
		mgmt->frame_control =
			IEEE80211_FC(WLAN_FC_TYPE_MGMT,
				     WLAN_FC_STYPE_DISASSOC);

#ifdef CONFIG_IEEE80211BE
	if (hapd->conf->mld_ap && ap_sta_is_mld(hapd, sta))
		own_addr = hapd->mld->mld_addr;
#endif /* CONFIG_IEEE80211BE */

	os_memcpy(mgmt->da, sta_mac, ETH_ALEN);
	os_memcpy(mgmt->sa, own_addr, ETH_ALEN);
	os_memcpy(mgmt->bssid, own_addr, ETH_ALEN);

	if (is_deauth)
		mgmt->u.deauth.reason_code = host_to_le16(reason_code);
	else
		mgmt->u.disassoc.reason_code = host_to_le16(reason_code);

	/*
	 * Append opaque tail (e.g., IEs)
	 */
	if (added_data_len > 0)
		os_memcpy(buf + IEEE80211_HDRLEN + fixed_body_len,
			  added_data, added_data_len);

	wpa_printf(MSG_DEBUG,
		   "hostapd_if: %s ifname=%s da=%02x:%02x:%02x:%02x:%02x:%02x "
		   "reason=%u tail_len=%zu send_len=%zu",
		   is_deauth ? "DEAUTH" : "DISASSOC", ifname,
		   sta_mac[0], sta_mac[1], sta_mac[2],
		   sta_mac[3], sta_mac[4], sta_mac[5],
		   reason_code, added_data_len, send_len);

	drv_ret = hostapd_drv_send_mlme(hapd, buf, send_len, 0, NULL, 0, 0, 0, 0);
	os_free(buf);
	if (drv_ret < 0) {
		__inbound_error_event(hapd, sta_mac,
				HOSTAPD_IF_SEND_DISCONNECT_ERROR,
				__func__, __LINE__);
		wpa_printf(MSG_ERROR,
			   "hostapd_if: %s - send_mlme failed (ret=%d) for %s " MACSTR " reason=%u",
			   __func__, drv_ret, ifname, MAC2STR(sta_mac), reason_code);
		goto __send_mgmt_disconnect_exit;
	}

	if (sta) {
		if (is_deauth)
			ap_sta_deauthenticate(hapd, sta, reason_code);
		else
			ap_sta_disassociate(hapd, sta, reason_code);
	}

	if (is_bcast)
		hostapd_free_stas(hapd);
__send_mgmt_disconnect_exit:
	os_free((void *)added_data);
}

void __hostapd_if_send_deauth(char *ifname, uint8_t *sta_mac,
			      uint16_t reason_code, int link_id,
			      uint8_t *added_data,
			      uint8_t added_data_len)
{
	__send_mgmt_disconnect(ifname, sta_mac, reason_code, link_id,
			added_data, (size_t) added_data_len, 1);
}

void __hostapd_if_send_disassoc(char *ifname, uint8_t *sta_mac,
				uint16_t reason_code, int link_id,
				uint8_t *added_data,
				uint8_t added_data_len)
{
	__send_mgmt_disconnect(ifname, sta_mac, reason_code, link_id,
			added_data, (size_t) added_data_len, 0);
}

void __hostapd_if_set_beacon_probe_vendor_ies(char *ifname, uint8_t *buf,
					      size_t buf_len, int link_id)
{
	struct hostapd_data *hapd;
	struct wpabuf *new_ies = NULL;

	wpa_printf(MSG_MSGDUMP,
		   "%s: %s, link_id=%d buf_len=%zu\n",
		   __func__, ifname, link_id, buf_len);

	wpa_hexdump(MSG_EXCESSIVE,
		    "hostapd_if_set_beacon_probe_vendor_ies buf",
		    buf, buf_len);

	/*
	 * Look up the interface
	 */
	hapd = __hostapd_get_link_iface(ifname, link_id);
	if (!hapd) {
		wpa_printf(MSG_ERROR,
			   "hostapd_if: set_beacon_probe_vendor_ies - "
			   "interface %s not found with link-id %d",
			   ifname, link_id);
		goto __hostapd_if_set_beacon_probe_vendor_ies_exit;
	}

#ifdef CONFIG_IEEE80211BE
	if (hapd->conf && hapd->conf->mld_ap && link_id >= 0) {
		struct hostapd_data *link =
			hostapd_mld_get_link_bss(hapd, link_id);

		if (link)
			hapd = link;
		else {
			__inbound_error_event(hapd, NULL,
				HOSTAPD_IF_SET_BEACON_PROBE_VENDOR_IES_ERROR,
				__func__, __LINE__);
			wpa_printf(MSG_ERROR,
				   "hostapd_if: ERROR! No BSS found with "
				   "link-id %d\n",
				   link_id);
			goto __hostapd_if_set_beacon_probe_vendor_ies_exit;
		}
	}
#endif /* CONFIG_IEEE80211BE */

	/*
	 * Allocate and copy the buffer
	 */
	if (buf) {
		new_ies = wpabuf_alloc_copy(buf, buf_len);
		if (!new_ies) {
			__inbound_error_event(hapd, NULL,
				HOSTAPD_IF_SET_BEACON_PROBE_VENDOR_IES_ERROR,
				__func__, __LINE__);
			wpa_printf(MSG_ERROR,
				   "hostapd_if: set_beacon_probe_vendor_ies - "
				   "failed to allocate buffer for %s",
				   ifname);
			goto __hostapd_if_set_beacon_probe_vendor_ies_exit;
		}
	}

	/*
	 * Free old buffer and set new one
	 */
	wpabuf_free(hapd->plugin_vendor_elements);
	hapd->plugin_vendor_elements = new_ies;

	if (hapd->conf && hapd->conf->mld_ap && link_id < 0) {
		unsigned int i, j;

		for (i = 0; i < hapd->iface->interfaces->count; ++i) {
			struct hostapd_iface *iface =
				hapd->iface->interfaces->iface[i];
			if (!iface)
				continue;

			for (j = 0; j < iface->num_bss; j++) {
				struct hostapd_data *partner =
					iface->bss[j];

				if (hapd == partner)
					continue;

				if (!hostapd_is_ml_partner(hapd, partner))
					continue;

				wpabuf_free(partner->plugin_vendor_elements);
				if (new_ies)
					partner->plugin_vendor_elements =
						wpabuf_dup(new_ies);
				else
					partner->plugin_vendor_elements = NULL;

				break;
			}
		}
	}

	wpa_printf(MSG_DEBUG,
		   "hostapd_if: set_beacon_probe_vendor_ies for %s, len=%zu",
		   ifname, buf_len);

	/*
	 * Trigger beacon update
	 */
	if (ieee802_11_set_beacon(hapd) < 0) {
		wpa_printf(MSG_ERROR,
			   "hostapd_if: set_beacon_probe_vendor_ies - "
			   "failed to update beacon for %s",
			   ifname);

	}
__hostapd_if_set_beacon_probe_vendor_ies_exit:
	os_free((void *)buf);
}

/*
 * Use MLD mac of STA in case of 11be STA
 */
int hostapd_if_get_pmk(char *ifname, uint8_t *sta_mac,
		       uint8_t pmk[PMK_LEN_MAX], size_t *pmk_len,
		       uint8_t pmkid[PMKID_LEN])
{
	struct hostapd_data *hapd;
	struct sta_info *sta;

	sta = __get_sta(ifname, sta_mac, -1, false, &hapd);
	if (!sta) {
		wpa_printf(MSG_ERROR,
			   "ERROR in fetching sta object %s "
			   MACSTR "\n",
			   __func__, MAC2STR(sta_mac));
		return -1;
	}

	return wpa_auth_get_pmk_full(sta->wpa_sm, pmk, pmk_len, pmkid);
}

/*
 * Use MLD mac of STA in case of 11be STA
 */
int hostapd_if_get_ptk(char *ifname, uint8_t *sta_mac,
		       uint8_t kck[MAX_KCK_LEN], size_t *kck_len,
		       uint8_t kek[MAX_KEK_LEN], size_t *kek_len,
		       uint8_t tk[MAX_TK_LEN], size_t *tk_len)
{
	struct hostapd_data *hapd;
	struct sta_info *sta;

	sta = __get_sta(ifname, sta_mac, -1, false, &hapd);
	if (!sta) {
		wpa_printf(MSG_ERROR,
			   "ERROR in fetching sta object %s "
			   MACSTR "\n",
			   __func__, MAC2STR(sta_mac));
		return -1;
	}

	return wpa_auth_get_ptk_full(sta->wpa_sm, kck, kck_len, kek, kek_len,
				     tk, tk_len);
}


int hostapd_if_get_gtk(char *ifname, int link_id, int *gtk_idx,
		       const uint8_t gtk[MAX_GTK_LEN], size_t *gtk_len)
{
	struct hostapd_data *hapd;

	hapd = __hostapd_get_link_iface(ifname, link_id);
	if (!hapd) {
		wpa_printf(MSG_ERROR, "ERROR in getting hapd %s\n", __func__);
		return -1;
	}
	return wpa_auth_get_gtk(hapd->wpa_auth, gtk_idx,
				(uint8_t *) gtk, gtk_len);
}

/*
 * ASYNC set hooks: route plugin requests to WPA authenticator
 */
/*
 * Use MLD mac of STA in case of 11be STA
 */
void __hostapd_if_set_pmk(char *ifname, uint8_t *sta_mac,
			  uint8_t *pmk, size_t pmk_len,
			  uint8_t *pmkid, int session_timeout,
			  struct dot1x_ctx *ctx, bool dot1x_done)
{
	struct hostapd_data *hapd;
	struct sta_info *sta;
	struct eapol_state_machine *eapol = NULL;
	struct wpa_state_machine *wpa_sm = NULL;

	wpa_printf(MSG_MSGDUMP,
		   "%s: %s, " MACSTR " pmk_len=%zu\n",
		   __func__, ifname, MAC2STR(sta_mac), pmk_len);

	wpa_hexdump_key(MSG_EXCESSIVE,
			"hostapd_if_set_pmk pmk",
			pmk, pmk_len);

	wpa_hexdump(MSG_EXCESSIVE,
		    "hostapd_if_set_pmk pmkid",
		    pmkid, PMKID_LEN);

	sta = __get_sta(ifname, sta_mac, -1, false, &hapd);
	if (!sta) {
		if (hapd)
			__inbound_error_event(hapd, sta_mac,
					HOSTAPD_IF_SET_PMK_ERROR,
					__func__, __LINE__);

		wpa_printf(MSG_ERROR,
			   "hostapd_if: set_pmk - STA " MACSTR " not found on %s",
			   MAC2STR(sta_mac), ifname);
		goto __hostapd_if_set_pmk_exit;
	}
	if (!sta->wpa_sm) {
		__inbound_error_event(hapd, sta_mac,
				HOSTAPD_IF_SET_PMK_ERROR,
				__func__, __LINE__);
		wpa_printf(MSG_ERROR,
			   "hostapd_if: set_pmk - wpa_sm not initialized for STA " MACSTR " on %s",
			   MAC2STR(sta_mac), ifname);
		goto __hostapd_if_set_pmk_exit;
	}

	wpa_sm = sta->wpa_sm;

	if (dot1x_done && ctx) {
		eapol = os_zalloc(sizeof(*eapol));
		if (!eapol) {
			wpa_printf(MSG_ERROR,
				   "hostapd_if: set_pmk - failed to allocate EAPOL state for STA "
				   MACSTR " on %s",
				   MAC2STR(sta_mac), ifname);
			goto __hostapd_if_set_pmk_exit;
		}
		eapol->sta = sta;
		if (ctx->identity && ctx->identity_len) {
			eapol->identity =
				(u8 *) dup_binstr(ctx->identity,
						ctx->identity_len);
			if (eapol->identity)
				eapol->identity_len = ctx->identity_len;
		}
		if (ctx->cui && ctx->cui_len)
			eapol->radius_cui =
				wpabuf_alloc_copy(ctx->cui,
						ctx->cui_len);
		eapol->acct_multi_session_id = ctx->multi_session_id;
	}

	if (wpa_auth_set_pmk_full(wpa_sm, pmk, pmkid, (int) pmk_len,
				  session_timeout, eapol)) {
		__inbound_error_event(hapd, sta_mac, HOSTAPD_IF_SET_PMK_ERROR,
				      __func__, __LINE__);
		goto __hostapd_if_set_pmk_exit;
	}

	if (dot1x_done && ctx) {
		ieee802_1x_new_station(hapd, sta);
		wpa_auth_sta_associated_start_sm(hapd->wpa_auth, wpa_sm);
	}

__hostapd_if_set_pmk_exit:
	os_free((void *)pmk);
	os_free((void *)pmkid);
	if (ctx) {
		if (ctx->identity)
			os_free(ctx->identity);
		if (ctx->cui)
			os_free(ctx->cui);
		os_free(ctx);
	}
	if (eapol) {
		if (eapol->identity)
			os_free(eapol->identity);
		if (eapol->radius_cui)
			wpabuf_free(eapol->radius_cui);
		os_free(eapol);
	}

}

/*
 * Use MLD mac of STA in case of 11be STA
 */
void __hostapd_if_set_ptk(char *ifname, uint8_t *sta_mac,
			  uint8_t *kck, size_t kck_len,
			  uint8_t *kek, size_t kek_len,
			  uint8_t *tk, size_t tk_len)
{
	struct hostapd_data *hapd;
	struct sta_info *sta;

	wpa_printf(MSG_MSGDUMP,
		   "%s: %s, " MACSTR " kck_len=%zu kek_len=%zu "
		   "tk_len=%zu\n",
		   __func__, ifname, MAC2STR(sta_mac),
		   kck_len, kek_len, tk_len);

	wpa_hexdump_key(MSG_EXCESSIVE,
			"hostapd_if_set_ptk kck",
			kck, kck_len);

	wpa_hexdump_key(MSG_EXCESSIVE,
			"hostapd_if_set_ptk kek",
			kek, kek_len);

	wpa_hexdump_key(MSG_EXCESSIVE,
			"hostapd_if_set_ptk tk",
			tk, tk_len);

	sta = __get_sta(ifname, sta_mac, -1, false, &hapd);
	if (!sta) {
		if (hapd)
			__inbound_error_event(hapd, sta_mac,
					HOSTAPD_IF_SET_PTK_ERROR,
					__func__, __LINE__);
		wpa_printf(MSG_ERROR,
			   "hostapd_if: set_ptk - STA " MACSTR " not found on %s",
			   MAC2STR(sta_mac), ifname);
		goto __hostapd_if_set_ptk_exit;
	}
	if (!sta->wpa_sm) {
		__inbound_error_event(hapd, sta_mac,
				HOSTAPD_IF_SET_PTK_ERROR,
				__func__, __LINE__);
		wpa_printf(MSG_ERROR,
			   "hostapd_if: set_ptk - wpa_sm not initialized for STA " MACSTR " on %s",
			   MAC2STR(sta_mac), ifname);
		goto __hostapd_if_set_ptk_exit;
	}

	wpa_auth_set_ptk_full(sta->wpa_sm, kck, kck_len,
			      kek, kek_len, tk, tk_len);
__hostapd_if_set_ptk_exit:
	os_free((void *)kck);
	os_free((void *)kek);
	os_free((void *)tk);
}

void __hostapd_if_set_gtk(char *ifname, int link_id,
			  int gtk_idx, uint8_t *gtk, size_t gtk_len)
{
	struct hostapd_data *hapd;

	wpa_printf(MSG_MSGDUMP,
		   "%s: %s, link-id:%d gtk_idx=%d gtk_len=%zu\n",
		   __func__, ifname, link_id,
		   gtk_idx, gtk_len);

	wpa_hexdump_key(MSG_EXCESSIVE,
			"hostapd_if_set_gtk gtk",
			gtk, gtk_len);

	hapd = __hostapd_get_link_iface(ifname, link_id);
	if (!hapd) {
		wpa_printf(MSG_ERROR,
			   "hostapd_if: set_gtk - interface %s not found",
			   ifname);
		goto __hostapd_if_set_gtk_exit;
	}

	if (!hapd->wpa_auth) {
		__inbound_error_event(hapd, NULL,
				HOSTAPD_IF_SET_GTK_ERROR,
				__func__, __LINE__);
		wpa_printf(MSG_ERROR,
			   "hostapd_if: set_gtk - wpa_auth not initialized for interface %s",
			   ifname);
		goto __hostapd_if_set_gtk_exit;
	}

	/*
	 * wpa_auth_set_gtk expects a pointer to the index
	 */
	wpa_auth_set_gtk(hapd->wpa_auth, gtk_idx, gtk, gtk_len);
__hostapd_if_set_gtk_exit:
	os_free((void *)gtk);
}

/*
 * Implementation of SA Query start entry point for plugin
 * Use MLD mac of STA in case of 11be STA
 */
void __hostapd_if_start_sa_query(char *ifname, uint8_t *sta_mac, int link_id)
{
	struct hostapd_data *hapd;
	struct sta_info *sta;

	wpa_printf(MSG_MSGDUMP,
		   "%s: %s, " MACSTR "\n",
		   __func__, ifname, MAC2STR(sta_mac));

	sta = __get_sta(ifname, sta_mac, link_id, false, &hapd);
	if (!sta) {
		if (hapd)
			__inbound_error_event(hapd, sta_mac,
					HOSTAPD_IF_START_SA_QUERY_ERROR,
					__func__, __LINE__);

		wpa_printf(MSG_ERROR,
			   "hostapd_if: start_sa_query - STA " MACSTR " not found on %s",
			   MAC2STR(sta_mac), ifname);
		goto __hostapd_if_start_sa_query_exit;
	}

	/*
	 * Call into core to start unsolicited SA Query
	 */
	if (start_unsolicited_sa_query(hapd, sta)) {
		__inbound_error_event(hapd, sta_mac,
				HOSTAPD_IF_START_SA_QUERY_ERROR,
				__func__, __LINE__);
	}
__hostapd_if_start_sa_query_exit:
	return;
}

/*
 * Resume EAPOL transmission from plugin.
 * Use MLD mac of STA in case of 11be STA.
 */
void __hostapd_if_eapol_tx(char *ifname, uint8_t *sta_mac, int link_id,
			   uint8_t type, uint8_t *data, uint16_t data_len)
{
	struct hostapd_data *hapd = NULL;
	struct sta_info *sta;

	wpa_printf(MSG_MSGDUMP,
		   "%s: %s, " MACSTR " link_id=%d type=%u data_len=%u\n",
		   __func__, ifname, MAC2STR(sta_mac), link_id, type, data_len);
	wpa_hexdump(MSG_EXCESSIVE, "hostapd_if_eapol_tx data",
		    data, data_len);

	sta = __get_sta(ifname, sta_mac, link_id, false, &hapd);
	if (!sta) {
		if (hapd)
			__inbound_error_event(hapd, sta_mac,
				      HOSTAPD_IF_EAPOL_TX_ERROR,
				      __func__, __LINE__);
		wpa_printf(MSG_ERROR,
			   "hostapd_if: eapol_tx - STA " MACSTR " not found on %s",
			   MAC2STR(sta_mac), ifname);

		goto  __hostapd_if_eapol_tx_exit;
	}

	ieee802_1x_send(hapd, sta, type, data, data_len);

 __hostapd_if_eapol_tx_exit:
	os_free((void *)data);
	return;
}


#ifdef HOSTAPD_EXTERNAL_PLUGIN
void hostapd_plugin_register(struct hostapd_external_app_object *plugin)
{
	hostapd_if_plugin = plugin;

	if (!plugin)
		return;

	/*
	 * Southbound API assignments
	 */
	plugin->register_frame = hostapd_if_register_frame;
	plugin->register_event = hostapd_if_register_event;
	plugin->get_pmk = hostapd_if_get_pmk;
	plugin->get_ptk = hostapd_if_get_ptk;
	plugin->get_gtk = hostapd_if_get_gtk;

	/*
	 * ASYNC southbound operations wired to async serializers
	 */
	hostapd_if_eloop_inbound_handlers(plugin);
}
#endif

/*
 * Event notification wrappers: emit a compact hostapd_if_event
 * to the plugin
 * Use MLD mac of STA (in addr parameter) in case of 11be STA
 */
void hostapd_if_event_deauth(struct hostapd_data *hapd, struct sta_info *sta,
			     enum hostapd_if_disconnect_type type,
			     uint16_t reason_code, bool is_tx_status,
			     int tx_status_ok)
{
	struct hostapd_if_event evt;
	int link_id = -1;

	if (!hostapd_if_is_event_registered(hapd,
					    HOSTAPD_IF_EVENT_DEAUTH))
		return;

	if (hapd->conf->mld_ap && hapd->mld)
		link_id = hapd->mld_link_id;

	os_memset(&evt, 0, sizeof(evt));
	evt.type = HOSTAPD_IF_EVENT_DEAUTH;
	os_strlcpy(evt.ifname, hapd->conf->iface,
		   sizeof(evt.ifname));
	os_memcpy(evt.sta_mac, sta->addr, sizeof(evt.sta_mac));

	evt.data.deauth_disassoc.link_id = link_id;
	if (link_id >= 0)
		os_memcpy(evt.data.deauth_disassoc.link_mac,
			  sta->mld_info.links[link_id].peer_addr, ETH_ALEN);
	evt.data.deauth_disassoc.type = type;
	evt.data.deauth_disassoc.reason_code = reason_code;
	evt.data.deauth_disassoc.is_tx_status = is_tx_status;
	evt.data.deauth_disassoc.tx_status_ok = tx_status_ok;

	wpa_printf(MSG_MSGDUMP, "%s: %d %s "MACSTR" %d %d %d %d\n", __func__,
		__LINE__, hapd->conf->iface, MAC2STR(sta->addr), link_id, reason_code,
		is_tx_status, tx_status_ok);
	HOSTAPD_EXTERNAL_PLUGIN_NOTIFY_EVENT(evt);
}

/*
 * Use MLD mac of STA (in addr parameter) in case of 11be STA
 */
void hostapd_if_event_disassoc(struct hostapd_data *hapd,
			       struct sta_info *sta,
			       enum hostapd_if_disconnect_type type,
			       uint16_t reason_code,
			       bool is_tx_status,
			       int tx_status_ok)
{
	struct hostapd_if_event evt;
	int link_id = -1;

	if (!hostapd_if_is_event_registered(hapd,
					    HOSTAPD_IF_EVENT_DISASSOC))
		return;

	if (hapd->conf->mld_ap && hapd->mld)
		link_id = hapd->mld_link_id;

	os_memset(&evt, 0, sizeof(evt));
	evt.type = HOSTAPD_IF_EVENT_DISASSOC;
	os_strlcpy(evt.ifname, hapd->conf->iface,
		   sizeof(evt.ifname));
	os_memcpy(evt.sta_mac, sta->addr, sizeof(evt.sta_mac));

	evt.data.deauth_disassoc.link_id = link_id;
	if (link_id >= 0)
		os_memcpy(evt.data.deauth_disassoc.link_mac,
			  sta->mld_info.links[link_id].peer_addr, ETH_ALEN);
	evt.data.deauth_disassoc.type = type;
	evt.data.deauth_disassoc.reason_code = reason_code;
	evt.data.deauth_disassoc.tx_status_ok = tx_status_ok;
	evt.data.deauth_disassoc.is_tx_status = is_tx_status;

	wpa_printf(MSG_MSGDUMP, "%s: %d %s "MACSTR" %d %d %d %d\n", __func__,
		__LINE__, hapd->conf->iface, MAC2STR(sta->addr), link_id, reason_code,
		is_tx_status, tx_status_ok);
	HOSTAPD_EXTERNAL_PLUGIN_NOTIFY_EVENT(evt);
}

/*
 * Use MLD mac of STA (in addr parameter) in case of 11be STA
 */
void hostapd_if_event_auth_tx_complete(struct hostapd_data *hapd,
				       const u8 *addr)
{
	struct hostapd_if_event evt;

	if (!hostapd_if_is_event_registered(
		    hapd, HOSTAPD_IF_EVENT_AUTH_TX_COMPLETE))
		return;

	os_memset(&evt, 0, sizeof(evt));
	evt.type = HOSTAPD_IF_EVENT_AUTH_TX_COMPLETE;
	os_strlcpy(evt.ifname, hapd->conf->iface,
		   sizeof(evt.ifname));
	os_memcpy(evt.sta_mac, addr, sizeof(evt.sta_mac));

	wpa_printf(MSG_MSGDUMP, "%s: %d %s "MACSTR"\n", __func__, __LINE__,
		hapd->conf->iface, MAC2STR(addr));
	HOSTAPD_EXTERNAL_PLUGIN_NOTIFY_EVENT(evt);
}

/*
 * Use MLD mac of STA (in addr parameter) in case of 11be STA
 */
void hostapd_if_event_assoc_tx_complete(struct hostapd_data *hapd,
					const u8 *addr, int ok, uint16_t status,
					uint16_t aid)
{
	struct hostapd_if_event evt;

	if (!hostapd_if_is_event_registered(
		    hapd, HOSTAPD_IF_EVENT_ASSOC_TX_COMPLETE))
		return;

	os_memset(&evt, 0, sizeof(evt));
	evt.type = HOSTAPD_IF_EVENT_ASSOC_TX_COMPLETE;
	os_strlcpy(evt.ifname, hapd->conf->iface,
		   sizeof(evt.ifname));
	os_memcpy(evt.sta_mac, addr, sizeof(evt.sta_mac));
	evt.data.assoc_resp_completion.ok = ok;
	evt.data.assoc_resp_completion.status = status;
	evt.data.assoc_resp_completion.aid = aid;

	wpa_printf(MSG_MSGDUMP, "%s: %d %s "MACSTR"\n", __func__, __LINE__,
		hapd->conf->iface, MAC2STR(addr));
	HOSTAPD_EXTERNAL_PLUGIN_NOTIFY_EVENT(evt);
}

/*
 * Use MLD mac of STA (in addr parameter) in case of 11be STA
 */
void hostapd_if_event_action_completion(struct hostapd_data *hapd,
					const u8 *addr)
{
	struct hostapd_if_event evt;

	if (!hostapd_if_is_event_registered(
		    hapd, HOSTAPD_IF_EVENT_ACTION_COMPLETION))
		return;

	os_memset(&evt, 0, sizeof(evt));
	evt.type = HOSTAPD_IF_EVENT_ACTION_COMPLETION;
	os_strlcpy(evt.ifname, hapd->conf->iface,
		   sizeof(evt.ifname));
	os_memcpy(evt.sta_mac, addr, sizeof(evt.sta_mac));

	wpa_printf(MSG_MSGDUMP, "%s: %d %s "MACSTR"\n", __func__, __LINE__,
		hapd->conf->iface, MAC2STR(addr));
	HOSTAPD_EXTERNAL_PLUGIN_NOTIFY_EVENT(evt);
}

void hostapd_if_event_gtk_completion(struct hostapd_data *hapd)
{
	struct hostapd_if_event evt;

	if (!hostapd_if_is_event_registered(
		    hapd, HOSTAPD_IF_EVENT_GTK_COMPLETION))
		return;

	os_memset(&evt, 0, sizeof(evt));
	evt.type = HOSTAPD_IF_EVENT_GTK_COMPLETION;
	os_strlcpy(evt.ifname, hapd->conf->iface, sizeof(evt.ifname));

	wpa_printf(MSG_MSGDUMP, "%s: %d %s\n", __func__, __LINE__,
		hapd->conf->iface);
	HOSTAPD_EXTERNAL_PLUGIN_NOTIFY_EVENT(evt);
}

/*
 * Use MLD mac of STA (in addr parameter) in case of 11be STA
 */
void hostapd_if_event_eapol_m2_received(struct hostapd_data *hapd,
					const u8 *addr)
{
	struct hostapd_if_event evt;

	if (!hostapd_if_is_event_registered(
		    hapd, HOSTAPD_IF_EVENT_EAPOL_M2_RECEIVED))
		return;

	os_memset(&evt, 0, sizeof(evt));
	evt.type = HOSTAPD_IF_EVENT_EAPOL_M2_RECEIVED;
	os_strlcpy(evt.ifname, hapd->conf->iface,
		   sizeof(evt.ifname));
	os_memcpy(evt.sta_mac, addr, sizeof(evt.sta_mac));

	wpa_printf(MSG_MSGDUMP, "%s: %d %s "MACSTR"\n", __func__, __LINE__,
		hapd->conf->iface, MAC2STR(addr));
	HOSTAPD_EXTERNAL_PLUGIN_NOTIFY_EVENT(evt);
}

/*
 * Use MLD mac of STA (in addr parameter) in case of 11be STA
 */
void hostapd_if_event_authorize_completion(struct hostapd_data *hapd,
					   const u8 *addr, int authorized)
{
	struct hostapd_if_event evt;

	if (!hostapd_if_is_event_registered(
		    hapd, HOSTAPD_IF_EVENT_AUTHORIZE_COMPLETION))
		return;

	os_memset(&evt, 0, sizeof(evt));
	evt.type = HOSTAPD_IF_EVENT_AUTHORIZE_COMPLETION;
	evt.data.authorize_completion.authorized = authorized;
	os_strlcpy(evt.ifname, hapd->conf->iface,
		   sizeof(evt.ifname));
	os_memcpy(evt.sta_mac, addr, sizeof(evt.sta_mac));

	wpa_printf(MSG_MSGDUMP, "%s: %d %s "MACSTR" %d\n", __func__, __LINE__,
		hapd->conf->iface, MAC2STR(addr), authorized);
	HOSTAPD_EXTERNAL_PLUGIN_NOTIFY_EVENT(evt);
}

/*
 * Use MLD mac of STA (in addr parameter) in case of 11be STA
 */
void hostapd_if_event_sa_query_completion(struct hostapd_data *hapd,
					  const u8 *addr,
					  enum hostapd_if_sa_query_status
					  status)
{
	struct hostapd_if_event evt;

	if (!hostapd_if_is_event_registered(
		    hapd, HOSTAPD_IF_EVENT_SA_QUERY_COMPLETION))
		return;

	os_memset(&evt, 0, sizeof(evt));
	evt.type = HOSTAPD_IF_EVENT_SA_QUERY_COMPLETION;
	os_strlcpy(evt.ifname, hapd->conf->iface,
		   sizeof(evt.ifname));
	os_memcpy(evt.sta_mac, addr, sizeof(evt.sta_mac));
	evt.data.sa_query.status = status;

	wpa_printf(MSG_MSGDUMP, "%s: %d %s "MACSTR" %d\n", __func__, __LINE__,
		hapd->conf->iface, MAC2STR(addr), status);
	HOSTAPD_EXTERNAL_PLUGIN_NOTIFY_EVENT(evt);
}

/*
 * Helper function to validate 802.11 IE buffer format
 */
static int validate_ie_buffer(const uint8_t *ie_buf, size_t buf_len,
			      const char *func)
{
	size_t pos = 0;
	size_t calculated_len = 0;

	if ((ie_buf && buf_len == 0) || (buf_len && !ie_buf)) {
		wpa_printf(MSG_ERROR,
			   "%s: invalid buf and len combination %p %zu\n",
			   func, ie_buf, buf_len);
		return -1;
	}

	if (!ie_buf || buf_len == 0)
		return 0; /* Empty buffer is valid */

	/*
	 * Iterate through IEs and calculate total length
	 */
	while (pos < buf_len) {
		uint8_t id;
		uint8_t len;

		/*
		 * Need at least 2 bytes for IE header (ID + Length)
		 */
		if (pos + 2 > buf_len) {
			wpa_printf(MSG_ERROR,
				   "%s: hostapd_if: IE validation failed - "
				   "incomplete IE header at offset %zu "
				   "(buf_len=%zu)",
				   func, pos, buf_len);
			return -1;
		}

		id = ie_buf[pos];
		len = ie_buf[pos + 1];

		/*
		 * Check if IE data fits within buffer
		 */
		if (pos + 2 + len > buf_len) {
			wpa_printf(MSG_ERROR,
				   "%s hostapd_if: IE validation failed - IE "
				   "(id=%u, len=%u) at offset %zu exceeds "
				   "buffer (buf_len=%zu)",
				   func, id, len, pos, buf_len);
			return -1;
		}

		/*
		 * Move to next IE
		 */
		pos += 2 + len;
		calculated_len += 2 + len;
	}

	/*
	 * Verify that calculated length matches provided buffer length
	 */
	if (calculated_len != buf_len) {
		wpa_printf(MSG_ERROR,
			   "%s hostapd_if: IE validation failed - calculated "
			   "length %zu does not match buffer length %zu",
			   func, calculated_len, buf_len);
		return -1;
	}

	return 0;
}

/*
 * Validate input stubs for async serializers
 */
int hostapd_if_assoc_response_validate_inputs(
	char *ifname, uint8_t *sta_mac, struct hostapd_if_frame_ctx *ctx)
{
	if (!ifname || !sta_mac || !ctx) {
		wpa_printf(MSG_ERROR, "%s: ERROR! NULL parameters %p:%p:%p\n",
				__func__, ifname, sta_mac, ctx);
		return -1;
	}

	if (ctx->data.assoc_resp.pmk.pmk &&
	    (!ctx->data.assoc_resp.pmk.pmkid ||
	     !ctx->data.assoc_resp.pmk.pmk_len)) {
		wpa_printf(MSG_ERROR, "%s: ERROR! Invalid PMK provided "
			   "%p %p %zu\n", __func__, ctx->data.assoc_resp.pmk.pmk,
			   ctx->data.assoc_resp.pmk.pmkid,
			   ctx->data.assoc_resp.pmk.pmk_len);
		return -1;
	}

	/*
	 * Validate additional IEs in assoc_resp
	 */
	return validate_ie_buffer(
			ctx->data.assoc_resp.additional_ies,
			ctx->data.assoc_resp.additional_ies_len, __func__);

}

int hostapd_if_auth_response_validate_inputs(
	char *ifname, uint8_t *sta_mac, struct hostapd_if_frame_ctx *ctx)
{
	if (!ifname || !sta_mac || !ctx) {
		wpa_printf(MSG_ERROR, "%s: ERROR! NULL parameters %p:%p:%p\n",
				__func__, ifname, sta_mac, ctx);
		return -1;
	}

	/*
	 * Validate additional IEs in auth_resp
	 */
	return validate_ie_buffer(
			ctx->data.auth_resp.additional_ies,
			ctx->data.auth_resp.additional_ies_len, __func__);

}

int hostapd_if_send_deauth_validate_inputs(char *ifname, uint8_t *sta_mac,
					   uint16_t reason_code,
					   uint8_t *added_data,
					   uint8_t added_data_len)
{
	if (!ifname || !sta_mac) {
		wpa_printf(MSG_ERROR, "%s: ERROR! NULL parameters %p:%p\n",
				__func__, ifname, sta_mac);
		return -1;
	}

	/*
	 * Validate added_data as 802.11 IEs
	 */
	return validate_ie_buffer(added_data, added_data_len, __func__);
}

int hostapd_if_send_disassoc_validate_inputs(char *ifname, uint8_t *sta_mac,
					     uint16_t reason_code,
					     uint8_t *added_data,
					     uint8_t added_data_len)
{
	if (!ifname || !sta_mac) {
		wpa_printf(MSG_ERROR, "%s: ERROR! NULL parameters %p:%p\n",
				__func__, ifname, sta_mac);
		return -1;
	}

	if (added_data && added_data_len == 0) {
		wpa_printf(MSG_ERROR,
			"%s: ERROR! added_data specified with 0 length\n",
			__func__);
		return -1;
	}

	/*
	 * Validate added_data as 802.11 IEs
	 */
	return validate_ie_buffer(added_data, added_data_len, __func__);
}

int hostapd_if_set_beacon_probe_vendor_ies_validate_inputs(char *ifname,
							   uint8_t *buf,
							   size_t buf_len,
							   int link_id)
{
	if (!ifname || (buf && !buf_len) || (!buf && buf_len)) {
		wpa_printf(MSG_ERROR, "%s: ERROR! INVALID parameters %p:%p:%zu\n",
				__func__, ifname, buf, buf_len);
		return -1;
	}

	/*
	 * Validate buf as 802.11 IEs
	 */
	return validate_ie_buffer(buf, buf_len, __func__);
}

int hostapd_if_set_pmk_validate_inputs(char *ifname, uint8_t *sta_mac,
				       uint8_t *pmk, size_t pmk_len,
				       uint8_t *pmkid)
{
	if (!ifname || !sta_mac || !pmk || pmk_len == 0 || !pmkid) {
		wpa_printf(MSG_ERROR,
			   "%s: ERROR! NULL/invalid parameters ifname=%p sta_mac=%p pmk=%p pmk_len=%zu pmkid=%p",
			   __func__, ifname, sta_mac, pmk, pmk_len, pmkid);
		return -1;
	}
	return 0;
}

int hostapd_if_set_ptk_validate_inputs(char *ifname, uint8_t *sta_mac,
				       uint8_t *kck, size_t kck_len,
				       uint8_t *kek, size_t kek_len,
				       uint8_t *tk, size_t tk_len)
{
	if (!ifname || !sta_mac || !kck || kck_len == 0 || !kek ||
			kek_len == 0 || !tk || tk_len == 0) {
		wpa_printf(MSG_ERROR,
			   "%s: ERROR! NULL/invalid parameters ifname=%p sta_mac=%p kck=%p kck_len=%zu kek=%p kek_len=%zu tk=%p tk_len=%zu",
			   __func__, ifname, sta_mac, kck, kck_len,
			   kek, kek_len, tk, tk_len);
		return -1;
	}
	return 0;
}

int hostapd_if_set_gtk_validate_inputs(char *ifname, int link_id,
				       int gtk_idx, uint8_t *gtk,
				       size_t gtk_len)
{
	const int GTK_INDEX_OFFSET = 1;

	if (gtk_idx != GTK_INDEX_OFFSET &&
	    gtk_idx != (GTK_INDEX_OFFSET + 1)) {
		wpa_printf(MSG_ERROR, "%s: ERROR! invalid GTK index %d",
			   __func__, gtk_idx);
		return -1;
	}

	if (!ifname || (link_id > 0xf) || !gtk || gtk_len == 0) {
		wpa_printf(MSG_ERROR,
			   "%s: ERROR! NULL/invalid parameters ifname=%p link_id=%d gtk=%p gtk_len=%zu",
			   __func__, ifname, link_id, gtk, gtk_len);
		return -1;
	}

	return 0;
}

int hostapd_if_start_sa_query_validate_inputs(char *ifname,
					      uint8_t *sta_mac,
					      int link_id)
{
	if (!ifname || !sta_mac || (link_id > 0xf)) {
		wpa_printf(MSG_ERROR, "%s: ERROR! NULL parameters %p:%p %d",
			   __func__, ifname, sta_mac, link_id);
		return -1;
	}
	return 0;
}

int hostapd_if_trigger_eapol_m3_validate_inputs(char *ifname,
						uint8_t *sta_mac)
{
	if (!ifname || !sta_mac) {
		wpa_printf(MSG_ERROR, "%s: ERROR! NULL parameters %p:%p",
			   __func__, ifname, sta_mac);
		return -1;
	}
	return 0;
}

int hostapd_if_eapol_tx_validate_inputs(char *ifname, uint8_t *sta_mac,
					int link_id, uint8_t *data,
					uint16_t data_len)
{
	static const size_t HOSTAPD_IF_MAX_EAP_DATA = 1500;
	if (!ifname || !sta_mac || (!data && data_len)) {
		wpa_printf(MSG_ERROR, "hostapd_if_eapol_tx: Invalid parameters");
		return -1;
	}

	if (link_id < -1 || link_id >= MAX_MLO_LINKS) {
		wpa_printf(MSG_ERROR,
			   "hostapd_if_eapol_tx: Invalid link_id %d",
			   link_id);
		return -1;
	}

	if (data_len > HOSTAPD_IF_MAX_EAP_DATA) {
		wpa_printf(MSG_ERROR,
			   "hostapd_if_eapol_tx: Data length %hu exceeds maximum %zu",
			   data_len, HOSTAPD_IF_MAX_EAP_DATA);
		return -1;
	}

	return 0;
}

void hostapd_if_assoc_response_dump_params(char *ifname, uint8_t *sta_mac,
					   struct hostapd_if_frame_ctx *ctx)
{
	wpa_printf(MSG_MSGDUMP,
		   "%s: %s, " MACSTR " %d %d\n",
		   __func__, ifname, MAC2STR(sta_mac),
		   ctx->data.assoc_resp.is_reassoc,
		   ctx->data.assoc_resp.rssi);

	wpa_hexdump(MSG_EXCESSIVE,
		    __func__,
		    ctx->data.assoc_resp.additional_ies,
		    ctx->data.assoc_resp.additional_ies_len);
}

void hostapd_if_auth_response_dump_params(char *ifname, uint8_t *sta_mac,
					  struct hostapd_if_frame_ctx *ctx)
{
	wpa_printf(MSG_MSGDUMP,
		   "%s: %s, " MACSTR " status=%u auth_alg=%u "
		   "auth_transaction=%u\n",
		   __func__, ifname, MAC2STR(sta_mac), ctx->status_code,
		   ctx->data.auth_resp.auth_alg,
		   ctx->data.auth_resp.auth_transaction);

	wpa_hexdump(MSG_EXCESSIVE,
		    __func__,
		    ctx->data.auth_resp.additional_ies,
		    ctx->data.auth_resp.additional_ies_len);
}

void hostapd_if_send_deauth_dump_params(char *ifname, uint8_t *sta_mac,
					uint16_t reason_code,
					int link_id,
					uint8_t *added_data,
					uint8_t added_data_len)
{
	wpa_printf(MSG_MSGDUMP,
		   "%s: %s, " MACSTR " reason_code=%u link_id = %d\n",
		   __func__, ifname, MAC2STR(sta_mac), reason_code, link_id);

	wpa_hexdump(MSG_EXCESSIVE,
		    __func__,
		    added_data, added_data_len);
}

void hostapd_if_send_disassoc_dump_params(char *ifname, uint8_t *sta_mac,
					  uint16_t reason_code,
					  uint8_t *added_data,
					  uint8_t added_data_len)
{
	wpa_printf(MSG_MSGDUMP,
		   "%s: %s, " MACSTR " reason_code=%u\n",
		   __func__, ifname, MAC2STR(sta_mac), reason_code);

	wpa_hexdump(MSG_EXCESSIVE,
		    __func__,
		    added_data, added_data_len);
}

void hostapd_if_set_beacon_probe_vendor_ies_dump_params(
	char *ifname, uint8_t *buf, size_t buf_len, int link_id)
{
	wpa_printf(MSG_MSGDUMP,
		   "%s: %s, link_id=%d buf_len=%zu\n",
		   __func__, ifname, link_id, buf_len);

	wpa_hexdump(MSG_EXCESSIVE,
		    __func__,
		    buf, buf_len);
}

void hostapd_if_set_pmk_dump_params(char *ifname, uint8_t *sta_mac,
				    uint8_t *pmk, size_t pmk_len,
				    uint8_t *pmkid)
{
	wpa_printf(MSG_MSGDUMP,
		   "%s: %s, " MACSTR " pmk_len=%zu\n",
		   __func__, ifname, MAC2STR(sta_mac), pmk_len);

	wpa_hexdump_key(MSG_EXCESSIVE,
			__func__,
			pmk, pmk_len);

	wpa_hexdump(MSG_EXCESSIVE,
		    __func__,
		    pmkid, PMKID_LEN);
}

void hostapd_if_set_ptk_dump_params(char *ifname, uint8_t *sta_mac,
				    uint8_t *kck, size_t kck_len,
				    uint8_t *kek, size_t kek_len,
				    uint8_t *tk, size_t tk_len)
{
	wpa_printf(MSG_MSGDUMP,
		   "%s: %s, " MACSTR " kck_len=%zu kek_len=%zu "
		   "tk_len=%zu\n",
		   __func__, ifname, MAC2STR(sta_mac),
		   kck_len, kek_len, tk_len);

	wpa_hexdump_key(MSG_EXCESSIVE,
			__func__,
			kck, kck_len);

	wpa_hexdump_key(MSG_EXCESSIVE,
			__func__,
			kek, kek_len);

	wpa_hexdump_key(MSG_EXCESSIVE,
			__func__,
			tk, tk_len);
}

void hostapd_if_set_gtk_dump_params(char *ifname, int link_id,
				    int gtk_idx, uint8_t *gtk, size_t gtk_len)
{
	wpa_printf(MSG_MSGDUMP,
		   "%s: %s, link:%d gtk_idx=%d gtk_len=%zu\n",
		   __func__, ifname, link_id,
		   gtk_idx, gtk_len);

	wpa_hexdump_key(MSG_EXCESSIVE,
			__func__,
			gtk, gtk_len);
}

void hostapd_if_start_sa_query_dump_params(char *ifname, uint8_t *sta_mac, int link_id)
{
	wpa_printf(MSG_MSGDUMP,
		   "%s: %s, " MACSTR " %d\n",
		   __func__, ifname, MAC2STR(sta_mac), link_id);
}

void hostapd_if_trigger_eapol_m3_dump_params(char *ifname, uint8_t *sta_mac)
{
	wpa_printf(MSG_MSGDUMP,
		   "%s: %s, " MACSTR "\n",
		   __func__, ifname, MAC2STR(sta_mac));
}

size_t hostapd_if_auth_reply_tail_len(struct sta_info *sta, size_t current_len)
{
	size_t tail_len;

	if (!sta)
		return 0;

	tail_len = sta->ext_auth_tail_len;

	if (!sta->ext_auth_tail || !tail_len) {
		wpa_printf(MSG_MSGDUMP, "%s: No tail %p %zu", __func__,
			sta->ext_auth_tail, tail_len);
		return 0;
	}

	/* Enforce max mgmt frame size for additional IEs; drop tail if it would overflow */
	if (current_len + tail_len > 2300) {
		wpa_printf(MSG_ERROR,
			"Auth Response additional IEs exceed max mgmt frame length; dropping");
		return 0;
	}
	return tail_len;
}

void hostapd_if_auth_reply_add_tail(struct sta_info *sta, size_t offset,
				    size_t tail_len,
				    struct ieee80211_mgmt *reply)
{
	/* Append external additional IEs, if any (always supported) */
	if (!tail_len || !sta || !sta->ext_auth_tail)
		return;

	os_memcpy(reply->u.auth.variable + offset, sta->ext_auth_tail,
		tail_len);
}

void hostapd_if_assoc_resp_tail(struct sta_info *sta, size_t buflen,
				size_t current_len, u8 **p)
{
	size_t tail_len;
	u8 *pos = *p;

	if (!sta)
		return;

	tail_len = sta->ext_assoc_tail_len;
	if (!sta->ext_assoc_tail || !tail_len) {
		wpa_printf(MSG_MSGDUMP, "%s: No tail %p %zu", __func__,
			sta->ext_assoc_tail, tail_len);
		return;
	}

	if ((current_len + tail_len) > buflen) {
		/* Not enough preallocated tailroom; drop with error */
		wpa_printf(MSG_ERROR,
			"Assoc Response additional IEs exceed local buffer;"
			" dropping\n");
		return;
	}

	os_memcpy(pos, sta->ext_assoc_tail, tail_len);
	*p = (pos + tail_len);
}

size_t hostapd_if_assoc_resp_tail_len(struct sta_info *sta, size_t current_len)
{
	size_t tail_len;

	if (!sta)
		return 0;

	tail_len = sta->ext_assoc_tail_len;
	if (!sta->ext_assoc_tail || !tail_len) {
		wpa_printf(MSG_MSGDUMP, "%s: No tail %p %zu", __func__,
			sta->ext_assoc_tail, tail_len);
		return 0;
	}

	/* Enforce max mgmt frame size for additional IEs; drop tail if it would overflow */
	if (current_len + tail_len > 2300) {
		wpa_printf(MSG_ERROR, "Assoc Response additional IEs exceed"
			" max mgmt frame length; dropping\n");
		return 0;
	}

	return tail_len;
}
