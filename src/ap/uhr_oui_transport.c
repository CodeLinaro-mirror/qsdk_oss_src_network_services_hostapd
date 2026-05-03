/*
 * hostapd / IEEE 802.11bn UHR
 *
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 */

#include "utils/includes.h"
#include "utils/common.h"
#include "utils/eloop.h"
#include "l2_packet/l2_packet.h"
#include "hostapd.h"
#include "uhr_oui_transport.h"
#include "uhr_iap.h"
#include "uhr_utils.h"
#include "ap_config.h"


/**
 * uhr_oui_rx_callback - Receive callback for ETH_P_OUI frames
 * @ctx: OUI context
 * @src_addr: Source MAC address
 * @buf: Received frame buffer
 * @len: Frame length
 *
 * Called by L2 packet layer when ETH_P_OUI frame is received.
 * Validates OUI header and dispatches to IAP handler.
 */
static void uhr_oui_rx_callback(void *ctx, const u8 *src_addr,
				const u8 *buf, size_t len)
{
	struct uhr_oui_ctx *oui_ctx = ctx;
	u8 oui_suffix;
	u8 dst_addr[ETH_ALEN] = {0};

	wpa_printf(MSG_DEBUG,
		   "SMD OUI: Received frame from " MACSTR " (len=%zu)",
		   MAC2STR(src_addr), len);

	/* Validate minimum length (OUI header = 4 bytes) */
	if (len < 4) {
		wpa_printf(MSG_DEBUG, "SMD OUI: Frame too short (%zu < 4)",
			   len);
		return;
	}

	wpa_hexdump(MSG_DEBUG, "SMD OUI: Received UHR OUI frame", buf, len);

	oui_suffix = *(buf + sizeof(struct l2_ethhdr) + 5);

	/* Validate suffix */
	if (oui_suffix != UHR_IAP_SUFFIX_REQUEST &&
	    oui_suffix != UHR_IAP_SUFFIX_RESPONSE) {
		wpa_printf(MSG_DEBUG, "SMD OUI: Invalid suffix 0x%02x",
			   oui_suffix);
		return;
	}

	wpa_printf(MSG_DEBUG, "SMD OUI: Valid frame (suffix=0x%02x)",
		   oui_suffix);

	os_memcpy(dst_addr, buf, ETH_ALEN);

	/* Dispatch to IAP handler (skip OUI header) */
	uhr_iap_rx(oui_ctx->hapd, src_addr, dst_addr, buf + sizeof(struct l2_ethhdr) + 6, len - sizeof(struct l2_ethhdr) - 6, oui_suffix);
}


/**
 * uhr_oui_init - Initialize UHR OUI transport
 */
struct uhr_oui_ctx *uhr_oui_init(struct hostapd_data *hapd)
{
	struct uhr_oui_ctx *ctx;

	wpa_printf(MSG_DEBUG,
		   "SMD OUI: Initializing native ETH_P_OUI transport");

	ctx = os_zalloc(sizeof(*ctx));
	if (!ctx) {
		wpa_printf(MSG_ERROR, "SMD OUI: Failed to allocate context");
		return NULL;
	}

	ctx->hapd = hapd;
	os_memcpy(ctx->own_addr, hapd->own_addr, ETH_ALEN);

	/* Create L2 packet socket for ETH_P_OUI */
	wpa_printf(MSG_INFO, "SMD OUI: Bridge is currently %s", hapd->conf->bridge);
	ctx->l2 = l2_packet_init(hapd->conf->bridge, NULL, ETH_P_OUI,
				 uhr_oui_rx_callback, ctx, 1);
	if (!ctx->l2) {
		wpa_printf(MSG_ERROR,
			   "SMD OUI: Failed to create L2 socket for interface %s",
			   hapd->conf->bridge);
		os_free(ctx);
		return NULL;
	}

	wpa_printf(MSG_INFO,
		   "SMD OUI: Initialized on interface %s (MAC " MACSTR ")",
		   hapd->conf->bridge, MAC2STR(ctx->own_addr));

	return ctx;
}


/**
 * uhr_oui_deinit - Cleanup UHR OUI transport
 */
void uhr_oui_deinit(struct uhr_oui_ctx *ctx)
{
	struct uhr_peer_entry *peer, *next;

	if (!ctx)
		return;

	wpa_printf(MSG_DEBUG, "SMD OUI: Deinitializing transport");

	if (ctx->l2) {
		l2_packet_deinit(ctx->l2);
		ctx->l2 = NULL;
	}

	/* Free peer list */
	peer = ctx->peers;
	while (peer) {
		next = peer->next;
		os_free(peer);
		peer = next;
	}

	os_free(ctx);
}


/**
 * uhr_oui_peer_exists - Check if peer exists in configured list
 */
int uhr_oui_peer_exists(struct uhr_oui_ctx *ctx, const u8 *mac_addr)
{
	struct uhr_peer_entry *peer;

	if (!ctx || !mac_addr)
		return 0;

	peer = ctx->peers;
	while (peer) {
		if (ether_addr_equal(peer->mac_addr, mac_addr))
			return 1;
		peer = peer->next;
	}

	return 0;
}


/**
 * uhr_oui_add_peer - Add peer to configured list
 */
int uhr_oui_add_peer(struct uhr_oui_ctx *ctx, const u8 *mac_addr)
{
	struct uhr_peer_entry *peer;

	if (!ctx || !mac_addr)
		return -1;

	/* Check if already exists */
	if (uhr_oui_peer_exists(ctx, mac_addr)) {
		wpa_printf(MSG_DEBUG, "SMD OUI: Peer " MACSTR " already exists",
			   MAC2STR(mac_addr));
		return 0;
	}

	peer = os_zalloc(sizeof(*peer));
	if (!peer) {
		wpa_printf(MSG_ERROR, "SMD OUI: Failed to allocate peer entry");
		return -1;
	}

	os_memcpy(peer->mac_addr, mac_addr, ETH_ALEN);
	peer->next = ctx->peers;
	ctx->peers = peer;

	wpa_printf(MSG_DEBUG, "SMD OUI: Added peer " MACSTR,
		   MAC2STR(mac_addr));
	return 0;
}


/**
 * uhr_oui_send - Send SMD IAP frame via ETH_P_OUI
 */
static const u8 global_oui_smd[] = { 0x00, 0x13, 0x74, 0x00, 0x02};
int uhr_oui_send(struct uhr_oui_ctx *ctx, const u8 *dst_addr, const u8 *src_addr, u8 oui_suffix,
		 const u8 *data, size_t data_len)
{
	u8 *packet, *p;
	size_t packet_len;
	int ret;
	struct l2_ethhdr *ethhdr;

	packet_len = sizeof(*ethhdr) + sizeof(global_oui_smd) + 1 + data_len;
	packet = os_zalloc(packet_len);
	if (!packet)
		return -1;
	p = packet;

	ethhdr = (struct l2_ethhdr *) packet;
	os_memcpy(ethhdr->h_source, src_addr, ETH_ALEN);
	os_memcpy(ethhdr->h_dest, dst_addr, ETH_ALEN);
	ethhdr->h_proto = host_to_be16(ETH_P_OUI);
	p += sizeof(*ethhdr);

	os_memcpy(p, global_oui_smd, sizeof(global_oui_smd));
	p[sizeof(global_oui_smd)] = oui_suffix;
	p += sizeof(global_oui_smd) + 1;

	os_memcpy(p, data, data_len);

	wpa_hexdump(MSG_DEBUG, "SMD OUI: Sending UHR OUI frame", packet, packet_len);

	ret = l2_packet_send(ctx->l2, NULL, 0, packet, packet_len);
	os_free(packet);
	if (ret < 0)
		wpa_printf(MSG_ERROR, "SMD OUI: l2_packet_send to " MACSTR " failed: %d",
			   MAC2STR(dst_addr), ret);
	return ret;
}


/**
 * uhr_load_partners - Load configured SMD partner APs
 * @hapd: hostapd data
 * Returns: Number of partners loaded, or -1 on error
 *
 * Loads SMD partner APs from configuration into OUI transport context.
 * Called during hostapd initialization after OUI transport is created.
 */
int uhr_load_partners(struct hostapd_data *hapd)
{
	struct smd_partner_entry *partner;
	int count = 0;

	if (!hapd->conf->smd_partners) {
		wpa_printf(MSG_WARNING, "SMD: No partners configured");
		return 0;
	}

	for (partner = hapd->conf->smd_partners; partner; partner = partner->next) {
		if (uhr_oui_add_peer(hapd->uhr_oui_ctx, partner->mac_addr) < 0) {
			wpa_printf(MSG_ERROR,
				   "SMD: Failed to add partner " MACSTR,
				   MAC2STR(partner->mac_addr));
			continue;
		}
		count++;
	}

	wpa_printf(MSG_INFO, "SMD: Loaded %d partner(s)", count);
	return count;
}
