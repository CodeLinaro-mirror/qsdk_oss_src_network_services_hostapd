/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: ISC
 */

#include <libmnl/libmnl.h>
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>
#include "utils/includes.h"
#include <linux/netfilter.h>
#include <linux/version.h>
#include "utils/common.h"
#include "hostapd.h"
#include "nft.h"

/* NFT support requires Linux kernel 5.16+ for NF_NETDEV_EGRESS */
#define NFT_MIN_KERNEL_VERSION KERNEL_VERSION(5, 16, 0)

#define NFT_SUPPORTED (LINUX_VERSION_CODE >= NFT_MIN_KERNEL_VERSION)

#define BATCH_BUF_SIZE		8192
#define NFNL_SUBSYS_RES_ID	10  /* Resource ID for nfnetlink subsystem */

/**
 * struct nft_global - Global NFT netlink socket management
 */
struct nft_global {
	struct mnl_socket *nl;
	u32 seq;
	unsigned int portid;
};

/* Global NFT context */
static struct nft_global *g_nft_global = NULL;

#if NFT_SUPPORTED

/* Full NFT implementation for kernel >= 5.16 */

/**
 * parse_nft_table_attr - Parse table attributes from netlink message
 * @attr: Netlink attribute
 * @data: Pointer to attribute table array
 */
static int parse_nft_table_attr(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_TABLE_MAX) < 0)
		return MNL_CB_OK;

	switch (type) {
	case NFTA_TABLE_NAME:
		if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0) {
			wpa_printf(MSG_DEBUG,
				   "NFT: Invalid table name attribute");
			return MNL_CB_ERROR;
		}
		break;
	case NFTA_TABLE_FLAGS:
		if (mnl_attr_validate(attr, MNL_TYPE_U32) < 0) {
			wpa_printf(MSG_DEBUG,
				   "NFT: Invalid table flags attribute");
			return MNL_CB_ERROR;
		}
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

/**
 * parse_nft_chain_attr - Parse chain attributes from netlink message
 * @attr: Netlink attribute
 * @data: Pointer to attribute table array
 */
static int parse_nft_chain_attr(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	if (mnl_attr_type_valid(attr, NFTA_CHAIN_MAX) < 0)
		return MNL_CB_OK;

	switch (type) {
	case NFTA_CHAIN_NAME:
	case NFTA_CHAIN_TABLE:
		if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0) {
			wpa_printf(MSG_DEBUG,
				   "NFT: Invalid chain attribute");
			return MNL_CB_ERROR;
		}
		break;
	case NFTA_CHAIN_HANDLE:
		if (mnl_attr_validate(attr, MNL_TYPE_U64) < 0) {
			wpa_printf(MSG_DEBUG,
				   "NFT: Invalid chain handle attribute");
			return MNL_CB_ERROR;
		}
		break;
	}

	tb[type] = attr;
	return MNL_CB_OK;
}

/**
 * nl_cb_handle_table - Handle table-related netlink messages
 * @nlh: Netlink message header
 * @nfg: NFGen message
 * @msg_type: Message type
 */
static void nl_cb_handle_table(const struct nlmsghdr *nlh,
				const struct nfgenmsg *nfg, uint8_t msg_type)
{
	struct nlattr *tb[NFTA_TABLE_MAX + 1] = {};
	const char *operation;
	const char *table_name;
	u32 flags = 0;

	mnl_attr_parse(nlh, sizeof(*nfg), parse_nft_table_attr, tb);

	operation = (msg_type == NFT_MSG_NEWTABLE) ? "created" : "deleted";

	if (tb[NFTA_TABLE_NAME]) {
		table_name = mnl_attr_get_str(tb[NFTA_TABLE_NAME]);

		if (tb[NFTA_TABLE_FLAGS])
			flags = ntohl(mnl_attr_get_u32(tb[NFTA_TABLE_FLAGS]));

		wpa_printf(MSG_INFO,
			   "NFT: Table '%s' %s successfully (family=%u, flags=0x%x, seq=%u)",
			   table_name, operation, nfg->nfgen_family, flags,
			   nlh->nlmsg_seq);
	} else {
		wpa_printf(MSG_WARNING,
			   "NFT: Table %s but name attribute missing (seq=%u)",
			   operation, nlh->nlmsg_seq);
	}
}

/**
 * nl_cb_handle_chain - Handle chain-related netlink messages
 * @nlh: Netlink message header
 * @nfg: NFGen message
 * @msg_type: Message type
 */
static void nl_cb_handle_chain(const struct nlmsghdr *nlh,
				const struct nfgenmsg *nfg, uint8_t msg_type)
{
	struct nlattr *tb[NFTA_CHAIN_MAX + 1] = {};
	const char *operation;
	const char *chain_name;
	const char *table_name;
	u64 handle = 0;

	mnl_attr_parse(nlh, sizeof(*nfg), parse_nft_chain_attr, tb);

	operation = (msg_type == NFT_MSG_NEWCHAIN) ? "created" : "deleted";

	if (tb[NFTA_CHAIN_TABLE] && tb[NFTA_CHAIN_NAME]) {
		chain_name = mnl_attr_get_str(tb[NFTA_CHAIN_NAME]);
		table_name = mnl_attr_get_str(tb[NFTA_CHAIN_TABLE]);

		if (tb[NFTA_CHAIN_HANDLE])
			handle = be64toh(mnl_attr_get_u64(tb[NFTA_CHAIN_HANDLE]));

		wpa_printf(MSG_INFO,
			   "NFT: Chain '%s' in table '%s' %s successfully (family=%u, handle=%llu, seq=%u)",
			   chain_name, table_name, operation,
			   nfg->nfgen_family, (unsigned long long) handle,
			   nlh->nlmsg_seq);
	} else {
		wpa_printf(MSG_WARNING,
			   "NFT: Chain %s but required attributes missing (seq=%u) - table=%s, chain=%s",
			   operation, nlh->nlmsg_seq,
			   tb[NFTA_CHAIN_TABLE] ? "present" : "missing",
			   tb[NFTA_CHAIN_NAME] ? "present" : "missing");
	}
}

/**
 * nl_cb - Netlink callback to handle kernel responses
 * @nlh: The netlink message header
 * @data: User-provided data
 * Returns: MNL_CB_OK on success, MNL_CB_ERROR on error, MNL_CB_STOP when done
 */
static int nl_cb(const struct nlmsghdr *nlh, void *data)
{
	const struct nlmsgerr *err;
	const struct nfgenmsg *nfg;
	uint8_t subsys, msg_type;

	/* Handle error messages */
	if (nlh->nlmsg_type == NLMSG_ERROR) {
		err = mnl_nlmsg_get_payload(nlh);
		if (err->error == 0) {
			/* ACK received - operation succeeded */
			wpa_printf(MSG_DEBUG,
				   "NFT: Netlink ACK received - operation successful (seq=%u)",
				   nlh->nlmsg_seq);
			return MNL_CB_OK;
		}

		/* Error occurred */
		wpa_printf(MSG_ERROR,
			   "NFT: Netlink operation failed - %s (errno=%d, seq=%u)",
			   strerror(-err->error), -err->error,
			   nlh->nlmsg_seq);

		return MNL_CB_ERROR;
	}

	/* Handle completion message */
	if (nlh->nlmsg_type == NLMSG_DONE) {
		wpa_printf(MSG_DEBUG,
			   "NFT: Netlink batch processing completed successfully (seq=%u)",
			   nlh->nlmsg_seq);
		return MNL_CB_STOP;
	}

	/* Parse nftables messages */
	subsys = NFNL_SUBSYS_ID(nlh->nlmsg_type);
	if (subsys != NFNL_SUBSYS_NFTABLES) {
		wpa_printf(MSG_DEBUG,
			   "NFT: Received non-nftables netlink message (subsys=%u, seq=%u)",
			   subsys, nlh->nlmsg_seq);
		return MNL_CB_OK;
	}

	nfg = mnl_nlmsg_get_payload(nlh);
	msg_type = NFNL_MSG_TYPE(nlh->nlmsg_type);

	wpa_printf(MSG_DEBUG,
		   "NFT: Processing nftables message (type=%u, seq=%u)",
		   msg_type, nlh->nlmsg_seq);

	switch (msg_type) {
	case NFT_MSG_NEWTABLE:
	case NFT_MSG_DELTABLE:
		nl_cb_handle_table(nlh, nfg, msg_type);
		break;
	case NFT_MSG_NEWCHAIN:
	case NFT_MSG_DELCHAIN:
		nl_cb_handle_chain(nlh, nfg, msg_type);
		break;
	default:
		wpa_printf(MSG_DEBUG,
			   "NFT: Unhandled nftables message type %u (seq=%u)",
			   msg_type, nlh->nlmsg_seq);
		break;
	}

	return MNL_CB_OK;
}

/**
 * nft_init - Initialize NFT netlink socket
 * Returns: 0 on success, -1 on failure
 */
int nft_init(void)
{
	if (g_nft_global) {
		wpa_printf(MSG_DEBUG, "NFT: Already initialized");
		return 0;
	}

	g_nft_global = os_zalloc(sizeof(*g_nft_global));
	if (!g_nft_global) {
		wpa_printf(MSG_ERROR, "NFT: Failed to allocate global context");
		return -1;
	}

	g_nft_global->nl = mnl_socket_open(NETLINK_NETFILTER);
	if (!g_nft_global->nl) {
		wpa_printf(MSG_ERROR, "NFT: Failed to open netlink socket: %s",
			   strerror(errno));
		os_free(g_nft_global);
		g_nft_global = NULL;
		return -1;
	}

	if (mnl_socket_bind(g_nft_global->nl, 0, MNL_SOCKET_AUTOPID) < 0) {
		wpa_printf(MSG_ERROR, "NFT: Failed to bind netlink socket: %s",
			   strerror(errno));
		mnl_socket_close(g_nft_global->nl);
		os_free(g_nft_global);
		g_nft_global = NULL;
		return -1;
	}

	g_nft_global->portid = mnl_socket_get_portid(g_nft_global->nl);
	g_nft_global->seq = 0;

	wpa_printf(MSG_INFO, "NFT: Initialized (portid=%u)",
		   g_nft_global->portid);
	return 0;
}

/**
 * nft_deinit - Deinitialize NFT netlink socket
 */
void nft_deinit(void)
{
	if (!g_nft_global)
		return;

	if (g_nft_global->nl) {
		mnl_socket_close(g_nft_global->nl);
		g_nft_global->nl = NULL;
	}

	os_free(g_nft_global);
	g_nft_global = NULL;

	wpa_printf(MSG_INFO, "NFT: Deinitialized");
}

/**
 * nft_send_and_receive - Send netlink batch and receive response
 * @batch: Netlink message batch
 * Returns: 0 on success, -1 on failure
 */
static int nft_send_and_receive(struct mnl_nlmsg_batch *batch)
{
	char rcv_buf[4096];
	int ret, recv_count = 0;
	u32 seq;
	size_t batch_size;

	if (!g_nft_global || !g_nft_global->nl) {
		wpa_printf(MSG_ERROR,
			   "NFT: Cannot send batch - global context not initialized");
		return -1;
	}

	seq = ++g_nft_global->seq;
	batch_size = mnl_nlmsg_batch_size(batch);

	wpa_printf(MSG_DEBUG,
		   "NFT: Preparing to send netlink batch (seq=%u, portid=%u, size=%zu bytes)",
		   seq, g_nft_global->portid, batch_size);

	ret = mnl_socket_sendto(g_nft_global->nl,
				mnl_nlmsg_batch_head(batch),
				batch_size);
	if (ret < 0) {
		wpa_printf(MSG_ERROR,
			   "NFT: Failed to send netlink batch - %s (errno=%d, seq=%u)",
			   strerror(errno), errno, seq);
		return -1;
	}

	wpa_printf(MSG_DEBUG,
		   "NFT: Netlink batch sent successfully (%d bytes transmitted, seq=%u)",
		   ret, seq);

	mnl_nlmsg_batch_stop(batch);

	wpa_printf(MSG_DEBUG,
		   "NFT: Waiting for netlink responses (seq=%u)...",
		   seq);

	/* Receive and process responses */
	do {
		ret = mnl_socket_recvfrom(g_nft_global->nl, rcv_buf,
					  sizeof(rcv_buf));
		if (ret == -1) {
			if (errno == EINTR) {
				wpa_printf(MSG_DEBUG,
					   "NFT: Receive interrupted, retrying...");
				continue;
			}
			wpa_printf(MSG_ERROR,
				   "NFT: Failed to receive netlink response - %s (errno=%d, seq=%u)",
				   strerror(errno), errno, seq);
			break;
		}

		recv_count++;
		wpa_printf(MSG_DEBUG,
			   "NFT: Received netlink message #%d (%d bytes, seq=%u)",
			   recv_count, ret, seq);

		ret = mnl_cb_run(rcv_buf, ret, seq, g_nft_global->portid,
				 nl_cb, NULL);
		if (ret <= 0) {
			if (ret == MNL_CB_STOP) {
				wpa_printf(MSG_DEBUG,
					   "NFT: Netlink batch processing complete (received %d messages, seq=%u)",
					   recv_count, seq);
			} else if (ret == MNL_CB_ERROR) {
				wpa_printf(MSG_ERROR,
					   "NFT: Netlink callback returned error (seq=%u)",
					   seq);
			}
			break;
		}
	} while (1);

	if (ret < 0) {
		wpa_printf(MSG_ERROR,
			   "NFT: Netlink batch operation failed (seq=%u, received %d messages)",
			   seq, recv_count);
		return -1;
	}

	wpa_printf(MSG_DEBUG,
		   "NFT: Netlink batch operation completed successfully (seq=%u, received %d messages)",
		   seq, recv_count);
	return 0;
}

/**
 * hostapd_mnl_batch_begin - Start a netlink batch operation
 * @batch: Netlink message batch
 * @cur_seq: Current sequence number
 */
static int hostapd_mnl_batch_begin(struct mnl_nlmsg_batch *batch,
				    uint32_t cur_seq)
{
	uint16_t family = NFPROTO_NETDEV;
	struct nlmsghdr *nlh;
	struct nfgenmsg *nfg;

	nlh = mnl_nlmsg_put_header(mnl_nlmsg_batch_current(batch));
	nlh->nlmsg_type = NFNL_MSG_BATCH_BEGIN;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq = cur_seq;

	/* nfgenmsg header */
	nfg = mnl_nlmsg_put_extra_header(nlh, sizeof(*nfg));
	nfg->nfgen_family = family;
	nfg->version = NFNETLINK_V0;
	nfg->res_id = htons(NFNL_SUBSYS_RES_ID);

	mnl_nlmsg_batch_next(batch);

	return 0;
}

/**
 * hostapd_mnl_batch_end - End a netlink batch operation
 * @batch: Netlink message batch
 * @cur_seq: Current sequence number
 */
static int hostapd_mnl_batch_end(struct mnl_nlmsg_batch *batch,
				  uint32_t cur_seq)
{
	uint16_t family = NFPROTO_NETDEV;
	struct nlmsghdr *nlh;
	struct nfgenmsg *nfg;

	nlh = mnl_nlmsg_put_header(mnl_nlmsg_batch_current(batch));
	nlh->nlmsg_type = NFNL_MSG_BATCH_END;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq = cur_seq;

	/* nfgenmsg header */
	nfg = mnl_nlmsg_put_extra_header(nlh, sizeof(*nfg));
	nfg->nfgen_family = family; /* NFPROTO_NETDEV */
	nfg->version = NFNETLINK_V0;
	nfg->res_id = htons(NFNL_SUBSYS_RES_ID);

	mnl_nlmsg_batch_next(batch);
	return 0;
}

/**
 * hostapd_mnl_prepare_nlmsghdr - Prepare netlink message header
 * @batch: Netlink message batch
 * @msg_type: Message type (e.g., NFT_MSG_NEWTABLE)
 * @flags: Additional netlink flags
 * @seq: Pointer to sequence number (will be incremented)
 */
static struct nlmsghdr *hostapd_mnl_prepare_nlmsghdr(struct mnl_nlmsg_batch *batch,
						   uint16_t msg_type,
						   uint16_t flags,
						   uint32_t *seq)
{
	struct nlmsghdr *nlh;
	struct nfgenmsg *nfg;
	uint16_t family = NFPROTO_NETDEV;

	nlh = mnl_nlmsg_put_header(mnl_nlmsg_batch_current(batch));
	nlh->nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | msg_type;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | flags;
	nlh->nlmsg_seq = ++(*seq);

	/* nfgenmsg header */
	nfg = mnl_nlmsg_put_extra_header(nlh, sizeof(*nfg));
	nfg->nfgen_family = family; /* NFPROTO_NETDEV */
	nfg->version = NFNETLINK_V0;
	nfg->res_id = htons(NFNL_SUBSYS_RES_ID);

	return nlh;
}

/**
 * hostapd_set_nft_table - Create or delete an nft table
 * @table_name: Name of the table to create/delete
 * @add: true to create, false to delete
 * Returns: 0 on success, -1 on failure
 */
static int hostapd_set_nft_table(char *table_name, bool add)
{
	char batch_buf[BATCH_BUF_SIZE];
	struct mnl_nlmsg_batch *batch;
	struct nlmsghdr *nlh;
	uint32_t seq = 0;
	uint32_t table_flags = 0;
	uint16_t msg_type;
	uint16_t flags;

	batch = mnl_nlmsg_batch_start(batch_buf, sizeof(batch_buf));
	if (!batch) {
		wpa_printf(MSG_ERROR,
			   "NFT: Failed to initialize netlink batch");
		return -1;
	}

	hostapd_mnl_batch_begin(batch, ++seq);

	/* Set message type and flags based on operation */
	if (add) {
		msg_type = NFT_MSG_NEWTABLE;
		flags = NLM_F_CREATE | NLM_F_EXCL | NLM_F_ECHO;
	} else {
		msg_type = NFT_MSG_DELTABLE;
		flags = NLM_F_EXCL | NLM_F_ECHO;
	}

	nlh = hostapd_mnl_prepare_nlmsghdr(batch, msg_type, flags, &seq);

	mnl_attr_put_strz(nlh, NFTA_TABLE_NAME, table_name);
	mnl_attr_put_u32(nlh, NFTA_TABLE_FLAGS, htonl(table_flags));
	mnl_nlmsg_batch_next(batch);

	hostapd_mnl_batch_end(batch, ++seq);

	return nft_send_and_receive(batch);
}

/**
 * hostapd_set_nft_chain - Create or delete a nft chain
 * @table_name: Name of the table
 * @chain_name: Name of the chain to create/delete
 * @iface_name: Network interface name
 * @add: true to create, false to delete
 * Returns: 0 on success, -1 on failure
 */
static int hostapd_set_nft_chain(char *table_name, char *chain_name,
				 char *iface_name, bool add)
{
	char batch_buf[BATCH_BUF_SIZE];
	struct mnl_nlmsg_batch *batch;
	struct nlmsghdr *nlh;
	struct nlattr *hook_nest;
	uint32_t seq = 0;
	uint16_t msg_type;
	uint16_t flags;

	batch = mnl_nlmsg_batch_start(batch_buf, sizeof(batch_buf));
	if (!batch) {
		wpa_printf(MSG_ERROR,
			   "NFT: Failed to initialize netlink batch");
		return -1;
	}

	hostapd_mnl_batch_begin(batch, ++seq);

	/* Set message type and flags based on operation */
	if (add) {
		msg_type = NFT_MSG_NEWCHAIN;
		flags = NLM_F_CREATE | NLM_F_EXCL | NLM_F_ECHO;
	} else {
		msg_type = NFT_MSG_DELCHAIN;
		flags = NLM_F_EXCL | NLM_F_ECHO;
	}

	nlh = hostapd_mnl_prepare_nlmsghdr(batch, msg_type, flags, &seq);

	mnl_attr_put_strz(nlh, NFTA_CHAIN_TABLE, table_name);
	mnl_attr_put_strz(nlh, NFTA_CHAIN_NAME, chain_name);

	/* Add hook attributes only when creating a chain */
	if (add) {
		hook_nest = mnl_attr_nest_start(nlh, NFTA_CHAIN_HOOK);
		if (!hook_nest) {
			mnl_nlmsg_batch_stop(batch);
			wpa_printf(MSG_ERROR,
				   "NFT: Failed to create chain hook attribute");
			return -1;
		}

		mnl_attr_put_u32(nlh, NFTA_HOOK_HOOKNUM, htonl(NF_NETDEV_EGRESS));
		mnl_attr_put_u32(nlh, NFTA_HOOK_PRIORITY, htonl(0));
		mnl_attr_put_strz(nlh, NFTA_HOOK_DEV, iface_name);
		mnl_attr_nest_end(nlh, hook_nest);

		mnl_attr_put_u32(nlh, NFTA_CHAIN_POLICY, htonl(NF_ACCEPT));
	}

	mnl_nlmsg_batch_next(batch);

	hostapd_mnl_batch_end(batch, ++seq);

	return nft_send_and_receive(batch);
}

/**
 * hostapd_config_nft_table - Create or delete a nft table
 * @table: Table name
 * @add: true to create, false to delete
 * Returns: 0 on success, -1 on failure
 */
int hostapd_config_nft_table(char *table, bool add)
{
	int ret;

	if (!table || !table[0]) {
		wpa_printf(MSG_ERROR, "NFT: Invalid table name");
		return -1;
	}

	wpa_printf(MSG_DEBUG, "NFT: %s table '%s'",
		   add ? "Creating" : "Deleting", table);

	ret = hostapd_set_nft_table(table, add);

	if (ret < 0) {
		wpa_printf(MSG_ERROR, "NFT: Failed to %s table '%s'",
			   add ? "create" : "delete", table);
		return -1;
	}

	wpa_printf(MSG_INFO, "NFT: Table '%s' %s successfully", table,
		   add ? "created" : "deleted");
	return 0;
}

/**
 * hostapd_config_nft_chain - Create or delete a nft chain
 * @hapd: Pointer to hostapd data
 * @table: Table name
 * @chain: Chain name
 * @add: true to create, false to delete
 * Returns: 0 on success, -1 on failure
 */
int hostapd_config_nft_chain(struct hostapd_data *hapd,
			     char *table, char *chain,
			     bool add)
{
	char *iface_name;
	int ret;

	if (!table || !table[0] || !chain || !chain[0]) {
		wpa_printf(MSG_ERROR, "NFT: Invalid table or chain name");
		return -1;
	}

	if (!hapd || !hapd->conf) {
		wpa_printf(MSG_ERROR,
			   "NFT: Invalid hostapd data or configuration");
		return -1;
	}

	iface_name = hapd->conf->iface;
	if (!iface_name || !iface_name[0]) {
		wpa_printf(MSG_ERROR, "NFT: Interface name not available");
		return -1;
	}

	wpa_printf(MSG_DEBUG,
		   "NFT: %s chain '%s' in table '%s' for interface %s",
		   add ? "Creating" : "Deleting", chain, table, iface_name);

	ret = hostapd_set_nft_chain(table, chain, iface_name, add);

	if (ret < 0) {
		wpa_printf(MSG_ERROR,
			   "NFT: Failed to %s chain '%s' in table '%s' for interface %s",
			   add ? "create" : "delete", chain, table,
			   iface_name);
		return -1;
	}

	wpa_printf(MSG_INFO,
		   "NFT: Chain '%s' in table '%s' %s successfully for interface %s",
		   chain, table, add ? "created" : "deleted", iface_name);
	return 0;
}

#else /* !NFT_SUPPORTED */

/* Stub implementation for kernel < 5.16 */

/**
 * nft_init - Initialize NFT netlink socket (stub)
 * Returns: -1 (not supported)
 */
int nft_init(void)
{
	wpa_printf(MSG_INFO,
		   "NFT: Not supported on this kernel version (requires >= 5.16, current: %d.%d)",
		   (LINUX_VERSION_CODE >> 16) & 0xFF,
		   (LINUX_VERSION_CODE >> 8) & 0xFF);
	return 0;
}

/**
 * nft_deinit - Deinitialize NFT netlink socket (stub)
 */
void nft_deinit(void)
{
	wpa_printf(MSG_DEBUG, "NFT: Deinit called (not supported)");
}

int hostapd_config_nft_table(char *table, bool add)
{
	wpa_printf(MSG_DEBUG,
		   "NFT: Table operation '%s' not supported on kernel < 5.16",
		   add ? "create" : "delete");
	return 0;
}

int hostapd_config_nft_chain(struct hostapd_data *hapd,
			     char *table, char *chain,
			     bool add)
{
	wpa_printf(MSG_DEBUG,
		   "NFT: Chain operation '%s' not supported on kernel < 5.16",
		   add ? "create" : "delete");
	return 0;
}

#endif /* NFT_SUPPORTED */
