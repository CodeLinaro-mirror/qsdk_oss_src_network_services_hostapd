/*
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: ISC
 */

#ifndef NFT_H
#define NFT_H

#include <stdbool.h>

struct hostapd_data;

/**
 * nft_init - Initialize NFT netlink socket
 * Returns: 0 on success, -1 on failure
 *
 * This function initializes the global NFT netlink socket that will be
 * used for all nftables operations.
 */
int nft_init(void);

/**
 * nft_deinit - Deinitialize NFT netlink socket
 *
 * This function closes the global NFT netlink socket and frees associated
 * resources.
 */
void nft_deinit(void);

int hostapd_config_nft_table(char *table, bool add);

int hostapd_config_nft_chain(struct hostapd_data *hapd,
			     char *table, char *chain,
			     bool add);

#endif /* NFT_H */
