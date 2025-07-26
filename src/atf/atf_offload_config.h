/*
 * Airtime Fairness offload config parsing and cli apis
 *
 * Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
 * SPDX-License-Identifier: BSD-3-Clause-Clear
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.*
 */

#ifndef ATF_OFFLOAD_CONFIG_H
#define ATF_OFFLOAD_CONFIG_H

struct atf_algo;

int atf_read_config(struct atf_algo *algo, const char *fname);

#endif /* ATF_OFFLOAD_CONFIG_H */
