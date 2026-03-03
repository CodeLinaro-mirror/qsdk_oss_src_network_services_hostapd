#Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
#SPDX-License-Identifier: BSD-3-Clause
#
#Copyright (c) 2013-2018, Jouni Malinen <j@w1.fi>
#
#This software may be distributed under the terms of the BSD license.
#See README for more details.

import logging
logger = logging.getLogger()
import time

import hostapd
from utils import *

from test_ap_acs import force_prev_ap_on_24g
from test_ap_acs import force_prev_ap_on_5g
from test_ap_acs import force_prev_ap_on_6g
from test_ap_acs import wait_acs

def test_ap_qacs(dev, apdev):
    """Automatic channel selection"""
    force_prev_ap_on_24g(apdev[0])
    params = hostapd.wpa2_params(ssid="test-acs", passphrase="12345678")
    params['channel'] = '0'
    params['qacs_enable'] = '1'
    hapd = hostapd.add_ap(apdev[0], params, wait_enabled=False)
    wait_acs(hapd)

    freq = hapd.get_status_field("freq")
    if int(freq) < 2400:
        raise Exception("Unexpected frequency")
    logger.info("Requesting last ACS report for 2G band")
    out = hapd.request("ACS show_report")
    logger.info("ACS_REPORT output:\n" + out)

    dev[0].connect("test-acs", psk="12345678", scan_freq=freq)

def test_ap_qacs_5ghz(dev, apdev):
    """Automatic channel selection on 5 GHz"""
    try:
        hapd = None
#        force_prev_ap_on_5g(apdev[0])
        params = hostapd.wpa2_params(ssid="test-acs", passphrase="12345678")
        params['hw_mode'] = 'a'
        params['channel'] = '0'
        params['qacs_enable'] = '1'
        params['country_code'] = 'US'
        hapd = hostapd.add_ap(apdev[0], params, wait_enabled=False)
        wait_acs(hapd)
        freq = hapd.get_status_field("freq")
        if int(freq) < 5000:
            raise Exception("Unexpected frequency")
        logger.info("Requesting last ACS report for 5G band")
        out = hapd.request("ACS show_report")
        logger.info("ACS_REPORT output:\n" + out)

        dev[0].connect("test-acs", psk="12345678", scan_freq=freq)
        dev[0].wait_regdom(country_ie=True)
    finally:
        clear_regdom(hapd, dev)

def test_ap_qacs_eht20(dev, apdev):
    """Automatic channel selection for EHT320 (offset 0)"""
    run_ap_qacs_eht20(dev, apdev, 0)

def run_ap_qacs_eht20(dev, apdev, bw32_offset):
    check_sae_capab(dev[0])
    try:
        hapd = None
        force_prev_ap_on_6g(apdev[0])
        params = hostapd.he_wpa2_params(ssid="test-acs", passphrase="12345678")
        params['hw_mode'] = 'a'
        params["ieee80211ax"] = "1"
        params["ieee80211be"] = "1"
        params['channel'] = '0'
        params['qacs_enable'] = '1'
        params['op_class'] = '131'
        params['ieee80211w'] = '2'
        params['country_code'] = 'CA'
        params['acs_num_scans'] = '1'
        params['ieee80211w'] = '2'
        params['wpa_key_mgmt'] = 'SAE-EXT-KEY'
        hapd = hostapd.add_ap(apdev[0], params)
        freq = hapd.get_status_field("freq")
        if int(freq) < 5900:
            raise Exception("Unexpected frequency")
        logger.info("Requesting last ACS report for 6G band")
        out = hapd.request("ACS show_report")
        logger.info("ACS_REPORT output:\n" + out)
        dev[0].set("sae_groups", "")
        dev[0].connect("test-acs", psk="12345678", key_mgmt="SAE-EXT-KEY",
                       ieee80211w="2", scan_freq=freq)
        dev[0].wait_regdom(country_ie=True)
    finally:
        clear_regdom(hapd, dev)


def test_ap_qacs_eht320(dev, apdev):
    """Automatic channel selection for EHT320 (offset 0)"""
    run_ap_qacs_eht320(dev, apdev, 0)


def run_ap_qacs_eht320(dev, apdev, bw32_offset):
    check_sae_capab(dev[0])
    try:
        hapd = None
        force_prev_ap_on_6g(apdev[0])
        params = hostapd.he_wpa2_params(ssid="test-acs", passphrase="12345678")
        params['hw_mode'] = 'a'
        params["ieee80211ax"] = "1"
        params["ieee80211be"] = "1"
        params['channel'] = '0'
        params['qacs_enable'] = '1'
        params['op_class'] = '137'
        params['eht_bw320_offset'] = str(bw32_offset)
        params['ieee80211w'] = '2'
        params['country_code'] = 'CA'
        params['acs_num_scans'] = '1'
        params['ieee80211w'] = '2'
        params['wpa_key_mgmt'] = 'SAE-EXT-KEY'
        hapd = hostapd.add_ap(apdev[0], params)
        freq = hapd.get_status_field("freq")
        if int(freq) < 5900:
            raise Exception("Unexpected frequency")
        logger.info("Requesting last ACS report for 6G band")
        out = hapd.request("ACS show_report")
        logger.info("ACS_REPORT output:\n" + out)
        dev[0].set("sae_groups", "")
        dev[0].connect("test-acs", psk="12345678", key_mgmt="SAE-EXT-KEY",
                       ieee80211w="2", scan_freq=freq)
        hapd.wait_sta()
        dev[0].wait_regdom(country_ie=True)
        sig = dev[0].request("SIGNAL_POLL").splitlines()
        logger.info("SIGNAL_POLL: " + str(sig))
        if "WIDTH=320 MHz" not in sig:
            raise Exception("Station did not report 320 MHz bandwidth")
        seg0 = int(hapd.get_status_field("eht_oper_centr_freq_seg0_idx"))
        offset = int(hapd.get_status_field("eht_bw320_offset"))
        chan_1 = [31, 95, 159]
        chan_2 = [63, 127, 191]
        if bw32_offset == 0:
            if offset != 1 and offset != 2:
                raise Exception("Unexpected eht_bw320_offset: %d" % offset)
            if seg0 not in chan_1 and seg0 not in chan_2:
                raise Exception("Unexpected seg0: %d" % seg0)
        if bw32_offset == 1:
            if offset != 1:
                raise Exception("Unexpected eht_bw320_offset: %d" % offset)
            if seg0 not in chan_1:
                raise Exception("Unexpected seg0: %d" % seg0)
        if bw32_offset == 2:
            if offset != 2:
                raise Exception("Unexpected eht_bw320_offset: %d" % offset)
            if seg0 not in chan_2:
                raise Exception("Unexpected seg0: %d" % seg0)

        dev[0].request("DISCONNECT")
        dev[0].wait_disconnected()
        hapd.wait_sta_disconnect()
    finally:
        clear_regdom(hapd, dev)

def test_ap_qacs_40mhz(dev, apdev):
    """Automatic channel selection for 40 MHz channel"""
    run_ap_qacs_40mhz(dev, apdev, '[HT40+]')

def test_ap_qacs_40mhz_he(dev, apdev):
    """Automatic channel selection for 40 MHz channel (HE)"""
    run_ap_qacs_40mhz(dev, apdev, '[HT40+]', he=True, allow20=True)

def test_ap_qacs_40mhz_plus_or_minus(dev, apdev):
    """Automatic channel selection for 40 MHz channel (plus or minus)"""
    run_ap_qacs_40mhz(dev, apdev, '[HT40+][HT40-]')

def run_ap_qacs_40mhz(dev, apdev, ht_capab, he=False, allow20=False):
    clear_scan_cache(apdev[0])
    force_prev_ap_on_24g(apdev[0])
    params = hostapd.wpa2_params(ssid="test-acs", passphrase="12345678")
    params['channel'] = '0'
    params['qacs_enable'] = '1'
    params['ht_capab'] = ht_capab
    if he:
        params['ieee80211ax'] = '1'
        params['he_oper_chwidth'] = '0'
    hapd = hostapd.add_ap(apdev[0], params, wait_enabled=False)
    wait_acs(hapd)

    freq = hapd.get_status_field("freq")
    if int(freq) < 2400:
        raise Exception("Unexpected frequency")

    out = hapd.request("ACS show_report")
    logger.info("ACS_REPORT output:\n" + out)

    sec = hapd.get_status_field("secondary_channel")
    if int(sec) == 0:
        if allow20:
            logger.info("Fallback to 20 MHz detected")
        else:
            raise Exception("Secondary channel not set")

    dev[0].connect("test-acs", psk="12345678", scan_freq=freq)

def test_ap_qacs_40mhz_minus(dev, apdev):
    """Automatic channel selection for HT40- channel"""
    clear_scan_cache(apdev[0])
    force_prev_ap_on_24g(apdev[0])
    params = hostapd.wpa2_params(ssid="test-acs", passphrase="12345678")
    params['channel'] = '0'
    params['qacs_enable'] = '1'
    params['ht_capab'] = '[HT40-]'
    params['acs_num_scans'] = '1'
    hapd = hostapd.add_ap(apdev[0], params, wait_enabled=False)
    wait_acs(hapd)

    freq = hapd.get_status_field("freq")
    if int(freq) < 2400:
        raise Exception("Unexpected frequency")

    out = hapd.request("ACS show_report")
    logger.info("ACS_REPORT output:\n" + out)

    sec = hapd.get_status_field("secondary_channel")
    if int(sec) != -1:
        raise Exception("Unexpected secondary_channel: " + sec)

    dev[0].connect("test-acs", psk="12345678", scan_freq=freq)
    sig = dev[0].request("SIGNAL_POLL").splitlines()
    logger.info("SIGNAL_POLL: " + str(sig))
    if "WIDTH=40 MHz" not in sig:
        raise Exception("Station did not report 40 MHz bandwidth")

