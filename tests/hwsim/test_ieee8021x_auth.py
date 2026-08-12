# Test cases for IEEE 802.1X authentication using Authentication frames
# Copyright (c) Qualcomm Technologies, Inc. and/or its subsidiaries.
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import binascii
import logging
import struct
import time

import hostapd
import hwsim_utils
from utils import *
from wpasupplicant import WpaSupplicant
from hwsim import HWSimRadio
from test_eht import eht_mld_ap_wpa2_params, eht_mld_enable_ap, eht_verify_status
from test_eap_pqc import check_mldsa_support

logger = logging.getLogger()

# ML-DSA certificates require TLS v1.3, which is not enabled by default. The
# shared RADIUS server does not have ML-DSA credentials, so use the integrated
# EAP server for these tests.
MLDSA_AP_PARAMS = {"eap_server": "1",
                   "eap_user_file": "auth_serv/eap_user.conf",
                   "ca_cert": "auth_serv/mldsa-ca.pem",
                   "server_cert": "auth_serv/mldsa-server.pem",
                   "private_key": "auth_serv/mldsa-server.key",
                   "tls_flags": "[ENABLE-TLSv1.3]"}

MLDSA_STA_CERTS = {"ca_cert": "auth_serv/mldsa-ca.pem",
                   "client_cert": "auth_serv/mldsa-user.pem",
                   "private_key": "auth_serv/mldsa-user.key",
                   "phase1": "tls_disable_tlsv1_3=0"}

def check_hlr_auc_gw_support():
    if not os.path.exists("/tmp/hlr_auc_gw.sock"):
        raise HwsimSkip("No hlr_auc_gw available")

def check_eap_capa(dev, method):
    res = dev.get_capability("eap")
    if method not in res:
        raise HwsimSkip("EAP method %s not supported in the build" % method)

def test_ieee8021x_auth_alg_eap_tls(dev, apdev):
    """IEEE 802.1X authentication using Authentication frames with EAP-TLS"""
    ssid = "test-ieee8021x-auth-tls"

    params = hostapd.wpa2_eap_params(ssid=ssid)

    params["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"

    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="TLS",
                   identity="tls user",
                   ca_cert="auth_serv/ca.pem",
                   client_cert="auth_serv/user.pem",
                   private_key="auth_serv/user.key",
                   scan_freq="2412",
                   eap_over_auth_frame="1")

    hapd.wait_sta()
    sta = hapd.get_sta(dev[0].own_addr())

    if sta["AKMSuiteSelector"] != '00-0f-ac-5':
        raise Exception("Incorrect AKMSuiteSelector value: " + sta["AKMSuiteSelector"])

    auth_alg = sta.get("auth_alg")
    logger.info("Auth Algorithm: " + str(auth_alg))
    if str(auth_alg) != "8":
        raise Exception("Expected IEEE 802.1X auth (8), got: " + str(auth_alg))
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_auth_alg_eap_ttls_mschapv2(dev, apdev):
    """IEEE 802.1X authentication using Authentication frames with EAP-TTLS/MSCHAPv2"""
    ssid = "test-ieee8021x-auth-ttls"

    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"

    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="TTLS",
                   identity="user",
                   anonymous_identity="ttls",
                   password="password",
                   phase2="autheap=MSCHAPV2",
                   ca_cert="auth_serv/ca.pem",
                   scan_freq="2412",
                   eap_over_auth_frame="1")

    hapd.wait_sta()
    sta = hapd.get_sta(dev[0].own_addr())

    if sta["AKMSuiteSelector"] != '00-0f-ac-5':
        raise Exception("Incorrect AKMSuiteSelector value: " + sta["AKMSuiteSelector"])

    auth_alg = sta.get("auth_alg")
    logger.info("Auth Algorithm: " + str(auth_alg))
    if str(auth_alg) != "8":
        raise Exception("Expected IEEE 802.1X auth (8), got: " + str(auth_alg))
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_auth_alg_eap_peap_mschapv2(dev, apdev):
    """IEEE 802.1X authentication using Authentication frames with EAP-PEAP/MSCHAPv2"""
    ssid = "test-ieee8021x-auth-peap"

    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"

    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="PEAP",
                   identity="user",
                   anonymous_identity="peap",
                   password="password",
                   phase2="auth=MSCHAPV2",
                   ca_cert="auth_serv/ca.pem",
                   scan_freq="2412",
                   eap_over_auth_frame="1")

    hapd.wait_sta()
    sta = hapd.get_sta(dev[0].own_addr())

    if sta["AKMSuiteSelector"] != '00-0f-ac-5':
        raise Exception("Incorrect AKMSuiteSelector value: " + sta["AKMSuiteSelector"])

    auth_alg = sta.get("auth_alg")
    logger.info("Auth Algorithm: " + str(auth_alg))
    if str(auth_alg) != "8":
        raise Exception("Expected IEEE 802.1X auth (8), got: " + str(auth_alg))
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_auth_alg_multiple_clients(dev, apdev):
    """IEEE 802.1X authentication with multiple clients"""
    ssid = "test-ieee8021x-auth-multi"

    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"

    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="TLS",
                   identity="tls user",
                   ca_cert="auth_serv/ca.pem",
                   client_cert="auth_serv/user.pem",
                   private_key="auth_serv/user.key",
                   scan_freq="2412",
                   eap_over_auth_frame="1")

    hapd.wait_sta()

    dev[1].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="TTLS",
                   identity="user",
                   anonymous_identity="ttls",
                   password="password",
                   phase2="autheap=MSCHAPV2",
                   ca_cert="auth_serv/ca.pem",
                   scan_freq="2412",
                   eap_over_auth_frame="1")

    hapd.wait_sta()

    sta0 = hapd.get_sta(dev[0].own_addr())
    sta1 = hapd.get_sta(dev[1].own_addr())

    if sta0["AKMSuiteSelector"] != '00-0f-ac-5':
        raise Exception("Incorrect AKMSuiteSelector for client 0")

    if sta1["AKMSuiteSelector"] != '00-0f-ac-5':
        raise Exception("Incorrect AKMSuiteSelector for client 1")

    auth_alg0 = sta0.get("auth_alg")
    logger.info("Auth Algorithm client 0: " + str(auth_alg0))
    if str(auth_alg0) != "8":
        raise Exception("Expected IEEE 802.1X auth (8) for client 0, got: " + str(auth_alg0))

    auth_alg1 = sta1.get("auth_alg")
    logger.info("Auth Algorithm client 1: " + str(auth_alg1))
    if str(auth_alg1) != "8":
        raise Exception("Expected IEEE 802.1X auth (8) for client 1, got: " + str(auth_alg1))
    hwsim_utils.test_connectivity(dev[0], hapd)
    hwsim_utils.test_connectivity(dev[1], hapd)

def test_ieee8021x_auth_alg_eap_tls_wpa_eap(dev, apdev):
    """IEEE 802.1X authentication with WPA-EAP (non-SHA256) AKM"""
    ssid = "test-ieee8021x-auth-wpa-eap"

    # Setup AP with WPA2-EAP (standard AKM, not SHA256)
    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"

    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP",
                   eap="TLS",
                   identity="tls user",
                   ca_cert="auth_serv/ca.pem",
                   client_cert="auth_serv/user.pem",
                   private_key="auth_serv/user.key",
                   scan_freq="2412",
                   eap_over_auth_frame="1")

    hapd.wait_sta()
    sta = hapd.get_sta(dev[0].own_addr())

    if sta["AKMSuiteSelector"] != '00-0f-ac-1':
        raise Exception("Incorrect AKMSuiteSelector value: " + sta["AKMSuiteSelector"])

    auth_alg = sta.get("auth_alg")
    logger.info("Auth Algorithm: " + str(auth_alg))
    if str(auth_alg) != "0":
        raise Exception("Expected OPEN_SYSTEM auth (0) for WPA-EAP, got: " + str(auth_alg))
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_auth_alg_eap_tls_wpa_eap_sha384(dev, apdev):
    """IEEE 802.1X authentication with WPA-EAP-SHA384 AKM"""
    ssid = "test-ieee8021x-auth-sha384"

    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP-SHA384"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"
    params["ieee80211w"] = "2"  # Required for SHA384

    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA384",
                   eap="TLS",
                   identity="tls user",
                   ca_cert="auth_serv/ca.pem",
                   client_cert="auth_serv/user.pem",
                   private_key="auth_serv/user.key",
                   ieee80211w="2",
                   scan_freq="2412",
                   eap_over_auth_frame="1")

    hapd.wait_sta()
    sta = hapd.get_sta(dev[0].own_addr())

    if sta["AKMSuiteSelector"] != '00-0f-ac-23':
        raise Exception("Incorrect AKMSuiteSelector value: " + sta["AKMSuiteSelector"])

    auth_alg = sta.get("auth_alg")
    logger.info("Auth Algorithm: " + str(auth_alg))
    if str(auth_alg) != "8":
        raise Exception("Expected IEEE 802.1X auth (8), got: " + str(auth_alg))
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_auth_alg_eap_tls_mixed_akm(dev, apdev):
    """IEEE 802.1X authentication with mixed AKM support"""
    ssid = "test-ieee8021x-auth-mixed"

    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP WPA-EAP-SHA256"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"

    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="TLS",
                   identity="tls user",
                   ca_cert="auth_serv/ca.pem",
                   client_cert="auth_serv/user.pem",
                   private_key="auth_serv/user.key",
                   scan_freq="2412",
                   eap_over_auth_frame="1")

    hapd.wait_sta()
    sta0 = hapd.get_sta(dev[0].own_addr())

    if sta0["AKMSuiteSelector"] != '00-0f-ac-5':
        raise Exception("Incorrect AKMSuiteSelector for SHA256 client")

    auth_alg0 = sta0.get("auth_alg")
    logger.info("Auth Algorithm: " + str(auth_alg0))
    if str(auth_alg0) != "8":
        raise Exception("Expected IEEE 802.1X auth (8), got: " + str(auth_alg0))
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_auth_alg_suite_b_192(dev, apdev):
    """IEEE 802.1X authentication using Authentication frames with Suite B 192-bit"""
    if "WPA-EAP-SUITE-B-192" not in dev[0].get_capability("key_mgmt"):
        raise HwsimSkip("WPA-EAP-SUITE-B-192 not supported")

    ssid = "test-ieee8021x-auth-suite-b-192"

    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP-SUITE-B-192"
    params["wpa_pairwise"] = "GCMP-256"
    params["rsn_pairwise"] = "GCMP-256"
    params["ieee80211w"] = "2"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"

    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SUITE-B-192",
                   ieee80211w="2",
                   group="GCMP-256",
                   pairwise="GCMP-256",
                   eap="TLS",
                   identity="tls user",
                   ca_cert="auth_serv/ca.pem",
                   client_cert="auth_serv/user.pem",
                   private_key="auth_serv/user.key",
                   scan_freq="2412",
                   eap_over_auth_frame="1")

    hapd.wait_sta()
    sta = hapd.get_sta(dev[0].own_addr())

    if sta["AKMSuiteSelector"] != '00-0f-ac-12':
        raise Exception("Incorrect AKMSuiteSelector value: " + sta["AKMSuiteSelector"])

    auth_alg = sta.get("auth_alg")
    logger.info("Auth Algorithm: " + str(auth_alg))
    if str(auth_alg) != "8":
        raise Exception("Expected IEEE 802.1X auth (8), got: " + str(auth_alg))
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_auth_alg_eap_sim(dev, apdev):
    """IEEE 802.1X authentication using Authentication frames with EAP-SIM"""
    check_hlr_auc_gw_support()
    ssid = "test-ieee8021x-auth-sim"
    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"
    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="SIM",
                   identity="1232010000000000",
                   password="90dca4eda45b53cf0f12d7c9c3bc6a89:cb9cccc4b9258e6dca4760379fb82581",
                   scan_freq="2412",
                   eap_over_auth_frame="1")
    hapd.wait_sta()
    sta = hapd.get_sta(dev[0].own_addr())
    if sta["AKMSuiteSelector"] != '00-0f-ac-5':
        raise Exception("Incorrect AKMSuiteSelector value: " + sta["AKMSuiteSelector"])

    auth_alg = sta.get("auth_alg")
    logger.info("Auth Algorithm: " + str(auth_alg))
    if str(auth_alg) != "8":
        raise Exception("Expected IEEE 802.1X auth (8), got: " + str(auth_alg))
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_auth_alg_eap_aka(dev, apdev):
    """IEEE 802.1X authentication using Authentication frames with EAP-AKA"""
    check_hlr_auc_gw_support()
    ssid = "test-ieee8021x-auth-aka"
    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"
    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="AKA",
                   identity="0232010000000000",
                   password="90dca4eda45b53cf0f12d7c9c3bc6a89:cb9cccc4b9258e6dca4760379fb82581:000000000123",
                   scan_freq="2412",
                   eap_over_auth_frame="1")
    hapd.wait_sta()
    sta = hapd.get_sta(dev[0].own_addr())
    if sta["AKMSuiteSelector"] != '00-0f-ac-5':
        raise Exception("Incorrect AKMSuiteSelector value: " + sta["AKMSuiteSelector"])

    auth_alg = sta.get("auth_alg")
    logger.info("Auth Algorithm: " + str(auth_alg))
    if str(auth_alg) != "8":
        raise Exception("Expected IEEE 802.1X auth (8), got: " + str(auth_alg))
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_auth_alg_eap_aka_prime(dev, apdev):
    """IEEE 802.1X authentication using Authentication frames with EAP-AKA'"""
    check_hlr_auc_gw_support()
    ssid = "test-ieee8021x-auth-aka-prime"
    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"
    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="AKA'",
                   identity="6555444333222111",
                   password="5122250214c33e723a5dd523fc145fc0:981d464c7c52eb6e5036234984ad0bcf:000000000123",
                   scan_freq="2412",
                   eap_over_auth_frame="1")
    hapd.wait_sta()
    sta = hapd.get_sta(dev[0].own_addr())
    if sta["AKMSuiteSelector"] != '00-0f-ac-5':
        raise Exception("Incorrect AKMSuiteSelector value: " + sta["AKMSuiteSelector"])

    auth_alg = sta.get("auth_alg")
    logger.info("Auth Algorithm: " + str(auth_alg))
    if str(auth_alg) != "8":
        raise Exception("Expected IEEE 802.1X auth (8), got: " + str(auth_alg))
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_auth_alg_eap_pwd(dev, apdev):
    """IEEE 802.1X authentication using Authentication frames with EAP-pwd"""
    check_eap_capa(dev[0], "PWD")
    ssid = "test-ieee8021x-auth-pwd"
    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"
    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="PWD",
                   identity="pwd user",
                   password="secret password",
                   scan_freq="2412",
                   eap_over_auth_frame="1")
    hapd.wait_sta()
    sta = hapd.get_sta(dev[0].own_addr())
    if sta["AKMSuiteSelector"] != '00-0f-ac-5':
        raise Exception("Incorrect AKMSuiteSelector value: " + sta["AKMSuiteSelector"])

    auth_alg = sta.get("auth_alg")
    logger.info("Auth Algorithm: " + str(auth_alg))
    if str(auth_alg) != "8":
        raise Exception("Expected IEEE 802.1X auth (8), got: " + str(auth_alg))
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_auth_alg_eap_pax(dev, apdev):
    """IEEE 802.1X authentication using Authentication frames with EAP-PAX"""
    ssid = "test-ieee8021x-auth-pax"
    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"
    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="PAX",
                   identity="pax.user@example.com",
                   password_hex="0123456789abcdef0123456789abcdef",
                   scan_freq="2412",
                   eap_over_auth_frame="1")
    hapd.wait_sta()
    sta = hapd.get_sta(dev[0].own_addr())
    if sta["AKMSuiteSelector"] != '00-0f-ac-5':
        raise Exception("Incorrect AKMSuiteSelector value: " + sta["AKMSuiteSelector"])

    auth_alg = sta.get("auth_alg")
    logger.info("Auth Algorithm: " + str(auth_alg))
    if str(auth_alg) != "8":
        raise Exception("Expected IEEE 802.1X auth (8), got: " + str(auth_alg))
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_auth_alg_eap_psk(dev, apdev):
    """IEEE 802.1X authentication using Authentication frames with EAP-PSK"""
    ssid = "test-ieee8021x-auth-psk"
    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"
    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="PSK",
                   identity="psk.user@example.com",
                   password_hex="0123456789abcdef0123456789abcdef",
                   scan_freq="2412",
                   eap_over_auth_frame="1")
    hapd.wait_sta()
    sta = hapd.get_sta(dev[0].own_addr())
    if sta["AKMSuiteSelector"] != '00-0f-ac-5':
        raise Exception("Incorrect AKMSuiteSelector value: " + sta["AKMSuiteSelector"])

    auth_alg = sta.get("auth_alg")
    logger.info("Auth Algorithm: " + str(auth_alg))
    if str(auth_alg) != "8":
        raise Exception("Expected IEEE 802.1X auth (8), got: " + str(auth_alg))
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_auth_alg_eap_sake(dev, apdev):
    """IEEE 802.1X authentication using Authentication frames with EAP-SAKE"""
    ssid = "test-ieee8021x-auth-sake"
    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"
    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="SAKE",
                   identity="sake user",
                   password_hex="0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                   scan_freq="2412",
                   eap_over_auth_frame="1")
    hapd.wait_sta()
    sta = hapd.get_sta(dev[0].own_addr())
    if sta["AKMSuiteSelector"] != '00-0f-ac-5':
        raise Exception("Incorrect AKMSuiteSelector value: " + sta["AKMSuiteSelector"])

    auth_alg = sta.get("auth_alg")
    logger.info("Auth Algorithm: " + str(auth_alg))
    if str(auth_alg) != "8":
        raise Exception("Expected IEEE 802.1X auth (8), got: " + str(auth_alg))
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_auth_alg_eap_gpsk(dev, apdev):
    """IEEE 802.1X authentication using Authentication frames with EAP-GPSK"""
    ssid = "test-ieee8021x-auth-gpsk"
    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"
    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="GPSK",
                   identity="gpsk user",
                   password="abcdefghijklmnop0123456789abcdef",
                   scan_freq="2412",
                   eap_over_auth_frame="1")
    hapd.wait_sta()
    sta = hapd.get_sta(dev[0].own_addr())
    if sta["AKMSuiteSelector"] != '00-0f-ac-5':
        raise Exception("Incorrect AKMSuiteSelector value: " + sta["AKMSuiteSelector"])

    auth_alg = sta.get("auth_alg")
    logger.info("Auth Algorithm: " + str(auth_alg))
    if str(auth_alg) != "8":
        raise Exception("Expected IEEE 802.1X auth (8), got: " + str(auth_alg))
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_auth_alg_eap_eke(dev, apdev):
    """IEEE 802.1X authentication using Authentication frames with EAP-EKE"""
    ssid = "test-ieee8021x-auth-eke"
    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"
    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="EKE",
                   identity="eke user",
                   password="hello",
                   scan_freq="2412",
                   eap_over_auth_frame="1")
    hapd.wait_sta()
    sta = hapd.get_sta(dev[0].own_addr())
    if sta["AKMSuiteSelector"] != '00-0f-ac-5':
        raise Exception("Incorrect AKMSuiteSelector value: " + sta["AKMSuiteSelector"])

    auth_alg = sta.get("auth_alg")
    logger.info("Auth Algorithm: " + str(auth_alg))
    if str(auth_alg) != "8":
        raise Exception("Expected IEEE 802.1X auth (8), got: " + str(auth_alg))
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_auth_alg_eap_ikev2(dev, apdev):
    """IEEE 802.1X authentication using Authentication frames with EAP-IKEv2"""
    check_eap_capa(dev[0], "IKEV2")
    ssid = "test-ieee8021x-auth-ikev2"
    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"
    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="IKEV2",
                   identity="ikev2 user",
                   password="ike password",
                   scan_freq="2412",
                   eap_over_auth_frame="1")
    hapd.wait_sta()
    sta = hapd.get_sta(dev[0].own_addr())
    if sta["AKMSuiteSelector"] != '00-0f-ac-5':
        raise Exception("Incorrect AKMSuiteSelector value: " + sta["AKMSuiteSelector"])

    auth_alg = sta.get("auth_alg")
    logger.info("Auth Algorithm: " + str(auth_alg))
    if str(auth_alg) != "8":
        raise Exception("Expected IEEE 802.1X auth (8), got: " + str(auth_alg))
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_auth_alg_eap_fast(dev, apdev):
    """IEEE 802.1X authentication using Authentication frames with EAP-FAST"""
    check_eap_capa(dev[0], "FAST")
    ssid = "test-ieee8021x-auth-fast"
    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"
    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="FAST",
                   identity="user",
                   anonymous_identity="FAST",
                   password="password",
                   ca_cert="auth_serv/ca.pem",
                   phase2="auth=MSCHAPV2",
                   phase1="fast_provisioning=1",
                   pac_file="blob://fast_pac",
                   scan_freq="2412",
                   eap_over_auth_frame="1")
    hapd.wait_sta()
    sta = hapd.get_sta(dev[0].own_addr())
    if sta["AKMSuiteSelector"] != '00-0f-ac-5':
        raise Exception("Incorrect AKMSuiteSelector value: " + sta["AKMSuiteSelector"])

    auth_alg = sta.get("auth_alg")
    logger.info("Auth Algorithm: " + str(auth_alg))
    if str(auth_alg) != "8":
        raise Exception("Expected IEEE 802.1X auth (8), got: " + str(auth_alg))
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_auth_mlo_single_link(dev, apdev):
    """IEEE 802.1X Authentication frames: MLO single-link EAP-TLS"""
    ssid = "test-ieee8021x-auth-mlo-1l"
    with HWSimRadio(use_mlo=True) as (hapd_radio, hapd_iface), \
         HWSimRadio(use_mlo=True) as (wpas_radio, wpas_iface):

        # AP MLD: single link (link-0)
        params = eht_mld_ap_wpa2_params(ssid, key_mgmt="WPA-EAP-SHA256")
        params.update(hostapd.radius_params())
        params["ieee8021x"] = "1"
        params["eap_using_authentication_frames"] = "1"
        params["assoc_frame_encryption"] = "1"

        hapd0 = eht_mld_enable_ap(hapd_iface, 0, params)

        # Non-AP MLD supplicant
        wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas.interface_add(wpas_iface)

        # Connect with EAP-TLS over IEEE 802.1X Authentication Frames
        wpas.connect(ssid,
                     key_mgmt="WPA-EAP-SHA256",
                     ieee80211w="2",  # PMF required for MLO
                     eap="TLS",
                     identity="tls user",
                     ca_cert="auth_serv/ca.pem",
                     client_cert="auth_serv/user.pem",
                     private_key="auth_serv/user.key",
                     scan_freq="2412",
		     eap_over_auth_frame="1")

        hapd0.wait_sta()

        sta = hapd0.get_sta(wpas.own_addr())
        if sta["AKMSuiteSelector"] != '00-0f-ac-5':
            raise Exception("Incorrect AKMSuiteSelector (single-link)")

        auth_alg = sta.get("auth_alg")
        logger.info("Auth Algorithm: " + str(auth_alg))
        if str(auth_alg) != "8":
            raise Exception("Expected IEEE 802.1X auth (8), got: " + str(auth_alg))

        # Verify MLD state: single link active
        eht_verify_status(wpas, hapd0, 2412, 20, is_ht=True, mld=True,
                          valid_links=1, active_links=1)
        hwsim_utils.test_connectivity(wpas, hapd0)

def test_ieee8021x_auth_mlo_two_links(dev, apdev):
    """IEEE 802.1X Authentication frames: MLO two-link EAP-TLS"""
    ssid = "test-ieee8021x-auth-mlo-2l"
    with HWSimRadio(use_mlo=True) as (hapd_radio, hapd_iface), \
         HWSimRadio(use_mlo=True) as (wpas_radio, wpas_iface):

        # AP MLD: two links (link-0 @ ch1, link-1 @ ch6)
        params = eht_mld_ap_wpa2_params(ssid, key_mgmt="WPA-EAP-SHA256")
        params.update(hostapd.radius_params())
        params["ieee8021x"] = "1"
        params["eap_using_authentication_frames"] = "1"
        params["assoc_frame_encryption"] = "1"

        hapd0 = eht_mld_enable_ap(hapd_iface, 0, params)
        params['channel'] = '6'
        hapd1 = eht_mld_enable_ap(hapd_iface, 1, params)

        # Non-AP MLD supplicant
        wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas.interface_add(wpas_iface)

        wpas.connect(ssid,
                     key_mgmt="WPA-EAP-SHA256",
                     ieee80211w="2",  # PMF required for MLO
                     eap="TLS",
                     identity="tls user",
                     ca_cert="auth_serv/ca.pem",
                     client_cert="auth_serv/user.pem",
                     private_key="auth_serv/user.key",
                     scan_freq="2412 2437",
		     eap_over_auth_frame="1")

        for hapd in (hapd0, hapd1):
            try:
                hapd.wait_sta()
            except Exception:
                pass

        sta = hapd0.get_sta(wpas.own_addr())
        if sta["AKMSuiteSelector"] != '00-0f-ac-5':
            raise Exception("Incorrect AKMSuiteSelector (two-links)")

        auth_alg = sta.get("auth_alg")
        logger.info("Auth Algorithm: " + str(auth_alg))
        if str(auth_alg) != "8":
            raise Exception("Expected IEEE 802.1X auth (8), got: " + str(auth_alg))

        # Verify MLD state: two links => bitmap 0b11 == 3
        eht_verify_status(wpas, hapd0, 2412, 20, is_ht=True, mld=True,
                          valid_links=3, active_links=3)
        hwsim_utils.test_connectivity(wpas, hapd0)

def test_ieee8021x_auth_mlo_three_links(dev, apdev):
    """IEEE 802.1X Authentication frames: MLO three-link EAP-TLS"""
    ssid = "test-ieee8021x-auth-mlo-3l"
    with HWSimRadio(use_mlo=True) as (hapd_radio, hapd_iface), \
         HWSimRadio(use_mlo=True) as (wpas_radio, wpas_iface):

        params = eht_mld_ap_wpa2_params(ssid, key_mgmt="WPA-EAP-SHA256")
        params.update(hostapd.radius_params())
        params["ieee8021x"] = "1"
        params["eap_using_authentication_frames"] = "1"
        params["assoc_frame_encryption"] = "1"

        hapd0 = eht_mld_enable_ap(hapd_iface, 0, params)
        params['channel'] = '6'
        hapd1 = eht_mld_enable_ap(hapd_iface, 1, params)
        params['channel'] = '11'
        hapd2 = eht_mld_enable_ap(hapd_iface, 2, params)

        wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas.interface_add(wpas_iface)

        wpas.connect(ssid,
                     key_mgmt="WPA-EAP-SHA256",
                     ieee80211w="2",  # PMF required for MLO
                     eap="TLS",
                     identity="tls user",
                     ca_cert="auth_serv/ca.pem",
                     client_cert="auth_serv/user.pem",
                     private_key="auth_serv/user.key",
                     scan_freq="2412 2437 2462",
		     eap_over_auth_frame="1")

        for hapd in (hapd0, hapd1, hapd2):
            try:
                hapd.wait_sta()
            except Exception:
                pass

        sta = hapd0.get_sta(wpas.own_addr())
        if sta["AKMSuiteSelector"] != '00-0f-ac-5':
            raise Exception("Incorrect AKMSuiteSelector (three-links)")

        auth_alg = sta.get("auth_alg")
        logger.info("Auth Algorithm: " + str(auth_alg))
        if str(auth_alg) != "8":
            raise Exception("Expected IEEE 802.1X auth (8), got: " + str(auth_alg))

        eht_verify_status(wpas, hapd0, 2412, 20, is_ht=True, mld=True,
                          valid_links=7, active_links=7)
        hwsim_utils.test_connectivity(wpas, hapd0)

def test_ieee8021x_auth_mlo_connect_disconnect_reconnect(dev, apdev):
    """IEEE 802.1X Authentication frames: MLO two-link connect/disconnect/reconnect"""
    ssid = "test-ieee8021x-auth-mlo-cdr"
    with HWSimRadio(use_mlo=True) as (hapd_radio, hapd_iface), \
         HWSimRadio(use_mlo=True) as (wpas_radio, wpas_iface):

        params = eht_mld_ap_wpa2_params(ssid, key_mgmt="WPA-EAP-SHA256")
        params.update(hostapd.radius_params())
        params["ieee8021x"] = "1"
        params["eap_using_authentication_frames"] = "1"
        params["assoc_frame_encryption"] = "1"

        hapd0 = eht_mld_enable_ap(hapd_iface, 0, params)
        params['channel'] = '6'
        hapd1 = eht_mld_enable_ap(hapd_iface, 1, params)

        wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas.interface_add(wpas_iface)

        wpas.connect(ssid,
                     key_mgmt="WPA-EAP-SHA256",
                     ieee80211w="2",  # PMF required for MLO
                     eap="TLS",
                     identity="tls user",
                     ca_cert="auth_serv/ca.pem",
                     client_cert="auth_serv/user.pem",
                     private_key="auth_serv/user.key",
                     scan_freq="2412 2437",
		     eap_over_auth_frame="1")

        for hapd in (hapd0, hapd1):
            try:
                hapd.wait_sta()
            except Exception:
                pass

        eht_verify_status(wpas, hapd0, 2412, 20, is_ht=True, mld=True,
                          valid_links=3, active_links=3)

        sta = hapd0.get_sta(wpas.own_addr())
        auth_alg = sta.get("auth_alg")
        logger.info("Auth Algorithm: " + str(auth_alg))
        if str(auth_alg) != "8":
            raise Exception("Expected IEEE 802.1X auth (8), got: " + str(auth_alg))
        hwsim_utils.test_connectivity(wpas, hapd0)

        for _ in range(2):
            wpas.request("DISCONNECT")
            wpas.wait_disconnected(timeout=5)
            wpas.request("RECONNECT")
            wpas.wait_connected(timeout=15)

            for hapd in (hapd0, hapd1):
                try:
                    hapd.wait_sta()
                except Exception:
                    pass
            hwsim_utils.test_connectivity(wpas, hapd0)

def test_ieee8021x_auth_mlo_pqc(dev, apdev):
    """IEEE 802.1X Authentication frames: MLO with a PQC AKM"""
    key_mgmt = dev[0].get_capability("key_mgmt")
    if "EAP-PQC" not in key_mgmt:
        raise HwsimSkip(f"EAP-PQC not supported: {key_mgmt}")

    ssid = "test-ieee8021x-auth-mlo-pqc"
    with HWSimRadio(use_mlo=True) as (hapd_radio, hapd_iface), \
         HWSimRadio(use_mlo=True) as (wpas_radio, wpas_iface):

        params = eht_mld_ap_wpa2_params(ssid, key_mgmt="")
        params.update(hostapd.radius_params())
        params["ieee8021x"] = "1"
        params["rsn_pairwise"] = "GCMP-256"
        params["group_cipher"] = "GCMP-256"
        # Only BIP-GMAC-256 is accepted once a security profile is selected.
        params["group_mgmt_cipher"] = "BIP-GMAC-256"
        params["security_profiles"] = "18"
        params["eap_using_authentication_frames"] = "1"
        params["assoc_frame_encryption"] = "1"
        params["pmksa_caching_privacy"] = "1"

        hapd0 = eht_mld_enable_ap(hapd_iface, 0, params)

        wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas.interface_add(wpas_iface)
        wpas.set("security_profiles", "1")

        wpas.connect(ssid,
                     key_mgmt="WPA-EAP",
                     ieee80211w="2",
                     pairwise="GCMP-256",
                     group="GCMP-256",
                     eap="TLS",
                     identity="tls user",
                     ca_cert="auth_serv/ca.pem",
                     client_cert="auth_serv/user.pem",
                     private_key="auth_serv/user.key",
                     scan_freq="2412",
                     pmksa_privacy="1",
                     eap_over_auth_frame="1",
                     security_profiles="18")

        hapd0.wait_sta()

        sta = hapd0.get_sta(wpas.own_addr())
        if sta["AKMSuiteSelector"] != '00-0f-ac-31':
            raise Exception("Incorrect AKMSuiteSelector: " +
                            sta["AKMSuiteSelector"])

        val = wpas.get_status_field("security_profile")
        if val != "18":
            raise Exception("Unexpected security_profile: " + str(val))

        eht_verify_status(wpas, hapd0, 2412, 20, is_ht=True, mld=True,
                          valid_links=1, active_links=1)

        # The PTK is derived over the Authentication frame transcript, so a
        # transcript mismatch only shows up as a data path failure here.
        hwsim_utils.test_connectivity(wpas, hapd0)

        # Exercise the EAPOL-Key integrity and key wrap algorithms, which for
        # the PQC AKMs are AKM defined rather than derived from the cipher.
        if "OK" not in hapd0.request("REKEY_GTK"):
            raise Exception("REKEY_GTK failed")
        ev = wpas.wait_event(["RSN: Group rekeying completed"], timeout=5)
        if ev is None:
            raise Exception("GTK rekey timed out")

        hwsim_utils.test_connectivity(wpas, hapd0)

def test_ieee8021x_auth_mlo_pqc_two_links(dev, apdev):
    """IEEE 802.1X Authentication frames: MLO two links with a PQC AKM"""
    key_mgmt = dev[0].get_capability("key_mgmt")
    if "EAP-PQC" not in key_mgmt:
        raise HwsimSkip(f"EAP-PQC not supported: {key_mgmt}")

    ssid = "test-ieee8021x-auth-mlo-pqc-2l"
    with HWSimRadio(use_mlo=True) as (hapd_radio, hapd_iface), \
         HWSimRadio(use_mlo=True) as (wpas_radio, wpas_iface):

        params = eht_mld_ap_wpa2_params(ssid, key_mgmt="")
        params.update(hostapd.radius_params())
        params["ieee8021x"] = "1"
        params["rsn_pairwise"] = "GCMP-256"
        params["group_cipher"] = "GCMP-256"
        # Only BIP-GMAC-256 is accepted once a security profile is selected.
        params["group_mgmt_cipher"] = "BIP-GMAC-256"
        params["security_profiles"] = "18"
        params["eap_using_authentication_frames"] = "1"
        params["assoc_frame_encryption"] = "1"
        params["pmksa_caching_privacy"] = "1"

        hapd0 = eht_mld_enable_ap(hapd_iface, 0, params)
        params['channel'] = '6'
        hapd1 = eht_mld_enable_ap(hapd_iface, 1, params)

        wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas.interface_add(wpas_iface)
        wpas.set("security_profiles", "1")

        wpas.connect(ssid,
                     key_mgmt="WPA-EAP",
                     ieee80211w="2",
                     pairwise="GCMP-256",
                     group="GCMP-256",
                     eap="TLS",
                     identity="tls user",
                     ca_cert="auth_serv/ca.pem",
                     client_cert="auth_serv/user.pem",
                     private_key="auth_serv/user.key",
                     scan_freq="2412 2437",
                     pmksa_privacy="1",
                     eap_over_auth_frame="1",
                     security_profiles="18")

        for hapd in (hapd0, hapd1):
            try:
                hapd.wait_sta()
            except Exception:
                pass

        sta = hapd0.get_sta(wpas.own_addr())
        if sta["AKMSuiteSelector"] != '00-0f-ac-31':
            raise Exception("Incorrect AKMSuiteSelector: " +
                            sta["AKMSuiteSelector"])

        val = wpas.get_status_field("security_profile")
        if val != "18":
            raise Exception("Unexpected security_profile: " + str(val))

        eht_verify_status(wpas, hapd0, 2412, 20, is_ht=True, mld=True,
                          valid_links=3, active_links=3)

        # The per-link GTKs are delivered in the encrypted (Re)Association
        # Response, so a wrong MLO GTK offset shows up only as a broadcast
        # failure on the affected link.
        for hapd in (hapd0, hapd1):
            hwsim_utils.test_connectivity(wpas, hapd)

        # Exercise the EAPOL-Key integrity and key wrap algorithms, which for
        # the PQC AKMs are AKM defined rather than derived from the cipher.
        if "OK" not in hapd0.request("REKEY_GTK"):
            raise Exception("REKEY_GTK failed")
        ev = wpas.wait_event(["RSN: Group rekeying completed"], timeout=5)
        if ev is None:
            raise Exception("GTK rekey timed out")

        for hapd in (hapd0, hapd1):
            hwsim_utils.test_connectivity(wpas, hapd)

def test_ieee8021x_auth_mlo_pqc_pmksa_caching(dev, apdev):
    """IEEE 802.1X Authentication frames: PQC AKM with PMKSA caching reuse"""
    key_mgmt = dev[0].get_capability("key_mgmt")
    if "EAP-PQC" not in key_mgmt:
        raise HwsimSkip(f"EAP-PQC not supported: {key_mgmt}")

    ssid = "test-ieee8021x-auth-pqc-pmksa"
    with HWSimRadio(use_mlo=True) as (hapd_radio, hapd_iface), \
         HWSimRadio(use_mlo=True) as (wpas_radio, wpas_iface):

        params = eht_mld_ap_wpa2_params(ssid, key_mgmt="")
        params.update(hostapd.radius_params())
        params["ieee8021x"] = "1"
        params["rsn_pairwise"] = "GCMP-256"
        params["group_cipher"] = "GCMP-256"
        # Only BIP-GMAC-256 is accepted once a security profile is selected.
        params["group_mgmt_cipher"] = "BIP-GMAC-256"
        params["security_profiles"] = "18"
        params["eap_using_authentication_frames"] = "1"
        params["assoc_frame_encryption"] = "1"
        params["pmksa_caching_privacy"] = "1"

        hapd0 = eht_mld_enable_ap(hapd_iface, 0, params)

        wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas.interface_add(wpas_iface)
        wpas.set("security_profiles", "1")

        wpas.connect(ssid,
                     key_mgmt="WPA-EAP",
                     ieee80211w="2",
                     pairwise="GCMP-256",
                     group="GCMP-256",
                     eap="TLS",
                     identity="tls user",
                     ca_cert="auth_serv/ca.pem",
                     client_cert="auth_serv/user.pem",
                     private_key="auth_serv/user.key",
                     scan_freq="2412",
                     pmksa_privacy="1",
                     eap_over_auth_frame="1",
                     security_profiles="18")

        hapd0.wait_sta()
        hwsim_utils.test_connectivity(wpas, hapd0)

        ap_mld_addr = hapd0.own_mld_addr()
        pmksa1 = wpas.get_pmksa(ap_mld_addr)
        if not pmksa1:
            raise Exception("No PMKSA cache entry after the initial connection")

        wpas.request("DISCONNECT")
        wpas.wait_disconnected()
        wpas.dump_monitor()

        # The reconnect is expected to reuse the cached PMKSA. The
        # Authentication frames then carry no EAP exchange, but they still
        # contribute to the transcript used for the PTK derivation.
        wpas.request("RECONNECT")
        ev = wpas.wait_event(["CTRL-EVENT-EAP-STARTED",
                              "CTRL-EVENT-CONNECTED"], timeout=15)
        if ev is None:
            raise Exception("Reconnect timed out")
        if "CTRL-EVENT-EAP-STARTED" in ev:
            raise Exception("Unexpected EAP exchange instead of PMKSA caching")

        hapd0.wait_sta()

        sta = hapd0.get_sta(wpas.own_addr())
        if sta["AKMSuiteSelector"] != '00-0f-ac-31':
            raise Exception("Incorrect AKMSuiteSelector after PMKSA caching: " +
                            sta["AKMSuiteSelector"])

        val = wpas.get_status_field("security_profile")
        if val != "18":
            raise Exception("Unexpected security_profile after PMKSA caching: " +
                            str(val))

        pmksa2 = wpas.get_pmksa(ap_mld_addr)
        if not pmksa2:
            raise Exception("No PMKSA cache entry after PMKSA caching")
        # The cached PMK is reused, but PMKID privacy re-derives the PMKID from
        # the nonces exchanged in this association.
        if pmksa2['pmkid'] == pmksa1['pmkid']:
            raise Exception("PMKID was not re-derived for the new association")

        hwsim_utils.test_connectivity(wpas, hapd0)

def test_ieee8021x_auth_mlo_pqc_implied_config(dev, apdev):
    """IEEE 802.1X Authentication frames: PQC AKM with implied configuration"""
    key_mgmt = dev[0].get_capability("key_mgmt")
    if "EAP-PQC" not in key_mgmt:
        raise HwsimSkip(f"EAP-PQC not supported: {key_mgmt}")

    ssid = "test-ieee8021x-auth-pqc-implied"
    with HWSimRadio(use_mlo=True) as (hapd_radio, hapd_iface), \
         HWSimRadio(use_mlo=True) as (wpas_radio, wpas_iface):

        params = eht_mld_ap_wpa2_params(ssid, key_mgmt="")
        params.update(hostapd.radius_params())
        params["ieee8021x"] = "1"
        params["rsn_pairwise"] = "GCMP-256"
        params["group_cipher"] = "GCMP-256"
        # Only BIP-GMAC-256 is accepted once a security profile is selected.
        params["group_mgmt_cipher"] = "BIP-GMAC-256"
        params["security_profiles"] = "18"
        params["eap_using_authentication_frames"] = "1"
        params["assoc_frame_encryption"] = "1"
        params["pmksa_caching_privacy"] = "1"

        hapd0 = eht_mld_enable_ap(hapd_iface, 0, params)

        wpas = WpaSupplicant(global_iface='/tmp/wpas-wlan5')
        wpas.interface_add(wpas_iface)
        wpas.set("security_profiles", "1")

        # ieee80211w, pmksa_privacy and eap_over_auth_frame are implied by the
        # PQC security profile and are not configured here.
        wpas.connect(ssid,
                     key_mgmt="WPA-EAP",
                     pairwise="GCMP-256",
                     group="GCMP-256",
                     eap="TLS",
                     identity="tls user",
                     ca_cert="auth_serv/ca.pem",
                     client_cert="auth_serv/user.pem",
                     private_key="auth_serv/user.key",
                     scan_freq="2412",
                     security_profiles="18")

        hapd0.wait_sta()

        sta = hapd0.get_sta(wpas.own_addr())
        if sta["AKMSuiteSelector"] != '00-0f-ac-31':
            raise Exception("Incorrect AKMSuiteSelector: " +
                            sta["AKMSuiteSelector"])

        val = wpas.get_status_field("security_profile")
        if val != "18":
            raise Exception("Unexpected security_profile: " + str(val))

        hwsim_utils.test_connectivity(wpas, hapd0)

def test_ieee8021x_auth_pqc_config_errors(dev, apdev):
    """IEEE 802.1X Authentication frames: PQC AKM configuration errors"""
    key_mgmt = dev[0].get_capability("key_mgmt")
    if "EAP-PQC" not in key_mgmt:
        raise HwsimSkip(f"EAP-PQC not supported: {key_mgmt}")

    base = {"ssid": "test-ieee8021x-auth-pqc-config",
            "wpa": "2",
            "wpa_key_mgmt": "",
            "ieee8021x": "1",
            "rsn_pairwise": "GCMP-256",
            "group_cipher": "GCMP-256",
            "ieee80211w": "2",
            "security_profiles": "18",
            "eap_using_authentication_frames": "1",
            "assoc_frame_encryption": "1",
            "pmksa_caching_privacy": "1"}
    base.update(hostapd.radius_params())

    # A None value drops the parameter instead of overriding it.
    for param, value in [("ieee80211w", "1"),
                         ("eap_using_authentication_frames", "0"),
                         ("assoc_frame_encryption", "0"),
                         ("pmksa_caching_privacy", "0")]:
        params = dict(base)
        if value is None:
            del params[param]
        else:
            params[param] = value
        hapd = hostapd.add_ap(apdev[0], params, no_enable=True)
        if "FAIL" not in hapd.request("ENABLE"):
            raise Exception("Unexpected ENABLE success with %s=%s" % (param,
                                                                     value))
        hostapd.remove_bss(apdev[0])

    hapd = hostapd.add_ap(apdev[0], base, no_enable=True)
    hapd.enable()

def test_ieee8021x_auth_connect_disconnect_reconnect(dev, apdev):
    """IEEE 802.1X Authentication frames: non-MLO connect/disconnect/reconnect"""
    ssid = "test-ieee8021x-auth-cdr"

    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"

    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="TLS",
                   identity="tls user",
                   ca_cert="auth_serv/ca.pem",
                   client_cert="auth_serv/user.pem",
                   private_key="auth_serv/user.key",
                   scan_freq="2412",
                   eap_over_auth_frame="1")

    hapd.wait_sta()

    sta = hapd.get_sta(dev[0].own_addr())
    auth_alg = sta.get("auth_alg")
    logger.info("Auth Algorithm: " + str(auth_alg))
    if str(auth_alg) != "8":
        raise Exception("Expected IEEE 802.1X auth (8), got: " + str(auth_alg))
    hwsim_utils.test_connectivity(dev[0], hapd)

    for _ in range(2):
        dev[0].request("DISCONNECT")
        dev[0].wait_disconnected(timeout=5)
        dev[0].request("RECONNECT")
        dev[0].wait_connected(timeout=15, error="Reconnect timed out")
        hapd.wait_sta()
        hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_auth_alg_legacy_akm_wpa_eap(dev, apdev):
    """Legacy WPA-EAP authentication with AKM 1 (supplicant should not use IEEE 802.1X Authentication frames with AKM 1)"""
    ssid = "test-legacy-akm-wpa-eap"

    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"

    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP",
                   eap="TLS",
                   identity="tls user",
                   ca_cert="auth_serv/ca.pem",
                   client_cert="auth_serv/user.pem",
                   private_key="auth_serv/user.key",
                   scan_freq="2412",
                   eap_over_auth_frame="1")

    hapd.wait_sta()
    sta = hapd.get_sta(dev[0].own_addr())

    if sta["AKMSuiteSelector"] != '00-0f-ac-1':
        raise Exception("Incorrect AKMSuiteSelector value: " + sta["AKMSuiteSelector"])

    auth_alg = sta.get("auth_alg")
    logger.info("Auth Algorithm: " + str(auth_alg))
    if str(auth_alg) != "OPEN_SYSTEM" and str(auth_alg) != "0":
        raise Exception("Expected legacy OPEN_SYSTEM auth, got: " + str(auth_alg))
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_auth_alg_eap_tls_pmksa_privacy(dev, apdev):
    """IEEE 802.1X authentication with EAP-TLS and PMKSA caching privacy"""
    ssid = "test-ieee8021x-auth-tls-pmksa"

    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"
    params["pmksa_caching_privacy"] = "1"

    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="TLS",
                   identity="tls user",
                   ca_cert="auth_serv/ca.pem",
                   client_cert="auth_serv/user.pem",
                   private_key="auth_serv/user.key",
                   pmksa_privacy="1",
                   scan_freq="2412",
                   eap_over_auth_frame="1")

    hapd.wait_sta()
    sta = hapd.get_sta(dev[0].own_addr())

    if sta["AKMSuiteSelector"] != '00-0f-ac-5':
        raise Exception("Incorrect AKMSuiteSelector value: " + sta["AKMSuiteSelector"])

    auth_alg = sta.get("auth_alg")
    logger.info("Auth Algorithm: " + str(auth_alg))
    if str(auth_alg) != "8":
        raise Exception("Expected IEEE 802.1X auth (8), got: " + str(auth_alg))
    hwsim_utils.test_connectivity(dev[0], hapd)

    pmksa1 = dev[0].get_pmksa(hapd.own_addr())
    if pmksa1 is None:
        raise Exception("No PMKSA entry after first connection")
    pmkid1 = pmksa1['pmkid']
    logger.info("PMKID after first connection: " + pmkid1)

    dev[0].request("DISCONNECT")
    dev[0].wait_disconnected()
    dev[0].request("RECONNECT")
    dev[0].wait_connected(timeout=15, error="Reconnect timed out")

    hapd.wait_sta()

    pmksa2 = dev[0].get_pmksa(hapd.own_addr())
    if pmksa2 is None:
        raise Exception("No PMKSA entry after second connection")
    pmkid2 = pmksa2['pmkid']
    logger.info("PMKID after second connection: " + pmkid2)

    if pmkid1 == pmkid2:
        raise Exception("PMKID did not rotate: %s == %s" % (pmkid1, pmkid2))

    sta = hapd.get_sta(dev[0].own_addr())

    if sta["AKMSuiteSelector"] != '00-0f-ac-5':
        raise Exception("Incorrect AKMSuiteSelector value after PMKSA caching")

    auth_alg = sta.get("auth_alg")
    logger.info("Auth Algorithm after PMKSA caching: " + str(auth_alg))
    if str(auth_alg) != "8":
        raise Exception("Expected IEEE 802.1X auth (8) after PMKSA caching, got: " + str(auth_alg))
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_auth_alg_eap_tls_ptk_rekey(dev, apdev):
    """IEEE 802.1X authentication with EAP-TLS and PTK rekey"""
    ssid = "test-ieee8021x-tls-ptk-rekey"

    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"
    params["wpa_ptk_rekey"] = "3"

    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="TLS",
                   identity="tls user",
                   ca_cert="auth_serv/ca.pem",
                   client_cert="auth_serv/user.pem",
                   private_key="auth_serv/user.key",
                   scan_freq="2412",
                   eap_over_auth_frame="1")

    hapd.wait_sta()
    sta = hapd.get_sta(dev[0].own_addr())

    if sta["AKMSuiteSelector"] != '00-0f-ac-5':
        raise Exception("Incorrect AKMSuiteSelector value: " + sta["AKMSuiteSelector"])

    auth_alg = sta.get("auth_alg")
    logger.info("Auth Algorithm: " + str(auth_alg))
    if str(auth_alg) != "8":
        raise Exception("Expected IEEE 802.1X auth (8), got: " + str(auth_alg))
    hwsim_utils.test_connectivity(dev[0], hapd)

    ev = dev[0].wait_event(["WPA: Key negotiation completed"], timeout=11)
    if ev is None:
        raise Exception("PTK rekey timed out")

    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_auth_alg_eap_tls_gtk_rekey(dev, apdev):
    """IEEE 802.1X authentication with EAP-TLS and GTK rekey"""
    ssid = "test-ieee8021x-tls-gtk-rekey"

    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"
    params["wpa_group_rekey"] = "2"

    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="TLS",
                   identity="tls user",
                   ca_cert="auth_serv/ca.pem",
                   client_cert="auth_serv/user.pem",
                   private_key="auth_serv/user.key",
                   scan_freq="2412",
                   eap_over_auth_frame="1")

    hapd.wait_sta()
    sta = hapd.get_sta(dev[0].own_addr())

    if sta["AKMSuiteSelector"] != '00-0f-ac-5':
        raise Exception("Incorrect AKMSuiteSelector value: " + sta["AKMSuiteSelector"])

    auth_alg = sta.get("auth_alg")
    logger.info("Auth Algorithm: " + str(auth_alg))
    if str(auth_alg) != "8":
        raise Exception("Expected IEEE 802.1X auth (8), got: " + str(auth_alg))

    ev = dev[0].wait_event(["RSN: Group rekeying completed"], timeout=11)
    if ev is None:
        raise Exception("GTK rekey timed out")

    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_auth_protocol_eap_tls_pmksa_not_found_by_ap(dev, apdev):
    """IEEE 802.1X authentication with PMKSA caching fallback when AP does not recognize PMKID"""
    ssid = "test-ieee8021x-pmksa-fallback"

    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"
    params["ieee80211w"] = "2"

    hapd = hostapd.add_ap(apdev[0], params)

    # First connection to establish PMKSA cache
    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   ieee80211w="2",
                   eap="TLS",
                   identity="tls user",
                   ca_cert="auth_serv/ca.pem",
                   client_cert="auth_serv/user.pem",
                   private_key="auth_serv/user.key",
                   scan_freq="2412",
                   eap_over_auth_frame="1")

    hapd.wait_sta()

    # Disconnect
    dev[0].request("DISCONNECT")
    dev[0].wait_disconnected()

    # Flush AP's PMKSA cache to simulate AP not recognizing the PMKID
    hapd.request("PMKSA_FLUSH")

    hapd.dump_monitor()
    dev[0].dump_monitor()

    # Reconnect - wpa_supplicant will try PMKSA caching but AP won't recognize
    # it, triggering fallback to full EAP authentication
    dev[0].request("RECONNECT")
    dev[0].wait_connected(timeout=15,
                          error="Reconnect with PMKSA fallback timed out")

    hapd.wait_sta()
    sta = hapd.get_sta(dev[0].own_addr())

    if sta["AKMSuiteSelector"] != '00-0f-ac-5':
        raise Exception("Incorrect AKMSuiteSelector after PMKSA fallback")

    auth_alg = sta.get("auth_alg")
    logger.info("Auth Algorithm: " + str(auth_alg))
    if str(auth_alg) != "8":
        raise Exception("Expected IEEE 802.1X auth (8) after PMKSA fallback, got: " + str(auth_alg))
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_auth_sta_eap_over_auth_frame_ap_no_support(dev, apdev):
    """STA requests EAP over auth frames but AP does not support it; connection succeeds with Open System auth"""
    ssid = "test-ieee8021x-auth-sta-only"

    # AP does not set eap_using_authentication_frames, so it will not
    # advertise or accept IEEE 802.1X Authentication frames. wpa_supplicant
    # sets eap_over_auth_frame=1 but must gracefully fall back to the
    # standard 802.11 Open System authentication + EAP-over-EAPOL path.
    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP-SHA256"

    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="TLS",
                   identity="tls user",
                   ca_cert="auth_serv/ca.pem",
                   client_cert="auth_serv/user.pem",
                   private_key="auth_serv/user.key",
                   scan_freq="2412",
                   eap_over_auth_frame="1")

    hapd.wait_sta()
    sta = hapd.get_sta(dev[0].own_addr())

    if sta["AKMSuiteSelector"] != '00-0f-ac-5':
        raise Exception("Incorrect AKMSuiteSelector value: " + sta["AKMSuiteSelector"])

    auth_alg = sta.get("auth_alg")
    logger.info("Auth Algorithm: " + str(auth_alg))
    if str(auth_alg) != "0":
        raise Exception("Expected OPEN_SYSTEM auth (0) when AP lacks auth frame support, got: " + str(auth_alg))
    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_auth_sta_opts_out_of_auth_frames(dev, apdev):
    """AP supports auth frames but STA explicitly opts out (eap_over_auth_frame=0)"""
    ssid = "test-ieee8021x-sta-opts-out"

    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"

    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="TLS",
                   identity="tls user",
                   ca_cert="auth_serv/ca.pem",
                   client_cert="auth_serv/user.pem",
                   private_key="auth_serv/user.key",
                   scan_freq="2412",
                   eap_over_auth_frame="0")

    hapd.wait_sta()
    sta = hapd.get_sta(dev[0].own_addr())

    if sta["AKMSuiteSelector"] != '00-0f-ac-5':
        raise Exception("Incorrect AKMSuiteSelector value: " + sta["AKMSuiteSelector"])

    auth_alg = sta.get("auth_alg")
    logger.info("Auth Algorithm: " + str(auth_alg))
    if str(auth_alg) not in ("0", "OPEN_SYSTEM"):
        raise Exception("Expected OPEN_SYSTEM auth (0) when STA opts out, got: " + str(auth_alg))

    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_auth_eap_failure_wrong_password(dev, apdev):
    """EAP authentication failure (wrong password) during auth frames exchange"""
    ssid = "test-ieee8021x-eap-fail-pw"

    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"

    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="TTLS",
                   identity="user",
                   anonymous_identity="ttls",
                   password="WRONG_PASSWORD",
                   phase2="autheap=MSCHAPV2",
                   ca_cert="auth_serv/ca.pem",
                   scan_freq="2412",
                   eap_over_auth_frame="1",
                   wait_connect=False)

    ev = dev[0].wait_event(["CTRL-EVENT-EAP-FAILURE",
                            "CTRL-EVENT-SSID-TEMP-DISABLED"], timeout=15)
    if ev is None:
        raise Exception("Expected EAP failure event, got nothing")
    logger.info("Got expected failure event: " + ev)

def test_ieee8021x_auth_eap_tls_cert_failure(dev, apdev):
    """EAP-TLS certificate failure during auth frames exchange"""
    ssid = "test-ieee8021x-tls-cert-fail"

    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"

    hapd = hostapd.add_ap(apdev[0], params)

    # Use wrong CA cert so TLS handshake fails
    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="TLS",
                   identity="tls user",
                   ca_cert="auth_serv/ca-sha384.pem",
                   client_cert="auth_serv/user.pem",
                   private_key="auth_serv/user.key",
                   scan_freq="2412",
                   eap_over_auth_frame="1",
                   wait_connect=False)

    ev = dev[0].wait_event(["CTRL-EVENT-EAP-FAILURE",
                            "CTRL-EVENT-SSID-TEMP-DISABLED"], timeout=15)
    if ev is None:
        raise Exception("Expected EAP-TLS certificate failure event, got nothing")
    logger.info("Got expected TLS cert failure event: " + ev)

def test_ieee8021x_auth_data_connectivity(dev, apdev):
    """Verify data plane works after EAP-over-auth-frames connection"""
    ssid = "test-ieee8021x-data-plane"

    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"

    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="TLS",
                   identity="tls user",
                   ca_cert="auth_serv/ca.pem",
                   client_cert="auth_serv/user.pem",
                   private_key="auth_serv/user.key",
                   scan_freq="2412",
                   eap_over_auth_frame="1")

    hapd.wait_sta()
    sta = hapd.get_sta(dev[0].own_addr())

    if sta["AKMSuiteSelector"] != '00-0f-ac-5':
        raise Exception("Incorrect AKMSuiteSelector value: " + sta["AKMSuiteSelector"])

    auth_alg = sta.get("auth_alg")
    logger.info("Auth Algorithm: " + str(auth_alg))
    if str(auth_alg) != "8":
        raise Exception("Expected IEEE 802.1X auth (8), got: " + str(auth_alg))

    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_auth_repeated_reconnects_auth_alg_stable(dev, apdev):
    """Verify auth_alg=8 is stable across 5 connect/disconnect cycles"""
    ssid = "test-ieee8021x-repeat-reconnect"

    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"

    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="TLS",
                   identity="tls user",
                   ca_cert="auth_serv/ca.pem",
                   client_cert="auth_serv/user.pem",
                   private_key="auth_serv/user.key",
                   scan_freq="2412",
                   eap_over_auth_frame="1")

    hapd.wait_sta()

    for cycle in range(5):
        dev[0].request("DISCONNECT")
        dev[0].wait_disconnected(timeout=5)
        dev[0].request("RECONNECT")
        dev[0].wait_connected(timeout=20,
                              error="Reconnect failed on cycle %d" % cycle)
        hapd.wait_sta()

        sta = hapd.get_sta(dev[0].own_addr())
        auth_alg = sta.get("auth_alg")
        logger.info("Cycle %d auth_alg: %s" % (cycle, str(auth_alg)))
        if str(auth_alg) != "8":
            raise Exception("auth_alg not 8 on cycle %d: %s" % (cycle, str(auth_alg)))

        hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_auth_gcmp256_cipher(dev, apdev):
    """IEEE 802.1X auth frames with GCMP-256 pairwise cipher"""
    ssid = "test-ieee8021x-gcmp256"

    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params["rsn_pairwise"] = "GCMP-256"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"
    params["ieee80211w"] = "2"

    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="TLS",
                   identity="tls user",
                   ca_cert="auth_serv/ca.pem",
                   client_cert="auth_serv/user.pem",
                   private_key="auth_serv/user.key",
                   pairwise="GCMP-256",
                   group="GCMP-256",
                   ieee80211w="2",
                   scan_freq="2412",
                   eap_over_auth_frame="1")

    hapd.wait_sta()
    sta = hapd.get_sta(dev[0].own_addr())

    if sta["AKMSuiteSelector"] != '00-0f-ac-5':
        raise Exception("Incorrect AKMSuiteSelector value: " + sta["AKMSuiteSelector"])

    auth_alg = sta.get("auth_alg")
    logger.info("Auth Algorithm: " + str(auth_alg))
    if str(auth_alg) != "8":
        raise Exception("Expected IEEE 802.1X auth (8) with GCMP-256, got: " + str(auth_alg))

    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_auth_deauth_during_exchange(dev, apdev):
    """AP deauthenticates STA after connection; reconnect succeeds cleanly"""
    ssid = "test-ieee8021x-deauth"

    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"

    hapd = hostapd.add_ap(apdev[0], params)

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="TLS",
                   identity="tls user",
                   ca_cert="auth_serv/ca.pem",
                   client_cert="auth_serv/user.pem",
                   private_key="auth_serv/user.key",
                   scan_freq="2412",
                   eap_over_auth_frame="1")

    hapd.wait_sta()
    sta = hapd.get_sta(dev[0].own_addr())
    if str(sta.get("auth_alg")) != "8":
        raise Exception("Expected auth_alg=8 before deauth")

    # Force AP to deauthenticate the STA
    hapd.request("DEAUTHENTICATE " + dev[0].own_addr())
    dev[0].wait_disconnected(timeout=5)

    # Reconnect must succeed cleanly (no leaked state)
    dev[0].wait_connected(timeout=20, error="Reconnect after deauth failed")
    hapd.wait_sta()

    sta = hapd.get_sta(dev[0].own_addr())
    auth_alg = sta.get("auth_alg")
    logger.info("Auth Algorithm after reconnect: " + str(auth_alg))
    if str(auth_alg) != "8":
        raise Exception("Expected auth_alg=8 after reconnect, got: " + str(auth_alg))

    hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_auth_roam_to_non_auth_frame_ap(dev, apdev):
    """Roam from auth-frame AP to standard AP: STA falls back to Open System auth"""
    ssid = "test-ieee8021x-roam"

    params1 = hostapd.wpa2_eap_params(ssid=ssid)
    params1["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params1["eap_using_authentication_frames"] = "1"
    params1["assoc_frame_encryption"] = "1"
    hapd1 = hostapd.add_ap(apdev[0], params1)

    params2 = hostapd.wpa2_eap_params(ssid=ssid)
    params2["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    hapd2 = hostapd.add_ap(apdev[1], params2)

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="TLS",
                   identity="tls user",
                   ca_cert="auth_serv/ca.pem",
                   client_cert="auth_serv/user.pem",
                   private_key="auth_serv/user.key",
                   scan_freq="2412",
                   eap_over_auth_frame="1")
    hapd1.wait_sta()

    sta1 = hapd1.get_sta(dev[0].own_addr())
    auth_alg1 = sta1.get("auth_alg")
    logger.info("Auth Algorithm on AP1: " + str(auth_alg1))
    if str(auth_alg1) != "8":
        raise Exception("Expected auth_alg=8 on AP1, got: " + str(auth_alg1))

    # Roam to AP2 (no auth frame support)
    dev[0].roam(apdev[1]['bssid'])
    hapd2.wait_sta()

    sta2 = hapd2.get_sta(dev[0].own_addr())
    auth_alg2 = sta2.get("auth_alg")
    logger.info("Auth Algorithm on AP2: " + str(auth_alg2))
    if str(auth_alg2) not in ("0", "OPEN_SYSTEM"):
        raise Exception("Expected OPEN_SYSTEM auth (0) on AP2, got: " + str(auth_alg2))

    hwsim_utils.test_connectivity(dev[0], hapd2)

def test_ieee8021x_auth_roam_between_auth_frame_aps(dev, apdev):
    """Roam between two auth-frame APs: second AP requires full EAP, first uses PMKSA fast path on return"""
    ssid = "test-ieee8021x-roam-both"

    params1 = hostapd.wpa2_eap_params(ssid=ssid)
    params1["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params1["eap_using_authentication_frames"] = "1"
    params1["assoc_frame_encryption"] = "1"
    hapd1 = hostapd.add_ap(apdev[0], params1)

    params2 = hostapd.wpa2_eap_params(ssid=ssid)
    params2["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params2["eap_using_authentication_frames"] = "1"
    params2["assoc_frame_encryption"] = "1"
    hapd2 = hostapd.add_ap(apdev[1], params2)

    # Initial connection to AP1
    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="TLS",
                   identity="tls user",
                   ca_cert="auth_serv/ca.pem",
                   client_cert="auth_serv/user.pem",
                   private_key="auth_serv/user.key",
                   scan_freq="2412",
                   eap_over_auth_frame="1")
    hapd1.wait_sta()

    sta1 = hapd1.get_sta(dev[0].own_addr())
    if str(sta1.get("auth_alg")) != "8":
        raise Exception("Expected auth_alg=8 on AP1")

    # Roam to AP2 (no PMKSA cache entry for AP2 yet — full EAP)
    dev[0].roam(apdev[1]['bssid'])
    hapd2.wait_sta()

    sta2 = hapd2.get_sta(dev[0].own_addr())
    auth_alg2 = sta2.get("auth_alg")
    logger.info("Auth Algorithm on AP2: " + str(auth_alg2))
    if str(auth_alg2) != "8":
        raise Exception("Expected auth_alg=8 on AP2, got: " + str(auth_alg2))

    # Roam back to AP1 (PMKSA cache hit — fast path)
    dev[0].roam(apdev[0]['bssid'])
    hapd1.wait_sta()

    sta1b = hapd1.get_sta(dev[0].own_addr())
    auth_alg1b = sta1b.get("auth_alg")
    logger.info("Auth Algorithm back on AP1: " + str(auth_alg1b))
    if str(auth_alg1b) != "8":
        raise Exception("Expected auth_alg=8 on return to AP1, got: " + str(auth_alg1b))

    hwsim_utils.test_connectivity(dev[0], hapd1)

def test_ieee8021x_auth_mixed_concurrent(dev, apdev):
    """One STA uses EAP-over-auth-frames, another uses standard Open System + EAPOL simultaneously"""
    ssid = "test-ieee8021x-mixed-concurrent"

    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"

    hapd = hostapd.add_ap(apdev[0], params)

    # dev[0]: uses IEEE 802.1X Authentication frames
    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="TLS",
                   identity="tls user",
                   ca_cert="auth_serv/ca.pem",
                   client_cert="auth_serv/user.pem",
                   private_key="auth_serv/user.key",
                   scan_freq="2412",
                   eap_over_auth_frame="1")
    hapd.wait_sta()

    # dev[1]: uses standard Open System auth + EAP-over-EAPOL (no auth frames)
    dev[1].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="TLS",
                   identity="tls user",
                   ca_cert="auth_serv/ca.pem",
                   client_cert="auth_serv/user.pem",
                   private_key="auth_serv/user.key",
                   scan_freq="2412")
    hapd.wait_sta()

    sta0 = hapd.get_sta(dev[0].own_addr())
    sta1 = hapd.get_sta(dev[1].own_addr())

    if sta0["AKMSuiteSelector"] != '00-0f-ac-5':
        raise Exception("Incorrect AKMSuiteSelector for dev[0]")
    if sta1["AKMSuiteSelector"] != '00-0f-ac-5':
        raise Exception("Incorrect AKMSuiteSelector for dev[1]")

    auth_alg0 = sta0.get("auth_alg")
    logger.info("Auth Algorithm dev[0]: " + str(auth_alg0))
    if str(auth_alg0) != "8":
        raise Exception("Expected IEEE 802.1X auth (8) for dev[0], got: " + str(auth_alg0))

    auth_alg1 = sta1.get("auth_alg")
    logger.info("Auth Algorithm dev[1]: " + str(auth_alg1))
    if str(auth_alg1) not in ("0", "OPEN_SYSTEM"):
        raise Exception("Expected OPEN_SYSTEM auth (0) for dev[1], got: " + str(auth_alg1))

    # Test STA-to-STA data delivery in both directions including broadcast.
    # Verifies the AP correctly forwards frames between an auth-frame STA
    # (auth_alg=8) and a standard EAPOL STA (auth_alg=0).
    # The GTK is delivered to dev[0] in the encrypted Association Response
    # (Key Delivery element), so broadcast should work immediately.
    hwsim_utils.test_connectivity(dev[0], dev[1])
    hwsim_utils.test_connectivity(dev[1], dev[0])

def _run_ieee8021x_auth_security_profile_pqc(dev, apdev, expected_akm,
                                             expected_profile, mldsa=False):
    ssid = "test-ieee8021x-auth-secprof-pqc"

    params = hostapd.wpa2_eap_params(ssid=ssid)
    # The PQC AKM and the PQC constraint are implied by the security profile.
    params["wpa_key_mgmt"] = ""
    params["rsn_pairwise"] = "GCMP-256"
    params["group_cipher"] = "GCMP-256"
    params["ieee80211w"] = "2"
    params["security_profiles"] = str(expected_profile)
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"
    params["pmksa_caching_privacy"] = "1"
    if mldsa:
        params.update(MLDSA_AP_PARAMS)

    hapd = hostapd.add_ap(apdev[0], params)
    if mldsa:
        check_mldsa_support(hapd)
        check_mldsa_support(dev[0])
        certs = MLDSA_STA_CERTS
    else:
        certs = {"ca_cert": "auth_serv/ca.pem",
                 "client_cert": "auth_serv/user.pem",
                 "private_key": "auth_serv/user.key"}

    try:
        dev[0].set("security_profiles", "1")
    except:
        raise HwsimSkip("Security profiles not supported")

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP",
                   ieee80211w="2",
                   pairwise="GCMP-256",
                   group="GCMP-256",
                   eap="TLS",
                   identity="tls user",
                   scan_freq="2412",
                   pmksa_privacy="1",
                   eap_over_auth_frame="1",
                   security_profiles=str(expected_profile),
                   **certs)

    hapd.wait_sta()
    sta = hapd.get_sta(dev[0].own_addr())

    if sta["AKMSuiteSelector"] != expected_akm:
        raise Exception("Incorrect AKMSuiteSelector value: " +
                        sta["AKMSuiteSelector"])

    val = dev[0].get_status_field("security_profile")
    if val != str(expected_profile):
        raise Exception("Unexpected security_profile: " + str(val))

    # Each profile uses a different hash and key length in the transcript based
    # PTK derivation, so a mismatch only shows up as a data path failure.
    hwsim_utils.test_connectivity(dev[0], hapd)

    # The EAPOL-Key integrity and key wrap algorithms are AKM defined for the
    # PQC AKMs, but their lengths follow the profile.
    if "OK" not in hapd.request("REKEY_GTK"):
        raise Exception("REKEY_GTK failed")
    ev = dev[0].wait_event(["RSN: Group rekeying completed"], timeout=5)
    if ev is None:
        raise Exception("GTK rekey timed out")

    hwsim_utils.test_connectivity(dev[0], hapd)

    # Disconnect and reconnect to verify PMKSA caching works
    for i in range(2):
        dev[0].request("DISCONNECT")
        dev[0].wait_disconnected(timeout=5)
        dev[0].request("RECONNECT")
        dev[0].wait_connected(timeout=15,
                              error="Reconnect %d timed out" % (i + 1))
        hapd.wait_sta()
        sta = hapd.get_sta(dev[0].own_addr())
        if sta["AKMSuiteSelector"] != expected_akm:
            raise Exception("Incorrect AKMSuiteSelector after reconnect %d: " %
                            (i + 1) + sta["AKMSuiteSelector"])
        hwsim_utils.test_connectivity(dev[0], hapd)

def test_ieee8021x_auth_alg_eap_tls_security_profile_16(dev, apdev):
    """IEEE 802.1X authentication with EAP-TLS and Security Profile 16 (PQC constraint 0)"""
    key_mgmt = dev[0].get_capability("key_mgmt")
    if "EAP-PQC" not in key_mgmt:
        raise HwsimSkip(f"EAP-PQC not supported: {key_mgmt}")

    _run_ieee8021x_auth_security_profile_pqc(dev, apdev,
                                             "00-0f-ac-31", 16)

def test_ieee8021x_auth_alg_eap_tls_security_profile_17(dev, apdev):
    """IEEE 802.1X authentication with EAP-TLS and Security Profile 17 (PQC constraint 1)"""
    key_mgmt = dev[0].get_capability("key_mgmt")
    if "EAP-PQC" not in key_mgmt:
        raise HwsimSkip(f"EAP-PQC not supported: {key_mgmt}")

    _run_ieee8021x_auth_security_profile_pqc(dev, apdev,
                                             "00-0f-ac-31", 17)

def test_ieee8021x_auth_alg_eap_tls_security_profile_18(dev, apdev):
    """IEEE 802.1X authentication with EAP-TLS and Security Profile 18 (PQC constraint 2)"""
    key_mgmt = dev[0].get_capability("key_mgmt")
    if "EAP-PQC" not in key_mgmt:
        raise HwsimSkip(f"EAP-PQC not supported: {key_mgmt}")

    _run_ieee8021x_auth_security_profile_pqc(dev, apdev,
                                             "00-0f-ac-31", 18)

def test_ieee8021x_auth_alg_eap_tls_security_profile_19(dev, apdev):
    """IEEE 802.1X authentication with EAP-TLS and Security Profile 19 (PQC constraint 3)"""
    key_mgmt = dev[0].get_capability("key_mgmt")
    if "EAP-PQC" not in key_mgmt:
        raise HwsimSkip(f"EAP-PQC not supported: {key_mgmt}")

    _run_ieee8021x_auth_security_profile_pqc(dev, apdev,
                                             "00-0f-ac-31", 19)

def test_ieee8021x_auth_alg_eap_tls_mldsa(dev, apdev):
    """IEEE 802.1X authentication using Authentication frames with ML-DSA certificates"""
    ssid = "test-ieee8021x-auth-mldsa"

    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"
    params.update(MLDSA_AP_PARAMS)

    hapd = hostapd.add_ap(apdev[0], params)
    check_mldsa_support(hapd)
    check_mldsa_support(dev[0])

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   eap="TLS",
                   identity="tls user",
                   scan_freq="2412",
                   eap_over_auth_frame="1",
                   **MLDSA_STA_CERTS)

    hapd.wait_sta()
    sta = hapd.get_sta(dev[0].own_addr())

    if sta["AKMSuiteSelector"] != '00-0f-ac-5':
        raise Exception("Incorrect AKMSuiteSelector value: " + sta["AKMSuiteSelector"])

    ver = dev[0].get_status_field("eap_tls_version")
    if ver != "TLSv1.3":
        raise Exception("Unexpected TLS version: " + str(ver))

def test_ieee8021x_auth_alg_eap_tls_mldsa_security_profile_18(dev, apdev):
    """IEEE 802.1X authentication with Security Profile 18 and ML-DSA certificates"""
    key_mgmt = dev[0].get_capability("key_mgmt")
    if "EAP-PQC" not in key_mgmt:
        raise HwsimSkip(f"EAP-PQC not supported: {key_mgmt}")

    # Fully post-quantum: ML-KEM in the PTK derivation and ML-DSA in the
    # credential used for the EAP authentication.
    _run_ieee8021x_auth_security_profile_pqc(dev, apdev,
                                             "00-0f-ac-31", 18, mldsa=True)

def test_ieee8021x_auth_alg_eap_tls_mldsa_security_profile_19(dev, apdev):
    """IEEE 802.1X authentication with Security Profile 19 and ML-DSA certificates"""
    key_mgmt = dev[0].get_capability("key_mgmt")
    if "EAP-PQC" not in key_mgmt:
        raise HwsimSkip(f"EAP-PQC not supported: {key_mgmt}")

    _run_ieee8021x_auth_security_profile_pqc(dev, apdev,
                                             "00-0f-ac-31", 19, mldsa=True)

def mgmt_rx_process(hapd, frame):
    cmd = "MGMT_RX_PROCESS freq=2412 datarate=0 ssi_signal=-30 frame=" + frame
    if "OK" not in hapd.request(cmd):
        raise Exception("MGMT_RX_PROCESS failed")

def build_802_1x_auth_frame(hapd, addr, auth_transaction=1, status=0, body=b''):
    bssid = hapd.own_addr().replace(':', '')
    hdr = "b0003a01" + bssid + addr.replace(':', '') + bssid + "1000"
    fixed = struct.pack("<HHH", WLAN_AUTH_802_1X, auth_transaction, status)
    return hdr + binascii.hexlify(fixed + body).decode()

def eapol_start_encap():
    """Encapsulation Length field followed by an EAPOL-Start PDU"""
    pdu = struct.pack(">BBH", 2, 1, 0)
    return struct.pack("<H", len(pdu)) + pdu

def test_ieee8021x_auth_alg_not_enabled(dev, apdev):
    """IEEE 802.1X over Authentication frames when the AP has not enabled them"""
    ssid = "test-ieee8021x-auth-not-enabled"

    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = "WPA-EAP-SHA256"
    params["ieee80211w"] = "2"

    hapd = hostapd.add_ap(apdev[0], params)
    hapd.set("ext_mgmt_frame_handling", "1")

    # The AP rejects the frame before a STA entry has been allocated.
    mgmt_rx_process(hapd, build_802_1x_auth_frame(hapd, "02:03:04:05:06:07",
                                                  body=eapol_start_encap()))

    if "PONG" not in hapd.request("PING"):
        raise Exception("hostapd did not survive the Authentication frame")

    hapd.set("ext_mgmt_frame_handling", "0")

    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP-SHA256",
                   ieee80211w="2",
                   eap="TLS",
                   identity="tls user",
                   ca_cert="auth_serv/ca.pem",
                   client_cert="auth_serv/user.pem",
                   private_key="auth_serv/user.key",
                   scan_freq="2412")

def test_ieee8021x_auth_pqc_akm_without_pqc_element(dev, apdev):
    """IEEE 802.1X over Authentication frames with a PQC AKM and no PQC Parameters element"""
    if "EAP-PQC" not in dev[0].get_capability("key_mgmt"):
        raise HwsimSkip("EAP-PQC not supported")

    ssid = "test-ieee8021x-auth-pqc-no-elem"

    params = hostapd.wpa2_eap_params(ssid=ssid)
    params["wpa_key_mgmt"] = ""
    params["rsn_pairwise"] = "GCMP-256"
    params["group_cipher"] = "GCMP-256"
    params["ieee80211w"] = "2"
    params["security_profiles"] = "18"
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"
    params["pmksa_caching_privacy"] = "1"

    hapd = hostapd.add_ap(apdev[0], params)
    hapd.set("ext_mgmt_frame_handling", "1")

    # AKM Suite Selector element advertising 00-0F-AC:31 without the PQC
    # Parameters element that carries the security profile.
    akm = struct.pack(">BBBBBBB", 255, 5, 114, 0x00, 0x0f, 0xac, 31)
    body = eapol_start_encap() + akm

    mgmt_rx_process(hapd, build_802_1x_auth_frame(hapd, "02:03:04:05:06:07",
                                                  body=body))

    hapd.set("ext_mgmt_frame_handling", "0")

    dev[0].set("security_profiles", "1")
    dev[0].connect(ssid,
                   key_mgmt="WPA-EAP",
                   ieee80211w="2",
                   pairwise="GCMP-256",
                   group="GCMP-256",
                   eap="TLS",
                   identity="tls user",
                   ca_cert="auth_serv/ca.pem",
                   client_cert="auth_serv/user.pem",
                   private_key="auth_serv/user.key",
                   scan_freq="2412",
                   pmksa_privacy="1",
                   eap_over_auth_frame="1",
                   security_profiles="18")

    hapd.wait_sta()
    sta = hapd.get_sta(dev[0].own_addr())
    if sta["AKMSuiteSelector"] != "00-0f-ac-31":
        raise Exception("Incorrect AKMSuiteSelector value: " +
                        sta["AKMSuiteSelector"])

    val = dev[0].get_status_field("security_profile")
    if val != "18":
        raise Exception("Unexpected security_profile: " + str(val))

SECURITY_PROFILE_MAX = 23
SECURITY_PROFILE_8021X_PQC_0 = 16
SECURITY_PROFILE_8021X_PQC_1 = 17
SECURITY_PROFILE_8021X_PQC_2 = 18
SECURITY_PROFILE_8021X_PQC_3 = 19

RSN_AKM_802_1X_PQC = b'\x00\x0f\xac\x1f'
RSN_AKM_FT_802_1X_PQC = b'\x00\x0f\xac\x20'
RSN_CIPHER_GCMP_256 = b'\x00\x0f\xac\x09'

def pqc_ap_params(ssid, profiles=str(SECURITY_PROFILE_8021X_PQC_2)):
    """AP parameters for IEEE 802.1X over Authentication frames with EAP-PQC"""
    params = hostapd.wpa2_eap_params(ssid=ssid)
    # The PQC AKM has no wpa_key_mgmt name of its own; it is implied by the
    # configured security profiles.
    params["wpa_key_mgmt"] = ""
    # Only BIP-GMAC-256 is accepted once a security profile is selected.
    params["group_mgmt_cipher"] = "BIP-GMAC-256"
    params["rsn_pairwise"] = "GCMP-256"
    params["group_cipher"] = "GCMP-256"
    params["ieee80211w"] = "2"
    params["security_profiles"] = profiles
    params["eap_using_authentication_frames"] = "1"
    params["assoc_frame_encryption"] = "1"
    params["pmksa_caching_privacy"] = "1"
    return params

# EAP-PSK keeps the Authentication frames small enough to be forwarded over
# the control interface, unlike the certificate exchange of EAP-TLS.
EAP_PSK_PARAMS = {"eap": "PSK",
                  "identity": "psk.user@example.com",
                  "password_hex": "0123456789abcdef0123456789abcdef"}

EAP_TLS_PARAMS = {"eap": "TLS",
                  "identity": "tls user",
                  "ca_cert": "auth_serv/ca.pem",
                  "client_cert": "auth_serv/user.pem",
                  "private_key": "auth_serv/user.key"}

def pqc_connect(dev, ssid, profiles=str(SECURITY_PROFILE_8021X_PQC_2),
                eap_params=EAP_TLS_PARAMS, **kwargs):
    """Connect with EAP-PQC using IEEE 802.1X over Authentication frames"""
    kwargs.setdefault("security_profiles", profiles)
    dev.set("security_profiles", "1")
    dev.connect(ssid, key_mgmt="WPA-EAP", ieee80211w="2", pairwise="GCMP-256",
                group="GCMP-256", scan_freq="2412", pmksa_privacy="1",
                eap_over_auth_frame="1", **eap_params, **kwargs)

def rsne_elem(akm=RSN_AKM_802_1X_PQC):
    """Build an RSNE with GCMP-256 and the given AKM suite selector"""
    data = struct.pack("<H", 1) + RSN_CIPHER_GCMP_256
    data += struct.pack("<H", 1) + RSN_CIPHER_GCMP_256
    data += struct.pack("<H", 1) + akm
    data += struct.pack("<H", 0x00c0)
    return struct.pack("BB", WLAN_EID_RSN, len(data)) + data

def nonce_elem(nonce=32 * b'\x11'):
    """Build a Nonce element"""
    return struct.pack("BBB", WLAN_EID_EXTENSION, 1 + len(nonce),
                       WLAN_EID_EXT_NONCE) + nonce

def akm_suite_selector_elem(akm=RSN_AKM_802_1X_PQC):
    """Build an AKM Suite Selector element"""
    return struct.pack("BBB", WLAN_EID_EXTENSION, 1 + len(akm),
                       WLAN_EID_EXT_AKM_SUITE_SELECTOR) + akm

def pqc_parameters_elem(sec_prof, content_present, payload=b'', datalen=None):
    """Build a PQC Parameters element carried in an Extended Length Element"""
    data = struct.pack("BB", sec_prof, content_present) + payload
    if datalen is None:
        datalen = len(data)
    return struct.pack("<BHH", WLAN_EID_EXT_LEN_ELEM,
                       WLAN_EID_EXT_LEN_PQC_PARAMETERS, datalen) + data

def enc_assoc_auth_body(pqc_elem):
    """Build the body of the first IEEE 802.1X Authentication frame

    The AP only processes the PQC Parameters element when the STA indicates
    support for (Re)Association frame encryption and includes an RSNE and a
    Nonce element.
    """
    return eapol_start_encap() + \
        rsnxe_elem([WLAN_RSNX_CAPAB_ASSOC_FRAME_ENCRYPTION,
                    WLAN_RSNX_CAPAB_802_1X_IN_AUTH_FRAMES,
                    WLAN_RSNX_CAPAB_PMKSA_CACHING_PRIVACY]) + \
        rsne_elem() + nonce_elem() + pqc_elem

def auth_resp_status(hapd, timeout=5):
    """Get the status code of the Authentication frame sent by the AP

    Returns None if the AP did not respond.
    """
    ev = hapd.wait_event(["MGMT-TX-STATUS"], timeout=timeout)
    if ev is None:
        return None
    buf = binascii.unhexlify(ev.split("buf=")[1].split(' ')[0])
    if len(buf) < 30:
        raise Exception("Too short Authentication frame from the AP")
    alg, transaction, status = struct.unpack("<HHH", buf[24:30])
    if alg != WLAN_AUTH_802_1X:
        raise Exception("Unexpected authentication algorithm %d" % alg)
    return status

def test_ieee8021x_auth_pqc_invalid_parameters(dev, apdev):
    """IEEE 802.1X over Authentication frames with an invalid PQC Parameters element"""
    check_pqc_capab(dev[0])

    ssid = "test-8021x-pqc-invalid"
    # Advertise a profile without an ECP group (16) and one with an ECP group
    # (18) so that both Content Present variants can be exercised.
    profiles = "%d %d" % (SECURITY_PROFILE_8021X_PQC_0,
                          SECURITY_PROFILE_8021X_PQC_2)
    hapd = hostapd.add_ap(apdev[0], pqc_ap_params(ssid, profiles=profiles))

    # The ECDH public key is the x coordinate of the point, i.e., the prime
    # length of ECP group 20 (P-384) used by security profile 18.
    p384_x = 48 * b'\xff'

    tests = [("Security profile number above the maximum",
              pqc_parameters_elem(SECURITY_PROFILE_MAX + 1, 1),
              WLAN_STATUS_REJECTED_INVALID_SECURITY_PROFILE),
             ("Security profile not advertised by the AP",
              pqc_parameters_elem(SECURITY_PROFILE_8021X_PQC_1, 3),
              WLAN_STATUS_REJECTED_INVALID_SECURITY_PROFILE),
             ("Security profile without a PQC constraint",
              pqc_parameters_elem(3, 1),
              WLAN_STATUS_REJECTED_INVALID_SECURITY_PROFILE),
             ("Invalid Content Present value",
              pqc_parameters_elem(SECURITY_PROFILE_8021X_PQC_0, 7),
              WLAN_STATUS_UNSPECIFIED_FAILURE),
             ("Missing ECDH public key for a profile with an ECP group",
              pqc_parameters_elem(SECURITY_PROFILE_8021X_PQC_2, 1,
                                  32 * b'\x00'),
              WLAN_STATUS_UNSPECIFIED_FAILURE),
             ("Unexpected ECDH public key for a profile without an ECP group",
              pqc_parameters_elem(SECURITY_PROFILE_8021X_PQC_0, 3, p384_x),
              WLAN_STATUS_UNSPECIFIED_FAILURE),
             ("Truncated ECDH public key",
              pqc_parameters_elem(SECURITY_PROFILE_8021X_PQC_2, 3,
                                  8 * b'\x00'),
              WLAN_STATUS_INVALID_PUBLIC_KEY),
             ("Invalid ECDH public key",
              pqc_parameters_elem(SECURITY_PROFILE_8021X_PQC_2, 3,
                                  p384_x + 32 * b'\x00'),
              WLAN_STATUS_INVALID_PUBLIC_KEY),
             ("Invalid ML-KEM encapsulation key",
              pqc_parameters_elem(SECURITY_PROFILE_8021X_PQC_0, 1,
                                  32 * b'\x00'),
              WLAN_STATUS_INVALID_ML_KEM_PARAMETER)]

    hapd.set("ext_mgmt_frame_handling", "1")
    for i, (note, elem, expected) in enumerate(tests):
        logger.info(note)
        # Use a separate address for each case so that the AP always starts
        # from a new STA entry.
        addr = "02:03:04:05:06:%02x" % i
        hapd.dump_monitor()
        mgmt_rx_process(hapd,
                        build_802_1x_auth_frame(hapd, addr,
                                                body=enc_assoc_auth_body(elem)))
        status = auth_resp_status(hapd)
        if status != expected:
            raise Exception("Unexpected status code %s (expected %d) for: %s" %
                            (str(status), expected, note))

    if "PONG" not in hapd.request("PING"):
        raise Exception("hostapd did not survive the Authentication frames")

    hapd.set("ext_mgmt_frame_handling", "0")
    pqc_connect(dev[0], ssid)

def test_ieee8021x_auth_pqc_ext_len_elem_parsing(dev, apdev):
    """IEEE 802.1X over Authentication frames with a malformed Extended Length Element"""
    check_pqc_capab(dev[0])

    ssid = "test-8021x-pqc-ele"
    profiles = "%d %d" % (SECURITY_PROFILE_8021X_PQC_0,
                          SECURITY_PROFILE_8021X_PQC_2)
    hapd = hostapd.add_ap(apdev[0], pqc_ap_params(ssid, profiles=profiles))

    # A PQC Parameters element without any Content Present information
    valid = pqc_parameters_elem(SECURITY_PROFILE_8021X_PQC_0, 0)

    tests = [("Truncated Extended Length Element header",
              struct.pack("<BH", WLAN_EID_EXT_LEN_ELEM,
                          WLAN_EID_EXT_LEN_PQC_PARAMETERS), False),
             ("Length field beyond the end of the frame",
              pqc_parameters_elem(SECURITY_PROFILE_8021X_PQC_0, 0,
                                  datalen=1000), False),
             ("Zero length PQC Parameters element",
              pqc_parameters_elem(SECURITY_PROFILE_8021X_PQC_0, 0)[:5], False),
             ("PQC Parameters element without the Content Present field",
              struct.pack("<BHH", WLAN_EID_EXT_LEN_ELEM,
                          WLAN_EID_EXT_LEN_PQC_PARAMETERS, 1) + b'\x10',
              False),
             ("Unknown Extended Length Element ID",
              struct.pack("<BHH", WLAN_EID_EXT_LEN_ELEM, 0xffff, 2) +
              b'\x10\x00', False),
             # An unknown Extended Length Element is skipped based on its
             # Length field, so the elements that follow it are still parsed.
             ("Unknown Extended Length Element ID before a valid element",
              struct.pack("<BHH", WLAN_EID_EXT_LEN_ELEM, 0xffff, 0) + valid,
              True)]

    hapd.set("ext_mgmt_frame_handling", "1")
    for i, (note, elem, accept) in enumerate(tests):
        logger.info(note)
        addr = "02:03:04:05:07:%02x" % i
        hapd.dump_monitor()
        mgmt_rx_process(hapd,
                        build_802_1x_auth_frame(hapd, addr,
                                                body=enc_assoc_auth_body(elem)))
        status = auth_resp_status(hapd, timeout=1)
        if accept:
            if status != 0:
                raise Exception("AP rejected the frame (status %s) for: %s" %
                                (str(status), note))
        elif status == 0:
            # The AP may either drop the frame or reject it, but it must not
            # accept it.
            raise Exception("AP accepted the frame for: " + note)
        if "PONG" not in hapd.request("PING"):
            raise Exception("hostapd did not survive: " + note)

    hapd.set("ext_mgmt_frame_handling", "0")
    pqc_connect(dev[0], ssid)
