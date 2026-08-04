# EAP-TLS tests with post-quantum cryptography (ML-DSA certificates)
# Copyright (c) 2026, Intel Corporation
#
# This software may be distributed under the terms of the BSD license.
# See README for more details.

import logging
logger = logging.getLogger()
import re

import hostapd
from utils import HwsimSkip
from test_ap_eap import check_tls13_support, eap_connect

def check_mldsa_support(dev):
    """Check that the TLS library can handle ML-DSA keys and certificates"""
    check_tls13_support(dev)
    tls = dev.request("GET tls_library")
    match = re.search(r"run=OpenSSL (\d+)\.(\d+)", tls)
    if not match:
        raise HwsimSkip("ML-DSA not supported with this TLS library: " + tls)
    if (int(match.group(1)), int(match.group(2))) < (3, 5):
        raise HwsimSkip("ML-DSA not supported with this TLS library: " + tls)

def mldsa_ap_params():
    """Return hostapd parameters for an AP using an ML-DSA server certificate"""
    return {"ssid": "test-wpa2-eap",
            "wpa": "2",
            "wpa_key_mgmt": "WPA-EAP",
            "rsn_pairwise": "CCMP",
            "ieee8021x": "1",
            "eap_server": "1",
            "eap_user_file": "auth_serv/eap_user.conf",
            "ca_cert": "auth_serv/mldsa-ca.pem",
            "server_cert": "auth_serv/mldsa-server.pem",
            "private_key": "auth_serv/mldsa-server.key",
            "tls_flags": "[ENABLE-TLSv1.3]"}

def mldsa_connect(dev, hapd, **kwargs):
    """Run EAP-TLS with an ML-DSA client certificate and verify TLS v1.3 is used"""
    eap_connect(dev, hapd, "TLS", "tls user",
                ca_cert="auth_serv/mldsa-ca.pem",
                client_cert="auth_serv/mldsa-user.pem",
                private_key="auth_serv/mldsa-user.key",
                phase1="tls_disable_tlsv1_3=0", **kwargs)
    ver = dev.get_status_field("eap_tls_version")
    if ver != "TLSv1.3":
        raise Exception("Unexpected TLS version: " + str(ver))

def test_eap_pqc_mldsa(dev, apdev):
    """EAP-TLS with ML-DSA certificates"""
    params = mldsa_ap_params()
    hapd = hostapd.add_ap(apdev[0], params)
    check_mldsa_support(hapd)
    check_mldsa_support(dev[0])
    mldsa_connect(dev[0], hapd)

def test_eap_pqc_mldsa_hybrid_kex(dev, apdev):
    """EAP-TLS with ML-DSA certificates and hybrid ML-KEM key exchange"""
    params = mldsa_ap_params()
    params["openssl_ecdh_curves"] = "X25519MLKEM768"
    hapd = hostapd.add_ap(apdev[0], params)
    check_mldsa_support(hapd)
    check_mldsa_support(dev[0])
    mldsa_connect(dev[0], hapd, openssl_ecdh_curves="X25519MLKEM768")

def test_eap_pqc_mldsa_sigalgs(dev, apdev):
    """EAP-TLS with ML-DSA certificates and explicit signature algorithms"""
    params = mldsa_ap_params()
    params["openssl_sigalgs"] = "mldsa87"
    hapd = hostapd.add_ap(apdev[0], params)
    check_mldsa_support(hapd)
    check_mldsa_support(dev[0])
    mldsa_connect(dev[0], hapd, openssl_sigalgs="mldsa87")

def test_eap_pqc_mldsa_sigalgs_mismatch(dev, apdev):
    """EAP-TLS with incompatible signature algorithm configuration"""
    params = mldsa_ap_params()
    params["openssl_sigalgs"] = "mldsa87"
    hapd = hostapd.add_ap(apdev[0], params)
    check_mldsa_support(hapd)
    check_mldsa_support(dev[0])

    dev[0].connect("test-wpa2-eap", key_mgmt="WPA-EAP", eap="TLS",
                   identity="tls user",
                   ca_cert="auth_serv/mldsa-ca.pem",
                   client_cert="auth_serv/mldsa-user.pem",
                   private_key="auth_serv/mldsa-user.key",
                   openssl_sigalgs="ecdsa_secp384r1_sha384",
                   phase1="tls_disable_tlsv1_3=0",
                   scan_freq="2412", wait_connect=False)
    ev = dev[0].wait_event(["CTRL-EVENT-EAP-FAILURE", "CTRL-EVENT-CONNECTED"],
                           timeout=15)
    if ev is None:
        raise Exception("No EAP result reported")
    if "CTRL-EVENT-CONNECTED" in ev:
        raise Exception("Unexpected connection with incompatible signature algorithms")
    logger.info("EAP authentication failed as expected: " + ev)

def test_eap_pqc_mldsa_fragmentation(dev, apdev):
    """EAP-TLS with ML-DSA certificates and small EAP fragments"""
    params = mldsa_ap_params()
    params["fragment_size"] = "500"
    hapd = hostapd.add_ap(apdev[0], params)
    check_mldsa_support(hapd)
    check_mldsa_support(dev[0])
    mldsa_connect(dev[0], hapd, fragment_size="500")
