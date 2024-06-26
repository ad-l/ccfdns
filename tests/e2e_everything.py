# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

import glob
import http
import logging
import time
import os
import requests
import json

import infra.e2e_args
import infra.network
import infra.node
import infra.checker
import infra.health_watcher
import infra.interfaces
from infra.interfaces import PRIMARY_RPC_INTERFACE

from loguru import logger as LOG

import dns.rdatatype as rdt
import dns.rdataclass as rdc
import dns.rdtypes.ANY.SOA as SOA

import adns_service
from adns_service import aDNSConfig, ServiceCAConfig
import ccf_demo_service
import pebble
from adns_tools import (
    cert_to_pem,
    write_ca_bundle,
    poll_for_receipt,
    NoReceiptException,
)


def register_service(
    service_info, cabundle, registration_info, client_cert=None, num_retries=10
):
    """Register the service"""

    reg_url = service_info["adns_base_url"] + "/app/register-service"

    while num_retries > 0:
        try:
            r = requests.post(
                reg_url,
                json.dumps(
                    {
                        "contact": service_info["contact"],
                        "csr": registration_info["csr"],
                        "node_information": registration_info["node_information"],
                        "configuration_receipt": str(
                            registration_info["configuration_receipt"]
                        ),
                    }
                ),
                headers={"Content-Type": "application/json"},
                timeout=120,
                verify=cabundle,
                cert=client_cert,
            )
            ok = (
                r.status_code == http.HTTPStatus.OK
                or r.status_code == http.HTTPStatus.NO_CONTENT
            )
            if not ok:
                LOG.info(r)
                LOG.info(r.text)
            assert ok
            assert "x-ms-ccf-transaction-id" in r.headers
            return poll_for_receipt(
                service_info["adns_base_url"],
                cabundle,
                r.headers["x-ms-ccf-transaction-id"],
            )
        except Exception as ex:
            logging.exception("caught exception")
            num_retries = num_retries - 1
            if num_retries == 0:
                raise ex
            else:
                n = 10
                LOG.error(f"Registration failed; retrying in {n} seconds.")
                time.sleep(n)
    return None


def register_delegation(
    parent_base_url,
    parent_member_cert,
    ca_certs,
    sub_adns_network,
    delegation_info,
    registration_info,
    num_retries=10,
):
    """Register delegation of a subdomain"""

    cabundle = write_ca_bundle(ca_certs)

    reg_url = parent_base_url + "/app/register-delegation"

    while num_retries > 0:
        try:
            r = requests.post(
                reg_url,
                json.dumps(
                    {
                        "subdomain": delegation_info["subdomain"],
                        "contact": delegation_info["contact"],
                        #
                        "csr": registration_info["csr"],
                        "dnskey_records": registration_info["dnskey_records"],
                        "node_information": registration_info["node_information"],
                        "configuration_receipt": str(
                            registration_info["configuration_receipt"]
                        ),
                    }
                ),
                headers={"Content-Type": "application/json"},
                timeout=60,
                verify=cabundle,
                cert=parent_member_cert,
            )
            assert (
                r.status_code == http.HTTPStatus.OK
                or r.status_code == http.HTTPStatus.NO_CONTENT
            )
            assert "x-ms-ccf-transaction-id" in r.headers
            receipt = poll_for_receipt(
                parent_base_url, cabundle, r.headers["x-ms-ccf-transaction-id"]
            )

            sub_primary, _ = sub_adns_network.find_primary()
            with sub_primary.client("user0") as client:
                client.get("/app/start-delegation-acme-client", {})

            return receipt
        except Exception as ex:
            logging.exception("caught exception")
            num_retries = num_retries - 1
            if num_retries == 0:
                raise ex
            else:
                n = 10
                LOG.error(f"Registration failed; retrying in {n} seconds.")
                time.sleep(n)
    return None


def run_server(args, wait_for_endorsed_cert=False):
    """Run an aDNS server (network)"""
    adns_endorsed_certs = None

    adns_nw, procs, adns_endorsed_certs, reginfo = adns_service.run(
        args,
        wait_for_endorsed_cert,
        with_proxies=False,
        tcp_port=53,
        udp_port=53,
    )

    if not adns_nw:
        raise Exception("Failed to start aDNS network")

    return adns_nw, procs, adns_endorsed_certs, reginfo


def start_and_register_service(service_args, certificates, member_cert):
    """Start, configure, and register service"""

    service_nw = ccf_demo_service.run(service_args)

    if not service_nw:
        raise Exception("Failed to start service network")

    node_addr = adns_service.assign_node_addresses(
        service_nw, service_args.node_addresses, False
    )

    service_cfg = {
        "service_name": service_args.service_name,
        "contact": ["mailto:" + service_args.email],
        "adns_base_url": service_args.adns_base_url,
        "ca_certs": certificates,
        "node_addresses": node_addr,
    }

    cabundle = write_ca_bundle(certificates)

    registered = False
    while not registered:
        try:
            pif0 = service_nw.nodes[0].host.rpc_interfaces[PRIMARY_RPC_INTERFACE]
            base_url = "https://" + pif0.host + ":" + str(pif0.port)

            reginfo = ccf_demo_service.configure(
                base_url, service_nw.cert_path, service_cfg
            )

            registration_receipt = register_service(
                service_cfg, cabundle, reginfo, member_cert
            )
            registered = True
        except Exception as ex:
            if hasattr(ex, "message"):
                LOG.info(f"Exception: {ex.message}")
            else:
                LOG.info(f"Exception: {ex}")
            logging.exception("caught exception")

    os.unlink(cabundle)

    assert registration_receipt is not None

    return registration_receipt


def run(pebble_args, adns_args, service_args, sub_adns_args, sub_service_args):
    """Run everything"""

    adns_nw = service_nw = sub_adns_nw = None
    procs = []

    try:
        if pebble_args:
            pebble_proc, _, _ = pebble.run_pebble(pebble_args)
            procs += [pebble_proc]
            while not os.path.exists(pebble_args.ca_cert_filename):
                time.sleep(0.25)
            ca_certs = pebble.ca_certs(pebble_args.mgmt_address)
            ca_certs += pebble.ca_certs_from_file(pebble_args.ca_cert_filename)
            adns_args.adns.service_ca.certificates += ca_certs
            sub_adns_args.adns.service_ca.certificates += ca_certs
        else:
            ca_certs = adns_args.adns.service_ca.certificates

        # Start top-level aDNS
        adns_nw, adns_procs, adns_certs, _ = run_server(
            adns_args, wait_for_endorsed_cert=True
        )
        procs += adns_procs

        member_cert = (
            os.path.join(adns_nw.common_dir, "member0_cert.pem"),
            os.path.join(adns_nw.common_dir, "member0_privk.pem"),
        )

        start_and_register_service(service_args, adns_certs + ca_certs, member_cert)

        # Start a sub-domain aDNS
        sub_adns_nw, sub_procs, _, sub_adns_reginfo = run_server(
            sub_adns_args, wait_for_endorsed_cert=False
        )
        procs += sub_procs

        # Register the delegation
        delegation_info = {
            "subdomain": sub_adns_args.adns.origin,
            "contact": ["mailto:" + email for email in sub_adns_args.adns.contact],
        }

        receipt = register_delegation(
            sub_adns_args.adns.parent_base_url,
            member_cert,
            adns_certs + ca_certs,
            sub_adns_nw,
            delegation_info,
            sub_adns_reginfo,
        )

        # TODO: receipt as a DNS record, AAAA fragmented

        sub_endorsed_certs = adns_service.wait_for_endorsed_certs(
            sub_adns_nw, delegation_info["subdomain"], num_retries=10000
        )

        sub_member_cert = (
            os.path.join(sub_adns_nw.common_dir, "member0_cert.pem"),
            os.path.join(sub_adns_nw.common_dir, "member0_privk.pem"),
        )

        start_and_register_service(
            sub_service_args, sub_endorsed_certs + ca_certs, sub_member_cert
        )

        LOG.info("Waiting forever...")
        while True:
            pass

    except Exception as ex:
        if hasattr(ex, "message"):
            LOG.info(f"Exception: {ex.message}")
        else:
            LOG.info(f"Exception: {ex}")
        logging.exception("caught exception")
    finally:
        if service_nw:
            service_nw.stop_all_nodes()
        if adns_nw:
            adns_nw.stop_all_nodes()
        if procs:
            for p in procs:
                if p:
                    p.kill()


def main():
    """Entry point"""

    def cliparser(parser):
        """CLI option parser"""
        parser.description = "Run a CCF-based demo service"

    # CA for service certificates
    if False:
        pebble_args = None
        service_ca_config = ServiceCAConfig(
            name="letsencrypt.org",
            directory="https://acme-staging-v02.api.letsencrypt.org/directory",
            certificates=[
                "-----BEGIN CERTIFICATE-----\nMIIFFjCCAv6gAwIBAgIRAJErCErPDBinU/bWLiWnX1owDQYJKoZIhvcNAQELBQAw\nTzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh\ncmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMjAwOTA0MDAwMDAw\nWhcNMjUwOTE1MTYwMDAwWjAyMQswCQYDVQQGEwJVUzEWMBQGA1UEChMNTGV0J3Mg\nRW5jcnlwdDELMAkGA1UEAxMCUjMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\nAoIBAQC7AhUozPaglNMPEuyNVZLD+ILxmaZ6QoinXSaqtSu5xUyxr45r+XXIo9cP\nR5QUVTVXjJ6oojkZ9YI8QqlObvU7wy7bjcCwXPNZOOftz2nwWgsbvsCUJCWH+jdx\nsxPnHKzhm+/b5DtFUkWWqcFTzjTIUu61ru2P3mBw4qVUq7ZtDpelQDRrK9O8Zutm\nNHz6a4uPVymZ+DAXXbpyb/uBxa3Shlg9F8fnCbvxK/eG3MHacV3URuPMrSXBiLxg\nZ3Vms/EY96Jc5lP/Ooi2R6X/ExjqmAl3P51T+c8B5fWmcBcUr2Ok/5mzk53cU6cG\n/kiFHaFpriV1uxPMUgP17VGhi9sVAgMBAAGjggEIMIIBBDAOBgNVHQ8BAf8EBAMC\nAYYwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMBIGA1UdEwEB/wQIMAYB\nAf8CAQAwHQYDVR0OBBYEFBQusxe3WFbLrlAJQOYfr52LFMLGMB8GA1UdIwQYMBaA\nFHm0WeZ7tuXkAXOACIjIGlj26ZtuMDIGCCsGAQUFBwEBBCYwJDAiBggrBgEFBQcw\nAoYWaHR0cDovL3gxLmkubGVuY3Iub3JnLzAnBgNVHR8EIDAeMBygGqAYhhZodHRw\nOi8veDEuYy5sZW5jci5vcmcvMCIGA1UdIAQbMBkwCAYGZ4EMAQIBMA0GCysGAQQB\ngt8TAQEBMA0GCSqGSIb3DQEBCwUAA4ICAQCFyk5HPqP3hUSFvNVneLKYY611TR6W\nPTNlclQtgaDqw+34IL9fzLdwALduO/ZelN7kIJ+m74uyA+eitRY8kc607TkC53wl\nikfmZW4/RvTZ8M6UK+5UzhK8jCdLuMGYL6KvzXGRSgi3yLgjewQtCPkIVz6D2QQz\nCkcheAmCJ8MqyJu5zlzyZMjAvnnAT45tRAxekrsu94sQ4egdRCnbWSDtY7kh+BIm\nlJNXoB1lBMEKIq4QDUOXoRgffuDghje1WrG9ML+Hbisq/yFOGwXD9RiX8F6sw6W4\navAuvDszue5L3sz85K+EC4Y/wFVDNvZo4TYXao6Z0f+lQKc0t8DQYzk1OXVu8rp2\nyJMC6alLbBfODALZvYH7n7do1AZls4I9d1P4jnkDrQoxB3UqQ9hVl3LEKQ73xF1O\nyK5GhDDX8oVfGKF5u+decIsH4YaTw7mP3GFxJSqv3+0lUFJoi5Lc5da149p90Ids\nhCExroL1+7mryIkXPeFM5TgO9r0rvZaBFOvV2z0gp35Z0+L4WPlbuEjN/lxPFin+\nHlUjr8gRsI3qfJOQFy/9rKIJR0Y/8Omwt/8oTWgy1mdeHmmjk7j1nYsvC9JSQ6Zv\nMldlTTKB3zhThV1+XWYp6rjd5JW1zbVWEkLNxE7GJThEUG3szgBVGP7pSWTUTsqX\nnLRbwHOoq7hHwg==\n-----END CERTIFICATE-----\n",
                "-----BEGIN CERTIFICATE-----\nMIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw\nTzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh\ncmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4\nWhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu\nZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY\nMTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc\nh77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+\n0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U\nA5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW\nT8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH\nB5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC\nB5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv\nKBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn\nOlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn\njh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw\nqHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI\nrU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV\nHRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq\nhkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL\nubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ\n3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK\nNFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5\nORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur\nTkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC\njNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc\noyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq\n4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA\nmRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d\nemyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=\n-----END CERTIFICATE-----\n",
                "-----BEGIN CERTIFICATE-----\nMIIDCzCCApGgAwIBAgIRALRY4992FVxZJKOJ3bpffWIwCgYIKoZIzj0EAwMwaDEL\nMAkGA1UEBhMCVVMxMzAxBgNVBAoTKihTVEFHSU5HKSBJbnRlcm5ldCBTZWN1cml0\neSBSZXNlYXJjaCBHcm91cDEkMCIGA1UEAxMbKFNUQUdJTkcpIEJvZ3VzIEJyb2Nj\nb2xpIFgyMB4XDTIwMDkwNDAwMDAwMFoXDTI1MDkxNTE2MDAwMFowVTELMAkGA1UE\nBhMCVVMxIDAeBgNVBAoTFyhTVEFHSU5HKSBMZXQncyBFbmNyeXB0MSQwIgYDVQQD\nExsoU1RBR0lORykgRXJzYXR6IEVkYW1hbWUgRTEwdjAQBgcqhkjOPQIBBgUrgQQA\nIgNiAAT9v/PJUtHOTk28nXCXrpP665vI4Z094h8o7R+5E6yNajZa0UubqjpZFoGq\nu785/vGXj6mdfIzc9boITGusZCSWeMj5ySMZGZkS+VSvf8VQqj+3YdEu4PLZEjBA\nivRFpEejggEQMIIBDDAOBgNVHQ8BAf8EBAMCAYYwHQYDVR0lBBYwFAYIKwYBBQUH\nAwIGCCsGAQUFBwMBMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYEFOv5JcKA\nKGbibQiSMvPC4a3D/zVFMB8GA1UdIwQYMBaAFN7Ro1lkDsGaNqNG7rAQdu+ul5Vm\nMDYGCCsGAQUFBwEBBCowKDAmBggrBgEFBQcwAoYaaHR0cDovL3N0Zy14Mi5pLmxl\nbmNyLm9yZy8wKwYDVR0fBCQwIjAgoB6gHIYaaHR0cDovL3N0Zy14Mi5jLmxlbmNy\nLm9yZy8wIgYDVR0gBBswGTAIBgZngQwBAgEwDQYLKwYBBAGC3xMBAQEwCgYIKoZI\nzj0EAwMDaAAwZQIwXcZbdgxcGH9rTErfSTkXfBKKygU0yO7OpbuNeY1id0FZ/hRY\nN5fdLOGuc+aHfCsMAjEA0P/xwKr6NQ9MN7vrfGAzO397PApdqfM7VdFK18aEu1xm\n3HMFKzIR8eEPsMx4smMl\n-----END CERTIFICATE-----\n",
                "-----BEGIN CERTIFICATE-----\nMIICTjCCAdSgAwIBAgIRAIPgc3k5LlLVLtUUvs4K/QcwCgYIKoZIzj0EAwMwaDEL\nMAkGA1UEBhMCVVMxMzAxBgNVBAoTKihTVEFHSU5HKSBJbnRlcm5ldCBTZWN1cml0\neSBSZXNlYXJjaCBHcm91cDEkMCIGA1UEAxMbKFNUQUdJTkcpIEJvZ3VzIEJyb2Nj\nb2xpIFgyMB4XDTIwMDkwNDAwMDAwMFoXDTQwMDkxNzE2MDAwMFowaDELMAkGA1UE\nBhMCVVMxMzAxBgNVBAoTKihTVEFHSU5HKSBJbnRlcm5ldCBTZWN1cml0eSBSZXNl\nYXJjaCBHcm91cDEkMCIGA1UEAxMbKFNUQUdJTkcpIEJvZ3VzIEJyb2Njb2xpIFgy\nMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEOvS+w1kCzAxYOJbA06Aw0HFP2tLBLKPo\nFQqR9AMskl1nC2975eQqycR+ACvYelA8rfwFXObMHYXJ23XLB+dAjPJVOJ2OcsjT\nVqO4dcDWu+rQ2VILdnJRYypnV1MMThVxo0IwQDAOBgNVHQ8BAf8EBAMCAQYwDwYD\nVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQU3tGjWWQOwZo2o0busBB2766XlWYwCgYI\nKoZIzj0EAwMDaAAwZQIwRcp4ZKBsq9XkUuN8wfX+GEbY1N5nmCRc8e80kUkuAefo\nuc2j3cICeXo1cOybQ1iWAjEA3Ooawl8eQyR4wrjCofUE8h44p0j7Yl/kBlJZT8+9\nvbtH7QiVzeKCOTQPINyRql6P\n-----END CERTIFICATE-----\n",
                "-----BEGIN CERTIFICATE-----\nMIIFmDCCA4CgAwIBAgIQU9C87nMpOIFKYpfvOHFHFDANBgkqhkiG9w0BAQsFADBm\nMQswCQYDVQQGEwJVUzEzMDEGA1UEChMqKFNUQUdJTkcpIEludGVybmV0IFNlY3Vy\naXR5IFJlc2VhcmNoIEdyb3VwMSIwIAYDVQQDExkoU1RBR0lORykgUHJldGVuZCBQ\nZWFyIFgxMB4XDTE1MDYwNDExMDQzOFoXDTM1MDYwNDExMDQzOFowZjELMAkGA1UE\nBhMCVVMxMzAxBgNVBAoTKihTVEFHSU5HKSBJbnRlcm5ldCBTZWN1cml0eSBSZXNl\nYXJjaCBHcm91cDEiMCAGA1UEAxMZKFNUQUdJTkcpIFByZXRlbmQgUGVhciBYMTCC\nAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBALbagEdDTa1QgGBWSYkyMhsc\nZXENOBaVRTMX1hceJENgsL0Ma49D3MilI4KS38mtkmdF6cPWnL++fgehT0FbRHZg\njOEr8UAN4jH6omjrbTD++VZneTsMVaGamQmDdFl5g1gYaigkkmx8OiCO68a4QXg4\nwSyn6iDipKP8utsE+x1E28SA75HOYqpdrk4HGxuULvlr03wZGTIf/oRt2/c+dYmD\noaJhge+GOrLAEQByO7+8+vzOwpNAPEx6LW+crEEZ7eBXih6VP19sTGy3yfqK5tPt\nTdXXCOQMKAp+gCj/VByhmIr+0iNDC540gtvV303WpcbwnkkLYC0Ft2cYUyHtkstO\nfRcRO+K2cZozoSwVPyB8/J9RpcRK3jgnX9lujfwA/pAbP0J2UPQFxmWFRQnFjaq6\nrkqbNEBgLy+kFL1NEsRbvFbKrRi5bYy2lNms2NJPZvdNQbT/2dBZKmJqxHkxCuOQ\nFjhJQNeO+Njm1Z1iATS/3rts2yZlqXKsxQUzN6vNbD8KnXRMEeOXUYvbV4lqfCf8\nmS14WEbSiMy87GB5S9ucSV1XUrlTG5UGcMSZOBcEUpisRPEmQWUOTWIoDQ5FOia/\nGI+Ki523r2ruEmbmG37EBSBXdxIdndqrjy+QVAmCebyDx9eVEGOIpn26bW5LKeru\nmJxa/CFBaKi4bRvmdJRLAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNVHRMB\nAf8EBTADAQH/MB0GA1UdDgQWBBS182Xy/rAKkh/7PH3zRKCsYyXDFDANBgkqhkiG\n9w0BAQsFAAOCAgEAncDZNytDbrrVe68UT6py1lfF2h6Tm2p8ro42i87WWyP2LK8Y\nnLHC0hvNfWeWmjZQYBQfGC5c7aQRezak+tHLdmrNKHkn5kn+9E9LCjCaEsyIIn2j\nqdHlAkepu/C3KnNtVx5tW07e5bvIjJScwkCDbP3akWQixPpRFAsnP+ULx7k0aO1x\nqAeaAhQ2rgo1F58hcflgqKTXnpPM02intVfiVVkX5GXpJjK5EoQtLceyGOrkxlM/\nsTPq4UrnypmsqSagWV3HcUlYtDinc+nukFk6eR4XkzXBbwKajl0YjztfrCIHOn5Q\nCJL6TERVDbM/aAPly8kJ1sWGLuvvWYzMYgLzDul//rUF10gEMWaXVZV51KpS9DY/\n5CunuvCXmEQJHo7kGcViT7sETn6Jz9KOhvYcXkJ7po6d93A/jy4GKPIPnsKKNEmR\nxUuXY4xRdh45tMJnLTUDdC9FIU0flTeO9/vNpVA8OPU1i14vCz+MU8KX1bV3GXm/\nfxlB7VBBjX9v5oUep0o/j68R/iDlCOM4VVfRa8gX6T2FU7fNdatvGro7uQzIvWof\ngN9WUwCbEMBy/YhBSrXycKA8crgGg3x1mIsopn88JKwmMBa68oS7EHM9w7C4y71M\n7DiA+/9Qdp9RBWJpTS9i/mDnJg1xvo8Xz49mrrgfmcAXTCJqXi24NatI3Oc=\n-----END CERTIFICATE-----\n",
            ],
        )
    else:
        pebble_args = pebble.Arguments(
            # dns_address="10.1.0.4:53",
            wait_forever=False,
            http_port=8080,
            ca_cert_filename="pebble-tls-cert.pem",
            config_filename="pebble.config.json",
            listen_address="0.0.0.0:1024",
            mgmt_address="0.0.0.0:1025",
        )
        service_ca_config = ServiceCAConfig(
            name="pebble",
            directory="https://127.0.0.1:1024/dir",
            certificates=[]
        )

    # First, an aDNS server for adns.ccf.dev.

    adns_args = infra.e2e_args.cli_args(cliparser)
    adns_args.node_addresses = [
        (
            "local://10.1.0.4:1443",  # primary/internal
            "local://10.1.0.4:8443",  # external/endorsed
            "ns1.adns.ccf.dev",  # public name
            "51.143.161.224",  # public IP
        ),
        (
            "local://10.1.0.5:1443",
            "local://10.1.0.5:8443",
            "ns2.adns.ccf.dev",
            "20.108.155.64",
        ),
        (
            "local://10.1.0.6:1443",
            "local://10.1.0.6:8443",
            "ns3.adns.ccf.dev",
            "20.0.255.182",
        ),
    ]
    adns_args.constitution = glob.glob("../tests/constitution/*")
    adns_args.package = "libccfdns"
    adns_args.label = "demo_adns"
    adns_args.acme_config_name = "custom"
    adns_args.wait_forever = False
    adns_args.http2 = False
    adns_args.initial_node_cert_validity_days = 365
    adns_args.initial_service_cert_validity_days = 365
    adns_args.message_timeout_ms = 2000
    adns_args.election_timeout_ms = 50000

    adns_args.adns = aDNSConfig(
        origin="adns.ccf.dev.",
        service_name="adns.ccf.dev.",
        node_addresses={},
        soa=str(
            SOA.SOA(
                rdc.IN,
                rdt.SOA,
                mname="ns1.adns.ccf.dev.",
                rname="some-dev.adns.ccf.dev.",
                serial=8,
                refresh=604800,
                retry=21600,
                expire=2419200,
                minimum=0,
            )
        ),
        default_ttl=3600,
        signing_algorithm="ECDSAP384SHA384",
        digest_type="SHA384",
        use_key_signing_key=True,
        use_nsec3=True,
        nsec3_hash_algorithm="SHA1",
        nsec3_hash_iterations=0,
        nsec3_salt_length=8,
        parent_base_url=None,
        contact=["cwinter@microsoft.com"],
        service_ca=service_ca_config,
    )

    # A service that registers for adns.ccf.dev.

    service_args = infra.e2e_args.cli_args(cliparser)
    service_args.service_name = "service43." + adns_args.adns.origin.rstrip(".")
    service_args.node_addresses = [
        (
            "local://10.1.0.4:3443",
            "local://10.1.0.4:9443",
            "node1." + service_args.service_name,
            "51.143.161.224",
        ),
        (
            "local://10.1.0.5:3443",
            "local://10.1.0.5:9443",
            "node2." + service_args.service_name,
            "20.108.155.64",
        ),
        (
            "local://10.1.0.6:3443",
            "local://10.1.0.6:9443",
            "node3." + service_args.service_name,
            "20.0.255.182",
        ),
    ]
    service_args.constitution = glob.glob("../tests/constitution/*")
    service_args.package = "libccf_demo_service"
    service_args.label = "demo_service"
    service_args.email = "cwinter@microsoft.com"
    service_args.acme_config_name = "custom"
    service_args.wait_forever = False
    service_args.http2 = False
    service_args.adns_base_url = "https://ns1.adns.ccf.dev:8443"
    service_args.ca_certs = service_ca_config.certificates
    service_args.initial_node_cert_validity_days = 365
    service_args.initial_service_cert_validity_days = 365

    # Then, a second aDNS server for sub.adns.ccf.dev.

    sub_adns_args = infra.e2e_args.cli_args(cliparser)
    sub_adns_args.node_addresses = [
        (
            "local://10.1.0.7:1443",
            "local://10.1.0.7:8443",
            "ns4.sub.adns.ccf.dev",
            "20.108.16.154",
        ),
        (
            "local://10.1.0.8:1443",
            "local://10.1.0.8:8443",
            "ns5.sub.adns.ccf.dev",
            "20.108.16.23",
        ),
        (
            "local://10.1.0.9:1443",
            "local://10.1.0.9:8443",
            "ns6.sub.adns.ccf.dev",
            "20.108.18.43",
        ),
    ]
    sub_adns_args.constitution = glob.glob("../tests/constitution/*")
    sub_adns_args.package = "libccfdns"
    sub_adns_args.label = "demo_sub_adns"
    sub_adns_args.acme_config_name = "custom"
    sub_adns_args.wait_forever = False
    sub_adns_args.http2 = False
    sub_adns_args.initial_node_cert_validity_days = 365
    sub_adns_args.initial_service_cert_validity_days = 365
    sub_adns_args.message_timeout_ms = 2000
    sub_adns_args.election_timeout_ms = 50000

    sub_adns_args.adns = aDNSConfig(
        origin="sub.adns.ccf.dev.",
        service_name="sub.adns.ccf.dev.",
        node_addresses=[],
        soa=str(
            SOA.SOA(
                rdc.IN,
                rdt.SOA,
                mname=sub_adns_args.node_addresses[0][2] + ".",
                rname="some-dev.sub.adns.ccf.dev.",
                serial=8,
                refresh=604800,
                retry=21600,
                expire=2419200,
                minimum=0,
            )
        ),
        default_ttl=3600,
        signing_algorithm="ECDSAP384SHA384",
        digest_type="SHA384",
        use_key_signing_key=True,
        use_nsec3=True,
        nsec3_hash_algorithm="SHA1",
        nsec3_hash_iterations=0,
        nsec3_salt_length=8,
        parent_base_url="https://ns1.adns.ccf.dev:8443",
        contact=["cwinter@microsoft.com"],
        service_ca=service_ca_config,
    )

    # A service that registers for sub.adns.ccf.dev.

    sub_service_args = infra.e2e_args.cli_args(cliparser)
    sub_service_args.service_name = "service45." + sub_adns_args.adns.origin.rstrip(".")
    sub_service_args.node_addresses = [
        (
            "local://10.1.0.7:3443",
            "local://10.1.0.7:9443",
            "node1." + sub_service_args.service_name,
            "20.108.16.154",
        ),
        (
            "local://10.1.0.9:3443",
            "local://10.1.0.9:9443",
            "node2." + sub_service_args.service_name,
            "20.108.18.43",
        ),
    ]
    sub_service_args.constitution = glob.glob("../tests/constitution/*")
    sub_service_args.package = "libccf_demo_service"
    sub_service_args.label = "demo_sub_service"
    sub_service_args.acme_config_name = "custom"
    sub_service_args.wait_forever = False
    sub_service_args.email = "cwinter@microsoft.com"
    sub_service_args.http2 = False
    sub_service_args.adns_base_url = "https://ns4.sub.adns.ccf.dev:8443"
    sub_service_args.ca_certs = service_ca_config.certificates
    sub_service_args.initial_node_cert_validity_days = 365
    sub_service_args.initial_service_cert_validity_days = 365

    run(pebble_args, adns_args, service_args, sub_adns_args, sub_service_args)


if __name__ == "__main__":
    main()
