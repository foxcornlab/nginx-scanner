#!/usr/bin/env python3
"""Tests for nginx_scanner.py: version tables, exposure folding,
config parsing, fake-nginx --local runs, and mock-server --url probes.
"""
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import nginx_scanner as ns

ALL_TRUE = ns.Exposure(http2=True, proxy=True, resolver=True,
                        resolver_trigger=True, http3=True, mail=True,
                        tls13=True)


def verdicts(results):
    return {r["cve"]: r["verdict"] for r in results}


class TestVersionParsing(unittest.TestCase):
    def test_plain(self):
        v, distro, _ = ns.parse_version("1.31.8")
        self.assertEqual(v, (1, 31, 8))
        self.assertFalse(distro)

    def test_prefixes(self):
        v, _, _ = ns.parse_version("nginx/1.31.8")
        self.assertEqual(v, (1, 31, 8))
        v, _, _ = ns.parse_version("nginx version: nginx/1.30.7")
        self.assertEqual(v, (1, 30, 7))

    def test_distro_suffix(self):
        v, distro, _ = ns.parse_version("1.18.0-0ubuntu1")
        self.assertEqual(v, (1, 18, 0))
        self.assertTrue(distro)
        v, distro, _ = ns.parse_version("1.22.1-9")
        self.assertEqual(v, (1, 22, 1))
        self.assertTrue(distro)

    def test_unparseable(self):
        v, _, _ = ns.parse_version("banana")
        self.assertIsNone(v)


class TestFixedLogic(unittest.TestCase):
    def test_branch_trap(self):
        # The trap: 1.30.7 is fixed, 1.31.8 is not.
        self.assertTrue(ns.is_fixed_oss((1, 30, 7)))
        self.assertTrue(ns.is_fixed_oss((1, 30, 9)))
        self.assertFalse(ns.is_fixed_oss((1, 30, 6)))
        self.assertFalse(ns.is_fixed_oss((1, 31, 8)))
        self.assertTrue(ns.is_fixed_oss((1, 31, 9)))
        self.assertTrue(ns.is_fixed_oss((1, 32, 0)))
        self.assertFalse(ns.is_fixed_oss((1, 28, 0)))
        self.assertFalse(ns.is_fixed_oss((1, 9, 5)))

    def test_per_cve_first_affected(self):
        # 1.9.4 predates every CVE here; 1.9.5 is the 123007 floor.
        res = verdicts(ns.grade_all(version="1.9.4", exposure=ALL_TRUE))
        self.assertEqual(res["CVE-2026-123007"], "NOT-AFFECTED")
        res = verdicts(ns.grade_all(version="1.9.5", exposure=ALL_TRUE))
        self.assertEqual(res["CVE-2026-123007"], "VULNERABLE")
        self.assertEqual(res["CVE-2026-123633"], "NOT-AFFECTED")
        # 1.19.6: only 123007 (+123634/113425/118899) apply.
        res = verdicts(ns.grade_all(version="1.19.6", exposure=ALL_TRUE))
        self.assertEqual(res["CVE-2026-123633"], "NOT-AFFECTED")
        self.assertEqual(res["CVE-2026-123007"], "VULNERABLE")
        res = verdicts(ns.grade_all(version="1.19.7", exposure=ALL_TRUE))
        self.assertEqual(res["CVE-2026-123633"], "VULNERABLE")
        # Resolver floor 0.6.18, mail floor 0.5.33, HTTP/3 floor 1.25.0,
        # TLS loop floor 1.13.0.
        res = verdicts(ns.grade_all(version="0.6.17", exposure=ALL_TRUE))
        self.assertEqual(res["CVE-2026-123634"], "NOT-AFFECTED")
        res = verdicts(ns.grade_all(version="0.6.18", exposure=ALL_TRUE))
        self.assertEqual(res["CVE-2026-123634"], "VULNERABLE")
        res = verdicts(ns.grade_all(version="0.5.32", exposure=ALL_TRUE))
        self.assertEqual(res["CVE-2026-113425"], "NOT-AFFECTED")
        res = verdicts(ns.grade_all(version="0.5.33", exposure=ALL_TRUE))
        self.assertEqual(res["CVE-2026-113425"], "VULNERABLE")
        res = verdicts(ns.grade_all(version="1.24.0", exposure=ALL_TRUE))
        self.assertEqual(res["CVE-2026-121810"], "NOT-AFFECTED")
        res = verdicts(ns.grade_all(version="1.25.0", exposure=ALL_TRUE))
        self.assertEqual(res["CVE-2026-121810"], "VULNERABLE")
        res = verdicts(ns.grade_all(version="1.12.2", exposure=ALL_TRUE))
        self.assertEqual(res["CVE-2026-118899"], "NOT-AFFECTED")
        res = verdicts(ns.grade_all(version="1.13.0", exposure=ALL_TRUE))
        self.assertEqual(res["CVE-2026-118899"], "VULNERABLE")

    def test_patched(self):
        res = verdicts(ns.grade_all(version="1.31.9", exposure=ALL_TRUE))
        self.assertTrue(all(v == "PATCHED" for v in res.values()))
        res = verdicts(ns.grade_all(version="1.30.7", exposure=ALL_TRUE))
        self.assertTrue(all(v == "PATCHED" for v in res.values()))

    def test_distro_build_unknown(self):
        res = verdicts(ns.grade_all(version="1.18.0-0ubuntu1",
                                    exposure=ALL_TRUE))
        self.assertTrue(all(v == "UNKNOWN" for v in res.values()))
        res = verdicts(ns.grade_all(version="1.22.1-9", exposure=ALL_TRUE))
        self.assertTrue(all(v == "UNKNOWN" for v in res.values()))

    def test_unparseable_unknown(self):
        res = verdicts(ns.grade_all(version="banana", exposure=ALL_TRUE))
        self.assertTrue(all(v == "UNKNOWN" for v in res.values()))


class TestExposureFolding(unittest.TestCase):
    def test_http2_off(self):
        exp = ns.Exposure(http2=False, proxy=True, resolver=True,
                          resolver_trigger=True, http3=True, mail=True,
                          tls13=True)
        res = verdicts(ns.grade_all(version="1.31.8", exposure=exp))
        self.assertEqual(res["CVE-2026-123007"], "NOT-EXPOSED")
        self.assertEqual(res["CVE-2026-123633"], "NOT-EXPOSED")
        self.assertEqual(res["CVE-2026-123634"], "VULNERABLE")
        self.assertEqual(res["CVE-2026-121810"], "VULNERABLE")
        self.assertEqual(res["CVE-2026-113425"], "VULNERABLE")
        self.assertEqual(res["CVE-2026-118899"], "VULNERABLE")

    def test_no_proxy(self):
        exp = ns.Exposure(http2=True, proxy=False, resolver=True,
                          resolver_trigger=True, http3=True, mail=True,
                          tls13=True)
        res = verdicts(ns.grade_all(version="1.31.8", exposure=exp))
        self.assertEqual(res["CVE-2026-123633"], "NOT-EXPOSED")
        self.assertEqual(res["CVE-2026-121810"], "NOT-EXPOSED")
        self.assertEqual(res["CVE-2026-123007"], "VULNERABLE")

    def test_resolver_without_trigger(self):
        exp = ns.Exposure(http2=True, proxy=True, resolver=True,
                          resolver_trigger=False, http3=True, mail=True,
                          tls13=True)
        res = verdicts(ns.grade_all(version="1.31.8", exposure=exp))
        self.assertEqual(res["CVE-2026-123634"], "NOT-EXPOSED")

    def test_unknown_exposure(self):
        res = verdicts(ns.grade_all(version="1.31.8",
                                    exposure=ns.Exposure()))
        self.assertTrue(all(v == "UNKNOWN" for v in res.values()))

    def test_tls13_off(self):
        exp = ns.Exposure(http2=True, proxy=True, resolver=True,
                          resolver_trigger=True, http3=True, mail=True,
                          tls13=False)
        res = verdicts(ns.grade_all(version="1.31.8", exposure=exp))
        self.assertEqual(res["CVE-2026-118899"], "NOT-EXPOSED")


class TestPlusGrading(unittest.TestCase):
    def test_fixed_builds(self):
        for build in ("37.0.8.1", "37.3.0.1", "37.0.9.0", "37.3.0.2"):
            res = verdicts(ns.grade_all(plus_version=build,
                                        exposure=ALL_TRUE))
            self.assertTrue(all(v == "PATCHED" for v in res.values()), build)

    def test_123633_only_builds(self):
        for build in ("37.0.7.1", "37.2.0.1"):
            res = verdicts(ns.grade_all(plus_version=build,
                                        exposure=ALL_TRUE))
            self.assertEqual(res["CVE-2026-123633"], "PATCHED", build)
            self.assertEqual(res["CVE-2026-123007"], "VULNERABLE", build)
            self.assertEqual(res["CVE-2026-121810"], "VULNERABLE", build)

    def test_nofix_releases(self):
        for rel in ("R34", "R35", "R36"):
            res = verdicts(ns.grade_all(plus_version=rel,
                                        exposure=ALL_TRUE))
            self.assertTrue(all(v == "VULNERABLE" for v in res.values()), rel)

    def test_bare_r37_unknown(self):
        res = verdicts(ns.grade_all(plus_version="R37", exposure=ALL_TRUE))
        self.assertTrue(all(v == "UNKNOWN" for v in res.values()))

    def test_garbage_unknown(self):
        res = verdicts(ns.grade_all(plus_version="hello",
                                    exposure=ALL_TRUE))
        self.assertTrue(all(v == "UNKNOWN" for v in res.values()))


class TestConfigParsing(unittest.TestCase):
    FULL = """
    # a comment with http2 on; inside it must not count
    user www-data;
    events { worker_connections 1024; }
    http {
        ssl_protocols TLSv1.2 TLSv1.3;
        resolver 1.1.1.1 valid=30s;
        server {
            listen 443 ssl http2;
            listen 443 quic reuseport;
            http3 on;
            location / {
                proxy_pass http://backend;
                mirror /mirror;
            }
            location = /mirror { internal; proxy_pass http://mirror; }
        }
        server {
            listen 80;
            location / { root /var/www/html; }
        }
    }
    mail {
        auth_http 127.0.0.1:9000/auth;
        server { listen 25; protocol smtp; }
    }
    """

    MINIMAL = """
    events { worker_connections 1024; }
    http {
        server {
            listen 80;
            location / { root /var/www/html; }
        }
    }
    """

    def test_full_config(self):
        exp = ns.parse_nginx_config(self.FULL)
        self.assertTrue(exp.http2)
        self.assertTrue(exp.http3)
        self.assertTrue(exp.resolver)
        self.assertTrue(exp.resolver_trigger)
        self.assertTrue(exp.proxy)
        self.assertTrue(exp.mail)
        self.assertTrue(exp.tls13)

    def test_minimal_config(self):
        exp = ns.parse_nginx_config(self.MINIMAL)
        self.assertFalse(exp.http2)
        self.assertFalse(exp.http3)
        self.assertFalse(exp.resolver)
        self.assertFalse(exp.proxy)
        self.assertFalse(exp.mail)
        self.assertFalse(exp.tls13)

    def test_tls13_disabled(self):
        cfg = self.FULL.replace("TLSv1.2 TLSv1.3", "TLSv1.2")
        exp = ns.parse_nginx_config(cfg)
        self.assertFalse(exp.tls13)

    def test_variable_proxy_triggers_resolver(self):
        cfg = """
        http {
            resolver 8.8.8.8;
            server {
                listen 443 ssl;
                location / { proxy_pass http://$host$request_uri; }
            }
        }
        """
        exp = ns.parse_nginx_config(cfg)
        self.assertTrue(exp.resolver)
        self.assertTrue(exp.resolver_trigger)


class TestLocalMode(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.fake = os.path.join(self.tmp, "nginx")
        with open(self.fake, "w") as fh:
            fh.write("#!/bin/sh\n"
                     "if [ \"$1\" = \"-V\" ]; then\n"
                     "  echo 'nginx version: nginx/1.31.8' >&2\n"
                     "  echo 'built with OpenSSL 3.0.2' >&2\n"
                     "  echo 'configure arguments: --with-http_ssl_module "
                     "--with-http_v2_module --with-stream' >&2\n"
                     "  exit 0\n"
                     "fi\n"
                     "if [ \"$1\" = \"-T\" ]; then\n"
                     "  echo 'nginx: the configuration file "
                     "/etc/nginx/nginx.conf syntax is ok'\n"
                     "  echo 'events { worker_connections 1024; }'\n"
                     "  echo 'http { server { listen 443 ssl http2; "
                     "location / { proxy_pass http://backend; } } }'\n"
                     "  exit 0\n"
                     "fi\n")
        os.chmod(self.fake, 0o755)

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_local_vulnerable(self):
        results, meta = ns.run_local(self.fake)
        res = verdicts(results)
        self.assertEqual(meta["version"], "1.31.8")
        self.assertEqual(res["CVE-2026-123007"], "VULNERABLE")
        self.assertEqual(res["CVE-2026-123633"], "VULNERABLE")
        # No resolver / mail / HTTP/3 in this fake config.
        self.assertEqual(res["CVE-2026-123634"], "NOT-EXPOSED")
        self.assertEqual(res["CVE-2026-121810"], "NOT-EXPOSED")
        self.assertEqual(res["CVE-2026-113425"], "NOT-EXPOSED")
        self.assertEqual(ns.overall_exit(results), ns.EXIT_VULNERABLE)

    def test_local_missing_binary(self):
        with self.assertRaises(RuntimeError):
            ns.run_local(os.path.join(self.tmp, "no-such-nginx"))

    def test_plus_release_parsing(self):
        out, _ = ns.parse_nginx_v(
            "nginx version: nginx/1.27.4 (nginx-plus-r33)\n"
            "built with OpenSSL 3.0.2\n")
        self.assertEqual(out, "1.27.4")
        _v, plus = ns.parse_nginx_v(
            "nginx version: nginx/1.27.4 (nginx-plus-r33)\n")
        self.assertEqual(plus, "R33")


class NginxHandler(BaseHTTPRequestHandler):
    server_version = "nginx/1.31.8"

    def version_string(self):
        return self.server_version

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass


def start_server(handler_cls, tls=False, alpn=None):
    import threading
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
    if tls:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(CERT, KEY)
        if alpn:
            ctx.set_alpn_protocols(alpn)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server


CERT = KEY = None


def setUpModule():
    global CERT, KEY
    tmp = tempfile.mkdtemp(prefix="nginx-scanner-test-")
    CERT = os.path.join(tmp, "cert.pem")
    KEY = os.path.join(tmp, "key.pem")
    proc = subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048",
         "-keyout", KEY, "-out", CERT, "-days", "1", "-nodes",
         "-subj", "/CN=127.0.0.1"],
        capture_output=True, timeout=30)
    if proc.returncode != 0:
        raise unittest.SkipTest("openssl self-signed cert generation failed")


class TestUrlMode(unittest.TestCase):
    def test_plain_http_version_only(self):
        server = start_server(NginxHandler)
        try:
            url = "http://127.0.0.1:%d/" % server.server_address[1]
            results, meta = ns.grade_url(url)
            res = verdicts(results)
            self.assertEqual(meta["version"], "1.31.8")
            # Cleartext: HTTP/2 not probed, TLS 1.3 absent.
            self.assertEqual(res["CVE-2026-123007"], "UNKNOWN")
            self.assertEqual(res["CVE-2026-118899"], "NOT-EXPOSED")
            self.assertEqual(res["CVE-2026-123634"], "UNKNOWN")
        finally:
            server.shutdown()
            server.server_close()

    def test_https_h2_offered(self):
        server = start_server(NginxHandler, tls=True, alpn=["h2", "http/1.1"])
        try:
            url = "https://127.0.0.1:%d/" % server.server_address[1]
            results, meta = ns.grade_url(url)
            res = verdicts(results)
            self.assertEqual(meta["version"], "1.31.8")
            self.assertEqual(res["CVE-2026-123007"], "VULNERABLE")
            self.assertEqual(res["CVE-2026-118899"], "VULNERABLE")
            self.assertEqual(res["CVE-2026-123633"], "UNKNOWN")
            self.assertEqual(ns.overall_exit(results), ns.EXIT_VULNERABLE)
        finally:
            server.shutdown()
            server.server_close()

    def test_https_no_h2(self):
        server = start_server(NginxHandler, tls=True, alpn=["http/1.1"])
        try:
            url = "https://127.0.0.1:%d/" % server.server_address[1]
            results, meta = ns.grade_url(url)
            res = verdicts(results)
            self.assertEqual(res["CVE-2026-123007"], "NOT-EXPOSED")
            self.assertEqual(res["CVE-2026-123633"], "NOT-EXPOSED")
        finally:
            server.shutdown()
            server.server_close()

    def test_masked_server_header(self):
        class Masked(NginxHandler):
            server_version = "nginx"

        server = start_server(Masked)
        try:
            url = "http://127.0.0.1:%d/" % server.server_address[1]
            with self.assertRaises(RuntimeError):
                ns.grade_url(url)
        finally:
            server.shutdown()
            server.server_close()

    def test_patched_remote(self):
        class Patched(NginxHandler):
            server_version = "nginx/1.30.7"

        server = start_server(Patched)
        try:
            url = "http://127.0.0.1:%d/" % server.server_address[1]
            results, _meta = ns.grade_url(url)
            res = verdicts(results)
            self.assertTrue(all(v == "PATCHED" for v in res.values()))
            self.assertEqual(ns.overall_exit(results), ns.EXIT_CLEAN)
        finally:
            server.shutdown()
            server.server_close()


class TestInventoryAndCli(unittest.TestCase):
    def test_inventory(self):
        entries = [
            {"host": "web-1", "version": "1.31.8"},
            {"host": "web-2", "version": "1.30.7"},
            {"host": "web-3", "version": "1.18.0-0ubuntu1"},
            {"host": "web-4", "plus_version": "37.0.8.1"},
        ]
        with tempfile.NamedTemporaryFile("w", suffix=".json",
                                        delete=False) as fh:
            json.dump(entries, fh)
            path = fh.name
        try:
            fleet = ns.grade_inventory(path)
            self.assertEqual(len(fleet), 4)
            self.assertEqual(verdicts(fleet[0]["results"])
                             ["CVE-2026-123007"], "UNKNOWN")
            self.assertTrue(all(v == "PATCHED" for v in
                                verdicts(fleet[1]["results"]).values()))
            self.assertTrue(all(v == "UNKNOWN" for v in
                                verdicts(fleet[2]["results"]).values()))
            self.assertTrue(all(v == "PATCHED" for v in
                                verdicts(fleet[3]["results"]).values()))
        finally:
            os.unlink(path)

    def test_cli_exits(self):
        code = ns.main(["--version", "1.31.9"])
        self.assertEqual(code, ns.EXIT_CLEAN)
        code = ns.main(["--version", "1.31.8"])
        self.assertEqual(code, ns.EXIT_VULNERABLE)
        code = ns.main(["--version", "1.18.0-0ubuntu1"])
        self.assertEqual(code, ns.EXIT_UNKNOWN)
        code = ns.main(["--list"])
        self.assertEqual(code, ns.EXIT_CLEAN)
        code = ns.main(["--version", "1.31.8", "--no-http2", "--no-http3",
                        "--no-resolver", "--no-mail", "--no-tls13",
                        "--no-proxy"])
        self.assertEqual(code, ns.EXIT_CLEAN)
        code = ns.main(["--version", "1.31.8", "--json"])
        self.assertEqual(code, ns.EXIT_VULNERABLE)

    def test_cli_usage_error(self):
        code = ns.main([])
        self.assertEqual(code, ns.EXIT_USAGE)
        code = ns.main(["--version", "1.31.8", "--local"])
        self.assertEqual(code, ns.EXIT_USAGE)


if __name__ == "__main__":
    unittest.main()
