#!/usr/bin/env python3
"""Detection-only triage for `nginx2root` and the same-release TLS flaw.

Grades an `nginx` install against the fixed releases for five
unauthenticated remote-code-execution flaws disclosed 2026-11-18
(`CVE-2026-123007`, `CVE-2026-123633`, `CVE-2026-123634`,
`CVE-2026-121810`, `CVE-2026-113425`, each `CVSS 4.0 9.2` / `CVSS 3.1 8.1`)
plus the same-release `CVE-2026-118899` (`CVSS 4.0 8.7`, TLS 1.3
infinite loop, denial of service).

Detection only. No payloads, no exploit traffic, no HTTP/2 frames.
`--url` opens two plain TLS connections (one ALPN probe, one plain
`HEAD`), reads the `Server` header, and closes. `--local` runs
`nginx -V` and `nginx -T` and reads the config. Everything else is
version-table grading.
"""

import argparse
import json
import re
import socket
import ssl
import subprocess
import sys
import urllib.parse

VERSION = "1.0.0"

# Fixed releases, per the nginx.org security advisories (primary source).
# Every CVE below is fixed in open-source 1.30.7+ (stable) and 1.31.9+
# (mainline). The branch split is the trap: 1.30.7 is fixed while 1.31.8
# is not, and 1.31.9 is fixed while 1.30.6 is not.
FIXED_STABLE = (1, 30, 7)
FIXED_MAINLINE = (1, 31, 9)

# (cve, title, cwe, cvss40, cvss31, nginx.org severity, first affected,
#  exposure key, exposure note)
CVES = [
    ("CVE-2026-123007",
     "HTTP/2 flow-control integer underflow",
     "CWE-191", "9.2", "8.1", "major", (1, 9, 5), "http2",
     "HTTP/2 enabled on a listener"),
    ("CVE-2026-123633",
     "HTTP/2 use-after-free",
     "CWE-416", "9.2", "8.1", "medium", (1, 19, 7), "http2_proxy",
     "HTTP/2 enabled and requests proxied to an upstream"),
    ("CVE-2026-123634",
     "resolver use-after-free",
     "CWE-416", "9.2", "8.1", "medium", (0, 6, 18), "resolver",
     "resolver configured with mirror, SSI subrequest, or proxy_pass "
     "with a request-derived variable"),
    ("CVE-2026-121810",
     "HTTP/3 use-after-free",
     "CWE-416", "9.2", "8.1", "medium", (1, 25, 0), "http3_proxy",
     "HTTP/3 (QUIC) enabled and requests proxied to an upstream"),
    ("CVE-2026-113425",
     "mail proxy use-after-free",
     "CWE-416", "9.2", "8.1", "major", (0, 5, 33), "mail",
     "mail proxy running with proxy and auth_http enabled"),
    ("CVE-2026-118899",
     "infinite loop reading client request body over TLS 1.3",
     "CWE-835", "8.7", "n/a", "major", (1, 13, 0), "tls13",
     "TLS 1.3 enabled (denial of service, not code execution)"),
]

# NGINX Plus fixed builds, per F5's November 2026 release notes as
# reported by Tenable / CyberKendra / Reef-Sentinel. 37.0.7.1 and 37.2.0.1
# close only CVE-2026-123633; R34-R36 have no fix at all.
PLUS_FIXED_ALL = ((37, 0, 8, 1), (37, 3, 0, 1))
PLUS_FIXED_123633_ONLY = ((37, 0, 7, 1), (37, 2, 0, 1))
PLUS_NOFIX_RELEASES = (34, 35, 36)

EXIT_CLEAN = 0
EXIT_VULNERABLE = 1
EXIT_UNKNOWN = 2
EXIT_USAGE = 3


def ver_tuple(text):
    """Parse "1.31.8" into (1, 31, 8). Returns None if unparseable."""
    parts = text.strip().split(".")
    if not 2 <= len(parts) <= 4:
        return None
    try:
        nums = tuple(int(p) for p in parts)
    except ValueError:
        return None
    return nums


def cmp_ver(a, b):
    """Compare two version tuples of possibly different lengths."""
    n = max(len(a), len(b))
    aa = a + (0,) * (n - len(a))
    bb = b + (0,) * (n - len(b))
    return (aa > bb) - (aa < bb)


def parse_version(raw):
    """Split a version string into (tuple, distro_build, plus_hint).

    distro_build is True when the string carries a distribution suffix
    such as "1.18.0-0ubuntu1" or "1.22.1-9", which may carry a backported
    fix the upstream number does not show. plus_hint is True when the
    string looks like an NGINX Plus build.
    """
    s = raw.strip()
    s = re.sub(r"^nginx version:\s*", "", s)
    s = re.sub(r"^nginx/", "", s)
    token = s.split()[0] if s.split() else ""
    plus_hint = "plus" in s.lower() or re.search(r"nginx-plus-r\d+", s)
    if "-" in token:
        base, _suffix = token.split("-", 1)
        return ver_tuple(base), True, bool(plus_hint)
    return ver_tuple(token), False, bool(plus_hint)


def is_fixed_oss(v):
    """True when an open-source version carries the November 2026 fix."""
    if v is None:
        return False
    if v[0] > 1:
        return True
    if v[0] == 1 and len(v) >= 2:
        if v[1] == 30:
            return len(v) >= 3 and cmp_ver(v, FIXED_STABLE) >= 0
        if v[1] == 31:
            return len(v) >= 3 and cmp_ver(v, FIXED_MAINLINE) >= 0
        if v[1] > 31:
            return True
    return False


def grade_oss(v, distro, cve):
    """Grade one open-source version against one CVE.

    Returns (verdict, note). Verdict is PATCHED, NOT-AFFECTED,
    VULNERABLE, or UNKNOWN.
    """
    _cid, _title, _cwe, _s40, _s31, _sev, first, _exp, _note = cve
    if v is None:
        return "UNKNOWN", "unparseable version string"
    if distro:
        return ("UNKNOWN",
                "distribution build (e.g. Debian/Ubuntu/RHEL) may carry a "
                "backported fix; check the vendor security tracker, do not "
                "trust the upstream number")
    if is_fixed_oss(v):
        return "PATCHED", "at or above 1.30.7 (stable) / 1.31.9 (mainline)"
    if cmp_ver(v, first) < 0:
        return ("NOT-AFFECTED",
                "below first affected %s" % ".".join(str(x) for x in first))
    return "VULNERABLE", "in affected range"


def grade_plus(build):
    """Grade an NGINX Plus build string, e.g. "37.0.8.1" or "R35".

    Returns a dict {cve_id: (verdict, note)}.
    """
    out = {}
    m = re.fullmatch(r"R(\d+)", build.strip(), re.IGNORECASE)
    if m:
        rel = int(m.group(1))
        if rel in PLUS_NOFIX_RELEASES:
            for cve in CVES:
                out[cve[0]] = ("VULNERABLE",
                               "NGINX Plus R%d has no fix release" % rel)
        else:
            for cve in CVES:
                out[cve[0]] = ("UNKNOWN",
                               "bare Plus release R%d: the fix lives in a "
                               "specific build (37.0.8.1 / 37.3.0.1), "
                               "grade the exact build" % rel)
        return out
    v = ver_tuple(build.strip())
    if v is None or len(v) != 4:
        for cve in CVES:
            out[cve[0]] = ("UNKNOWN", "unparseable Plus build string")
        return out
    if v[0] != 37:
        for cve in CVES:
            out[cve[0]] = ("UNKNOWN",
                           "unrecognised Plus build line; check F5 "
                           "advisories K000163926 / K000163928")
        return out
    line = (v[0], v[1])
    if line == (37, 0) and cmp_ver(v, (37, 0, 8, 1)) >= 0:
        fixed = True
    elif line == (37, 3) and cmp_ver(v, (37, 3, 0, 1)) >= 0:
        fixed = True
    else:
        fixed = False
    for cve in CVES:
        if fixed:
            out[cve[0]] = ("PATCHED", "at or above 37.0.8.1 / 37.3.0.1")
        elif v in PLUS_FIXED_123633_ONLY:
            if cve[0] == "CVE-2026-123633":
                out[cve[0]] = ("PATCHED",
                               "37.0.7.1 / 37.2.0.1 close only this CVE")
            else:
                out[cve[0]] = ("VULNERABLE",
                               "37.0.7.1 / 37.2.0.1 close only "
                               "CVE-2026-123633, not this CVE")
        elif line == (37, 0) and cmp_ver(v, (37, 0, 7, 1)) < 0:
            out[cve[0]] = ("UNKNOWN",
                           "Plus build before 37.0.7.1: no per-CVE fix "
                           "data in the sources checked; check F5 advisories")
        else:
            out[cve[0]] = ("UNKNOWN",
                           "unverified Plus build; check F5 advisories "
                           "K000163926 / K000163928")
    return out


class Exposure:
    """What the target is known to expose. None means unknown."""

    def __init__(self, http2=None, proxy=None, resolver=None,
                 resolver_trigger=None, http3=None, mail=None, tls13=None):
        self.http2 = http2
        self.proxy = proxy
        self.resolver = resolver
        self.resolver_trigger = resolver_trigger
        self.http3 = http3
        self.mail = mail
        self.tls13 = tls13

    def for_cve(self, cve):
        """(exposed, note) for one CVE given this exposure picture."""
        key = cve[7]
        if key == "http2":
            return self.http2, "HTTP/2 enabled" if self.http2 else \
                ("HTTP/2 not offered" if self.http2 is False else
                 "HTTP/2 exposure not confirmed")
        if key == "http2_proxy":
            if self.http2 is False:
                return False, "HTTP/2 not offered"
            if self.http2 is True and self.proxy is True:
                return True, "HTTP/2 enabled and proxying to an upstream"
            if self.http2 is True and self.proxy is False:
                return False, "HTTP/2 enabled but no upstream proxying"
            return None, "proxy upstream not verifiable from here"
        if key == "resolver":
            if self.resolver is False:
                return False, "no resolver directive"
            if self.resolver is True and self.resolver_trigger is True:
                return True, ("resolver configured with mirror, SSI "
                              "subrequest, or variable proxy_pass")
            if self.resolver is True and self.resolver_trigger is False:
                return False, "resolver present but no trigger directive"
            return None, "resolver trigger not verifiable from here"
        if key == "http3_proxy":
            if self.http3 is False:
                return False, "HTTP/3 not offered"
            if self.http3 is True and self.proxy is True:
                return True, "HTTP/3 enabled and proxying to an upstream"
            if self.http3 is True and self.proxy is False:
                return False, "HTTP/3 enabled but no upstream proxying"
            return None, "HTTP/3 / proxy exposure not verifiable from here"
        if key == "mail":
            return self.mail, "mail proxy with auth_http" if self.mail else \
                ("mail proxy not configured" if self.mail is False else
                 "mail proxy exposure not verifiable from here")
        if key == "tls13":
            return self.tls13, "TLS 1.3 negotiated" if self.tls13 else \
                ("TLS 1.3 not offered" if self.tls13 is False else
                 "TLS 1.3 exposure not confirmed")
        return None, "unknown exposure"


def apply_exposure(verdict, note, cve, exposure):
    """Fold an exposure picture into a version verdict."""
    if verdict in ("PATCHED", "NOT-AFFECTED"):
        return verdict, note
    if verdict == "UNKNOWN":
        return verdict, note
    exposed, enote = exposure.for_cve(cve)
    if exposed is True:
        return "VULNERABLE", note + "; " + enote
    if exposed is False:
        return "NOT-EXPOSED", enote
    return "UNKNOWN", note + "; " + enote


def grade_all(version=None, plus_version=None, exposure=None):
    """Grade every CVE. Returns a list of result dicts."""
    exposure = exposure or Exposure()
    results = []
    if plus_version:
        plus = grade_plus(plus_version)
        for cve in CVES:
            verdict, note = plus[cve[0]]
            verdict, note = apply_exposure(verdict, note, cve, exposure)
            results.append({"cve": cve[0], "title": cve[1], "cwe": cve[2],
                            "cvss40": cve[3], "cvss31": cve[4],
                            "severity": cve[5], "verdict": verdict,
                            "note": note})
        return results
    v, distro, _plus = parse_version(version or "")
    for cve in CVES:
        verdict, note = grade_oss(v, distro, cve)
        verdict, note = apply_exposure(verdict, note, cve, exposure)
        results.append({"cve": cve[0], "title": cve[1], "cwe": cve[2],
                        "cvss40": cve[3], "cvss31": cve[4],
                        "severity": cve[5], "verdict": verdict,
                        "note": note})
    return results


def overall_exit(results):
    verdicts = {r["verdict"] for r in results}
    if "VULNERABLE" in verdicts:
        return EXIT_VULNERABLE
    if "UNKNOWN" in verdicts:
        return EXIT_UNKNOWN
    return EXIT_CLEAN


# --- config parsing (local mode) -------------------------------------------

def strip_comments(text):
    out = []
    for line in text.splitlines():
        out.append(re.sub(r"#.*$", "", line))
    return "\n".join(out)


def parse_nginx_config(text):
    """Pull exposure facts out of an `nginx -T` dump (comments stripped)."""
    cfg = strip_comments(text)
    http2 = bool(re.search(r"\blisten\b[^;{]*\bhttp2\b", cfg)
                 or re.search(r"\bhttp2\s+on\s*;", cfg))
    http3 = bool(re.search(r"\blisten\b[^;{]*\bquic\b", cfg)
                 or re.search(r"\bhttp3\s+on\s*;", cfg))
    resolver = bool(re.search(r"\bresolver\b[^;]+;", cfg))
    mirror = bool(re.search(r"\bmirror\b[^;]+;", cfg))
    ssi = bool(re.search(r"\bssi\s+on\s*;", cfg))
    proxy_passes = re.findall(r"\bproxy_pass\b([^;]+);", cfg)
    proxy = bool(proxy_passes)
    variable_proxy = any("$" in p for p in proxy_passes)
    resolver_trigger = mirror or ssi or variable_proxy
    mail = bool(re.search(r"\bmail\s*\{", cfg)
                and re.search(r"\bauth_http\b[^;]+;", cfg))
    ssl_proto = re.search(r"\bssl_protocols\b([^;]+);", cfg)
    has_tls_listener = bool(re.search(r"\blisten\b[^;{]*\bssl\b", cfg))
    if ssl_proto:
        tls13 = "TLSv1.3" in ssl_proto.group(1)
    elif has_tls_listener:
        tls13 = True  # modern default includes TLS 1.3
    else:
        tls13 = False
    return Exposure(http2=http2, proxy=proxy, resolver=resolver,
                    resolver_trigger=resolver_trigger, http3=http3,
                    mail=mail, tls13=tls13)


def parse_nginx_v(stderr_text):
    """Parse `nginx -V` output (goes to stderr). Returns (version, plus)."""
    m = re.search(r"nginx/([0-9][^\s]*)", stderr_text)
    version = m.group(1) if m else None
    plus = re.search(r"nginx-plus-r(\d+)", stderr_text)
    return version, ("R%s" % plus.group(1)) if plus else None


def run_local(nginx_bin="nginx"):
    """Grade the local install. Returns (results, meta) or raises."""
    try:
        proc = subprocess.run([nginx_bin, "-V"],
                              capture_output=True, text=True, timeout=15)
    except FileNotFoundError:
        raise RuntimeError("nginx binary not found (%s)" % nginx_bin)
    except subprocess.TimeoutExpired:
        raise RuntimeError("nginx -V timed out")
    version, plus_rel = parse_nginx_v(proc.stderr + proc.stdout)
    if not version:
        raise RuntimeError("could not read version from `nginx -V`")
    exposure = Exposure()
    config_note = "config dump unavailable"
    try:
        proc_t = subprocess.run([nginx_bin, "-T"],
                                capture_output=True, text=True, timeout=30)
        dump = proc_t.stdout + proc_t.stderr
        if "configuration file" in dump or "server {" in dump:
            exposure = parse_nginx_config(dump)
            config_note = "config parsed from `nginx -T`"
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    meta = {"version": version, "plus_release": plus_rel,
            "config_note": config_note}
    if plus_rel:
        # Exact Plus build from the package manager, when available.
        build = plus_build_from_package()
        if build:
            meta["plus_build"] = build
            results = grade_all(plus_version=build, exposure=exposure)
        else:
            results = grade_all(plus_version=plus_rel, exposure=exposure)
        return results, meta
    results = grade_all(version=version, exposure=exposure)
    return results, meta


def plus_build_from_package():
    """Best-effort exact Plus build, e.g. 37.0.8.1, from dpkg/rpm."""
    for cmd in (["dpkg-query", "-W", "-f=${Version}", "nginx-plus"],
                ["rpm", "-q", "--queryformat", "%{VERSION}",
                 "nginx-plus"]):
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True,
                                  timeout=10)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
        out = proc.stdout.strip()
        m = re.search(r"(\d+\.\d+\.\d+\.\d+)", out)
        if m:
            return m.group(1)
    return None


# --- remote probing (url mode) ---------------------------------------------

def probe_url(url, timeout=10):
    """One ALPN probe + one plain HEAD. Returns (server_hdr, exposure).

    Detection only: the ALPN connection sends no HTTP at all, and the
    HEAD connection sends a single plain HEAD request and closes.
    """
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("URL must be http:// or https://")
    host = parsed.hostname
    if not host:
        raise ValueError("URL has no host")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    exposure = Exposure()
    server_hdr = None
    tls_version = None
    if parsed.scheme == "https":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_alpn_protocols(["h2", "http/1.1"])
        raw = socket.create_connection((host, port), timeout=timeout)
        try:
            ssock = ctx.wrap_socket(raw, server_hostname=host)
            try:
                exposure.http2 = ssock.selected_alpn_protocol() == "h2"
                tls_version = ssock.version()
                exposure.tls13 = tls_version == "TLSv1.3"
            finally:
                ssock.close()
        finally:
            raw.close()
        # Second connection: HTTP/1.1 only, to read the Server header.
        ctx2 = ssl.create_default_context()
        ctx2.check_hostname = False
        ctx2.verify_mode = ssl.CERT_NONE
        ctx2.set_alpn_protocols(["http/1.1"])
        raw = socket.create_connection((host, port), timeout=timeout)
        try:
            ssock = ctx2.wrap_socket(raw, server_hostname=host)
            try:
                server_hdr = http_head(ssock, host, port, path, timeout)
            finally:
                ssock.close()
        finally:
            raw.close()
    else:
        raw = socket.create_connection((host, port), timeout=timeout)
        try:
            server_hdr = http_head(raw, host, port, path, timeout)
        finally:
            raw.close()
        exposure.http2 = None  # HTTP/2 cleartext not probed
        exposure.tls13 = False
    return server_hdr, exposure


def http_head(sock, host, port, path, timeout):
    """Send one HEAD, return the Server header (or None)."""
    sock.settimeout(timeout)
    req = ("HEAD %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: "
           "nginx-scanner/1.0 (detection-only)\r\nConnection: close\r\n\r\n"
           % (path, host))
    sock.sendall(req.encode())
    buf = b""
    while b"\r\n\r\n" not in buf and len(buf) < 65536:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    text = buf.decode("iso-8859-1", "replace")
    m = re.search(r"(?im)^Server:\s*(.+?)\s*$", text)
    return m.group(1) if m else None


def grade_url(url, timeout=10):
    """Grade a live URL. Returns (results, meta)."""
    server_hdr, exposure = probe_url(url, timeout)
    meta = {"url": url, "server_header": server_hdr}
    if not server_hdr:
        raise RuntimeError("no Server header returned; cannot grade "
                           "remotely (server_tokens may be off)")
    m = re.search(r"nginx/([0-9][^\s]*)", server_hdr, re.IGNORECASE)
    if not m:
        raise RuntimeError("Server header does not disclose an nginx "
                           "version: %r" % server_hdr)
    version = m.group(1)
    _v, distro, _p = parse_version(version)
    if distro:
        meta["distro_build"] = True
    meta["version"] = version
    meta["assumption"] = ("remote version grading assumes an open-source "
                          "build; NGINX Plus hosts need --plus-version or "
                          "--local")
    results = grade_all(version=version, exposure=exposure)
    return results, meta


# --- inventory ---------------------------------------------------------------

def grade_inventory(path):
    """Grade a fleet file: [{"host","version",...}, ...]."""
    with open(path, encoding="utf-8") as fh:
        entries = json.load(fh)
    if not isinstance(entries, list):
        raise ValueError("inventory JSON must be a list of objects")
    out = []
    for entry in entries:
        host = entry.get("host") or entry.get("url") or "?"
        exposure = Exposure(
            http2=entry.get("http2"), proxy=entry.get("proxy"),
            resolver=entry.get("resolver"),
            resolver_trigger=entry.get("resolver_trigger"),
            http3=entry.get("http3"), mail=entry.get("mail"),
            tls13=entry.get("tls13"))
        if entry.get("plus_version"):
            results = grade_all(plus_version=entry["plus_version"],
                                exposure=exposure)
            version = entry["plus_version"]
        else:
            results = grade_all(version=entry.get("version", ""),
                                exposure=exposure)
            version = entry.get("version", "")
        out.append({"host": host, "version": version, "results": results})
    return out


# --- output ------------------------------------------------------------------

def render_text(results, meta=None, host=None):
    lines = []
    if host:
        lines.append("host: %s" % host)
    if meta:
        for key in ("version", "plus_release", "plus_build", "server_header",
                    "url", "config_note", "assumption"):
            if meta.get(key):
                lines.append("%s: %s" % (key, meta[key]))
    for r in results:
        lines.append("[%s] %s - %s (%s, CVSS 4.0 %s / 3.1 %s): %s"
                     % (r["verdict"], r["cve"], r["title"], r["cwe"],
                        r["cvss40"], r["cvss31"], r["note"]))
    verdicts = {r["verdict"] for r in results}
    if "VULNERABLE" in verdicts:
        worst = "VULNERABLE"
    elif "UNKNOWN" in verdicts:
        worst = "UNKNOWN"
    else:
        worst = "CLEAN"
    lines.append("overall: %s" % worst)
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Detection-only triage for nginx2root "
                    "(CVE-2026-123007 et al.) and CVE-2026-118899.")
    parser.add_argument("--version", help="nginx version to grade, e.g. 1.31.8")
    parser.add_argument("--plus-version",
                        help="NGINX Plus build to grade, e.g. 37.0.8.1 or R35")
    parser.add_argument("--version-file",
                        help="file holding a version string")
    parser.add_argument("--local", action="store_true",
                        help="grade the nginx install on this box")
    parser.add_argument("--nginx-bin", default="nginx",
                        help="nginx binary for --local (default: nginx)")
    parser.add_argument("--url", help="probe a live https:// or http:// URL")
    parser.add_argument("--inventory-json",
                        help="grade a fleet JSON file")
    parser.add_argument("--timeout", type=int, default=10,
                        help="seconds for --url probes (default 10)")
    parser.add_argument("--json", action="store_true",
                        help="machine-readable output")
    parser.add_argument("--list", action="store_true",
                        help="print the fixed-version table and exit")
    parser.add_argument("--no-http2", action="store_true",
                        help="HTTP/2 is off (version grading only)")
    parser.add_argument("--no-proxy", action="store_true",
                        help="no upstream proxying (version grading only)")
    parser.add_argument("--no-resolver", action="store_true",
                        help="no resolver directive (version grading only)")
    parser.add_argument("--no-http3", action="store_true",
                        help="HTTP/3 is off (version grading only)")
    parser.add_argument("--no-mail", action="store_true",
                        help="no mail proxy (version grading only)")
    parser.add_argument("--no-tls13", action="store_true",
                        help="TLS 1.3 is off (version grading only)")
    args = parser.parse_args(argv)

    if args.list:
        print("nginx2root + CVE-2026-118899 fixed releases")
        print("open-source stable : 1.30.7+")
        print("open-source mainline: 1.31.9+")
        print("NGINX Plus         : 37.0.8.1+ / 37.3.0.1+")
        print("NGINX Plus R34-R36 : no fix release")
        for cve in CVES:
            print("%s %s first affected %s, CVSS 4.0 %s"
                  % (cve[0], cve[1],
                     ".".join(str(x) for x in cve[6]), cve[3]))
        return EXIT_CLEAN

    modes = sum([bool(args.version or args.version_file or args.plus_version),
                 bool(args.local), bool(args.url),
                 bool(args.inventory_json)])
    if modes != 1:
        print("pick exactly one of --version/--plus-version/--version-file, "
              "--local, --url, --inventory-json", file=sys.stderr)
        return EXIT_USAGE

    try:
        if args.inventory_json:
            fleet = grade_inventory(args.inventory_json)
            if args.json:
                print(json.dumps(fleet, indent=2))
            else:
                for item in fleet:
                    print(render_text(item["results"], host=item["host"]))
                    print()
            codes = [overall_exit(i["results"]) for i in fleet]
            if EXIT_VULNERABLE in codes:
                return EXIT_VULNERABLE
            if EXIT_UNKNOWN in codes:
                return EXIT_UNKNOWN
            return EXIT_CLEAN
        if args.local:
            results, meta = run_local(args.nginx_bin)
            host = None
        elif args.url:
            results, meta = grade_url(args.url, args.timeout)
            host = args.url
        else:
            version = args.version
            if args.version_file:
                with open(args.version_file, encoding="utf-8") as fh:
                    version = fh.read().strip()
            exposure = Exposure(http2=not args.no_http2,
                                proxy=not args.no_proxy,
                                resolver=not args.no_resolver,
                                resolver_trigger=not args.no_resolver,
                                http3=not args.no_http3,
                                mail=not args.no_mail,
                                tls13=not args.no_tls13)
            meta = {"version": version or args.plus_version}
            host = None
            if args.plus_version:
                results = grade_all(plus_version=args.plus_version,
                                    exposure=exposure)
            else:
                results = grade_all(version=version, exposure=exposure)
    except (RuntimeError, ValueError, OSError) as exc:
        print("error: %s" % exc, file=sys.stderr)
        return EXIT_USAGE if isinstance(exc, ValueError) else EXIT_UNKNOWN
    except KeyboardInterrupt:
        return EXIT_USAGE

    if args.json:
        print(json.dumps({"meta": meta, "results": results}, indent=2))
    else:
        print(render_text(results, meta, host))
    return overall_exit(results)


if __name__ == "__main__":
    sys.exit(main())
