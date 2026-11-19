# `nginx-scanner`

Detection-only triage for `nginx2root`, five unauthenticated remote-code-execution flaws in `nginx` disclosed `2026-11-18` (`CVSS 4.0 9.2` each), plus the same-release TLS `1.3` denial-of-service flaw. Grades your `nginx` version against the fixed releases, probes a live server the way a defender would (one ALPN handshake, one plain `HEAD`, no HTTP/2 frames, no payloads), and reads your local config for the features each flaw actually needs. Nothing here can trigger any of the flaws.

## `What it checks`

* `CVE-2026-123007` — integer underflow in HTTP/2 flow control. When a stream is cancelled, `nginx` hands the stream's unused flow-control allowance back to the connection window without checking HTTP/2's maximum window size, and later copies with an invalid length. Unauthenticated RCE with HTTP/2 enabled, nothing else needed — static files behind it are enough. `CVSS 4.0 9.2` (`CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N`), `CVSS 3.1 8.1`, `CWE-191`, `nginx.org` rates it `major`. Present since HTTP/2 landed in `1.9.5` (2015). Rapid7 published a public proof of concept the same day; it needs roughly `128 GB` of HTTP/2 traffic and a specific `glibc` memory-copy implementation, so it is heavy, not trivial.
* `CVE-2026-123633` — use-after-free in HTTP/2. A connection with no active streams is marked reusable while a `HEADERS` frame is only partly received, and `nginx` does not take it off the reusable list when a request stream is created. Needs HTTP/2 plus requests proxied to an upstream. `CVSS 4.0 9.2` / `CVSS 3.1 8.1`, `CWE-416`, `nginx.org` rates it `medium`. Wiz showed RCE with ASLR defeated on a server serving static content directly.
* `CVE-2026-123634` — use-after-free in the resolver. Needs a `resolver` directive plus `mirror`, an SSI subrequest, or a `proxy_pass` with a request-derived variable. `CVSS 4.0 9.2` / `CVSS 3.1 8.1`, `CWE-416`, `medium`.
* `CVE-2026-121810` — use-after-free in HTTP/3. Needs HTTP/3 (`QUIC`) enabled plus requests proxied to an upstream. `CVSS 4.0 9.2` / `CVSS 3.1 8.1`, `CWE-416`, `medium`.
* `CVE-2026-113425` — use-after-free in the mail proxy. Needs the mail proxy running with `proxy` and `auth_http` enabled. `CVSS 4.0 9.2` / `CVSS 3.1 8.1`, `CWE-416`, `major`.
* `CVE-2026-118899` — infinite loop while reading a client request body over TLS `1.3`. Worker processes get stuck, so it is denial of service, not code execution. `CVSS 4.0 8.7`, `CWE-835`, `major`. Fixed in the same two releases, so it rides along for free.

Fixed versions, per the `nginx.org` security advisories (primary source):

| `Build` | `Upgrade to` |
| --- | --- |
| `nginx` open source, stable line | `1.30.7` or later `1.30.x` |
| `nginx` open source, mainline | `1.31.9` or later |
| `NGINX Plus` | `37.0.8.1` or `37.3.0.1` |
| `NGINX Plus` R34–R36 | no fix release |

`37.0.7.1` and `37.2.0.1` close only `CVE-2026-123633`, not the other four. Xint counted `56.7` million `nginx` hosts on Shodan as of `2026-11-10`; of the `11.94` million with an identifiable version, `98.9%` fell in the `CVE-2026-123007` range. No exploitation in the wild had been reported as of `2026-11-19`, and none of the five is in CISA KEV — the public proof of concept and the breadth are the reason to move now, not a KEV entry.

## `Usage`

```bash
# grade a version string
python3 nginx_scanner.py --version "1.31.8"
python3 nginx_scanner.py --version "1.30.7"
python3 nginx_scanner.py --plus-version "37.0.8.1"

# version grading with features you know are off
python3 nginx_scanner.py --version "1.31.8" --no-http2 --no-http3 --no-mail

# on the nginx box itself (version + modules + full config)
python3 nginx_scanner.py --local

# a live server: ALPN probe + Server header, two plain connections
python3 nginx_scanner.py --url https://example.com
python3 nginx_scanner.py --url http://192.0.2.10:8080

# a whole fleet at once
python3 nginx_scanner.py --inventory-json fleet.json

# machine output / the fixed-version table
python3 nginx_scanner.py --version "1.31.8" --json
python3 nginx_scanner.py --list
```

`--local` runs `nginx -V` and `nginx -T` and reads the config: `listen ... http2`, `http2 on;`, `listen ... quic`, `http3 on;`, `resolver`, `mirror`, `ssi on;`, `proxy_pass` (and whether it uses a `$variable`), `mail {` with `auth_http`, and `ssl_protocols`. `--url` opens one TLS connection that only negotiates ALPN (to learn whether `h2` is offered) and a second that sends one plain `HEAD` and reads the `Server` header. `--inventory-json` takes a list of `{"host": "web-1", "version": "1.31.8"}` objects, with optional `plus_version` and per-host exposure flags (`http2`, `proxy`, `resolver`, `resolver_trigger`, `http3`, `mail`, `tls13`).

Exit codes: `0` patched / not affected / not exposed / clean, `1` vulnerable, `2` unknown, `3` usage error.

## `Traps`

* The branch trap. `1.30.7` is fixed and `1.31.8` is not; `1.31.9` is fixed and `1.30.6` is not. A rule that flags everything below `1.31.9` wrongly flags fixed stable builds, and a rule that flags everything below `1.30.7` misses mainline `1.31.x`. This scanner grades per branch.
* The distro-backport trap. Debian, Ubuntu and RHEL packages had not shipped patched builds as of `2026-11-18`, and a distro version string like `1.18.0-0ubuntu1` may already carry a backported fix the upstream number does not show. Distro builds grade `UNKNOWN`: check the vendor security tracker, do not trust the number either way.
* The Plus base-version trap. A Plus box reports its open-source base version (e.g. `1.27.4 (nginx-plus-r33)`), which sits inside the affected range even when the Plus build is patched. Grade Plus by its build (`37.0.8.1`) or release (`R35`), never by the base version. A bare `R37` grades `UNKNOWN`: the fix lives in a specific build.
* The masked-header trap. With `server_tokens off`, the `Server` header says `nginx` and nothing else, so a remote probe cannot grade the version at all. Use `--local` or `--version` for those hosts.
* The `http2 off` trap. Disabling HTTP/2 closes `CVE-2026-123007` and `CVE-2026-123633` only. The resolver, HTTP/3 and mail-proxy flaws do not care about HTTP/2, and the TLS `1.3` loop does not either.
* The kernel chain. Xint chained the `nginx` flaws with a separate, currently unpatched Linux kernel SCTP use-after-free to reach root on the host. That kernel flaw has no CVE ID and no patch yet, so it is out of scope here; this scanner grades the five `nginx` flaws only. The name `nginx2root` describes the chain, not a single flaw that gives root by itself.

## `Out of scope`

The same `2026-11-18` release fixed four more flaws this scanner does not grade: `CVE-2026-120993` (PROXY protocol v2 NULL dereference, `minor`, mainline-only `1.31.4–1.31.8`), `CVE-2026-125283` (alias with `try_files` overflow, `medium`), `CVE-2026-120967` (SNI bypass in the stream module, `medium`), and `CVE-2026-123640` (stream `ssl_preread` validation, `minor`). They are lower severity and config-specific; upgrading to `1.30.7` / `1.31.9` closes them too.

## `Sources and disagreements`

* Fixed ranges and first-affected versions follow the `nginx.org` security advisories, the primary source. One secondary table listed `CVE-2026-123634`, `CVE-2026-121810` and `CVE-2026-113425` as fixed in `1.31.9` only; `nginx.org` lists both `1.30.7+` and `1.31.9+` for all five, so `nginx.org` was followed.
* Scores are F5's: `9.2` under `CVSS 4.0`, `8.1` under `CVSS 3.1` for the five, `8.7` under `CVSS 4.0` for `CVE-2026-118899`. `nginx.org` uses its own words instead (`major` / `medium`) and disagrees with F5 on two of them (`CVE-2026-123633` and `CVE-2026-121810` are `medium` there); both scales are shown.
* First-affected versions follow `nginx.org`: resolver `0.6.18`, mail proxy `0.5.33`. One secondary table gave `1.13.4` and `0.5.15` for those two; `nginx.org` was followed.
* Naming: Xint calls the set `nginx2root`; Ikotas Labs calls it `NGINX2Shell`. This scanner uses Xint's name and notes the alias.

## `Thanks to`

* `Xint` — found all five, named the set, published the exposure checks and the Shodan numbers.
* `Wiz Research`, `Ikotas Labs`, `Metnir`, `Rapid7` — independently found the HTTP/2 flaws; Rapid7's Stephen Fewer published the public proof of concept.
* `F5` and the `nginx` team — coordinated disclosure and the `1.30.7` / `1.31.9` releases.

## `Disclaimer`

Educational and defensive use only. This tool grades versions and reads configuration; it sends no exploit traffic and cannot confirm exploitation. Patching is the fix: upgrade to `1.30.7` / `1.31.9` (or your distribution's patched package), then confirm the old worker processes have actually exited. Run it only against systems you own or are authorised to test.

> Research by `Vineeth Kumar` (`foxcornlab`). Found a bug or want a feature, open an `issue`.
