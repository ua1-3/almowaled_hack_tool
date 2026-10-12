#!/usr/bin/env python3
"""
recon.py - Information gathering tool for websites, domains and IPs.

Only use on targets you own or have written permission to test.
Core features use the Python standard library only (no installs needed).
Optional: `pip install dnspython` for full DNS records (MX, NS, TXT...).

Examples:
  python3 recon.py example.com
  python3 recon.py -u https://example.com --all --json report.json
  python3 recon.py 8.8.8.8 --ports 22,80,443
"""
import argparse
import concurrent.futures as cf
import datetime as dt
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

UA = "Mozilla/5.0 (compatible; ReconTool/2.0)"

COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios", 143: "imap",
    443: "https", 445: "smb", 465: "smtps", 587: "submission", 993: "imaps",
    995: "pop3s", 1433: "mssql", 1521: "oracle", 2049: "nfs", 3306: "mysql",
    3389: "rdp", 5432: "postgresql", 5900: "vnc", 6379: "redis",
    8000: "http-alt", 8080: "http-proxy", 8443: "https-alt", 9200: "elasticsearch",
    27017: "mongodb",
}
HTTP_PORTS = {80, 8000, 8080, 8888}

SECURITY_HEADERS = [
    "Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
    "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy",
]

# ---------------------------------------------------------------- output ----
os.system("")  # enables ANSI colors on Windows 10+ terminals


class C:
    on = sys.stdout.isatty()
    CYAN = "\033[96m" if on else ""
    GREEN = "\033[92m" if on else ""
    YELLOW = "\033[93m" if on else ""
    RED = "\033[91m" if on else ""
    BOLD = "\033[1m" if on else ""
    DIM = "\033[2m" if on else ""
    END = "\033[0m" if on else ""


def section(title):
    print(f"\n{C.CYAN}{C.BOLD}== {title} =={C.END}")


def kv(key, value, color=""):
    print(f"  {C.DIM}{key:<24}{C.END}{color}{value}{C.END}")


def info(msg):
    print(f"  {C.YELLOW}[*]{C.END} {msg}")


def good(msg):
    print(f"  {C.GREEN}[+]{C.END} {msg}")


def bad(msg):
    print(f"  {C.RED}[-]{C.END} {msg}")


# ---------------------------------------------------------------- target ----
def parse_target(raw):
    parsed = urllib.parse.urlparse(raw if "://" in raw else "//" + raw)
    host = parsed.hostname
    if not host:
        sys.exit(f"{C.RED}[-] Could not understand target: {raw}{C.END}")
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False
    return host, parsed.port, parsed.scheme.lower(), is_ip


# ------------------------------------------------------------------- DNS ----
def dns_info(host, is_ip):
    out = {"ips": [], "reverse": {}, "records": {}}
    try:
        if is_ip:
            out["ips"] = [host]
        else:
            out["ips"] = sorted({i[4][0] for i in socket.getaddrinfo(host, None)})
    except socket.gaierror as e:
        out["error"] = str(e)
        return out

    for ip in out["ips"]:
        try:
            out["reverse"][ip] = socket.gethostbyaddr(ip)[0]
        except (socket.herror, socket.gaierror, OSError):
            out["reverse"][ip] = None

    if not is_ip:
        try:
            import dns.resolver  # optional dependency
            for rtype in ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA"):
                try:
                    ans = dns.resolver.resolve(host, rtype, lifetime=5)
                    out["records"][rtype] = [r.to_text() for r in ans]
                except Exception:
                    pass
        except ImportError:
            out["records_note"] = "Install dnspython for MX/NS/TXT records: pip install dnspython"
    return out


def print_dns(d):
    section("DNS")
    if "error" in d:
        bad(f"Resolution failed: {d['error']}")
        return
    for ip in d["ips"]:
        kv("IP", ip, C.GREEN)
        kv("  reverse DNS", d["reverse"].get(ip) or "-")
    for rtype, vals in d["records"].items():
        for v in vals:
            kv(rtype, v[:100])
    if d.get("records_note"):
        info(d["records_note"])


# ------------------------------------------------------------------ HTTP ----
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None  # we follow redirects manually to record the chain


def http_request(url, timeout=8, max_body=300_000):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # we want to analyse sites with bad certs too
    opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=ctx))
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        r = opener.open(req, timeout=timeout)
    except urllib.error.HTTPError as e:
        r = e
    body = r.read(max_body)
    return {
        "status": r.getcode(),
        "headers": r.headers,
        "cookies": r.headers.get_all("Set-Cookie") or [],
        "body": body.decode("utf-8", "replace"),
    }


def fetch_chain(url, max_hops=10):
    chain = []
    for _ in range(max_hops):
        resp = http_request(url)
        chain.append({"url": url, "status": resp["status"]})
        loc = resp["headers"].get("Location")
        if resp["status"] in (301, 302, 303, 307, 308) and loc:
            url = urllib.parse.urljoin(url, loc)
            continue
        break
    resp["chain"] = chain
    resp["final_url"] = url
    return resp


def detect_tech(headers, cookies, body):
    tech = set()
    for h in ("Server", "X-Powered-By", "X-Generator", "Via"):
        if headers.get(h):
            tech.add(f"{h}: {headers.get(h)}")
    hl = {k.lower() for k in headers.keys()}
    header_sigs = {
        "cf-ray": "Cloudflare", "x-amz-cf-id": "AWS CloudFront", "x-vercel-id": "Vercel",
        "x-served-by": "Fastly/Varnish", "x-akamai-transformed": "Akamai",
        "x-drupal-cache": "Drupal", "x-shopify-stage": "Shopify",
    }
    for k, name in header_sigs.items():
        if k in hl:
            tech.add(name)
    cookie_text = " ".join(cookies)
    cookie_sigs = {
        "PHPSESSID": "PHP", "JSESSIONID": "Java", "ASP.NET_SessionId": "ASP.NET",
        "laravel_session": "Laravel", "csrftoken": "Django", "connect.sid": "Node/Express",
    }
    for k, name in cookie_sigs.items():
        if k in cookie_text:
            tech.add(name)
    body_sigs = {
        r"wp-content|wp-includes": "WordPress", r"/sites/default/files": "Drupal",
        r"Joomla!": "Joomla", r"cdn\.shopify\.com": "Shopify", r"jquery": "jQuery",
        r"react(\.min)?\.js|data-reactroot|__NEXT_DATA__": "React/Next.js",
        r"bootstrap": "Bootstrap", r"vue(\.min)?\.js|data-v-": "Vue.js",
        r"googletagmanager\.com": "Google Tag Manager", r"google-analytics\.com": "Google Analytics",
    }
    for pat, name in body_sigs.items():
        if re.search(pat, body, re.I):
            tech.add(name)
    gen = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body, re.I)
    if gen:
        tech.add(f"Generator: {gen.group(1)}")
    return sorted(tech)


def cookie_audit(cookies):
    results = []
    for c in cookies:
        name = c.split("=", 1)[0]
        low = c.lower()
        flags = {"Secure": "secure" in low, "HttpOnly": "httponly" in low, "SameSite": "samesite" in low}
        results.append({"name": name, **flags})
    return results


def http_info(base_urls):
    last_err = None
    for base in base_urls:
        try:
            resp = fetch_chain(base)
        except Exception as e:  # connection refused, timeout, DNS...
            last_err = f"{base} -> {e}"
            continue
        headers, body = resp["headers"], resp["body"]
        title = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
        sec = {h: headers.get(h) for h in SECURITY_HEADERS}
        extra = {}
        origin = urllib.parse.urlparse(resp["final_url"])
        root = f"{origin.scheme}://{origin.netloc}"
        for path in ("/robots.txt", "/sitemap.xml", "/.well-known/security.txt"):
            try:
                r = http_request(root + path, timeout=5, max_body=2000)
                found = r["status"] == 200 and "<html" not in r["body"][:300].lower()
                extra[path] = "found" if found else f"not found ({r['status']})"
                if found and path == "/robots.txt":
                    extra["robots_disallow"] = re.findall(r"(?im)^disallow:\s*(\S+)", r["body"])[:15]
            except Exception:
                extra[path] = "error"
        return {
            "base": base,
            "status": resp["status"],
            "final_url": resp["final_url"],
            "chain": resp["chain"],
            "title": re.sub(r"\s+", " ", title.group(1)).strip()[:120] if title else None,
            "server": headers.get("Server"),
            "content_type": headers.get("Content-Type"),
            "length": len(body),
            "headers": {k: v for k, v in headers.items()},
            "security_headers": sec,
            "cookies": cookie_audit(resp["cookies"]),
            "technologies": detect_tech(headers, resp["cookies"], body),
            "files": extra,
        }
    return {"error": last_err or "no response"}


def print_http(h):
    section("HTTP")
    if "error" in h:
        bad(f"Connection failed: {h['error']}")
        return
    color = C.GREEN if h["status"] == 200 else C.YELLOW
    kv("Status", h["status"], color)
    kv("Final URL", h["final_url"])
    if len(h["chain"]) > 1:
        kv("Redirect chain", " -> ".join(f"{c['status']}" for c in h["chain"]))
    kv("Title", h["title"] or "-")
    kv("Server", h["server"] or "hidden")
    kv("Content-Type", h["content_type"] or "-")
    kv("Body size", f"{h['length']} bytes (first 300KB max)")
    if h["technologies"]:
        kv("Technologies", ", ".join(h["technologies"]))
    print(f"\n  {C.BOLD}Security headers{C.END}")
    for name, val in h["security_headers"].items():
        if val:
            good(f"{name}: {val[:70]}")
        else:
            bad(f"{name} missing")
    if h["cookies"]:
        print(f"\n  {C.BOLD}Cookies{C.END}")
        for c in h["cookies"]:
            miss = [f for f in ("Secure", "HttpOnly", "SameSite") if not c[f]]
            (bad if miss else good)(f"{c['name']}" + (f" (missing: {', '.join(miss)})" if miss else ""))
    print(f"\n  {C.BOLD}Common files{C.END}")
    for path, status in h["files"].items():
        if path.startswith("/"):
            kv(path, status)
    if h["files"].get("robots_disallow"):
        kv("robots Disallow", ", ".join(h["files"]["robots_disallow"]))


# ------------------------------------------------------------------- TLS ----
def tls_info(host, port=443):
    out = {}
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                cert = s.getpeercert()
                out["verified"] = True
                out["protocol"], out["cipher"] = s.version(), s.cipher()[0]
                out["subject"] = dict(x[0] for x in cert.get("subject", ()))
                out["issuer"] = dict(x[0] for x in cert.get("issuer", ()))
                out["not_before"] = cert.get("notBefore")
                out["not_after"] = cert.get("notAfter")
                out["san"] = [v for _, v in cert.get("subjectAltName", ())]
                exp = ssl.cert_time_to_seconds(cert["notAfter"])
                out["days_left"] = int((exp - dt.datetime.now().timestamp()) / 86400)
    except ssl.SSLCertVerificationError as e:
        out["verified"] = False
        out["verify_error"] = e.verify_message
        try:  # still grab protocol/cipher
            bare = ssl.create_default_context()
            bare.check_hostname, bare.verify_mode = False, ssl.CERT_NONE
            with socket.create_connection((host, port), timeout=6) as sock:
                with bare.wrap_socket(sock, server_hostname=host) as s:
                    out["protocol"], out["cipher"] = s.version(), s.cipher()[0]
        except Exception:
            pass
    except Exception as e:
        out["error"] = str(e)
    return out


def print_tls(t):
    section("TLS / Certificate")
    if "error" in t:
        bad(f"No TLS: {t['error']}")
        return
    (good if t["verified"] else bad)("Certificate trusted" if t["verified"] else f"Verification failed: {t.get('verify_error')}")
    kv("Protocol", t.get("protocol", "-"), C.YELLOW if t.get("protocol") in ("TLSv1", "TLSv1.1") else "")
    kv("Cipher", t.get("cipher", "-"))
    if t.get("subject"):
        kv("Subject CN", t["subject"].get("commonName", "-"))
        kv("Issuer", t["issuer"].get("organizationName") or t["issuer"].get("commonName", "-"))
        kv("Valid until", t["not_after"])
        days = t["days_left"]
        kv("Days left", days, C.RED if days < 30 else C.GREEN)
        kv("Alt names", ", ".join(t["san"][:10]) + (" ..." if len(t["san"]) > 10 else ""))


# ------------------------------------------------------------ RDAP/WHOIS ----
def rdap_get(path):
    req = urllib.request.Request(f"https://rdap.org/{path}", headers={"User-Agent": UA, "Accept": "application/rdap+json"})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.loads(r.read().decode())


def rdap_info(host, is_ip):
    try:
        if is_ip:
            d = rdap_get(f"ip/{host}")
            return {
                "type": "ip", "name": d.get("name"), "country": d.get("country"),
                "range": f"{d.get('startAddress')} - {d.get('endAddress')}",
                "kind": d.get("type"),
            }
        labels = host.split(".")
        for i in range(len(labels) - 1):  # try host, then parent domains
            name = ".".join(labels[i:])
            try:
                d = rdap_get(f"domain/{name}")
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    continue
                raise
            events = {e["eventAction"]: e["eventDate"] for e in d.get("events", [])}
            registrar = None
            for ent in d.get("entities", []):
                if "registrar" in ent.get("roles", []):
                    for item in ent.get("vcardArray", [None, []])[1]:
                        if item[0] == "fn":
                            registrar = item[3]
            return {
                "type": "domain", "domain": d.get("ldhName"), "registrar": registrar,
                "status": d.get("status", []), "created": events.get("registration"),
                "expires": events.get("expiration"), "updated": events.get("last changed"),
                "nameservers": [n["ldhName"] for n in d.get("nameservers", [])],
            }
        return {"error": "domain not found in RDAP"}
    except Exception as e:
        return {"error": str(e)}


def print_rdap(r):
    section("WHOIS / RDAP")
    if "error" in r:
        bad(r["error"])
        return
    for k, v in r.items():
        if k == "type" or not v:
            continue
        kv(k.capitalize(), ", ".join(v) if isinstance(v, list) else v)


# ------------------------------------------------------------ subdomains ----
def subdomain_info(domain):
    """Passive discovery from certificate transparency logs (crt.sh)."""
    try:
        url = f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json"
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=25) as r:
            data = json.loads(r.read().decode())
        names = set()
        for row in data:
            for n in row.get("name_value", "").split("\n"):
                n = n.strip().lower()
                if n and not n.startswith("*"):
                    names.add(n)
        return sorted(names)
    except Exception as e:
        return {"error": str(e)}


def print_subdomains(s):
    section("Subdomains (crt.sh)")
    if isinstance(s, dict):
        bad(f"Failed: {s['error']}")
        return
    info(f"{len(s)} found")
    for n in s[:50]:
        print(f"    {n}")
    if len(s) > 50:
        info(f"... and {len(s) - 50} more (see --json output)")


# ------------------------------------------------------------ port scan -----
def parse_ports(spec):
    if spec == "common":
        return sorted(COMMON_PORTS)
    ports = set()
    for part in spec.split(","):
        if "-" in part:
            a, b = part.split("-")
            ports.update(range(int(a), int(b) + 1))
        else:
            ports.add(int(part))
    return sorted(p for p in ports if 0 < p < 65536)


def scan_ports(ip, ports, timeout=1.0, threads=100):
    def probe(p):
        try:
            with socket.create_connection((ip, p), timeout=timeout) as s:
                s.settimeout(1.0)
                banner = ""
                try:
                    if p in HTTP_PORTS:
                        s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    data = s.recv(256).decode("latin-1", "replace").strip()
                    banner = data.splitlines()[0][:100] if data else ""
                except OSError:
                    pass
                return {"port": p, "service": COMMON_PORTS.get(p, "unknown"), "banner": banner}
        except OSError:
            return None

    with cf.ThreadPoolExecutor(max_workers=threads) as ex:
        return sorted((r for r in ex.map(probe, ports) if r), key=lambda r: r["port"])


def print_ports(ip, results, total):
    section(f"Open ports on {ip} ({total} scanned)")
    if not results:
        info("No open ports found (or filtered by a firewall)")
    for r in results:
        good(f"{r['port']:<6}{r['service']:<14}{r['banner']}")


def run_nmap(ip):
    section("Nmap service scan")
    if not shutil.which("nmap"):
        bad("nmap not installed. Install it yourself (e.g. sudo apt install nmap) and re-run.")
        return None
    info("Running: nmap -sV -T4 --top-ports 100 (this can take a minute)")
    try:
        p = subprocess.run(["nmap", "-sV", "-T4", "--top-ports", "100", ip],
                           capture_output=True, text=True, timeout=300)
        print(p.stdout)
        return p.stdout
    except subprocess.TimeoutExpired:
        bad("nmap timed out")
        return None


# ------------------------------------------------------------------ main ----
def main():
    ap = argparse.ArgumentParser(
        description="Gather information about a website, domain or IP address. Use only with permission.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__.split("Examples:")[1].join(["Examples:", ""]) if "Examples:" in __doc__ else "",
    )
    ap.add_argument("target", nargs="?", help="URL, domain or IP")
    ap.add_argument("-u", "--url", help="Target (same as positional)")
    ap.add_argument("--ports", nargs="?", const="common", metavar="SPEC",
                    help="TCP port scan: 'common' (default), '1-1024', or '22,80,443'")
    ap.add_argument("--subdomains", action="store_true", help="Passive subdomain lookup (crt.sh)")
    ap.add_argument("--nmap", action="store_true", help="Run nmap service detection if installed")
    ap.add_argument("--all", action="store_true", help="Enable ports + subdomains")
    ap.add_argument("--skip", nargs="+", default=[], choices=["dns", "http", "tls", "whois"],
                    help="Skip modules")
    ap.add_argument("--json", metavar="FILE", help="Save full report as JSON")
    args = ap.parse_args()

    raw = args.url or args.target
    if not raw:
        ap.error("target required (e.g. recon.py example.com)")
    if args.all:
        args.ports = args.ports or "common"
        args.subdomains = True

    host, port, scheme, is_ip = parse_target(raw)
    report = {"target": raw, "host": host, "time": dt.datetime.now(dt.timezone.utc).isoformat()}

    print(f"{C.BOLD}Recon target: {host}{C.END}  {C.DIM}({'IP' if is_ip else 'domain'}){C.END}")
    if args.ports or args.nmap:
        print(f"{C.YELLOW}[!] Active scanning: make sure you are authorized to test this target.{C.END}")

    # DNS
    dns_data = dns_info(host, is_ip)
    report["dns"] = dns_data
    if "dns" not in args.skip:
        print_dns(dns_data)
    if "error" in dns_data:
        bad("Target does not resolve, stopping.")
        return

    # HTTP
    if "http" not in args.skip:
        netloc = f"[{host}]" if ":" in host else host
        if port:
            netloc += f":{port}"
        bases = [f"{scheme}://{netloc}"] if scheme in ("http", "https") else [f"https://{netloc}", f"http://{netloc}"]
        report["http"] = http_info(bases)
        print_http(report["http"])

    # TLS
    if "tls" not in args.skip and scheme != "http":
        report["tls"] = tls_info(host, port or 443)
        print_tls(report["tls"])

    # WHOIS / RDAP
    if "whois" not in args.skip:
        report["rdap"] = rdap_info(host if is_ip else host, is_ip)
        print_rdap(report["rdap"])

    # Subdomains
    if args.subdomains and not is_ip:
        report["subdomains"] = subdomain_info(host)
        print_subdomains(report["subdomains"])

    # Ports
    scan_ip = next((i for i in dns_data["ips"] if ":" not in i), dns_data["ips"][0])
    if args.ports:
        try:
            plist = parse_ports(args.ports)
        except ValueError:
            sys.exit(f"{C.RED}[-] Bad --ports value: {args.ports}{C.END}")
        report["ports"] = scan_ports(scan_ip, plist)
        print_ports(scan_ip, report["ports"], len(plist))
    if args.nmap:
        report["nmap"] = run_nmap(scan_ip)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, default=str)
        print(f"\n{C.GREEN}[+] Report saved to {args.json}{C.END}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{C.RED}[-] Interrupted{C.END}")
        sys.exit(130)