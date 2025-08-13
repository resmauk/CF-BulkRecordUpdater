#!/usr/bin/env python3
# cf_host_bulk.py — v2.2
# - Apex or subdomains
# - Prompt for token + visible target IPv4 (or pass flags)
# - Only touch A/AAAA at the exact FQDN
# - Optional SPF sync: replace ip4:OLD -> ip4:NEW in SPF TXT at host/apex/both
# - Skips hosts that are CNAMEs (unless --replace-cname)

import argparse, csv, getpass, ipaddress, re, sys, time, warnings, requests
from getpass import GetPassWarning

API_BASE = "https://api.cloudflare.com/client/v4"

# ---------- HTTP helpers ----------
def H(tok): return {"Authorization": f"Bearer {tok}", "Content-Type":"application/json"}

def cf_get(s, url, tok, params=None):
    r = s.get(url, headers=H(tok), params=params or {})
    r.raise_for_status(); return r.json()

def cf_post(s, url, tok, payload):
    r = s.post(url, headers=H(tok), json=payload)
    if r.status_code == 429:
        time.sleep(int(r.headers.get("Retry-After", "2") or "2")); r = s.post(url, headers=H(tok), json=payload)
    r.raise_for_status(); return r.json()

def cf_patch(s, url, tok, payload):
    r = s.patch(url, headers=H(tok), json=payload)
    if r.status_code == 429:
        time.sleep(int(r.headers.get("Retry-After", "2") or "2")); r = s.patch(url, headers=H(tok), json=payload)
    r.raise_for_status(); return r.json()

def cf_delete(s, url, tok):
    r = s.delete(url, headers=H(tok))
    if r.status_code == 429:
        time.sleep(int(r.headers.get("Retry-After", "2") or "2")); r = s.delete(url, headers=H(tok))
    r.raise_for_status(); return r.json()

# ---------- Cloudflare ops ----------
def verify_token(s, tok):
    j = cf_get(s, f"{API_BASE}/user/tokens/verify", tok); return bool(j.get("success"))

_zone_cache = {}
def get_zone_id_for_name(s, tok, zone_name):
    if zone_name in _zone_cache: return _zone_cache[zone_name]
    j = cf_get(s, f"{API_BASE}/zones", tok, params={"name": zone_name, "status": "active"})
    rid = j.get("result", [])
    zid = rid[0]["id"] if rid else None
    _zone_cache[zone_name] = zid
    return zid

def find_zone_for_fqdn(s, tok, fqdn):
    labels = fqdn.strip(".").split(".")
    for i in range(len(labels)):
        candidate = ".".join(labels[i:])
        zid = get_zone_id_for_name(s, tok, candidate)
        if zid: return candidate, zid
    return None, None

def list_dns(s, tok, zone_id, **params):
    out, page = [], 1
    while True:
        p = {"page": page, "per_page": 100}; p.update({k:v for k,v in (params or {}).items() if v not in (None,"",[])})
        j = cf_get(s, f"{API_BASE}/zones/{zone_id}/dns_records", tok, params=p)
        out.extend(j.get("result", []))
        info = j.get("result_info", {}) or {}
        if page >= info.get("total_pages", 1): break
        page += 1
    return out

# ---------- Utilities ----------
def norm(s: str) -> str:
    return (s or "").replace("\ufeff","").strip().lower()

def sniff_csv(path, forced_delim=None):
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        sample = f.read(4096) or ""
    if forced_delim:
        used = forced_delim
    else:
        try:
            used = csv.Sniffer().sniff(sample, delimiters=[",",";","\t","|"]).delimiter
        except csv.Error:
            used = ","
    with open(path, "r", encoding="utf-8-sig", newline="") as f:
        reader = csv.DictReader(f, delimiter=used)
        raw_headers = reader.fieldnames or []
    hdrmap = {h: norm(h) for h in raw_headers}
    return used, raw_headers, hdrmap

def pick_host_key(raw_headers, hdrmap):
    for raw in raw_headers:
        if hdrmap.get(raw) in {"domain","host","hostname","fqdn","zone","name","apex","root","record"}:
            return raw
    return None

def prompt_token():
    print("Enter your Cloudflare API token. Input is hidden; paste and press Enter.")
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", category=GetPassWarning)
            t = getpass.getpass("Token: ").strip()
    except Exception:
        t = ""
    if not t:
        print("Hidden input empty; falling back to visible input."); t = input("Token (VISIBLE): ").strip()
    return t

def validate_ipv4(s):
    try:
        ip = ipaddress.ip_address(s); 
        if ip.version != 4: raise ValueError("Not IPv4")
        return str(ip)
    except Exception:
        raise argparse.ArgumentTypeError(f"Invalid IPv4 address: {s}")

# ---------- SPF sync ----------
def spf_replace_ip4_tokens(text, old_ips, new_ip):
    """
    Replace ip4:OLD -> ip4:NEW; if NEW already present, remove OLD.
    Preserve other mechanisms; handle optional /32 suffix on OLD.
    """
    if "v=spf1" not in text.lower(): 
        return text, False

    changed = False
    # Ensure we don't double-add
    new_token = f"ip4:{new_ip}"
    have_new = re.search(rf"(?<![\w:]){re.escape(new_token)}(?![\w./])", text) is not None

    def repl(m):
        nonlocal changed
        prefix = m.group(1) or ""  # leading space or start
        old_ip = m.group(2)
        cidr  = m.group(3) or ""
        # If new already exists, drop the old token; else replace with new
        if have_new:
            changed = True
            return prefix  # remove old token
        # keep any /mask ONLY if it's '/32'
        rep = new_token + ("/32" if cidr == "/32" else "")
        changed = True
        return prefix + rep

    # match tokens like: [start/space]ip4:1.2.3.4[/32][space/end]
    pattern = rf'(^|\s)ip4:({"|".join(map(re.escape, old_ips))})(/32)?(?=$|\s)'
    new_text = re.sub(pattern, repl, text)
    # Compact multiple spaces
    new_text = re.sub(r"\s+", " ", new_text).strip()
    return new_text, changed

def spf_sync_for_names(session, token, zone_id, names, old_ips, new_ip, dry_run):
    """
    For each DNS name in `names`, find TXT SPF and update ip4:OLD -> ip4:NEW.
    Returns (num_edited, details[])
    """
    edited = 0
    details = []
    for name in names:
        txts = [r for r in list_dns(session, token, zone_id, name=name, type="TXT") if r.get("name")==name]
        for rec in txts:
            content = rec.get("content","") or ""
            if "v=spf1" not in content.lower():
                continue
            new_content, changed = spf_replace_ip4_tokens(content, old_ips, new_ip)
            if not changed:
                continue
            details.append(f"{name}: SPF edit")
            if not dry_run:
                payload = {"type":"TXT","name":name,"content":new_content,"ttl":rec.get("ttl",1)}
                cf_patch(session, f"{API_BASE}/zones/{zone_id}/dns_records/{rec['id']}", token, payload)
            edited += 1
    return edited, details

# ---------- Main ----------
def main():
    ap = argparse.ArgumentParser(
        description="Bulk update A and delete AAAA for hostnames (apex or subdomains) in Cloudflare. Optional SPF ip4 sync.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  py cf_host_bulk.py .\\hosts.csv --dry-run
  py cf_host_bulk.py .\\hosts.csv --yes
  py cf_host_bulk.py .\\hosts.csv --ip 203.0.113.10
  py cf_host_bulk.py .\\hosts.csv --token cf_XXXX
  py cf_host_bulk.py .\\hosts.csv --csv-delim ';'
  py cf_host_bulk.py .\\hosts.csv --keep-aaaa
  py cf_host_bulk.py .\\hosts.csv --update-all-a
  py cf_host_bulk.py .\\hosts.csv --replace-cname
  py cf_host_bulk.py .\\hosts.csv --spf-sync --spf-scope both
        """
    )
    ap.add_argument("csv_path", help="CSV with hostnames. Header can be: domain, host, hostname, fqdn, zone, name, apex, root, record.")
    ap.add_argument("--ip", type=validate_ipv4, default=None, help="Target IPv4 for A records. If omitted, you'll be prompted.")
    ap.add_argument("--report", default="cf_host_report.csv", help="Output report CSV.")
    ap.add_argument("--dry-run", action="store_true", help="Plan only; no changes.")
    ap.add_argument("--yes", action="store_true", help="Skip confirmation prompt.")
    ap.add_argument("--token", default=None, help="Cloudflare API token (overrides interactive prompt).")
    ap.add_argument("--csv-delim", default=None, help="Force CSV delimiter, e.g. ',' or ';'")
    ap.add_argument("--update-all-a", action="store_true", help="Update ALL A records at that FQDN (default: only the first).")
    ap.add_argument("--keep-aaaa", action="store_true", help="Do NOT delete AAAA records at that FQDN.")
    ap.add_argument("--replace-cname", action="store_true", help="If FQDN is a CNAME, delete it and create an A (default: skip).")
    # SPF options
    ap.add_argument("--spf-sync", action="store_true", help="Also update SPF TXT: replace ip4:OLD_A_IP -> ip4:NEW_IP where found.")
    ap.add_argument("--spf-scope", choices=["host","apex","both"], default="host",
                    help="Where to search/patch SPF TXT: only the host, only the zone apex, or both. Default: host.")
    args = ap.parse_args()

    # Token & IP
    token = args.token or prompt_token()
    if not token:
        print("No token provided.", file=sys.stderr); sys.exit(2)
    if args.ip is None:
        shown = input("Enter target IPv4 address (visible): ").strip()
        args.ip = validate_ipv4(shown)

    # Explain
    print("\nPlan:")
    print(f" • Set A → {args.ip} at each FQDN in CSV (apex or subdomains).")
    print(" • Delete AAAA at that FQDN." if not args.keep_aaaa else " • Keep AAAA unchanged.")
    print(" • Skip if the FQDN is a CNAME (unless --replace-cname).")
    if args.spf_sync:
        where = {"host":"the FQDN only","apex":"the zone apex only","both":"both the FQDN and the zone apex"}[args.spf_scope]
        print(f" • SPF sync enabled: in {where}, replace any ip4:<OLD_A_IP> with ip4:{args.ip}.")
    else:
        print(" • SPF unchanged (add --spf-sync to update ip4: tokens in SPF).")
    print(" • No other record types are modified.\n")

    if not args.yes:
        if input("Proceed? (y/N): ").strip().lower() not in ("y","yes"):
            print("Aborted."); sys.exit(0)

    s = requests.Session(); s.headers.update({"User-Agent": "cf-host-bulk/2.2"})

    # Verify token
    if not verify_token(s, token):
        print("[FATAL] Token verify failed. Ensure API Token has Zone:Read + DNS:Edit.", file=sys.stderr); sys.exit(2)
    print("[OK] Token verified.")

    # CSV prep
    try:
        used_delim, raw_headers, hdrmap = sniff_csv(args.csv_path, args.csv_delim)
    except Exception as e:
        print(f"[FATAL] CSV read/sniff failed: {e}", file=sys.stderr); sys.exit(2)
    print(f"[INFO] Detected delimiter: '{used_delim}'")
    print(f"[INFO] Headers: {raw_headers}")
    host_key = pick_host_key(raw_headers, hdrmap)
    if not host_key:
        print("[FATAL] No usable hostname column. Use one of: domain, host, hostname, fqdn, zone, name, apex, root, record.", file=sys.stderr)
        sys.exit(2)
    print(f"[INFO] Using hostname column: '{host_key}'")

    # Run
    with open(args.csv_path, "r", encoding="utf-8-sig", newline="") as f_in, \
         open(args.report, "w", encoding="utf-8", newline="") as rep:

        reader = csv.DictReader(f_in, delimiter=used_delim)
        writer = csv.DictWriter(rep, fieldnames=[
            "fqdn","zone_name","zone_id","action_a","old_a","new_a","a_proxied","a_ttl","aaaa_deleted","spf_edits","notes","error"
        ])
        writer.writeheader()

        for row in reader:
            if not any((v or "").strip() for v in row.values()):
                continue

            fqdn = (row.get(host_key, "") or "").strip().rstrip(".")
            ttl_str = (row.get("ttl","") or row.get("TTL","") or "").strip()
            proxied_str = (row.get("proxied","") or row.get("Proxied","") or "").strip()

            notes, error = [], ""
            action_a, old_a, a_proxied, a_ttl = "", "", "", ""
            aaaa_deleted = 0
            spf_edits = 0

            if not fqdn:
                writer.writerow({"fqdn":"", "error":"missing hostname"}); continue

            print(f"\n=== {fqdn} ===")
            try:
                zone_name, zid = find_zone_for_fqdn(s, token, fqdn)
                if not zid:
                    error = "no matching zone in this account (or not Active)"
                    print(f"[ERROR] {error}")
                    writer.writerow({"fqdn":fqdn, "zone_name":"", "zone_id":"", "error":error})
                    continue

                # If host is a CNAME
                cname = [r for r in list_dns(s, token, zid, name=fqdn, type="CNAME") if r.get("name")==fqdn]
                if cname and not args.replace_cname:
                    print(f"[SKIP] FQDN is a CNAME → {cname[0].get('content','')}. Use --replace-cname to convert.")
                    writer.writerow({"fqdn":fqdn, "zone_name":zone_name, "zone_id":zid, "notes":"CNAME present; skipped"})
                    continue

                # TTL/proxied parse
                ttl_val = None
                if ttl_str:
                    try: ttl_val = int(ttl_str)
                    except: notes.append("ttl not integer; ignored")
                def parse_bool(v):
                    if (v or "").strip() == "": return None
                    return (v or "").strip().lower() in ("1","true","yes","y")
                proxied_override = parse_bool(proxied_str)

                # If replacing CNAME, delete it now
                if cname and args.replace_cname and not args.dry_run:
                    for rec in cname:
                        print(f"[PLAN] Delete CNAME {fqdn} → {rec.get('content','')}")
                        cf_delete(s, f"{API_BASE}/zones/{zid}/dns_records/{rec['id']}", token)

                # Gather A/AAAA at FQDN
                a_recs    = [r for r in list_dns(s, token, zid, name=fqdn, type="A")    if r.get("name")==fqdn and r.get("type")=="A"]
                aaaa_recs = [r for r in list_dns(s, token, zid, name=fqdn, type="AAAA") if r.get("name")==fqdn and r.get("type")=="AAAA"]

                # Determine which A records we update (collect old IPs for SPF sync)
                old_ips = []
                if a_recs:
                    targets = a_recs if args.update_all_a else [a_recs[0]]
                    for idx, rec in enumerate(targets, 1):
                        old_a = rec.get("content",""); 
                        if old_a: old_ips.append(old_a)
                        payload = {
                            "type":"A","name":fqdn,"content":args.ip,
                            "proxied": rec.get("proxied", False) if proxied_override is None else proxied_override,
                            "ttl": rec.get("ttl", 1) if ttl_val is None else ttl_val
                        }
                        a_proxied = str(payload["proxied"]); a_ttl = str(payload["ttl"])
                        action_a = "update"
                        print(f"[PLAN] Update A {idx}/{len(targets)}: {old_a} → {args.ip} (proxied={a_proxied}, ttl={a_ttl})")
                        if not args.dry_run:
                            cf_patch(s, f"{API_BASE}/zones/{zid}/dns_records/{rec['id']}", token, payload)
                else:
                    payload = {
                        "type":"A","name":fqdn,"content":args.ip,
                        "proxied": proxied_override if proxied_override is not None else False,
                        "ttl": ttl_val if ttl_val is not None else 1
                    }
                    a_proxied = str(payload["proxied"]); a_ttl = str(payload["ttl"])
                    action_a = "create"
                    print(f"[PLAN] Create A: {fqdn} → {args.ip} (proxied={a_proxied}, ttl={a_ttl})")
                    if not args.dry_run:
                        cf_post(s, f"{API_BASE}/zones/{zid}/dns_records", token, payload)

                # AAAA: delete unless kept
                if not args.keep_aaaa:
                    for rec in aaaa_recs:
                        print(f"[PLAN] Delete AAAA: {rec.get('content')}")
                        if not args.dry_run:
                            cf_delete(s, f"{API_BASE}/zones/{zid}/dns_records/{rec['id']}", token)
                        aaaa_deleted += 1

                # SPF sync (only if we have old IPs to swap)
                if args.spf_sync and old_ips:
                    names = []
                    if args.spf_scope in ("host","both"): names.append(fqdn)
                    if args.spf_scope in ("apex","both"): names.append(zone_name)
                    edits, details = spf_sync_for_names(s, token, zid, names, old_ips, args.ip, args.dry_run)
                    spf_edits += edits
                    for d in details:
                        print(f"[PLAN] {d} (ip4: old→new)")

                writer.writerow({
                    "fqdn": fqdn, "zone_name": zone_name, "zone_id": zid,
                    "action_a": action_a, "old_a": old_a, "new_a": args.ip,
                    "a_proxied": a_proxied, "a_ttl": a_ttl,
                    "aaaa_deleted": aaaa_deleted,
                    "spf_edits": spf_edits,
                    "notes": "; ".join(notes), "error": error
                })

            except requests.HTTPError as e:
                code = getattr(e.response,"status_code","?")
                body = getattr(e.response,"text",str(e))[:250]
                print(f"[HTTP ERROR] {code}: {body}")
                writer.writerow({"fqdn":fqdn, "zone_name":"", "zone_id":"", "error": f"HTTP {code} {body}"})
            except Exception as e:
                print(f"[EXC] {e}")
                writer.writerow({"fqdn":fqdn, "zone_name":"", "zone_id":"", "error": str(e)})

    print("\nDone. See report:", args.report)

if __name__ == "__main__":
    main()
