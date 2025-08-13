# CF-BulkApexUpdater
Connects to Cloudflare API and update A Record and SPF record IP4 address from an old address to a new one. Aimed at usage for whole server migrations

# cf\_host\_bulk

> Bulk-update Cloudflare DNS **A** records (apex or subdomains), optionally delete **AAAA**, and (optionally) **sync SPF** `TXT v=spf1` entries by swapping `ip4:OLD → ip4:NEW`.

<p align="left">
  <a href="https://www.python.org/"><img alt="Python 3.9+" src="https://img.shields.io/badge/Python-3.9+-blue.svg"></a>
  <img alt="Platform" src="https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey">
  <img alt="Status" src="https://img.shields.io/badge/Status-Production%20Ready-brightgreen">
</p>

---

## ✨ What it does

For each hostname (FQDN) in your CSV:

1. **Finds the correct Cloudflare zone** by walking up labels (`a.b.example.com → example.com → com`) until a zone in your account is found.
2. **A record** at that exact FQDN

   * If present → **update** to your target IPv4
   * If absent → **create** it
3. **AAAA record** at that FQDN

   * **Delete** (default) or **keep** with `--keep-aaaa`
4. **SPF sync (optional)**

   * If enabled, and an SPF TXT at the FQDN and/or apex contains `ip4:<OLD_A_IP>`, replace it with `ip4:<NEW_IP>` (or remove `OLD` if `NEW` already exists)
5. **Safety rails**

   * **Never** touches TXT/MX/CNAME/etc. (except SPF TXT when `--spf-sync` is on)
   * If the FQDN is a **CNAME**, it **skips** (or converts to A only if you pass `--replace-cname`)

---

## 🧰 Requirements

* **Python 3.9+**
* `requests`:

  ```bash
  python -m pip install --user requests
  ```
* **Cloudflare API Token** (not the global key) with least privilege:

  * Permissions: `Zone:Read` + `DNS:Edit`
  * Zone Resources: restrict to the zones you’ll modify

---

## 📦 Files

* `cf_host_bulk.py` — the script
* `hosts.csv` — your input CSV
* `cf_host_report.csv` — output audit trail (created by the script)

---

## 📄 CSV format

Header can be any one of:
`domain`, `host`, `hostname`, `fqdn`, `zone`, `name`, `apex`, `root`, `record`.

Optional columns:

* `ttl` (seconds; blank = “Auto”)
* `proxied` (`true`/`false`; blank = preserve existing on update, `false` on create)

**Example (comma-separated):**

```csv
host,ttl,proxied
example.com,,
api.example.com,300,true
status.example.co.uk,120,false
```

> If Excel saved with semicolons, add `--csv-delim ';'`.

---

## 🚀 Quick start (Windows)

```powershell
# 1) In the folder with cf_host_bulk.py and hosts.csv
py -m pip install --user requests

# 2) Dry run (no changes – see plan)
py .\cf_host_bulk.py .\hosts.csv --dry-run

# 3) Execute (with confirmation)
py .\cf_host_bulk.py .\hosts.csv

# 4) Non-interactive (e.g., CI/RMM)
py .\cf_host_bulk.py .\hosts.csv --token cf_XXXX --ip 203.0.113.10 --yes
```

---

## 🔄 New in v2.3

* **`--change-www-a`** — Also update/create the **A** record for `www.<zone_apex>` to the same target IP.

  * Skips if `www` is a **CNAME** (unless you pass `--replace-cname`).
  * Respects `--update-all-a` and your `ttl` / `proxied` overrides.
  * **Does not** touch AAAA for `www` (by design).

---

## 🧪 Examples

* Basic plan:

  ```powershell
  py .\cf_host_bulk.py .\hosts.csv --dry-run
  ```
* Update all A’s and keep IPv6:

  ```powershell
  py .\cf_host_bulk.py .\hosts.csv --update-all-a --keep-aaaa
  ```
* Convert CNAME → A and sync SPF at both host and apex:

  ```powershell
  py .\cf_host_bulk.py .\hosts.csv --replace-cname --spf-sync --spf-scope both
  ```
* **Plan only, including updating `www.<zone_apex>` A**:

  ```powershell
  py .\cf_host_bulk.py .\hosts.csv --change-www-a --dry-run
  ```
* **Real run, updating `www` and converting any `www` CNAME → A**:

  ```powershell
  py .\cf_host_bulk.py .\hosts.csv --change-www-a --replace-cname
  ```
* **Non-interactive (CI/RMM): update FQDNs + `www` A**:

  ```powershell
  py .\cf_host_bulk.py .\hosts.csv --change-www-a --ip 209.42.18.118 --token cf_XXXX --yes
  ```

---

## 🧯 Safety notes (read before production)

* **CNAME at FQDN**: Skipped by default. Converting with `--replace-cname` may break CDN/vendor setups depending on that CNAME.
* **IPv6 removal**: Default deletes AAAA (forces IPv4-only). Use `--keep-aaaa` for dual-stack.
* **Multiple A records**: If you intentionally use multiple A’s, add `--update-all-a`.
* **Propagation**: Plan a change window; DNS propagation applies.
* **Permissions**: Token must have `Zone:Read` & `DNS:Edit` on target zones.
* **`--change-www-a`** does **not** modify AAAA for `www.<zone_apex>`; only the **A** record is created/updated.

---

## 🖥️ Command-line reference

Run `--help` anytime:

```bash
py .\cf_host_bulk.py --help
```

| Flag                           |              Default | Purpose                                                                        | Example             |
| ------------------------------ | -------------------: | ------------------------------------------------------------------------------ | ------------------- |
| `CSV_PATH`                     |           (required) | Path to input CSV                                                              | `.\hosts.csv`       |
| `--ip IPv4`                    |               prompt | Target IPv4 for A records (validated)                                          | `--ip 203.0.113.10` |
| `--token TOKEN`                |               prompt | Cloudflare **API Token** (Bearer)                                              | `--token cf_XXXX`   |
| `--report PATH`                | `cf_host_report.csv` | Output audit CSV                                                               | `--report out.csv`  |
| `--dry-run`                    |                  off | Show plan only; no changes                                                     | `--dry-run`         |
| `--yes`                        |                  off | Skip confirmation prompt                                                       | `--yes`             |
| `--csv-delim CHAR`             |                 auto | Force CSV delimiter                                                            | `--csv-delim ';'`   |
| `--keep-aaaa`                  |                  off | Do **not** delete AAAA (keep IPv6)                                             | `--keep-aaaa`       |
| `--update-all-a`               |                  off | Update **all** A records at the FQDN                                           | `--update-all-a`    |
| `--replace-cname`              |                  off | If FQDN is CNAME, delete it and create an A                                    | `--replace-cname`   |
| `--spf-sync`                   |                  off | Edit SPF TXT: swap `ip4:OLD → ip4:NEW`                                         | `--spf-sync`        |
| `--spf-scope {host,apex,both}` |               `host` | Where to patch SPF TXT                                                         | `--spf-scope both`  |
| `--change-www-a`               |                  off | Also update/create **A** for `www.<zone_apex>` to the new IP (no AAAA changes) | `--change-www-a`    |

---

## 🧠 How SPF sync works (`--spf-sync`)

* Captures the **old A IPs** that were actually updated at each FQDN.
* Searches SPF TXT at:

  * `host` → the FQDN only
  * `apex` → the zone apex only
  * `both` → both places
* For any `v=spf1` record found:

  * Replaces `ip4:<OLD>` with `ip4:<NEW>`
  * If `<NEW>` already present, **removes** the old `ip4:<OLD>` token (prevents duplicates)
* Doesn’t touch other mechanisms (`include:`, `mx`, `a`, etc.) and **does not** chase `include:` chains.

> If your SPF is centrally managed (via `include:`), consider leaving SPF alone here.

---

## 📤 Output report (`cf_host_report.csv`)

Columns:

* `fqdn` — processed hostname
* `zone_name`, `zone_id` — resolved Cloudflare zone
* `action_a` — `create` / `update` (blank if skipped)
* `old_a`, `new_a` — previous and new A values
* `a_proxied`, `a_ttl` — final values applied
* `aaaa_deleted` — count deleted (0 if `--keep-aaaa`)
* `spf_edits` — number of SPF TXT edits
* `notes`, `error` — extra info

---

## 🔍 Typical console output

```
[OK] Token verified.
[INFO] Detected delimiter: ','
[INFO] Headers: ['host','ttl','proxied']

=== api.example.com ===
[PLAN] Update A 1/1: 198.51.100.23 → 203.0.113.10 (proxied=True, ttl=300)
[PLAN] Delete AAAA: 2001:db8::1234
[PLAN] api.example.com: SPF edit (ip4: old→new)   # only with --spf-sync
```

CNAME case (skipped by default):

```
=== www.example.com ===
[SKIP] FQDN is a CNAME → target.example.net. Use --replace-cname to convert.
```

---

## 🧭 Troubleshooting

<details>
<summary><b>Token prompt seems to “do nothing”</b></summary>

* In Windows Terminal/PowerShell, paste is hidden; press **Enter** after pasting.
* Or pass `--token cf_XXXX` on the command line for visible input.

</details>

<details>
<summary><b>“no matching zone in this account (or not Active)”</b></summary>

* The FQDN doesn’t belong to any zone your token can access, or the zone isn’t **Active**.
* Ensure you used an **API Token** (not global key) with `Zone:Read` + `DNS:Edit` and correct zone scoping.

</details>

<details>
<summary><b>“Skipping row with empty hostname”</b></summary>

* Ensure the CSV header is one of: `domain`, `host`, `hostname`, `fqdn`, `zone`, `name`, `apex`, `root`, `record`.
* EU/UK locales often save with `;` → use `--csv-delim ';'`.

</details>

<details>
<summary><b>403/401 errors</b></summary>

* Wrong credential type or missing permissions. Use an **API Token**, not a global key.

</details>

<details>
<summary><b>CNAME skipped but you expected an A</b></summary>

* Use `--replace-cname` to remove the CNAME and create an A (make sure this won’t break upstream/CDN).

</details>

---

## 🔁 Rollback

Re-run with the **previous** IP:

```powershell
py .\cf_host_bulk.py .\hosts.csv --ip 198.51.100.23 --yes
```

If you used `--spf-sync`, running again with the old IP as target will swap `ip4:NEW → ip4:OLD`.

---

## 🔐 Security

* Treat API tokens like passwords.
* Prefer short-lived, least-privileged tokens.
* Don’t store tokens in repos; use the prompt or a secure secret store.

---

## 🤝 Contributing

Issues and PRs welcome. If you need a **PowerShell** edition (better for RMM variable injection), open an issue and we’ll mirror the flags/behavior.

---

## 📝 License

MIT (or your preferred license – add a `LICENSE` file).
