import os
import re
import csv
import smtplib
import requests
from bs4 import BeautifulSoup
from datetime import datetime
from collections import defaultdict, Counter
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from io import StringIO
from html import unescape

# =========================
# CONFIG
# =========================
blog_urls = [
    "https://www.borncity.com/blog/",
    "https://www.allianz-fuer-cybersicherheit.de/SiteGlobals/Forms/Suche/BSI/Sicherheitswarnungen/Sicherheitswarnungen_Formular.html?nn=145684&cl2Categories_DocType=callforbids/",
    "https://support.sophos.com/support/s/?language=en_US#t=AllTab&sort=relevancy/",
    "https://wid.cert-bund.de/portal/wid/kurzinformationen/",
    "https://euvd.enisa.europa.eu/"
]

keywords = [
    # Vendors & products
    "Cisco","Microsoft","Windows","Linux","Apache","Nginx","Fortinet","Palo Alto","Sophos","Trend Micro",
    "VMware","Citrix","Oracle","SAP","Exchange","Outlook","SharePoint","Teams",
    # Threats & vulns
    "vulnerability","exploit","malware","zero-day","threat","ransomware","phishing","trojan","spyware",
    "backdoor","rootkit","botnet","CVE","remote code execution","privilege escalation","denial of service",
    "DoS","DDoS","compromise","data leak","exfiltration",
    # Security concepts
    "Active Directory","LDAP","Kerberos","VPN","Firewall","Proxy","DNS","Cloud","Azure","AWS","Google Cloud",
    "SIEM","SOC","EDR","XDR","IAM","MFA","SSO","TLS","SSL","MITRE ATT&CK","NIST","ISO 27001",
    # TTPs & tools
    "Brute force","SQL injection","XSS","CSRF","Metasploit","Cobalt Strike","Mimikatz","PowerShell",
    "Living off the Land","LOLBins",
    # General
    "incident","breach","patch","update","hotfix","security advisory"
]

# Critical keywords
critical_keywords = {
    "zero-day", "exploit", "ransomware",
    "remote code execution", "privilege escalation", "CVE"
}

# Map vendors to owner/team labels (optional; used in recs)
vendor_labels = {
    "Microsoft": "Windows/Office owners (WSUS/Intune)",
    "VMware": "VM/Hypervisor team",
    "Citrix": "NetScaler/VDI team",
    "Fortinet": "Network/Security team (FortiGate/PSIRT)",
    "Sophos": "Endpoint/Firewall team",
    "SAP": "SAP Basis team",
    "Trend Micro": "Endpoint Security team",
    "Cisco": "Network team",
    "Palo Alto": "Network/Security team",
    "Nginx": "Web/Infra team",
    "Apache": "Web/Infra team",
}

headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}

SMTP_SERVER = "grp-ex01.vivavis.int"
SMTP_PORT = 25
SENDER_EMAIL = "Schwachstellenmanagment@vivavis.com"
RECIPIENTS = ["Jagankumar.Kothandan@Vivavis.com"]

# =========================
# HELPERS
# =========================
CVE_REGEX = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

def is_critical(kw: str) -> bool:
    return kw.lower() in {k.lower() for k in critical_keywords}

def normalize_kw(kw: str) -> str:
    return kw.strip()

def extract_links_and_titles(soup, base_url):
    """Return a list of (title, href) tuples; safely handle relative links."""
    items = []
    seen = set()
    for a in soup.find_all("a"):
        title = (a.get_text(" ", strip=True) or "").strip()
        href = a.get("href") or ""
        if not href:
            continue
        href = unescape(href)
        if href.startswith("//"):
            href = f"https:{href}"
        elif href.startswith("/"):
            from urllib.parse import urljoin
            href = urljoin(base_url, href)
        key = (title[:160], href)
        if key in seen:
            continue
        seen.add(key)
        items.append(key)
    return items

def check_blogs_for_keywords():
    matches_per_source = defaultdict(lambda: {"keywords": set(), "hits": []})
    keyword_counter = Counter()
    cve_ids = set()

    for url in blog_urls:
        try:
            resp = requests.get(url, headers=headers, timeout=20)
            resp.raise_for_status()
            html = resp.text
            soup = BeautifulSoup(html, "html.parser")
            text = soup.get_text(" ", strip=True)
            text_lc = text.lower()

            found = set()
            for kw in keywords:
                if kw.lower() in text_lc:
                    kw_norm = normalize_kw(kw)
                    found.add(kw_norm)
                    keyword_counter[kw_norm] += 1

            for m in CVE_REGEX.findall(text):
                cve = m.upper()
                cve_ids.add(cve)
                # keep "CVE" metric for dashboards
                keyword_counter["CVE"] += 1

            # find representative links with those keywords in title text
            hits = []
            if found:
                for title, href in extract_links_and_titles(soup, url):
                    tl = title.lower()
                    hit_kws = sorted({kw for kw in found if kw.lower() in tl})
                    if hit_kws:
                        hits.append({
                            "title": title[:160],
                            "url": href,
                            "keywords": hit_kws,
                            "critical": any(is_critical(k) for k in hit_kws)
                        })

            if found:
                matches_per_source[url]["keywords"].update(found)
                # prefer critical hits, then density of matched kws
                hits_sorted = sorted(
                    hits,
                    key=lambda h: (not h["critical"], -len(h["keywords"]), h["title"])
                )
                matches_per_source[url]["hits"] = hits_sorted[:10]

        except Exception as e:
            print(f"Error fetching {url}: {e}")

    # finalize keyword sets
    for src in matches_per_source:
        matches_per_source[src]["keywords"] = sorted(
            matches_per_source[src]["keywords"],
            key=lambda k: (not is_critical(k), k.lower())
        )
    return matches_per_source, keyword_counter, sorted(cve_ids)

# =========================
# DYNAMIC RECOMMENDATIONS
# =========================
def assess_severity(keyword_counter, cve_ids):
    """Score & label overall severity for the digest."""
    weights = {
        "zero-day": 5,
        "ransomware": 5,
        "remote code execution": 5,
        "exploit": 4,
        "privilege escalation": 4,
        "CVE": 3,
    }
    score = 0
    for k, c in keyword_counter.items():
        score += weights.get(k.lower(), 0) * c
    score += min(len(cve_ids), 5)  # bounded CVE bonus

    critical_hits = sum(c for k, c in keyword_counter.items() if is_critical(k))
    if score >= 10 or critical_hits >= 4:
        return "CRITICAL"
    if score >= 4 or critical_hits >= 1:
        return "HIGH"
    return "INFO"

def generate_recommendations(matches, keyword_counter, cve_ids):
    """Return an ordered list of context-aware recommendation strings."""
    kws = {k.lower() for k in keyword_counter.keys()}
    vendors_detected = [v for v in vendor_labels if v.lower() in kws or any(v.lower() in k.lower() for k in kws)]

    recs = []
    add = recs.append

    # Global priorities driven by threats
    if any(k in kws for k in ("zero-day",)):
        add("Prioritize zero-day items: apply vendor mitigations immediately; reduce exposure (disable vulnerable features, restrict WAN access, enable WAF/IPS virtual patching) within 24h.")
    if any(k in kws for k in ("remote code execution", "exploit")):
        add("Treat RCE/exploit indicators as emergency: identify affected services, restrict access (ACL/geo/IP allowlist), and fast-track patch validation & deployment.")
    if "ransomware" in kws:
        add("Ransomware indicators: verify last successful, immutable backups; review EDR detections and isolate suspicious hosts; update detection content and block IoCs.")
    if "privilege escalation" in kws:
        add("Privilege escalation risk: review admin accounts & recent privilege changes; enforce MFA; rotate credentials/tokens where applicable.")
    if "phishing" in kws:
        add("Phishing mentions: reinforce mail filtering rules, block observed sender domains/URLs, and brief helpdesk on potential surge of user reports.")

    # CVE-specific workflow
    if cve_ids:
        add(f"Validate CVE impact: match {len(cve_ids)} CVE(s) against your asset inventory; if affected, open change tickets and plan emergency patching.")
        add("Check vendor advisories and known exploited catalogs; monitor for exploit activity while patching is in progress.")

    # Vendor playbooks (lightweight routing)
    if vendors_detected:
        targets = ", ".join(f"{v} → {vendor_labels[v]}" for v in vendors_detected)
        add(f"Notify product owners: {targets}. Request assessment of affected versions and current patch status.")
    if "microsoft" in {v.lower() for v in vendors_detected} or "windows" in kws:
        add("For Microsoft items: review the latest Patch Tuesday/Out-of-band advisories; validate via WSUS/Intune rings; consider temporary hardening (ASR rules).")
    if "vmware" in {v.lower() for v in vendors_detected}:
        add("For VMware items: check VMSA advisories; restrict management interfaces; snapshot & patch maintenance windows.")
    if "citrix" in {v.lower() for v in vendors_detected}:
        add("For Citrix/NetScaler: verify ADM/NS appliance exposure; apply updated builds; enforce gateway hardening (MFA, rate limiting).")
    if "fortinet" in {v.lower() for v in vendors_detected}:
        add("For Fortinet: review PSIRT bulletins; ensure IPS signatures are current; restrict administrative access on WAN.")
    if "sap" in {v.lower() for v in vendors_detected}:
        add("For SAP: check latest SAP Security Notes; coordinate with SAP Basis for patch scheduling and regression testing.")

    # Infra/service hardening if network terms appear
    if any(k in kws for k in ("vpn", "firewall", "ssl", "tls", "dns", "proxy")):
        add("Network exposure: verify admin services are not exposed on WAN; enforce MFA and restrict access via VPN or IP allowlists.")

    # If nothing critical but still findings
    if not recs:
        add("Monitor for updates: no immediate action required; recheck vendor advisories and schedule normal patch cycle.")

    # Deduplicate & order by importance (simple heuristic)
    seen = set()
    ordered = []
    for r in recs:
        if r not in seen:
            ordered.append(r)
            seen.add(r)
    return ordered

# =========================
# EMAIL BUILDERS
# =========================
def build_html_email(matches, keyword_counter, cve_ids):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total_hits = sum(keyword_counter.values())
    unique_keywords = len(keyword_counter)
    critical_count = sum(c for k, c in keyword_counter.items() if is_critical(k))
    severity = assess_severity(keyword_counter, cve_ids)
    recommendations = generate_recommendations(matches, keyword_counter, cve_ids)

    def badge(kw, count=None):
        crit = is_critical(kw)
        text = f"{kw}" + (f" ({count})" if count is not None else "")
        color = "#c0392b" if crit else "#2d6cdf"
        return f'<span style="display:inline-block;background:{color};color:#fff;border-radius:4px;padding:2px 6px;margin:2px;font-size:12px;">{text}</span>'

    top_kw_html = "".join(badge(k, c) for k, c in keyword_counter.most_common())

    cve_html = ""
    if cve_ids:
        cve_html = "<p><strong>Detected CVEs:</strong> " + ", ".join(
            f'<span style="background:#8e44ad;color:#fff;border-radius:4px;padding:2px 6px;margin:2px;">{c}</span>'
            for c in cve_ids
        ) + "</p>"

    # Critical messages (from hits)
    critical_items = []
    for src, data in matches.items():
        for h in data.get("hits", []):
            if h["critical"]:
                kw_badges = " ".join(badge(k) for k in h["keywords"])
                critical_items.append(
                    f'<li><a href="{h["url"]}" style="text-decoration:none;color:#0a58ca;">{h["title"]}</a> '
                    f'— {kw_badges} <span style="color:#999">({src})</span></li>'
                )
    critical_html = "<ul>" + "".join(critical_items[:8]) + "</ul>" if critical_items else ""

    # Per-source table
    rows = []
    for src, data in matches.items():
        kw_html = " ".join(badge(k) for k in data["keywords"])
        if data["hits"]:
            items = "".join(
                f'<li><a href="{h["url"]}">{h["title"]}</a> {" ".join(badge(k) for k in h["keywords"])}</li>'
                for h in data["hits"]
            )
            links_html = f"<ul>{items}</ul>"
        else:
            links_html = "<em>No specific headlines found—keywords only in page text.</em>"
        rows.append(f"""
            <tr>
                <td style="vertical-align:top;padding:8px 12px;"><a href="{src}">{src}</a></td>
                <td style="vertical-align:top;padding:8px 12px;">{kw_html}</td>
                <td style="vertical-align:top;padding:8px 12px;">{links_html}</td>
            </tr>
        """)

    # Recommendations list
    rec_list_html = "".join(f"<li>{r}</li>" for r in recommendations)

    html = f"""\
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Cyber Digest</title>
</head>
<body style="font-family:Segoe UI,Arial,sans-serif; color:#1b1f23;">
  <h2 style="margin:0 0 8px 0;">Cybersecurity Digest</h2>
  <div style="color:#666;">Generated: {ts}</div>
  <hr style="border:none;border-top:1px solid #eee;margin:12px 0;">

  <h3>Summary</h3>
  <ul>
    <li>Sources scanned: <strong>{len(blog_urls)}</strong></li>
    <li>Total keyword hits: <strong>{total_hits}</strong></li>
    <li>Unique keywords: <strong>{unique_keywords}</strong></li>
    <li>Critical hits: <strong style="color:#c0392b;">{critical_count}</strong></li>
    <li>Severity: <strong>{severity}</strong></li>
  </ul>

  <h3>Top Keywords</h3>
  <div>{top_kw_html}</div>
  {cve_html}

  {"<h3>Critical Headlines</h3>" + critical_html if critical_html else ""}

  <h3>Details by Source</h3>
  <table style="border-collapse:collapse;width:100%;font-size:14px;">
    <thead>
      <tr style="background:#f6f8fa;">
        <th style="text-align:left;padding:8px 12px;border-bottom:1px solid #eaecef;">Source</th>
        <th style="text-align:left;padding:8px 12px;border-bottom:1px solid #eaecef;">Matched Keywords</th>
        <th style="text-align:left;padding:8px 12px;border-bottom:1px solid #eaecef;">Relevant Articles</th>
      </tr>
    </thead>
    <tbody>
      {''.join(rows)}
    </tbody>
  </table>

  <h3>Next Steps (Context-aware)</h3>
  <ol>{rec_list_html}</ol>

  <div style="font-size:12px;color:#666;margin-top:10px;">
    Attachment: <em>matches.csv</em> (raw data: source, keyword, criticality, title, URL).
  </div>
</body>
</html>
"""
    # Plain-text fallback
    plain = [
        f"Cybersecurity Digest | {ts}",
        f"Sources: {len(blog_urls)} | Total: {total_hits} | Unique: {unique_keywords} | Critical: {critical_count} | Severity: {severity}",
        "",
        "Top Keywords:",
    ]
    for k, c in keyword_counter.most_common():
        label = " [CRITICAL]" if is_critical(k) else ""
        plain.append(f" - {k}: {c}{label}")
    if cve_ids:
        plain.append("")
        plain.append("Detected CVEs: " + ", ".join(cve_ids))
    plain.append("\nDetails by source:")
    for src, data in matches.items():
        ks = ", ".join(data["keywords"])
        plain.append(f"- {src} -> {ks}")
        for h in data.get("hits", []):
            plain.append(f"    * {h['title']} ({h['url']})")
    plain.append("\nNext Steps:")
    for i, r in enumerate(recommendations, 1):
        plain.append(f"{i}. {r}")
    plain_text = "\n".join(plain)
    return html, plain_text, assess_severity(keyword_counter, cve_ids)

def build_csv_attachment(matches):
    sio = StringIO()
    writer = csv.writer(sio)
    writer.writerow(["timestamp", "source", "keyword", "critical", "title", "url"])
    ts = datetime.now().isoformat(timespec="seconds")
    for src, data in matches.items():
        for kw in data["keywords"]:
            writer.writerow([ts, src, kw, "yes" if is_critical(kw) else "no", "", ""])
        for h in data.get("hits", []):
            kwlist = ";".join(h["keywords"])
            writer.writerow([ts, src, kwlist, "yes" if h["critical"] else "no", h["title"], h["url"]])
    payload = sio.getvalue().encode("utf-8")
    sio.close()
    return payload
def send_email_alert(matches, keyword_counter, cve_ids):
    if not matches:
        print("No keywords found. No email sent.")
        return

    html_body, plain_body, severity = build_html_email(matches, keyword_counter, cve_ids)
    ts = datetime.now().strftime("%Y-%m-%d %H:%M")
    subject = f"[{severity}] Cybersecurity Digest – {len(blog_urls)} sources | {len(keyword_counter)} uniq | {ts}"

    msg = MIMEMultipart("alternative")
    msg["From"] = SENDER_EMAIL
    msg["To"] = ", ".join(RECIPIENTS)
    msg["Subject"] = subject

    # Attach plain + HTML
    msg.attach(MIMEText(plain_body, "plain", "utf-8"))
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    # CSV attachment
    csv_bytes = build_csv_attachment(matches)
    part = MIMEBase("text", "csv")
    part.set_payload(csv_bytes)
    encoders.encode_base64(part)
    part.add_header("Content-Disposition", "attachment", filename="matches.csv")
    msg.attach(part)

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.sendmail(SENDER_EMAIL, RECIPIENTS, msg.as_string())
        print("HTML email sent successfully.")
    except Exception as e:
        print(f"Error sending email: {e}")

# =========================
# MAIN
# =========================
if __name__ == "__main__":
    matches, keyword_counter, cve_ids = check_blogs_for_keywords()

    if matches:
        print("Matched keywords (summary):")
        for url, data in matches.items():
            print(f"{url}:\n  - " + ", ".join(data["keywords"]))
    else:
        print("No keywords found.")

    send_email_alert(matches, keyword_counter, cve_ids)
