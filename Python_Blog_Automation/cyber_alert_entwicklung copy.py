#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cybersecurity Digest – context-aware (German recommendations)
- Scans a set of sources for keywords
- Extracts CVEs
- Builds HTML and plaintext email with dynamic German recommendations
- Attaches CSV raw data

Dependencies:
    pip install requests beautifulsoup4
"""

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

# Critical keywords (case-insensitive check below)
critical_keywords = {
    "zero-day", "exploit", "ransomware",
    "remote code execution", "privilege escalation", "CVE"
}

# German vendor labels (routing hints)
vendor_labels_de = {
    "Microsoft": "Windows/Office-Team (WSUS/Intune)",
    "VMware": "VM/Hypervisor-Team",
    "Citrix": "NetScaler/VDI-Team",
    "Fortinet": "Netzwerk/Security-Team (FortiGate/PSIRT)",
    "Sophos": "Endpoint-/Firewall-Team",
    "SAP": "SAP-Basis-Team",
    "Trend Micro": "Endpoint-Security-Team",
    "Cisco": "Netzwerk-Team",
    "Palo Alto": "Netzwerk-/Security-Team",
    "Nginx": "Web/Infra-Team",
    "Apache": "Web/Infra-Team",
}

headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}

# SMTP / Email
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
    """Return a list of (title, href) tuples; safely handle relative links; deduplicate."""
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
    """Fetch pages, detect keywords, extract CVEs and representative article links."""
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
                # Keep "CVE" metric in counter for dashboards
                keyword_counter["CVE"] += 1

            # Representative links whose titles include any found keyword
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
                hits_sorted = sorted(
                    hits,
                    key=lambda h: (not h["critical"], -len(h["keywords"]), h["title"])
                )
                matches_per_source[url]["hits"] = hits_sorted[:10]

        except Exception as e:
            print(f"Fehler beim Abrufen von {url}: {e}")

    # finalize keyword sets (critical first)
    for src in matches_per_source:
        matches_per_source[src]["keywords"] = sorted(
            matches_per_source[src]["keywords"],
            key=lambda k: (not is_critical(k), k.lower())
        )
    return matches_per_source, keyword_counter, sorted(cve_ids)

# =========================
# DYNAMIC RECOMMENDATIONS (German)
# =========================
def assess_severity(keyword_counter, cve_ids):
    """Score & label overall severity (English label used internally)."""
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

def severity_to_de(sev: str) -> str:
    return {"CRITICAL": "KRITISCH", "HIGH": "HOCH", "INFO": "INFO"}.get(sev, sev)

def generate_recommendations_de(matches, keyword_counter, cve_ids):
    """Erzeugt kontextbezogene Empfehlungen (Deutsch) basierend auf Befunden."""
    kws = {k.lower() for k in keyword_counter.keys()}

    # Vendor-Erkennung über vorkommende Keywords
    vendors_detected = [
        v for v in vendor_labels_de
        if v.lower() in kws or any(v.lower() in k for k in kws)
    ]

    recs = []
    add = recs.append

    # --- Bedrohungsgetrieben ---
    if "zero-day" in kws:
        add("Zero-Day-Meldungen priorisieren: Vendor-Maßnahmen sofort umsetzen; Angriffsfläche reduzieren "
            "(verwundbare Features deaktivieren, WAN-Zugriff einschränken, WAF/IPS‑Virtual‑Patching) innerhalb von 24 h.")
    if "remote code execution" in kws or "exploit" in kws:
        add("RCE/Exploit-Indikatoren als Notfall behandeln: betroffene Dienste identifizieren, Zugriff beschränken "
            "(ACL/Geo/IP-Allowlist), Patches validieren und beschleunigt ausrollen.")
    if "ransomware" in kws:
        add("Ransomware-Indikatoren: letzte erfolgreichen, unveränderlichen Backups prüfen; EDR-Erkennungen sichten "
            "und verdächtige Hosts isolieren; Signaturen/Regeln aktualisieren und IoCs blockieren.")
    if "privilege escalation" in kws:
        add("Privilegienerhöhung: Admin-Konten & jüngste Rechteänderungen prüfen; MFA erzwingen; Anmeldedaten/Tokens rotieren.")
    if "phishing" in kws:
        add("Phishing-Hinweise: Mailfilter-Regeln schärfen, beobachtete Absender/URLs blockieren, Helpdesk auf erhöhtes Meldeaufkommen vorbereiten.")

    # --- CVE-Workflow ---
    if cve_ids:
        add(f"CVE-Auswirkung validieren: {len(cve_ids)} CVE(s) gegen das Asset-Inventar abgleichen; "
            "bei Betroffenheit Change-/Notfall‑Patch einplanen.")
        add("Vendor‑Advisories und Known‑Exploited‑Catalogs prüfen; während des Patchens auf Exploit‑Aktivität monitoren.")

    # --- Vendor-spezifische Playbooks / Routing ---
    if vendors_detected:
        ziele = ", ".join(f"{v} → {vendor_labels_de[v]}" for v in vendors_detected)
        add(f"Produktverantwortliche informieren: {ziele}. Einschätzung betroffener Versionen und Patch-Status anfordern.")
    vlow = {v.lower() for v in vendors_detected}
    if "microsoft" in vlow or "windows" in kws:
        add("Für Microsoft: aktuelle Patch‑Tuesday/Out‑of‑Band‑Hinweise prüfen; WSUS/Intune‑Ringe validieren; "
            "temporäre Härtung (ASR‑Regeln) erwägen.")
    if "vmware" in vlow:
        add("Für VMware: VMSA‑Advisories prüfen; Management‑Interfaces einschränken; Snapshots & Wartungsfenster für Patching planen.")
    if "citrix" in vlow:
        add("Für Citrix/NetScaler: Exponierung von ADM/NS prüfen; neue Builds einspielen; Gateway‑Härtung (MFA, Rate‑Limiting).")
    if "fortinet" in vlow:
        add("Für Fortinet: PSIRT‑Bulletins prüfen; IPS‑Signaturen aktualisieren; administrativen WAN‑Zugriff minimieren.")
    if "sap" in vlow:
        add("Für SAP: aktuelle SAP Security Notes prüfen; mit SAP‑Basis Patchplanung & Regressionstests abstimmen.")

    # --- Infrastruktur / Dienste ---
    if any(k in kws for k in ("vpn", "firewall", "ssl", "tls", "dns", "proxy")):
        add("Netzwerk‑Exponierung prüfen: sicherstellen, dass Admin‑Services nicht am WAN exponiert sind; "
            "MFA erzwingen; Zugriff über VPN bzw. IP‑Allowlists beschränken.")

    # --- Fallback ---
    if not recs:
        add("Beobachten: kein sofortiger Handlungsbedarf; Vendor‑Hinweise erneut prüfen und in den regulären Patchzyklus einplanen.")

    # Deduplizieren und Reihenfolge beibehalten
    seen, ordered = set(), []
    for r in recs:
        if r not in seen:
            ordered.append(r)
            seen.add(r)
    return ordered

# =========================
# EMAIL BUILDERS (German UI)
# =========================
def build_html_email(matches, keyword_counter, cve_ids):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total_hits = sum(keyword_counter.values())
    unique_keywords = len(keyword_counter)
    critical_count = sum(c for k, c in keyword_counter.items() if is_critical(k))

    severity_en = assess_severity(keyword_counter, cve_ids)
    severity_de = severity_to_de(severity_en)

    recommendations = generate_recommendations_de(matches, keyword_counter, cve_ids)

    def badge(kw, count=None):
        crit = is_critical(kw)
        text = f"{kw}" + (f" ({count})" if count is not None else "")
        color = "#c0392b" if crit else "#2d6cdf"
        return f'<span style="display:inline-block;background:{color};color:#fff;border-radius:4px;padding:2px 6px;margin:2px;font-size:12px;">{text}</span>'

    top_kw_html = "".join(badge(k, c) for k, c in keyword_counter.most_common())

    cve_html = ""
    if cve_ids:
        cve_html = "<p><strong>Erkannte CVEs:</strong> " + ", ".join(
            f'<span style="background:#8e44ad;color:#fff;border-radius:4px;padding:2px 6px;margin:2px;">{c}</span>'
            for c in cve_ids
        ) + "</p>"

    # Kritische Überschriften
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

    # Tabellenzeilen pro Quelle
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
            links_html = "<em>Keine konkreten Artikelüberschriften gefunden – nur Begriffe im Seiteninhalt.</em>"
        rows.append(f"""
            <tr>
                <td style="vertical-align:top;padding:8px 12px;"><a href="{src}">{src}</a></td>
                <td style="vertical-align:top;padding:8px 12px;">{kw_html}</td>
                <td style="vertical-align:top;padding:8px 12px;">{links_html}</td>
            </tr>
        """)

    rec_list_html = "".join(f"<li>{r}</li>" for r in recommendations)

    html = f"""\
<!doctype html>
<html>
<head><meta charset="utf-8"><title>Cybersecurity Digest</title></head>
<body style="font-family:Segoe UI,Arial,sans-serif; color:#1b1f23;">
  <h2 style="margin:0 0 8px 0;">Cybersecurity Digest</h2>
  <div style="color:#666;">Bericht erstellt am: {ts}</div>
  <hr style="border:none;border-top:1px solid #eee;margin:12px 0;">

  <h3>Zusammenfassung</h3>
  <ul>
    <li>Überwachte Quellen: <strong>{len(blog_urls)}</strong></li>
    <li>Gefundene Schlüsselwörter gesamt: <strong>{total_hits}</strong></li>
    <li>Unterschiedliche Schlüsselwörter: <strong>{unique_keywords}</strong></li>
    <li>Kritische Treffer: <strong style="color:#c0392b;">{critical_count}</strong></li>
    <li>Schweregrad: <strong>{severity_de}</strong></li>
  </ul>

  <h3>Top-Schlüsselwörter</h3>
  <div>{top_kw_html}</div>
  {cve_html}

  {"<h3>Kritische Überschriften</h3>" + critical_html if critical_html else ""}

  <h3>Details pro Quelle</h3>
  <table style="border-collapse:collapse;width:100%;font-size:14px;">
    <thead>
      <tr style="background:#f6f8fa;">
        <th style="text-align:left;padding:8px 12px;border-bottom:1px solid #eaecef;">Quelle</th>
        <th style="text-align:left;padding:8px 12px;border-bottom:1px solid #eaecef;">Gefundene Schlüsselwörter</th>
        <th style="text-align:left;padding:8px 12px;border-bottom:1px solid #eaecef;">Relevante Artikel</th>
      </tr>
    </thead>
    <tbody>
      {''.join(rows)}
    </tbody>
  </table>

  <h3>Nächste Schritte (kontextbezogen)</h3>
  <ol>{rec_list_html}</ol>

  <div style="font-size:12px;color:#666;margin-top:10px;">
    Anhang: <em>matches.csv</em> (Rohdaten: Quelle, Keyword, Kritikalität, Titel, URL).
  </div>
</body>
</html>
"""
    # Plaintext-Fallback (Deutsch)
    plain = [
        f"Cybersecurity Digest | {ts}",
        f"Quellen: {len(blog_urls)} | Gesamt: {total_hits} | Uniq: {unique_keywords} | "
        f"Kritisch: {critical_count} | Schweregrad: {severity_de}",
        "",
        "Top-Schlüsselwörter:",
    ]
    for k, c in keyword_counter.most_common():
        label = " [KRITISCH]" if is_critical(k) else ""
        plain.append(f" - {k}: {c}{label}")
    if cve_ids:
        plain.append("")
        plain.append("Erkannte CVEs: " + ", ".join(cve_ids))
    plain.append("\nDetails pro Quelle:")
    for src, data in matches.items():
        ks = ", ".join(data["keywords"])
        plain.append(f"- {src} -> {ks}")
        for h in data.get("hits", []):
            plain.append(f"    * {h['title']} ({h['url']})")
    plain.append("\nNächste Schritte:")
    for i, r in enumerate(recommendations, 1):
        plain.append(f"{i}. {r}")
    plain_text = "\n".join(plain)
    return html, plain_text, severity_en  # keep English severity for internal logic

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
        print("Keine Schlüsselwörter gefunden. Keine E-Mail gesendet.")
        return

    html_body, plain_body, severity_en = build_html_email(matches, keyword_counter, cve_ids)
    severity_de = severity_to_de(severity_en)
    ts = datetime.now().strftime("%Y-%m-%d %H:%M")
    subject = f"[{severity_de}] Cybersecurity Digest – {len(blog_urls)} Quellen | {len(keyword_counter)} uniq | {ts}"

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
        print("HTML-E-Mail erfolgreich gesendet.")
    except Exception as e:
        print(f"Fehler beim Senden der E-Mail: {e}")

# =========================
# MAIN
# =========================
if __name__ == "__main__":
    matches, keyword_counter, cve_ids = check_blogs_for_keywords()

    if matches:
        print("Gefundene Schlüsselwörter (zusammengefasst):")
        for url, data in matches.items():
            print(f"{url}:\n  - " + ", ".join(data["keywords"]))
    else:
        print("Keine Schlüsselwörter gefunden.")

    send_email_alert(matches, keyword_counter, cve_ids)
