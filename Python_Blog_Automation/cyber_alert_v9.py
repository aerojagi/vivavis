# VIVAVIS - Python Script
#
# -Einsatz      Überwachung von Sicherheitsblogs auf relevante Stichwörter
# -Erstellung   jko 2025-09-29  V4.1
# -Änderungen   V4.1  Nur neue CVEs werden gemeldet (Duplikate werden gefiltert)
# -Bemerkungen  0. WICHTIG – Dieses Skript ist nur von geschultem Personal zu verwenden!
#               1. Bitte passen Sie die Liste der Blogs (`blog_urls`) und Stichwörter (`keywords`) bei Bedarf an.
#               2. Die Funktion `send_email_alert()` nutzt SMTP zur Benachrichtigung.
#               3. Das Skript ruft Inhalte ab, durchsucht sie nach Stichwörtern und versendet eine E-Mail mit den Ergebnissen.
#
# Ab hier keine Anpassungen erforderlich ###############################################################
import os
import re
import csv
import json
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
from urllib.parse import urljoin

# --------------------------
# KONFIGURATION
# --------------------------
blog_urls = [
    "https://www.borncity.com/blog/",
    "https://www.allianz-fuer-cybersicherheit.de/SiteGlobals/Forms/Suche/BSI/Sicherheitswarnungen/Sicherheitswarnungen_Formular.html?nn=145684&cl2Categories_DocType=callforbids/",
    "https://support.sophos.com/support/s/?language=en_US#t=AllTab&sort=relevancy/",
    "https://wid.cert-bund.de/portal/wid/kurzinformationen/",
    "https://euvd.enisa.europa.eu/",
    "https://cve.enginsight.com/media-exposure.html"
]
# Kritische Schlüsselwörter (Groß-/Kleinschreibung-unabhängige Prüfung)
keywords = [
    "Cisco","Microsoft","Windows","Linux","Apache","Nginx","Fortinet","Palo Alto","Sophos","Trend Micro",
    "VMware","Citrix","Oracle","SAP","Exchange","Outlook","SharePoint","Teams",
    "vulnerability","exploit","malware","zero-day","threat","ransomware","phishing","trojan","spyware",
    "backdoor","rootkit","botnet","CVE","remote code execution","privilege escalation","denial of service",
    "DoS","DDoS","compromise","data leak","exfiltration",
    "Active Directory","LDAP","Kerberos","VPN","Firewall","Proxy","DNS","Cloud","Azure","AWS","Google Cloud",
    "SIEM","SOC","EDR","XDR","IAM","MFA","SSO","TLS","SSL","MITRE ATT&CK","NIST","ISO 27001",
    "Brute force","SQL injection","XSS","CSRF","Metasploit","Cobalt Strike","Mimikatz","PowerShell",
    "Living off the Land","LOLBins",
    "incident","breach","patch","update","hotfix","security advisory"
]
critical_keywords = {"zero-day", "exploit", "ransomware", "remote code execution", "privilege escalation", "CVE"}

headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}

SMTP_SERVER = "grp-ex01.vivavis.int"
SMTP_PORT = 25
SENDER_EMAIL = "Schwachstellenmanagment@vivavis.com"
RECIPIENTS = ["Jagankumar.Kothandan@Vivavis.com"]

ALERTS_FILE = "last_alerts.json"
CVE_FILE = "last_cves.json"  # NEU: Datei zur Speicherung der gemeldeten CVEs

# --------------------------
# HILFSFUNKTIONEN
# --------------------------
CVE_REGEX = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)

def is_critical(kw: str) -> bool:
    # Prüft, ob ein Schlüsselwort als kritisch eingestuft ist
    return kw.lower() in {k.lower() for k in critical_keywords}

def normalize_kw(kw: str) -> str:
    # Entfernt Leerzeichen am Anfang/Ende eines Schlüsselworts
    return kw.strip()

def extract_links_and_titles(soup, base_url):
    # Extrahiert Links und Titel aus dem HTML-Inhalt
    items = []
    for a in soup.find_all("a"):
        title = (a.get_text(" ", strip=True) or "").strip()
        href = a.get("href") or ""
        if not href:
            continue
        href = unescape(href)
        if href.startswith("//"):
            href = f"https:{href}"
        elif href.startswith("/"):
            href = urljoin(base_url, href)
        items.append((title, href))
    return items

def check_blogs_for_keywords():
    # Durchsucht alle Blogs nach Schlüsselwörtern und CVEs
    matches_per_source = defaultdict(lambda: {"keywords": set(), "hits": []})
    keyword_counter = Counter()
    cve_ids = set()

    for url in blog_urls:
        try:
            resp = requests.get(url, headers=headers, timeout=15)
            resp.raise_for_status()
            html = resp.text
            soup = BeautifulSoup(html, "html.parser")
            text = soup.get_text(" ", strip=True)
            text_lc = text.lower()
            found = set()
            for kw in keywords:
                if kw.lower() in text_lc:
                    found.add(normalize_kw(kw))
                    keyword_counter[normalize_kw(kw)] += 1
            for m in CVE_REGEX.findall(text):
                cve_ids.add(m.upper())
                keyword_counter["CVE"] += 1
            hits = []
            if found:
                for title, href in extract_links_and_titles(soup, url):
                    tl = title.lower()
                    hit_kws = sorted({kw for kw in found if kw.lower() in tl})
                    if hit_kws:
                        hits.append({"title": title[:160], "url": href, "keywords": hit_kws,
                                     "critical": any(is_critical(k) for k in hit_kws)})
            if found:
                matches_per_source[url]["keywords"].update(found)
                hits_sorted = sorted(hits, key=lambda h: (not h["critical"], -len(h["keywords"]), h['title']))
                matches_per_source[url]["hits"] = hits_sorted[:10]
        except Exception as e:
            print(f"Fehler beim Abrufen von {url}: {e}")
    for src in matches_per_source:
        matches_per_source[src]["keywords"] = sorted(matches_per_source[src]["keywords"],
                                                     key=lambda k: (not is_critical(k), k.lower()))
    return matches_per_source, keyword_counter, sorted(cve_ids)

# NEU: Funktionen zur CVE-Verfolgung
def save_current_cves(cve_ids):
    # Speichert die aktuelle Liste der CVEs in einer Datei
    with open(CVE_FILE, "w", encoding="utf-8") as f:
        json.dump(list(cve_ids), f, indent=2)

def load_previous_cves():
    # Lädt die zuvor gemeldeten CVEs aus der Datei
    if os.path.exists(CVE_FILE):
        try:
            with open(CVE_FILE, "r", encoding="utf-8") as f:
                return set(json.load(f))
        except Exception:
            return set()
    return set()

def build_html_email(matches, keyword_counter, cve_ids):
    # Erstellt den HTML- und Klartext-Inhalt für die E-Mail
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    total_hits = sum(keyword_counter.values())
    unique_keywords = len(keyword_counter)
    critical_count = sum(c for k, c in keyword_counter.items() if is_critical(k))

    def badge(kw, count=None):
        # Erstellt ein farbiges Badge für ein Schlüsselwort
        crit = is_critical(kw)
        text = f"{kw}" + (f" ({count})" if count is not None else "")
        color = "#c0392b" if crit else "#2d6cdf"
        return f'<span style="display:inline-block;background:{color};color:#fff;border-radius:4px;padding:2px 6px;margin:2px;font-size:12px;">{text}</span>'

    top_kw_html = "".join(badge(k, c) for k, c in keyword_counter.most_common())

    cve_html = ""
    if cve_ids:
        cve_html = "<p><strong>Neue CVEs erkannt:</strong> " + ", ".join(
            f'<span style="background:#8e44ad;color:#fff;border-radius:4px;padding:2px 6px;margin:2px;">{c}</span>'
            for c in cve_ids) + "</p>"
    critical_items = []
    for src, data in matches.items():
        for h in data.get("hits", []):
            if h["critical"]:
                kw_badges = " ".join(badge(k) for k in h["keywords"])
                critical_items.append(
                    f'<li><a href="{h['url']}" style="text-decoration:noneor:#999">({src})</span></li>'
                )
    critical_html = "<ul>" + "".join(critical_items[:8]) + "</ul>" if critical_items else ""
    rows = []
    for src, data in matches.items():
        kw_html = " ".join(badge(k) for k in data["keywords"])
        links_html = ""
        if data["hits"]:
            items = "".join(
                f'<li><a href="{h["]}</a> {" ".join(badge(k) for k in h["keywords"])}</li>'
                for h in data["hits"]
            )
            links_html = f"<ul>{items}</ul>"
        else:
            links_html = "<em>Keine konkreten Artikelüberschriften gefunden – nur Begriffe im Seiteninhalt.</em>"
        rows.append(f"""
<tr>
<td style="vertical-align:top;padding:8px 12px;">{src}{src}</a></td>
<td style="vertical-align:top;padding:8px 12px;">{kw_html}</td>
<td style="vertical-align:top;padding:8px 12px;">{links_html}</td>
</tr>
""")
    html = f"""\
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>Cyber Digest</title>
</head>
<body style="font-family:Segoe UI,Arial,sans-serif; color:#1b1f23;">
<h2 style="margin:0 0 8px 0;">Blog-Sicherheitscheck: Schwachstellen im Blick</h2>
<div style="color:#666;">Bericht erstellt am: {ts}</div>
<hr style="border:none;border-top:1px solid #eee;margin:12px 0;">

<h3>Zusammenfassung</h3>
<ul>
<li>Überwachte Quellen: <strong>{len(blog_urls)}</strong></li>
<li>Gefundene Schlüsselwörter gesamt: <strong>{total_hits}</strong></li>
<li>Unterschiedliche Schlüsselwörter: <strong>{unique_keywords}</strong></li>
<li>Kritische Treffer: <strong style="color:#c0392b;">{critical_count}</strong></li>
</ul>

<h3>Top-Schlüsselwörter</h3>
<div>{top_kw_html}</div>
{cve_html}
{"<h3>Kritische Meldungen (höchste Priorität)</h3>" + critical_html if critical_html else ""}

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

<h3>Nächste Schritte (Empfehlung)</h3>
<ol>
<li>Bewerten Sie <strong>kritische Treffer</strong> (Zero-Day, RCE, Ransomware, CVE) innerhalb von 24h.</li>
<li>Prüfen Sie verfügbare Patches/Workarounds für betroffene Produkte (Microsoft, Fortinet, Citrix, VMware etc.).</li>
<li>Falls CVEs genannt werden, gleichen Sie betroffene Versionen in Ihrem Bestand ab.</li>
<li>Kommunizieren Sie nur bestätigte, relevante Risiken an die Stakeholder (Change/Incident-Prozess).</li>
</ol>

<div style="font-size:12px;color:#666;margin-top:10px;">
Anhang: <em>matches.csv</em> mit Rohdaten (Quelle, Keyword, Kritikalität, Titel, URL).
</div>
</body>
</html>
"""
    plain = [
        f"Cybersecurity Digest | {ts}",
        f"Quellen: {len(blog_urls)} | Gesamt: {total_hits} | Uniq: {unique_keywords} | Kritisch: {critical_count}",
        "",
        "Top-Schlüsselwörter:",
    ]
    for k, c in keyword_counter.most_common():
        label = " [KRITISCH]" if is_critical(k) else ""
        plain.append(f" - {k}: {c}{label}")
    if cve_ids:
        plain.append("")
        plain.append("Neue CVEs erkannt: " + ", ".join(cve_ids))
    plain.append("\nDetails pro Quelle:")
    for src, data in matches.items():
        ks = ", ".join(data["keywords"])
        plain.append(f"- {src} -> {ks}")
        for h in data.get("hits", []):
            plain.append(f"    * {h['title']} ({h['url']})")
    plain_text = "\n".join(plain)
    return html, plain_text, critical_count

def build_csv_attachment(matches):
    # Erstellt den CSV-Anhang für die E-Mail
    sio = StringIO()
    writer = csv.writer(sio)
    writer.writerow(["timestamp", "source", "keyword", "critical", "title", "url"])
    ts = datetime.now().isoformat(timespec="seconds")
    for src, data in matches.items():
        for kw in data["keywords"]:
            writer.writerow([ts, src, kw, "yes" if is_critical(kw) else "no", "", ""])
        for h in data.get("hits", []):
            kwlist = ";".join(h["keywords"])
            writer.writerow([ts, src, kwlist, "yes" if h["critical"] else "no", h['title'], h['url']])
    payload = sio.getvalue().encode("utf-8")
    sio.close()
    return payload

def send_email_alert(matches, keyword_counter, cve_ids):
    # Versendet die E-Mail mit den neuen Treffern und CVEs
    html_body, plain_body, critical_count = build_html_email(matches, keyword_counter, cve_ids)
    ts = datetime.now().strftime("%Y-%m-%d %H:%M")
    subject_prefix = f"[CRITICAL {critical_count}]" if critical_count > 0 else "[INFO]"
    subject = f"{subject_prefix} Schwachstellen – {len(blog_urls)} Quellen | {len(keyword_counter)} uniq | {ts}"

    msg = MIMEMultipart("alternative")
    msg["From"] = SENDER_EMAIL
    msg["To"] = ", ".join(RECIPIENTS)
    msg["Subject"] = subject

    msg.attach(MIMEText(plain_body, "plain", "utf-8"))
    msg.attach(MIMEText(html_body, "html", "utf-8"))

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

def extract_unique_items(matches):
    # Extrahiert eindeutige Artikel (URL + Titel) aus den Treffern
    unique_items = set()
    for src, data in matches.items():
        for hit in data.get("hits", []):
            identifier = f"{hit['url']}|{hit['title']}"
            unique_items.add(identifier)
    return unique_items

def filter_new_matches(current_matches, previous_items):
    # Filtert nur neue Artikel/URLs heraus, die noch nicht gemeldet wurden
    new_matches = {}
    for src, data in current_matches.items():
        new_hits = []
        for hit in data.get("hits", []):
            identifier = f"{hit['url']}|{hit['title']}"
            if identifier not in previous_items:
                new_hits.append(hit)
        if new_hits:
            new_matches[src] = {
                "keywords": data["keywords"],
                "hits": new_hits
            }
    return new_matches

def save_current_alerts(matches):
    # Speichert die aktuellen Artikel/URLs in einer Datei
    items = list(extract_unique_items(matches))
    with open(ALERTS_FILE, "w", encoding="utf-8") as f:
        json.dump(items, f, indent=2)

def load_previous_alerts():
    # Lädt die zuvor gemeldeten Artikel/URLs aus der Datei
    if os.path.exists(ALERTS_FILE):

    try:
            with open(ALERTS_FILE, "r", encoding="utf-8") as f:
                content = f.read().strip()
                if not content:
                    return set()
                return set(json.loads(content))
        except (json.JSONDecodeError, StopIteration):
            return set()
    return set()

    # --------------------------
# MAIN
# --------------------------
if __name__ == "__main__":
    matches, keyword_counter, cve_ids = check_blogs_for_keywords()
    previous_items = load_previous_alerts()
    new_matches = filter_new_matches(matches, previous_items)
    save_current_alerts(matches)

    # --- CVE Filtering ---
    previous_cves = load_previous_cves()
    new_cves = set(cve_ids) - previous_cves
    save_current_cves(cve_ids)

    # Only send email if there are new matches or new CVEs
    if new_matches or new_cves:
        send_email_alert(new_matches, keyword_counter, list(new_cves))
    else:
        print("No new content or CVEs found. No email sent.")