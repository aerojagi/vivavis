import os
import requests
from bs4 import BeautifulSoup
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from collections import defaultdict, Counter

# Liste der zu überwachenden Blog-URLs
blog_urls = [
    "https://www.borncity.com/blog/",
    "https://www.allianz-fuer-cybersicherheit.de/SiteGlobals/Forms/Suche/BSI/Sicherheitswarnungen/Sicherheitswarnungen_Formular.html?nn=145684&amp;cl2Categories_DocType=callforbids/",
    "https://support.sophos.com/support/s/?language=en_US#t=AllTab&amp;sort=relevancy/",
    "https://wid.cert-bund.de/portal/wid/kurzinformationen/",
    "https://euvd.enisa.europa.eu/"
]

# Erweiterte Liste von Stichwörtern
keywords = [
    # Hersteller & Produkte
    "Cisco", "Microsoft", "Windows", "Linux", "Apache", "Nginx", "Fortinet", "Palo Alto", "Sophos", "Trend Micro",
    "VMware", "Citrix", "Oracle", "SAP", "Exchange", "Outlook", "SharePoint", "Teams",

    # Bedrohungen & Schwachstellen
    "vulnerability", "exploit", "malware", "zero-day", "threat", "ransomware", "phishing", "trojan", "spyware",
    "backdoor", "rootkit", "botnet", "CVE", "remote code execution", "privilege escalation", "denial of service",
    "DoS", "DDoS", "compromise", "data leak", "exfiltration",

    # Sicherheitskonzepte
    "Active Directory", "LDAP", "Kerberos", "VPN", "Firewall", "Proxy", "DNS", "Cloud", "Azure", "AWS", "Google Cloud",
    "SIEM", "SOC", "EDR", "XDR", "IAM", "MFA", "SSO", "TLS", "SSL", "MITRE ATT&CK", "NIST", "ISO 27001",

    # Angreifertechniken & Tools
    "Brute force", "SQL injection", "XSS", "CSRF", "Metasploit", "Cobalt Strike", "Mimikatz", "PowerShell",
    "Living off the Land", "LOLBins",

    # Allgemeine Begriffe
    "incident", "breach", "patch", "update", "hotfix", "security advisory"
]

# Kritische Stichwörter für Hervorhebung
critical_keywords = {"zero-day", "exploit", "ransomware", "remote code execution", "privilege escalation", "CVE"}

# Header definieren, um einen Browser nachzuahmen
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
}

# SMTP-Konfiguration
SMTP_SERVER = "grp-ex01.vivavis.int"
SMTP_PORT = 25
SENDER_EMAIL = "Schwachstellenmanagment@vivavis.com"
RECIPIENTS = ["Jagankumar.Kothandan@Vivavis.com"]

# Funktion zum Abrufen und Durchsuchen von Blog-Inhalten
def check_blogs_for_keywords():
    matches = defaultdict(list)
    keyword_counter = Counter()
    for url in blog_urls:
        try:
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            text = soup.get_text().lower()
            found_keywords = [kw for kw in keywords if kw.lower() in text]
            for kw in found_keywords:
                keyword_counter[kw] += 1
            if found_keywords:
                matches[url] = found_keywords
        except Exception as e:
            print(f"Fehler beim Abrufen von {url}: {e}")
    return matches, keyword_counter

# Funktion zum Versenden von E-Mails über SMTP
def send_email_alert(matches, keyword_counter):
    if not matches:
        print("Keine Stichwörter gefunden. Keine E-Mail gesendet.")
        return

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    subject = f"Cybersicherheitswarnung: Schlüsselwörter gefunden ({timestamp})"

    body = f"Bericht erstellt am: {timestamp}\n\n"
    body += "Zusammenfassung:\n"
    body += f"- Anzahl überwachte Blogs: {len(blog_urls)}\n"
    body += f"- Anzahl gefundener Schlüsselwörter: {sum(keyword_counter.values())}\n"
    body += f"- Anzahl unterschiedlicher Schlüsselwörter: {len(keyword_counter)}\n\n"

    body += "Häufigkeit der gefundenen Schlüsselwörter:\n"
    for kw, count in keyword_counter.most_common():
        highlight = " [KRITISCH]" if kw in critical_keywords else ""
        body += f"  - {kw}: {count}{highlight}\n"
    body += "\n"

    body += "Details pro Blog:\n"
    for url, found in matches.items():
        body += f"{url}:\n"
        for kw in found:
            highlight = " [KRITISCH]" if kw in critical_keywords else ""
            body += f"  - {kw}{highlight}\n"
        body += "\n"

    try:
        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = ", ".join(RECIPIENTS)
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.sendmail(SENDER_EMAIL, RECIPIENTS, msg.as_string())

        print("E-Mail erfolgreich gesendet.")
    except Exception as e:
        print(f"Fehler beim Senden der E-Mail: {e}")

# Hauptdurchführung
if __name__ == "__main__":
    keyword_matches, keyword_counter = check_blogs_for_keywords()

    if keyword_matches:
        print("Gefundene Schlüsselwörter:")
        for url, found in keyword_matches.items():
            print(f"{url}:\n  - " + ", ".join(found))
    else:
        print("Keine Schlüsselwörter gefunden.")

    send_email_alert(keyword_matches, keyword_counter)
