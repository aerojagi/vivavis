# VIVAVIS - Python Script
#
# -Einsatz      Überwachung von Sicherheitsblogs auf relevante Stichwörter
# -Erstellung   jko 2025-08-12  V3.0
# -Änderungen   V2.1  Erweiterung der Stichwortliste für umfassendere Sicherheitsüberwachung
# -Bemerkungen  0. WICHTIG – Dieses Skript ist nur von geschultem Personal zu verwenden!
#               1. Bitte passen Sie die Liste der Blogs (`blog_urls`) und Stichwörter (`keywords`) bei Bedarf an.
#               2. Die Funktion `send_email_alert()` nutzt SMTP zur Benachrichtigung.
#               3. Das Skript ruft Inhalte ab, durchsucht sie nach Stichwörtern und versendet eine E-Mail mit den Ergebnissen.
#
# Skript – ab hier keine Anpassungen erforderlich ###############################################################
import os
import requests
from bs4 import BeautifulSoup
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

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

# Header definieren, um einen Browser nachzuahmen
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
}

# SMTP-Konfiguration
SMTP_SERVER = "grp-ex01.vivavis.int"
SMTP_PORT = 25
SENDER_EMAIL = "Schwachstellenmanagment@vivavis.com"
RECIPIENTS = ["Jagankumar.Kothandan@Vivavis.com"]  # Bitte bei Bedarf anpassen

# Funktion zum Abrufen und Durchsuchen von Blog-Inhalten
def check_blogs_for_keywords():
    matches = []
    for url in blog_urls:
        try:
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            text = soup.get_text().lower()
            found_keywords = [kw for kw in keywords if kw.lower() in text]
            if found_keywords:
                matches.append((url, found_keywords))
        except Exception as e:
            print(f"Fehler beim Abrufen von {url}: {e}")
    return matches

# Funktion zum Versenden von E-Mails über SMTP
def send_email_alert(matches):
    if not matches:
        print("Keine Stichwörter gefunden. Keine E-Mail gesendet.")
        return

    subject = "Cybersicherheitswarnung: In Blogs gefundene Schlüsselwörter"
    body = "Die folgenden Schlüsselwörter wurden in den überwachten Blogs gefunden:\n\n"
    for url, found in matches:
        body += f"{url}:\n  - " + ", ".join(found) + "\n\n"

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
    keyword_matches = check_blogs_for_keywords()

    if keyword_matches:
        print("Gefundene Schlüsselwörter:")
        for url, found in keyword_matches:
            print(f"{url}:\n  - " + ", ".join(found))
    else:
        print("Keine Schlüsselwörter gefunden.")

    send_email_alert(keyword_matches)
