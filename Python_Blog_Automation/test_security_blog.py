import os
import requests
from bs4 import BeautifulSoup
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# List of blog URLs to monitor
blog_urls = [
    "https://www.borncity.com/blog/",
    "https://www.bleepingcomputer.com/",
    "https://blog.talosintelligence.com/"
]

# Keywords to search for
keywords = ["Cisco", "vulnerability", "exploit", "malware", "zero-day", "threat"]


# Define headers to mimic a browser
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
}

# Email configuration
sender_email = "jagankumar.kothandan@vivavis.com"
recipient_emails = ["jagankumar.kothandan@vivavis.com"]  # Add more recipients if needed
smtp_server = "smtp.office365.com"
smtp_port = 587

# Get password from environment variable
email_password = os.getenv("EMAIL_PASSWORD")

# Function to fetch and search blog content
def check_blogs_for_keywords():
    matches = []
    for url in blog_urls:
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')
            text = soup.get_text().lower()
            found_keywords = [kw for kw in keywords if kw.lower() in text]
            if found_keywords:
                matches.append((url, found_keywords))
        except Exception as e:
            print(f"Error fetching {url}: {e}")
    return matches

# Function to send email alert
def send_email_alert(matches):
    if not matches:
        print("No keywords found. No email sent.")
        return

    subject = "Cybersecurity Alert: Keywords Found in Blogs"
    body = "The following keywords were found in the monitored blogs:\n\n"
    for url, found in matches:
        body += f"{url}:\n  - " + ", ".join(found) + "\n\n"

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = ", ".join(recipient_emails)
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(sender_email, email_password)
            server.sendmail(sender_email, recipient_emails, msg.as_string())
        print("Email alert sent successfully.")
    except Exception as e:
        print(f"Failed to send email: {e}")

# Main execution
if __name__ == "__main__":
    keyword_matches = check_blogs_for_keywords()
    send_email_alert(keyword_matches)

