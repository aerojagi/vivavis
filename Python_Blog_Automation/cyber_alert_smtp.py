import requests
from bs4 import BeautifulSoup
import smtplib
from email.mime.text import MIMEText
from datetime import datetime

# List of blog URLs to monitor
blog_urls = [
    "https://www.borncity.com/blog/",
    "https://www.bleepingcomputer.com/",
    "https://blog.talosintelligence.com/"
]

# Keywords to search for
keywords = ["Cisco", "vulnerability", "exploit", "malware", "zero-day", "threat"]

# Email configuration
SMTP_SERVER = "smtp.example.com"  # Replace with actual SMTP server
SMTP_PORT = 587
EMAIL_SENDER = "your_email@example.com"  # Replace with sender email
EMAIL_PASSWORD = "your_password"         # Replace with sender email password
EMAIL_RECIPIENTS = ["recipient1@example.com", "recipient2@example.com"]  # Replace with actual recipients

# Function to check each blog for keywords
def check_blogs():
    alerts = []
    for url in blog_urls:
        try:
            response = requests.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            text = soup.get_text().lower()
            found_keywords = [kw for kw in keywords if kw.lower() in text]
            if found_keywords:
                alerts.append(f"Keywords {found_keywords} found on {url}")
        except Exception as e:
            alerts.append(f"Error accessing {url}: {str(e)}")
    return alerts

# Function to send email alert
def send_email(alerts):
    if not alerts:
        return
    body = "\n".join(alerts)
    msg = MIMEText(body)
    msg['Subject'] = f"Cybersecurity Alert - {datetime.now().strftime('%Y-%m-%d %H:%M')}"
    msg['From'] = EMAIL_SENDER
    msg['To'] = ", ".join(EMAIL_RECIPIENTS)

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_SENDER, EMAIL_PASSWORD)
            server.sendmail(EMAIL_SENDER, EMAIL_RECIPIENTS, msg.as_string())
        print("Alert email sent successfully.")
    except Exception as e:
        print(f"Failed to send email: {str(e)}")

# Main execution
if __name__ == "__main__":
    alerts = check_blogs()
    send_email(alerts)

