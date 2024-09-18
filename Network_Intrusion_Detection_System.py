import json
import os
import requests

# Path to the Suricata log file (JSON output)
SURICATA_LOG_PATH = "/var/log/suricata/eve.json"

# Function to read and parse Suricata logs
def read_suricata_logs(log_file):
    with open(log_file, 'r') as f:
        for line in f:
            try:
                log_entry = json.loads(line)
                analyze_log(log_entry)
            except json.JSONDecodeError:
                continue  # Skip malformed entries

# Function to analyze a log entry
def analyze_log(log_entry):
    # Check if the log entry contains an alert
    if log_entry.get('event_type') == 'alert':
        alert_info = log_entry.get('alert', {})
        src_ip = log_entry.get('src_ip', 'Unknown')
        dest_ip = log_entry.get('dest_ip', 'Unknown')
        alert_signature = alert_info.get('signature', 'Unknown Alert')

        print(f"Alert: {alert_signature} | Source: {src_ip} | Destination: {dest_ip}")

        # If ICMP flood or other types of attacks detected, block the source IP
        if "ICMP Flood" in alert_signature or "DDoS" in alert_signature:
            block_ip(src_ip)
            send_slack_alert(f"Blocked IP {src_ip} for {alert_signature}")

# Function to block an IP address using IPTables
def block_ip(ip):
    try:
        os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")
        print(f"Blocked IP: {ip}")
    except Exception as e:
        print(f"Error blocking IP {ip}: {e}")

# Optional: Send alerts to Slack
def send_slack_alert(message):
    slack_webhook_url = 'https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK'
    payload = {'text': message}
    try:
        requests.post(slack_webhook_url, json=payload)
        print(f"Sent Slack alert: {message}")
    except Exception as e:
        print(f"Failed to send Slack alert: {e}")

# Main function to start monitoring logs
def start_monitoring():
    print("Starting Suricata log monitoring...")
    read_suricata_logs(SURICATA_LOG_PATH)

# Run the script
if __name__ == "__main__":
    start_monitoring()
