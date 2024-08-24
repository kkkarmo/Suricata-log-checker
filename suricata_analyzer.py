import os
from groq import Groq
import json
from datetime import datetime
import time
import ipaddress
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

# Configuration from environment variables
GROQ_API_KEY = os.getenv('GROQ_API_KEY')
EVE_JSON_LOG_PATH = os.getenv('EVE_JSON_LOG_PATH')
OUTPUT_DIR = os.getenv('OUTPUT_DIR')

client = Groq(api_key=GROQ_API_KEY)

# Custom private IP ranges and common DNS servers
CUSTOM_PRIVATE_RANGES = [
    ipaddress.ip_network('20.20.20.0/24'),
    ipaddress.ip_network('192.168.0.0/16'),
]

COMMON_DNS_SERVERS = [
    '1.1.1.1', '1.1.1.3', '1.0.0.1', '8.8.8.8', '8.8.4.4', '9.9.9.9', '149.112.112.112',
    '208.67.222.222', '208.67.220.220', '64.6.64.6', '64.6.65.6', '185.228.168.9',
    '185.228.169.9', '76.76.19.19', '76.76.2.0',
]

def is_public_ip(ip_string):
    try:
        ip = ipaddress.ip_address(ip_string)
        if any(ip in network for network in CUSTOM_PRIVATE_RANGES):
            return False
        if str(ip) in COMMON_DNS_SERVERS:
            return False
        return not (ip.is_private or ip.is_loopback or ip.is_link_local)
    except ValueError:
        return False

def analyze_event(event):
    src_ip = event.get("src_ip", "")
    dest_ip = event.get("dest_ip", "")
    
    if not (is_public_ip(src_ip) or is_public_ip(dest_ip)):
        return None
    
    event_data = {
        "timestamp": event.get("timestamp", ""),
        "event_type": event.get("event_type", ""),
        "src_ip": src_ip,
        "src_port": event.get("src_port", ""),
        "dest_ip": dest_ip,
        "dest_port": event.get("dest_port", ""),
        "proto": event.get("proto", ""),
        "app_proto": event.get("app_proto", ""),
        "alert": event.get("alert", {}),
    }
    
    prompt = f"""Analyze the following Suricata event involving at least one public IP address and provide a brief security assessment:
    {json.dumps(event_data, indent=2)}
    
    Consider the following in your analysis:
    1. Is there any suspicious activity related to the public IP(s)?
    2. What is the nature of the communication (e.g., incoming connection, outgoing connection)?
    3. Are there any potential security risks or indicators of compromise?
    4. What recommendations would you make for further investigation or action?
    """
    
    try:
        response = client.chat.completions.create(
            model="mixtral-8x7b-32768",
            messages=[
                {"role": "system", "content": "You are a cybersecurity analyst specializing in network security, threat detection, and Suricata logs."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=200,
            temperature=0.5,
        )
        
        analysis = response.choices[0].message.content.strip()
        return {"event": event_data, "analysis": analysis}
    except Exception as e:
        print(f"API request failed: {e}")
        return None

class LogHandler(FileSystemEventHandler):
    def __init__(self):
        self.last_position = 0
        self.output_file = os.path.join(OUTPUT_DIR, f"suricata_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")

    def on_modified(self, event):
        if event.src_path == EVE_JSON_LOG_PATH:
            self.process_new_events()

    def process_new_events(self):
        with open(EVE_JSON_LOG_PATH, 'r') as log_file:
            log_file.seek(self.last_position)
            for line in log_file:
                try:
                    event = json.loads(line.strip())
                    result = analyze_event(event)
                    if result:
                        self.save_result(result)
                except json.JSONDecodeError:
                    continue
            self.last_position = log_file.tell()

    def save_result(self, result):
        with open(self.output_file, 'a') as f:
            f.write(f"Event: {json.dumps(result['event'], indent=2)}\n")
            f.write(f"Analysis: {result['analysis']}\n\n")

def main():
    if not all([GROQ_API_KEY, EVE_JSON_LOG_PATH, OUTPUT_DIR]):
        print("Error: Missing required environment variables.")
        return

    print(f"Starting Suricata log analysis.")
    print(f"Watching log file: {EVE_JSON_LOG_PATH}")
    print(f"Saving results to: {OUTPUT_DIR}")

    event_handler = LogHandler()
    observer = Observer()
    observer.schedule(event_handler, path=os.path.dirname(EVE_JSON_LOG_PATH), recursive=False)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    main()
