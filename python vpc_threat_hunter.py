import boto3
import gzip
import io
import os
from datetime import datetime

# Configure your S3 bucket details
BUCKET_NAME = 'aws-security-logs-jar-2026'
# Leave prefix empty if testing, or specify the AWS Logs path
PREFIX = 'AWSLogs/'

s3_client = boto3.client('s3')

def fetch_and_parse_logs():
    print(f"[*] Scanning S3 Bucket: {BUCKET_NAME} for suspicious traffic...")
    
    response = s3_client.list_objects_v2(Bucket=BUCKET_NAME, Prefix=PREFIX)
    
    if 'Contents' not in response:
        print("[-] No logs found yet. Wait 5-10 minutes for AWS to deliver them.")
        return

    threat_events = []

    for obj in response['Contents']:
        key = obj['Key']
        if not key.endswith('.log.gz'):
            continue
            
        # Download and decompress the log file in memory
        log_obj = s3_client.get_object(Bucket=BUCKET_NAME, Key=key)
        compressed_content = log_obj['Body'].read()
        
        with gzip.GzipFile(fileobj=io.BytesIO(compressed_content), mode='rb') as gz:
            log_lines = gz.read().decode('utf-8').splitlines()
            
            # Skip the AWS header line
            for line in log_lines[1:]:
                fields = line.split()
                if len(fields) < 14: continue
                
                src_ip = fields[3]
                dst_port = fields[6]
                action = fields[12]
                
                # Threat Logic: Flag REJECTED traffic targeting SSH (22) or RDP (3389)
                if action == 'REJECT' and dst_port in ['22', '3389']:
                    threat_events.append({
                        'timestamp': datetime.now().isoformat(),
                        'attacker_ip': src_ip,
                        'target_port': dst_port,
                        'action': 'BLOCKED_BRUTE_FORCE'
                    })

    if threat_events:
        print(f"[!] {len(threat_events)} suspicious events detected.")
        for event in threat_events:
            print(f"    -> [ALERT] IP: {event['attacker_ip']} | Target Port: {event['target_port']} | Status: {event['action']}")
    else:
        print("[+] Network traffic is clean. No high-risk anomalies detected.")

if __name__ == '__main__':
    fetch_and_parse_logs()
