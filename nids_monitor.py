import json
import time
from datetime import datetime

LOG_FILE = "/var/log/suricata/eve.json"
INCIDENT_LOG = "/home/kushal/incident_response.log"

print("NIDS Alert Monitor Started")
print("Waiting for Suricata alerts...\n")

with open(LOG_FILE, "r") as file:
    file.seek(0, 2)

    while True:
        line = file.readline()

        if not line:
            time.sleep(1)
            continue

        try:
            event = json.loads(line)

            if event.get("event_type") == "alert":
                alert = event.get("alert", {})

                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                source_ip = event.get("src_ip")
                destination_ip = event.get("dest_ip")
                protocol = event.get("proto")
                signature = alert.get("signature")
                severity = alert.get("severity")
                action = alert.get("action")

                print("=" * 60)
                print("🚨 SECURITY ALERT")
                print("=" * 60)
                print("Time           :", timestamp)
                print("Source IP      :", source_ip)
                print("Destination IP :", destination_ip)
                print("Protocol       :", protocol)
                print("Signature      :", signature)
                print("Severity       :", severity)
                print("Action         :", action)
                print("=" * 60)

                with open(INCIDENT_LOG, "a") as incident_file:
                    incident_file.write("=" * 60 + "\n")
                    incident_file.write("SECURITY INCIDENT\n")
                    incident_file.write("=" * 60 + "\n")
                    incident_file.write(f"Time: {timestamp}\n")
                    incident_file.write(f"Source IP: {source_ip}\n")
                    incident_file.write(f"Destination IP: {destination_ip}\n")
                    incident_file.write(f"Protocol: {protocol}\n")
                    incident_file.write(f"Signature: {signature}\n")
                    incident_file.write(f"Severity: {severity}\n")
                    incident_file.write(f"Action: {action}\n")
                    incident_file.write(
                        "Response: Alert recorded for SOC investigation\n"
                    )
                    incident_file.write("=" * 60 + "\n\n")

                print("Response: Incident recorded")
                print()

        except json.JSONDecodeError:
            continue
