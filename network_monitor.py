# Apache License
# Version 2.0, January 2004
# http://www.apache.org/licenses/

# Copyright 2025 emanoyhl and emanoyhl.net find me at github.com/emanoyhl 
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from scapy.all import sniff

class NetworkMonitor:
    def __init__(self):
        self.suspicious_keywords = ['malicious.com', 'suspicious_ip', 'localhost', '127.0.0.1']

    def alert(self, packet):
        """Alert when suspicious activity is detected."""
        if packet.haslayer('IP') and packet.haslayer('TCP'):
            ip_src = packet['IP'].src
            ip_dst = packet['IP'].dst
            
            # Check for suspicious keywords in HTTP requests
            if packet.haslayer('Raw'):
                payload = str(packet['Raw'].load)
                #print(f"Captured payload: {payload}")  # LIVE VIEW disable for just monitoring, otherwise it'll act like wireshark in a sense...
                if any(keyword in payload for keyword in self.suspicious_keywords):
                    print(f"[ALERT] Suspicious activity detected: {ip_src} -> {ip_dst}")

    def start_monitoring(self):
        """Start monitoring network traffic.
    
    Filters:
    - ip: Capture all IP packets
    - tcp: Capture all TCP packets
    - udp: Capture all UDP packets
    - icmp: Capture all ICMP packets
    - arp: Capture all ARP packets
    - udp port 53: Capture DNS packets
    - tcp port 80: Capture HTTP packets
    - Combine filters using 'and'/'or' (e.g., 'tcp and src host 192.168.1.1')
    """
        """Start monitoring network traffic."""
        print("Starting network monitoring...")
        sniff(prn=self.alert, store=False)  # Capture all packets

if __name__ == "__main__":
    monitor = NetworkMonitor()
    monitor.start_monitoring()