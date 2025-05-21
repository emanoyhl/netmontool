# NetMonTool
Network monitor tool checks for suspicious keywords; uses scapy

## Usage
```bash
python network_monitor.py
```

## Settings
```bash
line 23: self.suspicious_keywords = ['malicious.com', 'suspicious_ip', 'localhost', 'any ip address', 'any key word'] - this is your list for keywords, websites, a sort of no-no list...
```

```bash
line 53: sniff(prn=self.alert, store=False) captures all packets, use filters to capture ip/tcp/udp/icmp/arp/etc...
sniff(prn=self.alert, store=False, filter=tcp)
```
  extra settings:
  ```bash
  line 34: uncomment this line #print(f"Captured payload: {payload}") to have a live view similar to wireshark
  ```
