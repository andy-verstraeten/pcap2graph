# pcap2graph
CLI tool to visualise contents of a PCAP file in a Mermaid markdown graph.

# Usage

python3 pcap2graph.py -i input.pcap -o /path/to/output.md

# Example output

```mermaid
graph LR
192.168.198.225---192.168.198.255
192.168.198.225---192.168.198.2
192.168.198.225---192.168.198.224
192.168.198.225---239.255.255.250