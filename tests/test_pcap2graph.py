import os
import sys

from scapy.all import Packet

p = os.path.abspath(".")
sys.path.insert(1, p)


from pcap2graph import *


def test_generate_connections_markdown():
    test_connections = {"1.1.1.1": ("2.2.2.2", "3.3.3.3")}
    expected_output = "1.1.1.1---2.2.2.2\n1.1.1.1---3.3.3.3"
    actual_output = generate_connections_markdown(test_connections)
    assert expected_output == actual_output


def test_generate_markdown():
    test_connections = {"1.1.1.1": ("2.2.2.2", "3.3.3.3")}
    expected_output = """
```mermaid
graph TB
1.1.1.1---2.2.2.2
1.1.1.1---3.3.3.3
"""
    actual_output = generate_markdown(test_connections)
    assert expected_output == actual_output


def create_packet_mock(src, dst):
    packet = Packet()
    packet.src = "1.1.1.1"
    packet.dst = "2.2.2.2"
    return packet


def test_map_unique_ip_connections():
    test_packet_list = PacketList(
        [
            create_packet_mock("1.1.1.1", "2.2.2.2"),
            create_packet_mock("1.1.1.1", "2.2.2.2"),
            create_packet_mock("2.2.2.2", "1.1.1.1"),
        ]
    )
    expected_output = {"1.1.1.1": {"2.2.2.2"}}
    actual_output = map_unique_ip_connections(test_packet_list)
    assert expected_output == actual_output
