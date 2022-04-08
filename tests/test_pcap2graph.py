import os
import sys

from scapy.all import IP

p = os.path.abspath(".")
sys.path.insert(1, p)


from pcap2graph import *


def test_parse_args_input_file_i_flag():
    """Test to see if -i flag with input file works correctly"""
    filename = "/Users/andyverstraeten/Downloads/pcaps/nitroba.pcap"
    args = parse_args(["-i", filename])
    assert args.input == filename


def test_parse_args_output_file_o_flag():
    """Test to see if -i flag with input file works correctly"""
    filename = "/Users/andyverstraeten/Downloads/pcaps/nitroba.pcap"
    args = parse_args(["-o", filename])
    assert args.output == filename


def test_generate_connections_markdown():
    test_connections = {"1.1.1.1": ("2.2.2.2", "3.3.3.3")}
    expected_output = "1.1.1.1---2.2.2.2\n1.1.1.1---3.3.3.3"
    actual_output = generate_connections_markdown(test_connections)
    assert expected_output == actual_output


def test_generate_markdown():
    test_connections = {"1.1.1.1": ("2.2.2.2", "3.3.3.3")}
    expected_output = """
```mermaid
graph LR
1.1.1.1---2.2.2.2
1.1.1.1---3.3.3.3
"""
    actual_output = generate_markdown(test_connections)
    assert expected_output == actual_output


def create_packet_mock(src, dst):
    packet = IP()
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
