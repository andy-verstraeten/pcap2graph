import os
import sys

import pytest
import scapy.all

p = os.path.abspath(".")
sys.path.insert(1, p)


from pcap2graph import *


def test_pcap2graph_input_file_nonexistant(capsys, monkeypatch):
    """Test if correct message is shown when file is not found."""

    def raise_file_not_found_error(file):
        raise FileNotFoundError

    monkeypatch.setattr(scapy.all, "rdpcap", raise_file_not_found_error)
    pcap2graph("/not_existant_file.pcap", "output.md")
    captured = capsys.readouterr()
    assert captured.out == "Input file does not exist.\n"


def test_pcap2graph_input_file_scapy_error(capsys, monkeypatch):
    """Test correct response when input file is not a pcap and raises SyntaxError"""

    def raise_scapy_error(*args, **kwargs):
        raise scapy.all.Scapy_Exception

    monkeypatch.setattr(scapy.all, "rdpcap", raise_scapy_error)

    pcap2graph("/not_a_pcap.pcap", "output.md")
    captured = capsys.readouterr()
    assert captured.out == "Input file does not seem to be a valid pcap.\n"


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


"""
def test_load_pcap_file_not_exist(capsys, tmp_path):
    path = os.path.join(tmp_path, "not_exist.pcap")
    load_pcap(path)
    captured = capsys.readouterr()
    assert captured.out == "Input file does not exist.\n"
"""


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
