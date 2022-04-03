from argparse import ArgumentParser, Namespace
from sys import argv, stdin
from typing import Dict, List, Set

from scapy.all import Packet, PacketList, rdpcap


def load_pcap(filename: str) -> PacketList:
    """Loads a pcap file from path

    Args:
        filename (str): Path to the pcap file

    Returns:
        PacketList: a list of Scapy packets
    """
    packets = rdpcap(filename)
    return packets


def map_unique_ip_connections(packets: PacketList) -> dict:
    """Map all unique source and destination IP pairs

    Args:
        packets (PacketList): A list of packets

    Returns:
        dict: dict of all src ip's containing a set of the destination ip's
    """
    src_ips: Dict[str, Set] = {}
    for p in packets:
        if p.src in src_ips:
            src_ips[p.src].add(p.dst)
        elif p.dst in src_ips:
            src_ips[p.dst].add(p.src)
        else:
            src_ips[p.src] = {p.dst}
    return src_ips


def generate_connections_markdown(connections: dict) -> str:
    """Generate markdown to go inside Mermaid from the connnection dictionary

    Args:
        connections (dict): A dictionary with src_ip as keys containing sets of destination ip's for the source.

    Returns:
        str: Markdown to go inside mermaid block
    """
    connection_strings = []
    for src_ip in connections.keys():
        for dst_ip in connections[src_ip]:
            connection_strings.append(f"{src_ip}---{dst_ip}")
    return "\n".join(connection_strings)


def generate_markdown(connections: dict) -> str:
    """Generate markdown from connections

    Args:
        connections (dict): A dictionary with src_ip as keys containing sets of destination ip's for the source.

    Returns:
        str: Markdown of the mermaid graph
    """
    connection_md = generate_connections_markdown(connections)
    return f"""
```mermaid
graph TB
{connection_md}
"""


def save_md_to_file(markdown: str, output_file: str):
    """Save the markdown string to the output_file.

    Args:
        markdown (str): A string containing valid markdown
        output_file (str): Output file
    """
    with open(output_file, "w+") as f:
        f.write(markdown)


def parse_args(argv: List[str] | None = None) -> Namespace:
    """Parse command line arguments

    Args:
        argv (List[str] | None, optional): List of command line arguments. Defaults to None.

    Returns:
        Namespace: Namespace object containing the argument values.
    """
    parser = ArgumentParser()
    parser.add_argument(
        "--input",
        "-i",
        type=str,
        default=stdin,
        metavar="PATH",
        help="Input pcap file.",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default=stdin,
        metavar="PATH",
        help="Path to output markdown file(.md).",
    )
    return parser.parse_args(argv)


if __name__ == "__main__":
    args = parse_args(argv[1:])
    packets = load_pcap(args.input)
    connections = map_unique_ip_connections(packets)
    markdown = generate_markdown(connections)
    save_md_to_file(markdown, args.output)
