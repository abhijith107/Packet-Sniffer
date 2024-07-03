#!/usr/bin/env python
import sys
import argparse
import logging
from scapy.all import sniff, Raw
from scapy.layers.http import HTTPRequest

def get_interface():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Specify interface on which to sniff packets")
    arguments = parser.parse_args()
    return arguments.interface

def sniff_packets(iface):
    try:
        print(f"Sniffing on interface {iface}...")
        sniff(iface=iface, store=False, prn=process_packet)
    except Exception as e:
        logging.error(f"Error occurred while sniffing: {str(e)}")

def process_packet(packet):
    try:
        if packet.haslayer(HTTPRequest):
            method = packet[HTTPRequest].Method if isinstance(packet[HTTPRequest].Method, bytes) else str(packet[HTTPRequest].Method)
            host = packet[HTTPRequest].Host if isinstance(packet[HTTPRequest].Host, bytes) else str(packet[HTTPRequest].Host)
            path = packet[HTTPRequest].Path if isinstance(packet[HTTPRequest].Path, bytes) else str(packet[HTTPRequest].Path)
            headers = packet[HTTPRequest].fields  # Get all HTTP headers
            header_info = "\n".join([f"{k.decode('utf-8', errors='ignore')}: {v.decode('utf-8', errors='ignore')}" if isinstance(v, bytes) else f"{k}: {v}" for k, v in headers.items()])

            print(f"\n[+] HTTP Request:")
            print(f"    - Method: {method}")
            print(f"    - Host: {host}")
            print(f"    - Path: {path}")
            print(f"    - Headers:\n{header_info}")

            if packet.haslayer(Raw):
                load = packet[Raw].load.decode('utf-8', errors='ignore') if isinstance(packet[Raw].load, bytes) else str(packet[Raw].load)
                keys = ["username", "password", "pass", "email"]
                for key in keys:
                    if key in load:
                        print(f"\n[+] Potential credentials found in payload:")
                        print(f"    {load.strip()}\n")
                        break
    except Exception as e:
        logging.error(f"Error processing packet: {str(e)}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
    iface = get_interface()
    if not iface:
        logging.error("Please specify an interface using '-i' or '--interface'")
        sys.exit(1)
    sniff_packets(iface)

