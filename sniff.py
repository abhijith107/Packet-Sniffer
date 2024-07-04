#!/usr/bin/env python
import sys
import argparse
import logging
import json
from scapy.all import sniff, Raw, IP, TCP, UDP, DNS, DNSQR
from scapy.layers.http import HTTPRequest, HTTPResponse

def get_interface():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Specify interface on which to sniff packets")
    parser.add_argument("-o", "--output", dest="output", help="Specify output file to save captured data", default=None)
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    arguments = parser.parse_args()
    return arguments.interface, arguments.output, arguments.verbose

def sniff_packets(iface, output_file, verbose):
    try:
        print(f"Sniffing on interface {iface}...")
        sniff(iface=iface, store=False, prn=lambda x: process_packet(x, output_file, verbose))
    except Exception as e:
        logging.error(f"Error occurred while sniffing: {str(e)}")

def process_packet(packet, output_file, verbose):
    try:
        if packet.haslayer(HTTPRequest):
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
            else:
                src_ip = "Unknown"
                dst_ip = "Unknown"
            
            method = packet[HTTPRequest].Method.decode('utf-8', errors='ignore') if isinstance(packet[HTTPRequest].Method, bytes) else str(packet[HTTPRequest].Method)
            host = packet[HTTPRequest].Host.decode('utf-8', errors='ignore') if isinstance(packet[HTTPRequest].Host, bytes) else str(packet[HTTPRequest].Host)
            path = packet[HTTPRequest].Path.decode('utf-8', errors='ignore') if isinstance(packet[HTTPRequest].Path, bytes) else str(packet[HTTPRequest].Path)
            headers = packet[HTTPRequest].fields  # Get all HTTP headers
            header_info = "\n".join([f"{k.decode('utf-8', errors='ignore') if isinstance(k, bytes) else k}: {v.decode('utf-8', errors='ignore') if isinstance(v, bytes) else v}" for k, v in headers.items()])

            # Ensure headers are JSON serializable
            headers_json = {k.decode('utf-8', errors='ignore') if isinstance(k, bytes) else k: v.decode('utf-8', errors='ignore') if isinstance(v, bytes) else v for k, v in headers.items()}

            output = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "method": method,
                "host": host,
                "path": path,
                "headers": headers_json
            }

            if verbose:
                print(f"\n[+] HTTP Request:")
                print(f"    - Source IP: {src_ip}")
                print(f"    - Destination IP: {dst_ip}")
                print(f"    - Method: {method}")
                print(f"    - Host: {host}")
                print(f"    - Path: {path}")
                print(f"    - Headers:\n{header_info}")

            if packet.haslayer(Raw):
                load = packet[Raw].load.decode('utf-8', errors='ignore') if isinstance(packet[Raw].load, bytes) else str(packet[Raw].load)
                keys = ["username", "password", "pass", "email"]
                for key in keys:
                    if key in load:
                        output["credentials"] = load.strip()
                        if verbose:
                            print(f"\n[+] Potential credentials found in payload:")
                            print(f"    {load.strip()}\n")
                        break

            if output_file:
                with open(output_file, 'a') as f:
                    f.write(json.dumps(output) + "\n")

        if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:  # DNS query
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
            else:
                src_ip = "Unknown"
                dst_ip = "Unknown"
            
            dns_query = packet[DNSQR].qname.decode('utf-8')
            output = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dns_query": dns_query
            }

            if verbose:
                print(f"\n[+] DNS Request:")
                print(f"    - Source IP: {src_ip}")
                print(f"    - Destination IP: {dst_ip}")
                print(f"    - Query: {dns_query}")

            if output_file:
                with open(output_file, 'a') as f:
                    f.write(json.dumps(output) + "\n")

    except Exception as e:
        logging.error(f"Error processing packet: {str(e)}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
    iface, output_file, verbose = get_interface()
    if not iface:
        logging.error("Please specify an interface using '-i' or '--interface'")
        sys.exit(1)
    sniff_packets(iface, output_file, verbose)

