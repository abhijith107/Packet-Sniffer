#!/usr/bin/env python
import sys
import argparse
import logging
import json
from scapy.all import sniff, Raw, IP, TCP, UDP, DNS, DNSQR
from scapy.layers.http import HTTPRequest
from scapy.layers.tls.all import TLS, TLSClientHello, TLSClientKeyExchange, TLSCertificate
from scapy.layers.inet import ICMP
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import asyncio
from concurrent.futures import ThreadPoolExecutor

def get_interface():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", help="Specify interface on which to sniff packets")
    parser.add_argument("-o", "--output", dest="output", help="Specify output file to save captured data", default=None)
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    arguments = parser.parse_args()
    return arguments.interface, arguments.output, arguments.verbose

def analyze_tls(packet, src_ip, dst_ip, output, verbose):
    tls_layer = packet[TLS]
    tls_info = {}

    if tls_layer.haslayer(TLSClientHello):
        tls_info['type'] = 'Client Hello'
        tls_info['version'] = tls_layer[TLSClientHello].version
        tls_info['cipher_suites'] = tls_layer[TLSClientHello].cipher_suites

    elif tls_layer.haslayer(TLSClientKeyExchange):
        tls_info['type'] = 'Client Key Exchange'
        tls_info['public_key'] = tls_layer[TLSClientKeyExchange].pubkey

    elif tls_layer.haslayer(TLSCertificate):
        try:
            raw_cert = tls_layer[TLSCertificate].certificates[0]
            cert = x509.load_der_x509_certificate(raw_cert, default_backend())
            tls_info['cert_subject'] = cert.subject.rfc4514_string()
            tls_info['cert_issuer'] = cert.issuer.rfc4514_string()
            tls_info['cert_not_valid_before'] = cert.not_valid_before.isoformat()
            tls_info['cert_not_valid_after'] = cert.not_valid_after.isoformat()
            tls_info['cert_expired'] = cert.not_valid_after < datetime.utcnow()

            if tls_info['cert_expired']:
                tls_info['issue'] = "Certificate expired"

        except Exception as e:
            logging.error(f"Error processing TLS certificate: {str(e)}")

    output["tls_info"] = tls_info

    if verbose:
        print(f"\n[+] TLS Packet:")
        for key, value in tls_info.items():
            print(f"    - {key}: {value}")

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

        elif packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:
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

        elif packet.haslayer(TLS):
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
            else:
                src_ip = "Unknown"
                dst_ip = "Unknown"

            output = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": "TLS"
            }

            analyze_tls(packet, src_ip, dst_ip, output, verbose)

            if output_file:
                with open(output_file, 'a') as f:
                    f.write(json.dumps(output) + "\n")

        elif TCP in packet:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
            else:
                src_ip = "Unknown"
                dst_ip = "Unknown"

            load = packet[TCP].payload.decode('utf-8', errors='ignore') if isinstance(packet[TCP].payload, bytes) else str(packet[TCP].payload)

            if "220" in load or "EHLO" in load or "MAIL FROM" in load:
                protocol = "SMTP"
                output = {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "protocol": protocol,
                    "payload": load
                }

                if verbose:
                    print(f"\n[+] SMTP Packet:")
                    print(f"    - Source IP: {src_ip}")
                    print(f"    - Destination IP: {dst_ip}")
                    print(f"    - Payload: {load}")

                if output_file:
                    with open(output_file, 'a') as f:
                        f.write(json.dumps(output) + "\n")

            elif "USER" in load or "PASS" in load or "220" in load or "230" in load:
                protocol = "FTP"
                output = {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "protocol": protocol,
                    "payload": load
                }

                if verbose:
                    print(f"\n[+] FTP Packet:")
                    print(f"    - Source IP: {src_ip}")
                    print(f"    - Destination IP: {dst_ip}")
                    print(f"    - Payload: {load}")

                if output_file:
                    with open(output_file, 'a') as f:
                        f.write(json.dumps(output) + "\n")

            else:
                protocol = "TCP"
                output = {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "protocol": protocol
                }

                if verbose:
                    print(f"\n[+] TCP Packet:")
                    print(f"    - Source IP: {src_ip}")
                    print(f"    - Destination IP: {dst_ip}")

                if output_file:
                    with open(output_file, 'a') as f:
                        f.write(json.dumps(output) + "\n")

        elif UDP in packet:
            src_ip = packet[IP].src if IP in packet else "Unknown"
            dst_ip = packet[IP].dst if IP in packet else "Unknown"
            protocol = "UDP"

            output = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": protocol
            }

            if verbose:
                print(f"\n[+] UDP Packet:")
                print(f"    - Source IP: {src_ip}")
                print(f"    - Destination IP: {dst_ip}")

            if output_file:
                with open(output_file, 'a') as f:
                    f.write(json.dumps(output) + "\n")

        elif packet.haslayer(ICMP):
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
            else:
                src_ip = "Unknown"
                dst_ip = "Unknown"

            output = {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "protocol": "ICMP"
            }

            if verbose:
                print(f"\n[+] ICMP Packet:")
                print(f"    - Source IP: {src_ip}")
                print(f"    - Destination IP: {dst_ip}")

            if output_file:
                with open(output_file, 'a') as f:
                    f.write(json.dumps(output) + "\n")

        else:
            logging.warning(f"Unhandled packet: {packet.summary()}")

    except Exception as e:
        logging.error(f"Error processing packet: {str(e)}")

async def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
    iface, output_file, verbose = get_interface()
    if not iface:
        logging.error("Please specify an interface using '-i' or '--interface'")
        sys.exit(1)

    with ThreadPoolExecutor() as executor:
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(executor, sniff_packets, iface, output_file, verbose)

def sniff_packets(iface, output_file, verbose):
    try:
        print(f"Sniffing on interface {iface}...")
        sniff(iface=iface, store=False, prn=lambda x: process_packet(x, output_file, verbose))
    except Exception as e:
        logging.error(f"Error occurred while sniffing: {str(e)}")

if __name__ == "__main__":
    asyncio.run(main())

