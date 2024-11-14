#!/usr/bin/env python3

import logging
import socket
import sys
import argparse
import dns.resolver
import warnings
from dns.rrset import from_text
from scapy.all import DNS, DNSQR, DNSRR
from dnslib import DNSRecord, DNSHeader, DNSQuestion, RR, QTYPE
import requests
import base64

DNS_PORT = 53
DNS_SERVER_IP = '127.0.0.1'

# Timeout values (in seconds)
DOH_TIMEOUT = 50  # Timeout for DNS-over-HTTPS requests
SOCKET_TIMEOUT = 10  # Timeout for socket (local DNS queries)

# Function to initialize logging
def initialize_logger(log_file):
    logging.basicConfig(filename=log_file, filemode='a', format="%(message)s", level=logging.INFO)
    return logging.getLogger()

query_type_mapping = { 1: "A", 28: "AAAA", 15: "MX", 2: "NS", 5: "CNAME"}

# Function to initialize the DNS server socket
def initialize_dns_server():
    try:
        dns_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        dns_socket.bind((DNS_SERVER_IP, DNS_PORT))
        dns_socket.settimeout(SOCKET_TIMEOUT)  # Set timeout for socket
        print(f'DNS server is listening on {DNS_SERVER_IP}:{DNS_PORT}')
        print(f'Usage: dig @{DNS_SERVER_IP} -t q_type domain_name')
        return dns_socket
    except Exception as e:
        print(f"An error occurred while initializing the DNS server: {e}")
        return None

# Argument parsing
parser = argparse.ArgumentParser(description='DNS FORWARDER')
parser.add_argument("-d", metavar='DST_IP', type=str, help='Destination DNS server IP', required=False)
parser.add_argument("-f", metavar='DENY_LIST_FILE', type=str, help='File containing domains to block', required=False)
parser.add_argument("-l", metavar='LOG_FILE', default='logfile.log', type=str, help='Append-only log file', required=False)
parser.add_argument("--doh", help='Use default upstream DoH server', action='store_true')
parser.add_argument("--doh_server", metavar='DOH_SERVER', help='Use this upstream DoH server', required=False)
args = parser.parse_args()

logs = initialize_logger(args.l)

deny_list = []

# Loading deny list from a file
if args.f:
    try:
        with open(args.f, 'r') as denied:
            deny_list = [line.strip() for line in denied]
    except FileNotFoundError:
        print(f"Error: The file '{args.f}' was not found.")
    except Exception as e:
        print(f"An error occurred while reading the blocklist file: {e}")

# Function to handle DNS requests (forwarding to another DNS server or handling locally)
def handle_dns_request(socket, query, client_address):
    qname, qtype = str(query.q.qname)[:-1], query.q.qtype
    record_type = query_type_mapping.get(qtype, "UNKNOWN")

    resolver = dns.resolver.Resolver()

    if qname in deny_list:
       action = "DENY"
       rcode = 3  # NXDOMAIN
    else:
        action = "ALLOW"
        try:
            if args.d:  # Use the IP address for forwarding
                resolver.nameservers = [args.d]
            answer = resolver.resolve(qname, qtype)
            rcode = 0  # NOERROR
        except dns.resolver.NXDOMAIN:
            rcode = 3  # NXDOMAIN
        except Exception as e:
            rcode = 2  # Server failure or other error

    logs.info(f'{qname} {record_type} {action}')

    response = create_dns_response(query.header.id, qname, qtype, rcode)

    if not qname in deny_list and rcode == 0:
        for resource_record in answer.response.answer:
            response.add_answer(*RR.fromZone(str(resource_record)))

    socket.sendto(response.pack(), client_address)

# Function to create a DNS response
def create_dns_response(query_id, qname, qtype, rcode):
    return DNSRecord(DNSHeader(id=query_id, qr=1, aa=1, ra=1, rcode=rcode), q=DNSQuestion(qname, qtype=qtype))

# Function to handle DNS-over-HTTPS requests
def handle_dns_over_http_request(socket, query, client_address, doh_server, deny_list, logs):
    # Prepare the DNS request in the DNS wire format (from dnslib)
    dns_request = DNSRecord(DNSHeader(rd=1))
    dns_request.add_question(DNSQuestion(qname=str(query.q.qname)[:-1], qtype=query.q.qtype))

    # Pack the DNS request and base64 encode it for the DoH query
    dns_request_bytes = dns_request.pack()  
    url = f'https://{doh_server}/dns-query?dns={base64.urlsafe_b64encode(dns_request_bytes).rstrip(b"=").decode()}'

    # Send the GET request to the DoH server with a timeout
    headers = {'content-type': 'application/dns-message'}
    try:
        response = requests.get(url, headers=headers, timeout=DOH_TIMEOUT)

        # Check if the response is successful (HTTP status code 200)
        if response.status_code != 200:
            print(f"Error: Failed to retrieve DNS data from DoH server (HTTP {response.status_code})")
            return

        # Parse the DNS response content using dnslib
        parsed_response = DNSRecord.parse(response.content)

        # Prepare a final response to send back to the client
        final_response = DNSRecord(
            DNSHeader(
                id=query.header.id,
                qr=parsed_response.header.qr,
                rd=parsed_response.header.rd,
                ra=parsed_response.header.ra,
                ad=parsed_response.header.ad,
                aa=parsed_response.header.aa,
                rcode=parsed_response.header.rcode
            )
        )
        final_response.add_question(DNSQuestion(str(query.q.qname)[:-1], qtype=query.q.qtype))

        # Determine whether the domain is in the deny list
        domain_name = str(query.q.qname)[:-1]
        qtype = query.q.qtype
        action = "ALLOW" if domain_name not in deny_list else "DENY"
        logs.info(f'{domain_name} {qtype} {action}')

        # If the domain is blocked, set NXDOMAIN
        if action == "DENY":
            final_response.header.rcode = 3  # NXDOMAIN
        else:
            # Add the answers from the parsed DoH response
            for rr_data in parsed_response.rr:
                rr_type = rr_data.rtype
                rr_info = f'{domain_name} {rr_data.ttl} IN {QTYPE[rr_type]} {rr_data.rdata}'

                # Add the answer to the final response
                final_response.add_answer(*RR.fromZone(rr_info))

        # Send the response back to the client
        socket.sendto(final_response.pack(), client_address)

    except requests.RequestException as e:
        print(f"Error in DoH request: {e}")
        return
    except Exception as e:
        print(f"General error occurred: {e}")
        return

# Initialize the DNS server
sock = initialize_dns_server()

# Main loop: Handling incoming DNS requests
while True:
    try:
        data, client_address = sock.recvfrom(4096)
        query = DNSRecord.parse(data)

        if args.d:
            handle_dns_request(sock, query, client_address)
        elif args.doh or args.doh_server:
            # Use args.doh_server if specified; otherwise, default to '1.1.1.1'
            doh_server = args.doh_server if args.doh_server else '1.1.1.1'
            handle_dns_over_http_request(sock, query, client_address, doh_server, deny_list, logs)

    except socket.timeout:
        print("Socket timeout: No data received from clients.")
    except Exception as e:
        print(f"Error occurred while processing DNS query: {e}")
