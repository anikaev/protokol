
import ipaddress
import sys
import re
from socket import socket, AF_INET, SOCK_RAW, IPPROTO_ICMP, \
    IPPROTO_IP, IP_HDRINCL, error, SOCK_DGRAM, create_connection, \
    timeout, gethostbyname, gaierror
from struct import pack
from argparse import ArgumentParser
from logging import warning
from tabulate import tabulate

DEFAULT_TTL = 30
DEFAULT_WHOIS_SERVER = "192.0.32.59"
WHOIS_PORT = 43
TIMEOUT = 5

def main():
    destination = argument_parse()

    try:
        sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
        sock.setsockopt(IPPROTO_IP, IP_HDRINCL, 1)
        sock.settimeout(TIMEOUT)
    except error:
        print("Permission denied")
        sys.exit(0)

    source = get_ip()
    results = []  # Храним данные для таблицы

    try:
        address = gethostbyname(destination[0])
        print("Tracing route to", address)
        ttl = 1
        current_address = ""
        while ttl <= DEFAULT_TTL and current_address != address:
            buff = package_assembly(ttl, source, address)
            sock.sendto(buff, (destination[0], 0))
            try:
                reply = sock.recvfrom(1024)
                current_address = reply[1][0]

                if is_local_ip(current_address):
                    asn, country, netname = "-", "-", "-"
                else:
                    country, netname, asn = get_info(current_address)
                    country = country or "-"
                    netname = netname or "-"
                    asn = asn or "-"

                results.append((ttl, current_address, asn, country, netname))

            except timeout:
                results.append((ttl, "*", "-", "-", "-"))

            ttl += 1

    except gaierror:
        warning("Wrong destination: {}".format(destination[0]))
    except timeout:
        print("Timeout exceeded.")
    finally:
        sock.close()

    # Выводим таблицу
    headers = ["№", "IP", "AS", "Country", "Provider"]
    print("\nРезультат трассировки:\n")
    print(tabulate(results, headers=headers, tablefmt="grid"))

def is_local_ip(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return ip_obj.is_private

def argument_parse():
    parser = ArgumentParser()
    parser.add_argument("destination", type=str, nargs=1, default=["8.8.8.8"])
    args = parser.parse_args()
    return args.destination

def package_assembly(ttl, source, destination):
    version_ihl = 4 << 4 | 5
    total_length = 60
    protocol_icmp = 1
    source = address_format(source)
    destination = address_format(destination)
    echo_icmp = 8

    ip_header = pack("!BBHLBBH", version_ihl, 0, total_length,
                     0, ttl, protocol_icmp, 0) + source + destination
    icmp_header = pack("!BBHL", echo_icmp, 0, 0, 0)
    icmp_checksum = calc_checksum(icmp_header)
    icmp_header = pack("!BBHL", echo_icmp, 0, icmp_checksum, 0)
    result = ip_header + icmp_header

    return result

def address_format(address):
    addr = tuple(int(x) for x in address.split('.'))
    return pack("!BBBB", *addr)

def get_ip():
    sock = socket(AF_INET, SOCK_DGRAM)
    try:
        sock.connect((DEFAULT_WHOIS_SERVER, WHOIS_PORT))
        return sock.getsockname()[0]
    finally:
        sock.close()

def calc_checksum(packet):
    words = [int.from_bytes(packet[i:i+2], "big") for i in range(0, len(packet), 2)]
    checksum = sum(words)
    while checksum > 0xffff:
        checksum = (checksum & 0xffff) + (checksum >> 16)
    return 0xffff - checksum

def send_request(request, host_port):
    sock = create_connection(host_port, TIMEOUT)
    data = bytes()
    try:
        sock.sendall(f"{request}\r\n".encode('utf-8'))
        while True:
            buff = sock.recv(1024)
            if not buff:
                return data.decode("utf-8")
            data += buff
    finally:
        sock.close()

def get_info(address):
    REFER = re.compile(r"refer:\s*(.*?)\n")
    COUNTRY = re.compile(r"country:\s*(.*?)\n", re.IGNORECASE)
    NETNAME = re.compile(r"netname:\s*(.*?)\n", re.IGNORECASE)
    AUTONOMIC_SYSTEM = re.compile(r"origin:\s*(.*?)\n", re.IGNORECASE)

    reply = send_request(address, (DEFAULT_WHOIS_SERVER, WHOIS_PORT))
    refer = re.search(REFER, reply)
    if refer:
        refer = refer.group(1).strip()
        reply = send_request(address, (refer, WHOIS_PORT))

    country = re.search(COUNTRY, reply)
    netname = re.search(NETNAME, reply)
    asn = re.search(AUTONOMIC_SYSTEM, reply)

    return (
        country.group(1).strip() if country else None,
        netname.group(1).strip() if netname else None,
        asn.group(1).strip() if asn else None
    )

if __name__ == "__main__":
    main()
