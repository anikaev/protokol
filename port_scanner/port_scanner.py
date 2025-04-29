"""Port scanner module"""
import threading
import argparse
import socket
import struct
import re

DNS_ID = 23330
DNS_PACKET = struct.pack('!HHHHHH', DNS_ID, 256, 1, 0, 0, 0) + \
    b'\x06google\x03com\x00\x00\x01\x00\x01'
NTP_PACKET = struct.pack('!BBBb11I', 0b00100011, *([0]*14))
HTTP_PACKET = b'GET / HTTP/1.1\r\nHost: google.com\r\n\r\n'
SMTP_PACKET = b'Mock message'
POP3_PACKET = b'AUTH'

TCP_PACKETS = {
    'dns': struct.pack('!H', len(DNS_PACKET)) + DNS_PACKET,
    'http': HTTP_PACKET,
    'smtp': SMTP_PACKET,
    'pop3': POP3_PACKET,
}

UDP_PACKETS = {
    'dns': DNS_PACKET,
    'ntp': NTP_PACKET
}


class PortScanner:
    """Class for scanning ports"""

    def __init__(self, target: str, start: int, end: int) -> None:
        self.target = target
        self.start = start
        self.end = end
        self.open_tcp_ports = []
        self.open_udp_ports = []

    def check_protocol(self, packet: bytes):
        """Checks the protocol of the packet"""
        if struct.pack('!H', DNS_ID) in packet:
            return 'dns'
        if packet.startswith(b'HTTP'):
            return 'http'
        if re.match(b'[0-9]{3}', packet[:3]):
            return 'smtp'
        if packet.startswith(b'+'):
            return 'pop3'

        try:
            struct.unpack('!BBBb11I', packet)
            return 'ntp'
        except struct.error:
            pass

        return 'undefined'

    def scan_tcp_port(self, port: int):
        """Scans TCP port"""
        protocol = ""

        for packet in TCP_PACKETS.values():
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(1)
                try:
                    sock.connect((self.target, port))
                    sock.sendall(packet)
                    data = sock.recv(1024)
                    protocol = self.check_protocol(data)
                except (ConnectionResetError, ConnectionRefusedError,
                        PermissionError, TimeoutError):
                    continue

        if protocol:
            self.open_tcp_ports.append((port, protocol))

    def scan_udp_port(self, port: int):
        """Scans UDP port"""
        protocol = ""

        for packet in UDP_PACKETS.values():
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(1)
                try:
                    sock.sendto(packet, (self.target, port))
                    data, _ = sock.recvfrom(1024)
                    protocol = self.check_protocol(data)
                except (ConnectionResetError, ConnectionRefusedError,
                        PermissionError, TimeoutError):
                    continue

        if protocol:
            self.open_udp_ports.append((port, protocol))

    def scan_ports(self):
        """Scans ports"""
        threads: list[threading.Thread] = []

        for port in range(self.start, self.end + 1):
            t1 = threading.Thread(target=self.scan_tcp_port, args=(port,))
            t2 = threading.Thread(target=self.scan_udp_port, args=(port,))
            threads += [t1, t2]
            t1.start()
            t2.start()

        for thread in threads:
            thread.join()
        threads.clear()


def main():
    parser = argparse.ArgumentParser(
        prog="Port scanner",
        description="Scan open ports in given range"
    )
    parser.add_argument('hostname', action='store', help='Hostname/IP address')
    parser.add_argument('start', action='store',
                        type=int, help="Starting port")
    parser.add_argument('end', action='store', type=int, help="Ending port")
    args = parser.parse_args()

    if args.start < 1 or args.end > 65535 or \
            args.end < args.start:
        print('Invalid argumens')
        return

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as mock_sock:
        try:
            mock_sock.bind((args.hostname, 8888))
        except socket.gaierror:
            print('Invalid hostname')
            return
        except OSError:
            pass

    port_scanner = PortScanner(args.hostname, args.start, args.end)
    port_scanner.scan_ports()

    for port, protocol in port_scanner.open_tcp_ports:
        print(f'TCP port {port} is open. (protocol: {protocol})')
    for port, protocol in port_scanner.open_udp_ports:
        print(f'UDP port {port} is open. (protocol: {protocol})')


if __name__ == '__main__':
    main()
