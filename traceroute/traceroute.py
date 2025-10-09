"""
CS 168 Project 1: Traceroute Implementation

This module implements a traceroute utility that discovers the network path
to a destination by sending UDP probes with incrementing TTL values and
processing ICMP Time Exceeded and Destination Unreachable responses.
"""
import util

# Your program should send TTLs in the range [1, TRACEROUTE_MAX_TTL] inclusive.
# Technically IPv4 supports TTLs up to 255, but in practice this is excessive.
# Most traceroute implementations cap at approximately 30.  The unit tests
# assume you don't change this number.
TRACEROUTE_MAX_TTL = 30

# Cisco seems to have standardized on UDP ports [33434, 33464] for traceroute.
# While not a formal standard, it appears that some routers on the internet
# will only respond with time exceeeded ICMP messages to UDP packets send to
# those ports.  Ultimately, you can choose whatever port you like, but that
# range seems to give more interesting results.
TRACEROUTE_PORT_NUMBER = 33434  # Cisco traceroute port number.

# Sometimes packets on the internet get dropped.  PROBE_ATTEMPT_COUNT is the
# maximum number of times your traceroute function should attempt to probe a
# single router before giving up and moving on.
PROBE_ATTEMPT_COUNT = 3

class IPv4:
    """IPv4 packet header parser."""
    # Each member below is a field from the IPv4 packet header.  They are
    # listed below in the order they appear in the packet.  All fields should
    # be stored in host byte order.
    #
    # You should only modify the __init__() method of this class.
    version: int
    header_len: int  # Note length in bytes, not the value in the packet.
    tos: int         # Also called DSCP and ECN bits (i.e. on wikipedia).
    length: int      # Total length of the packet.
    id: int
    flags: int
    frag_offset: int
    ttl: int
    proto: int
    cksum: int
    src: str
    dst: str

    def __init__(self, buffer: bytes):
        bitstring = ''.join(format(byte, '08b') for byte in [*buffer])
        self.version = int(bitstring[:4], 2)
        self.header_len = int(bitstring[4 : 8], 2)
        self.tos = int(bitstring[8 : 16], 2)
        self.length = int(bitstring[16 : 32], 2)
        self.id = int(bitstring[32 : 48], 2)
        self.flags = int(bitstring[48 : 51], 2)
        self.frag_offset = int(bitstring[51 : 64], 2)
        self.ttl = int(bitstring[64 : 72], 2)
        self.proto = int(bitstring[72 : 80], 2)
        self.cksum = int(bitstring[80 : 96], 2)
        self.src = util.inet_ntoa(buffer[12 : 16])

        self.dst = util.inet_ntoa(buffer[16 : 20])

    def __str__(self) -> str:
        return f"IPv{self.version} (tos 0x{self.tos:x}, ttl {self.ttl}, " + \
            f"id {self.id}, flags 0x{self.flags:x}, " + \
            f"ofsset {self.frag_offset}, " + \
            f"proto {self.proto}, header_len {self.header_len}, " + \
            f"len {self.length}, cksum 0x{self.cksum:x}) " + \
            f"{self.src} > {self.dst}"


class ICMP:
    """ICMP packet header parser."""
    # Each member below is a field from the ICMP header.  They are listed below
    # in the order they appear in the packet.  All fields should be stored in
    # host byte order.
    #
    # You should only modify the __init__() function of this class.
    type: int
    code: int
    cksum: int

    def __init__(self, buffer: bytes):
        bitstring = ''.join(format(byte, '08b') for byte in [*buffer])

        self.type = int(bitstring[0 : 8], 2)
        self.code = int(bitstring[8 : 16], 2)
        self.cksum = int(bitstring[16 : 32], 2)

    def __str__(self) -> str:
        return f"ICMP (type {self.type}, code {self.code}, " + \
            f"cksum 0x{self.cksum:x})"


class UDP:
    """UDP packet header parser."""
    # Each member below is a field from the UDP header.  They are listed below
    # in the order they appear in the packet.  All fields should be stored in
    # host byte order.
    #
    # You should only modify the __init__() function of this class.
    src_port: int
    dst_port: int
    len: int
    cksum: int

    def __init__(self, buffer: bytes):
        bitstring = ''.join(format(byte, '08b') for byte in [*buffer])
        self.src_port = int(bitstring[0 : 16], 2)
        self.dst_port = int(bitstring[16 : 32], 2)
        self.len = int(bitstring[32 : 48], 2)
        self.cksum = int(bitstring[48 : 64], 2)

    def __str__(self) -> str:
        return f"UDP (src_port {self.src_port}, dst_port {self.dst_port}, " + \
            f"len {self.len}, cksum 0x{self.cksum:x})"

ICMP_TYPE_DESTINATION_UNREACHABLE = 3
ICMP_TYPE_TIME_EXCEEDED = 11
ICMP_CODE_TTL_TIME_EXCEEDED = 0
ICMP_BYTES_LENGTH = 8

IPV4_PROTOCOL_ICMP = 1
IPV4_PROTOCOL_UDP = 17
IPV4_MIN_TOTAL_PACKET_LENGTH = 20
IPV4_WORDS_LENGTH = 4
IPV4_BYTES_LENGTH = 20

UDP_BYTES_LENGTH = 8

def is_valid_ip(ip_string):
    """ Check if the IP address is valid. """
    parts = ip_string.split('.')
    # Check for exactly 4 parts
    if len(parts) != 4:
        return False
    for part in parts:
        # Check for leading zeros (except for '0') and if part is a number
        if not part.isdigit() or (len(part) > 1 and part.startswith('0')):
            return False
        # Check if the number is in the valid range
        try:
            num = int(part)
            if not 0 <= num <= 255:
                return False
        except ValueError:
            return False
    return True

def is_valid_icmp(icmp: ICMP):
    """ Check if the ICMP packet is valid. """
    if icmp.type not in (ICMP_TYPE_DESTINATION_UNREACHABLE, ICMP_TYPE_TIME_EXCEEDED):
        return False
    if icmp.type == ICMP_TYPE_TIME_EXCEEDED and icmp.code != ICMP_CODE_TTL_TIME_EXCEEDED:
        return False

    return True


def traceroute(sendsock: util.Socket, recvsock: util.Socket, ip: str) \
        -> list[list[str]]:
    """ Run traceroute and returns the discovered path.

    Calls util.print_result() on the result of each TTL's probes to show
    progress.

    Arguments:
    sendsock -- This is a UDP socket you will use to send traceroute probes.
    recvsock -- This is the socket on which you will receive ICMP responses.
    ip -- This is the IP address of the end host you will be tracerouting.

    Returns:
    A list of lists representing the routers discovered for each ttl that was
    probed.  The ith list contains all of the routers found with TTL probe of
    i+1.   The routers discovered in the ith list can be in any order.  If no
    routers were found, the ith list can be empty.  If `ip` is discovered, it
    should be included as the final element in the list.
    """

    all_routers = []
    for ttl in range(1, TRACEROUTE_MAX_TTL+1):
        ttl_routers = []
        ip_exist = set()
        for _ in range(PROBE_ATTEMPT_COUNT):
            sendsock.set_ttl(ttl)
            sendsock.sendto("Hello".encode(), (ip, TRACEROUTE_PORT_NUMBER))
            while recvsock.recv_select():
                buf, _ = recvsock.recvfrom()

                recv_ip = IPv4(buf)
                icmp_start = recv_ip.header_len * IPV4_WORDS_LENGTH
                recv_icmp = ICMP(buf[icmp_start: icmp_start + ICMP_BYTES_LENGTH])

                # Basic validation first
                if not is_valid_ip(recv_ip.src):
                    continue
                if not is_valid_icmp(recv_icmp):
                    continue
                if recv_ip.proto != util.IPPROTO_ICMP:
                    continue
                if recv_ip.length < IPV4_MIN_TOTAL_PACKET_LENGTH:
                    continue

                # Validate embedded packet (Test B16) - only reject if clearly wrong
                embedded_ip_start = icmp_start + ICMP_BYTES_LENGTH
                if len(buf) >= embedded_ip_start + IPV4_BYTES_LENGTH:
                    try:
                        embedded_ip = IPv4(buf[embedded_ip_start:])

                        # Only skip if we can prove this is NOT our packet
                        # Check if it's UDP to our destination
                        if embedded_ip.proto == util.IPPROTO_UDP:
                            if embedded_ip.dst != ip:
                                continue  # Wrong destination, skip

                            # Check UDP port if available
                            embedded_udp_start = embedded_ip.header_len * IPV4_WORDS_LENGTH
                            min_len = embedded_ip_start + embedded_udp_start + UDP_BYTES_LENGTH
                            if len(buf) >= min_len:
                                try:
                                    embedded_udp = UDP(buf[embedded_ip_start + embedded_udp_start:])
                                    if embedded_udp.dst_port != TRACEROUTE_PORT_NUMBER:
                                        continue  # Wrong port, skip
                                except (ValueError, IndexError):
                                    pass  # Can't parse UDP, allow packet
                        # If not UDP or can't determine, allow the packet
                    except (ValueError, IndexError):
                        pass  # Can't parse embedded packet, allow packet

                # Duplicate check (only within same TTL)
                if recv_ip.src not in ip_exist:
                    ttl_routers.append(recv_ip.src)
                    ip_exist.add(recv_ip.src)
                    # Reach destination
                    if recv_ip.src == ip:
                        all_routers.append(ttl_routers)
                        return all_routers
        util.print_result(ttl_routers, ttl)
        all_routers.append(ttl_routers)

    return all_routers

if __name__ == '__main__':
    args = util.parse_args()
    ip_addr = util.gethostbyname(args.host)
    print(f"traceroute to {args.host} ({ip_addr})")
    traceroute(util.Socket.make_udp(), util.Socket.make_icmp(), ip_addr)
