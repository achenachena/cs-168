import struct
import sys
from collections import deque
from pathlib import Path
from unittest import mock
import unittest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
for path in (PROJECT_ROOT.parent, PROJECT_ROOT):
    PATH_STRING = str(path)
    if PATH_STRING not in sys.path:
        sys.path.insert(0, PATH_STRING)

import traceroute
from traceroute import traceroute as traceroute_mod
from traceroute import util

# Import constants directly
ICMP_TYPE_DESTINATION_UNREACHABLE = traceroute.ICMP_TYPE_DESTINATION_UNREACHABLE
ICMP_TYPE_TIME_EXCEEDED = traceroute.ICMP_TYPE_TIME_EXCEEDED
ICMP_CODE_TTL_TIME_EXCEEDED = traceroute.ICMP_CODE_TTL_TIME_EXCEEDED
TRACEROUTE_PORT_NUMBER = traceroute.TRACEROUTE_PORT_NUMBER
TRACEROUTE_MAX_TTL = traceroute.TRACEROUTE_MAX_TTL
PROBE_ATTEMPT_COUNT = traceroute.PROBE_ATTEMPT_COUNT


class PacketBuilder:
    """Helper class to build various packet types for testing"""

    @staticmethod
    def ipv4_header(
        *,
        version: int = 4,
        ihl: int = 5,
        tos: int = 0,
        total_length: int = 56,
        ident: int = 0x1C46,
        flags: int = 0b010,
        frag_offset: int = 0,
        ttl: int = 64,
        proto: int = util.IPPROTO_ICMP,
        checksum: int = 0xB1E6,
        src: str = "192.0.2.1",
        dst: str = "198.51.100.10",
    ) -> bytes:
        first_byte = (version << 4) | ihl
        second_word = (flags << 13) | frag_offset
        return struct.pack(
            "!BBHHHBBH4s4s",
            first_byte,
            tos,
            total_length,
            ident,
            second_word,
            ttl,
            proto,
            checksum,
            util.inet_aton(src),
            util.inet_aton(dst),
        )

    @staticmethod
    def icmp_header(
        *,
        icmp_type: int = ICMP_TYPE_TIME_EXCEEDED,
        code: int = ICMP_CODE_TTL_TIME_EXCEEDED,
        checksum: int = 0xF7FF,
    ) -> bytes:
        return struct.pack("!BBH4s", icmp_type, code, checksum, b"\x00" * 4)

    @staticmethod
    def udp_header(
        *,
        src_port: int = 49152,
        dst_port: int = TRACEROUTE_PORT_NUMBER,
        length: int = 28,
        checksum: int = 0x1A2B,
    ) -> bytes:
        return struct.pack("!HHHH", src_port, dst_port, length, checksum)


class FakeSendSocket:
    """Mock UDP socket for sending traceroute probes."""
    def __init__(self):
        self.ttl_history: list[int] = []
        self.sent_packets: list[tuple[bytes, tuple[str, int]]] = []

    def set_ttl(self, ttl: int):
        self.ttl_history.append(ttl)

    def sendto(self, data: bytes, address: tuple[str, int]) -> int:
        self.sent_packets.append((data, address))
        return len(data)


class FakeRecvSocket:
    """Mock ICMP socket for receiving responses."""
    def __init__(self, responses: list[bytes | None]):
        self._responses: deque[bytes | None] = deque(responses)
        self._current: bytes | None = None
        self.select_calls = 0

    def recv_select(self) -> bool:
        self.select_calls += 1
        if not self._responses:
            self._current = None
            return False

        next_response = self._responses.popleft()
        if next_response is None:
            self._current = None
            return False

        self._current = next_response
        return True

    def recvfrom(self):
        if self._current is None:
            raise AssertionError("recvfrom called without a pending packet")
        packet = self._current
        self._current = None
        return packet, ("0.0.0.0", 0)


def build_time_exceeded_packet(src: str, dst: str, ttl: int = 64, ident: int = 0x1C46) -> bytes:
    """Build ICMP Time Exceeded packet with customizable fields"""
    header = PacketBuilder.ipv4_header(src=src, dst=dst, total_length=28, ttl=ttl, ident=ident)
    icmp = PacketBuilder.icmp_header(
        icmp_type=ICMP_TYPE_TIME_EXCEEDED,
        code=ICMP_CODE_TTL_TIME_EXCEEDED,
    )
    return header + icmp


def build_destination_unreachable_packet(src: str, dst: str, code: int = 3, ident: int = 0x1C46) -> bytes:
    """Build ICMP Destination Unreachable packet with customizable fields"""
    header = PacketBuilder.ipv4_header(src=src, dst=dst, total_length=28, ident=ident)
    icmp = PacketBuilder.icmp_header(
        icmp_type=ICMP_TYPE_DESTINATION_UNREACHABLE,
        code=code,
    )
    return header + icmp


class TestDuplicatePacketCases(unittest.TestCase):
    """Comprehensive tests for all duplicate packet scenarios in Project 1B"""

    def test_identical_time_exceeded_packets(self):
        """Test handling of completely identical ICMP Time Exceeded packets"""
        destination_ip = "198.51.100.99"
        router_ip = "203.0.113.1"

        # Create identical packets (same source, destination, TTL, identifier)
        packet1 = build_time_exceeded_packet(router_ip, destination_ip, ttl=64, ident=0x1234)
        packet2 = build_time_exceeded_packet(router_ip, destination_ip, ttl=64, ident=0x1234)
        packet3 = build_time_exceeded_packet(router_ip, destination_ip, ttl=64, ident=0x1234)

        responses = [packet1, packet2, packet3]

        send_socket = FakeSendSocket()
        recv_socket = FakeRecvSocket(responses)

        with mock.patch("traceroute.util.print_result"):
            result = traceroute_mod(send_socket, recv_socket, destination_ip)

        # Should only record the router once despite identical packets
        # Traceroute continues until destination reached or max TTL
        expected = [[router_ip]] + [[] for _ in range(traceroute.TRACEROUTE_MAX_TTL - 1)]
        self.assertEqual(result, expected)

    def test_duplicate_with_different_identifiers(self):
        """Test handling of duplicate packets with different IP identifiers"""
        destination_ip = "198.51.100.99"
        router_ip = "203.0.113.1"

        # Same router, but different packet identifiers
        packet1 = build_time_exceeded_packet(router_ip, destination_ip, ident=0x1000)
        packet2 = build_time_exceeded_packet(router_ip, destination_ip, ident=0x2000)
        packet3 = build_time_exceeded_packet(router_ip, destination_ip, ident=0x3000)

        responses = [packet1, packet2, packet3]

        send_socket = FakeSendSocket()
        recv_socket = FakeRecvSocket(responses)

        with mock.patch("traceroute.util.print_result"):
            result = traceroute_mod(send_socket, recv_socket, destination_ip)

        # Should only record the router once (duplicates by source IP)
        expected = [[router_ip]] + [[] for _ in range(traceroute.TRACEROUTE_MAX_TTL - 1)]
        self.assertEqual(result, expected)

    def test_duplicate_with_different_ttls(self):
        """Test handling of duplicate packets with different TTL values"""
        destination_ip = "198.51.100.99"
        router_ip = "203.0.113.1"

        # Same router, but different TTL values in the packet
        packet1 = build_time_exceeded_packet(router_ip, destination_ip, ttl=1)
        packet2 = build_time_exceeded_packet(router_ip, destination_ip, ttl=2)
        packet3 = build_time_exceeded_packet(router_ip, destination_ip, ttl=3)

        responses = [packet1, packet2, packet3]

        send_socket = FakeSendSocket()
        recv_socket = FakeRecvSocket(responses)

        with mock.patch("traceroute.util.print_result"):
            result = traceroute_mod(send_socket, recv_socket, destination_ip)

        # Should only record the router once (duplicates by source IP)
        expected = [[router_ip]] + [[] for _ in range(traceroute.TRACEROUTE_MAX_TTL - 1)]
        self.assertEqual(result, expected)

    def test_duplicate_destination_unreachable_different_codes(self):
        """Test handling of duplicate destination unreachable packets with different codes"""
        destination_ip = "198.51.100.99"

        # Same destination, but different unreachable codes
        packet1 = build_destination_unreachable_packet(destination_ip, destination_ip, code=3)  # Port unreachable
        packet2 = build_destination_unreachable_packet(destination_ip, destination_ip, code=1)  # Host unreachable
        packet3 = build_destination_unreachable_packet(destination_ip, destination_ip, code=0)  # Network unreachable

        responses = [packet1, packet2, packet3]

        send_socket = FakeSendSocket()
        recv_socket = FakeRecvSocket(responses)

        with mock.patch("traceroute.util.print_result"):
            result = traceroute_mod(send_socket, recv_socket, destination_ip)

        # Should only record the destination once (duplicates by source IP)
        self.assertEqual(result, [[destination_ip]])

    def test_cross_ttl_duplicates(self):
        """Test handling of duplicate responses that arrive across different TTL probes"""
        destination_ip = "198.51.100.99"
        router_ip = "203.0.113.1"

        responses = [
            # TTL 1 probes
            build_time_exceeded_packet(router_ip, destination_ip),  # TTL 1, probe 1
            build_time_exceeded_packet(router_ip, destination_ip),  # TTL 1, probe 2 (duplicate)
            None,  # TTL 1, probe 3 (no response)

            # TTL 2 probes - late arriving duplicate from TTL 1
            build_time_exceeded_packet(router_ip, destination_ip),  # TTL 2, probe 1 (duplicate from TTL 1)
            build_time_exceeded_packet("203.0.113.2", destination_ip),  # TTL 2, probe 2 (different router)
            None,  # TTL 2, probe 3 (no response)

            # TTL 3 - destination reached
            build_destination_unreachable_packet(destination_ip, destination_ip),
        ]

        send_socket = FakeSendSocket()
        recv_socket = FakeRecvSocket(responses)

        with mock.patch("traceroute.util.print_result"):
            result = traceroute_mod(send_socket, recv_socket, destination_ip)

        # Should record router_ip once for TTL 1, router2_ip for TTL 2, destination for TTL 3
        # The late duplicate from router_ip at TTL 2 should be ignored
        self.assertEqual(result, [[router_ip], ["203.0.113.2"], [destination_ip]])

    def test_multiple_duplicates_from_same_router_different_ttls(self):
        """Test handling of same router responding at multiple TTL levels"""
        destination_ip = "198.51.100.99"
        router_ip = "203.0.113.1"

        responses = [
            # TTL 1 - router responds
            build_time_exceeded_packet(router_ip, destination_ip),
            build_time_exceeded_packet(router_ip, destination_ip),  # Duplicate
            None,

            # TTL 2 - same router responds again (should be treated as different hop)
            build_time_exceeded_packet(router_ip, destination_ip),
            build_time_exceeded_packet(router_ip, destination_ip),  # Duplicate
            None,

            # TTL 3 - different router
            build_time_exceeded_packet("203.0.113.3", destination_ip),
            None,
            None,

            # TTL 4 - destination reached
            build_destination_unreachable_packet(destination_ip, destination_ip),
        ]

        send_socket = FakeSendSocket()
        recv_socket = FakeRecvSocket(responses)

        with mock.patch("traceroute.util.print_result"):
            result = traceroute_mod(send_socket, recv_socket, destination_ip)

        # Same router can appear at different TTL levels (load balancing scenario)
        self.assertEqual(result, [[router_ip, "203.0.113.3"], [destination_ip]])

    def test_duplicate_destination_reached_packets(self):
        """Test handling of multiple destination reached packets"""
        destination_ip = "198.51.100.99"

        responses = [
            # TTL 1 - router
            build_time_exceeded_packet("203.0.113.1", destination_ip),
            None,
            None,

            # TTL 2 - multiple destination reached packets
            build_destination_unreachable_packet(destination_ip, destination_ip, code=3),  # Port unreachable
            build_destination_unreachable_packet(destination_ip, destination_ip, code=3),  # Duplicate
            build_destination_unreachable_packet(destination_ip, destination_ip, code=1),  # Different code, same source
        ]

        send_socket = FakeSendSocket()
        recv_socket = FakeRecvSocket(responses)

        with mock.patch("traceroute.util.print_result"):
            result = traceroute_mod(send_socket, recv_socket, destination_ip)

        # Should record router for TTL 1, destination once for TTL 2
        self.assertEqual(result, [["203.0.113.1"], [destination_ip]])

    def test_duplicate_mixed_icmp_types(self):
        """Test handling of duplicate packets with mixed ICMP types from same source"""
        destination_ip = "198.51.100.99"
        router_ip = "203.0.113.1"

        responses = [
            # Same router sending both time exceeded and destination unreachable
            build_time_exceeded_packet(router_ip, destination_ip),  # Time exceeded
            build_time_exceeded_packet(router_ip, destination_ip),  # Duplicate time exceeded
            build_destination_unreachable_packet(router_ip, destination_ip, code=3),  # Destination unreachable
        ]

        send_socket = FakeSendSocket()
        recv_socket = FakeRecvSocket(responses)

        with mock.patch("traceroute.util.print_result"):
            result = traceroute_mod(send_socket, recv_socket, destination_ip)

        # Should only record the router once (duplicates by source IP)
        expected = [[router_ip]] + [[] for _ in range(traceroute.TRACEROUTE_MAX_TTL - 1)]
        self.assertEqual(result, expected)

    def test_extreme_duplicate_scenario(self):
        """Test handling of extreme duplicate scenario with many identical packets"""
        destination_ip = "198.51.100.99"
        router_ip = "203.0.113.1"

        # Send 10 identical time exceeded packets from same router
        responses = [build_time_exceeded_packet(router_ip, destination_ip)] * 10
        responses.extend([None] * 20)  # No responses for TTL 2
        responses.append(build_destination_unreachable_packet(destination_ip, destination_ip))

        send_socket = FakeSendSocket()
        recv_socket = FakeRecvSocket(responses)

        with mock.patch("traceroute.util.print_result"):
            result = traceroute_mod(send_socket, recv_socket, destination_ip)

        # Should handle extreme duplicates gracefully
        self.assertEqual(result, [[router_ip], [destination_ip]])

    def test_duplicate_packets_with_validation_errors(self):
        """Test that duplicate packets are handled correctly even when some fail validation"""
        destination_ip = "198.51.100.99"
        router_ip = "203.0.113.1"

        # Create a valid packet and an invalid packet from same source
        valid_packet = build_time_exceeded_packet(router_ip, destination_ip)

        # Create invalid packet (malformed ICMP)
        invalid_header = PacketBuilder.ipv4_header(src=router_ip, dst=destination_ip, total_length=28)
        invalid_icmp = PacketBuilder.icmp_header(icmp_type=42, code=1)  # Invalid ICMP type
        invalid_packet = invalid_header + invalid_icmp

        responses = [
            valid_packet,      # Valid packet
            invalid_packet,    # Invalid packet from same source
            valid_packet,      # Another valid packet (duplicate)
        ]

        send_socket = FakeSendSocket()
        recv_socket = FakeRecvSocket(responses)

        with mock.patch("traceroute.util.print_result"):
            result = traceroute_mod(send_socket, recv_socket, destination_ip)

        # Should only record router once (valid packets are duplicates)
        expected = [[router_ip]] + [[] for _ in range(traceroute.TRACEROUTE_MAX_TTL - 1)]
        self.assertEqual(result, expected)


if __name__ == "__main__":
    unittest.main()
