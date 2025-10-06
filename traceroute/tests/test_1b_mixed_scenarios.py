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


def build_time_exceeded_packet(src: str, dst: str) -> bytes:
    """Build ICMP Time Exceeded packet"""
    header = PacketBuilder.ipv4_header(src=src, dst=dst, total_length=28)
    icmp = PacketBuilder.icmp_header(
        icmp_type=ICMP_TYPE_TIME_EXCEEDED,
        code=ICMP_CODE_TTL_TIME_EXCEEDED,
    )
    return header + icmp


def build_destination_unreachable_packet(src: str, dst: str, code: int = 3) -> bytes:
    """Build ICMP Destination Unreachable packet"""
    header = PacketBuilder.ipv4_header(src=src, dst=dst, total_length=28)
    icmp = PacketBuilder.icmp_header(
        icmp_type=ICMP_TYPE_DESTINATION_UNREACHABLE,
        code=code,
    )
    return header + icmp


def build_echo_reply_packet(src: str, dst: str) -> bytes:
    """Build ICMP Echo Reply packet (unrelated to traceroute)"""
    header = PacketBuilder.ipv4_header(src=src, dst=dst, total_length=28)
    icmp = PacketBuilder.icmp_header(
        icmp_type=0,  # Echo Reply
        code=0,
    )
    return header + icmp


def build_udp_packet(src: str, dst: str, src_port: int = 12345, dst_port: int = 80) -> bytes:
    """Build UDP packet (unrelated to traceroute)"""
    header = PacketBuilder.ipv4_header(src=src, dst=dst, total_length=28, proto=util.IPPROTO_UDP)
    udp = PacketBuilder.udp_header(src_port=src_port, dst_port=dst_port)
    return header + udp


def build_malformed_packet() -> bytes:
    """Build a malformed packet for testing"""
    return b"\x45\x00\x00\x14"  # Only first 4 bytes of IP header


class TestMixedErrorScenarios(unittest.TestCase):
    """Comprehensive tests for complex mixed error scenarios in Project 1B"""

    def test_duplicates_unrelated_and_drops_combined(self):
        """Test complex scenario with duplicates, unrelated packets, and drops"""
        destination_ip = "198.51.100.99"
        router1_ip = "203.0.113.1"
        router2_ip = "203.0.113.2"

        responses = [
            # TTL 1: duplicate responses from router1, plus unrelated packet
            build_time_exceeded_packet(router1_ip, destination_ip),  # Valid
            build_time_exceeded_packet(router1_ip, destination_ip),  # Duplicate
            build_echo_reply_packet("8.8.8.8", "1.1.1.1"),  # Unrelated

            # TTL 2: packet drops
            None, None, None,  # All dropped

            # TTL 3: valid response mixed with unrelated
            build_udp_packet("10.0.0.1", "10.0.0.2"),  # Unrelated
            build_time_exceeded_packet(router2_ip, destination_ip),  # Valid

            # TTL 4: destination reached with duplicates
            build_destination_unreachable_packet(destination_ip, destination_ip),
            build_destination_unreachable_packet(destination_ip, destination_ip),  # Duplicate
        ]

        send_socket = FakeSendSocket()
        recv_socket = FakeRecvSocket(responses)

        with mock.patch("traceroute.util.print_result"):
            result = traceroute_mod(send_socket, recv_socket, destination_ip)

        # Should handle all scenarios correctly
        # Traceroute stops early when destination is reached
        self.assertEqual(result, [[router1_ip], [router2_ip, destination_ip]])

    def test_non_responsive_duplicates_and_unrelated_packets(self):
        """Test handling of non-responsive routers combined with duplicates and unrelated packets"""
        destination_ip = "198.51.100.99"
        router1_ip = "203.0.113.1"
        router3_ip = "203.0.113.3"  # Skip router 2 (non-responsive)

        responses = [
            # TTL 1: duplicates and unrelated packets
            build_echo_reply_packet("1.1.1.1", "2.2.2.2"),  # Unrelated
            build_time_exceeded_packet(router1_ip, destination_ip),  # Valid
            build_time_exceeded_packet(router1_ip, destination_ip),  # Duplicate

            # TTL 2: non-responsive router with unrelated packets
            build_udp_packet("10.0.0.1", "10.0.0.2"),  # Unrelated
            None,  # Non-responsive
            build_echo_reply_packet("3.3.3.3", "4.4.4.4"),  # Unrelated

            # TTL 3: valid response with duplicates
            build_time_exceeded_packet(router3_ip, destination_ip),
            build_time_exceeded_packet(router3_ip, destination_ip),  # Duplicate

            # TTL 4: destination reached
            build_destination_unreachable_packet(destination_ip, destination_ip),
        ]

        send_socket = FakeSendSocket()
        recv_socket = FakeRecvSocket(responses)

        with mock.patch("traceroute.util.print_result"):
            result = traceroute_mod(send_socket, recv_socket, destination_ip)

        # Should handle all scenarios correctly
        # Traceroute stops early when destination is reached
        self.assertEqual(result, [[router1_ip, router3_ip, destination_ip]])

    def test_intermittent_drops_with_duplicates_and_unrelated(self):
        """Test intermittent packet drops combined with duplicates and unrelated packets"""
        destination_ip = "198.51.100.99"
        router1_ip = "203.0.113.1"
        router2_ip = "203.0.113.2"

        responses = [
            # TTL 1: intermittent drops with duplicates and unrelated
            build_time_exceeded_packet(router1_ip, destination_ip),  # Valid
            build_echo_reply_packet("8.8.8.8", "1.1.1.1"),  # Unrelated
            None,  # Dropped

            # TTL 2: more drops with unrelated packets
            build_udp_packet("10.0.0.1", "10.0.0.2"),  # Unrelated
            None,  # Dropped
            build_time_exceeded_packet(router1_ip, destination_ip),  # Duplicate from TTL 1

            # TTL 3: valid response with duplicates
            build_time_exceeded_packet(router2_ip, destination_ip),
            build_time_exceeded_packet(router2_ip, destination_ip),  # Duplicate

            # TTL 4: destination reached with duplicates
            build_destination_unreachable_packet(destination_ip, destination_ip),
            build_destination_unreachable_packet(destination_ip, destination_ip),  # Duplicate
        ]

        send_socket = FakeSendSocket()
        recv_socket = FakeRecvSocket(responses)

        with mock.patch("traceroute.util.print_result"):
            result = traceroute_mod(send_socket, recv_socket, destination_ip)

        # Should handle all scenarios correctly
        # Traceroute stops early when destination is reached
        self.assertEqual(result, [[router1_ip, router2_ip, destination_ip]])

    def test_late_arriving_duplicates_with_drops(self):
        """Test handling of late arriving duplicates combined with packet drops"""
        destination_ip = "198.51.100.99"
        router1_ip = "203.0.113.1"
        router2_ip = "203.0.113.2"

        responses = [
            # TTL 1: valid response
            build_time_exceeded_packet(router1_ip, destination_ip),
            None,  # Dropped
            None,  # Dropped

            # TTL 2: late duplicate from TTL 1 arrives
            build_time_exceeded_packet(router1_ip, destination_ip),  # Late duplicate
            build_echo_reply_packet("8.8.8.8", "1.1.1.1"),  # Unrelated
            None,  # Dropped

            # TTL 3: valid response
            build_time_exceeded_packet(router2_ip, destination_ip),
            None,  # Dropped
            None,  # Dropped

            # TTL 4: destination reached
            build_destination_unreachable_packet(destination_ip, destination_ip),
        ]

        send_socket = FakeSendSocket()
        recv_socket = FakeRecvSocket(responses)

        with mock.patch("traceroute.util.print_result"):
            result = traceroute_mod(send_socket, recv_socket, destination_ip)

        # Should handle late duplicates and drops correctly
        # Traceroute stops early when destination is reached
        self.assertEqual(result, [[router1_ip], [router2_ip, destination_ip]])

    def test_mixed_icmp_types_with_drops_and_unrelated(self):
        """Test handling of mixed ICMP types combined with drops and unrelated packets"""
        destination_ip = "198.51.100.99"
        router_ip = "203.0.113.1"

        # Create mixed ICMP packet (time exceeded and destination unreachable from same source)
        time_exceeded = build_time_exceeded_packet(router_ip, destination_ip)
        dest_unreachable = build_destination_unreachable_packet(router_ip, destination_ip, code=3)

        responses = [
            # TTL 1: mixed ICMP types with unrelated packets
            build_echo_reply_packet("8.8.8.8", "1.1.1.1"),  # Unrelated
            time_exceeded,  # Valid time exceeded
            dest_unreachable,  # Different ICMP type from same source
            None,  # Dropped

            # TTL 2: destination reached with duplicates
            build_destination_unreachable_packet(destination_ip, destination_ip),
            build_destination_unreachable_packet(destination_ip, destination_ip),  # Duplicate
        ]

        send_socket = FakeSendSocket()
        recv_socket = FakeRecvSocket(responses)

        with mock.patch("traceroute.util.print_result"):
            result = traceroute_mod(send_socket, recv_socket, destination_ip)

        # Should handle mixed ICMP types correctly (duplicates by source IP)
        self.assertEqual(result, [[router_ip, destination_ip]])

    def test_extreme_mixed_scenario(self):
        """Test extreme mixed scenario with all types of errors"""
        destination_ip = "198.51.100.99"
        router1_ip = "203.0.113.1"
        router3_ip = "203.0.113.3"  # Skip router 2 (non-responsive)

        responses = [
            # TTL 1: everything mixed together
            build_echo_reply_packet("8.8.8.8", "1.1.1.1"),  # Unrelated
            build_time_exceeded_packet(router1_ip, destination_ip),  # Valid
            build_time_exceeded_packet(router1_ip, destination_ip),  # Duplicate
            build_udp_packet("10.0.0.1", "10.0.0.2"),  # Unrelated
            None,  # Dropped

            # TTL 2: non-responsive with unrelated packets
            build_echo_reply_packet("3.3.3.3", "4.4.4.4"),  # Unrelated
            None,  # Non-responsive
            None,  # Non-responsive
            build_udp_packet("5.5.5.5", "6.6.6.6"),  # Unrelated
            None,  # Non-responsive

            # TTL 3: valid response with duplicates and unrelated
            build_time_exceeded_packet(router3_ip, destination_ip),  # Valid
            build_time_exceeded_packet(router3_ip, destination_ip),  # Duplicate
            build_echo_reply_packet("7.7.7.7", "8.8.8.8"),  # Unrelated
            build_time_exceeded_packet(router3_ip, destination_ip),  # Another duplicate
            build_udp_packet("9.9.9.9", "10.10.10.10"),  # Unrelated

            # TTL 4: destination reached with duplicates and unrelated
            build_destination_unreachable_packet(destination_ip, destination_ip),  # Valid
            build_destination_unreachable_packet(destination_ip, destination_ip),  # Duplicate
            build_echo_reply_packet("11.11.11.11", "12.12.12.12"),  # Unrelated
        ]

        send_socket = FakeSendSocket()
        recv_socket = FakeRecvSocket(responses)

        with mock.patch("traceroute.util.print_result"):
            result = traceroute_mod(send_socket, recv_socket, destination_ip)

        # Should handle extreme mixed scenario correctly
        # Traceroute stops early when destination is reached
        self.assertEqual(result, [[router1_ip], [router3_ip, destination_ip]])

    def test_network_congestion_simulation(self):
        """Test handling under simulated network congestion (high drops, duplicates, unrelated)"""
        destination_ip = "198.51.100.99"
        router1_ip = "203.0.113.1"
        router5_ip = "203.0.113.5"  # Skip routers 2-4 due to congestion

        responses = []

        # TTL 1: congestion with some responses
        responses.extend([
            build_time_exceeded_packet(router1_ip, destination_ip),  # Valid
            build_echo_reply_packet("1.1.1.1", "2.2.2.2"),  # Unrelated
            None,  # Dropped due to congestion
            build_time_exceeded_packet(router1_ip, destination_ip),  # Duplicate
            build_udp_packet("3.3.3.3", "4.4.4.4"),  # Unrelated
        ])

        # TTL 2-4: severe congestion (all dropped with unrelated packets)
        for ttl in range(2, 5):
            responses.extend([
                build_echo_reply_packet(f"{ttl}.{ttl}.{ttl}.{ttl}", f"{ttl+1}.{ttl+1}.{ttl+1}.{ttl+1}"),  # Unrelated
                None,  # Dropped
                build_udp_packet(f"{ttl+10}.{ttl+10}.{ttl+10}.{ttl+10}", f"{ttl+11}.{ttl+11}.{ttl+11}.{ttl+11}"),  # Unrelated
                None,  # Dropped
                None,  # Dropped
            ])

        # TTL 5: router responds despite congestion
        responses.extend([
            build_time_exceeded_packet(router5_ip, destination_ip),  # Valid
            build_echo_reply_packet("20.20.20.20", "21.21.21.21"),  # Unrelated
            build_time_exceeded_packet(router5_ip, destination_ip),  # Duplicate
            None,  # Dropped
            build_udp_packet("22.22.22.22", "23.23.23.23"),  # Unrelated
        ])

        # TTL 6: destination reached
        responses.extend([
            build_destination_unreachable_packet(destination_ip, destination_ip),  # Valid
            build_destination_unreachable_packet(destination_ip, destination_ip),  # Duplicate
            build_echo_reply_packet("24.24.24.24", "25.25.25.25"),  # Unrelated
        ])

        send_socket = FakeSendSocket()
        recv_socket = FakeRecvSocket(responses)

        with mock.patch("traceroute.util.print_result"):
            result = traceroute_mod(send_socket, recv_socket, destination_ip)

        # Should handle network congestion correctly
        expected = [
            [router1_ip],  # TTL 1 - responds despite congestion
            [],            # TTL 2 - congested
            [],            # TTL 3 - congested
            [router5_ip, destination_ip],  # TTL 4 - responds despite congestion + destination
        ]
        self.assertEqual(result, expected)

    def test_load_balancing_with_mixed_errors(self):
        """Test load balancing scenario with mixed error conditions"""
        destination_ip = "198.51.100.99"

        responses = [
            # TTL 1: load balancing with mixed errors
            build_time_exceeded_packet("203.0.113.1", destination_ip),  # Router 1
            build_time_exceeded_packet("203.0.113.2", destination_ip),  # Router 2 (load balancing)
            build_echo_reply_packet("8.8.8.8", "1.1.1.1"),  # Unrelated
            build_time_exceeded_packet("203.0.113.1", destination_ip),  # Duplicate from router 1
            build_udp_packet("10.0.0.1", "10.0.0.2"),  # Unrelated
            None,  # Dropped

            # TTL 2: non-responsive router with unrelated packets
            build_echo_reply_packet("3.3.3.3", "4.4.4.4"),  # Unrelated
            None,  # Non-responsive
            None,  # Non-responsive
            build_udp_packet("5.5.5.5", "6.6.6.6"),  # Unrelated
            None,  # Non-responsive

            # TTL 3: load balancing with duplicates
            build_time_exceeded_packet("203.0.113.5", destination_ip),  # Router 5
            build_time_exceeded_packet("203.0.113.6", destination_ip),  # Router 6 (load balancing)
            build_time_exceeded_packet("203.0.113.5", destination_ip),  # Duplicate from router 5
            build_echo_reply_packet("7.7.7.7", "8.8.8.8"),  # Unrelated
            build_time_exceeded_packet("203.0.113.6", destination_ip),  # Duplicate from router 6

            # TTL 4: destination reached with duplicates
            build_destination_unreachable_packet(destination_ip, destination_ip),
            build_destination_unreachable_packet(destination_ip, destination_ip),  # Duplicate
        ]

        send_socket = FakeSendSocket()
        recv_socket = FakeRecvSocket(responses)

        with mock.patch("traceroute.util.print_result"):
            result = traceroute_mod(send_socket, recv_socket, destination_ip)

        # Should handle load balancing with mixed errors correctly
        expected = [
            ["203.0.113.1", "203.0.113.2"],  # TTL 1 - load balancing
            ["203.0.113.5", "203.0.113.6", destination_ip],  # TTL 2 - load balancing + destination
        ]
        self.assertEqual(result, expected)


if __name__ == "__main__":
    unittest.main()
