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


def build_time_exceeded_packet(src: str, dst: str, ttl: int = 64) -> bytes:
    """Build ICMP Time Exceeded packet"""
    header = PacketBuilder.ipv4_header(src=src, dst=dst, total_length=28, ttl=ttl)
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


class TestProject1BDuplicatePackets(unittest.TestCase):
    """Test cases for handling duplicate packets in Project 1B"""

    def test_duplicate_icmp_time_exceeded_same_ttl(self):
        """Test that duplicate ICMP Time Exceeded messages from same router are handled correctly"""
        destination_ip = "198.51.100.99"
        router_ip = "203.0.113.1"

        # Send 3 identical time exceeded responses for TTL 1
        responses = [
            build_time_exceeded_packet(router_ip, destination_ip),  # First response
            build_time_exceeded_packet(router_ip, destination_ip),  # Duplicate
            build_time_exceeded_packet(router_ip, destination_ip),  # Another duplicate
            None,  # No response for TTL 2 probe 1
            None,  # No response for TTL 2 probe 2
            None,  # No response for TTL 2 probe 3
        ]

        send_socket = FakeSendSocket()
        recv_socket = FakeRecvSocket(responses)

        with mock.patch("traceroute.util.print_result"):
            result = traceroute_mod(send_socket, recv_socket, destination_ip)

        # Should only record router_ip once for TTL 1, even though we got 3 responses
        self.assertEqual(result[0], [router_ip])  # TTL 1 should have only one entry
        self.assertEqual(result[1], [])  # TTL 2 should be empty

        # Should have sent 6 probes total (3 for TTL 1, 3 for TTL 2)
        self.assertEqual(len(send_socket.ttl_history), 6)
        self.assertEqual(send_socket.ttl_history, [1, 1, 1, 2, 2, 2])

    def test_duplicate_icmp_destination_unreachable(self):
        """Test that duplicate ICMP Destination Unreachable messages are handled correctly"""
        destination_ip = "198.51.100.99"

        # Send multiple destination unreachable responses
        responses = [
            build_destination_unreachable_packet(destination_ip, destination_ip, code=3),  # Port unreachable
            build_destination_unreachable_packet(destination_ip, destination_ip, code=3),  # Duplicate
            build_destination_unreachable_packet(destination_ip, destination_ip, code=3),  # Another duplicate
        ]

        send_socket = FakeSendSocket()
        recv_socket = FakeRecvSocket(responses)

        with mock.patch("traceroute.util.print_result"):
            result = traceroute_mod(send_socket, recv_socket, destination_ip)

        # Should record destination only once despite multiple responses
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], [destination_ip])

    def test_duplicate_from_different_routers_same_ttl(self):
        """Test handling of responses from different routers at same TTL"""
        destination_ip = "198.51.100.99"
        router1_ip = "203.0.113.1"
        router2_ip = "203.0.113.2"
        router3_ip = "203.0.113.3"

        # Multiple routers responding at TTL 1
        responses = [
            build_time_exceeded_packet(router1_ip, destination_ip),
            build_time_exceeded_packet(router2_ip, destination_ip),
            build_time_exceeded_packet(router3_ip, destination_ip),
            None, None, None,  # No responses for TTL 2
        ]

        send_socket = FakeSendSocket()
        recv_socket = FakeRecvSocket(responses)

        with mock.patch("traceroute.util.print_result"):
            result = traceroute_mod(send_socket, recv_socket, destination_ip)

        # Should record all three routers for TTL 1
        self.assertEqual(len(result[0]), 3)
        self.assertIn(router1_ip, result[0])
        self.assertIn(router2_ip, result[0])
        self.assertIn(router3_ip, result[0])
        self.assertEqual(result[1], [])  # TTL 2 should be empty

    def test_mixed_duplicate_and_unique_responses(self):
        """Test handling of mixed duplicate and unique responses"""
        destination_ip = "198.51.100.99"
        router_ip = "203.0.113.1"

        responses = [
            build_time_exceeded_packet(router_ip, destination_ip),  # TTL 1, probe 1
            build_time_exceeded_packet(router_ip, destination_ip),  # TTL 1, probe 2 (duplicate)
            None,  # TTL 1, probe 3 (no response)
            build_time_exceeded_packet(destination_ip, destination_ip),  # TTL 2, probe 1 (destination reached)
        ]

        send_socket = FakeSendSocket()
        recv_socket = FakeRecvSocket(responses)

        with mock.patch("traceroute.util.print_result"):
            result = traceroute_mod(send_socket, recv_socket, destination_ip)

        # Should have router once for TTL 1, destination for TTL 2
        self.assertEqual(result, [[router_ip, destination_ip]])


class TestProject1BUnrelatedPackets(unittest.TestCase):
    """Test cases for handling unrelated packets in Project 1B"""

    def test_icmp_echo_reply_ignored(self):
        """Test that ICMP Echo Reply packets are ignored"""
        destination_ip = "198.51.100.99"
        router_ip = "203.0.113.1"

        responses = [
            build_echo_reply_packet("8.8.8.8", "1.1.1.1"),  # Unrelated echo reply
            build_time_exceeded_packet(router_ip, destination_ip),  # Valid time exceeded
            build_destination_unreachable_packet(destination_ip, destination_ip),  # Destination reached
        ]

        send_socket = FakeSendSocket()
        recv_socket = FakeRecvSocket(responses)

        with mock.patch("traceroute.util.print_result"):
            result = traceroute_mod(send_socket, recv_socket, destination_ip)

        # Should ignore echo reply and only process valid responses
        self.assertEqual(result, [[router_ip, destination_ip]])

    def test_udp_packet_ignored(self):
        """Test that unrelated UDP packets are ignored"""
        destination_ip = "198.51.100.99"
        router_ip = "203.0.113.1"

        responses = [
            build_udp_packet("10.0.0.1", "10.0.0.2"),  # Unrelated UDP packet
            build_time_exceeded_packet(router_ip, destination_ip),  # Valid time exceeded
            build_destination_unreachable_packet(destination_ip, destination_ip),  # Destination reached
        ]

        send_socket = FakeSendSocket()
        recv_socket = FakeRecvSocket(responses)

        with mock.patch("traceroute.util.print_result"):
            result = traceroute_mod(send_socket, recv_socket, destination_ip)

        # Should ignore UDP packet and only process valid responses
        self.assertEqual(result, [[router_ip, destination_ip]])

    def test_invalid_icmp_type_ignored(self):
        """Test that ICMP packets with invalid types are ignored"""
        destination_ip = "198.51.100.99"
        router_ip = "203.0.113.1"

        # Create invalid ICMP packet (type 42, code 1)
        invalid_icmp_header = PacketBuilder.ipv4_header(src="1.1.1.1", dst="2.2.2.2", total_length=28)
        invalid_icmp = PacketBuilder.icmp_header(icmp_type=42, code=1)
        invalid_packet = invalid_icmp_header + invalid_icmp

        responses = [
            invalid_packet,  # Invalid ICMP packet
            build_time_exceeded_packet(router_ip, destination_ip),  # Valid time exceeded
            build_destination_unreachable_packet(destination_ip, destination_ip),  # Destination reached
        ]

        send_socket = FakeSendSocket()
        recv_socket = FakeRecvSocket(responses)

        with mock.patch("traceroute.util.print_result"):
            result = traceroute_mod(send_socket, recv_socket, destination_ip)

        # Should ignore invalid ICMP and only process valid responses
        self.assertEqual(result, [[router_ip, destination_ip]])

    def test_malformed_packets_ignored(self):
        """Test that malformed packets are ignored"""
        destination_ip = "198.51.100.99"
        router_ip = "203.0.113.1"

        # Create malformed packet (too short)
        malformed_packet = b"\x45\x00\x00\x14"  # Only first 4 bytes of IP header

        responses = [
            build_time_exceeded_packet(router_ip, destination_ip),  # Valid time exceeded
            build_destination_unreachable_packet(destination_ip, destination_ip),  # Destination reached
        ]

        send_socket = FakeSendSocket()
        recv_socket = FakeRecvSocket(responses)

        with mock.patch("traceroute.util.print_result"):
            result = traceroute_mod(send_socket, recv_socket, destination_ip)

        # Should ignore malformed packet and only process valid responses
        self.assertEqual(result, [[router_ip, destination_ip]])


class TestProject1BPacketDrops(unittest.TestCase):
    """Test cases for handling packet drops in Project 1B"""

    def test_no_response_for_some_probes(self):
        """Test handling when some probes don't receive responses"""
        destination_ip = "198.51.100.99"
        router_ip = "203.0.113.1"

        # Only first probe gets response, others are dropped
        responses = [
            build_time_exceeded_packet(router_ip, destination_ip),  # TTL 1, probe 1
            None,  # TTL 1, probe 2 (dropped)
            None,  # TTL 1, probe 3 (dropped)
            build_time_exceeded_packet(destination_ip, destination_ip),  # TTL 2, probe 1
        ]

        send_socket = FakeSendSocket()
        recv_socket = FakeRecvSocket(responses)

        with mock.patch("traceroute.util.print_result"):
            result = traceroute_mod(send_socket, recv_socket, destination_ip)

        # Should still record the router that responded
        self.assertEqual(result, [[router_ip, destination_ip]])

    def test_no_response_for_entire_ttl(self):
        """Test handling when entire TTL gets no responses"""
        destination_ip = "198.51.100.99"
        router_ip = "203.0.113.1"

        # TTL 1 gets responses, TTL 2 gets nothing, TTL 3 reaches destination
        responses = [
            build_time_exceeded_packet(router_ip, destination_ip),  # TTL 1, probe 1
            None,  # TTL 1, probe 2
            None,  # TTL 1, probe 3
            None,  # TTL 2, probe 1 (dropped)
            None,  # TTL 2, probe 2 (dropped)
            None,  # TTL 2, probe 3 (dropped)
            build_time_exceeded_packet(destination_ip, destination_ip),  # TTL 3, probe 1
        ]

        send_socket = FakeSendSocket()
        recv_socket = FakeRecvSocket(responses)

        with mock.patch("traceroute.util.print_result"):
            result = traceroute_mod(send_socket, recv_socket, destination_ip)

        # Should have router for TTL 1, empty for TTL 2, destination for TTL 3
        self.assertEqual(result, [[router_ip], [], [destination_ip]])

    def test_intermittent_packet_drops(self):
        """Test handling of intermittent packet drops across multiple TTLs"""
        destination_ip = "198.51.100.99"
        router1_ip = "203.0.113.1"
        router2_ip = "203.0.113.2"

        # Mixed responses and drops
        responses = [
            build_time_exceeded_packet(router1_ip, destination_ip),  # TTL 1, probe 1
            None,  # TTL 1, probe 2 (dropped)
            build_time_exceeded_packet(router1_ip, destination_ip),  # TTL 1, probe 3
            None,  # TTL 2, probe 1 (dropped)
            build_time_exceeded_packet(router2_ip, destination_ip),  # TTL 2, probe 2
            None,  # TTL 2, probe 3 (dropped)
            build_destination_unreachable_packet(destination_ip, destination_ip),  # TTL 3, probe 1
        ]

        send_socket = FakeSendSocket()
        recv_socket = FakeRecvSocket(responses)

        with mock.patch("traceroute.util.print_result"):
            result = traceroute_mod(send_socket, recv_socket, destination_ip)

        # Should record routers that responded despite drops
        self.assertEqual(result, [[router1_ip, router2_ip, destination_ip]])


class TestProject1BNonResponsive(unittest.TestCase):
    """Test cases for handling non-responsive routers and hosts in Project 1B"""

    def test_non_responsive_router_continues_to_next_ttl(self):
        """Test that non-responsive routers don't block traceroute progression"""
        destination_ip = "198.51.100.99"
        router1_ip = "203.0.113.1"
        router3_ip = "203.0.113.3"  # Skip router 2 (non-responsive)

        # Router at TTL 1 responds, TTL 2 is non-responsive, TTL 3 responds
        responses = [
            build_time_exceeded_packet(router1_ip, destination_ip),  # TTL 1
            None, None, None,  # TTL 2 (non-responsive)
            build_time_exceeded_packet(router3_ip, destination_ip),  # TTL 3
            None, None, None,  # TTL 4 (non-responsive)
            build_destination_unreachable_packet(destination_ip, destination_ip),  # TTL 5
        ]

        send_socket = FakeSendSocket()
        recv_socket = FakeRecvSocket(responses)

        with mock.patch("traceroute.util.print_result"):
            result = traceroute_mod(send_socket, recv_socket, destination_ip)

        # Should have router1 for TTL 1, empty for TTL 2, router3 for TTL 3, empty for TTL 4, destination for TTL 5
        self.assertEqual(result, [[router1_ip], [router3_ip, destination_ip]])

    def test_non_responsive_destination_timeout(self):
        """Test handling when destination host doesn't respond"""
        destination_ip = "198.51.100.99"
        router_ip = "203.0.113.1"

        # Router responds, but destination never responds
        responses = [
            build_time_exceeded_packet(router_ip, destination_ip),  # TTL 1
            None, None, None,  # TTL 2 (no response)
            None, None, None,  # TTL 3 (no response)
            # Continue with no responses until max TTL
        ]
        # Add more None responses to reach max TTL
        responses.extend([None] * (TRACEROUTE_MAX_TTL - 3) * 3)

        send_socket = FakeSendSocket()
        recv_socket = FakeRecvSocket(responses)

        with mock.patch("traceroute.util.print_result"):
            result = traceroute_mod(send_socket, recv_socket, destination_ip)

        # Should have router for TTL 1, then all empty lists until max TTL
        self.assertEqual(len(result), TRACEROUTE_MAX_TTL)
        self.assertEqual(result[0], [router_ip])  # Only TTL 1 has a response
        for i in range(1, TRACEROUTE_MAX_TTL):
            self.assertEqual(result[i], [])  # All other TTLs are empty

    def test_mixed_responsive_and_non_responsive(self):
        """Test handling of mixed responsive and non-responsive routers"""
        destination_ip = "198.51.100.99"

        responses = [
            build_time_exceeded_packet("203.0.113.1", destination_ip),  # TTL 1 - responsive
            None, None, None,  # TTL 2 - non-responsive
            build_time_exceeded_packet("203.0.113.3", destination_ip),  # TTL 3 - responsive
            None, None, None,  # TTL 4 - non-responsive
            build_time_exceeded_packet("203.0.113.5", destination_ip),  # TTL 5 - responsive
            None, None, None,  # TTL 6 - non-responsive
            build_destination_unreachable_packet(destination_ip, destination_ip),  # TTL 7 - destination
        ]

        send_socket = FakeSendSocket()
        recv_socket = FakeRecvSocket(responses)

        with mock.patch("traceroute.util.print_result"):
            result = traceroute_mod(send_socket, recv_socket, destination_ip)

        expected = [
            ["203.0.113.1"],  # TTL 1
            [],               # TTL 2 (non-responsive)
            ["203.0.113.3"],  # TTL 3
            [],               # TTL 4 (non-responsive)
            ["203.0.113.5"],  # TTL 5
            [],               # TTL 6 (non-responsive)
            [destination_ip], # TTL 7 (destination)
        ]
        self.assertEqual(result, expected)


class TestProject1BMixedScenarios(unittest.TestCase):
    """Test cases for complex mixed error scenarios in Project 1B"""

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

            # TTL 3: valid response
            build_time_exceeded_packet(router2_ip, destination_ip),
            None, None,  # Some dropped

            # TTL 4: destination reached with duplicates
            build_destination_unreachable_packet(destination_ip, destination_ip),
            build_destination_unreachable_packet(destination_ip, destination_ip),  # Duplicate
        ]

        send_socket = FakeSendSocket()
        recv_socket = FakeRecvSocket(responses)

        with mock.patch("traceroute.util.print_result"):
            result = traceroute_mod(send_socket, recv_socket, destination_ip)

        # Should handle all scenarios correctly
        self.assertEqual(result, [[router1_ip], [router2_ip, destination_ip]])

    def test_late_arriving_duplicates(self):
        """Test handling of duplicates that arrive after valid responses"""
        destination_ip = "198.51.100.99"
        router_ip = "203.0.113.1"

        responses = [
            build_time_exceeded_packet(router_ip, destination_ip),  # TTL 1, probe 1 (valid)
            None,  # TTL 1, probe 2 (dropped)
            build_time_exceeded_packet(router_ip, destination_ip),  # TTL 1, probe 3 (duplicate)
            build_time_exceeded_packet(destination_ip, destination_ip),  # TTL 2, probe 1 (destination)
        ]

        send_socket = FakeSendSocket()
        recv_socket = FakeRecvSocket(responses)

        with mock.patch("traceroute.util.print_result"):
            result = traceroute_mod(send_socket, recv_socket, destination_ip)

        # Should record router once despite duplicate
        self.assertEqual(result, [[router_ip, destination_ip]])

    def test_maximum_error_conditions(self):
        """Test traceroute behavior under maximum error conditions"""
        destination_ip = "198.51.100.99"

        responses = []
        # Fill with mostly unrelated packets and drops, with occasional valid responses
        for ttl in range(1, TRACEROUTE_MAX_TTL + 1):
            for probe in range(3):
                if ttl == 1 and probe == 0:
                    responses.append(build_time_exceeded_packet("203.0.113.1", destination_ip))
                elif ttl == 5 and probe == 1:
                    responses.append(build_time_exceeded_packet("203.0.113.5", destination_ip))
                elif ttl == 15 and probe == 2:
                    responses.append(build_destination_unreachable_packet(destination_ip, destination_ip))
                elif ttl % 3 == 0:  # Every 3rd TTL, add unrelated packets
                    responses.append(build_echo_reply_packet(f"192.168.{ttl}.1", f"10.0.{ttl}.1"))
                else:
                    responses.append(None)  # Most packets are dropped

        send_socket = FakeSendSocket()
        recv_socket = FakeRecvSocket(responses)

        with mock.patch("traceroute.util.print_result"):
            result = traceroute_mod(send_socket, recv_socket, destination_ip)

        # Should have responses at TTL 1, 5, and 15 only
        self.assertEqual(len(result), TRACEROUTE_MAX_TTL)
        self.assertEqual(result[0], ["203.0.113.1"])   # TTL 1
        self.assertEqual(result[4], ["203.0.113.5"])   # TTL 5
        self.assertEqual(result[14], [destination_ip]) # TTL 15 (destination reached)

        # All other TTLs should be empty
        for i in range(TRACEROUTE_MAX_TTL):
            if i not in [0, 4, 14]:
                self.assertEqual(result[i], [])


if __name__ == "__main__":
    unittest.main()
