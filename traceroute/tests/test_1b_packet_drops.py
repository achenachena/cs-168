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


class TestPacketDropScenarios(unittest.TestCase):
    """Comprehensive tests for packet drop scenarios in Project 1B"""

    def test_some_probes_dropped_but_others_respond(self):
        """Test handling when some probes don't receive responses but others do"""
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

    def test_all_probes_dropped_for_single_ttl(self):
        """Test handling when all probes for a TTL are dropped"""
        destination_ip = "198.51.100.99"
        router1_ip = "203.0.113.1"
        router3_ip = "203.0.113.3"

        responses = [
            build_time_exceeded_packet(router1_ip, destination_ip),  # TTL 1, probe 1
            None,  # TTL 1, probe 2
            None,  # TTL 1, probe 3
            None,  # TTL 2, probe 1 (all dropped)
            None,  # TTL 2, probe 2 (all dropped)
            None,  # TTL 2, probe 3 (all dropped)
            build_time_exceeded_packet(router3_ip, destination_ip),  # TTL 3, probe 1
            None,  # TTL 3, probe 2
            None,  # TTL 3, probe 3
            build_destination_unreachable_packet(destination_ip, destination_ip),  # TTL 4, probe 1
        ]

        send_socket = FakeSendSocket()
        recv_socket = FakeRecvSocket(responses)

        with mock.patch("traceroute.util.print_result"):
            result = traceroute_mod(send_socket, recv_socket, destination_ip)

        # Should have router1 for TTL 1, empty for TTL 2, router3 for TTL 3, destination for TTL 4
        self.assertEqual(result, [[router1_ip], [router3_ip, destination_ip]])

    def test_intermittent_packet_drops_across_ttls(self):
        """Test handling of intermittent packet drops across multiple TTLs"""
        destination_ip = "198.51.100.99"
        router1_ip = "203.0.113.1"
        router2_ip = "203.0.113.2"
        router3_ip = "203.0.113.3"

        responses = [
            # TTL 1: first and third probes respond
            build_time_exceeded_packet(router1_ip, destination_ip),  # TTL 1, probe 1
            None,  # TTL 1, probe 2 (dropped)
            build_time_exceeded_packet(router1_ip, destination_ip),  # TTL 1, probe 3

            # TTL 2: only second probe responds
            None,  # TTL 2, probe 1 (dropped)
            build_time_exceeded_packet(router2_ip, destination_ip),  # TTL 2, probe 2
            None,  # TTL 2, probe 3 (dropped)

            # TTL 3: all probes respond (no drops)
            build_time_exceeded_packet(router3_ip, destination_ip),  # TTL 3, probe 1
            build_time_exceeded_packet(router3_ip, destination_ip),  # TTL 3, probe 2
            build_time_exceeded_packet(router3_ip, destination_ip),  # TTL 3, probe 3

            # TTL 4: destination reached
            build_destination_unreachable_packet(destination_ip, destination_ip),
        ]

        send_socket = FakeSendSocket()
        recv_socket = FakeRecvSocket(responses)

        with mock.patch("traceroute.util.print_result"):
            result = traceroute_mod(send_socket, recv_socket, destination_ip)

        # Should record routers that responded despite drops
        self.assertEqual(result, [[router1_ip, router2_ip], [router3_ip, destination_ip]])

    def test_high_packet_loss_rate(self):
        """Test handling under high packet loss conditions"""
        destination_ip = "198.51.100.99"
        router_ip = "203.0.113.1"

        # High loss rate: only 1 in 9 probes gets a response
        responses = []
        for ttl in range(1, 4):
            for probe in range(3):
                if ttl == 1 and probe == 0:
                    responses.append(build_time_exceeded_packet(router_ip, destination_ip))
                elif ttl == 3 and probe == 1:
                    responses.append(build_destination_unreachable_packet(destination_ip, destination_ip))
                else:
                    responses.append(None)  # Most packets are dropped

        send_socket = FakeSendSocket()
        recv_socket = FakeRecvSocket(responses)

        with mock.patch("traceroute.util.print_result"):
            result = traceroute_mod(send_socket, recv_socket, destination_ip)

        # Should handle high loss gracefully
        self.assertEqual(result, [[router_ip], [], [destination_ip]])

    def test_complete_packet_loss_until_destination(self):
        """Test handling when all intermediate routers drop packets"""
        destination_ip = "198.51.100.99"

        # All intermediate routers drop packets, only destination responds
        responses = []
        for ttl in range(1, 6):  # TTLs 1-5
            for probe in range(3):
                if ttl == 5 and probe == 0:  # Only destination at TTL 5 responds
                    responses.append(build_destination_unreachable_packet(destination_ip, destination_ip))
                else:
                    responses.append(None)  # All other packets dropped

        send_socket = FakeSendSocket()
        recv_socket = FakeRecvSocket(responses)

        with mock.patch("traceroute.util.print_result"):
            result = traceroute_mod(send_socket, recv_socket, destination_ip)

        # Should have empty lists for TTLs 1-4, destination for TTL 5
        expected = [[]] * 4 + [[destination_ip]]  # 4 empty lists, then destination
        self.assertEqual(result, expected)

    def test_packet_drops_with_late_arriving_responses(self):
        """Test handling of packet drops with some responses arriving late"""
        destination_ip = "198.51.100.99"
        router_ip = "203.0.113.1"

        responses = [
            # TTL 1: first probe responds immediately, others are dropped
            build_time_exceeded_packet(router_ip, destination_ip),  # TTL 1, probe 1
            None,  # TTL 1, probe 2 (dropped)
            None,  # TTL 1, probe 3 (dropped)

            # TTL 2: all probes dropped
            None,  # TTL 2, probe 1 (dropped)
            None,  # TTL 2, probe 2 (dropped)
            None,  # TTL 2, probe 3 (dropped)

            # TTL 3: destination reached
            build_destination_unreachable_packet(destination_ip, destination_ip),
        ]

        send_socket = FakeSendSocket()
        recv_socket = FakeRecvSocket(responses)

        with mock.patch("traceroute.util.print_result"):
            result = traceroute_mod(send_socket, recv_socket, destination_ip)

        # Should handle drops correctly
        self.assertEqual(result, [[router_ip], [], [destination_ip]])

    def test_selective_packet_drops_by_router(self):
        """Test handling when specific routers consistently drop packets"""
        destination_ip = "198.51.100.99"
        router1_ip = "203.0.113.1"  # Always responds
        router2_ip = "203.0.113.2"  # Never responds (always drops)
        router3_ip = "203.0.113.3"  # Sometimes responds

        responses = [
            # TTL 1: router1 always responds
            build_time_exceeded_packet(router1_ip, destination_ip),
            build_time_exceeded_packet(router1_ip, destination_ip),
            build_time_exceeded_packet(router1_ip, destination_ip),

            # TTL 2: router2 never responds (all dropped)
            None, None, None,

            # TTL 3: router3 sometimes responds
            build_time_exceeded_packet(router3_ip, destination_ip),
            None,  # Dropped
            build_time_exceeded_packet(router3_ip, destination_ip),

            # TTL 4: destination reached
            build_destination_unreachable_packet(destination_ip, destination_ip),
        ]

        send_socket = FakeSendSocket()
        recv_socket = FakeRecvSocket(responses)

        with mock.patch("traceroute.util.print_result"):
            result = traceroute_mod(send_socket, recv_socket, destination_ip)

        # Should record responding routers and skip non-responding ones
        self.assertEqual(result, [[router1_ip], [router3_ip, destination_ip]])

    def test_packet_drops_with_duplicate_handling(self):
        """Test that packet drops work correctly with duplicate packet handling"""
        destination_ip = "198.51.100.99"
        router_ip = "203.0.113.1"

        responses = [
            # TTL 1: one response, one duplicate, one drop
            build_time_exceeded_packet(router_ip, destination_ip),  # Valid response
            build_time_exceeded_packet(router_ip, destination_ip),  # Duplicate
            None,  # Dropped

            # TTL 2: all dropped
            None, None, None,

            # TTL 3: destination reached
            build_destination_unreachable_packet(destination_ip, destination_ip),
        ]

        send_socket = FakeSendSocket()
        recv_socket = FakeRecvSocket(responses)

        with mock.patch("traceroute.util.print_result"):
            result = traceroute_mod(send_socket, recv_socket, destination_ip)

        # Should handle both drops and duplicates correctly
        self.assertEqual(result, [[router_ip], [], [destination_ip]])

    def test_maximum_packet_loss_scenario(self):
        """Test traceroute behavior under maximum packet loss conditions"""
        destination_ip = "198.51.100.99"

        # Maximum loss: only destination responds at the very end
        responses = []
        for ttl in range(1, TRACEROUTE_MAX_TTL + 1):
            for probe in range(3):
                if ttl == TRACEROUTE_MAX_TTL and probe == 0:
                    responses.append(build_destination_unreachable_packet(destination_ip, destination_ip))
                else:
                    responses.append(None)  # Everything else is dropped

        send_socket = FakeSendSocket()
        recv_socket = FakeRecvSocket(responses)

        with mock.patch("traceroute.util.print_result"):
            result = traceroute_mod(send_socket, recv_socket, destination_ip)

        # Should handle maximum loss gracefully
        expected = [[]] * (TRACEROUTE_MAX_TTL - 1) + [[destination_ip]]
        self.assertEqual(result, expected)

    def test_packet_drops_with_timeout_behavior(self):
        """Test that packet drops are handled correctly with timeout behavior"""
        destination_ip = "198.51.100.99"
        router_ip = "203.0.113.1"

        # Simulate timeout scenario: first TTL gets one response, then long gap of drops
        responses = [
            build_time_exceeded_packet(router_ip, destination_ip),  # TTL 1, probe 1
            None, None,  # TTL 1, probes 2-3 (dropped)
        ]

        # Add many None responses to simulate timeout period
        responses.extend([None] * 30)  # Simulate 10 TTLs worth of drops

        # Finally, destination responds
        responses.append(build_destination_unreachable_packet(destination_ip, destination_ip))

        send_socket = FakeSendSocket()
        recv_socket = FakeRecvSocket(responses)

        with mock.patch("traceroute.util.print_result"):
            result = traceroute_mod(send_socket, recv_socket, destination_ip)

        # Should handle timeout scenario correctly
        # Traceroute stops early when destination is reached
        self.assertEqual(result, [[router_ip], [destination_ip]])
        self.assertEqual(result[0], [router_ip])  # Only TTL 1 has a response

        # Find where destination appears
        destination_ttl = None
        for i, routers in enumerate(result):
            if destination_ip in routers:
                destination_ttl = i
                break

        self.assertIsNotNone(destination_ttl)
        self.assertEqual(result[destination_ttl], [destination_ip])


if __name__ == "__main__":
    unittest.main()
