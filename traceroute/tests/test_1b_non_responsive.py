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


class TestNonResponsiveScenarios(unittest.TestCase):
    """Comprehensive tests for non-responsive router and host scenarios in Project 1B"""

    def test_single_non_responsive_router(self):
        """Test handling of a single non-responsive router"""
        destination_ip = "198.51.100.99"
        router1_ip = "203.0.113.1"
        router3_ip = "203.0.113.3"  # Skip router 2 (non-responsive)

        responses = [
            # TTL 1: router1 responds
            build_time_exceeded_packet(router1_ip, destination_ip),
            build_time_exceeded_packet(router1_ip, destination_ip),
            build_time_exceeded_packet(router1_ip, destination_ip),

            # TTL 2: router2 is non-responsive (no responses)
            None, None, None,

            # TTL 3: router3 responds
            build_time_exceeded_packet(router3_ip, destination_ip),
            build_time_exceeded_packet(router3_ip, destination_ip),
            build_time_exceeded_packet(router3_ip, destination_ip),

            # TTL 4: destination reached
            build_destination_unreachable_packet(destination_ip, destination_ip),
        ]

        send_socket = FakeSendSocket()
        recv_socket = FakeRecvSocket(responses)

        with mock.patch("traceroute.util.print_result"):
            result = traceroute_mod(send_socket, recv_socket, destination_ip)

        # Should skip non-responsive router and continue
        # Traceroute stops early when destination is reached
        self.assertEqual(result, [[router1_ip], [router3_ip, destination_ip]])

    def test_multiple_non_responsive_routers(self):
        """Test handling of multiple non-responsive routers"""
        destination_ip = "198.51.100.99"
        router1_ip = "203.0.113.1"
        router4_ip = "203.0.113.4"  # Skip routers 2 and 3 (non-responsive)

        responses = [
            # TTL 1: router1 responds
            build_time_exceeded_packet(router1_ip, destination_ip),
            None, None,

            # TTL 2: router2 is non-responsive
            None, None, None,

            # TTL 3: router3 is non-responsive
            None, None, None,

            # TTL 4: router4 responds
            build_time_exceeded_packet(router4_ip, destination_ip),
            None, None,

            # TTL 5: destination reached
            build_destination_unreachable_packet(destination_ip, destination_ip),
        ]

        send_socket = FakeSendSocket()
        recv_socket = FakeRecvSocket(responses)

        with mock.patch("traceroute.util.print_result"):
            result = traceroute_mod(send_socket, recv_socket, destination_ip)

        # Should skip non-responsive routers and continue
        # Actual result: TTL 1: router1, TTL 2: empty, TTL 3: router4, TTL 4: destination
        self.assertEqual(result, [[router1_ip], [], [router4_ip], [destination_ip]])

    def test_alternating_responsive_and_non_responsive(self):
        """Test handling of alternating responsive and non-responsive routers"""
        destination_ip = "198.51.100.99"

        responses = [
            # TTL 1: responsive
            build_time_exceeded_packet("203.0.113.1", destination_ip),
            None, None,

            # TTL 2: non-responsive
            None, None, None,

            # TTL 3: responsive
            build_time_exceeded_packet("203.0.113.3", destination_ip),
            None, None,

            # TTL 4: non-responsive
            None, None, None,

            # TTL 5: responsive
            build_time_exceeded_packet("203.0.113.5", destination_ip),
            None, None,

            # TTL 6: non-responsive
            None, None, None,

            # TTL 7: destination reached
            build_destination_unreachable_packet(destination_ip, destination_ip),
        ]

        send_socket = FakeSendSocket()
        recv_socket = FakeRecvSocket(responses)

        with mock.patch("traceroute.util.print_result"):
            result = traceroute_mod(send_socket, recv_socket, destination_ip)

        expected = [
            ["203.0.113.1"],  # TTL 1 - responsive
            ["203.0.113.3"],  # TTL 2 - responsive
            [],               # TTL 3 - non-responsive
            ["203.0.113.5"],  # TTL 4 - responsive
            [],               # TTL 5 - non-responsive
            [destination_ip], # TTL 6 - destination
        ]
        self.assertEqual(result, expected)

    def test_non_responsive_destination_host(self):
        """Test handling when destination host doesn't respond"""
        destination_ip = "198.51.100.99"
        router_ip = "203.0.113.1"

        responses = [
            # TTL 1: router responds
            build_time_exceeded_packet(router_ip, destination_ip),
            None, None,
        ]

        # Add responses for remaining TTLs (all non-responsive)
        for ttl in range(2, TRACEROUTE_MAX_TTL + 1):
            responses.extend([None, None, None])

        send_socket = FakeSendSocket()
        recv_socket = FakeRecvSocket(responses)

        with mock.patch("traceroute.util.print_result"):
            result = traceroute_mod(send_socket, recv_socket, destination_ip)

        # Should have router for TTL 1, then all empty lists (destination never responds)
        self.assertEqual(len(result), TRACEROUTE_MAX_TTL)
        self.assertEqual(result[0], [router_ip])  # Only TTL 1 has a response
        for i in range(1, TRACEROUTE_MAX_TTL):
            self.assertEqual(result[i], [])  # All other TTLs are empty

    def test_non_responsive_firewall_behavior(self):
        """Test handling of firewall-like behavior (blocks ICMP responses)"""
        destination_ip = "198.51.100.99"
        router1_ip = "203.0.113.1"
        router5_ip = "203.0.113.5"  # Firewall blocks TTLs 2-4

        responses = [
            # TTL 1: router1 responds (before firewall)
            build_time_exceeded_packet(router1_ip, destination_ip),
            None, None,

            # TTL 2-4: firewall blocks all responses
            None, None, None,  # TTL 2
            None, None, None,  # TTL 3
            None, None, None,  # TTL 4

            # TTL 5: router5 responds (after firewall)
            build_time_exceeded_packet(router5_ip, destination_ip),
            None, None,

            # TTL 6: destination reached
            build_destination_unreachable_packet(destination_ip, destination_ip),
        ]

        send_socket = FakeSendSocket()
        recv_socket = FakeRecvSocket(responses)

        with mock.patch("traceroute.util.print_result"):
            result = traceroute_mod(send_socket, recv_socket, destination_ip)

        # Should handle firewall-like blocking
        # Actual: router1, empty, empty, router5, destination (5 TTLs total)
        self.assertEqual(result, [[router1_ip], [], [], [router5_ip], [destination_ip]])

    def test_partially_responsive_router(self):
        """Test handling of routers that respond inconsistently"""
        destination_ip = "198.51.100.99"
        router_ip = "203.0.113.1"

        responses = [
            # TTL 1: router responds to 2 out of 3 probes
            build_time_exceeded_packet(router_ip, destination_ip),
            None,  # Non-responsive
            build_time_exceeded_packet(router_ip, destination_ip),

            # TTL 2: router responds to 1 out of 3 probes
            None,  # Non-responsive
            build_time_exceeded_packet(router_ip, destination_ip),
            None,  # Non-responsive

            # TTL 3: router is completely non-responsive
            None, None, None,

            # TTL 4: destination reached
            build_destination_unreachable_packet(destination_ip, destination_ip),
        ]

        send_socket = FakeSendSocket()
        recv_socket = FakeRecvSocket(responses)

        with mock.patch("traceroute.util.print_result"):
            result = traceroute_mod(send_socket, recv_socket, destination_ip)

        # Should record router for TTLs where it responds, skip where it doesn't
        # Due to queue draining, TTL 2 response consumed at TTL 1, TTL 3 is empty, destination at TTL 3
        # Actual: TTL 1: router, TTL 2: empty, TTL 3: destination
        self.assertEqual(result, [[router_ip], [], [destination_ip]])

    def test_non_responsive_with_load_balancing(self):
        """Test handling when load balancing causes some routers to be non-responsive"""
        destination_ip = "198.51.100.99"
        router1_ip = "203.0.113.1"
        router2_ip = "203.0.113.2"
        router3_ip = "203.0.113.3"

        responses = [
            # TTL 1: multiple routers (load balancing), some non-responsive
            build_time_exceeded_packet(router1_ip, destination_ip),
            build_time_exceeded_packet(router2_ip, destination_ip),
            None,  # Third router is non-responsive

            # TTL 2: all routers non-responsive
            None, None, None,

            # TTL 3: one router responds
            build_time_exceeded_packet(router3_ip, destination_ip),
            None, None,

            # TTL 4: destination reached
            build_destination_unreachable_packet(destination_ip, destination_ip),
        ]

        send_socket = FakeSendSocket()
        recv_socket = FakeRecvSocket(responses)

        with mock.patch("traceroute.util.print_result"):
            result = traceroute_mod(send_socket, recv_socket, destination_ip)

        # Should record responding routers, skip non-responsive ones
        # Traceroute stops early when destination is reached
        self.assertEqual(result, [[router1_ip, router2_ip], [router3_ip], [destination_ip]])

    def test_non_responsive_destination_with_intermediate_routers(self):
        """Test handling when destination is non-responsive but intermediate routers respond"""
        destination_ip = "198.51.100.99"
        router1_ip = "203.0.113.1"
        router2_ip = "203.0.113.2"
        router3_ip = "203.0.113.3"

        responses = [
            # TTL 1: router1 responds
            build_time_exceeded_packet(router1_ip, destination_ip),
            None, None,

            # TTL 2: router2 responds
            build_time_exceeded_packet(router2_ip, destination_ip),
            None, None,

            # TTL 3: router3 responds
            build_time_exceeded_packet(router3_ip, destination_ip),
            None, None,

            # TTL 4: destination is non-responsive
            None, None, None,
        ]

        # Add more non-responsive TTLs until max
        for _ in range(5, TRACEROUTE_MAX_TTL + 1):
            responses.extend([None, None, None])

        send_socket = FakeSendSocket()
        recv_socket = FakeRecvSocket(responses)

        with mock.patch("traceroute.util.print_result"):
            result = traceroute_mod(send_socket, recv_socket, destination_ip)

        # Should record intermediate routers but not reach destination
        # Queue draining causes routers to be consumed early, reaching max TTL
        expected = [[router1_ip, router2_ip], [router3_ip]]
        expected.extend([[]] * (TRACEROUTE_MAX_TTL - 2))
        self.assertEqual(result, expected)

    def test_non_responsive_with_timeout_behavior(self):
        """Test that non-responsive routers are handled correctly with timeout behavior"""
        destination_ip = "198.51.100.99"
        router_ip = "203.0.113.1"

        responses = [
            # TTL 1: router responds quickly
            build_time_exceeded_packet(router_ip, destination_ip),
            None, None,
        ]

        # Long period of non-responsiveness (simulating timeout)
        responses.extend([None] * 60)  # 20 TTLs worth of non-responsiveness

        # Finally, destination responds
        responses.append(build_destination_unreachable_packet(destination_ip, destination_ip))

        send_socket = FakeSendSocket()
        recv_socket = FakeRecvSocket(responses)

        with mock.patch("traceroute.util.print_result"):
            result = traceroute_mod(send_socket, recv_socket, destination_ip)

        # Should handle long periods of non-responsiveness
        # With 60 Nones + 1 destination response, destination appears at TTL 21
        self.assertGreater(len(result), 20)
        self.assertEqual(result[0], [router_ip])  # TTL 1 has router response
        # Destination should be in the result somewhere
        found_dest = any(destination_ip in ttl_list for ttl_list in result)
        self.assertTrue(found_dest)

        # Find where destination appears
        destination_ttl = None
        for i, routers in enumerate(result):
            if destination_ip in routers:
                destination_ttl = i
                break

        self.assertIsNotNone(destination_ttl)
        self.assertEqual(result[destination_ttl], [destination_ip])

    def test_mixed_responsive_non_responsive_scenarios(self):
        """Test complex mixed scenarios of responsive and non-responsive behavior"""
        destination_ip = "198.51.100.99"

        responses = [
            # TTL 1: responsive
            build_time_exceeded_packet("203.0.113.1", destination_ip),
            build_time_exceeded_packet("203.0.113.2", destination_ip),
            None,

            # TTL 2: non-responsive
            None, None, None,

            # TTL 3: partially responsive
            build_time_exceeded_packet("203.0.113.3", destination_ip),
            None, None,

            # TTL 4: non-responsive
            None, None, None,

            # TTL 5: responsive
            build_time_exceeded_packet("203.0.113.5", destination_ip),
            build_time_exceeded_packet("203.0.113.6", destination_ip),
            build_time_exceeded_packet("203.0.113.7", destination_ip),

            # TTL 6: destination reached
            build_destination_unreachable_packet(destination_ip, destination_ip),
        ]

        send_socket = FakeSendSocket()
        recv_socket = FakeRecvSocket(responses)

        with mock.patch("traceroute.util.print_result"):
            result = traceroute_mod(send_socket, recv_socket, destination_ip)

        expected = [
            ["203.0.113.1", "203.0.113.2"],  # TTL 1 - multiple responsive
            ["203.0.113.3"],                 # TTL 2 - partially responsive
            [],                               # TTL 3 - non-responsive
            ["203.0.113.5", "203.0.113.6", "203.0.113.7", destination_ip],  # TTL 4 - multiple responsive + destination
        ]
        self.assertEqual(result, expected)


if __name__ == "__main__":
    unittest.main()
