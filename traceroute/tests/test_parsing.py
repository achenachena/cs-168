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


class PacketBuilder:
    """Helper class to build various packet types for testing."""
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
        icmp_type: int = traceroute.ICMP_TYPE_TIME_EXCEEDED,
        code: int = traceroute.ICMP_CODE_TTL_TIME_EXCEEDED,
        checksum: int = 0xF7FF,
    ) -> bytes:
        return struct.pack("!BBH4s", icmp_type, code, checksum, b"\x00" * 4)

    @staticmethod
    def udp_header(
        *,
        src_port: int = 49152,
        dst_port: int = traceroute.TRACEROUTE_PORT_NUMBER,
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
    header = PacketBuilder.ipv4_header(src=src, dst=dst, total_length=28)
    icmp = PacketBuilder.icmp_header(
        icmp_type=traceroute.ICMP_TYPE_TIME_EXCEEDED,
        code=traceroute.ICMP_CODE_TTL_TIME_EXCEEDED,
    )
    return header + icmp


def build_destination_packet(src: str, dst: str) -> bytes:
    header = PacketBuilder.ipv4_header(src=src, dst=dst, total_length=28)
    icmp = PacketBuilder.icmp_header(
        icmp_type=traceroute.ICMP_TYPE_DESTINATION_UNREACHABLE,
        code=1,
    )
    return header + icmp


class TestIPv4Parsing(unittest.TestCase):
    """Test IPv4 packet header parsing."""
    def test_ipv4_header_fields_are_parsed(self):
        header = PacketBuilder.ipv4_header()
        packet = traceroute.IPv4(header)
        self.assertEqual(packet.version, 4)
        self.assertEqual(packet.header_len, 5)
        self.assertEqual(packet.tos, 0)
        self.assertEqual(packet.length, 56)
        self.assertEqual(packet.id, 0x1C46)
        self.assertEqual(packet.flags, 0b010)
        self.assertEqual(packet.frag_offset, 0)
        self.assertEqual(packet.ttl, 64)
        self.assertEqual(packet.proto, util.IPPROTO_ICMP)
        self.assertEqual(packet.cksum, 0xB1E6)
        self.assertEqual(packet.src, "192.0.2.1")
        self.assertEqual(packet.dst, "198.51.100.10")

    def test_ipv4_string_representation_contains_key_fields(self):
        header = PacketBuilder.ipv4_header(ttl=32, total_length=60, checksum=0xABCD)
        packet = traceroute.IPv4(header)
        rendered = str(packet)

        self.assertIn("IPv4", rendered)
        self.assertIn("ttl 32", rendered)
        self.assertIn("len 60", rendered)
        self.assertIn("cksum 0xabcd", rendered)
        self.assertIn("192.0.2.1 > 198.51.100.10", rendered)


class TestIcmpParsing(unittest.TestCase):
    """Test ICMP packet header parsing."""
    def test_icmp_header_fields_are_parsed(self):
        header = PacketBuilder.icmp_header(
            icmp_type=traceroute.ICMP_TYPE_TIME_EXCEEDED,
            code=traceroute.ICMP_CODE_TTL_TIME_EXCEEDED,
            checksum=0xAAAA,
        )
        packet = traceroute.ICMP(header)

        self.assertEqual(packet.type, traceroute.ICMP_TYPE_TIME_EXCEEDED)
        self.assertEqual(packet.code, traceroute.ICMP_CODE_TTL_TIME_EXCEEDED)
        self.assertEqual(packet.cksum, 0xAAAA)


class TestUdpParsing(unittest.TestCase):
    """Test UDP packet header parsing."""
    def test_udp_header_fields_are_parsed(self):
        header = PacketBuilder.udp_header(
            src_port=54321,
            dst_port=traceroute.TRACEROUTE_PORT_NUMBER,
            length=42,
            checksum=0x1248,
        )
        packet = traceroute.UDP(header)

        self.assertEqual(packet.src_port, 54321)
        self.assertEqual(packet.dst_port, traceroute.TRACEROUTE_PORT_NUMBER)
        self.assertEqual(packet.len, 42)
        self.assertEqual(packet.cksum, 0x1248)


class TestValidationHelpers(unittest.TestCase):
    """Test validation helper functions."""
    def test_is_valid_ip_accepts_common_cases(self):
        self.assertTrue(traceroute.is_valid_ip("8.8.4.4"))
        self.assertTrue(traceroute.is_valid_ip("0.0.0.0"))
        self.assertTrue(traceroute.is_valid_ip("255.255.255.255"))

    def test_is_valid_ip_rejects_invalid_strings(self):
        for candidate in ("", "127.0.0", "01.2.3.4", "a.b.c.d", "256.1.1.1", "1.1.1.-1"):
            with self.subTest(candidate=candidate):
                self.assertFalse(traceroute.is_valid_ip(candidate))

    def test_is_valid_icmp_allows_time_exceeded(self):
        packet = traceroute.ICMP(PacketBuilder.icmp_header())
        self.assertTrue(traceroute.is_valid_icmp(packet))

    def test_is_valid_icmp_rejects_unexpected_types(self):
        header = PacketBuilder.icmp_header(icmp_type=42, code=1)
        packet = traceroute.ICMP(header)
        self.assertFalse(traceroute.is_valid_icmp(packet))

    def test_is_valid_icmp_rejects_time_exceeded_with_wrong_code(self):
        header = PacketBuilder.icmp_header(
            icmp_type=traceroute.ICMP_TYPE_TIME_EXCEEDED,
            code=99,
        )
        packet = traceroute.ICMP(header)
        self.assertFalse(traceroute.is_valid_icmp(packet))


class TestTracerouteLogic(unittest.TestCase):
    """Test basic traceroute logic."""
    def test_traceroute_discovers_path_and_returns_on_destination(self):
        destination_ip = "198.51.100.99"
        router_ip = "203.0.113.1"

        responses = [
            build_time_exceeded_packet(router_ip, destination_ip),
            None,
            None,
            build_destination_packet(destination_ip, destination_ip),
        ]

        send_socket = FakeSendSocket()
        recv_socket = FakeRecvSocket(responses)

        with mock.patch("traceroute.util.print_result") as print_result:
            result = traceroute_mod(send_socket, recv_socket, destination_ip)

        self.assertEqual(result, [[router_ip], [destination_ip]])
        self.assertEqual(send_socket.ttl_history, [1, 1, 1, 2])
        self.assertEqual(
            [address for _, address in send_socket.sent_packets],
            [(destination_ip, traceroute.TRACEROUTE_PORT_NUMBER)] * 4,
        )

        print_result.assert_called_once_with([router_ip], 1)

        self.assertGreaterEqual(recv_socket.select_calls, 4)


if __name__ == "__main__":
    unittest.main()
