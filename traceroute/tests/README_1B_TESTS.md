# CS 168 Project 1B - Traceroute Error Handling Test Suite

This directory contains comprehensive tests for **Project 1B: Traceroute Error Handling** of CS 168 Spring 2025.

## Overview

Project 1B focuses on enhancing your traceroute implementation to handle various network anomalies that occur in real-world networks:

- **Duplicate packets**
- **Unrelated packets** 
- **Packet drops**
- **Non-responsive routers/hosts**

## Test Files

### Core Test Files

1. **`test_1b_error_handling.py`** - Main test file with comprehensive error handling scenarios
2. **`test_1b_duplicate_packets.py`** - Detailed tests for all duplicate packet scenarios
3. **`test_1b_unrelated_packets.py`** - Tests for filtering unrelated packets
4. **`test_1b_packet_drops.py`** - Tests for packet drop scenarios
5. **`test_1b_non_responsive.py`** - Tests for non-responsive routers and hosts
6. **`test_1b_mixed_scenarios.py`** - Complex mixed error scenarios

### Test Runner

- **`run_project_1b_tests.py`** - Comprehensive test runner for all Project 1B tests

## Running Tests

### Run All Project 1B Tests
```bash
cd /Users/lmc/repos/cs-168/traceroute/tests
python3 run_project_1b_tests.py
```

### Run with Verbose Output
```bash
python3 run_project_1b_tests.py --verbose
```

### Run Specific Test Suite
```bash
python3 run_project_1b_tests.py --specific test_1b_duplicate_packets
```

### Show Test Summary
```bash
python3 run_project_1b_tests.py --summary
```

## Test Coverage

### 1. Duplicate Packet Handling
- ✅ Identical ICMP Time Exceeded packets
- ✅ Duplicate packets with different identifiers  
- ✅ Duplicate packets with different TTLs
- ✅ Duplicate destination unreachable packets
- ✅ Cross-TTL duplicates (late arriving)
- ✅ Same router responding at multiple TTLs
- ✅ Mixed ICMP type duplicates
- ✅ Extreme duplicate scenarios

### 2. Unrelated Packet Filtering
- ✅ ICMP Echo Request/Reply packets
- ✅ UDP packets
- ✅ TCP packets
- ✅ ICMP Redirect packets
- ✅ ICMP Parameter Problem packets
- ✅ ICMP Timestamp packets
- ✅ Invalid ICMP types and codes
- ✅ Malformed packets
- ✅ Wrong protocol packets

### 3. Packet Drop Scenarios
- ✅ Some probes dropped, others respond
- ✅ All probes dropped for single TTL
- ✅ Intermittent drops across TTLs
- ✅ High packet loss rates
- ✅ Complete packet loss until destination
- ✅ Late arriving responses
- ✅ Selective drops by router
- ✅ Maximum packet loss scenarios

### 4. Non-Responsive Routers/Hosts
- ✅ Single non-responsive router
- ✅ Multiple non-responsive routers
- ✅ Alternating responsive/non-responsive
- ✅ Non-responsive destination host
- ✅ Firewall-like blocking behavior
- ✅ Partially responsive routers
- ✅ Load balancing with non-responsive routers
- ✅ Timeout behavior scenarios

### 5. Mixed Error Scenarios
- ✅ Duplicates + unrelated + drops combined
- ✅ Non-responsive + duplicates + unrelated
- ✅ Intermittent drops + duplicates + unrelated
- ✅ Late arriving duplicates + drops
- ✅ Mixed ICMP types + drops + unrelated
- ✅ Extreme mixed scenarios
- ✅ Network congestion simulation
- ✅ Load balancing with mixed errors

## Test Architecture

### Helper Classes

- **`PacketBuilder`** - Builds various packet types for testing
- **`FakeSendSocket`** - Mocks UDP socket for sending probes
- **`FakeRecvSocket`** - Mocks ICMP socket for receiving responses

### Test Structure

Each test file follows this pattern:
1. **Setup** - Create test packets and mock sockets
2. **Execute** - Run traceroute with specific scenario
3. **Verify** - Check that results match expected behavior

### Key Test Functions

- `build_time_exceeded_packet()` - Creates ICMP Time Exceeded packets
- `build_destination_unreachable_packet()` - Creates ICMP Destination Unreachable packets
- `build_echo_reply_packet()` - Creates unrelated ICMP Echo Reply packets
- `build_udp_packet()` - Creates unrelated UDP packets
- `build_malformed_packet()` - Creates malformed packets for testing

## Expected Behavior

Your traceroute implementation should:

1. **Handle Duplicates**: Record each unique router only once per TTL
2. **Filter Unrelated**: Ignore packets not related to your traceroute probes
3. **Handle Drops**: Continue probing when packets are lost
4. **Skip Non-Responsive**: Continue to next TTL when routers don't respond
5. **Reach Destination**: Stop when destination is reached or max TTL exceeded

## Integration with Existing Tests

These tests complement the existing `test_parsing.py` which covers:
- IPv4, ICMP, and UDP packet parsing
- Basic validation functions
- Simple traceroute logic

The Project 1B tests focus specifically on error handling scenarios that make your traceroute robust against real-world network conditions.

## Debugging Failed Tests

If tests fail:

1. **Check packet parsing** - Ensure IPv4/ICMP parsing works correctly
2. **Verify validation** - Check that `is_valid_ip()` and `is_valid_icmp()` work
3. **Review duplicate handling** - Make sure you're tracking unique routers per TTL
4. **Check filtering** - Ensure unrelated packets are properly ignored
5. **Test timeout behavior** - Verify handling of non-responsive routers

## Success Criteria

Your implementation passes all tests when it correctly handles:
- ✅ All duplicate packet scenarios
- ✅ All unrelated packet filtering
- ✅ All packet drop scenarios  
- ✅ All non-responsive scenarios
- ✅ All mixed error scenarios

**Total: 50+ individual test cases covering comprehensive error handling**
