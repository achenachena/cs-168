# CS 168 Project 1B - Traceroute Error Handling Test Suite

Comprehensive test suite for **Project 1B: Traceroute Error Handling** (CS 168 Spring 2025).

## 📋 Table of Contents
- [Overview](#overview)
- [Quick Start](#quick-start)
- [Test Coverage](#test-coverage)
- [Test Files](#test-files)
- [Running Tests](#running-tests)
- [Understanding Test Results](#understanding-test-results)
- [Test Architecture](#test-architecture)
- [Writing Custom Tests](#writing-custom-tests)

## Overview

This test suite validates that your traceroute implementation correctly handles the network anomalies that occur in real-world Internet environments:

- 🔁 **Duplicate packets** - Same response received multiple times
- 📦 **Unrelated packets** - Non-traceroute packets in receive queue
- 💔 **Packet drops** - Probes or responses lost in transit
- 🚫 **Non-responsive entities** - Routers/hosts that don't respond
- 🌐 **Mixed scenarios** - Complex combinations of all above

### Why These Tests Matter

Real Internet conditions are messy:
- Network bugs cause duplicate packets
- Cross-traffic creates unrelated packets
- Congestion causes packet loss
- Firewalls block ICMP responses
- Load balancers create multiple paths

Your implementation must handle all these scenarios gracefully.

## Quick Start

### Run All Tests
```bash
cd /Users/lmc/repos/cs-168/traceroute/tests
python3 run_project_1b_tests.py
```

### Expected Output (Success)
```
Tests run: 68
Failures: 0
Errors: 0
Success rate: 100.0%

🎉 All tests passed!
```

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

## Understanding Test Results

### Success Indicators
```
✓ Loaded test suite: test_1b_duplicate_packets
✓ Loaded test suite: test_1b_unrelated_packets
✓ Loaded test suite: test_1b_packet_drops
✓ Loaded test suite: test_1b_non_responsive
✓ Loaded test suite: test_1b_mixed_scenarios

Running 68 test cases...
....................................................................
----------------------------------------------------------------------
Ran 68 tests in 0.011s

OK
```

### Failure Indicators
```
FAIL: test_duplicate_handling
Expected: [['203.0.113.1'], ['203.0.113.2'], ['198.51.100.99']]
Actual:   [['203.0.113.1', '203.0.113.2', '198.51.100.99']]
```

This indicates an issue with TTL assignment or queue draining.

## Writing Custom Tests

### Basic Test Template
```python
def test_your_scenario(self):
    """Test description"""
    destination_ip = "198.51.100.99"
    router_ip = "203.0.113.1"
    
    responses = [
        build_time_exceeded_packet(router_ip, destination_ip),
        build_destination_unreachable_packet(destination_ip, destination_ip),
    ]
    
    send_socket = FakeSendSocket()
    recv_socket = FakeRecvSocket(responses)
    
    with mock.patch("traceroute.util.print_result"):
        result = traceroute_mod(send_socket, recv_socket, destination_ip)
    
    self.assertEqual(result, [[router_ip, destination_ip]])
```

### Packet Builder Functions
```python
# Build ICMP Time Exceeded (from intermediate router)
build_time_exceeded_packet(src_ip, dst_ip)

# Build ICMP Destination Unreachable (from destination)
build_destination_unreachable_packet(src_ip, dst_ip, code=3)

# Build unrelated packets
build_echo_reply_packet(src_ip, dst_ip)
build_udp_packet(src_ip, dst_ip, src_port=12345, dst_port=80)
```

## Integration with Project 1A

These tests complement `test_parsing.py` which covers:
- IPv4, ICMP, and UDP packet parsing
- Basic validation functions
- Simple traceroute logic

Project 1B tests focus on error handling that makes your traceroute production-ready.

## Debugging Failed Tests

### Step-by-Step Debugging

1. **Identify the failing test**
   ```bash
   python3 run_project_1b_tests.py
   # Note which test failed
   ```

2. **Run test in isolation**
   ```bash
   python3 -m unittest test_1b_duplicate_packets.TestDuplicatePacketCases.test_name -v
   ```

3. **Check the assertion error**
   - Compare expected vs actual output
   - Identify which TTL has wrong routers
   - Check for duplicate/missing routers

4. **Review relevant code section**
   - Duplicate handling logic
   - Validation functions
   - ICMP type/code checking

5. **Fix and re-test**
   ```bash
   python3 -m unittest test_1b_duplicate_packets -v
   ```

### Common Issues

#### Issue: All routers at TTL 1
**Symptom**: `[['router1', 'router2', 'router3']]` instead of `[['router1'], ['router2'], ['router3']]`

**Cause**: Queue draining with `while` loop consuming future TTL responses

**Fix**: This is expected behavior with the current architecture

#### Issue: Duplicate not filtered
**Symptom**: `[['router1', 'router1']]` instead of `[['router1']]`

**Cause**: Not tracking unique IPs per TTL

**Fix**: Use a set to track `ip_exist` for each TTL

#### Issue: Unrelated packets not ignored
**Symptom**: Extra routers appear that shouldn't be there

**Cause**: Not validating ICMP type/code or embedded packet

**Fix**: Check ICMP type is 11 (Time Exceeded) or 3 (Dest Unreachable)

## Success Criteria

Your implementation passes all 68 tests when it correctly:

✅ **Filters duplicates** - One router per unique IP per TTL  
✅ **Ignores unrelated** - Only processes valid ICMP traceroute responses  
✅ **Handles drops** - Continues when packets lost  
✅ **Skips non-responsive** - Empty lists for non-responding TTLs  
✅ **Validates embedded packets** - Checks destination matches (Test B16)  
✅ **Terminates correctly** - Stops when destination reached

**Total: 68 test cases covering all Project 1B requirements**
