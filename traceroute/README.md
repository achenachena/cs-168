# CS 168 Project 1: Traceroute

This directory contains the implementation and tests for CS 168 Project 1: Traceroute, including both Project 1A (Basic Traceroute) and Project 1B (Error Handling).

## Project Overview

**Project 1A: Basic Traceroute** - Implement core traceroute functionality
**Project 1B: Error Handling** - Add robust error handling for real-world network conditions

## Files

- `traceroute.py` - Main traceroute implementation
- `util.py` - Utility functions for socket handling and packet parsing
- `tests/` - Test suite directory
  - `test_parsing.py` - Tests for packet parsing and basic functionality
  - `test_1b_*.py` - Comprehensive Project 1B error handling tests
  - `run_project_1b_tests.py` - Test runner for Project 1B

## Quick Start

### Basic Usage

```bash
# Run traceroute to a destination
sudo python3 traceroute.py cmu.edu

# Run with verbose output
sudo python3 traceroute.py -v google.com
```

### Setup Requirements

- **Operating System**: Linux or macOS (Windows users should use WSL)
- **Python**: 3.11 or higher
- **Privileges**: `sudo` required for raw socket access

## Testing

### Running Tests

#### 1. Basic Functionality Tests (Project 1A)

```bash
# Run basic packet parsing and functionality tests
cd tests
python3 -m unittest test_parsing.py

# Run with verbose output
python3 -m unittest test_parsing.py -v
```

These tests verify:
- IPv4, ICMP, and UDP packet parsing
- Basic validation functions
- Simple traceroute logic
- Integration with utility functions

#### 2. Error Handling Tests (Project 1B)

```bash
# Navigate to tests directory first
cd tests

# Run all Project 1B error handling tests
python3 run_project_1b_tests.py

# Run with verbose output
python3 run_project_1b_tests.py --verbose

# Run specific test suite
python3 run_project_1b_tests.py --specific test_1b_duplicate_packets

# Show test summary only
python3 run_project_1b_tests.py --summary
```

### Project 1B Test Coverage

The Project 1B test suite covers all major error handling scenarios:

#### Duplicate Packet Handling
- Identical ICMP Time Exceeded packets
- Duplicate packets with different identifiers
- Cross-TTL duplicates (late arriving)
- Same router responding at multiple TTL levels
- Extreme duplicate scenarios

#### Unrelated Packet Filtering
- ICMP Echo Request/Reply packets
- UDP/TCP packets
- ICMP Redirect/Parameter Problem packets
- Invalid ICMP types and codes
- Malformed packets

#### Packet Drop Scenarios
- Some probes dropped, others respond
- All probes dropped for single TTL
- Intermittent drops across TTLs
- High packet loss rates
- Complete packet loss until destination

#### Non-Responsive Routers/Hosts
- Single/multiple non-responsive routers
- Alternating responsive/non-responsive behavior
- Non-responsive destination host
- Firewall-like blocking behavior
- Timeout scenarios

#### Mixed Error Scenarios
- Combinations of duplicates, unrelated packets, and drops
- Network congestion simulation
- Load balancing with mixed errors
- Complex real-world scenarios

### Test Architecture

#### Helper Classes
- **`PacketBuilder`** - Builds various packet types for testing
- **`FakeSendSocket`** - Mocks UDP socket for sending probes
- **`FakeRecvSocket`** - Mocks ICMP socket for receiving responses

#### Test Structure
Each test follows this pattern:
1. **Setup** - Create test packets and mock sockets
2. **Execute** - Run traceroute with specific scenario
3. **Verify** - Check that results match expected behavior

### Expected Behavior

Your traceroute implementation should:

1. **Handle Duplicates**: Record each unique router only once per TTL
2. **Filter Unrelated**: Ignore packets not related to your traceroute probes
3. **Handle Drops**: Continue probing when packets are lost
4. **Skip Non-Responsive**: Continue to next TTL when routers don't respond
5. **Reach Destination**: Stop when destination is reached or max TTL exceeded

## Debugging Failed Tests

### Common Issues and Solutions

#### 1. Import Errors
```
Error: 'function' object has no attribute 'ICMP_TYPE_TIME_EXCEEDED'
```
**Solution**: Ensure you're importing constants correctly from the traceroute module.

#### 2. Mock Path Errors
```
Error: 'function' object has no attribute 'util'
```
**Solution**: Use correct mock paths: `traceroute.util.print_result` not `traceroute.traceroute.util.print_result`

#### 3. Test Failures
If tests fail, check:
- **Packet parsing** - Ensure IPv4/ICMP parsing works correctly
- **Validation** - Check that `is_valid_ip()` and `is_valid_icmp()` work
- **Duplicate handling** - Make sure you're tracking unique routers per TTL
- **Filtering** - Ensure unrelated packets are properly ignored
- **Timeout behavior** - Verify handling of non-responsive routers

### Test Output Interpretation

#### Successful Test Run
```
✓ Loaded test suite: test_1b_duplicate_packets
✓ Loaded test suite: test_1b_unrelated_packets
✓ Loaded test suite: test_1b_packet_drops
✓ Loaded test suite: test_1b_non_responsive
✓ Loaded test suite: test_1b_mixed_scenarios

Running 50+ test cases...
================================================================================
🎉 All tests passed! Your Project 1B implementation handles errors correctly.
```

#### Failed Test Run
```
Tests run: 50
Failures: 5
Errors: 0
Success rate: 90.0%

FAILURES (5):
  • test_duplicate_handling
  • test_packet_drop_recovery
  • test_non_responsive_router
  • test_mixed_error_scenario
  • test_destination_reached

❌ 5 test(s) failed. Review the output above.
```

## Development Workflow

### 1. Implement Basic Functionality (Project 1A)
```bash
# Start with basic tests
python3 -m unittest test_parsing.py

# Implement core traceroute logic
# Test with real destinations
sudo python3 traceroute.py google.com
```

### 2. Add Error Handling (Project 1B)
```bash
# Navigate to tests directory
cd tests

# Run error handling tests
python3 run_project_1b_tests.py

# Fix failing tests one by one
python3 run_project_1b_tests.py --specific test_1b_duplicate_packets

# Verify all tests pass
python3 run_project_1b_tests.py --verbose
```

### 3. Integration Testing
```bash
# Test with real network conditions
sudo python3 traceroute.py cmu.edu
sudo python3 traceroute.py google.com
sudo python3 traceroute.py 8.8.8.8

# Test error scenarios
sudo python3 traceroute.py 192.0.2.1  # RFC 5737 test address
```

## Test Files Reference

### Core Test Files
- `test_parsing.py` - Basic functionality tests
- `test_1b_error_handling.py` - Main comprehensive error handling tests
- `test_1b_duplicate_packets.py` - Detailed duplicate packet scenarios
- `test_1b_unrelated_packets.py` - Unrelated packet filtering tests
- `test_1b_packet_drops.py` - Packet drop scenario tests
- `test_1b_non_responsive.py` - Non-responsive router/host tests
- `test_1b_mixed_scenarios.py` - Complex mixed error scenarios

### Test Runner
- `run_project_1b_tests.py` - Comprehensive test runner with options

## Success Criteria

Your implementation passes all tests when it correctly handles:

✅ **All duplicate packet scenarios**  
✅ **All unrelated packet filtering**  
✅ **All packet drop scenarios**  
✅ **All non-responsive scenarios**  
✅ **All mixed error scenarios**  

**Total: 50+ individual test cases covering comprehensive error handling**

## Getting Help

### Resources
- **Course Website**: https://sp25.cs168.io/proj1/
- **Project 1A Guide**: https://sp25.cs168.io/proj1/proj1a/
- **Project 1B Guide**: https://sp25.cs168.io/proj1/proj1b/
- **Traceroute Guide**: https://sp25.cs168.io/proj1/guide/

### Debugging Tips
1. **Start with basic tests** - Fix `test_parsing.py` first
2. **Use verbose output** - Add `-v` flag to see detailed test results
3. **Test incrementally** - Fix one test suite at a time
4. **Check packet parsing** - Ensure your IPv4/ICMP parsing is correct
5. **Verify constants** - Make sure you're using the right ICMP types and codes

### Common Debugging Commands
```bash
# Navigate to tests directory first
cd tests

# Run specific failing test with verbose output
python3 -m unittest test_1b_duplicate_packets.TestDuplicatePacketCases.test_identical_time_exceeded_packets -v

# Check packet parsing only
python3 -m unittest test_parsing.TestIPv4Parsing -v

# Run all tests with detailed output
python3 run_project_1b_tests.py --verbose
```

## Project Submission

Before submitting:

1. **All tests pass** - Run `python3 run_project_1b_tests.py` and ensure 100% success
2. **Basic functionality works** - Test with real destinations
3. **Error handling works** - Verify robust behavior under various conditions
4. **Code is clean** - No linting errors or unused code

```bash
# Final verification
cd tests
python3 run_project_1b_tests.py
cd ..
sudo python3 traceroute.py cmu.edu
```

Good luck with your traceroute implementation! 🚀