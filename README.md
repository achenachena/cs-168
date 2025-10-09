# CS 168: Introduction to the Internet: Architecture and Protocols

This repository contains project implementations for **CS 168 Spring 2025** at UC Berkeley.

## 📚 Course Overview

CS 168 covers the fundamental principles and design of the Internet, including:
- Network architecture and protocols
- Routing algorithms
- Transport layer protocols
- Network security
- Quality of service

## 🗂️ Projects

### [Project 1: Traceroute](./traceroute/)
Implementation of a traceroute utility that discovers network paths by sending UDP probes with incrementing TTL values.

- **Project 1A**: Basic traceroute functionality
- **Project 1B**: Robust error handling for real-world network conditions

### Project 2: Routing _(Coming Soon)_
Distance-vector and link-state routing protocol implementations.

### Project 3: Transport _(Coming Soon)_
Reliable data transfer protocol implementation.

## 🚀 Quick Start

### Prerequisites
- **Python**: 3.11 or higher
- **Operating System**: Linux, macOS, or WSL (Windows)
- **Privileges**: `sudo` access required for raw socket operations

### Running Traceroute
```bash
cd traceroute
sudo python3 traceroute.py google.com
```

### Running Tests
```bash
cd traceroute/tests
python3 run_project_1b_tests.py
```

## 📖 Documentation

Each project directory contains detailed documentation:
- Implementation guides
- Test suite documentation
- Debugging tips
- Example usage

## 🎓 Academic Integrity

All projects must follow the [CS 168 Collaboration Policy](https://sp25.cs168.io/policies/). Work may be done individually or with one partner (where permitted).

## 📞 Resources

- **Course Website**: https://sp25.cs168.io/
- **Ed Discussion**: Course discussion forum
- **Office Hours**: Check course calendar

## ✨ Current Status

- ✅ **Project 1A**: Completed
- ✅ **Project 1B**: Completed (100% test pass rate)
- ⏳ **Project 2**: Not started
- ⏳ **Project 3**: Not started

---

**Course**: CS 168 - Introduction to the Internet  
**Semester**: Spring 2025  
**Institution**: UC Berkeley
