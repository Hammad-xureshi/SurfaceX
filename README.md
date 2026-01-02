     ██████╗██╗   ██╗██████╗ ███████╗ █████╗  ██████╗███████╗    ██╗  ██╗
    ██╔════╝██║   ██║██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝    ╚██╗██╔╝
    ╚█████╗ ██║   ██║██████╔╝█████╗  ███████║██║     █████╗       ╚███╔╝ 
     ╚═══██╗██║   ██║██╔══██╗██╔══╝  ██╔══██║██║     ██╔══╝       ██╔██╗ 
    ██████╔╝╚██████╔╝██║  ██║██║     ██║  ██║╚██████╗███████╗    ██╔╝╚██╗
    ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝     ╚═╝  ╚═╝ ╚═════╝╚══════╝    ╚═╝  ╚═╝

    🛡 SURFACE X - Bash-Driven Recon & Bug Evidence Detection 🛡
     Version: 1.0.0 | Made by: Hammad Naeem | Mode: In-Memory
Bash-Driven Recon & Bug Evidence Detection Orchestrator

[![Made with Bash](https://img.shields.io/badge/Made%20with-Bash-1f425f.svg)](https://www.gnu.org/software/bash/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg)](https://github.com/hammadnaeem/surface-x/graphs/commit-activity)
[![GitHub issues](https://img.shields.io/github/issues/hammadnaeem/surface-x)](https://github.com/hammadnaeem/surface-x/issues)
[![GitHub stars](https://img.shields.io/github/stars/hammadnaeem/surface-x)](https://github.com/hammadnaeem/surface-x/stargazers)

**A professional-grade, terminal-based reconnaissance and vulnerability evidence framework built entirely in Bash.**

[Features](#-features) • [Installation](#-installation) • [Usage](#-usage) • [Modules](#-modules) • [Screenshots](#-screenshots) • [Contributing](#-contributing)

</div>

---

## 🎯 About

**Surface X** is a powerful, all-in-one reconnaissance tool designed for penetration testers, bug bounty hunters, and security researchers. Built primarily in Bash, it leverages native Linux tools to perform comprehensive target analysis without leaving artifacts on disk.

### Why Surface X?

- 🚀 **Fast**: Parallel execution with optimized tool integration
- 🔒 **Stealthy**: In-memory operations, no disk artifacts by default
- 🧠 **Smart**: Built-in knowledge engine from CTFs & bug bounties
- 📊 **Evidence-Based**: Confidence scoring with proof for each finding
- 🔧 **Extensible**: Modular architecture for easy customization

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔍 **Port Discovery** | Fast port scanning using RustScan/Nmap |
| 🌐 **Service Detection** | Detailed service and version fingerprinting |
| 📡 **Subdomain Enumeration** | Passive subdomain discovery (Subfinder, Assetfinder) |
| 🌍 **HTTP Analysis** | Live host detection, header analysis, tech detection |
| 🔐 **SSH/FTP Analysis** | Protocol support detection, banner grabbing, anonymous login check |
| 📂 **Directory Enumeration** | Gobuster integration for path discovery |
| 🐛 **Vulnerability Detection** | Safe Nuclei templates for vuln identification |
| 🧠 **Knowledge Engine** | 60+ patterns from real-world security research |
| 📈 **Risk Scoring** | Automated confidence scoring (LOW/MEDIUM/HIGH) |
| 📋 **Reporting** | Clean terminal reports with optional file export |

---

## 🔧 Installation

### Prerequisites

```bash
# Required
sudo apt install nmap curl

# Recommended (for full functionality)
sudo apt install gobuster wordlists seclists

# Install Go tools (optional but recommended)
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
go install github.com/tomnomnom/assetfinder@latest

# Install RustScan (optional, for faster port scanning)
wget https://github.com/RustScan/RustScan/releases/download/2.0.1/rustscan_2.0.1_amd64.deb
sudo dpkg -i rustscan_2.0.1_amd64.deb


# Clone the repository
git clone https://github.com/hammadnaeem/surface-x.git

# Navigate to directory
cd surface-x

# Make executable
chmod +x surface-x.sh

# Run
./surface-x.sh --help


# Clone and install
git clone https://github.com/hammadnaeem/surface-x.git
cd surface-x
chmod +x surface-x.sh

# Create symlink for global access
sudo ln -s $(pwd)/surface-x.sh /usr/local/bin/surface-x

# Now run from anywhere
surface-x example.com


# Basic domain scan
./surface-x.sh example.com

# Full scan with verbose output and report
./surface-x.sh -v -r example.com

# Scan IP address
./surface-x.sh 192.168.1.1

# Scan URL
./surface-x.sh https://example.com

# Export report to file
./surface-x.sh -r -e report.txt example.com

# HTTP-only analysis (quick)
./surface-x.sh --http-only example.com

# Ports-only scan (fastest)
./surface-x.sh --ports-only 10.10.10.10

# Stealth mode (slower, less detectable)
./surface-x.sh -s example.com

# Skip subdomain enumeration
./surface-x.sh --no-subs example.com

# Skip Nuclei vulnerability scan
./surface-x.sh --no-nuclei example.com

Options
Option	Description
-h, --help	Show help message
-v, --verbose	Enable verbose/debug output
-r, --report	Generate summary report
-e, --export FILE	Export report to file
-j, --jobs N	Parallel jobs (default: 10)
-s, --stealth	Stealth mode (slower, careful)
--no-subs	Skip subdomain enumeration
--no-nuclei	Skip Nuclei vulnerability scan
--ports-only	Only perform port discovery
--http-only	Only perform HTTP analysis


📦 Modules
Core Modules
Module	Tool	Description
Port Discovery	RustScan/Nmap	Fast open port detection
Service Detection	Nmap	Service version fingerprinting
Subdomain Enum	Subfinder/Assetfinder	Passive subdomain discovery
HTTP Analysis	httpx/curl	Live host & header analysis
Vuln Scanning	Nuclei	Safe vulnerability detection
Correlation Engine	Built-in	Multi-signal risk analysis
Extension Modules
Located in extensions/ folder:

Extension	Description
recon_extras.sh	Gobuster directory enum + SSH/FTP analysis
path_discovery.sh	Critical path detection
intelligence.sh	Attack guidance generator
parallel.sh	Parallel execution engine
🧠 Knowledge Engine
Surface X includes a built-in knowledge engine with 60+ patterns from:

Real-world CTF challenges
Bug bounty programs
Security research papers
CVE databases
Pattern Categories
Port/Service Patterns: SSH, FTP, SMB, MySQL, Redis, Docker, etc.
HTTP Header Patterns: Security headers, CORS, debug info
Path Patterns: .git, .env, admin panels, API endpoints
Version Patterns: Known vulnerable software versions
Response Patterns: Error codes, authentication surfaces




👨‍💻 Author
<div align="center">
Hammad Naeem

GitHub

</div>
⭐ Star History
If you find this tool useful, please consider giving it a star! ⭐
