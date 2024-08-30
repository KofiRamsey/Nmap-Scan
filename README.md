# Nmap Vulnerability Scan

This Python script runs an Nmap scan on a target to identify open ports, associated services, and other relevant network information. It also highlights common vulnerable ports that may require further attention.

## Features

- **Nmap Scan**: Executes a thorough Nmap scan (`-A -p- -T4` options) to detect open ports, services, and more on the target.
- **Port Parsing**: Extracts details such as open ports, services, MAC address, OS details, and network distance.
- **Vulnerable Ports Identification**: Identifies common vulnerable ports that are open on the target and highlights them for further analysis.

## Requirements

- Python 3.x
- Nmap installed on your system

## Installation

1. **Install Python 3**: Ensure Python 3 is installed. You can download it from the [official Python website](https://www.python.org/downloads/).
   
2. **Install Nmap**: Install Nmap on your system. On Linux or macOS, you can install it using your package manager:
   - On Debian/Ubuntu:
     ```bash
     sudo apt-get install nmap
     ```
   - On macOS (using Homebrew):
     ```bash
     brew install nmap
     ```

## Usage

To run the script, use the following command:

```bash
python nmap_scan.py <target>
```

### Example

```bash
python nmap_scan.py 192.168.1.1
```

This command will scan the target `192.168.1.1` and display open ports and services.

## Output

The script will output:

1. **Open Ports**: Lists open ports, their state, associated services, and additional info.
2. **Vulnerable Ports**: Highlights common vulnerable ports that are open on the target.

### Example Output

```bash
Port       State      Service              Info
--------------------------------------------------
22/tcp     open       ssh                  OpenSSH 7.6p1 Ubuntu 4ubuntu0.3
80/tcp     open       http                 Apache httpd 2.4.29 ((Ubuntu))
139/tcp    open       netbios-ssn          

Common Vulnerable Ports to Focus On:
Port       State      Service              Info
--------------------------------------------------
21/tcp     Closed     ftp                  
22/tcp     Open       ssh                  
23/tcp     Closed     telnet               
80/tcp     Open       http                 
445/tcp    Closed     netbios-ssn          
...
```

## Notes

- **Target**: The `<target>` can be an IP address, a hostname, or a network range.
- **Vulnerable Ports**: The script highlights ports commonly associated with vulnerabilities, but you should conduct further analysis to determine the actual risk.
  
## Disclaimer

This script is intended for educational purposes and authorized network testing only. Unauthorized scanning of networks may be illegal in some jurisdictions. Always ensure you have permission before running any scans.
