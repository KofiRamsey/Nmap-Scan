#!/usr/bin/env python3

import subprocess
import sys
import re

# Common vulnerable ports and their services
COMMON_VULNERABLE_PORTS = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "domain",
    80: "http",
    111: "rpcbind",
    139: "netbios-ssn",
    445: "netbios-ssn",
    512: "exec",
    513: "login",
    514: "tcpwrapped",
    1099: "java-rmi",
    1524: "bindshell",
    2049: "nfs",
    2121: "ftp",
    3306: "mysql",
    3632: "distccd",
    5432: "postgresql",
    5900: "vnc",
    6000: "X11",
    6667: "irc",
    6697: "irc",
    8009: "ajp13",
    8180: "http",
    8787: "drb",
    33936: "java-rmi",
    44543: "status",
    51988: "mountd",
    54024: "nlockmgr",
}

def run_nmap(target):
    try:
        # Run the nmap command with -A, -p-, and -T4 options
        result = subprocess.run(
            ['nmap', '-A', '-p-', '-T4', target],
            capture_output=True,
            text=True
        )

        # Check if the nmap command was successful
        if result.returncode == 0:
            return result.stdout
        else:
            return f"Error: {result.stderr}"
    except Exception as e:
        return f"Exception occurred: {str(e)}"

def parse_nmap_output(output):
    parsed_info = []
    lines = output.split('\n')

    # Pattern to match open ports and services
    port_pattern = re.compile(r'(\d+/tcp|(\d+/udp))\s+(\w+)\s+(.+)')
    
    for line in lines:
        # Extract information related to open ports
        match = port_pattern.match(line)
        if match:
            port = match.group(1)
            state = match.group(3)
            service = match.group(4).split(' ')[0]  # Get service name
            info = ' '.join(match.group(4).split(' ')[1:])  # Get additional info
            parsed_info.append({
                'Port': port,
                'State': state,
                'Service': service,
                'Info': info
            })

        # Extract MAC Address
        if line.startswith('MAC Address'):
            mac_address = line.split(':', 1)[1].strip()
            parsed_info.append({'MAC Address': mac_address})

        # Extract Device Type
        if line.startswith('Device type'):
            device_type = line.split(':', 1)[1].strip()
            parsed_info.append({'Device Type': device_type})

        # Extract OS Details
        if line.startswith('Running'):
            os_details = line.split(':', 1)[1].strip()
            parsed_info.append({'OS Details': os_details})

        # Extract OS CPE
        if line.startswith('OS CPE'):
            os_cpe = line.split(':', 1)[1].strip()
            parsed_info.append({'OS CPE': os_cpe})

        # Extract Network Distance
        if line.startswith('Network Distance'):
            network_distance = line.split(':', 1)[1].strip()
            parsed_info.append({'Network Distance': network_distance})

        # Extract Service Info
        if line.startswith('Service Info'):
            service_info = line.split(':', 1)[1].strip()
            parsed_info.append({'Service Info': service_info})

    return parsed_info

def print_results(results):
    print(f"{'Port':<10} {'State':<10} {'Service':<20} {'Info'}")
    print('-' * 50)
    for result in results:
        if 'Port' in result and 'State' in result:
            print(f"{result['Port']:<10} {result['State']:<10} {result['Service']:<20} {result['Info']}")

def print_vulnerable_ports(results):
    open_ports = {int(result['Port'].split('/')[0]) for result in results if 'Port' in result and 'open' in result['State']}
    print("\nCommon Vulnerable Ports to Focus On:")
    print(f"{'Port':<10} {'State':<10} {'Service':<20} {'Info'}")
    print('-' * 50)
    for port, service in COMMON_VULNERABLE_PORTS.items():
        status = "Open" if port in open_ports else "Closed"
        info = "N/A" if status == "Closed" else "Common Service"
        print(f"{port:<10}/tcp {status:<10} {service:<20} ")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python nmap.py <target>")
        sys.exit(1)

    target = sys.argv[1]

    # Run nmap scan
    nmap_output = run_nmap(target)

    if "Error" in nmap_output or "Exception occurred" in nmap_output:
        print(nmap_output)
    else:
        # Parse and print the nmap scan results
        parsed_results = parse_nmap_output(nmap_output)
        print_results(parsed_results)
        print_vulnerable_ports(parsed_results)
