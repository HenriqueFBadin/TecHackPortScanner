import socket
import sys
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from threading import Lock
import ipaddress

port_results = {}
open_ports = {}
closed_ports = []
filtered_ports = []
lock = Lock()


def generate_chunks(port_range="0-100", N_threads=10):
    port_range = port_range.split("-")
    N_ports = int(port_range[1]) - int(port_range[0])
    chunk_size = max(1, N_ports // N_threads)
    chunks = [
        (i, min(i + chunk_size, N_ports + 1)) for i in range(1, N_ports + 1, chunk_size)
    ]
    return chunks


def scan(ip_address, chunk, ip_type=socket.AF_INET, protocol="tcp"):
    """Escaneia um intervalo de portas TCP ou UDP"""
    proto = socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM

    for port in range(chunk[0], chunk[1]):
        try:
            scan_socket = socket.socket(ip_type, proto)
            scan_socket.settimeout(1)

            if protocol == "tcp":
                result = scan_socket.connect_ex((ip_address, port))
                status = "open" if result == 0 else "closed"

            else:
                try:
                    scan_socket.sendto(b"\x00", (ip_address, port))
                    scan_socket.recvfrom(1024)
                    status = "open"
                except socket.timeout:
                    status = "filtered"
                except socket.error:
                    status = "closed"

            with lock:
                port_results[port] = status

            scan_socket.close()

        except KeyboardInterrupt:
            print("You canceled the operation with Ctrl + C")
            sys.exit()
        except socket.gaierror:
            print("Hostname couldn't be resolved. Exiting...")
            sys.exit()
        except socket.error:
            print("Couldn't connect to the server")
            sys.exit()


def group_ports(ports, status_type):
    grouped = []
    start = None
    prev = None

    for port in sorted(ports):
        if start is None:
            start = port
        elif prev is not None and port != prev + 1:
            grouped.append(
                f"{start}-{prev} - {status_type}"
                if start != prev
                else f"{start} - {status_type}"
            )
            start = port
        prev = port

    if start is not None:
        grouped.append(
            f"{start}-{prev} - {status_type}"
            if start != prev
            else f"{start} - {status_type}"
        )

    return grouped


def group_open_ports(open_ports):
    grouped = []
    current_service = None
    start = None
    prev = None

    for port in sorted(open_ports):
        service = open_ports[port]

        if current_service is None:
            current_service = service
            start = port
        elif service != current_service or port != prev + 1:
            grouped.append(
                f"{start}-{prev} open {current_service}"
                if start != prev
                else f"{start} open {current_service}"
            )
            current_service = service
            start = port

        prev = port

    if start is not None:
        grouped.append(
            f"{start}-{prev} open {current_service}"
            if start != prev
            else f"{start} open {current_service}"
        )

    return grouped


def network_scan(network, port_range, max_threads, protocolType):
    """Escaneia um intervalo de endereços IP e portas"""
    ip_network = ipaddress.ip_network(network, strict=False)
    for ip in ip_network.hosts():
        print(f"\nScanning IP: {ip}")
        port_results.clear()
        open_ports.clear()
        closed_ports.clear()
        filtered_ports.clear()

        chunks = generate_chunks(port_range=port_range, N_threads=max_threads)
        with ThreadPoolExecutor(max_threads) as executor:
            for chunk in chunks:
                executor.submit(scan, str(ip), chunk, socket.AF_INET, protocolType)

        for port, status in port_results.items():
            try:
                service = socket.getservbyport(port, protocolType)
            except:
                service = "Unknown"

            if status == "open":
                open_ports[port] = service
            elif status == "closed":
                closed_ports.append(port)
            else:
                filtered_ports.append(port)

        print("\nScan Results for IP:", ip)
        print("=" * 40)

        grouped_open_ports = group_open_ports(open_ports)
        if grouped_open_ports:
            print("\nOpen Ports:")
            for line in grouped_open_ports:
                print(line)

        if closed_ports:
            print("\nClosed Ports:")
            for line in group_ports(closed_ports, "closed"):
                print(line)

        if filtered_ports:
            print("\nFiltered Ports:")
            for line in group_ports(filtered_ports, "filtered"):
                print(line)


def resolve_host(host):
    """Resolve o nome do host para um endereço IP"""
    try:
        return socket.gethostbyname(host)
    except socket.gaierror:
        print(f"Hostname {host} couldn't be resolved. Exiting...")
        sys.exit()


scan_type = input("Enter scan type (single, network, or website): ").lower()
if scan_type == "single":
    remote_server = input("Enter a remote host to scan: ")
    port_range = input("Enter the port range you want to scan (e.g. 100-200): ")
    max_threads = int(input("Enter the number of threads: "))
    protocolType = input(
        "Enter the type of protocol you want to verify (tcp or udp): "
    ).lower()

    remoteServerIP = socket.getaddrinfo(remote_server, None)[0][4][0]
    ipType = socket.getaddrinfo(remote_server, None)[0][0]

    print("-" * 60)
    print(
        f"Trying to connect to the host: {remoteServerIP} using {protocolType.upper()}"
    )
    print("-" * 60)

    time_init = datetime.now()
    chunks = generate_chunks(port_range=port_range, N_threads=max_threads)

    with ThreadPoolExecutor(max_threads) as executor:
        for chunk in chunks:
            executor.submit(scan, remoteServerIP, chunk, ipType, protocolType)

    time_final = datetime.now()

    for port, status in port_results.items():
        try:
            service = socket.getservbyport(port, protocolType)
        except:
            service = "Unknown"

        if status == "open":
            open_ports[port] = service
        elif status == "closed":
            closed_ports.append(port)
        else:
            filtered_ports.append(port)

    print("\n\nScan Results\n" + "=" * 40)

    grouped_open_ports = group_open_ports(open_ports)
    if grouped_open_ports:
        print("\nOpen Ports:")
        for line in grouped_open_ports:
            print(line)

    if closed_ports:
        print("\nClosed Ports:")
        for line in group_ports(closed_ports, "closed"):
            print(line)

    if filtered_ports:
        print("\nFiltered Ports:")
        for line in group_ports(filtered_ports, "filtered"):
            print(line)

    print("\nScanning completed in:", time_final - time_init)

elif scan_type == "network":
    network = input("Enter the network to scan (e.g. 192.168.1.0/24): ")
    port_range = input("Enter the port range you want to scan (e.g. 100-200): ")
    max_threads = int(input("Enter the number of threads: "))
    protocolType = input(
        "Enter the type of protocol you want to verify (tcp or udp): "
    ).lower()

    time_init = datetime.now()
    network_scan(network, port_range, max_threads, protocolType)
    time_final = datetime.now()

    print("\nNetwork scanning completed in:", time_final - time_init)

elif scan_type == "website":
    website = input("Enter the website URL (e.g. https://noic.com.br): ")
    port_range = input("Enter the port range you want to scan (e.g. 100-200): ")
    max_threads = int(input("Enter the number of threads: "))
    protocolType = input(
        "Enter the type of protocol you want to verify (tcp or udp): "
    ).lower()

    # Extrair o nome do host da URL
    host = website.split("//")[-1].split("/")[0]
    remoteServerIP = resolve_host(host)

    print("-" * 60)
    print(
        f"Trying to connect to the host: {remoteServerIP} using {protocolType.upper()}"
    )
    print("-" * 60)

    time_init = datetime.now()
    chunks = generate_chunks(port_range=port_range, N_threads=max_threads)

    with ThreadPoolExecutor(max_threads) as executor:
        for chunk in chunks:
            executor.submit(scan, remoteServerIP, chunk, socket.AF_INET, protocolType)

    time_final = datetime.now()

    for port, status in port_results.items():
        try:
            service = socket.getservbyport(port, protocolType)
        except:
            service = "Unknown"

        if status == "open":
            open_ports[port] = service
        elif status == "closed":
            closed_ports.append(port)
        else:
            filtered_ports.append(port)

    print("\n\nScan Results\n" + "=" * 40)

    grouped_open_ports = group_open_ports(open_ports)
    if grouped_open_ports:
        print("\nOpen Ports:")
        for line in grouped_open_ports:
            print(line)

    if closed_ports:
        print("\nClosed Ports:")
        for line in group_ports(closed_ports, "closed"):
            print(line)

    if filtered_ports:
        print("\nFiltered Ports:")
        for line in group_ports(filtered_ports, "filtered"):
            print(line)

    print("\nScanning completed in:", time_final - time_init)

else:
    print("Invalid scan type. Please enter 'single', 'network', or 'website'.")
