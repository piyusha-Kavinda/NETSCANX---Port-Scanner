import socket
import csv
import os

from concurrent.futures import ThreadPoolExecutor, as_completed




COMMON_SERVICES = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    111: "RPC",
    119: "NNTP",
    123: "NTP",
    135: "MS-RPC",
    137: "NetBIOS",
    138: "NetBIOS",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP",
    631: "IPP",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1433: "MS-SQL",
    1521: "Oracle",
    2049: "NFS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
}




def get_service_name(port):
    """
    Get a service name for the given TCP port.
    """

   
    if port in COMMON_SERVICES:
        return COMMON_SERVICES[port]

    try:
        return socket.getservbyport(
            port,
            "tcp"
        ).upper()

    except OSError:
        return "Unknown"




def scan_port(
    target_ip,
    port,
    timeout=0.5
):
    """
    Scan one TCP port.

    Returns:
        (port, service) if the port is open
        None if the port is closed/unavailable
    """

    sock = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    sock.settimeout(timeout)

    try:

        result = sock.connect_ex(
            (
                target_ip,
                port
            )
        )

        if result == 0:

            service = get_service_name(
                port
            )

            return (
                port,
                service
            )

        return None

    except (
        socket.timeout,
        socket.error
    ):

        return None

    finally:

        sock.close()




def scan_target(
    target,
    start_port,
    end_port,
    progress_callback=None,
    stop_event=None
):
    """
    Scan a target over a range of TCP ports.

    Parameters:
        target:
            IP address or hostname.

        start_port:
            First port.

        end_port:
            Last port.

        progress_callback:
            Function that receives progress percentage.

        stop_event:
            threading.Event used to stop the scan.

    Returns:
        List of dictionaries.
    """


    try:

        target_ip = socket.gethostbyname(
            target
        )

    except socket.gaierror:

        raise ValueError(
            "Invalid target. "
            "Please enter a valid IP address or hostname."
        )



    open_ports = []


    total_ports = (
        end_port
        -
        start_port
        +
        1
    )

    completed_ports = 0



    with ThreadPoolExecutor(
        max_workers=50
    ) as executor:

        futures = {}



        for port in range(
            start_port,
            end_port + 1
        ):

            if (
                stop_event
                and
                stop_event.is_set()
            ):
                break

            future = executor.submit(
                scan_port,
                target_ip,
                port
            )

            futures[future] = port



        for future in as_completed(
            futures
        ):

           
            if (
                stop_event
                and
                stop_event.is_set()
            ):

               
                for pending_future in futures:

                    if not pending_future.done():

                        pending_future.cancel()

                break

            try:

                result = future.result()

                if result is not None:

                    port, service = result

                    open_ports.append(
                        {
                            "port": port,
                            "service": service,
                            "status": "OPEN"
                        }
                    )

            except Exception:
                pass

           
            completed_ports += 1

           
            progress = int(
                (
                    completed_ports
                    /
                    total_ports
                )
                *
                100
            )

         
            if progress_callback:

                progress_callback(
                    progress
                )



    open_ports.sort(
        key=lambda item: item["port"]
    )

    return open_ports



def save_txt_report(
    filename,
    target,
    start_port,
    end_port,
    open_ports,
    duration=None
):
    """
    Save scan results as a TXT file.
    """

    directory = os.path.dirname(
        filename
    )

    if directory:

        os.makedirs(
            directory,
            exist_ok=True
        )


    with open(
        filename,
        "w",
        encoding="utf-8"
    ) as file:

        file.write(
            "=" * 65 + "\n"
        )

        file.write(
            "                    NETSCANX REPORT\n"
        )

        file.write(
            "=" * 65 + "\n\n"
        )

        file.write(
            f"Target        : {target}\n"
        )

        file.write(
            f"Port Range    : "
            f"{start_port}-{end_port}\n"
        )

        file.write(
            f"Open Ports    : "
            f"{len(open_ports)}\n"
        )

        if duration is not None:

            file.write(
                f"Scan Duration : "
                f"{duration:.2f} seconds\n"
            )

        file.write("\n")

        file.write(
            "-" * 65 + "\n"
        )

        file.write(
            f"{'PORT':<12}"
            f"{'SERVICE':<25}"
            f"{'STATUS':<12}\n"
        )

        file.write(
            "-" * 65 + "\n"
        )


        for item in open_ports:

            file.write(
                f"{item['port']:<12}"
                f"{item['service']:<25}"
                f"{item['status']:<12}\n"
            )

        file.write(
            "-" * 65 + "\n"
        )

        if not open_ports:

            file.write(
                "No open ports were found.\n"
            )

        file.write("\n")

        file.write(
            "Generated by NetScanX\n"
        )




def save_csv_report(
    filename,
    target,
    start_port,
    end_port,
    open_ports
):
    """
    Save scan results as CSV.
    """

   
    directory = os.path.dirname(
        filename
    )

    if directory:

        os.makedirs(
            directory,
            exist_ok=True
        )

    with open(
        filename,
        "w",
        newline="",
        encoding="utf-8"
    ) as file:

        writer = csv.writer(
            file
        )

        
        writer.writerow(
            ["NetScanX Scan Report"]
        )

        writer.writerow(
            [
                "Target",
                target
            ]
        )

        writer.writerow(
            [
                "Port Range",
                f"{start_port}-{end_port}"
            ]
        )

        writer.writerow([])

  
        writer.writerow(
            [
                "PORT",
                "SERVICE",
                "STATUS"
            ]
        )

       
        for item in open_ports:

            writer.writerow(
                [
                    item["port"],
                    item["service"],
                    item["status"]
                ]
            )




def parse_port_range(
    port_range
):
    """
    Convert a string such as:

        1-1000

    into:

        1, 1000
    """

    try:

        parts = port_range.split("-")

        if len(parts) != 2:

            raise ValueError

        start_port = int(
            parts[0].strip()
        )

        end_port = int(
            parts[1].strip()
        )

    except ValueError:

        raise ValueError(
            "Invalid port range. "
            "Use format: 1-1000"
        )

 
    if not (
        1 <= start_port <= 65535
        and
        1 <= end_port <= 65535
    ):

        raise ValueError(
            "Ports must be between "
            "1 and 65535."
        )

  
    if start_port > end_port:

        raise ValueError(
            "Starting port must be "
            "smaller than the ending port."
        )

    return (
        start_port,
        end_port
    )




def main():

    parser = __import__(
        "argparse"
    ).ArgumentParser(
        description="NetScanX - Network Port Scanner"
    )

    parser.add_argument(
        "target",
        help="Target IP address or hostname"
    )

    parser.add_argument(
        "-p",
        "--ports",
        default="1-100",
        help="Port range. Example: 1-1000"
    )

    args = parser.parse_args()



    try:

        start_port, end_port = parse_port_range(
            args.ports
        )

    except ValueError as error:

        print(
            f"Error: {error}"
        )

        return



    try:

        target_ip = socket.gethostbyname(
            args.target
        )

    except socket.gaierror:

        print(
            "Error: Invalid target."
        )

        return



    print()
    print(
        "=" * 55
    )

    print(
        "                    NETSCANX"
    )

    print(
        "              Network Port Scanner"
    )

    print(
        "=" * 55
    )

    print(
        f"Target : {args.target}"
    )

    print(
        f"IP     : {target_ip}"
    )

    print(
        f"Ports  : {start_port}-{end_port}"
    )

    print(
        "=" * 55
    )

    print(
        "\nScanning...\n"
    )



    def show_progress(
        progress
    ):

        print(
            f"\rProgress: {progress}%",
            end="",
            flush=True
        )



    open_ports = scan_target(
        args.target,
        start_port,
        end_port,
        progress_callback=show_progress
    )

    print("\n")



    print(
        f"{'PORT':<12}"
        f"{'SERVICE':<25}"
        f"{'STATUS':<10}"
    )

    print(
        "-" * 47
    )

    for item in open_ports:

        print(
            f"{item['port']:<12}"
            f"{item['service']:<25}"
            f"{item['status']:<10}"
        )

    print()

    print(
        f"Open ports: "
        f"{len(open_ports)}"
    )

    print(
        "\nScan completed."
    )




if __name__ == "__main__":

    main()
