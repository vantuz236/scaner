from nmap import *
import pprint
def scan_target(target):
    nm = PortScanner()
    ports = "22,80,443,8080"
    nm.scan(hosts=target, ports=ports, arguments="-sV")
    parsed_res = {}

    for host in nm.all_hosts():
        parsed_res[host] = []

        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for port in lport:
                port_data = nm[host][proto][port]
                if port_data["state"] == "open":
                    product = port_data.get("product", "")
                    version = port_data.get("version", "")
                    service = port_data.get("name", "")
                    service_info = {
                        "port": port,
                        "protocol": proto,
                        "service": service,
                        "product": product,
                        "version": version

                    }
                    parsed_res[host].append(service_info)
    return parsed_res


if __name__ == "__main__":
    test_host = "scanme.nmap.org"
    scan_data = scan_target(test_host)
    pprint.pprint(scan_data)