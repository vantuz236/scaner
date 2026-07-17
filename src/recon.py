import nmap


def scan_target(target):
    try:
        nm = nmap.PortScanner()
    except Exception:
        print("-Критическая ошибка. Убедитесь, что в системе установлен Nmap в PATH")
        return {}
    try:
        nm.scan(hosts=target, ports="22,80,443,8080", arguments="-sV -Pn --open")
        parsed_res = {}

        for host in nm.all_hosts():
            parsed_res[host] = []
            for proto in nm[host].all_protocols():
                for port in nm[host][proto]:
                    port_data = nm[host][proto][port]
                    service_info = {
                        "port": port,
                        "protocol": proto,
                        "service": port_data.get("name", ""),
                        "product": port_data.get("product", ""),
                        "version": port_data.get("version", "")
                    }
                    parsed_res[host].append(service_info)
        if parsed_res and any(parsed_res.values()):
            return parsed_res

    except Exception:
        pass