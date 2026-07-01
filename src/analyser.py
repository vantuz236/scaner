import requests
import time

def get_cves(product, version):
    url = f"https://cve.circl.lu/api/search/{product.lower()}"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            all_cves = response.json()
            matched_cves = []

            for i in all_cves:
                summary = i.get("summary", "")
                if version in summary:
                    cvss = i.get("cvss")
                    if cvss:
                        cvss = float(cvss)
                    else:
                        cvss = 0.0
                    danger="None"
                    if cvss >= 9.0:
                        danger = "critical"
                    elif 7.0 <= cvss <= 8.9:
                        danger = "high"
                    elif 4.0 <= cvss <= 6.9:
                        danger = "medium"
                    elif 0.1 < cvss < 4.0:
                        danger = "low"

                    matched_cves.append(
                        {
                            "id": i.get("id", "CVE-Unkniwn"),
                            "cvss": cvss,
                            "danger":danger,
                            "sumary": summary[:200] + "..."
                        }
                    )
            return matched_cves
    except Exception:
        return 0


def analyse(scan_data):
    an_results = {}
    for host, ports in scan_data.items():
        an_results[host]= []

        for port_info in ports:
            pass