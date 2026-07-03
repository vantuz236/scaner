import requests
import time

import requests
import time


def get_cves(product, version):
    nproduct = product.lower()

    # Нормализуем версию
    version_digits = "".join([c if c.isdigit() or c == "." else "" for c in version])
    v_parts = version_digits.strip(".").split(".")
    v_main = ".".join(v_parts[:3])  # '6.6.1' или '2.4.7'

    # Для Apache httpd лучше искать по фразе "Apache HTTP Server", чтобы убрать Groovy/Tomcat
    if "apache" in nproduct:
        search_keyword = f"Apache HTTP Server {v_main}"
    else:
        search_keyword = f"{product} {v_main}"

    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={search_keyword}"
    headers = {"User-Agent": "Mozilla/5.0"}

    try:
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code == 200:
            data = response.json()
            vulnerabilities = data.get("vulnerabilities", [])

            matched_cves = []
            for item in vulnerabilities:
                cve_data = item.get("cve", {})
                cve_id = cve_data.get("id", "CVE-Unknown")

                descriptions = cve_data.get("descriptions", [])
                summary = ""
                for desc in descriptions:
                    if desc.get("lang") == "en":
                        summary = desc.get("value", "")
                        break

                summary_lower = summary.lower()

                # --- ЖЕСТКАЯ ФИЛЬТРАЦИЯ ЛОЖНЫХ СРАБАТЫВАНИЙ (Anti-False Positive) ---
                if "apache" in nproduct:
                    # Если ищем веб-сервер, выкидываем Java-мусор
                    if any(x in summary_lower for x in ["groovy", "cxf", "tomcat", "solr", "derby", "struts"]):
                        continue
                if "openssh" in nproduct:
                    # Убеждаемся, что речь про OpenSSH, а не про сторонний софт
                    if "openssh" not in summary_lower:
                        continue
                # -----------------------------------------------------------------

                metrics = cve_data.get("metrics", {})
                cvss = 0.0
                if "cvssMetricV31" in metrics:
                    cvss = metrics["cvssMetricV31"][0].get("cvssData", {}).get("baseScore", 0.0)
                elif "cvssMetricV30" in metrics:
                    cvss = metrics["cvssMetricV30"][0].get("cvssData", {}).get("baseScore", 0.0)
                elif "cvssMetricV2" in metrics:
                    cvss = metrics["cvssMetricV2"][0].get("cvssData", {}).get("baseScore", 0.0)

                cvss = float(cvss)

                danger = "None"
                if cvss >= 9.0:
                    danger = "critical"
                elif 7.0 <= cvss < 9.0:
                    danger = "high"
                elif 4.0 <= cvss < 7.0:
                    danger = "medium"
                elif 0.0 < cvss < 4.0:
                    danger = "low"

                matched_cves.append({
                    "id": cve_id,
                    "cvss": cvss,
                    "danger": danger,
                    "summary": summary[:150] + "..." if summary else "No description available"
                })

            matched_cves.sort(key=lambda x: x["cvss"], reverse=True)
            return matched_cves[:5]
        else:
            return []
    except Exception:
        return []

def analyse(scan_data):
    an_results = {}
    for host, ports in scan_data.items():
        an_results[host] = []

        for port_info in ports:
            new_port_info = port_info.copy()
            product = port_info.get("product")
            version = port_info.get("version")

            print(f"- Проверка на уязвимости: {product} v. {version}")
            cves = get_cves(product, version)
            new_port_info["vulnerabilities"] = cves

            an_results[host].append(new_port_info)

            # NIST API без токена банит, если слать запросы слишком часто.
            # Задержка в 6 секунд необходима по их официальной документации!
            print("  Ждем лимит API NIST (6 сек)...")
            time.sleep(6)

    return an_results


if __name__ == "__main__":
    test_scan_data = {
        '45.33.32.156': [
            {'port': 22, 'product': 'OpenSSH', 'protocol': 'tcp', 'service': 'ssh', 'version': '6.6.1p1'},
            {'port': 80, 'product': 'Apache httpd', 'protocol': 'tcp', 'service': 'http', 'version': '2.4.7'}
        ]
    }

    print("[+] Запускаю анализ уязвимостей по официальной базе NIST NVD...")
    final_report_data = analyse(test_scan_data)

    print("\n[+] Анализ завершен. Финальная структура данных:")
    import pprint

    pprint.pprint(final_report_data)