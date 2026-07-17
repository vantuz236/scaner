import re
import time
import requests

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
HEADERS = {"User-Agent": "Universal_Vulnerability_Scanner/3.0"}
DELAY = 1.0


def parse_version(version_str):
    if not version_str:
        return (0, 0, 0)
    # 1.1 (.111?)
    match = re.search(r"(\d+)\.(\d+)(?:\.(\d+))?", version_str)
    if not match:
        return (0, 0, 0)

    try:
        fst = int(match.group(1))
        # отсекаем случаи, когда за 1е число берется год
        if fst > 1990 and fst < 2030:
            return (0, 0, 0)

        sec = int(match.group(2))
        thrd = int(match.group(3)) if match.group(3) else 0
        return (fst, sec, thrd)
    except Exception:
        return (0, 0, 0)

def get_clean(product, version):
    if not product:
        return "", ""

    clean_product = re.sub(r"\b\d+\.\d+(?:\.\d+)?\b.*", "", product).strip()
    full_text = f"{product} {version or ''}".lower()
    match = re.search(r"(\d+\.\d+(?:\.\d+)?)", full_text)
    clean_version = match.group(1) if match else ""

    return clean_version, clean_product


def false_trigger(product, version, summary_lower):
    prod_lower = product.lower()
    target_info = f"{prod_lower} {version.lower() if version else ''}"

    if "ubuntu" in target_info or "debian" in target_info:
        if any(x in summary_lower for x in ["red hat", "rhel", "freebsd", "openbsd", "windows"]) and not any(x in summary_lower for x in ["ubuntu", "debian"]):
            return True


    if "apache" in prod_lower and "tomcat" not in prod_lower:
        if any(x in summary_lower for x in ["tomcat", "coyote", "servlet"]):
            return True
    if "tomcat" in prod_lower and "mod_ssl" in summary_lower:
        return True


    if any(word in summary_lower for word in ["wordpress", "dropbear", "cxf", "solr", "plugin", "httpclient"]):
        return True

    our_ver = parse_version(version)
    if our_ver == (0, 0, 0):
        return False

    match_ver = re.search(r"(?:before|prior to|through|to)\s+(\d+)\.(\d+)", summary_lower)
    if match_ver:
        cve0 = int(match_ver.group(1))
        if 1900 < cve0 < 2100:
            return False
        if cve0 > our_ver[0]:
            return True


    before_match = re.search(r"(?:before|prior to)\s+(\d+\.\d+(?:\.\d+)?)", summary_lower)
    if before_match:
        limit_ver = parse_version(before_match.group(1))
        if limit_ver != (0, 0, 0):
            if limit_ver[0] != our_ver[0] or our_ver >= limit_ver:
                return True

    through_match = re.search(r"(?:through|up to|and)\s+(\d+\.\d+(?:\.\d+)?)", summary_lower)
    if through_match:
        limit_ver = parse_version(through_match.group(1))
        if limit_ver != (0, 0, 0):
            if limit_ver[0] != our_ver[0] or our_ver > limit_ver:
                return True

    range_match = re.search(r"(\d+\.\d+(?:\.\d+)?)\s+(?:through|to|and|up to)\s+(\d+\.\d+(?:\.\d+)?)", summary_lower)
    if range_match:
        start_ver = parse_version(range_match.group(1))
        end_ver = parse_version(range_match.group(2))
        if start_ver != (0, 0, 0) and end_ver != (0, 0, 0):
            if our_ver < start_ver or our_ver > end_ver:
                return True

    return False

def get_cves(product, version):
    if not product or product.lower() == "unknown":
        return []

    clean_version, search_keyword = get_clean(product, version)
    if not clean_version:
        return []

    params = {"keywordSearch": search_keyword, "resultsPerPage": 60}
    try:
        time.sleep(DELAY)
        response = requests.get(NVD_API, params=params, headers=HEADERS, timeout=12)
        if response.status_code != 200:
            return []

        vulnerabilities = response.json().get("vulnerabilities", [])
        matched_cves = []


        version_parts = clean_version.split(".")
        if len(version_parts) >= 2:
            ver_pattern = f"{version_parts[0]}.{version_parts[1]}"
        else:
            ver_pattern = clean_version

        for item in vulnerabilities:
            cve_data = item.get("cve", {})
            cve_id = cve_data.get("id", "CVE-Unknown")

            summary = "No description"
            for d in cve_data.get("descriptions", []):
                if d.get("lang") == "en":
                    summary = d.get("value", "")
                    break

            summary_lower = summary.lower()


            if search_keyword.lower() not in summary_lower:
                continue

            if ver_pattern not in summary_lower:
                if "before" not in summary_lower and "prior to" not in summary_lower and "through" not in summary_lower:
                    continue

            if false_trigger(product, clean_version, summary_lower):
                continue

            cvss = 0.0
            metrics = cve_data.get("metrics", {})
            for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                if key in metrics and metrics[key]:
                    cvss = float(metrics[key][0].get("cvssData", {}).get("baseScore", 0.0))
                    break

            if cvss >= 9.0:
                danger = "CRITICAL"
            elif cvss >= 7.0:
                danger = "HIGH"
            elif cvss >= 4.0:
                danger = "MEDIUM"
            else:
                danger = "LOW" if cvss > 0.0 else "NONE"

            matched_cves.append({
                "id": cve_id,
                "cvss": cvss,
                "danger": danger,
                "summary": summary
            })

        # Сортируем по CVSS (от критических к низким) и берем топ-5 самых опасных
        matched_cves.sort(key=lambda x: x["cvss"], reverse=True)
        return matched_cves[:5]

    except requests.RequestException:
        return []


def analyse(scan_data):
    an_results = {}
    for host, ports in scan_data.items():
        an_results[host] = []
        print(f"[*] Анализ хоста: {host}")
        for port_info in ports:
            new_port_info = port_info.copy()
            product = port_info.get("product")
            version = port_info.get("version", "Unknown")
            print(f"    - Проверка: {product} (v. {version})")

            new_port_info["vulnerabilities"] = get_cves(product, version)
            an_results[host].append(new_port_info)

    return an_results