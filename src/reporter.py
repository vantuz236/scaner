def generate_html_report(scan_data, output_filename="report.html"):
    html_content = """<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>Отчет сканирования ITMO Stars</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; background: #0f172a; color: #cbd5e1; margin: 0; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; }
        h1 { color: #f8fafc; border-bottom: 2px solid #3b82f6; padding-bottom: 10px; font-size: 24px; }
        h2 { color: #3b82f6; font-size: 20px; margin-top: 30px; }
        .host-block { background: #1e293b; margin-bottom: 25px; padding: 20px; border-radius: 8px; border: 1px solid #334155; }
        .service-header { font-size: 16px; font-weight: bold; color: #f1f5f9; background: #334155; padding: 8px 12px; border-radius: 4px; margin-top: 15px; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; table-layout: fixed; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #334155; word-wrap: break-word; vertical-align: top; }
        th { background: #1e293b; color: #94a3b8; font-size: 13px; text-transform: uppercase; }
        .badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 11px; text-transform: uppercase; text-align: center; }
        .danger-critical { background: #7f1d1d; color: #fca5a5; }
        .danger-high { background: #7c2d12; color: #fdba74; }
        .danger-medium { background: #713f12; color: #fde047; }
        .danger-low { background: #14532d; color: #86efac; }
        .danger-none { background: #334155; color: #94a3b8; }
        .no-vulns { color: #4ade80; font-weight: bold; font-size: 14px; margin: 10px 0; }
        .cve-id { font-family: monospace; font-weight: bold; color: #f87171; font-size: 14px; }
        .desc-text { font-size: 13px; line-height: 1.5; color: #e2e8f0; white-space: normal; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Результаты сканирования безопасности</h1>
        <p>Статус: Анализ завершен успешно | Папка: reports/</p>
    """

    for ip, ports in scan_data.items():
        html_content += f"<div class='host-block'><h2>Хост: {ip}</h2>"
        for port_info in ports:
            port = port_info.get('port')
            product = port_info.get('product', 'Unknown')
            version = port_info.get('version', 'Unknown')
            service = port_info.get('service', 'Unknown')
            vulns = port_info.get('vulnerabilities', [])

            html_content += f"<div class='service-header'>Порт {port}/{port_info.get('protocol', 'tcp')} — {service} ({product} {version})</div>"

            if not vulns:
                html_content += "<p class='no-vulns'>[+] Известных уязвимостей в базе NVD не найдено.</p>"
            else:
                html_content += """
                <table>
                    <colgroup>
                        <col style="width: 15%;">
                        <col style="width: 8%;">
                        <col style="width: 12%;">
                        <col style="width: 65%;">
                    </colgroup>
                    <tr>
                        <th>ID Уязвимости</th>
                        <th>CVSS</th>
                        <th>Опасность</th>
                        <th>Полное описание CVE</th>
                    </tr>
                """
                for v in vulns:
                    v_id = v.get('id', 'CVE-Unknown')
                    cvss = v.get('cvss', '0.0')
                    danger = v.get('danger', 'none').lower()
                    summary = v.get('summary', 'Нет описания')

                    html_content += f"""
                    <tr>
                        <td class="cve-id">{v_id}</td>
                        <td style="font-weight: bold; color: #f1f5f9;">{cvss}</td>
                        <td><span class="badge danger-{danger}">{danger}</span></td>
                        <td class="desc-text">{summary}</td>
                    </tr>
                    """
                html_content += "</table>"
        html_content += "</div>"

    html_content += "</div></body></html>"

    with open(output_filename, "w", encoding="utf-8") as f:
        f.write(html_content)