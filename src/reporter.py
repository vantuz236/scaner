import os


def generate_html_report(scan_data, output_filename="report.html"):
    """
    Берет словарь с результатами сканирования и генерирует красивый HTML-отчет.
    """
    html_content = """
    <!DOCTYPE html>
    <html lang="ru">
    <head>
        <meta charset="UTF-8">
        <title>Отчет о сканировании уязвимостей</title>
        <style>
            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f6f9; color: #333; margin: 0; padding: 20px; }
            .container { max-width: 1000px; margin: 0 auto; background: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
            h1 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
            h2 { color: #2980b9; margin-top: 30px; }
            .host-block { margin-bottom: 40px; padding: 20px; border: 1px solid #e0e0e0; border-radius: 6px; background: #fafafa; }
            table { width: 100%; border-collapse: collapse; margin-top: 15px; background: #fff; }
            th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
            th { background-color: #34495e; color: #fff; }
            .badge { padding: 5px 10px; border-radius: 4px; font-weight: bold; font-size: 12px; text-transform: uppercase; }
            .danger-high { background-color: #e74c3c; color: white; }
            .danger-medium { background-color: #f39c12; color: white; }
            .danger-low { background-color: #f1c40f; color: black; }
            .no-vulns { color: #27ae60; font-weight: bold; }
            .cve-id { font-family: monospace; font-weight: bold; color: #c0392b; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Результаты сканирования безопасности</h1>
            <p><strong>Статус:</strong> Анализ завершен успешно</p>
    """

    # Итерируемся по хостам (IP адресам)
    for ip, ports in scan_data.items():
        html_content += f"""
        <div class="host-block">
            <h2>Хост: {ip}</h2>
        """

        for port_info in ports:
            port = port_info.get('port')
            product = port_info.get('product', 'Unknown')
            version = port_info.get('version', 'Unknown')
            service = port_info.get('service', 'Unknown')
            vulns = port_info.get('vulnerabilities', [])

            html_content += f"""
            <h3>Порт {port} ({service}) — {product} {version}</h3>
            """

            if not vulns:
                html_content += "<p class='no-vulns'>[+] Известных уязвимостей не найдено.</p>"
            else:
                html_content += """
                <table>
                    <tr>
                        <th style="width: 15%;">ID Уязвимости</th>
                        <th style="width: 10%;">CVSS</th>
                        <th style="width: 15%;">Критичность</th>
                        <th style="width: 60%;">Описание</th>
                    </tr>
                """
                for v in vulns:
                    v_id = v.get('id', 'CVE-Unknown')
                    cvss = v.get('cvss', 'N/A')
                    danger = v.get('danger', 'low').lower()
                    summary = v.get('summary', 'Нет описания')

                    # Присваиваем класс для подсветки
                    badge_class = f"badge danger-{danger}"

                    html_content += f"""
                    <tr>
                        <td class="cve-id">{v_id}</td>
                        <td>{cvss}</td>
                        <td><span class="{badge_class}">{danger}</span></td>
                        <td>{summary}</td>
                    </tr>
                    """
                html_content += "</table>"

        html_content += "</div>"

    html_content += """
        </div>
    </body>
    </html>
    """

    # Записываем всё это добро в файл
    with open(output_filename, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"[+] Красивый отчёт сгенерирован: {os.path.abspath(output_filename)}")


# Тестовый запуск (чисто проверить, как работает с твоими данными)
if __name__ == "__main__":
    test_data = {'45.33.32.156': [
        {'port': 22, 'product': 'OpenSSH', 'protocol': 'tcp', 'service': 'ssh', 'version': '6.6.1p1',
         'vulnerabilities': []},
        {'port': 80, 'product': 'Apache httpd', 'protocol': 'tcp', 'service': 'http', 'version': '2.4.7',
         'vulnerabilities': [{'cvss': 8.2, 'danger': 'high', 'id': 'CVE-2021-44224',
                              'summary': 'A crafted URI sent to httpd configured as a forward proxy can cause a crash...'},
                             {'cvss': 5.4, 'danger': 'medium', 'id': 'CVE-2025-66200',
                              'summary': 'mod_userdir+suexec bypass via AllowOverride FileInfo vulnerability in Apache HTTP Server.'}]}]}
    generate_html_report(test_data)