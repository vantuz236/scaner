import os
# Импортируем твои модули. Убедись, что файлы называются именно так
import recon
import analyser
import reporter

def main():
    print("=" * 50)
    print("[*] СКАНЕР УЯЗВИМОСТЕЙ ДЛЯ ITMO STARS ЗАПУЩЕН")
    print("=" * 50)

    # 1. Запрос цели у пользователя
    target = input("[?] Введи IP-адрес или домен для сканирования: ").strip()
    if not target:
        print("[-] Ошибка: цель не введена. Выход.")
        return

    # 2. Этап Recon (Сбор данных)
    print(f"\n[*] Шаг 1: Сканирование цели {target}...")
    try:
        scan_data = recon.scan_target(target)
        if not scan_data:
            print("[-] Не удалось собрать данные о портах. Проверь сеть или IP.")
            return
    except Exception as e:
        print(f"[-] Критическая ошибка на этапе сканирования: {e}")
        return

    # 3. Этап Анализа (Поиск CVE)
    print("\n[*] Шаг 2: Запуск анализа уязвимостей по базе NIST NVD...")
    try:
        final_report_data = analyser.analyse(scan_data)
    except Exception as e:
        print(f"[-] Критическая ошибка на этапе анализа CVE: {e}")
        return

    # 4. Этап Генерации отчета (HTML)
    print("\n[*] Шаг 3: Генерация финального HTML-отчета...")
    try:
        output_file = "final_report.html"
        reporter.generate_html_report(final_report_data, output_filename=output_file)
        print(f"\n[+] ГОТОВО! Отчет сохранен как: {os.path.abspath(output_file)}")
    except Exception as e:
        print(f"[-] Критическая ошибка при сборке HTML-отчета: {e}")
        return

    print("=" * 50)
    print("[+] Прогон успешно завершен. Проект работает.")
    print("=" * 50)

if __name__ == "__main__":
    main()