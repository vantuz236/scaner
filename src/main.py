import os
import recon
import analyser
import reporter

def main():
    target = input("? Введите IP адрес или домен для сканирования: ").strip()

    #recon
    print(f"\nШаг 1: Сканирование цели {target}...")
    try:
        scan_data = recon.scan_target(target)
        if not scan_data:
            print("!ERROR: Не удалось собрать данные о портах. Проверь сеть или IP.")
            return
    except Exception as e:
        print(f"!CRITICAL ERROR: {e}")
        return

    #analyse
    print("\nШаг 2: Запуск анализа уязвимостей по базе NIST NVD...")
    try:
        final_report_data = analyser.analyse(scan_data)
    except Exception as e:
        print(f"CRITICAL ERROR: {e}")
        return

    #html generate
    print("\nШаг 3: Генерация финального HTML-отчета...")
    try:
        reports_dir = os.path.join(os.getcwd(), "reports")
        filename_input = input("? Введите имя файла отчета (опционально): ").strip()
        if not filename_input:
            filename_input = "rep_" + target.replace('.', "-")
        output_file = os.path.join(reports_dir, f"{filename_input}.html")
        reporter.generate_html_report(final_report_data, output_filename=output_file)
        print(f"\nГОТОВО! Отчет сохранен как: {os.path.abspath(output_file)}")
    except Exception as e:
        print(f"!CRITICAL ERROR: {e}")
        return


if __name__ == "__main__":
    main()