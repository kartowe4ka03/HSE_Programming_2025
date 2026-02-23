import json
from collections import Counter
from datetime import datetime
import pyshark
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd


def extract_network_artifacts(pcap_path: str) -> dict:
    """
    Анализирует сетевой дамп (PCAP/PCAPNG) и извлекает ключевые артефакты:
    IP-адреса и DNS-запросы.

    Args:
        pcap_path (str): Путь к файлу дампа сети.

    Returns:
        dict: Словарь, содержащий списки IP-адресов и DNS-запросов.
    """
    print(f"[*] Начинаем анализ файла: {pcap_path}")
    
    # Инициализация хранилищ для артефактов
    artifacts = {
        "ip_addresses": [],
        "dns_queries": []
    }
    
    try:
        # Открываем дамп с помощью pyshark
        # keep_packets=False помогает экономить оперативную память
        capture = pyshark.FileCapture(pcap_path, keep_packets=False)
        
        for packet in capture:
            # Извлечение IP-адресов (источник и назначение)
            if hasattr(packet, 'ip'):
                artifacts["ip_addresses"].append(packet.ip.src)
                artifacts["ip_addresses"].append(packet.ip.dst)
                
            # Извлечение DNS-запросов
            if hasattr(packet, 'dns') and hasattr(packet.dns, 'qry_name'):
                dns_info = {
                    "timestamp": packet.sniff_time.isoformat(),
                    "query_name": packet.dns.qry_name
                }
                artifacts["dns_queries"].append(dns_info)
                
        capture.close()
        print("[+] Анализ успешно завершен.")
        
    except FileNotFoundError:
        print(f"[-] Ошибка: Файл {pcap_path} не найден.")
    except Exception as e:
        print(f"[-] Произошла ошибка при обработке дампа: {e}")
        
    return artifacts


def save_results_to_json(data: dict, output_file: str) -> None:
    """
    Сохраняет извлеченные данные в формате JSON.

    Args:
        data (dict): Данные для сохранения.
        output_file (str): Имя выходного файла.
    """
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        print(f"[+] Результаты сохранены в лог: {output_file}")
    except IOError as e:
        print(f"[-] Ошибка при сохранении файла: {e}")


def visualize_dns_queries(dns_queries: list) -> None:
    """
    Создает минимальную визуализацию самых частых DNS-запросов.

    Args:
        dns_queries (list): Список словарей с информацией о DNS-запросах.
    """
    if not dns_queries:
        print("[-] Нет данных о DNS-запросах для визуализации.")
        return

    # Извлекаем только имена доменов
    domain_names = [query["query_name"] for query in dns_queries]
    
    # Считаем частоту запросов
    domain_counts = Counter(domain_names)
    
    # Берем топ-10 самых частых доменов для графика
    top_domains = dict(domain_counts.most_common(10))
    
    if not top_domains:
        return

    # Подготавливаем данные для Seaborn/Matplotlib
    df = pd.DataFrame(list(top_domains.items()), columns=['Домен', 'Количество запросов'])
    
    # Настройка стиля графика
    sns.set_theme(style="whitegrid")
    plt.figure(figsize=(10, 6))
    
    # Построение столбчатой диаграммы
    ax = sns.barplot(x='Количество запросов', y='Домен', data=df, palette='viridis')
    ax.set_title('Топ-10 запрашиваемых DNS доменов', fontsize=16)
    ax.set_xlabel('Количество', fontsize=12)
    ax.set_ylabel('Доменное имя', fontsize=12)
    
    plt.tight_layout()
    
    # Сохраняем график как картинку
    plt.savefig('dns_visualization.png')
    print("[+] График DNS-запросов сохранен как 'dns_visualization.png'.")
    
    # Отображаем график на экране
    plt.show()


def main():
    """
    Главная функция для запуска скрипта.
    """
    # Путь к файлу дампа (замените на нужный, если отличается)
    pcap_file = 'dynDNS_winupdatedurchServer.pcap'
    output_json = 'forensics_report.json'
    
    # Этап 2: Извлечение артефактов
    artifacts = extract_network_artifacts(pcap_file)
    
    # Этап 3: Создание лога (сохранение в JSON)
    save_results_to_json(artifacts, output_json)
    
    # Этап 3: Визуализация результатов
    visualize_dns_queries(artifacts["dns_queries"])


if __name__ == '__main__':
    main()