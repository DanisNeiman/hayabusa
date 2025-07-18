import requests
import socket
import ssl
from datetime import datetime
import os
import traceback
from colorama import Fore, Style, init
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn
from prompt_toolkit import prompt
from prompt_toolkit.history import FileHistory

init(autoreset=True)
console = Console()

# --- Логгирование ---
class Logger:
    def __init__(self, filename):
        self.log_file = open(filename, 'w', encoding='utf-8')

    def write(self, text):
        self.log_file.write(text + "\n")

    def close(self):
        self.log_file.close()

log_filename = f"pentest_log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
logger = Logger(log_filename)

def log_print(*args, **kwargs):
    text = " ".join(str(x) for x in args)
    console.print(*args, **kwargs)
    logger.write(text)

# --- Поддержка функций ---
COMMON_DIRS = [
    "admin", "login", "dashboard", "test", "backup", "tmp",
    "upload", "images", "css", "js", "api", "robots.txt", "sitemap.xml"
]

COMMON_FILES = [
    ".env", "wp-config.php", "config.php", "web.config",
    ".git/config", ".htaccess", "database.php"
]

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "blog", "dev", "test", "portal", "api", "vpn",
    "staging", "support", "remote", "ns1", "ns2", "m", "shop", "webmail"
]

COMMON_PORTS = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    8080: "HTTP Proxy"
}

# --- Проверка URL ---
def check_url(url):
    try:
        response = requests.get(url, timeout=5, allow_redirects=False)
        status_code = response.status_code
        if status_code == 200:
            return {"url": url, "status": status_code, "found": True}
        elif 300 <= status_code < 400:
            redirect_url = response.headers.get('Location', 'Неизвестно')
            return {"url": url, "status": status_code, "redirect": redirect_url}
        else:
            return {"url": url, "status": status_code}
    except Exception as e:
        return {"url": url, "error": True}

# --- Сканер директорий ---
def scan_directories(base_url):
    results = []
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
        task = progress.add_task("[cyan]Сканируем директории...", total=len(COMMON_DIRS))
        for d in COMMON_DIRS:
            result = check_url(f"{base_url}/{d}")
            results.append(result)
            progress.update(task, advance=1)
    return results

# --- Сканер файлов ---
def scan_files(base_url):
    results = []
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
        task = progress.add_task("[cyan]Сканируем файлы...", total=len(COMMON_FILES))
        for f in COMMON_FILES:
            result = check_url(f"{base_url}/{f}")
            results.append(result)
            progress.update(task, advance=1)
    return results

# --- Проверка заголовков безопасности ---
def check_headers(url):
    try:
        response = requests.head(url, timeout=5)
        headers = response.headers

        security_headers = {
            "X-Content-Type-Options": "Рекомендуется: 'nosniff'",
            "X-Frame-Options": "Рекомендуется: 'DENY' или 'SAMEORIGIN'",
            "X-XSS-Protection": "Рекомендуется: '1; mode=block'",
            "Content-Security-Policy": "Отсутствует",
            "Strict-Transport-Security": "Рекомендуется: 'max-age=63072000'"
        }

        table = Table(title="Проверка заголовков безопасности")
        table.add_column("Заголовок", style="cyan")
        table.add_column("Статус", style="green")
        table.add_column("Информация", style="dim")

        for header, info in security_headers.items():
            value = headers.get(header)
            if value:
                table.add_row(header, f"✅ Найдено: {value}", "")
            else:
                table.add_row(header, "❌ Отсутствует", info)

        log_print(table)
        return dict(headers)
    except Exception as e:
        log_print(f"[red][-] Не удалось получить заголовки: {e}[/red]")
        return {}

# --- Информация о SSL-сертификате ---
def get_ssl_info(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                expires = cert.get('notAfter', 'Неизвестно')
                issuer = ", ".join([f"{x[0]}={x[1]}" for x in cert.get('issuer', [])])
                log_print(Panel.fit(
                    f"[green]Издатель:[/green] {issuer}\n[green]Срок действия до:[/green] {expires}",
                    title="SSL-сертификат"))
                return {"issuer": issuer, "expires": expires}
    except Exception as e:
        log_print(f"[red][-] Не удалось получить информацию о SSL: {e}[/red]")
        return {}

# --- Сканер поддоменов ---
def scan_subdomains(domain):
    results = []
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
        task = progress.add_task("[cyan]Проверяем поддомены...", total=len(COMMON_SUBDOMAINS))
        found = False
        for sub in COMMON_SUBDOMAINS:
            full_domain = f"{sub}.{domain}"
            try:
                ip = socket.gethostbyname(full_domain)
                results.append({"domain": full_domain, "ip": ip})
                found = True
            except socket.gaierror:
                pass
            finally:
                progress.update(task, advance=1)

        if found:
            table = Table(title="Найденные поддомены")
            table.add_column("Поддомен", style="cyan")
            table.add_column("IP", style="green")
            for r in results:
                table.add_row(r["domain"], r["ip"])
            log_print(table)
        else:
            log_print("[yellow][-] Поддомены не найдены[/yellow]")

    return results

# --- Сканер портов ---
def scan_ports(domain):
    results = []
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
        task = progress.add_task("[cyan]Проверяем порты...", total=len(COMMON_PORTS))
        found_open = False
        for port, service in COMMON_PORTS.items():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((domain, port))
            sock.close()
            if result == 0:
                results.append({"port": port, "service": service})
                found_open = True
            progress.update(task, advance=1)

        if found_open:
            table = Table(title="Открытые порты")
            table.add_column("Порт", style="cyan")
            table.add_column("Служба", style="green")
            for r in results:
                table.add_row(str(r["port"]), r["service"])
            log_print(table)
        else:
            log_print("[yellow][-] Открытые порты не найдены[/yellow]")

    return results

# --- Вывод результатов ---
def print_results(results, title="Результаты"):
    table = Table(title=title)
    table.add_column("URL", style="cyan")
    table.add_column("Статус", style="green")
    table.add_column("Доп. информация", style="dim")

    for r in results:
        url = r["url"]
        if r.get("found"):
            status = f"✅ {r['status']}"
            extra = ""
        elif r.get("redirect"):
            status = f"🔄 {r['status']}"
            extra = f"→ {r['redirect']}"
        elif r.get("error"):
            status = "❌ Ошибка"
            extra = ""
        else:
            continue
        table.add_row(url, status, extra)

    log_print(table)

# --- Экспорт в TXT ---
def export_to_txt(data, filename):
    with open(filename, 'w', encoding='utf-8') as f:
        for line in data:
            f.write(line + "\n")

# --- Экспорт в JSON ---
def export_to_json(data, filename):
    import json
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4, ensure_ascii=False)

# --- Экспорт в HTML ---
def export_to_html(data, filename):
    html = """
<!DOCTYPE html>
<html lang="ru">
<head><meta charset="UTF-8"><title>PenTest Report</title></head>
<body><pre>{}</pre></body>
</html>
""".format('\n'.join(data))
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(html)

# --- Главная функция ---
def main():
    console.clear()
    log_print(Panel.fit("[bold cyan]🛡️ Hayabusa Web Scanner[/bold cyan]", subtitle="by Danis Neiman"))

    target = prompt("Введите домен для анализа (например, example.com): ",
                    history=FileHistory(os.path.expanduser('~/.pentest_history'))).strip()

    base_url_https = f"https://{target}"
    base_url_http = f"http://{target}"

    log_print(f"\n[bold cyan]Подключение к {target}...[/bold cyan]")

    base_url = None
    try:
        resp = requests.get(base_url_https, timeout=5)
        base_url = base_url_https
        log_print(f"[green][+] Используется HTTPS[/green]")
    except:
        try:
            resp = requests.get(base_url_http, timeout=5)
            base_url = base_url_http
            log_print(f"[yellow][!] Используется HTTP (без шифрования)[/yellow]")
        except:
            log_print(f"[red][-] Сайт недоступен по обоим протоколам[/red]")
            return

    # Проверка заголовков
    log_print("\n[bold blue]🔎 Проверка заголовков безопасности")
    headers_data = check_headers(base_url)

    # Информация о SSL
    ssl_data = {}
    if base_url.startswith("https"):
        log_print("\n[bold blue]🔐 Информация о SSL-сертификате")
        ssl_data = get_ssl_info(target)

    # Поиск директорий
    log_print("\n[bold blue]📁 Поиск распространённых директорий")
    dir_results = scan_directories(base_url)
    print_results(dir_results, "Результаты сканирования директорий")

    # Поиск файлов
    log_print("\n[bold blue]📄 Поиск распространённых файлов")
    file_results = scan_files(base_url)
    print_results(file_results, "Результаты сканирования файлов")

    # Поиск поддоменов
    log_print("\n[bold blue]🌐 Поиск поддоменов")
    sub_results = scan_subdomains(target)

    # Сканирование портов
    log_print("\n[bold blue]📡 Сканирование портов")
    port_results = scan_ports(target)

    # Формируем данные для экспорта
    data = {
        "target": target,
        "headers": headers_data,
        "ssl": ssl_data,
        "directories": dir_results,
        "files": file_results,
        "subdomains": sub_results,
        "ports": port_results
    }

    log_print("\n[bold green]✅ Анализ завершён.[/bold green]")
    log_print(f"[cyan]📄 Лог сохранён в файл: {log_filename}[/cyan]")

    choice = prompt("Сохранить отчёт? (txt/json/html/n): ").strip().lower()
    if choice in ["txt", "json", "html"]:
        export_filename = f"report_{target}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{choice}"
        lines = [line.rstrip('\n') for line in logger.log_file.getvalue().split('\n')]
        
        if choice == "txt":
            export_to_txt(lines, export_filename)
        elif choice == "json":
            export_to_json(data, export_filename)
        elif choice == "html":
            export_to_html(lines, export_filename)

        log_print(f"[cyan]📄 Отчёт сохранён: {export_filename}[/cyan]")

    logger.close()

if __name__ == "__main__":
    main()
