#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import os
import socket
import urllib.parse
import urllib.request
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Set, Tuple, Optional

# ============================================================
# 1. НАСТРОЙКИ И ИСТОЧНИКИ
# ============================================================
OUTPUT_DIR = "githubmirror"
os.makedirs(OUTPUT_DIR, exist_ok=True)

SOURCES_CONFIG = [
    {
        "name": "FILTER-1",
        "url": "https://gist.githubusercontent.com/flaafix/c79a81037d15163360571c7a7331b153/raw/AetrisVPN.txt"
    },
    {
        "name": "FILTER-2",
        "url": "https://github.com/AvenCores/goida-vpn-configs/raw/refs/heads/main/githubmirror/26.txt"
    },
    {
        "name": "FILTER-3",
        "url": "https://raw.githubusercontent.com/zieng2/wl/main/vless_lite.txt"
    },
    {
        "name": "FILTER-4",
        "url": "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-all.txt"
    },
    {
        "name": "FILTER-5",
        "url": "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt"
    }
    # Добавляй новые источники сюда по образцу
]

# ============================================================
# 2. ФИЛЬТРЫ НЕБЕЗОПАСНЫХ ПАРАМЕТРОВ
# ============================================================
UNSAFE_PATTERNS = [
    r'[&?]allowinsecure=1', r'[&?]allowinsecure=true',
    r'[&?]insecure=1', r'[&?]insecure=true',
    r'[&?]security=none',
    r'[&?]verify=0', r'[&?]verify=false',
    r'[&?]skip-cert-verify=0', r'[&?]skip-cert-verify=false',
    r'[&?]encryption=none',
    r'[&?]allowinsecurecipher=1', r'[&?]allowinsecurecipher=true',
    r'[&?]flow=none',
    r'[&?]tls13=0', r'[&?]tls13=false',
]
UNSAFE_REGEX = re.compile('|'.join(UNSAFE_PATTERNS), re.IGNORECASE)

def has_insecure_params(url: str) -> bool:
    return bool(UNSAFE_REGEX.search(url))

def is_safe_uri(uri: str) -> bool:
    line = uri.strip()
    if not line:
        return False
    if not (line.startswith('vless://') or line.startswith('trojan://')):
        return False
    if has_insecure_params(line):
        return False
    if line.startswith('trojan://'):
        return 'sni=' in line
    if line.startswith('vless://'):
        if re.search(r'security=reality|pbk=|flow=xtls-rprx-vision', line, re.I):
            return True
        if 'security=tls' in line and 'encryption=none' in line:
            return 'sni=' in line or 'alpn=' in line
        return False
    return False

# ============================================================
# 3. ЗАГРУЗКА ИСТОЧНИКОВ
# ============================================================
def fetch_url(url: str) -> Optional[str]:
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.read().decode('utf-8', errors='ignore')
    except Exception as e:
        print(f"  Ошибка загрузки {url}: {e}")
        return None

def load_from_source(source: dict) -> Set[str]:
    name = source['name']
    print(f"  [{name}] Загрузка...")
    content = fetch_url(source['url'])
    if not content:
        return set()
    uris = set()
    for line in content.splitlines():
        uri = line.strip()
        if uri and not uri.startswith('#'):
            if is_safe_uri(uri):
                uris.add(uri)
    return uris

# ============================================================
# 4. TCP-ПИНГ И ФОРМАТИРОВАНИЕ ИМЁН
# ============================================================
def extract_host_port(uri: str) -> Tuple[Optional[str], Optional[int], Optional[str]]:
    try:
        parsed = urllib.parse.urlparse(uri)
        host_port = parsed.netloc.split('@')[-1]
        if ':' in host_port:
            host, port_str = host_port.split(':', 1)
            port = int(port_str.split('?')[0].split('#')[0])
        else:
            host = host_port
            port = 443
        name = ''
        if '#' in uri:
            name = urllib.parse.unquote(uri.split('#')[-1])
        return host, port, name
    except Exception:
        return None, None, None

def test_tcp_latency(host: str, port: int, timeout: float = 3.0) -> Optional[float]:
    try:
        start = datetime.now()
        with socket.create_connection((host, port), timeout=timeout):
            return (datetime.now() - start).total_seconds() * 1000
    except Exception:
        return None

def check_uri(uri: str) -> Tuple[Optional[float], str]:
    host, port, original_name = extract_host_port(uri)
    if not host or not port:
        return None, uri
    latency = test_tcp_latency(host, port, timeout=3)
    if latency is None:
        new_name = f"[dead] {original_name}" if original_name else "[dead] unknown"
    else:
        new_name = f"[{int(latency)}ms] {original_name}" if original_name else f"[{int(latency)}ms]"
    if '#' in uri:
        base = uri.split('#')[0]
        new_uri = f"{base}#{urllib.parse.quote(new_name)}"
    else:
        new_uri = f"{uri}#{urllib.parse.quote(new_name)}"
    return latency, new_uri

# ============================================================
# 5. ОСНОВНАЯ ЛОГИКА
# ============================================================
def main():
    print("=== Фильтрация и проверка задержки прокси (TCP ping) ===")
    start_total = datetime.now()

    # --- Шаг 1: сбор всех безопасных URI из всех источников ---
    all_safe = set()
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(load_from_source, src): src for src in SOURCES_CONFIG}
        for future in as_completed(futures):
            src = futures[future]
            try:
                uris = future.result()
                all_safe.update(uris)
                print(f"  [{src['name']}] → {len(uris)} безопасных URI")
            except Exception as e:
                print(f"  [{src['name']}] Ошибка: {e}")

    print(f"\nВсего собрано безопасных URI: {len(all_safe)}")

    # --- Шаг 2: проверка задержки ---
    print("\n=== Проверка задержки (TCP ping, таймаут 3 с) ===")
    results = []  # (latency, updated_uri)
    with ThreadPoolExecutor(max_workers=20) as executor:
        future_to_uri = {executor.submit(check_uri, uri): uri for uri in all_safe}
        for future in as_completed(future_to_uri):
            latency, updated_uri = future.result()
            if latency is not None:
                results.append((latency, updated_uri))
            if len(results) % 20 == 0:
                print(f"  Прогресс: {len(results)} живых / {len(all_safe)} проверено")

    results.sort(key=lambda x: x[0])  # сортировка по возрастанию пинга
    print(f"\nЖивых прокси: {len(results)}")

    # --- Шаг 3: сохранение индивидуальных FILTER-*.txt ---
    for src in SOURCES_CONFIG:
        uris = load_from_source(src)   # повторная загрузка, но кеш не сохранялся
        out_file = os.path.join(OUTPUT_DIR, f"{src['name']}.txt")
        with open(out_file, 'w', encoding='utf-8', newline='\n') as f:
            f.write('\n'.join(sorted(uris)))
            if uris:
                f.write('\n')
        print(f"  Сохранён {src['name']}.txt → {len(uris)} записей")

    # --- Шаг 4: сохранение FAST-server.txt (только живые, отсортированные) ---
    fast_file = os.path.join(OUTPUT_DIR, "FAST-server.txt")
    with open(fast_file, 'w', encoding='utf-8', newline='\n') as f:
        for _, uri in results:
            f.write(uri + '\n')
    print(f"\nСоздан FAST-server.txt с {len(results)} живыми прокси (отсортировано по пингу)")

    elapsed = (datetime.now() - start_total).total_seconds()
    print(f"\n✅ Полный цикл завершён за {elapsed:.2f} сек.")

if __name__ == "__main__":
    main()
