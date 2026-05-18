#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import os
import urllib.request
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Set, List, Dict, Optional

# ============================================================
# 1. НАСТРОЙКИ
# ============================================================
OUTPUT_DIR = "githubmirror"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Список поддерживаемых протоколов (для валидации строк)
SUPPORTED_PROTOCOLS = ['vless://', 'vmess://', 'trojan://', 'ss://']

# Дополнительная фильтрация по доменным именам (оставить пустым, если не нужно)
# Пример: ALLOWED_DOMAINS = ['example.com', 'myserver.net']  # только эти домены
# Пример: BLOCKED_DOMAINS = ['blocked.com', 'bad.org']       # исключить эти домены
ALLOWED_DOMAINS = []   # если не пустой, то только домены из списка
BLOCKED_DOMAINS = []   # домены, которые нужно исключить

# Источники подписок
SOURCES_CONFIG = [
    {"name": "FILTER-1", "url": "https://gist.githubusercontent.com/flaafix/c79a81037d15163360571c7a7331b153/raw/AetrisVPN.txt"},
    {"name": "FILTER-2", "url": "https://github.com/AvenCores/goida-vpn-configs/raw/refs/heads/main/githubmirror/26.txt"},
    {"name": "FILTER-3", "url": "https://raw.githubusercontent.com/zieng2/wl/main/vless_lite.txt"},
    {"name": "FILTER-4", "url": "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-all.txt"},
    {"name": "FILTER-5", "url": "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt"}
]

# ============================================================
# 2. ФУНКЦИИ ФИЛЬТРАЦИИ
# ============================================================
def is_supported_protocol(line: str) -> bool:
    """Проверяет, начинается ли строка с одного из поддерживаемых протоколов."""
    line = line.strip()
    return any(line.startswith(proto) for proto in SUPPORTED_PROTOCOLS)

def extract_domain_from_uri(uri: str) -> Optional[str]:
    """Извлекает домен из URI (для фильтрации по доменам)."""
    try:
        # Убираем протокол
        for proto in SUPPORTED_PROTOCOLS:
            if uri.startswith(proto):
                uri = uri[len(proto):]
                break
        # Формат: uuid@host:port?params или host:port?params (для ss)
        if '@' in uri:
            host_part = uri.split('@')[-1]
        else:
            host_part = uri
        # Отделяем порт и параметры
        host = host_part.split(':')[0]
        return host
    except Exception:
        return None

def domain_allowed(domain: str) -> bool:
    """Проверяет, разрешён ли домен (если заданы ALLOWED_DOMAINS или BLOCKED_DOMAINS)."""
    if not domain:
        return True
    if ALLOWED_DOMAINS:
        return any(allowed in domain for allowed in ALLOWED_DOMAINS)  # простое вхождение
    if BLOCKED_DOMAINS:
        return not any(blocked in domain for blocked in BLOCKED_DOMAINS)
    return True

def decode_base64_content(content: str) -> str:
    """Пытается декодировать base64, если вся подписка выглядит как base64."""
    content = content.strip()
    # Проверяем, что строка состоит из допустимых символов base64 и не содержит "://"
    if '://' in content:
        return content  # уже plain text
    try:
        decoded = base64.b64decode(content).decode('utf-8', errors='ignore')
        # Если после декодирования появились протоколы, значит успешно
        if any(proto in decoded for proto in SUPPORTED_PROTOCOLS):
            return decoded
    except Exception:
        pass
    return content  # не base64

# ============================================================
# 3. ЗАГРУЗКА И ОБРАБОТКА ПОДПИСОК
# ============================================================
def fetch_url(url: str) -> Optional[str]:
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.read().decode('utf-8', errors='ignore')
    except Exception as e:
        print(f"  Ошибка загрузки {url}: {e}")
        return None

def load_and_filter_source(source: dict) -> Set[str]:
    name = source['name']
    url = source['url']
    print(f"  [{name}] Загрузка {url} ...")
    content = fetch_url(url)
    if not content:
        return set()

    # Пробуем декодировать base64 (если вся подписка закодирована)
    content = decode_base64_content(content)

    valid_uris = set()
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if not is_supported_protocol(line):
            continue
        # Дополнительная фильтрация по домену
        domain = extract_domain_from_uri(line)
        if domain and not domain_allowed(domain):
            continue
        # Базовая проверка на наличие небезопасных параметров (оставляем только clean)
        # Можно удалить, если не нужно – но для чистоты оставим флаг allowInsecure и т.п.
        if 'allowInsecure=1' in line or 'insecure=1' in line or 'security=none' in line:
            continue
        valid_uris.add(line)

    print(f"  [{name}] → {len(valid_uris)} валидных конфигов")
    return valid_uris

# ============================================================
# 4. ОСНОВНОЙ ПРОЦЕСС
# ============================================================
def main():
    print("=== Мультипротокольный фильтр подписок ===")
    # Собираем конфиги из всех источников (параллельно)
    all_configs = {}
    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_source = {executor.submit(load_and_filter_source, src): src for src in SOURCES_CONFIG}
        for future in as_completed(future_to_source):
            src = future_to_source[future]
            try:
                uris = future.result()
                all_configs[src['name']] = uris
            except Exception as e:
                print(f"  [{src['name']}] Ошибка: {e}")
                all_configs[src['name']] = set()

    # Сохраняем отдельные FILTER-*.txt
    for name, uris in all_configs.items():
        out_file = os.path.join(OUTPUT_DIR, f"{name}.txt")
        with open(out_file, 'w', encoding='utf-8') as f:
            if uris:
                f.write('\n'.join(sorted(uris)) + '\n')
        print(f"  Сохранён {name}.txt → {len(uris)} записей")

    # Создаём объединённый ALL.txt (дедупликация по всем источникам)
    all_uris = set()
    for uris in all_configs.values():
        all_uris.update(uris)
    all_file = os.path.join(OUTPUT_DIR, "ALL.txt")
    with open(all_file, 'w', encoding='utf-8') as f:
        if all_uris:
            f.write('\n'.join(sorted(all_uris)) + '\n')
    print(f"\n✅ Создан ALL.txt с {len(all_uris)} уникальными конфигами")

if __name__ == "__main__":
    main()
