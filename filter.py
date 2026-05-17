#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import urllib.request
import urllib.parse
import os

# Папка, куда будем сохранять файлы
OUTPUT_DIR = "githubmirror"

# Создаём папку, если её нет
os.makedirs(OUTPUT_DIR, exist_ok=True)

# === ИСТОЧНИКИ: КЛЮЧ = ИМЯ ФАЙЛА (внутри OUTPUT_DIR) ===
SOURCES = {
    "FILTER-1.txt": "https://gist.githubusercontent.com/flaafix/c79a81037d15163360571c7a7331b153/raw/AetrisVPN.txt",
    "FILTER-2.txt": "https://github.com/AvenCores/goida-vpn-configs/raw/refs/heads/main/githubmirror/26.txt",
    "FILTER-3.txt": "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt",
    "FILTER-4.txt": "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-all.txt",
    "FILTER-5.txt": "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "FILTER-6.txt": "https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/RU.txt",
}

# === НЕБЕЗОПАСНЫЕ ПАРАМЕТРЫ (ЧЁРНЫЙ СПИСОК) ===
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

def is_safe(line: str) -> bool:
    line = line.strip()
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

def load_lines(url: str):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=15) as resp:
            content = resp.read().decode('utf-8', errors='ignore')
            lines = []
            for raw in content.splitlines():
                line = raw.strip()
                if line and not line.startswith('#'):
                    lines.append(line)
            return lines
    except Exception as e:
        print(f"Ошибка загрузки {url}: {e}")
        return []

def main():
    print("=== Фильтрация прокси (сохранение в githubmirror/) ===")
    for filename, source_url in SOURCES.items():
        print(f"\nОбработка {filename} из {source_url}")
        raw_lines = load_lines(source_url)
        if not raw_lines:
            print(f"  → Нет данных из источника")
            continue
        good = set()
        for line in raw_lines:
            if is_safe(line):
                good.add(line)
        out_path = os.path.join(OUTPUT_DIR, filename)
        with open(out_path, 'w', encoding='utf-8', newline='\n') as f:
            f.write('\n'.join(sorted(good)))
            if good:
                f.write('\n')
        print(f"  → Сохранено {len(good)} конфигов в {out_path}")
    print("\nГотово.")

if __name__ == "__main__":
    main()
