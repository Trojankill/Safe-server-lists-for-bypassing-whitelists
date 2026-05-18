#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import os
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Set, List

from xray_tester import XrayTester

OUTPUT_DIR = "githubmirror"
os.makedirs(OUTPUT_DIR, exist_ok=True)

SOURCES_CONFIG = [
    {"name": "FILTER-1", "url": "https://gist.githubusercontent.com/flaafix/c79a81037d15163360571c7a7331b153/raw/AetrisVPN.txt"},
    {"name": "FILTER-2", "url": "https://github.com/AvenCores/goida-vpn-configs/raw/refs/heads/main/githubmirror/26.txt"},
    {"name": "FILTER-3", "url": "https://raw.githubusercontent.com/zieng2/wl/main/vless_lite.txt"},
    {"name": "FILTER-4", "url": "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-all.txt"},
    {"name": "FILTER-5", "url": "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt"}
]

# ----------------------------------------------
# Фильтры безопасности (как раньше)
# ----------------------------------------------
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
    uri = uri.strip()
    if not uri:
        return False
    if not (uri.startswith('vless://') or uri.startswith('trojan://')):
        return False
    if has_insecure_params(uri):
        return False
    if uri.startswith('trojan://'):
        return 'sni=' in uri
    if uri.startswith('vless://'):
        if re.search(r'security=reality|pbk=|flow=xtls-rprx-vision', uri, re.I):
            return True
        if 'security=tls' in uri and 'encryption=none' in uri:
            return 'sni=' in uri or 'alpn=' in uri
        return False
    return False

def fetch_url(url: str):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.read().decode('utf-8', errors='ignore')
    except Exception as e:
        print(f"  Ошибка {url}: {e}")
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
        if uri and not uri.startswith('#') and is_safe_uri(uri):
            uris.add(uri)
    return uris

def main():
    print("=== Фильтрация + XrayTester (реальная проверка прокси) ===")
    # 1. Собираем безопасные URI из всех источников
    all_safe = set()
    with ThreadPoolExecutor(max_workers=5) as ex:
        futures = [ex.submit(load_from_source, src) for src in SOURCES_CONFIG]
        for f in as_completed(futures):
            all_safe.update(f.result())
    print(f"\nВсего безопасных URI: {len(all_safe)}")
    if not all_safe:
        return

    # 2. Тестируем через XrayTester
    print("\n=== Запуск XrayTester (проверка реальной работы, может занять время) ===")
    tester = XrayTester()
    results = tester.test_batch(list(all_safe), concurrency=50, timeout=8.0)

    # 3. Формируем список живых с новыми именами
    working = []
    for url, ok, latency in results:
        if ok and latency > 0:
            original_name = url.split('#')[-1] if '#' in url else ""
            new_name = f"[{int(latency)}ms] {original_name}"
            new_uri = url.split('#')[0] + f"#{new_name}"
            working.append((latency, new_uri))
    working.sort(key=lambda x: x[0])

    # 4. Сохраняем индивидуальные FILTER-*.txt (без проверки, просто безопасные)
    for src in SOURCES_CONFIG:
        uris = load_from_source(src)  # можно было сохранить из этапа 1, но для простоты повторяем
        out_path = os.path.join(OUTPUT_DIR, f"{src['name']}.txt")
        with open(out_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(sorted(uris)) + ('\n' if uris else ''))
        print(f"  Сохранён {src['name']}.txt → {len(uris)} записей")

    # 5. FAST-server.txt
    fast_path = os.path.join(OUTPUT_DIR, "FAST-server.txt")
    with open(fast_path, 'w', encoding='utf-8') as f:
        for _, uri in working:
            f.write(uri + '\n')
    print(f"\n✅ FAST-server.txt: {len(working)} живых прокси (отсортировано по пингу)")

if __name__ == "__main__":
    main()
