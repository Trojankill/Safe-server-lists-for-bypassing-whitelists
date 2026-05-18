#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import os
import socket
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Set, List, Tuple, Optional

from xray_tester import XrayTester

OUTPUT_DIR = "githubmirror"
os.makedirs(OUTPUT_DIR, exist_ok=True)

MAX_LIVE_CHECK = 30          # Сколько прокси проверим реально (через Xray)
TCP_TIMEOUT = 1.5            # Таймаут TCP-пинга

SOURCES_CONFIG = [
    {"name": "FILTER-1", "url": "https://gist.githubusercontent.com/flaafix/c79a81037d15163360571c7a7331b153/raw/AetrisVPN.txt"},
    {"name": "FILTER-2", "url": "https://github.com/AvenCores/goida-vpn-configs/raw/refs/heads/main/githubmirror/26.txt"},
    {"name": "FILTER-3", "url": "https://raw.githubusercontent.com/zieng2/wl/main/vless_lite.txt"},
    {"name": "FILTER-4", "url": "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-all.txt"},
    {"name": "FILTER-5", "url": "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt"}
]

# ---------- безопасность ----------
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

def extract_host_port(uri: str) -> Tuple[Optional[str], Optional[int]]:
    try:
        # Формат: vless://uuid@host:port?params#name
        # или trojan://password@host:port?params#name
        netloc = uri.split('://')[1].split('@')[-1]
        host_port = netloc.split('?')[0].split('#')[0]
        if ':' in host_port:
            host, port_str = host_port.split(':', 1)
            return host, int(port_str)
        return host_port, 443
    except:
        return None, None

def tcp_ping(host: str, port: int, timeout: float = TCP_TIMEOUT) -> Optional[float]:
    try:
        start = time.time()
        with socket.create_connection((host, port), timeout=timeout):
            return (time.time() - start) * 1000
    except:
        return None

def main():
    import time
    print("=== Гибридная фильтрация: TCP-пинг + Xray (только лучшие) ===")
    start_total = time.time()
    
    # 1. Собираем все безопасные URI
    all_safe = set()
    with ThreadPoolExecutor(max_workers=5) as ex:
        futures = [ex.submit(load_from_source, src) for src in SOURCES_CONFIG]
        for f in as_completed(futures):
            all_safe.update(f.result())
    print(f"\nВсего безопасных URI: {len(all_safe)}")
    if not all_safe:
        return

    # 2. Быстрый TCP-пинг для всех и сортировка
    print("\n=== Быстрый TCP-пинг (отсев мёртвых) ===")
    ping_results = []  # (latency, uri)
    with ThreadPoolExecutor(max_workers=30) as ex:
        def ping_one(uri):
            host, port = extract_host_port(uri)
            if not host:
                return None
            lat = tcp_ping(host, port)
            if lat is not None:
                return (lat, uri)
            return None
        futures = [ex.submit(ping_one, uri) for uri in all_safe]
        for f in as_completed(futures):
            res = f.result()
            if res:
                ping_results.append(res)
    ping_results.sort(key=lambda x: x[0])  # по возрастанию пинга
    print(f"  Живых по TCP: {len(ping_results)}/{len(all_safe)}")

    # 3. Отбираем лучшие (по пингу) для реальной проверки через Xray
    to_test = [uri for _, uri in ping_results[:MAX_LIVE_CHECK]]
    print(f"\n=== Реальная проверка через Xray (топ {len(to_test)} прокси) ===")
    if to_test:
        tester = XrayTester()
        # Уменьшаем таймауты для ускорения
        results = tester.test_batch(to_test, concurrency=20, timeout=5.0)
        working = []
        for url, ok, latency in results:
            if ok and latency > 0:
                original_name = url.split('#')[-1] if '#' in url else ""
                new_name = f"[{int(latency)}ms] {original_name}"
                new_uri = url.split('#')[0] + f"#{new_name}"
                working.append((latency, new_uri))
        working.sort(key=lambda x: x[0])
        print(f"  Реально рабочих: {len(working)}/{len(to_test)}")
    else:
        working = []

    # 4. Сохраняем FILTER-*.txt (все безопасные, даже непроверенные)
    for src in SOURCES_CONFIG:
        uris = load_from_source(src)  # повторная загрузка (можно кеш, но не критично)
        out_path = os.path.join(OUTPUT_DIR, f"{src['name']}.txt")
        with open(out_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(sorted(uris)) + ('\n' if uris else ''))
        print(f"  Сохранён {src['name']}.txt → {len(uris)}")

    # 5. FAST-server.txt (только реально проверенные рабочие)
    fast_path = os.path.join(OUTPUT_DIR, "FAST-server.txt")
    with open(fast_path, 'w', encoding='utf-8') as f:
        for _, uri in working:
            f.write(uri + '\n')
    print(f"\n✅ FAST-server.txt: {len(working)} живых прокси (отсортировано по пингу)")

    elapsed = time.time() - start_total
    print(f"\n⏱️  Время выполнения: {elapsed:.1f} секунд")

if __name__ == "__main__":
    main()
