#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import os
import sys
import json
import subprocess
import tempfile
import urllib.request
import time
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, parse_qs
from typing import List, Tuple, Optional, Set

# ============================================================
# 1. НАСТРОЙКИ
# ============================================================
OUTPUT_DIR = "githubmirror"
os.makedirs(OUTPUT_DIR, exist_ok=True)

MAX_PROXIES_TO_TEST = 40          # Сколько прокси проверим (остальные только в FILTER-*.txt)
MAX_LATENCY_MS = 300               # Прокси с пингом выше этого не попадают в FAST-server.txt
TEST_TIMEOUT = 5.0                 # Таймаут теста в секундах
XRAY_BINARY = "./xray/xray"        # Путь к Xray (будет скачан в workflow)

SOURCES_CONFIG = [
    {"name": "FILTER-1", "url": "https://gist.githubusercontent.com/flaafix/c79a81037d15163360571c7a7331b153/raw/AetrisVPN.txt"},
    {"name": "FILTER-2", "url": "https://github.com/AvenCores/goida-vpn-configs/raw/refs/heads/main/githubmirror/26.txt"},
    {"name": "FILTER-3", "url": "https://raw.githubusercontent.com/zieng2/wl/main/vless_lite.txt"},
    {"name": "FILTER-4", "url": "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-all.txt"},
    {"name": "FILTER-5", "url": "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt"}
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
        if uri and not uri.startswith('#') and is_safe_uri(uri):
            uris.add(uri)
    return uris

# ============================================================
# 4. TCP ПИНГ ДЛЯ БЫСТРОГО ОТСЕВА
# ============================================================
def extract_host_port(uri: str) -> Tuple[Optional[str], Optional[int]]:
    try:
        # Формат: vless://uuid@host:port... или trojan://pass@host:port...
        after_proto = uri.split('://', 1)[1]
        host_port_part = after_proto.split('@')[-1].split('?')[0].split('#')[0]
        if ':' in host_port_part:
            host, port_str = host_port_part.split(':', 1)
            return host, int(port_str)
        return host_port_part, 443
    except:
        return None, None

def tcp_ping(host: str, port: int, timeout: float = 1.5) -> Optional[float]:
    try:
        start = time.time()
        with socket.create_connection((host, port), timeout=timeout):
            return (time.time() - start) * 1000
    except:
        return None

# ============================================================
# 5. ПРОВЕРКА ЧЕРЕЗ XRAY (РЕАЛЬНЫЙ ЗАПРОС)
# ============================================================
def vless_to_xray_outbound(url: str, tag: str = "proxy") -> Optional[dict]:
    """Минимальный парсер VLESS URL в outbound для Xray."""
    try:
        # удаляем vless://
        rest = url.replace('vless://', '', 1)
        # отрезаем #fragment
        if '#' in rest:
            rest = rest.split('#', 1)[0]
        # разделяем базу и параметры
        if '?' in rest:
            base, query_str = rest.split('?', 1)
        else:
            base, query_str = rest, ''
        # base = uuid@host:port
        if '@' not in base:
            return None
        uuid, host_port = base.rsplit('@', 1)
        if ':' not in host_port:
            return None
        host, port_str = host_port.rsplit(':', 1)
        port = int(port_str.split('/')[0])
        # параметры
        params = parse_qs(query_str)
        security = params.get('security', ['none'])[0]
        out = {
            "protocol": "vless",
            "settings": {
                "vnext": [{
                    "address": host,
                    "port": port,
                    "users": [{
                        "id": uuid,
                        "encryption": params.get('encryption', ['none'])[0],
                        "flow": params.get('flow', [''])[0]
                    }]
                }]
            },
            "streamSettings": {
                "network": params.get('type', ['tcp'])[0],
                "security": security
            }
        }
        if security == 'tls':
            out["streamSettings"]["tlsSettings"] = {
                "serverName": params.get('sni', [host])[0],
                "fingerprint": params.get('fp', ['chrome'])[0]
            }
        elif security == 'reality':
            out["streamSettings"]["realitySettings"] = {
                "serverName": params.get('sni', [''])[0],
                "fingerprint": params.get('fp', ['chrome'])[0],
                "publicKey": params.get('pbk', [''])[0],
                "shortId": params.get('sid', [''])[0]
            }
        return out
    except:
        return None

def trojan_to_xray_outbound(url: str, tag: str = "proxy") -> Optional[dict]:
    try:
        rest = url.replace('trojan://', '', 1)
        if '#' in rest:
            rest = rest.split('#', 1)[0]
        if '?' in rest:
            rest = rest.split('?', 1)[0]
        if '@' not in rest:
            return None
        password, host_port = rest.rsplit('@', 1)
        if ':' not in host_port:
            return None
        host, port_str = host_port.rsplit(':', 1)
        port = int(port_str)
        return {
            "protocol": "trojan",
            "settings": {"servers": [{"address": host, "port": port, "password": password}]},
            "streamSettings": {
                "network": "tcp",
                "security": "tls",
                "tlsSettings": {"serverName": host}
            }
        }
    except:
        return None

def test_proxy_with_xray(uri: str, timeout: float = TEST_TIMEOUT) -> Tuple[bool, float, str]:
    """Возвращает (успех, задержка_мс, новый_URI_с_пингом_в_имени)"""
    # Извлекаем оригинальное имя
    original_name = uri.split('#')[-1] if '#' in uri else ""
    # Создаём outbound
    if uri.startswith('vless://'):
        out = vless_to_xray_outbound(uri)
    elif uri.startswith('trojan://'):
        out = trojan_to_xray_outbound(uri)
    else:
        return False, 0.0, uri
    if not out:
        return False, 0.0, uri

    # Генерируем порт для SOCKS
    socks_port = 30000 + (hash(uri) % 5000)  # простой deterministic порт
    config = {
        "log": {"loglevel": "error"},
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": socks_port,
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": False}
        }],
        "outbounds": [out],
        "routing": {"rules": [{"type": "field", "inboundTag": ["socks"], "outboundTag": "proxy"}]}
    }
    # Создаём временный конфиг
    fd, conf_path = tempfile.mkstemp(suffix='.json', prefix='xray_')
    os.close(fd)
    with open(conf_path, 'w') as f:
        json.dump(config, f)
    try:
        proc = subprocess.Popen([XRAY_BINARY, "run", "-config", conf_path],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.5)  # даём Xray время подняться
        if proc.poll() is not None:
            return False, 0.0, uri
        # Тестовый HTTP-запрос через SOCKS5
        test_url = "http://ip-api.com"
        start = time.time()
        curl_cmd = [
            "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
            "-x", f"socks5h://127.0.0.1:{socks_port}",
            "--max-time", str(timeout),
            test_url
        ]
        result = subprocess.run(curl_cmd, capture_output=True, text=True, timeout=timeout+1)
        latency = (time.time() - start) * 1000
        if result.returncode == 0 and result.stdout.strip() == "200":
            new_name = f"[{int(latency)}ms] {original_name}" if original_name else f"[{int(latency)}ms]"
            new_uri = uri.split('#')[0] + f"#{new_name}"
            return True, latency, new_uri
        else:
            return False, 0.0, uri
    except Exception:
        return False, 0.0, uri
    finally:
        proc.terminate()
        proc.wait(timeout=2)
        os.unlink(conf_path)

# ============================================================
# 6. ОСНОВНАЯ ЛОГИКА
# ============================================================
def main():
    print("=== Минимальный фильтр + Xray проверка (только живые, пинг < 300 мс) ===")
    start_all = time.time()
    
    # 1. Сбор всех безопасных URI
    all_safe = set()
    with ThreadPoolExecutor(max_workers=5) as ex:
        futures = [ex.submit(load_from_source, src) for src in SOURCES_CONFIG]
        for f in as_completed(futures):
            all_safe.update(f.result())
    print(f"\nВсего безопасных URI: {len(all_safe)}")
    if not all_safe:
        return

    # 2. Быстрый TCP-пинг + сортировка
    print("\n=== Быстрая TCP-проверка (отсев мёртвых) ===")
    ping_list = []  # (latency, uri)
    with ThreadPoolExecutor(max_workers=30) as ex:
        def tcp_one(uri):
            host, port = extract_host_port(uri)
            if not host:
                return None
            lat = tcp_ping(host, port)
            if lat is not None:
                return (lat, uri)
            return None
        for uri in all_safe:
            futures = [ex.submit(tcp_one, uri) for uri in all_safe]
            for f in as_completed(futures):
                res = f.result()
                if res:
                    ping_list.append(res)
    ping_list.sort(key=lambda x: x[0])
    print(f"  Живых по TCP: {len(ping_list)}/{len(all_safe)}")

    # 3. Отбираем лучшие для реальной проверки
    to_test = [uri for _, uri in ping_list[:MAX_PROXIES_TO_TEST]]
    print(f"\n=== Реальная проверка через Xray (топ {len(to_test)} прокси, таймаут {TEST_TIMEOUT}c) ===")
    good_proxies = []  # (latency, new_uri)
    for i, uri in enumerate(to_test):
        print(f"  Тестируем {i+1}/{len(to_test)}...")
        ok, lat, new_uri = test_proxy_with_xray(uri)
        if ok and lat <= MAX_LATENCY_MS:
            good_proxies.append((lat, new_uri))
            print(f"    ✅ {int(lat)}ms -> имя обновлено")
        else:
            print(f"    ❌ не прошёл (латенси: {int(lat) if ok else 'таймаут'})")
    good_proxies.sort(key=lambda x: x[0])

    # 4. Сохраняем FILTER-*.txt (все безопасные)
    for src in SOURCES_CONFIG:
        uris = load_from_source(src)  # повтор, но можно кешировать
        out = os.path.join(OUTPUT_DIR, f"{src['name']}.txt")
        with open(out, 'w', encoding='utf-8') as f:
            f.write('\n'.join(sorted(uris)) + ('\n' if uris else ''))
        print(f"  Сохранён {src['name']}.txt → {len(uris)}")

    # 5. FAST-server.txt (только живые, пинг < MAX_LATENCY_MS)
    fast_path = os.path.join(OUTPUT_DIR, "FAST-server.txt")
    with open(fast_path, 'w', encoding='utf-8') as f:
        for _, uri in good_proxies:
            f.write(uri + '\n')
    print(f"\n✅ FAST-server.txt: {len(good_proxies)} живых прокси (отсортировано по пингу)")

    elapsed = time.time() - start_all
    print(f"\n⏱️  Время выполнения: {elapsed:.1f} секунд")

if __name__ == "__main__":
    main()
