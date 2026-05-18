#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import os
import json
import urllib.parse
import urllib.request
import subprocess
import tempfile
import time
import socket
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Set, Tuple, Optional, Dict, Any

# ============================================================
# 1. НАСТРОЙКИ
# ============================================================
OUTPUT_DIR = "githubmirror"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Путь к Xray-core (будет скачан в workflow)
XRAY_BINARY = "./xray/xray"

# Источники (только прямые ссылки, без дат)
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
# 4. ПРЕОБРАЗОВАНИЕ URI В КОНФИГ XRAY
# ============================================================
def uri_to_xray_config(uri: str) -> Optional[Dict[str, Any]]:
    """
    Преобразует VLESS или Trojan URI в JSON-конфиг для Xray-core (входящий прокси).
    Возвращает конфиг для outbound.
    """
    if not uri.startswith(('vless://', 'trojan://')):
        return None
    
    parsed = urllib.parse.urlparse(uri)
    protocol = parsed.scheme  # vless или trojan
    # Извлекаем host:port из netloc (формат: uuid@host:port или password@host:port)
    netloc = parsed.netloc
    if '@' in netloc:
        auth, host_port = netloc.split('@', 1)
    else:
        auth = ''
        host_port = netloc
    if ':' in host_port:
        host, port_str = host_port.split(':', 1)
        port = int(port_str.split('?')[0].split('#')[0])
    else:
        host = host_port
        port = 443  # fallback
    
    # Параметры запроса
    query = urllib.parse.parse_qs(parsed.query)
    # Имя (фрагмент #)
    name = urllib.parse.unquote(parsed.fragment) if parsed.fragment else ""
    
    # Базовый outbound
    outbound = {
        "protocol": protocol,
        "settings": {},
        "streamSettings": {
            "network": "tcp",
            "security": "tls" if protocol == "trojan" else "none",
            "tlsSettings": {},
            "realitySettings": {}
        },
        "tag": name if name else "proxy"
    }
    
    if protocol == "vless":
        # VLESS
        uuid = auth
        outbound["settings"]["vnext"] = [{
            "address": host,
            "port": port,
            "users": [{
                "id": uuid,
                "encryption": query.get("encryption", ["none"])[0],
                "flow": query.get("flow", [""])[0],
                "level": 0
            }]
        }]
        # Reality или TLS
        if "security" in query and query["security"][0] == "reality":
            outbound["streamSettings"]["security"] = "reality"
            outbound["streamSettings"]["realitySettings"] = {
                "serverName": query.get("sni", [host])[0],
                "fingerprint": query.get("fp", ["chrome"])[0],
                "publicKey": query.get("pbk", [""])[0],
                "shortId": query.get("sid", [""])[0],
                "spiderX": ""
            }
        elif "security" in query and query["security"][0] == "tls":
            outbound["streamSettings"]["security"] = "tls"
            outbound["streamSettings"]["tlsSettings"] = {
                "serverName": query.get("sni", [host])[0],
                "allowInsecure": False,
                "fingerprint": query.get("fp", ["chrome"])[0]
            }
        else:
            # no TLS (rare)
            outbound["streamSettings"]["security"] = "none"
    
    elif protocol == "trojan":
        password = auth
        outbound["settings"]["servers"] = [{
            "address": host,
            "port": port,
            "password": password,
            "level": 0
        }]
        outbound["streamSettings"]["security"] = "tls"
        outbound["streamSettings"]["tlsSettings"] = {
            "serverName": query.get("sni", [host])[0],
            "allowInsecure": False,
            "fingerprint": query.get("fp", ["chrome"])[0]
        }
    
    return outbound

# ============================================================
# 5. ПРОВЕРКА ЧЕРЕЗ XRAY-CORE (РЕАЛЬНЫЙ ЗАПРОС)
# ============================================================
def test_proxy_via_xray(uri: str, timeout: float = 10.0) -> Tuple[Optional[float], str]:
    """
    Запускает Xray-core с конфигом, подключается к прокси и делает тестовый HTTP-запрос.
    Возвращает (задержка_мс, обновлённый_URI) или (None, URI) при неудаче.
    """
    # Извлекаем оригинальное имя
    original_name = ""
    if '#' in uri:
        original_name = urllib.parse.unquote(uri.split('#')[-1])
    
    # Конвертируем URI в outbound
    outbound = uri_to_xray_config(uri)
    if not outbound:
        return None, uri
    
    # Создаём полный конфиг Xray (минимальный inbounds для socks, один outbound)
    config = {
        "log": {"loglevel": "warning"},
        "inbounds": [{
            "protocol": "socks",
            "port": 1080,
            "listen": "127.0.0.1",
            "settings": {"auth": "noauth", "udp": False}
        }],
        "outbounds": [outbound],
        "routing": {"domainStrategy": "AsIs"}
    }
    
    with tempfile.TemporaryDirectory() as tmpdir:
        config_path = os.path.join(tmpdir, "config.json")
        with open(config_path, 'w') as f:
            json.dump(config, f)
        
        # Запускаем Xray
        proc = subprocess.Popen(
            [XRAY_BINARY, "-c", config_path],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        time.sleep(1.5)  # даём время подняться
        
        try:
            # Тестовый запрос через socks5
            start = time.time()
            # Используем curl через socks5
            cmd = [
                "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                "-x", "socks5h://127.0.0.1:1080",
                "--max-time", str(timeout),
                "http://ip-api.com"
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout+2)
            elapsed_ms = (time.time() - start) * 1000
            
            if result.returncode == 0 and result.stdout.strip() == "200":
                # Успех
                new_name = f"[{int(elapsed_ms)}ms] {original_name}" if original_name else f"[{int(elapsed_ms)}ms]"
                new_uri = uri.split('#')[0] + f"#{urllib.parse.quote(new_name)}"
                return elapsed_ms, new_uri
            else:
                # Прокси не работает
                return None, uri
        except Exception as e:
            return None, uri
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except:
                proc.kill()

# ============================================================
# 6. ОСНОВНАЯ ЛОГИКА
# ============================================================
def main():
    print("=== Фильтрация и проверка прокси через Xray-core ===")
    start_total = datetime.now()
    
    # Шаг 1: сбор всех безопасных URI
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
    
    print(f"\nВсего безопасных URI: {len(all_safe)}")
    if not all_safe:
        print("Нет безопасных конфигов. Завершение.")
        return
    
    # Шаг 2: проверка через Xray-core (реальные запросы)
    print("\n=== Реальная проверка через Xray-core (может занять время) ===")
    results = []  # (latency, updated_uri)
    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_uri = {executor.submit(test_proxy_via_xray, uri): uri for uri in all_safe}
        for future in as_completed(future_to_uri):
            latency, updated_uri = future.result()
            if latency is not None:
                results.append((latency, updated_uri))
            # Прогресс
            done = len(results) + (len(all_safe) - len(future_to_uri))
            if done % 10 == 0 or done == len(all_safe):
                print(f"  Прогресс: {done} / {len(all_safe)} (живых: {len(results)})")
    
    results.sort(key=lambda x: x[0])  # сортируем по задержке
    
    # Шаг 3: сохраняем индивидуальные FILTER-*.txt (без проверки, просто безопасные)
    for src in SOURCES_CONFIG:
        uris = load_from_source(src)   # повторная загрузка (неэффективно, но просто)
        out_file = os.path.join(OUTPUT_DIR, f"{src['name']}.txt")
        with open(out_file, 'w', encoding='utf-8', newline='\n') as f:
            f.write('\n'.join(sorted(uris)))
            if uris:
                f.write('\n')
        print(f"  Сохранён {src['name']}.txt → {len(uris)} записей")
    
    # Шаг 4: сохраняем FAST-server.txt (только живые, отсортированные)
    fast_file = os.path.join(OUTPUT_DIR, "FAST-server.txt")
    with open(fast_file, 'w', encoding='utf-8', newline='\n') as f:
        for latency, uri in results:
            f.write(uri + '\n')
    print(f"\nСоздан FAST-server.txt с {len(results)} живыми прокси (отсортировано по пингу)")
    
    elapsed = (datetime.now() - start_total).total_seconds()
    print(f"\n✅ Полный цикл завершён за {elapsed:.2f} сек.")

if __name__ == "__main__":
    main()
