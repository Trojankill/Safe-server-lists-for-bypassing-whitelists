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

OUTPUT_DIR = "githubmirror"
os.makedirs(OUTPUT_DIR, exist_ok=True)

XRAY_BINARY = "./xray/xray"

SOURCES_CONFIG = [
    {"name": "FILTER-1", "url": "https://gist.githubusercontent.com/flaafix/c79a81037d15163360571c7a7331b153/raw/AetrisVPN.txt"},
    {"name": "FILTER-2", "url": "https://github.com/AvenCores/goida-vpn-configs/raw/refs/heads/main/githubmirror/26.txt"},
    {"name": "FILTER-3", "url": "https://raw.githubusercontent.com/zieng2/wl/main/vless_lite.txt"},
    {"name": "FILTER-4", "url": "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-all.txt"},
    {"name": "FILTER-5", "url": "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt"}
]

# === фильтры безопасности (как раньше) ===
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

def fetch_url(url: str) -> Optional[str]:
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
        if uri and not uri.startswith('#'):
            if is_safe_uri(uri):
                uris.add(uri)
    return uris

def uri_to_xray_config(uri: str) -> Optional[Dict[str, Any]]:
    # ... (та же функция, что и в предыдущем коде, она не меняется) ...
    # Чтобы не дублировать, вставь её из предыдущего сообщения, либо я дам ссылку.
    # Для краткости здесь предполагается, что она уже есть.
    pass

# ------------------------------------------------------------
# БЫСТРЫЙ TCP-ПИНГ (отсеиваем заведомо мёртвые)
# ------------------------------------------------------------
def tcp_ping(host: str, port: int, timeout: float = 1.5) -> Optional[float]:
    try:
        start = time.time()
        with socket.create_connection((host, port), timeout=timeout):
            return (time.time() - start) * 1000
    except:
        return None

# ------------------------------------------------------------
# ПРОВЕРКА ЧЕРЕЗ XRAY (только для живых по TCP)
# ------------------------------------------------------------
def extract_host_port(uri: str) -> Tuple[Optional[str], Optional[int], str]:
    try:
        parsed = urllib.parse.urlparse(uri)
        netloc = parsed.netloc.split('@')[-1]
        if ':' in netloc:
            host, port_str = netloc.split(':', 1)
            port = int(port_str.split('?')[0].split('#')[0])
        else:
            host = netloc
            port = 443
        name = ''
        if '#' in uri:
            name = urllib.parse.unquote(uri.split('#')[-1])
        return host, port, name
    except:
        return None, None, ''

def test_proxy_via_xray(uri: str, timeout: float = 5.0) -> Tuple[Optional[float], str]:
    """Запускает Xray только для прокси, прошедшего TCP-пинг."""
    # Предварительный TCP-пинг (быстрый)
    host, port, orig_name = extract_host_port(uri)
    if not host or not port:
        return None, uri
    tcp_latency = tcp_ping(host, port, timeout=1.5)
    if tcp_latency is None:
        return None, uri   # TCP не отвечает – даже не пытаемся
    
    # Теперь реальная проверка через Xray
    outbound = uri_to_xray_config(uri)
    if not outbound:
        return None, uri
    
    config = {
        "log": {"loglevel": "warning"},
        "inbounds": [{"protocol": "socks", "port": 1080, "listen": "127.0.0.1", "settings": {"auth": "noauth"}}],
        "outbounds": [outbound],
        "routing": {"domainStrategy": "AsIs"}
    }
    
    with tempfile.TemporaryDirectory() as tmpdir:
        config_path = os.path.join(tmpdir, "config.json")
        with open(config_path, 'w') as f:
            json.dump(config, f)
        
        proc = subprocess.Popen([XRAY_BINARY, "-c", config_path], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.5)   # сократили с 1.5 до 0.5 секунд
        
        try:
            start = time.time()
            cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                   "-x", "socks5h://127.0.0.1:1080", "--max-time", str(timeout), "http://ip-api.com"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout+1)
            latency = (time.time() - start) * 1000
            if result.returncode == 0 and result.stdout.strip() == "200":
                new_name = f"[{int(latency)}ms] {orig_name}" if orig_name else f"[{int(latency)}ms]"
                new_uri = uri.split('#')[0] + f"#{urllib.parse.quote(new_name)}"
                return latency, new_uri
        except:
            pass
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=1)
            except:
                proc.kill()
    return None, uri

# ------------------------------------------------------------
# ОСНОВНАЯ ЛОГИКА (с параллелизацией 15 потоков)
# ------------------------------------------------------------
def main():
    print("=== Фильтрация + TCP префильтр + Xray проверка (ускоренная) ===")
    start_total = datetime.now()
    
    # Шаг 1: сбор безопасных URI
    all_safe = set()
    with ThreadPoolExecutor(max_workers=5) as ex:
        futures = [ex.submit(load_from_source, src) for src in SOURCES_CONFIG]
        for f in as_completed(futures):
            all_safe.update(f.result())
    
    print(f"\nБезопасных URI: {len(all_safe)}")
    if not all_safe:
        return
    
    # Шаг 2: проверка через Xray (сначала быстрый TCP-пинг)
    print("\n=== Проверка (TCP+реальная) с параллелизацией 15 потоков ===")
    results = []
    with ThreadPoolExecutor(max_workers=15) as ex:
        future_to_uri = {ex.submit(test_proxy_via_xray, uri): uri for uri in all_safe}
        completed = 0
        for future in as_completed(future_to_uri):
            latency, new_uri = future.result()
            completed += 1
            if latency is not None:
                results.append((latency, new_uri))
            if completed % 20 == 0 or completed == len(all_safe):
                print(f"  Прогресс: {completed}/{len(all_safe)} (живых: {len(results)})")
    
    results.sort(key=lambda x: x[0])
    
    # Шаг 3: сохранение FILTER-*.txt (индивидуальные)
    for src in SOURCES_CONFIG:
        uris = load_from_source(src)   # повторная загрузка – можно оптимизировать, но не критично
        out = os.path.join(OUTPUT_DIR, f"{src['name']}.txt")
        with open(out, 'w', encoding='utf-8') as f:
            f.write('\n'.join(sorted(uris)) + ('\n' if uris else ''))
        print(f"  {src['name']}.txt → {len(uris)}")
    
    # Шаг 4: FAST-server.txt
    fast_path = os.path.join(OUTPUT_DIR, "FAST-server.txt")
    with open(fast_path, 'w', encoding='utf-8') as f:
        for _, uri in results:
            f.write(uri + '\n')
    print(f"\nFAST-server.txt: {len(results)} живых прокси (отсортировано)")
    
    elapsed = (datetime.now() - start_total).total_seconds()
    print(f"\n✅ Завершено за {elapsed:.2f} сек.")
