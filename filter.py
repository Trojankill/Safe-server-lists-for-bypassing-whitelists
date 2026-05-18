#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import os
import json
import yaml
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Set, Dict, List, Optional, Any

# ------------------------------------------------------------------
# 1. Настройки
# ------------------------------------------------------------------
OUTPUT_DIR = "githubmirror"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ----- Список источников (добавляй/редактируй по своему усмотрению) -----
SOURCES_CONFIG = [
    # Старые прямые ссылки (plain text)
    {
        "name": "FILTER-1",
        "type": "direct",
        "url": "https://gist.githubusercontent.com/flaafix/c79a81037d15163360571c7a7331b153/raw/AetrisVPN.txt",
        "format": "plain"
    },
    {
        "name": "FILTER-2",
        "type": "direct",
        "url": "https://github.com/AvenCores/goida-vpn-configs/raw/refs/heads/main/githubmirror/26.txt",
        "format": "plain"
    },
    {
        "name": "FILTER-3",
        "type": "direct",
        "url": "https://raw.githubusercontent.com/zieng2/wl/main/vless_lite.txt",
        "format": "plain"
    },
    {
        "name": "FILTER-4",
        "type": "direct",
        "url": "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-all.txt",
        "format": "plain"
    },
    {
        "name": "FILTER-5",
        "type": "direct",
        "url": "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
        "format": "plain"
    },
    {
        "name": "FILTER-6",
        "type": "direct",
        "url": "https://raw.githubusercontent.com/rtwo2/FastNodes/main/sub/countries/RU.txt",
        "format": "plain"
    },
    # ------------------------------------------------------------
    # ПРИМЕР: источник с ежедневными файлами (раскомментировать и настроить)
    # {
    #     "name": "FILTER-7",
    #     "type": "github_dated",
    #     "repo": "someuser/daily-proxies",           # владелец/репозиторий
    #     "path_template": "configs/{date}/all.txt",  # {date} заменяется на YYYY-MM-DD
    #     "branch": "main",
    #     "format": "plain"
    # },
    # ------------------------------------------------------------
    # ПРИМЕР: YAML-конфиг (Clash) с прямой ссылкой
    # {
    #     "name": "FILTER-8",
    #     "type": "direct",
    #     "url": "https://example.com/clash.yaml",
    #     "format": "yaml"
    # },
]

# ------------------------------------------------------------------
# 2. Фильтры небезопасных параметров (остались без изменений)
# ------------------------------------------------------------------
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
    """Проверяет один URI (vless:// или trojan://) на безопасность"""
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

# ------------------------------------------------------------------
# 3. Загрузка и парсинг (с поддержкой curl_cffi, GitHub API, YAML)
# ------------------------------------------------------------------
try:
    from curl_cffi import requests as curl_requests
    USE_CURL = True
except ImportError:
    import requests as fallback_requests
    USE_CURL = False
    print("[WARN] curl_cffi не установлен, используется requests (медленнее)")

def fetch_url(url: str) -> Optional[str]:
    """Загружает содержимое по URL (с имитацией браузера, если возможно)"""
    try:
        if USE_CURL:
            resp = curl_requests.get(url, impersonate="chrome", timeout=15)
            if resp.status_code == 200:
                return resp.text
        else:
            resp = fallback_requests.get(url, timeout=15, headers={'User-Agent': 'Mozilla/5.0'})
            if resp.status_code == 200:
                return resp.text
        print(f"  HTTP {resp.status_code} для {url}")
        return None
    except Exception as e:
        print(f"  Ошибка загрузки {url}: {e}")
        return None

def get_latest_github_file(repo: str, path_template: str, branch: str = "main", days_back: int = 3) -> Optional[str]:
    """Ищет файл по шаблону с датой, перебирая дни от сегодня и на days_back назад.
       Возвращает raw URL, если найден, иначе None."""
    try:
        from github import Github
        g = Github()  # без токена – 60 запросов/час хватает для небольшого числа источников
        repo_obj = g.get_repo(repo)
        for i in range(days_back + 1):
            date_str = (datetime.now() - timedelta(days=i)).strftime("%Y-%m-%d")
            path = path_template.format(date=date_str)
            try:
                contents = repo_obj.get_contents(path, ref=branch)
                if contents.type == "file":
                    print(f"  Найден файл {path} (дата {date_str})")
                    return contents.download_url
            except Exception:
                continue
    except Exception as e:
        print(f"  Ошибка GitHub API: {e}")
    return None

def parse_yaml_to_uris(yaml_content: str) -> Set[str]:
    """Извлекает прокси из YAML (Clash / Sing‑box) и конвертирует в URI."""
    uris = set()
    try:
        data = yaml.safe_load(yaml_content)
        if not isinstance(data, dict):
            return uris
        # Clash: proxies
        if 'proxies' in data and isinstance(data['proxies'], list):
            for proxy in data['proxies']:
                uri = convert_clash_proxy_to_uri(proxy)
                if uri:
                    uris.add(uri)
        # Sing-box: outbounds
        if 'outbounds' in data and isinstance(data['outbounds'], list):
            for out in data['outbounds']:
                uri = convert_singbox_outbound_to_uri(out)
                if uri:
                    uris.add(uri)
    except Exception as e:
        print(f"  Ошибка парсинга YAML: {e}")
    return uris

def convert_clash_proxy_to_uri(proxy: dict) -> Optional[str]:
    ptype = proxy.get('type', '').lower()
    name = proxy.get('name', '')
    server = proxy.get('server', '')
    port = proxy.get('port', '')
    if not server or not port:
        return None
    if ptype == 'vless':
        uuid = proxy.get('uuid', '')
        encryption = proxy.get('encryption', 'none')
        flow = proxy.get('flow', '')
        sni = proxy.get('sni', '')
        fp = proxy.get('fp', 'chrome')
        pbk = proxy.get('pbk', '')
        sid = proxy.get('sid', '')
        params = [f"encryption={encryption}"]
        if flow:
            params.append(f"flow={flow}")
        if sni:
            params.append(f"sni={sni}")
        if fp:
            params.append(f"fp={fp}")
        if pbk:
            params.append(f"pbk={pbk}")
        if sid:
            params.append(f"sid={sid}")
        query = "&".join(params)
        return f"vless://{uuid}@{server}:{port}?{query}#{urllib.parse.quote(name)}"
    if ptype == 'trojan':
        password = proxy.get('password', '')
        sni = proxy.get('sni', '')
        fp = proxy.get('fp', 'chrome')
        params = []
        if sni:
            params.append(f"sni={sni}")
        if fp:
            params.append(f"fp={fp}")
        query = "&".join(params)
        return f"trojan://{password}@{server}:{port}?{query}#{urllib.parse.quote(name)}"
    # ss:// можно добавить при необходимости
    return None

def convert_singbox_outbound_to_uri(out: dict) -> Optional[str]:
    out_type = out.get('type', '').lower()
    if out_type == 'vless':
        server = out.get('server', '')
        port = out.get('server_port', '')
        uuid = out.get('uuid', '')
        flow = out.get('flow', '')
        tls = out.get('tls', {})
        reality = out.get('reality', {})
        sni = tls.get('server_name', '')
        fp = tls.get('utls', {}).get('fingerprint', 'chrome')
        pbk = reality.get('public_key', '')
        sid = reality.get('short_id', '')
        if not server or not port or not uuid:
            return None
        params = ["encryption=none"]
        if flow:
            params.append(f"flow={flow}")
        if sni:
            params.append(f"sni={sni}")
        if fp:
            params.append(f"fp={fp}")
        if pbk:
            params.append(f"pbk={pbk}")
            params.append("security=reality")
        elif tls.get('enabled'):
            params.append("security=tls")
        if sid:
            params.append(f"sid={sid}")
        query = "&".join(params)
        return f"vless://{uuid}@{server}:{port}?{query}#{urllib.parse.quote(out.get('tag', ''))}"
    if out_type == 'trojan':
        server = out.get('server', '')
        port = out.get('server_port', '')
        password = out.get('password', '')
        tls = out.get('tls', {})
        sni = tls.get('server_name', '')
        if not server or not port or not password:
            return None
        params = [f"sni={sni}"] if sni else []
        query = "&".join(params)
        return f"trojan://{password}@{server}:{port}?{query}#{urllib.parse.quote(out.get('tag', ''))}"
    return None

def load_from_source(source: dict) -> Set[str]:
    """Загружает один источник и возвращает set безопасных URI"""
    name = source['name']
    print(f"  [{name}] Загрузка...")
    content = None
    if source['type'] == 'direct':
        content = fetch_url(source['url'])
    elif source['type'] == 'github_dated':
        raw_url = get_latest_github_file(
            source['repo'],
            source['path_template'],
            source.get('branch', 'main')
        )
        if raw_url:
            content = fetch_url(raw_url)
        else:
            print(f"  [{name}] Не найден свежий файл по шаблону")
    else:
        print(f"  [{name}] Неизвестный тип источника")
        return set()

    if not content:
        return set()

    uris = set()
    fmt = source.get('format', 'plain')
    if fmt == 'plain':
        for line in content.splitlines():
            uri = line.strip()
            if uri and not uri.startswith('#'):
                if is_safe_uri(uri):
                    uris.add(uri)
    elif fmt == 'yaml':
        extracted = parse_yaml_to_uris(content)
        for uri in extracted:
            if is_safe_uri(uri):
                uris.add(uri)
    return uris

# ------------------------------------------------------------------
# 4. Основной процесс (параллельный)
# ------------------------------------------------------------------
def main():
    print("=== Продвинутый фильтр прокси (параллельно, YAML, даты) ===")
    start = datetime.now()
    results = {}

    with ThreadPoolExecutor(max_workers=5) as executor:
        future_to_source = {executor.submit(load_from_source, src): src for src in SOURCES_CONFIG}
        for future in as_completed(future_to_source):
            src = future_to_source[future]
            try:
                uris = future.result()
                results[src['name']] = uris
                print(f"  [{src['name']}] → {len(uris)} безопасных URI")
            except Exception as e:
                print(f"  [{src['name']}] Ошибка: {e}")
                results[src['name']] = set()

    # Сохраняем в файлы
    for src in SOURCES_CONFIG:
        name = src['name']
        out_file = os.path.join(OUTPUT_DIR, f"{name}.txt")
        uris = results.get(name, set())
        with open(out_file, 'w', encoding='utf-8', newline='\n') as f:
            f.write('\n'.join(sorted(uris)))
            if uris:
                f.write('\n')
        print(f"  Сохранён {name}.txt → {len(uris)} записей")

    elapsed = (datetime.now() - start).total_seconds()
    print(f"\n✅ Готово за {elapsed:.2f} сек.")

if __name__ == "__main__":
    import urllib.parse  # импорт для кодирования имён
    main()
