#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import os
import json
import base64
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
from typing import Set, Dict, Optional, List, Tuple

OUTPUT_DIR = "githubmirror"
os.makedirs(OUTPUT_DIR, exist_ok=True)

SUPPORTED_PROTOCOLS = [
    "vless://", "vmess://", "trojan://", "hysteria2://", "hy2://", "ss://"
]

SOURCES_CONFIG = [
    {"name": "FILTER-1", "url": "https://gist.githubusercontent.com/flaafix/c79a81037d15163360571c7a7331b153/raw/AetrisVPN.txt"},
    {"name": "FILTER-2", "url": "https://github.com/AvenCores/goida-vpn-configs/raw/refs/heads/main/githubmirror/26.txt"},
    {"name": "FILTER-3", "url": "https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_universal.txt"},
    {"name": "FILTER-4", "url": "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-all.txt"},
    {"name": "FILTER-5", "url": "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt"}
]

# ---------- Чёрный список подозрительных доменов в SNI ----------
DANGEROUS_SNI_DOMAINS = [
    'trahodrom.fun', 'persik.host', 'skysafe.online', 'alexandroff.ru',
    'grovpn.com.alexandroff.ru', 'cdn.trahodrom.fun', 'rruu.persik.host',
    'pol.skysafe.online'
]

# ---------- Глобальные небезопасные параметры (без encryption=none) ----------
UNSAFE_PATTERNS = [
    r'[&?]allowinsecure=1', r'[&?]allowinsecure=true',
    r'[&?]insecure=1', r'[&?]insecure=true',
    r'[&?]security=none',
    r'[&?]verify=0', r'[&?]verify=false',
    r'[&?]skip-cert-verify=0', r'[&?]skip-cert-verify=false',
    r'[&?]allowinsecurecipher=1', r'[&?]allowinsecurecipher=true',
    r'[&?]tls13=0', r'[&?]tls13=false',
]
UNSAFE_REGEX = re.compile('|'.join(UNSAFE_PATTERNS), re.IGNORECASE)

def is_supported_protocol(line: str) -> bool:
    line = line.strip()
    for proto in SUPPORTED_PROTOCOLS:
        if line.startswith(proto):
            return True
    return False

def has_insecure_params(line: str) -> bool:
    return bool(UNSAFE_REGEX.search(line))

# ---------- Дополнительные проверки безопасности ----------
def is_dangerous_sni(url: str) -> bool:
    sni_match = re.search(r'[?&]sni=([^&]+)', url, re.I)
    if not sni_match:
        return False
    sni = sni_match.group(1).lower()
    for domain in DANGEROUS_SNI_DOMAINS:
        if domain in sni:
            return True
    return False

def is_suspicious_host(url: str) -> bool:
    # Проверка хоста: если он выглядит как IP.домен (например, 138.124.125.83.alexandroff.ru)
    host_match = re.search(r'vless://[^@]+@([^:?]+)', url)
    if not host_match:
        return False
    host = host_match.group(1)
    if re.match(r'^\d+\.\d+\.\d+\.\d+\.[a-zA-Z]', host):
        return True
    return False

def has_dangerous_transport_combination(url: str) -> bool:
    # type=raw + flow=xtls-rprx-vision
    type_match = re.search(r'[?&]type=([^&]+)', url, re.I)
    flow_match = re.search(r'[?&]flow=([^&]+)', url, re.I)
    if type_match and type_match.group(1).lower() == 'raw' and flow_match and 'xtls-rprx-vision' in flow_match.group(1).lower():
        return True
    # type=xhttp без host (обязательный параметр для xhttp)
    if type_match and type_match.group(1).lower() == 'xhttp':
        if '&host=' not in url and '?host=' not in url:
            return True
    return False

# ---------- Извлечение pbk и UUID для статистики ----------
def extract_pbk(url: str) -> Optional[str]:
    pbk_match = re.search(r'[?&]pbk=([^&]+)', url, re.I)
    return pbk_match.group(1) if pbk_match else None

def extract_uuid(url: str) -> Optional[str]:
    # UUID находится после vless:// и до @
    uuid_match = re.search(r'vless://([a-f0-9-]+)@', url, re.I)
    return uuid_match.group(1).lower() if uuid_match else None

# ---------- Протокол-специфичные проверки ----------
def is_safe_vless(url: str) -> bool:
    if not url.startswith('vless://'):
        return False

    security_match = re.search(r'[?&]security=([^&]*)', url, re.I)
    security_value = security_match.group(1).lower() if security_match else ''

    type_match = re.search(r'[?&]type=([^&]*)', url, re.I)
    transport = type_match.group(1).lower() if type_match else ''

    has_sni = bool(re.search(r'[?&]sni=[^&]+', url, re.I))

    if not security_value or security_value == 'none':
        return False

    if security_value == 'reality' and 'pbk=' in url:
        return True

    if security_value == 'tls' and transport in ('ws', 'grpc', 'http') and has_sni and 'encryption=none' in url:
        return True

    return False

def is_safe_trojan(url: str) -> bool:
    if not url.startswith('trojan://'):
        return False
    return 'sni=' in url

def is_safe_vmess(url: str) -> bool:
    if not url.startswith('vmess://'):
        return False
    b64 = url.replace('vmess://', '').split('#')[0].split('?')[0]
    try:
        missing = len(b64) % 4
        if missing:
            b64 += '=' * (4 - missing)
        decoded = base64.b64decode(b64).decode('utf-8')
        cfg = json.loads(decoded)
        if cfg.get('aid', cfg.get('alterId', 0)) != 0:
            return False
        if not cfg.get('tls', False):
            return False
        if cfg.get('v', '2') != '2':
            return False
        return True
    except Exception:
        return False

def is_safe_hysteria2(url: str) -> bool:
    return url.startswith(('hysteria2://', 'hy2://'))

def is_safe_ss(url: str) -> bool:
    if not url.startswith('ss://'):
        return False
    try:
        after_proto = url.replace('ss://', '', 1)
        if '@' not in after_proto:
            return False
        method_part = after_proto.split('@')[0]
        if ':' in method_part:
            method = method_part.split(':')[0]
            if method.lower() == 'none':
                return False
    except Exception:
        return False
    return True

def is_safe_config_base(line: str) -> bool:
    """Базовая проверка без учёта статистики pbk/uuid (для предварительной фильтрации)."""
    line = line.strip()
    if not line or not is_supported_protocol(line):
        return False
    if has_insecure_params(line):
        return False
    if is_dangerous_sni(line):
        return False
    if is_suspicious_host(line):
        return False
    if has_dangerous_transport_combination(line):
        return False

    if line.startswith('vless://'):
        return is_safe_vless(line)
    if line.startswith('trojan://'):
        return is_safe_trojan(line)
    if line.startswith('vmess://'):
        return is_safe_vmess(line)
    if line.startswith(('hysteria2://', 'hy2://')):
        return is_safe_hysteria2(line)
    if line.startswith('ss://'):
        return is_safe_ss(line)
    return True

# ---------- Парсинг многострочных конфигов ----------
def parse_multiline_configs(lines: List[str]) -> List[str]:
    configs = []
    current = ""
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if is_supported_protocol(stripped):
            if current:
                configs.append(current)
            current = stripped
        else:
            if current:
                current += stripped
    if current:
        configs.append(current)
    return configs

def fetch_url(url: str) -> Optional[str]:
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=15) as resp:
            content = resp.read().decode('utf-8', errors='ignore')
            if re.fullmatch(r'^[A-Za-z0-9+/=\s]+$', content.strip()):
                try:
                    decoded = base64.b64decode(content.strip()).decode('utf-8', errors='ignore')
                    if any(proto in decoded for proto in SUPPORTED_PROTOCOLS):
                        return decoded
                except:
                    pass
            return content
    except Exception as e:
        print(f"  Ошибка загрузки {url}: {e}")
        return None

def load_and_filter(source: Dict) -> Set[str]:
    name = source['name']
    print(f"  [{name}] Загрузка...")
    content = fetch_url(source['url'])
    if not content:
        return set()
    lines = content.splitlines()
    lines = [line.strip() for line in lines if line.strip() and not line.strip().startswith('#')]
    raw_configs = parse_multiline_configs(lines)

    # Предварительная фильтрация (базовая безопасность)
    pre_filtered = []
    for cfg in raw_configs:
        if is_safe_config_base(cfg):
            pre_filtered.append(cfg)

    # Подсчёт частоты pbk и uuid среди предварительно отфильтрованных
    pbk_count = defaultdict(int)
    uuid_count = defaultdict(int)
    config_pbk = {}
    config_uuid = {}
    for cfg in pre_filtered:
        pbk = extract_pbk(cfg)
        if pbk:
            config_pbk[cfg] = pbk
            pbk_count[pbk] += 1
        uuid = extract_uuid(cfg)
        if uuid:
            config_uuid[cfg] = uuid
            uuid_count[uuid] += 1

    # Финальная фильтрация: отбрасываем конфиги с слишком частыми pbk (>3) или uuid (>2)
    # Параметры можно вынести в константы
    PBK_MAX_REPEAT = 3
    UUID_MAX_REPEAT = 2
    final_filtered = set()
    for cfg in pre_filtered:
        pbk = config_pbk.get(cfg)
        uuid = config_uuid.get(cfg)
        if pbk and pbk_count[pbk] > PBK_MAX_REPEAT:
            continue
        if uuid and uuid_count[uuid] > UUID_MAX_REPEAT:
            continue
        final_filtered.add(cfg)

    return final_filtered

# ---------- Сортировка по протоколам ----------
def protocol_priority(uri: str) -> int:
    if uri.startswith('vless://'):
        return 1
    if uri.startswith('trojan://'):
        return 2
    if uri.startswith('vmess://'):
        return 3
    if uri.startswith(('hysteria2://', 'hy2://')):
        return 4
    if uri.startswith('ss://'):
        return 5
    return 6

def main():
    print("=== Финальный фильтр прокси (с защитой от общих pbk/uuid и опасных доменов) ===")
    all_filtered = set()
    with ThreadPoolExecutor(max_workers=5) as ex:
        futures = {ex.submit(load_and_filter, src): src for src in SOURCES_CONFIG}
        for future in as_completed(futures):
            src = futures[future]
            name = src['name']
            try:
                configs = future.result()
                out = os.path.join(OUTPUT_DIR, f"{name}.txt")
                sorted_cfg = sorted(configs, key=lambda u: (protocol_priority(u), u))
                with open(out, 'w', encoding='utf-8', newline='\n') as f:
                    f.write('\n'.join(sorted_cfg))
                    if sorted_cfg:
                        f.write('\n')
                print(f"  Сохранён {name}.txt → {len(configs)} конфигов")
                all_filtered.update(configs)
            except Exception as e:
                print(f"  [{name}] Ошибка: {e}")

    all_file = os.path.join(OUTPUT_DIR, "ALL.txt")
    sorted_all = sorted(all_filtered, key=lambda u: (protocol_priority(u), u))
    with open(all_file, 'w', encoding='utf-8', newline='\n') as f:
        f.write('\n'.join(sorted_all))
        if sorted_all:
            f.write('\n')
    print(f"\n✅ Создан ALL.txt с {len(all_filtered)} уникальными конфигами")

if __name__ == "__main__":
    main()
