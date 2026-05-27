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
    {"name": "FILTER-1", "url": "https://raw.githubusercontent.com/VAL41K/bypass-rkn-blocks/refs/heads/main/configs/obhod_WL"},
    {"name": "FILTER-2", "url": "https://github.com/AvenCores/goida-vpn-configs/raw/refs/heads/main/githubmirror/26.txt"},
    {"name": "FILTER-3", "url": "https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_universal.txt"},
    {"name": "FILTER-4", "url": "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-all.txt"},
    {"name": "FILTER-5", "url": "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt"}
]

# ---------- РАСШИРЕННЫЙ ЧЁРНЫЙ СПИСОК ДОМЕНОВ (SNI и хост) ----------
BANNED_DOMAINS = [
    # Бесплатные / временные домены
    '.fly.dev', '.workers.dev', '.us.kg', '.xyz', '.work', '.site', '.click',
    '.eu.org', '.tk', '.ml', '.cf', '.ga', '.gq', '.mwscdn.ru',
    # Проблемные зоны и конкретные домены
    '.alexandroff.ru', '.qzz.io', '.dynu.net', '.grovpn.com.alexandroff.ru',
    'trahodrom.fun', 'persik.host', 'skysafe.online', 'cdn.trahodrom.fun',
    'rruu.persik.host', 'pol.skysafe.online', 'boot-lee.ru', 'locklance.lol',
    'xenovpn.top', 'towersflowerss.com', 'vepene.site', 'cloudconsole.ru',
    'moscow-neversleep.digital', 'amnesia.pw', 'magicvpssub.ru',
    'fromblancwithlove.com', 'Koma-YT.PAGeS.Dev', 'ripaojiedian',
    'gpt-plus.vepene.site'
]

# ---------- Глобальные небезопасные параметры (encryption=none удалён) ----------
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

# ---------- Проверка запрещённых доменов в SNI и хосте ----------
def is_dangerous_sni(url: str) -> bool:
    sni_match = re.search(r'[?&]sni=([^&]+)', url, re.I)
    if not sni_match:
        return False
    sni = sni_match.group(1).lower()
    for domain in BANNED_DOMAINS:
        if domain in sni:
            return True
    return False

def is_banned_host(url: str) -> bool:
    """Проверяет, содержит ли хост (IP или домен) запрещённый домен."""
    host_match = re.search(r'vless://[^@]+@([^:?]+)', url)
    if not host_match:
        host_match = re.search(r'trojan://[^@]+@([^:?]+)', url)
    if not host_match:
        return False
    host = host_match.group(1).lower()
    for domain in BANNED_DOMAINS:
        if domain in host:
            return True
    # Особый случай: IP.домен (например, 138.124.125.83.alexandroff.ru)
    if re.match(r'^\d+\.\d+\.\d+\.\d+\.[a-zA-Z]', host):
        return True
    return False

# ---------- Опасные комбинации (исправлено: type=raw всегда блокируется) ----------
def has_dangerous_transport_combination(url: str) -> bool:
    type_match = re.search(r'[?&]type=([^&]+)', url, re.I)
    if not type_match:
        return False
    transport = type_match.group(1).lower()
    # Блокируем type=raw всегда
    if transport == 'raw':
        return True
    # type=raw + flow=xtls-rprx-vision (уже не нужно отдельно, но оставим для страховки)
    flow_match = re.search(r'[?&]flow=([^&]+)', url, re.I)
    if transport == 'raw' and flow_match and 'xtls-rprx-vision' in flow_match.group(1).lower():
        return True
    # type=xhttp без host
    if transport == 'xhttp':
        if '&host=' not in url and '?host=' not in url:
            return True
    return False

def is_suspicious_encryption(url: str) -> bool:
    enc_match = re.search(r'[?&]encryption=([^&]+)', url, re.I)
    if enc_match and 'mlkem' in enc_match.group(1).lower():
        return True
    return False

def is_trojan_public_pool(url: str) -> bool:
    if not url.startswith('trojan://'):
        return False
    markers = ['Koma-YT.PAGeS.Dev', 'ripaojiedian', 't.me/ripaojiedian', 'trTelegram']
    for m in markers:
        if m in url:
            return True
    path_match = re.search(r'[?&]path=([^&]+)', url, re.I)
    if path_match and 'trTelegram' in path_match.group(1):
        return True
    return False

def is_dangerous_uuid(url: str) -> bool:
    if 'localhost' in url:
        return True
    return False

# ---------- Извлечение идентификаторов ----------
def extract_pbk(url: str) -> Optional[str]:
    pbk_match = re.search(r'[?&]pbk=([^&]+)', url, re.I)
    return pbk_match.group(1) if pbk_match else None

def extract_uuid(url: str) -> Optional[str]:
    uuid_match = re.search(r'vless://([a-f0-9-]+)@', url, re.I)
    return uuid_match.group(1).lower() if uuid_match else None

def extract_sid(url: str) -> Optional[str]:
    sid_match = re.search(r'[?&]sid=([^&]+)', url, re.I)
    return sid_match.group(1) if sid_match else None

def extract_trojan_password(url: str) -> Optional[str]:
    if not url.startswith('trojan://'):
        return None
    pass_match = re.search(r'trojan://([^@]+)@', url, re.I)
    return pass_match.group(1) if pass_match else None

# ---------- Базовые проверки протоколов ----------
def is_safe_vless_base(url: str) -> bool:
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

def is_safe_trojan_base(url: str) -> bool:
    if not url.startswith('trojan://'):
        return False
    if 'sni=' not in url:
        return False
    if is_trojan_public_pool(url):
        return False
    return True

def is_safe_vmess_base(url: str) -> bool:
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

def is_safe_hysteria2_base(url: str) -> bool:
    return url.startswith(('hysteria2://', 'hy2://'))

def is_safe_ss_base(url: str) -> bool:
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
    line = line.strip()
    if not line or not is_supported_protocol(line):
        return False
    if has_insecure_params(line):
        return False
    if is_dangerous_sni(line):
        return False
    if is_banned_host(line):
        return False
    if has_dangerous_transport_combination(line):
        return False
    if is_suspicious_encryption(line):
        return False
    if is_dangerous_uuid(line):
        return False

    if line.startswith('vless://'):
        return is_safe_vless_base(line)
    if line.startswith('trojan://'):
        return is_safe_trojan_base(line)
    if line.startswith('vmess://'):
        return is_safe_vmess_base(line)
    if line.startswith(('hysteria2://', 'hy2://')):
        return is_safe_hysteria2_base(line)
    if line.startswith('ss://'):
        return is_safe_ss_base(line)
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

    # Предварительная фильтрация
    pre_filtered = []
    for cfg in raw_configs:
        if is_safe_config_base(cfg):
            pre_filtered.append(cfg)

    # Подсчёт статистики повторяющихся идентификаторов
    pbk_count = defaultdict(int)
    uuid_count = defaultdict(int)
    sid_count = defaultdict(int)
    trojan_pass_count = defaultdict(int)
    config_pbk = {}
    config_uuid = {}
    config_sid = {}
    config_trojan_pass = {}

    for cfg in pre_filtered:
        pbk = extract_pbk(cfg)
        if pbk:
            config_pbk[cfg] = pbk
            pbk_count[pbk] += 1
        uuid = extract_uuid(cfg)
        if uuid:
            config_uuid[cfg] = uuid
            uuid_count[uuid] += 1
        sid = extract_sid(cfg)
        if sid:
            config_sid[cfg] = sid
            sid_count[sid] += 1
        if cfg.startswith('trojan://'):
            pwd = extract_trojan_password(cfg)
            if pwd:
                config_trojan_pass[cfg] = pwd
                trojan_pass_count[pwd] += 1

    # Пороги отбраковки
    PBK_MAX_REPEAT = 2      # >2 – отбрасываем
    UUID_MAX_REPEAT = 2
    SID_MAX_REPEAT = 2
    TROJAN_PASS_MAX_REPEAT = 2

    final_filtered = set()
    for cfg in pre_filtered:
        pbk = config_pbk.get(cfg)
        uuid = config_uuid.get(cfg)
        sid = config_sid.get(cfg)
        tpass = config_trojan_pass.get(cfg)
        if pbk and pbk_count[pbk] > PBK_MAX_REPEAT:
            continue
        if uuid and uuid_count[uuid] > UUID_MAX_REPEAT:
            continue
        if sid and sid_count[sid] > SID_MAX_REPEAT:
            continue
        if tpass and trojan_pass_count[tpass] > TROJAN_PASS_MAX_REPEAT:
            continue
        final_filtered.add(cfg)

    return final_filtered

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
    print("=== Финальный фильтр прокси (блокировка type=raw + расширенные чёрные списки) ===")
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
