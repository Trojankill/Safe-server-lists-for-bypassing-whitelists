#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import os
import json
import base64
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
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

def is_supported_protocol(line: str) -> bool:
    line = line.strip()
    for proto in SUPPORTED_PROTOCOLS:
        if line.startswith(proto):
            return True
    return False

def has_insecure_params(line: str) -> bool:
    return bool(UNSAFE_REGEX.search(line))

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
        net = cfg.get('net', 'tcp')
        if net not in ('tcp', 'ws', 'grpc', 'http'):
            return False
        return True
    except Exception:
        return False

def is_safe_trojan(url: str) -> bool:
    if not url.startswith('trojan://'):
        return False
    if 'sni=' not in url:
        return False
    if 'flow=' in url:
        flow_match = re.search(r'[?&]flow=([^&]+)', url, re.I)
        if flow_match and flow_match.group(1).lower() == 'none':
            return False
    if 'security=none' in url:
        return False
    return True

def is_safe_vless(url: str) -> bool:
    if not url.startswith('vless://'):
        return False
    if re.search(r'security=reality|pbk=', url, re.I):
        return True
    if 'security=tls' in url and 'encryption=none' in url and ('sni=' in url or 'alpn=' in url):
        return True
    return False

def is_safe_hysteria2(url: str) -> bool:
    if not url.startswith(('hysteria2://', 'hy2://')):
        return False
    if re.search(r'insecure=1|insecure=true|allowInsecure=1', url, re.I):
        return False
    return True

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

def is_safe_config(line: str) -> bool:
    line = line.strip()
    if not line or not is_supported_protocol(line):
        return False
    if has_insecure_params(line):
        return False

    if line.startswith('vmess://'):
        return is_safe_vmess(line)
    if line.startswith('trojan://'):
        return is_safe_trojan(line)
    if line.startswith('vless://'):
        return is_safe_vless(line)
    if line.startswith(('hysteria2://', 'hy2://')):
        return is_safe_hysteria2(line)
    if line.startswith('ss://'):
        return is_safe_ss(line)
    return True

def parse_multiline_configs(lines: List[str]) -> List[str]:
    """Собирает целые конфиги из разорванных строк."""
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
            # Если содержимое похоже на base64, декодируем (для поддержки некоторых подписок)
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

def load_and_filter(source: Dict) -> Tuple[Set[str], List[str]]:
    """
    Возвращает (множество отфильтрованных конфигов, список всех собранных сырых конфигов).
    """
    name = source['name']
    print(f"  [{name}] Загрузка...")
    content = fetch_url(source['url'])
    if not content:
        return set(), []

    lines = content.splitlines()
    # Убираем комментарии и пустые строки
    lines = [line.strip() for line in lines if line.strip() and not line.strip().startswith('#')]

    raw_configs = parse_multiline_configs(lines)

    valid = set()
    for cfg in raw_configs:
        if is_safe_config(cfg):
            valid.add(cfg)
    return valid, raw_configs

def main():
    print("=== Фильтр подписок (с дополнительным UNFILTER-3 для отладки) ===")
    all_filtered = set()
    with ThreadPoolExecutor(max_workers=5) as ex:
        futures = {ex.submit(load_and_filter, src): src for src in SOURCES_CONFIG}
        for future in as_completed(futures):
            src = futures[future]
            name = src['name']
            try:
                filtered, raw = future.result()
                # Сохраняем отфильтрованные
                out = os.path.join(OUTPUT_DIR, f"{name}.txt")
                with open(out, 'w', encoding='utf-8', newline='\n') as f:
                    f.write('\n'.join(sorted(filtered)))
                    if filtered:
                        f.write('\n')
                print(f"  Сохранён {name}.txt → {len(filtered)} конфигов")
                all_filtered.update(filtered)

                # Для FILTER-3 дополнительно сохраняем нефильтрованные в UNFILTER-3.txt
                if name == "FILTER-3":
                    unfiltered_path = os.path.join(OUTPUT_DIR, "UNFILTER-3.txt")
                    with open(unfiltered_path, 'w', encoding='utf-8', newline='\n') as f:
                        f.write('\n'.join(raw))
                        if raw:
                            f.write('\n')
                    print(f"  Сохранён UNFILTER-3.txt → {len(raw)} сырых конфигов (без фильтрации)")
            except Exception as e:
                print(f"  [{name}] Ошибка: {e}")

    # Общий ALL.txt
    all_file = os.path.join(OUTPUT_DIR, "ALL.txt")
    with open(all_file, 'w', encoding='utf-8', newline='\n') as f:
        f.write('\n'.join(sorted(all_filtered)))
        if all_filtered:
            f.write('\n')
    print(f"\n✅ Создан ALL.txt с {len(all_filtered)} уникальными конфигами")

if __name__ == "__main__":
    main()
