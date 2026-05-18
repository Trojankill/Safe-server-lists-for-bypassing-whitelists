#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import os
import json
import base64
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Set, Dict, Optional

# ============================================================
# 1. НАСТРОЙКИ
# ============================================================
OUTPUT_DIR = "githubmirror"
os.makedirs(OUTPUT_DIR, exist_ok=True)

SUPPORTED_PROTOCOLS = [
    "vless://", "vmess://", "trojan://", "hysteria2://", "hy2://", "ss://"
]

SOURCES_CONFIG = [
    {"name": "FILTER-1", "url": "https://gist.githubusercontent.com/flaafix/c79a81037d15163360571c7a7331b153/raw/AetrisVPN.txt"},
    {"name": "FILTER-2", "url": "https://github.com/AvenCores/goida-vpn-configs/raw/refs/heads/main/githubmirror/26.txt"},
    {"name": "FILTER-3", "url": "https://raw.githubusercontent.com/zieng2/wl/main/vless_lite.txt"},
    {"name": "FILTER-4", "url": "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-all.txt"},
    {"name": "FILTER-5", "url": "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt"}
]

# Расширенный набор небезопасных параметров для фильтрации.
# Добавлен флаг 'tls13' и синонимы insecure.
UNSAFE_PATTERNS = [
    # Основные флаги безопасности
    r'[&?]allowinsecure=1', r'[&?]allowinsecure=true',
    r'[&?]insecure=1', r'[&?]insecure=true',
    r'[&?]security=none',
    r'[&?]verify=0', r'[&?]verify=false',
    r'[&?]skip-cert-verify=0', r'[&?]skip-cert-verify=false',
    r'[&?]encryption=none',
    r'[&?]allowinsecurecipher=1', r'[&?]allowinsecurecipher=true',
    r'[&?]flow=none',
    # Современная проверка: блокировка принудительного использования устаревшей версии TLS 1.2
    r'[&?]tls13=0', r'[&?]tls13=false',
]
UNSAFE_REGEX = re.compile('|'.join(UNSAFE_PATTERNS), re.IGNORECASE)

# ============================================================
# ФУНКЦИИ ПРОВЕРКИ БЕЗОПАСНОСТИ (IS_SAFE_*)
# ============================================================

def is_supported_protocol(line: str) -> bool:
    """Проверка, начинается ли строка с поддерживаемого протокола."""
    line = line.strip()
    for proto in SUPPORTED_PROTOCOLS:
        if line.startswith(proto):
            return True
    return False

def has_insecure_params(line: str) -> bool:
    """Проверка строки на наличие небезопасных параметров (allowInsecure, security=none и т.д.)."""
    return bool(UNSAFE_REGEX.search(line))

def is_safe_vmess(url: str) -> bool:
    """
    Проверка VMess конфигурации.
    - Декодирует base64.
    - Убеждается, что alterId равен 0 (рекомендованный безопасный режим).
    - Проверяет, что TLS включен (tls != '').
    - Фильтрует устаревшие версии протокола (v != '2').
    """
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
        # Доп. проверка: блокировка устаревшей версии протокола (не '2')
        if cfg.get('v', '2') != '2':
            return False
        net = cfg.get('net', 'tcp')
        if net not in ('tcp', 'ws', 'grpc', 'http'):
            return False
        return True
    except Exception:
        return False

def is_safe_trojan(url: str) -> bool:
    """Проверка безопасности Trojan: требует наличие sni и отсутствие небезопасных флагов."""
    if not url.startswith('trojan://'):
        return False
    # Trojан небезопасен без sni (даже если allowInsecure=0, отсутствие sni снижает обфускацию)
    if 'sni=' not in url:
        return False
    # Доп. проверка: если присутствует flow=none, отбрасываем
    if 'flow=' in url:
        flow_match = re.search(r'[?&]flow=([^&]+)', url, re.I)
        if flow_match and flow_match.group(1).lower() == 'none':
            return False
    if 'security=none' in url:
        return False
    return True

def is_safe_vless(url: str) -> bool:
    """Проверка безопасности VLESS: допустимы Reality и TLS с шифрованием, требуется sni или alpn."""
    if not url.startswith('vless://'):
        return False
    # Reality считается безопасным, вне зависимости от остальных параметров
    if re.search(r'security=reality|pbk=', url, re.I):
        return True
    # TLS допустим только с encryption=none и наличием sni или alpn
    if 'security=tls' in url and 'encryption=none' in url and ('sni=' in url or 'alpn=' in url):
        return True
    return False

def is_safe_hysteria2(url: str) -> bool:
    """Проверка безопасности Hysteria2: не должно быть флага insecure=1."""
    if not url.startswith(('hysteria2://', 'hy2://')):
        return False
    if re.search(r'insecure=1|insecure=true|allowInsecure=1', url, re.I):
        return False
    return True

def is_safe_ss(url: str) -> bool:
    """
    Проверка безопасности Shadowsocks.
    Проверяет, что шифрование (scy) не установлено в 'none'.
    """
    if not url.startswith('ss://'):
        return False
    # URL Shadowsocks имеет формат ss://method:password@host:port
    try:
        # Извлекаем часть с методом шифрования
        after_proto = url.replace('ss://', '', 1)
        if '@' not in after_proto:
            return False
        method_part = after_proto.split('@')[0]
        # Метод может быть как в явном виде, так и закодирован в base64
        if ':' in method_part:
            method = method_part.split(':')[0]
            if method.lower() == 'none':
                return False
    except Exception:
        return False
    return True

def is_safe_config(line: str) -> bool:
    """Основная функция, проверяющая конфигурацию по протоколу."""
    line = line.strip()
    if not line or not is_supported_protocol(line):
        return False
    if has_insecure_params(line):
        return False

    # Вызов специфичных для протокола проверок
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

# ============================================================
# ЗАГРУЗКА ДАННЫХ И ОСНОВНАЯ ЛОГИКА
# ============================================================

def fetch_url(url: str) -> Optional[str]:
    """Загрузка данных с поддержкой base64-кодированных подписок."""
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=15) as resp:
            content = resp.read().decode('utf-8', errors='ignore')
            # Автоматическое декодирование base64, если содержимое не содержит символов протокола
            if re.fullmatch(r'^[A-Za-z0-9+/=\s]+$', content.strip()):
                try:
                    decoded = base64.b64decode(content.strip()).decode('utf-8', errors='ignore')
                    # Проверка, что декодированные данные выглядят как список URL
                    if any(proto in decoded for proto in SUPPORTED_PROTOCOLS):
                        return decoded
                except Exception:
                    pass
            return content
    except Exception as e:
        print(f"  Ошибка загрузки {url}: {e}")
        return None

def load_and_filter(source: Dict) -> Set[str]:
    """Загрузка и фильтрация одного источника."""
    name = source['name']
    print(f"  [{name}] Загрузка...")
    content = fetch_url(source['url'])
    if not content:
        return set()
    configs = set()
    for line in content.splitlines():
        line = line.strip()
        if line and not line.startswith('#') and is_safe_config(line):
            configs.add(line)
    return configs

def main():
    print("=== Универсальный фильтр подписок (VMess, VLESS, Trojan, Hysteria2, Shadowsocks) ===")
    all_configs = set()
    with ThreadPoolExecutor(max_workers=5) as ex:
        futures = {ex.submit(load_and_filter, src): src for src in SOURCES_CONFIG}
        for future in as_completed(futures):
            src = futures[future]
            try:
                configs = future.result()
                out = os.path.join(OUTPUT_DIR, f"{src['name']}.txt")
                with open(out, 'w', encoding='utf-8', newline='\n') as f:
                    f.write('\n'.join(sorted(configs)))
                    if configs:
                        f.write('\n')
                print(f"  Сохранён {src['name']}.txt → {len(configs)} конфигов")
                all_configs.update(configs)
            except Exception as e:
                print(f"  [{src['name']}] Ошибка: {e}")
    all_file = os.path.join(OUTPUT_DIR, "ALL.txt")
    with open(all_file, 'w', encoding='utf-8', newline='\n') as f:
        f.write('\n'.join(sorted(all_configs)))
        if all_configs:
            f.write('\n')
    print(f"\n✅ Создан ALL.txt с {len(all_configs)} уникальными конфигами")

if __name__ == "__main__":
    main()
