#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Фильтр прокси-конфигураций v3.1 + QR
Строгая проверка. URL Health + авто-очистка. SS 2022 key validation.
SSR. Hysteria v1. QR-коды для подписки и отдельных конфигов.
"""

import re
import os
import json
import base64
import time
import hashlib
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
from functools import lru_cache
from typing import Set, Dict, Optional, List, Tuple

# =====================================================================
#  КОНСТАНТЫ
# =====================================================================

OUTPUT_DIR = "githubmirror"
HEALTH_FILE = os.path.join(OUTPUT_DIR, "url_health.json")
REJECT_DIR = os.path.join(OUTPUT_DIR, "rejected")
QR_DIR = os.path.join(OUTPUT_DIR, "QR-CODE")
QR_CONFIGS_DIR = os.path.join(QR_DIR, "configs")

os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(REJECT_DIR, exist_ok=True)

MAX_CONSECUTIVE_FAILURES = 3
MAX_QR_CONFIGS = 200  # максимум QR для отдельных конфигов

# ⚠️ ЗАМЕНИ на свой логин и репо!
SUBSCRIPTION_URL = "https://raw.githubusercontent.com/USERNAME/REPO/main/githubmirror/ALL.txt"

SUPPORTED_PROTOCOLS = [
    "vless://", "vmess://", "trojan://",
    "hysteria2://", "hy2://", "hysteria://",
    "ss://", "ssr://",
]

SOURCES_CONFIG = [
    {"name": "FILTER-1", "url": "https://raw.githubusercontent.com/VAL41K/bypass-rkn-blocks/refs/heads/main/configs/obhod_WL"},
    {"name": "FILTER-2", "url": "https://github.com/AvenCores/goida-vpn-configs/raw/refs/heads/main/githubmirror/26.txt"},
    {"name": "FILTER-3", "url": "https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_universal.txt"},
    {"name": "FILTER-4", "url": "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-all.txt"},
    {"name": "FILTER-5", "url": "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt"},
]

# ---------- ЧЁРНЫЙ СПИСОК ДОМЕНОВ ----------
BANNED_DOMAINS = [
    '.fly.dev', '.workers.dev', '.us.kg', '.xyz', '.work', '.site', '.click',
    '.eu.org', '.tk', '.ml', '.cf', '.ga', '.gq', '.mwscdn.ru',
    '.alexandroff.ru', '.qzz.io', '.dynu.net', '.grovpn.com.alexandroff.ru',
    'trahodrom.fun', 'persik.host', 'skysafe.online', 'cdn.trahodrom.fun',
    'rruu.persik.host', 'pol.skysafe.online', 'boot-lee.ru', 'locklance.lol',
    'xenovpn.top', 'towersflowerss.com', 'vepene.site', 'cloudconsole.ru',
    'moscow-neversleep.digital', 'amnesia.pw', 'magicvpssub.ru',
    'fromblancwithlove.com', 'koma-yt.pages.dev', 'ripaojiedian',
    'gpt-plus.vepene.site',
]

# ---------- ШИФРЫ SS (расширенные) ----------
SAFE_SS_METHODS = {
    'aes-128-gcm', 'aes-256-gcm',
    'chacha20-poly1305', 'chacha20-ietf-poly1305',
    'xchacha20-poly1305', 'xchacha20-ietf-poly1305',
    '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm',
    '2022-blake3-chacha20-poly1305',
}

WEAK_SS_METHODS = {
    'rc4', 'rc4-md5', 'rc4-md5-6',
    'des', 'des-cfb', 'bf-cfb', 'cast5-cfb',
    'salsa20', 'xsalsa20', 'chacha20', 'xchacha20',
    'aes-128-cfb', 'aes-192-cfb', 'aes-256-cfb',
    'aes-128-cfb8', 'aes-192-cfb8', 'aes-256-cfb8',
    'aes-128-cfb1', 'aes-192-cfb1', 'aes-256-cfb1',
    'aes-128-cfb-fast', 'aes-192-cfb-fast', 'aes-256-cfb-fast',
    'aes-128-cfb-simple', 'aes-192-cfb-simple', 'aes-256-cfb-simple',
    'aes-128-ctr', 'aes-192-ctr', 'aes-256-ctr',
    'camellia-128-cfb', 'camellia-192-cfb', 'camellia-256-cfb',
    'seed-cfb', 'idea-cfb', 'rc2-cfb',
    'none', '',
}

# ---------- SS 2022: ожидаемая длина ключа ----------
_SS_2022_KEY_LENGTHS = {
    '2022-blake3-aes-128-gcm': 16,
    '2022-blake3-aes-256-gcm': 32,
    '2022-blake3-chacha20-poly1305': 32,
}

# ---------- FINGERPRINTS ----------
SAFE_FINGERPRINTS = {
    'chrome', 'firefox', 'safari', 'ios', 'android',
    'edge', '360', 'qq', 'random', 'randomized',
}

# ---------- НЕБЕЗОПАСНЫЕ ПАРАМЕТРЫ ----------
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


# =====================================================================
#  SS 2022 KEY VALIDATION
# =====================================================================

def _check_ss_2022_key(method: str, password: str) -> bool:
    """True если ключ НЕВАЛИДНЫЙ. Multi-key (key1:key2) пропускаем."""
    method_lower = method.lower().strip()
    expected_len = _SS_2022_KEY_LENGTHS.get(method_lower)
    if expected_len is None:
        return False
    if ':' in password:
        return False
    try:
        rem = len(password) % 4
        padded = password + '=' * (4 - rem) if rem else password
        decoded = base64.b64decode(padded)
        if len(decoded) != expected_len:
            return True
    except (ValueError, TypeError):
        pass
    return False


# =====================================================================
#  БАЗОВЫЕ ПРОВЕРКИ
# =====================================================================

def is_supported_protocol(line: str) -> bool:
    line = line.strip()
    return any(line.startswith(p) for p in SUPPORTED_PROTOCOLS)


def has_insecure_params(line: str) -> bool:
    return bool(UNSAFE_REGEX.search(line))


def is_dangerous_domain_param(url: str) -> bool:
    for param in ('sni', 'host'):
        match = re.search(rf'[?&]{param}=([^&]+)', url, re.I)
        if match:
            value = match.group(1).lower()
            for domain in BANNED_DOMAINS:
                if domain in value:
                    return True
    return False


def is_banned_host(url: str) -> bool:
    host_match = re.search(r'(?:vless|trojan)://[^@]+@([^:?]+)', url, re.I)
    if not host_match:
        return False
    host = host_match.group(1).lower()
    for domain in BANNED_DOMAINS:
        if domain in host:
            return True
    if re.match(r'^\d+\.\d+\.\d+\.\d+\.[a-zA-Z]', host):
        return True
    if re.match(r'^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|0\.0\.0\.0|::1|localhost)', host):
        return True
    return False


def has_dangerous_transport_combination(url: str) -> bool:
    type_match = re.search(r'[?&]type=([^&]+)', url, re.I)
    if not type_match:
        return False
    transport = type_match.group(1).lower()
    security_match = re.search(r'[?&]security=([^&]+)', url, re.I)
    security = security_match.group(1).lower() if security_match else ''
    if transport == 'raw' and security in ('', 'none'):
        return True
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
    markers = ['koma-yt.pages.dev', 'ripaojiedian', 't.me/ripaojiedian', 'trtelegram']
    lower = url.lower()
    for m in markers:
        if m in lower:
            return True
    path_match = re.search(r'[?&]path=([^&]+)', url, re.I)
    if path_match and 'trtelegram' in path_match.group(1).lower():
        return True
    return False


def is_dangerous_uuid(url: str) -> bool:
    lower = url.lower()
    if 'localhost' in lower:
        return True
    if re.search(r'@(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|0\.0\.0\.0|::1)', lower):
        return True
    return False


# =====================================================================
#  ИЗВЛЕЧЕНИЕ ИДЕНТИФИКАТОРОВ
# =====================================================================

def extract_pbk(url: str) -> Optional[str]:
    m = re.search(r'[?&]pbk=([^&]+)', url, re.I)
    return m.group(1) if m else None


def extract_uuid(url: str) -> Optional[str]:
    m = re.search(r'vless://([a-f0-9-]+)@', url, re.I)
    return m.group(1).lower() if m else None


def extract_sid(url: str) -> Optional[str]:
    m = re.search(r'[?&]sid=([^&]+)', url, re.I)
    return m.group(1) if m else None


def extract_trojan_password(url: str) -> Optional[str]:
    if not url.startswith('trojan://'):
        return None
    m = re.search(r'trojan://([^@]+)@', url, re.I)
    return m.group(1) if m else None


# =====================================================================
#  СТРОГИЕ ПРОВЕРКИ ПРОТОКОЛОВ
# =====================================================================

def is_safe_vless_base(url: str) -> bool:
    if not url.startswith('vless://'):
        return False
    security_match = re.search(r'[?&]security=([^&]*)', url, re.I)
    security = security_match.group(1).lower() if security_match else ''
    type_match = re.search(r'[?&]type=([^&]*)', url, re.I)
    transport = type_match.group(1).lower() if type_match else ''

    if not security or security == 'none':
        return False

    if security == 'reality':
        if not re.search(r'[?&]pbk=[^&]+', url, re.I):
            return False
        fp_match = re.search(r'[?&]fp=([^&]+)', url, re.I)
        if not fp_match:
            return False
        if fp_match.group(1).lower() not in SAFE_FINGERPRINTS:
            return False
        flow_match = re.search(r'[?&]flow=([^&]+)', url, re.I)
        if flow_match:
            flow = flow_match.group(1).lower()
            if flow not in ('xtls-rprx-vision', 'none', ''):
                return False
        return True

    if security == 'tls':
        if transport not in ('ws', 'grpc', 'http', 'tcp'):
            return False
        if not re.search(r'[?&]sni=[^&]+', url, re.I):
            return False
        if transport in ('ws', 'http'):
            if not re.search(r'[?&]host=[^&]+', url, re.I):
                return False
        alpn_match = re.search(r'[?&]alpn=([^&]+)', url, re.I)
        if not alpn_match:
            return False
        alpn = alpn_match.group(1).lower()
        if 'h2' not in alpn and 'http/1.1' not in alpn:
            return False
        return True

    return False


def is_safe_trojan_base(url: str) -> bool:
    if not url.startswith('trojan://'):
        return False
    if not re.search(r'[?&]sni=[^&]+', url, re.I):
        return False
    if is_trojan_public_pool(url):
        return False
    if is_dangerous_domain_param(url):
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
        if cfg.get('allowInsecure', False):
            return False
        if str(cfg.get('v', '2')) != '2':
            return False

        net = cfg.get('net', 'tcp').lower()
        if net not in ('ws', 'grpc', 'http', 'tcp'):
            return False
        if net in ('ws', 'http') and not cfg.get('host'):
            return False

        for field in ('add', 'sni', 'host'):
            val = cfg.get(field, '').lower()
            for domain in BANNED_DOMAINS:
                if domain in val:
                    return False

        add = cfg.get('add', '').lower()
        if re.match(r'^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|0\.0\.0\.0|::1|localhost)', add):
            return False

        return True
    except Exception:
        return False


def is_safe_hysteria2_base(url: str) -> bool:
    if not url.startswith(('hysteria2://', 'hy2://')):
        return False
    if re.search(r'[?&]insecure=1', url, re.I):
        return False
    if not re.search(r'[?&]sni=[^&]+', url, re.I):
        return False
    pass_match = re.search(r'(?:hysteria2|hy2)://([^@]*)@', url, re.I)
    if pass_match and not pass_match.group(1).strip():
        return False
    return True


def is_safe_hysteria1_base(url: str) -> bool:
    if not url.startswith('hysteria://'):
        return False
    if re.search(r'[?&]insecure=1', url, re.I):
        return False
    if not re.search(r'[?&]sni=[^&]+', url, re.I):
        return False
    return True


def is_safe_ss_base(url: str) -> bool:
    if not url.startswith('ss://'):
        return False
    try:
        after_proto = url.replace('ss://', '', 1)
        if '#' in after_proto:
            after_proto = after_proto.split('#')[0]
        if '?' in after_proto:
            after_proto = after_proto.split('?')[0]
        if '@' not in after_proto:
            return False
        userinfo = after_proto.split('@')[0]

        if ':' not in userinfo:
            try:
                missing = len(userinfo) % 4
                if missing:
                    userinfo += '=' * (4 - missing)
                userinfo = base64.b64decode(userinfo).decode('utf-8', errors='ignore')
            except Exception:
                return False

        if ':' not in userinfo:
            return False
        method, password = userinfo.split(':', 1)
        method = method.lower().strip()
        password = password.strip()

        if not password:
            return False
        if method in WEAK_SS_METHODS or method not in SAFE_SS_METHODS:
            return False
        if _check_ss_2022_key(method, password):
            return False

    except Exception:
        return False
    return True


def is_safe_ssr_base(url: str) -> bool:
    if not url.startswith('ssr://'):
        return False
    try:
        payload = url[6:]
        rem = len(payload) % 4
        if rem:
            payload += '=' * (4 - rem)
        decoded = base64.b64decode(payload).decode('utf-8', errors='ignore')
        parts = decoded.split(':')
        if len(parts) < 6:
            return False
        method = parts[3].lower()
        if method in WEAK_SS_METHODS or method not in SAFE_SS_METHODS:
            return False
        password_part = parts[5].split('/')[0].strip()
        if not password_part:
            return False
        return True
    except Exception:
        return False


@lru_cache(maxsize=65536)
def is_safe_config_base(line: str) -> bool:
    line = line.strip()
    if not line or not is_supported_protocol(line):
        return False
    if has_insecure_params(line):
        return False
    if is_dangerous_domain_param(line):
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
    if line.startswith('hysteria://'):
        return is_safe_hysteria1_base(line)
    if line.startswith('ss://'):
        return is_safe_ss_base(line)
    if line.startswith('ssr://'):
        return is_safe_ssr_base(line)
    return False


# =====================================================================
#  ПАРСИНГ
# =====================================================================

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
            if current and ('?' in stripped or '&' in stripped or '=' in stripped):
                current += stripped
            elif current:
                configs.append(current)
                current = ""
    if current:
        configs.append(current)
    return configs


# =====================================================================
#  URL HEALTH
# =====================================================================

def load_health() -> Dict:
    if os.path.exists(HEALTH_FILE):
        try:
            with open(HEALTH_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def save_health(health: Dict):
    with open(HEALTH_FILE, 'w', encoding='utf-8') as f:
        json.dump(health, f, indent=2, ensure_ascii=False)


def fetch_url_with_health(url: str, health: Dict) -> Optional[str]:
    entry = health.get(url, {"failures": 0, "last_status": None, "last_check": None})

    if entry["failures"] >= MAX_CONSECUTIVE_FAILURES:
        print(f"  ⚠️  {url} — {entry['failures']} провалов подряд, пропускаем")
        return None

    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=15) as resp:
            content = resp.read().decode('utf-8', errors='ignore')

            entry["failures"] = 0
            entry["last_status"] = "ok"
            entry["last_check"] = time.strftime('%Y-%m-%d %H:%M:%S UTC')
            health[url] = entry

            stripped = re.sub(r'\s+', '', content.strip())
            if re.fullmatch(r'[A-Za-z0-9+/=]+', stripped):
                try:
                    decoded = base64.b64decode(stripped).decode('utf-8', errors='ignore')
                    if any(p in decoded for p in SUPPORTED_PROTOCOLS):
                        return decoded
                    stripped2 = re.sub(r'\s+', '', decoded.strip())
                    if re.fullmatch(r'[A-Za-z0-9+/=]+', stripped2):
                        decoded2 = base64.b64decode(stripped2).decode('utf-8', errors='ignore')
                        if any(p in decoded2 for p in SUPPORTED_PROTOCOLS):
                            return decoded2
                except Exception:
                    pass
            return content

    except Exception as e:
        entry["failures"] = entry.get("failures", 0) + 1
        entry["last_status"] = str(e)
        entry["last_check"] = time.strftime('%Y-%m-%d %H:%M:%S UTC')
        health[url] = entry
        print(f"  ❌ {url}: {e} (провал #{entry['failures']})")
        return None


def write_health_report(health: Dict, source_stats: Dict[str, Dict]):
    report_path = os.path.join(OUTPUT_DIR, "URL_HEALTH_REPORT.md")
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write("# URL Health Report\n\n")
        f.write(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC')}\n\n")
        f.write("| Source | Status | Fails | Raw | Filtered | Rejected | Last Check |\n")
        f.write("|---|---|---|---|---|---|---|\n")
        for src in SOURCES_CONFIG:
            url = src['url']
            name = src['name']
            entry = health.get(url, {})
            status = "✅" if entry.get("last_status") == "ok" else "❌"
            fails = entry.get("failures", 0)
            last = entry.get("last_check", "N/A")
            st = source_stats.get(url, {})
            raw = st.get("raw", "-")
            filt = st.get("filtered", "-")
            rej = st.get("rejected", "-")
            f.write(f"| {name} | {status} | {fails} | {raw} | {filt} | {rej} | {last} |\n")
        f.write(f"\n**Авто-очистка:** URL с {MAX_CONSECUTIVE_FAILURES}+ провалами подряд пропускаются.\n")


# =====================================================================
#  QR-CODE ГЕНЕРАЦИЯ
# =====================================================================

PROTO_NAMES = {
    'vless://': 'vless',
    'trojan://': 'trojan',
    'vmess://': 'vmess',
    'hysteria2://': 'hy2',
    'hy2://': 'hy2',
    'hysteria://': 'hy1',
    'ss://': 'ss',
    'ssr://': 'ssr',
}


def generate_qr_codes(configs: List[str]):
    try:
        import qrcode
        from qrcode.constants import ERROR_CORRECT_M
    except ImportError:
        print("  ⚠️  qrcode не установлен. pip install qrcode[pil]")
        return

    os.makedirs(QR_CONFIGS_DIR, exist_ok=True)

    # 1. QR подписки
    sub_qr = qrcode.QRCode(version=None, error_correction=ERROR_CORRECT_M, box_size=10, border=4)
    sub_qr.add_data(SUBSCRIPTION_URL)
    sub_qr.make(fit=True)
    img = sub_qr.make_image(fill_color="black", back_color="white")
    img.save(os.path.join(QR_DIR, "subscription.png"))
    print(f"  📱 QR подписки: {QR_DIR}/subscription.png")

    # 2. QR для отдельных конфигов (с лимитом)
    limited = configs[:MAX_QR_CONFIGS]
    for i, cfg in enumerate(limited, 1):
        proto_label = 'unknown'
        for prefix, label in PROTO_NAMES.items():
            if cfg.startswith(prefix):
                proto_label = label
                break
        cfg_hash = hashlib.md5(cfg.encode()).hexdigest()[:8]
        filename = f"{i:04d}_{proto_label}_{cfg_hash}.png"
        filepath = os.path.join(QR_CONFIGS_DIR, filename)

        qr = qrcode.QRCode(version=None, error_correction=ERROR_CORRECT_M, box_size=8, border=3)
        qr.add_data(cfg)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        img.save(filepath)

    print(f"  📱 QR конфигов: {len(limited)} шт. → {QR_CONFIGS_DIR}/")

    # 3. HTML-индекс
    _generate_qr_index(limited)


def _generate_qr_index(configs: List[str]):
    index_path = os.path.join(QR_DIR, "index.html")
    with open(index_path, 'w', encoding='utf-8') as f:
        f.write("""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>QR-коды прокси</title>
<style>
  body { font-family: system-ui, sans-serif; background: #1a1a2e; color: #eee; margin: 20px; }
  h1 { text-align: center; color: #00d4ff; }
  .sub-qr { text-align: center; margin: 30px 0; }
  .sub-qr img { width: 300px; height: 300px; border: 4px solid #00d4ff; border-radius: 12px; }
  .sub-qr p { color: #aaa; font-size: 14px; }
  .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(220px, 1fr)); gap: 16px; margin-top: 30px; }
  .card { background: #16213e; border-radius: 10px; padding: 12px; text-align: center; }
  .card img { width: 180px; height: 180px; border-radius: 6px; }
  .card .label { font-size: 12px; color: #888; margin-top: 8px; word-break: break-all; }
  .card .proto { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: bold; margin-bottom: 6px; }
  .proto-vless { background: #e94560; }
  .proto-trojan { background: #0f3460; }
  .proto-vmess { background: #533483; }
  .proto-hy2 { background: #e94560; }
  .proto-hy1 { background: #e94560; }
  .proto-ss { background: #0f3460; }
  .proto-ssr { background: #533483; }
</style>
</head>
<body>
<h1>📱 QR-коды прокси</h1>
<div class="sub-qr">
  <img src="subscription.png" alt="Subscription QR">
  <p>Отсканируй для добавления <b>всех</b> конфигов как подписку</p>
</div>
<h2>Отдельные конфиги</h2>
<div class="grid">
""")
        for i, cfg in enumerate(configs, 1):
            proto_label = 'unknown'
            for prefix, label in PROTO_NAMES.items():
                if cfg.startswith(prefix):
                    proto_label = label
                    break
            cfg_hash = hashlib.md5(cfg.encode()).hexdigest()[:8]
            filename = f"{i:04d}_{proto_label}_{cfg_hash}.png"
            name_match = re.search(r'#([^&]+)$', cfg)
            display_name = name_match.group(1) if name_match else f"{proto_label} #{i}"
            if len(display_name) > 40:
                display_name = display_name[:37] + "..."
            f.write(f'  <div class="card">\n')
            f.write(f'    <span class="proto proto-{proto_label}">{proto_label.upper()}</span>\n')
            f.write(f'    <img src="configs/{filename}" alt="{display_name}">\n')
            f.write(f'    <div class="label">{display_name}</div>\n')
            f.write(f'  </div>\n')

        f.write("</div>\n</body>\n</html>")
    print(f"  📄 HTML-индекс: {index_path}")


# =====================================================================
#  ЗАГРУЗКА + ФИЛЬТРАЦИЯ
# =====================================================================

def load_and_filter(source: Dict, health: Dict) -> Tuple[Set[str], List[str], Dict]:
    name = source['name']
    url = source['url']
    print(f"  [{name}] Загрузка...")

    content = fetch_url_with_health(url, health)
    if not content:
        return set(), [], {"raw": 0, "filtered": 0, "rejected": 0}

    lines = content.splitlines()
    lines = [l.strip() for l in lines if l.strip() and not l.strip().startswith('#')]
    raw_configs = parse_multiline_configs(lines)
    raw_count = len(raw_configs)

    pre_filtered = []
    rejected = []
    for cfg in raw_configs:
        if is_safe_config_base(cfg):
            pre_filtered.append(cfg)
        else:
            rejected.append(cfg)

    pbk_count = defaultdict(int)
    uuid_count = defaultdict(int)
    sid_count = defaultdict(int)
    trojan_pass_count = defaultdict(int)
    config_pbk, config_uuid, config_sid, config_tpass = {}, {}, {}, {}

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
                config_tpass[cfg] = pwd
                trojan_pass_count[pwd] += 1

    PBK_MAX = 3
    UUID_MAX = 3
    SID_MAX = 3
    TROJAN_PASS_MAX = 3

    final_filtered = set()
    for cfg in pre_filtered:
        pbk = config_pbk.get(cfg)
        uuid = config_uuid.get(cfg)
        sid = config_sid.get(cfg)
        tpass = config_tpass.get(cfg)
        if pbk and pbk_count[pbk] > PBK_MAX:
            rejected.append(cfg)
            continue
        if uuid and uuid_count[uuid] > UUID_MAX:
            rejected.append(cfg)
            continue
        if sid and sid_count[sid] > SID_MAX:
            rejected.append(cfg)
            continue
        if tpass and trojan_pass_count[tpass] > TROJAN_PASS_MAX:
            rejected.append(cfg)
            continue
        final_filtered.add(cfg)

    stats = {"raw": raw_count, "filtered": len(final_filtered), "rejected": len(rejected)}
    return final_filtered, rejected, stats


# =====================================================================
#  СОРТИРОВКА
# =====================================================================

def protocol_priority(uri: str) -> int:
    if uri.startswith('vless://'):
        return 1
    if uri.startswith('trojan://'):
        return 2
    if uri.startswith('vmess://'):
        return 3
    if uri.startswith(('hysteria2://', 'hy2://')):
        return 4
    if uri.startswith('hysteria://'):
        return 5
    if uri.startswith('ss://'):
        return 6
    if uri.startswith('ssr://'):
        return 7
    return 8


# =====================================================================
#  MAIN
# =====================================================================

def main():
    print("=== Фильтр прокси v3.1 + QR ===")

    health = load_health()
    all_filtered = set()
    all_rejected = []
    source_stats = {}

    with ThreadPoolExecutor(max_workers=5) as ex:
        futures = {ex.submit(load_and_filter, src, health): src for src in SOURCES_CONFIG}
        for future in as_completed(futures):
            src = futures[future]
            name = src['name']
            try:
                configs, rejected, stats = future.result()
                all_rejected.extend(rejected)
                source_stats[src['url']] = stats

                out = os.path.join(OUTPUT_DIR, f"{name}.txt")
                sorted_cfg = sorted(configs, key=lambda u: (protocol_priority(u), u))
                with open(out, 'w', encoding='utf-8', newline='\n') as f:
                    f.write('\n'.join(sorted_cfg))
                    if sorted_cfg:
                        f.write('\n')
                print(f"  ✅ {name}.txt → {len(configs)} конфигов (отброшено: {stats['rejected']})")
                all_filtered.update(configs)
            except Exception as e:
                print(f"  ❌ [{name}] Ошибка: {e}")

    # ALL.txt
    all_file = os.path.join(OUTPUT_DIR, "ALL.txt")
    sorted_all = sorted(all_filtered, key=lambda u: (protocol_priority(u), u))
    with open(all_file, 'w', encoding='utf-8', newline='\n') as f:
        f.write('\n'.join(sorted_all))
        if sorted_all:
            f.write('\n')

    # rejected.txt
    reject_file = os.path.join(REJECT_DIR, "rejected.txt")
    with open(reject_file, 'w', encoding='utf-8', newline='\n') as f:
        f.write('\n'.join(all_rejected))
        if all_rejected:
            f.write('\n')

    # URL Health
    save_health(health)
    write_health_report(health, source_stats)

    # QR-коды
    generate_qr_codes(sorted_all)

    print(f"\n✅ ALL.txt: {len(all_filtered)} уникальных конфигов")
    print(f"⚠️  Отброшено: {len(all_rejected)} (rejected/rejected.txt)")
    print(f"📊 URL Health: {os.path.join(OUTPUT_DIR, 'URL_HEALTH_REPORT.md')}")
    print(f"📱 QR-коды: {QR_DIR}/")


if __name__ == "__main__":
    main()
