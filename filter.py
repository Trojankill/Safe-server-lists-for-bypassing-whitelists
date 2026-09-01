#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Фильтр прокси-конфигураций v5.1 (Karing Edition)
Защита: Karing (sing-box) + V2RayNG/v2rayTun (Xray-core)
v5.1: потокобезопасность, порт-валидация, точный домен-матч,
      fail-closed SSR decode, vmess-2 alterId, env RAW_BASE.
"""

import re
import os
import json
import base64
import time
import threading
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
QR_DIR = "QR-CODE"

os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(REJECT_DIR, exist_ok=True)
os.makedirs(QR_DIR, exist_ok=True)

MAX_CONSECUTIVE_FAILURES = 3

RAW_BASE = os.environ.get(
    'RAW_BASE',
    'https://raw.githubusercontent.com/Trojankill/Safe-server-lists-for-bypassing-whitelists/main/githubmirror'
)

SUPPORTED_PROTOCOLS = [
    "vless://", "vmess://", "trojan://",
    "hysteria2://", "hy2://",
    "ss://", "ssr://", "tuic://",
]

SOURCES_CONFIG = [
    {"name": "FILTER-1", "url": "https://raw.githubusercontent.com/RKPchannel/RKP_bypass_configs/refs/heads/main/whitelist.txt"},
    {"name": "FILTER-2", "url": "https://github.com/AvenCores/goida-vpn-configs/raw/refs/heads/main/githubmirror/26.txt"},
    {"name": "FILTER-3", "url": "https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_universal.txt"},
    {"name": "FILTER-4", "url": "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-all.txt"},
    {"name": "FILTER-5", "url": "https://raw.githack.com/igareck/vpn-configs-for-russia/main/WHITE-CIDR-RU-all.txt"},
    {"name": "FILTER-6", "url": "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/refs/heads/main/output/vless.txt"},
    {"name": "FILTER-7-BASE64", "url": "https://solovyov-jenya2004.vercel.app/final_sorted_base64/"},
    {"name": "FILTER-8-BASE64", "url": "https://raw.githubusercontent.com/Diversan313/apex-parser/refs/heads/main/subs/main/alive_bs.txt"},
    {"name": "FILTER-9", "url": "https://raw.githubusercontent.com/VOID-Anonymity/V.O.I.D-VPN_Bypass/refs/heads/main/url_work.txt"},
]

# Точный домен-матч: '.cf' матчит только TLD, 'boot-lee.ru' только host
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

SAFE_SS_METHODS = {
    'aes-128-gcm', 'aes-256-gcm',
    'chacha20-poly1305', 'chacha20-ietf-poly1305',
    'xchacha20-poly1305', 'xchacha20-ietf-poly1305',
    '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm',
    '2022-blake3-chacha20-poly1305',
}

WEAK_SS_METHODS = {
    'rc4', 'rc4-md5', 'rc4-md5-6', 'des', 'des-cfb', 'bf-cfb', 'cast5-cfb',
    'salsa20', 'xsalsa20', 'chacha20', 'xchacha20', 'aes-128-cfb', 'aes-192-cfb',
    'aes-256-cfb', 'aes-128-cfb8', 'aes-192-cfb8', 'aes-256-cfb8', 'none', '',
}

_SS_2022_KEY_LENGTHS = {
    '2022-blake3-aes-128-gcm': 16,
    '2022-blake3-aes-256-gcm': 32,
    '2022-blake3-chacha20-poly1305': 32,
}

SAFE_FINGERPRINTS = {
    'chrome', 'firefox', 'safari', 'ios', 'android',
    'edge', '360', 'qq', 'random', 'randomized',
}

UNSAFE_PATTERNS = [
    r'[&?]allowinsecure=1', r'[&?]allowinsecure=true',
    r'[&?]allow_insecure=1', r'[&?]allow_insecure=true',
    r'[&?]disable_sni=1', r'[&?]disable_sni=true',
    r'[&?]insecure=1', r'[&?]insecure=true',
    r'[&?]security=none', r'[&?]verify=0', r'[&?]verify=false',
    r'[&?]skip-cert-verify=0', r'[&?]skip-cert-verify=false',
    r'[&?]allowinsecurecipher=1', r'[&?]allowinsecurecipher=true',
    r'[&?]tls13=0', r'[&?]tls13=false',
]

UNSAFE_REGEX = re.compile('|'.join(UNSAFE_PATTERNS), re.IGNORECASE)

TRUSTED_DNS = {
    '1.1.1.1', '8.8.8.8', '8.8.4.4', '94.140.14.14', '9.9.9.9',
    'cloudflare-dns.com', 'dns.google', 'dns.adguard.com',
}

TUIC_CC_WHITELIST = {'bbr', 'cubic', 'new_reno'}
TUIC_UDP_MODES = {'native', 'quic'}

_IPv4_AFTER_AT = re.compile(r'@(\d{1,3}\.){3}\d{1,3}', re.I)

# =====================================================================
#  ПОТОКОБЕЗОПАСНОСТЬ
# =====================================================================

_health_lock = threading.Lock()

# =====================================================================
#  ДОМЕН-МАТЧИНГ (v5.1: точный вместо substring)
# =====================================================================

def _domain_matches(host: str, domain: str) -> bool:
    """
    Точное совпадение домена или поддомена.
    '.cf' → matчит только 'cf' TLD (host == 'cf' или endswith('.cf'))
    'boot-lee.ru' → matчит host == 'boot-lee.ru' или *.boot-lee.ru
    """
    if domain.startswith('.'):
        return host == domain[1:] or host.endswith(domain)
    return host == domain or host.endswith('.' + domain)

def _is_host_banned(host: str) -> bool:
    """Проверка host против BANNED_DOMAINS с точным матчем."""
    return any(_domain_matches(host, d) for d in BANNED_DOMAINS)

# =====================================================================
#  SS 2022 KEY VALIDATION
# =====================================================================

def _check_ss_2022_key(method: str, password: str) -> bool:
    """True = КЛЮЧ ПЛОХОЙ. fail-closed — невалидный base64 = reject."""
    method_lower = method.lower().strip()
    expected_len = _SS_2022_KEY_LENGTHS.get(method_lower)
    if expected_len is None:
        return False
    if ':' in password:
        return False
    rem = len(password) % 4
    padded = password + '=' * (4 - rem) if rem else password
    try:
        decoded = base64.b64decode(padded, validate=True)
        return len(decoded) != expected_len
    except Exception:
        return True

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
            value = match.group(1).lower().strip('.')
            # проверяем value как host — точный матч
            if _is_host_banned(value):
                return True
            # проверяем вложренные поддомены: 'evil.boot-lee.ru'
            for domain in BANNED_DOMAINS:
                if _domain_matches(value, domain):
                    return True
    return False

def is_banned_host_universal(url: str) -> bool:
    m = re.search(r'^[a-z0-9]+://(?:[^@/]+@)?([^:/?#]+)(?::(\d+))?', url, re.I)
    if not m:
        return False
    host = m.group(1).lower()
    port = m.group(2)

    # v5.1: порт-валидация — 1..65535
    if port:
        try:
            if not (1 <= int(port) <= 65535):
                return True
        except ValueError:
            return True

    if _is_host_banned(host):
        return True
    if re.match(r'^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|0\.0\.0\.0|::1|localhost|fe80::|fc00::|fd)', host):
        return True
    return False

def is_ssr_host_banned(url: str) -> bool:
    if not url.startswith('ssr://'):
        return False
    try:
        payload = url[6:].split('#')[0]
        rem = len(payload) % 4
        if rem:
            payload += '=' * (4 - rem)
        # v5.1: fail-closed — битая кодировка = reject
        decoded = base64.b64decode(payload).decode('utf-8')
        host = decoded.split(':')[0].lower().strip('.')
        if _is_host_banned(host):
            return True
    except Exception:
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
    if enc_match:
        enc = enc_match.group(1).lower()
        if 'mlkem' in enc and 'x25519' not in enc:
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

def _is_private_ipv4(ip: str) -> bool:
    o = ip.split('.')
    if len(o) != 4:
        return False
    try:
        a, b = int(o[0]), int(o[1])
        if a > 255 or int(o[2]) > 255 or int(o[3]) > 255:
            return False
    except ValueError:
        return False
    return (a == 127 or a == 10
            or (a == 192 and b == 168)
            or (a == 172 and 16 <= b <= 31)
            or ip == '0.0.0.0')

def is_dangerous_uuid(url: str) -> bool:
    lower = url.lower()
    if 'localhost' in lower:
        return True
    m = _IPv4_AFTER_AT.search(url)
    if m and _is_private_ipv4(m.group(0)[1:]):
        return True
    if '::1' in lower or 'fe80:' in lower:
        return True
    if re.search(r'vless://(0{8}-0{4}-0{4}-0{4}-0{12}|f{8}-f{4}-f{4}-f{4}-f{12})@', url, re.I):
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

def extract_tuic_creds(url: str) -> Optional[str]:
    if not url.startswith('tuic://'):
        return None
    m = re.search(r'tuic://([^@]+)@', url, re.I)
    return m.group(1).lower() if m else None

def extract_host_port(url: str) -> Optional[str]:
    proto = url.split('://')[0]
    m = re.search(r'^[a-z0-9]+://(?:[^@/]+@)?([^:/?#]+)(?::(\d+))?', url, re.I)
    if m:
        host = m.group(1).lower()
        port = m.group(2) or 'default'
        if port != 'default':
            try:
                if not (1 <= int(port) <= 65535):
                    return None
            except ValueError:
                return None
        return f"{host}:{port}:{proto}"
    return None

# =====================================================================
#  УНИВЕРСАЛЬНАЯ ЗАЩИТА
# =====================================================================

def has_custom_ca_mitm(url: str) -> bool:
    ca_match = re.search(r'[?&]ca=([^&]+)', url, re.I)
    if ca_match:
        ca_val = ca_match.group(1)
        if ca_val.startswith('http') or len(ca_val) > 50:
            return True
    return False

def has_malicious_dns_override(url: str) -> bool:
    dns_match = re.search(r'[?&](?:dns|doh|dns-server)=([^&]+)', url, re.I)
    if dns_match:
        dns_val = dns_match.group(1).lower()
        host = re.sub(r'^https?://', '', dns_val)
        host = host.split('/')[0].split('#')[0].split(':')[0].strip('.')
        if host and host not in TRUSTED_DNS:
            return True
    return False

def has_sniffing_exfiltration(url: str) -> bool:
    sniff_match = re.search(r'[?&](?:sniffing|destoverride)=([^&]+)', url, re.I)
    if sniff_match:
        val = sniff_match.group(1).lower()
        if 'localhost' not in val and re.search(r'[a-zA-Z0-9-]+\.[a-zA-Z]{2,}', val):
            return True
    return False

def has_invalid_reality_pbk(url: str) -> bool:
    if 'security=reality' not in url.lower():
        return False
    pbk_match = re.search(r'[?&]pbk=([^&]+)', url, re.I)
    if not pbk_match:
        return True
    pbk = pbk_match.group(1).rstrip('=')
    if len(pbk) != 43:
        return True
    return False

def has_invalid_reality_sid(url: str) -> bool:
    if 'security=reality' not in url.lower():
        return False
    sid_match = re.search(r'[?&]sid=([^&]*)', url, re.I)
    if not sid_match:
        return False
    sid = sid_match.group(1)
    if len(sid) == 0:
        return False
    if len(sid) > 16 or len(sid) % 2 != 0 or not re.match(r'^[0-9a-fA-F]+$', sid):
        return True
    return False

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
        if transport not in ('ws', 'grpc', 'http', 'tcp', 'raw'):
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
        if 'h2' not in alpn and 'http/1.1' not in alpn and 'h3' not in alpn:
            return False
        return True

    return False

def is_safe_trojan_base(url: str) -> bool:
    if not url.startswith('trojan://'):
        return False
    pass_match = re.search(r'trojan://([^@]*)@', url, re.I)
    if not pass_match or not pass_match.group(1).strip():
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

    # Формат 2: vmess://uuid@host:port?params
    if '@' in url.split('?')[0]:
        if is_dangerous_uuid(url):
            return False
        # v5.1: alterId проверка — replay-атака защита
        aid_match = re.search(r'[?&]alterId=(\d+)', url, re.I)
        if aid_match and int(aid_match.group(1)) != 0:
            return False
        security_match = re.search(r'[?&]security=([^&]*)', url, re.I)
        security = security_match.group(1).lower() if security_match else ''
        if not security or security == 'none':
            return False
        if security == 'reality' and not re.search(r'[?&]pbk=[^&]+', url, re.I):
            return False
        if security in ('tls', 'reality') and not re.search(r'[?&]sni=[^&]+', url, re.I):
            return False
        return True

    # Формат 1: legacy base64 JSON
    b64 = url.replace('vmess://', '').split('#')[0].split('?')[0]
    try:
        missing = len(b64) % 4
        if missing:
            b64 += '=' * (4 - missing)
        decoded = base64.b64decode(b64).decode('utf-8')
        cfg = json.loads(decoded)

        try:
            aid_val = cfg.get('aid', cfg.get('alterId', 0))
            if int(aid_val) != 0:
                return False
        except (ValueError, TypeError):
            return False

        if not cfg.get('tls', False):
            return False
        if cfg.get('allowInsecure', False):
            return False
        # v5.1: v=1 тоже валиден — старый формат, Karing парсит
        if str(cfg.get('v', '2')) not in ('1', '2'):
            return False

        scy = cfg.get('scy', 'auto').lower()
        if scy not in ('auto', 'aes-128-gcm', 'chacha20-poly1305'):
            return False

        net = cfg.get('net', 'tcp').lower()
        if net not in ('ws', 'grpc', 'http', 'tcp', 'raw'):
            return False
        if net in ('ws', 'http') and not cfg.get('host'):
            return False

        # v5.1: точный домен-матч
        for field in ('add', 'sni', 'host'):
            val = str(cfg.get(field, '')).lower().strip('.')
            if val and _is_host_banned(val):
                return False
        add = str(cfg.get('add', '')).lower()
        if re.match(r'^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|0\.0\.0\.0|::1|localhost)', add):
            return False
        return True
    except Exception:
        return False

def is_safe_hysteria2_base(url: str) -> bool:
    if not url.startswith(('hysteria2://', 'hy2://')):
        return False
    if re.search(r'[&?]insecure=1', url, re.I):
        return False
    if not re.search(r'[?&]sni=[^&]+', url, re.I):
        return False
    pass_match = re.search(r'(?:hysteria2|hy2)://([^@]*)@', url, re.I)
    if pass_match and not pass_match.group(1).strip():
        return False
    return True

def is_safe_tuic_base(url: str) -> bool:
    if not url.startswith('tuic://'):
        return False
    cred_match = re.search(r'tuic://([^@]+)@', url, re.I)
    if not cred_match:
        return False
    cred = cred_match.group(1)
    if ':' in cred:
        token, _, password = cred.partition(':')
        if not token.strip() or not password.strip():
            return False
    elif not cred.strip():
        return False
    if not re.search(r'[?&]sni=[^&]+', url, re.I):
        return False
    cc_match = re.search(r'[?&]congestion_control=([^&]+)', url, re.I)
    if cc_match and cc_match.group(1).lower() not in TUIC_CC_WHITELIST:
        return False
    udp_match = re.search(r'[?&]udp_relay_mode=([^&]+)', url, re.I)
    if udp_match and udp_match.group(1).lower() not in TUIC_UDP_MODES:
        return False
    alpn_match = re.search(r'[?&]alpn=([^&]+)', url, re.I)
    if alpn_match and 'h3' not in alpn_match.group(1).lower():
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
        decoded = base64.b64decode(payload).decode('utf-8')
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

    if has_custom_ca_mitm(line): return False
    if has_malicious_dns_override(line): return False
    if has_sniffing_exfiltration(line): return False
    if has_invalid_reality_pbk(line): return False
    if has_invalid_reality_sid(line): return False

    if has_insecure_params(line): return False
    if is_dangerous_domain_param(line): return False
    if is_banned_host_universal(line): return False
    if is_ssr_host_banned(line): return False
    if has_dangerous_transport_combination(line): return False
    if is_suspicious_encryption(line): return False
    if is_dangerous_uuid(line): return False

    if line.startswith('vless://'): return is_safe_vless_base(line)
    if line.startswith('trojan://'): return is_safe_trojan_base(line)
    if line.startswith('vmess://'): return is_safe_vmess_base(line)
    if line.startswith(('hysteria2://', 'hy2://')): return is_safe_hysteria2_base(line)
    if line.startswith('tuic://'): return is_safe_tuic_base(line)
    if line.startswith('ss://'): return is_safe_ss_base(line)
    if line.startswith('ssr://'): return is_safe_ssr_base(line)
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
                # v5.1: избегаем двойного ? или &
                if '?' in current and stripped.startswith('?'):
                    current += stripped[1:]
                elif '&' in current and stripped.startswith('&'):
                    current += stripped[1:]
                elif '?' in current and '&' not in stripped:
                    current += '&' + stripped
                else:
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

def _try_b64_decode(s: str) -> Optional[str]:
    def single(x: str) -> Optional[str]:
        try:
            return base64.b64decode(x + '=' * (-len(x) % 4)).decode('utf-8', errors='ignore')
        except Exception:
            try:
                return base64.urlsafe_b64decode(x + '=' * (-len(x) % 4)).decode('utf-8', errors='ignore')
            except Exception:
                return None
    first = single(s)
    if first is None:
        return None
    if any(p in first for p in SUPPORTED_PROTOCOLS):
        return first
    stripped2 = re.sub(r'\s+', '', first)
    if re.fullmatch(r'[A-Za-z0-9+/_=-]+', stripped2):
        second = single(stripped2)
        if second and any(p in second for p in SUPPORTED_PROTOCOLS):
            return second
    return None

def fetch_url_with_health(url: str, health: Dict) -> Tuple[Optional[str], bool]:
    # v5.1: lock на чтение health
    with _health_lock:
        entry = health.get(url, {"failures": 0, "last_status": None, "last_check": None})
        failure_count = entry["failures"]

    if failure_count >= MAX_CONSECUTIVE_FAILURES:
        print(f"  ⚠️  {url} — {failure_count} провалов подряд, пропускаем")
        return None, False

    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=15) as resp:
            content = resp.read().decode('utf-8', errors='ignore')

        # v5.1: lock на запись health
        with _health_lock:
            entry["failures"] = 0
            entry["last_status"] = "ok"
            entry["last_check"] = time.strftime('%Y-%m-%d %H:%M:%S UTC')
            health[url] = entry

        stripped = re.sub(r'\s+', '', content.strip())
        if re.fullmatch(r'[A-Za-z0-9+/_=-]+', stripped):
            decoded = _try_b64_decode(stripped)
            if decoded is not None:
                return decoded, True

        return content, False

    except Exception as e:
        # v5.1: lock на запись при ошибке
        with _health_lock:
            entry["failures"] = entry.get("failures", 0) + 1
            entry["last_status"] = str(e)
            entry["last_check"] = time.strftime('%Y-%m-%d %H:%M:%S UTC')
            health[url] = entry
            fail_num = entry["failures"]
        print(f"  ❌ {url}: {e} (провал #{fail_num})")
        return None, False

def write_health_report(health: Dict, source_stats: Dict[str, Dict]):
    report_path = os.path.join(OUTPUT_DIR, "URL_HEALTH_REPORT.md")
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write("# URL Health Report\n")
        f.write(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
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

def generate_qr_codes(file_counts: Dict[str, int]):
    try:
        import qrcode
        from qrcode.constants import ERROR_CORRECT_M
    except ImportError:
        print("  ⚠️  qrcode не установлен. pip install qrcode[pil]")
        return

    os.makedirs(QR_DIR, exist_ok=True)
    qr_files = []

    for name, count in file_counts.items():
        if count == 0:
            continue
        file_url = f"{RAW_BASE}/{name}.txt"
        qr = qrcode.QRCode(
            version=None,
            error_correction=ERROR_CORRECT_M,
            box_size=10,
            border=4,
        )
        qr.add_data(file_url)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        filename = f"{name}.png"
        filepath = os.path.join(QR_DIR, filename)
        img.save(filepath)
        qr_files.append((name, count, filename))
        print(f"  📱 QR: {filepath} → {file_url}")

    _generate_qr_index(qr_files)

def _generate_qr_index(qr_files: List[Tuple[str, int]]):
    index_path = os.path.join(QR_DIR, "index.html")
    with open(index_path, 'w', encoding='utf-8') as f:
        f.write("""<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>QR-коды подписок</title>
<style>
body { font-family: system-ui, sans-serif; background: #1a1a2e; color: #eee; margin: 20px; }
h1 { text-align: center; color: #00d4ff; }
.grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 24px; margin-top: 30px; }
.card { background: #16213e; border-radius: 12px; padding: 20px; text-align: center; }
.card img { width: 240px; height: 240px; border-radius: 8px; }
.card .name { font-size: 18px; font-weight: bold; color: #00d4ff; margin-top: 12px; }
.card .count { font-size: 14px; color: #888; margin-top: 4px; }
.card .url { font-size: 11px; color: #555; margin-top: 8px; word-break: break-all; }
.all-card { border: 2px solid #00d4ff; }
</style>
</head>
<body>
<h1>📱 QR-коды подписок</h1>
<p style="text-align:center;color:#aaa;">Отсканируй QR-код в клиенте (v2rayNG, Karing, Hiddify) для добавления подписки</p>
<div class="grid">
""")
        for name, count, filename in qr_files:
            card_class = 'card all-card' if name == 'ALL' else 'card'
            file_url = f"{RAW_BASE}/{name}.txt"
            f.write(f'  <div class="{card_class}">\n')
            f.write(f'    <img src="{filename}" alt="{name}">\n')
            f.write(f'    <div class="name">{name}</div>\n')
            f.write(f'    <div class="count">{count} конфигов</div>\n')
            f.write(f'    <div class="url">{file_url}</div>\n')
            f.write(f'  </div>\n')
        f.write("</div>\n</body>\n</html>")
    print(f"  📄 HTML-индекс: {index_path}")

# =====================================================================
#  ЗАГРУЗКА + ФИЛЬТРАЦИЯ
# =====================================================================

def load_and_filter(source: Dict, health: Dict) -> Tuple[Set[str], List[str], Dict, bool]:
    name = source['name']
    url = source['url']
    print(f"  [{name}] Загрузка...")

    content, was_base64 = fetch_url_with_health(url, health)

    if not content:
        return set(), [], {"raw": 0, "filtered": 0, "rejected": 0}, False

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
    host_port_count = defaultdict(int)
    tuic_cred_count = defaultdict(int)

    config_pbk, config_uuid, config_sid, config_tpass, config_hp = {}, {}, {}, {}, {}
    config_tuic = {}

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
        if cfg.startswith('tuic://'):
            tcred = extract_tuic_creds(cfg)
            if tcred:
                config_tuic[cfg] = tcred
                tuic_cred_count[tcred] += 1
        hp = extract_host_port(cfg)
        if hp:
            config_hp[cfg] = hp
            host_port_count[hp] += 1

    PBK_MAX = 3
    UUID_MAX = 3
    SID_MAX = 3
    TROJAN_PASS_MAX = 3
    TUIC_CRED_MAX = 3
    HP_MAX = 5  # v5.1: 5 — один CDN/IP за разными серверами это норм

    final_filtered = set()
    for cfg in pre_filtered:
        pbk = config_pbk.get(cfg)
        uuid = config_uuid.get(cfg)
        sid = config_sid.get(cfg)
        tpass = config_tpass.get(cfg)
        tcred = config_tuic.get(cfg)
        hp = config_hp.get(cfg)

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
        if tcred and tuic_cred_count[tcred] > TUIC_CRED_MAX:
            rejected.append(cfg)
            continue
        if hp and host_port_count[hp] > HP_MAX:
            rejected.append(cfg)
            continue

        final_filtered.add(cfg)

    stats = {"raw": raw_count, "filtered": len(final_filtered), "rejected": len(rejected)}
    return final_filtered, rejected, stats, was_base64

# =====================================================================
#  СОРТИРОВКА
# =====================================================================

def protocol_priority(uri: str) -> int:
    if uri.startswith('vless://'): return 1
    if uri.startswith('trojan://'): return 2
    if uri.startswith('vmess://'): return 3
    if uri.startswith(('hysteria2://', 'hy2://')): return 4
    if uri.startswith('tuic://'): return 5
    if uri.startswith('ss://'): return 6
    if uri.startswith('ssr://'): return 7
    return 8

# =====================================================================
#  MAIN
# =====================================================================

def main():
    print("=== Фильтр прокси v5.1 (Karing Edition) ===")
    health = load_health()
    all_filtered = set()
    all_rejected = []
    source_stats = {}
    file_counts = {}

    with ThreadPoolExecutor(max_workers=5) as ex:
        futures = {ex.submit(load_and_filter, src, health): src for src in SOURCES_CONFIG}
        for future in as_completed(futures):
            src = futures[future]
            name = src['name']
            try:
                configs, rejected, stats, was_base64 = future.result()
                all_rejected.extend(rejected)
                source_stats[src['url']] = stats

                out = os.path.join(OUTPUT_DIR, f"{name}.txt")
                sorted_cfg = sorted(configs, key=lambda u: (protocol_priority(u), u))

                if was_base64 and sorted_cfg:
                    plaintext = '\n'.join(sorted_cfg) + '\n'
                    encoded = base64.b64encode(plaintext.encode('utf-8')).decode('ascii')
                    with open(out, 'w', encoding='utf-8', newline='\n') as f:
                        f.write(encoded)
                    print(f"  ✅ {name}.txt → {len(configs)} конфигов [base64] (отброшено: {stats['rejected']})")
                else:
                    with open(out, 'w', encoding='utf-8', newline='\n') as f:
                        f.write('\n'.join(sorted_cfg))
                        if sorted_cfg:
                            f.write('\n')
                    print(f"  ✅ {name}.txt → {len(configs)} конфигов (отброшено: {stats['rejected']})")

                all_filtered.update(configs)
                file_counts[name] = len(configs)

            except Exception as e:
                print(f"  ❌ [{name}] Ошибка: {e}")
                file_counts[name] = 0

    all_file = os.path.join(OUTPUT_DIR, "ALL.txt")
    sorted_all = sorted(all_filtered, key=lambda u: (protocol_priority(u), u))
    with open(all_file, 'w', encoding='utf-8', newline='\n') as f:
        f.write('\n'.join(sorted_all))
        if sorted_all:
            f.write('\n')
    file_counts["ALL"] = len(all_filtered)

    reject_file = os.path.join(REJECT_DIR, "rejected.txt")
    with open(reject_file, 'w', encoding='utf-8', newline='\n') as f:
        f.write('\n'.join(all_rejected))
        if all_rejected:
            f.write('\n')

    save_health(health)
    write_health_report(health, source_stats)
    generate_qr_codes(file_counts)

    print(f"\n✅ ALL.txt: {len(all_filtered)} уникальных конфигов")
    print(f"⚠️  Отброшено: {len(all_rejected)} (rejected/rejected.txt)")
    print(f"📊 URL Health: {os.path.join(OUTPUT_DIR, 'URL_HEALTH_REPORT.md')}")
    print(f"📱 QR-коды: {QR_DIR}/")

if __name__ == "__main__":
    main()
