#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Фильтр прокси-конфигураций v6.0 (Karing + Clash/Mihomo + sing-box Edition)
Защита: Karing (sing-box) + V2RayNG/v2rayTun (Xray-core) + Clash (Mihomo) + sing-box-extended
v6.0: Интеграция чекера sing-box-extended, IPv6 host extraction, SSR obfs/protocol param validation,
Clash name sanitization + host:port dedup, timeout 30s, explicit SS 2022 rem=1 rejection

Объединяет:
- Строгие проверки безопасности из filter.py v5.3
- Чекер совместимости с sing-box-extended из Cleaner.py
- Проверку SNI для TLS-конфигов
- Проверку методов шифрования SS
"""
import re
import os
import sys
import json
import time
import base64
import threading
import subprocess
import urllib.request
import urllib.parse
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
from functools import lru_cache
from typing import Set, Dict, Optional, List, Tuple

try:
    import yaml
    HAS_YAML = True
except ImportError:
    try:
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'pyyaml', '--quiet'])
        import yaml
        HAS_YAML = True
    except Exception:
        yaml = None
        HAS_YAML = False
        print("  ⚠️  pyyaml недоступен — Clash подписки не парсятся")

# =====================================================================
#  КОНСТАНТЫ
# =====================================================================
OUTPUT_DIR = "githubmirror"
HEALTH_FILE = os.path.join(OUTPUT_DIR, "url_health.json")
REJECT_DIR = os.path.join(OUTPUT_DIR, "rejected")
QR_DIR = "QR-CODE"
CLASH_DIR = os.path.join(OUTPUT_DIR, "Clash")

os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(REJECT_DIR, exist_ok=True)
os.makedirs(QR_DIR, exist_ok=True)
os.makedirs(CLASH_DIR, exist_ok=True)

MAX_CONSECUTIVE_FAILURES = 3
FETCH_TIMEOUT = 30
RAW_BASE = os.environ.get(
    'RAW_BASE',
    'https://raw.githubusercontent.com/Trojankill/Safe-server-lists-for-bypassing-whitelists/main/githubmirror'
)

SUPPORTED_PROTOCOLS = [
    "vless://", "vmess://", "trojan://",
    "hysteria2://", "hy2://",
    "ss://", "ssr://", "tuic://",
]

# Из Cleaner.py: чекер sing-box-extended
SING_BOX_SUPPORTED_TRANSPORTS = {'tcp', 'ws', 'grpc', 'http', 'raw', 'xhttp'}
SING_BOX_SUPPORTED_SECURITY = {'tls', 'reality', 'none'}
SING_BOX_SUPPORTED_SS_METHODS = {
    'aes-128-gcm', 'aes-256-gcm', 'chacha20-poly1305', 'chacha20-ietf-poly1305',
    'xchacha20-poly1305', 'xchacha20-ietf-poly1305',
    '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm', '2022-blake3-chacha20-poly1305'
}

SOURCES_CONFIG = [
    {"name": "FILTER-1", "url": "https://hub.mos.ru/rkp/sub-roskompozor/raw/main/wl"},
    {"name": "FILTER-2", "url": "https://github.com/regionovec-jpg/subs_pars/raw/refs/heads/main/subs_wl.txt"},
    {"name": "FILTER-3", "url": "https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_lite.txt"},
    {"name": "FILTER-4", "url": "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-all.txt"},
    {"name": "FILTER-5", "url": "https://raw.githubusercontent.com/LSO-LinSpisokObhod/LSO-LinSpisokObhod.github.io/refs/heads/main/sub/LTE.txt"},
    {"name": "FILTER-6", "url": "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/refs/heads/main/output/vless.txt"},
    {"name": "FILTER-7-BASE64", "url": "https://solovyov-jenya2004.vercel.app/final_sorted_base64/"},
    {"name": "FILTER-8-BASE64", "url": "https://raw.githubusercontent.com/Diversan313/apex-parser/refs/heads/main/subs/main/alive_bs.txt"},
    {"name": "FILTER-9-BASE64", "url": "https://raw.githubusercontent.com/Diversan313/apex-parser/main/subs/main/alive_bl.txt"},
    {"name": "FILTER-10", "url": "https://sub.vlessfo.ru/vlessforu/working_configs.txt"},
    {"name": "FILTER-11", "url": "https://hub.mos.ru/akelladejavu/bunker/-/raw/main/WHITE_LIST.txt"},
    {"name": "FILTER-12", "url": "https://translated.turbopages.org/proxy_u/de-de.ru.e6e5a2dd-6ac65a76-30ee4feb-74722d776562/https/bitbucket.org/igareck/vpn-configs-for-russia/raw/main/WHITE-CIDR-RU-all.txt"},
    {"name": "FILTER-13", "url": "https://github.com/vessel-web/CoolSubs/raw/refs/heads/main/Cool-White.txt"},
]

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

# IPv6: [2001:db8::1]:443 — bracket notation
_IPv4_AFTER_AT = re.compile(r'@(\d{1,3}\.){3}\d{1,3}', re.I)
_IPv6_BRACKET = re.compile(r'@\[([0-9a-fA-F:]+)\](?::(\d+))?')

# =====================================================================
#  ПОТОКОБЕЗОПАСНОСТЬ
# =====================================================================
_health_lock = threading.Lock()

# =====================================================================
#  ДОМЕН-МАТЧИНГ
# =====================================================================
def _domain_matches(host: str, domain: str) -> bool:
    if domain.startswith('.'):
        return host == domain[1:] or host.endswith(domain)
    return host == domain or host.endswith('.' + domain)

def _is_host_banned(host: str) -> bool:
    return any(_domain_matches(host, d) for d in BANNED_DOMAINS)

# =====================================================================
#  ИЗВЛЕЧЕНИЕ HOST:PORT (IPv4 + IPv6)
# =====================================================================
def _extract_host_port_from_uri(url: str) -> Tuple[Optional[str], Optional[int]]:
    """Извлекает host и port из proxy URI. Поддерживает IPv4 и IPv6 [bracket]."""
    m6 = _IPv6_BRACKET.search(url)
    if m6:
        host = f'[{m6.group(1)}]'
        port = int(m6.group(2)) if m6.group(2) else None
        return host, port
    m = re.search(r'^(?:[^@/]+@)?([^:/?#]+)(?::(\d+))?', url.split('://', 1)[-1] if '://' in url else url)
    if not m:
        return None, None
    host = m.group(1)
    port = int(m.group(2)) if m.group(2) else None
    return host, port

# =====================================================================
#  SS 2022 KEY VALIDATION
# =====================================================================
def _check_ss_2022_key(method: str, password: str) -> bool:
    """True = reject. Проверяет длину ключа после base64 decode."""
    method_lower = method.lower().strip()
    expected_len = _SS_2022_KEY_LENGTHS.get(method_lower)
    if expected_len is None:
        return False
    if ':' in password:
        return False
    rem = len(password) % 4
    if rem == 1:
        return True
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
            if _is_host_banned(value):
                return True
            for domain in BANNED_DOMAINS:
                if _domain_matches(value, domain):
                    return True
    return False

def is_banned_host_universal(url: str) -> bool:
    m6 = _IPv6_BRACKET.search(url)
    if m6:
        host = m6.group(1).lower()
        port = m6.group(2)
        if port:
            try:
                if not (1 <= int(port) <= 65535):
                    return True
            except ValueError:
                return True
        if host in ('::1', 'fe80::', 'fc00::', 'fd00::', ''):
            return True
        if host.startswith(('fe80:', 'fc', 'fd', '::1', '::')):
            return True
        return False
    m = re.search(r'^[a-z0-9]+://(?:[^@/]+@)?([^:/?#]+)(?::(\d+))?', url, re.I)
    if not m:
        return False
    host = m.group(1).lower()
    port = m.group(2)
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
    m6 = _IPv6_BRACKET.search(url)
    if m6 and m6.group(1).lower().startswith(('fe80:', 'fc', 'fd', '::1', '::')):
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
    host, port = _extract_host_port_from_uri(url)
    if host is None:
        return None
    host_lower = host.lower()
    port_str = str(port) if port else 'default'
    if port is not None:
        if not (1 <= port <= 65535):
            return None
    return f"{host_lower}:{port_str}:{proto}"

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
#  SSR ДОПОЛНИТЕЛЬНАЯ ПРОВЕРКА — obfs_param / protocol_param
# =====================================================================
def has_ssr_dangerous_params(url: str) -> bool:
    """Проверяет obfs_param и protocol_param в SSR на запрещённые домены."""
    if not url.startswith('ssr://'):
        return False
    try:
        payload = url[6:].split('#')[0]
        rem = len(payload) % 4
        if rem:
            payload += '=' * (4 - rem)
        decoded = base64.b64decode(payload).decode('utf-8')
        if '/?' in decoded:
            extra = decoded.split('/?', 1)[1]
            for kv in extra.split('&'):
                if '=' in kv:
                    k, _, v = kv.partition('=')
                    if k in ('obfs_param', 'protocol_param', 'obfs-param', 'protocol-param'):
                        val = v.lower().strip('.')
                        if val and _is_host_banned(val):
                            return True
                        if re.match(r'^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)', val):
                            return True
    except Exception:
        pass
    return False

# =====================================================================
#  НОВЫЕ ПРОВЕРКИ ИЗ CLEANER.PY (sing-box-extended)
# =====================================================================
def is_sing_box_transport_compatible(url: str) -> bool:
    """Проверяет, поддерживает ли sing-box-extended транспортный протокол."""
    if url.startswith('vless://'):
        type_match = re.search(r'[?&]type=([^&]+)', url, re.I)
        transport = type_match.group(1).lower() if type_match else 'tcp'
        return transport in SING_BOX_SUPPORTED_TRANSPORTS
    elif url.startswith('vmess://'):
        type_match = re.search(r'[?&]type=([^&]+)', url, re.I)
        transport = type_match.group(1).lower() if type_match else 'tcp'
        return transport in SING_BOX_SUPPORTED_TRANSPORTS
    return True

def is_sing_box_ss_compatible(url: str) -> bool:
    """Проверяет, поддерживает ли sing-box-extended метод шифрования SS."""
    if url.startswith('ss://'):
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
            method, _ = userinfo.split(':', 1)
            method = method.lower().strip()
            return method in SING_BOX_SUPPORTED_SS_METHODS
        except Exception:
            return False
    return True

def has_valid_sni_for_tls(url: str) -> bool:
    """Для TLS-конфигов проверяет наличие SNI (требование sing-box-extended)."""
    security_match = re.search(r'[?&]security=([^&]+)', url, re.I)
    if security_match and security_match.group(1).lower() in ('tls', 'reality'):
        sni_match = re.search(r'[?&]sni=[^&]+', url, re.I)
        if not sni_match:
            return False
    return True

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
    if '@' in url.split('?')[0]:
        if is_dangerous_uuid(url):
            return False
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
        if has_ssr_dangerous_params(url):
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
    
    # Новые проверки из Cleaner.py для sing-box-extended
    if not is_sing_box_transport_compatible(line):
        return False
    if not is_sing_box_ss_compatible(line):
        return False
    if not has_valid_sni_for_tls(line):
        return False
    
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
#  CLASH PARSING
# =====================================================================
def is_clash_content(content: str) -> bool:
    stripped = content.strip()
    if stripped.startswith('proxies:'):
        return True
    if stripped.startswith('port:') or stripped.startswith('mixed-port:'):
        return True
    lines = stripped.splitlines()
    for line in lines[:50]:
        ls = line.strip()
        if ls.startswith('proxies:'):
            return True
        if re.match(r'^-\s+name:', ls) and 'type:' in content:
            return True
        if re.match(r'^\{.*name.*type.*\}', ls):
            return True
    if 'proxy-groups:' in stripped and 'proxies:' in stripped:
        return True
    return False

def clash_to_uris(content: str) -> List[str]:
    if not HAS_YAML:
        return []
    try:
        data = yaml.safe_load(content)
        if not isinstance(data, dict) or 'proxies' not in data:
            return []
        uris = []
        for p in data.get('proxies', []):
            if not isinstance(p, dict):
                continue
            u = _clash_proxy_to_uri(p)
            if u:
                uris.append(u)
        return uris
    except Exception:
        return []

def _clash_proxy_to_uri(p: dict) -> Optional[str]:
    t = str(p.get('type', '')).lower()
    name = str(p.get('name', ''))
    host = str(p.get('server', ''))
    try:
        port = int(p.get('port', 0))
    except (ValueError, TypeError):
        return None
    frag = urllib.parse.quote(name)
    if t == 'vless':
        params = {}
        if p.get('reality-opts'):
            params['security'] = 'reality'
            ro = p['reality-opts']
            if ro.get('public-key'):
                params['pbk'] = ro['public-key']
            if ro.get('short-id'):
                params['sid'] = ro['short-id']
        elif p.get('tls'):
            params['security'] = 'tls'
        else:
            params['security'] = 'none'
        if p.get('servername'):
            params['sni'] = str(p['servername'])
        if p.get('client-fingerprint'):
            params['fp'] = str(p['client-fingerprint'])
        if p.get('flow'):
            params['flow'] = str(p['flow'])
        if p.get('alpn'):
            al = p['alpn']
            if isinstance(al, list):
                params['alpn'] = ','.join(str(x) for x in al)
            else:
                params['alpn'] = str(al)
        net = str(p.get('network', 'tcp'))
        params['type'] = net
        if net == 'ws' and p.get('ws-opts'):
            wo = p['ws-opts']
            if wo.get('path'):
                params['path'] = str(wo['path'])
            wh = wo.get('headers', {})
            if isinstance(wh, dict) and wh.get('Host'):
                params['host'] = str(wh['Host'])
        elif net == 'grpc' and p.get('grpc-opts'):
            if p['grpc-opts'].get('grpc-service-name'):
                params['serviceName'] = str(p['grpc-opts']['grpc-service-name'])
        qs = '&'.join(f'{k}={urllib.parse.quote(str(v), safe="")}' for k, v in params.items())
        return f"vless://{p.get('uuid', '')}@{host}:{port}?{qs}#{frag}"
    if t == 'vmess':
        return _clash_vmess_to_uri(p, name, host, port)
    if t == 'trojan':
        params = {}
        if p.get('sni'):
            params['sni'] = str(p['sni'])
        if p.get('alpn'):
            al = p['alpn']
            if isinstance(al, list):
                params['alpn'] = ','.join(str(x) for x in al)
            else:
                params['alpn'] = str(al)
        net = str(p.get('network', 'tcp'))
        if net != 'tcp':
            params['type'] = net
        if net == 'ws' and p.get('ws-opts'):
            wo = p['ws-opts']
            if wo.get('path'):
                params['path'] = str(wo['path'])
            wh = wo.get('headers', {})
            if isinstance(wh, dict) and wh.get('Host'):
                params['host'] = str(wh['Host'])
        elif net == 'grpc' and p.get('grpc-opts'):
            if p['grpc-opts'].get('grpc-service-name'):
                params['serviceName'] = str(p['grpc-opts']['grpc-service-name'])
        qs = '&'.join(f'{k}={urllib.parse.quote(str(v), safe="")}' for k, v in params.items())
        return f"trojan://{p.get('password', '')}@{host}:{port}?{qs}#{frag}"
    if t == 'hysteria2':
        params = {}
        if p.get('sni'):
            params['sni'] = str(p['sni'])
        qs = '&'.join(f'{k}={v}' for k, v in params.items())
        if qs:
            return f"hysteria2://{p.get('password', '')}@{host}:{port}?{qs}#{frag}"
        return f"hysteria2://{p.get('password', '')}@{host}:{port}#{frag}"
    if t == 'tuic':
        tok = str(p.get('token', ''))
        pwd = str(p.get('password', ''))
        cred = f"{tok}:{pwd}" if pwd else tok
        params = {}
        if p.get('sni'):
            params['sni'] = str(p['sni'])
        if p.get('alpn'):
            al = p['alpn']
            if isinstance(al, list):
                params['alpn'] = ','.join(str(x) for x in al)
            else:
                params['alpn'] = str(al)
        qs = '&'.join(f'{k}={v}' for k, v in params.items())
        if qs:
            return f"tuic://{cred}@{host}:{port}?{qs}#{frag}"
        return f"tuic://{cred}@{host}:{port}#{frag}"
    return None

def _clash_vmess_to_uri(p: dict, name: str, host: str, port: int) -> Optional[str]:
    try:
        uuid = str(p.get('uuid', ''))
        alterId = int(p.get('alterId', 0))
        cipher = str(p.get('cipher', 'auto'))
        tls = bool(p.get('tls', False))
        net = str(p.get('network', 'tcp'))
        ws_path = ''
        ws_host = ''
        if net == 'ws' and p.get('ws-opts'):
            wo = p['ws-opts']
            ws_path = str(wo.get('path', ''))
            wh = wo.get('headers', {})
            if isinstance(wh, dict) and wh.get('Host'):
                ws_host = str(wh['Host'])
        vmess_cfg = {
            'v': '2',
            'ps': name,
            'add': host,
            'port': str(port),
            'id': uuid,
            'aid': str(alterId),
            'scy': cipher,
            'net': net,
            'type': 'none',
            'host': ws_host or host,
            'path': ws_path or '/',
            'tls': 'tls' if tls else '',
            'sni': str(p.get('servername', '')),
        }
        b64 = base64.b64encode(json.dumps(vmess_cfg).encode('utf-8')).decode('utf-8')
        return f"vmess://{b64}"
    except Exception:
        return None

# =====================================================================
#  ДЕДУПЛИКАЦИЯ
# =====================================================================
def dedup_configs(configs: List[str]) -> List[str]:
    """Дедупликация по host:port:protocol + UUID/password для vless/trojan."""
    seen = set()
    result = []
    for cfg in configs:
        host_port = extract_host_port(cfg)
        if not host_port:
            result.append(cfg)
            continue
        # Для vless добавляем UUID
        if cfg.startswith('vless://'):
            uuid = extract_uuid(cfg)
            if uuid:
                key = f"{host_port}:{uuid}"
            else:
                key = host_port
        # Для trojan добавляем password
        elif cfg.startswith('trojan://'):
            password = extract_trojan_password(cfg)
            if password:
                key = f"{host_port}:{password}"
            else:
                key = host_port
        # Для tuic добавляем creds
        elif cfg.startswith('tuic://'):
            creds = extract_tuic_creds(cfg)
            if creds:
                key = f"{host_port}:{creds}"
            else:
                key = host_port
        else:
            key = host_port
        if key not in seen:
            seen.add(key)
            result.append(cfg)
    return result

# =====================================================================
#  ЗАГРУЗКА ИСТОЧНИКОВ
# =====================================================================
def fetch_url(url: str, timeout: int = FETCH_TIMEOUT) -> Optional[str]:
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode('utf-8', errors='ignore')
    except Exception:
        return None

def decode_base64_content(content: str) -> str:
    try:
        stripped = content.strip()
        rem = len(stripped) % 4
        if rem:
            stripped += '=' * (4 - rem)
        return base64.b64decode(stripped).decode('utf-8', errors='ignore')
    except Exception:
        return content

def fetch_all_sources() -> List[str]:
    all_configs = []
    for source in SOURCES_CONFIG:
        url = source['url']
        name = source['name']
        print(f"  [FETCH] {name}: {url[:80]}...")
        content = fetch_url(url)
        if not content:
            print(f"  [FAIL] {name}: не удалось загрузить")
            continue
        # Проверяем — Clash или base64 или plain text
        if is_clash_content(content):
            uris = clash_to_uris(content)
            all_configs.extend(uris)
            print(f"  [OK] {name}: Clash, {len(uris)} конфигов")
        else:
            lines = content.strip().split('\n')
            # Проверяем base64
            if lines and not any(is_supported_protocol(l.strip()) for l in lines[:5]):
                decoded = decode_base64_content(content)
                lines = decoded.strip().split('\n')
            # Фильтруем только конфиги
            valid_lines = [l.strip() for l in lines if is_supported_protocol(l.strip())]
            all_configs.extend(valid_lines)
            print(f"  [OK] {name}: {len(valid_lines)} конфигов")
    return all_configs

# =====================================================================
#  ФИЛЬТРАЦИЯ
# =====================================================================
def filter_configs(configs: List[str]) -> Tuple[List[str], List[Tuple[str, str]]]:
    """Фильтрует конфиги. Возвращает (список безопасных, список отклонённых с причинами)."""
    safe_configs = []
    rejected = []
    for cfg in configs:
        cfg = cfg.strip()
        if not cfg:
            continue
        if not is_supported_protocol(cfg):
            rejected.append((cfg, "неподдерживаемый протокол"))
            continue
        if not is_safe_config_base(cfg):
            # Определяем причину
            reason = _get_rejection_reason(cfg)
            rejected.append((cfg, reason))
            continue
        safe_configs.append(cfg)
    return safe_configs, rejected

def _get_rejection_reason(url: str) -> str:
    """Определяет причину отклонения конфига."""
    if has_custom_ca_mitm(url):
        return "кастомный CA / MITM"
    if has_malicious_dns_override(url):
        return "опасный DNS override"
    if has_sniffing_exfiltration(url):
        return "sniffing эксфильтрация"
    if has_invalid_reality_pbk(url):
        return "невалидный Reality pbk"
    if has_invalid_reality_sid(url):
        return "невалидный Reality sid"
    if has_insecure_params(url):
        return "небезопасные параметры"
    if is_dangerous_domain_param(url):
        return "опасный домен"
    if is_banned_host_universal(url):
        return "забаненный хост"
    if is_ssr_host_banned(url):
        return "забаненный SSR хост"
    if has_dangerous_transport_combination(url):
        return "опасная комбинация транспорта"
    if is_suspicious_encryption(url):
        return "подозрительное шифрование"
    if is_dangerous_uuid(url):
        return "опасный UUID"
    if not is_sing_box_transport_compatible(url):
        return "транспорт несовместим с sing-box"
    if not is_sing_box_ss_compatible(url):
        return "метод SS несовместим с sing-box"
    if not has_valid_sni_for_tls(url):
        return "отсутствует SNI для TLS"
    if url.startswith('vless://') and not is_safe_vless_base(url):
        return "vless не прошёл проверку"
    if url.startswith('trojan://') and not is_safe_trojan_base(url):
        return "trojan не прошёл проверку"
    if url.startswith('vmess://') and not is_safe_vmess_base(url):
        return "vmess не прошёл проверку"
    if url.startswith(('hysteria2://', 'hy2://')) and not is_safe_hysteria2_base(url):
        return "hysteria2 не прошёл проверку"
    if url.startswith('tuic://') and not is_safe_tuic_base(url):
        return "tuic не прошёл проверку"
    if url.startswith('ss://') and not is_safe_ss_base(url):
        return "ss не прошёл проверку"
    if url.startswith('ssr://') and not is_safe_ssr_base(url):
        return "ssr не прошёл проверку"
    return "неизвестная причина"

# =====================================================================
#  СОХРАНЕНИЕ РЕЗУЛЬТАТОВ
# =====================================================================
def save_results(safe_configs: List[str], rejected: List[Tuple[str, str]]):
    # Сохраняем безопасные конфиги
    with open(os.path.join(OUTPUT_DIR, "filtered.txt"), 'w', encoding='utf-8') as f:
        for cfg in safe_configs:
            f.write(cfg + '\n')
    
    # Сохраняем base64 версию
    b64_content = base64.b64encode('\n'.join(safe_configs).encode('utf-8')).decode('utf-8')
    with open(os.path.join(OUTPUT_DIR, "filtered_base64.txt"), 'w', encoding='utf-8') as f:
        f.write(b64_content)
    
    # Сохраняем отклонённые с причинами
    with open(os.path.join(REJECT_DIR, "rejected.txt"), 'w', encoding='utf-8') as f:
        for cfg, reason in rejected:
            f.write(f"{reason}|{cfg}\n")
    
    # Статистика
    stats = {
        'total_input': len(safe_configs) + len(rejected),
        'total_safe': len(safe_configs),
        'total_rejected': len(rejected),
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'rejection_reasons': defaultdict(int),
    }
    for _, reason in rejected:
        stats['rejection_reasons'][reason] += 1
    
    with open(os.path.join(OUTPUT_DIR, "stats.json"), 'w', encoding='utf-8') as f:
        json.dump(stats, f, ensure_ascii=False, indent=2)
    
    # Сохраняем Clash формат
    _save_clash_format(safe_configs)

def _save_clash_format(configs: List[str]):
    """Конвертирует и сохраняет в Clash формате."""
    if not HAS_YAML:
        return
    
    clash_proxies = []
    for cfg in configs:
        proxy = _uri_to_clash_proxy(cfg)
        if proxy:
            clash_proxies.append(proxy)
    
    if not clash_proxies:
        return
    
    clash_config = {
        'proxies': clash_proxies,
        'proxy-groups': [
            {
                'name': 'PROXY',
                'type': 'select',
                'proxies': [p['name'] for p in clash_proxies]
            }
        ],
        'rules': ['MATCH,PROXY']
    }
    
    with open(os.path.join(CLASH_DIR, "config.yaml"), 'w', encoding='utf-8') as f:
        yaml.dump(clash_config, f, allow_unicode=True, default_flow_style=False)

def _uri_to_clash_proxy(uri: str) -> Optional[dict]:
    """Конвертирует URI в Clash proxy формат."""
    try:
        if uri.startswith('vless://'):
            # Парсим vless URI
            m = re.search(r'vless://([^@]+)@([^:]+):(\d+)(?:\?(.*))?#(.*)?', uri)
            if not m:
                return None
            uuid, host, port, params_str, name = m.groups()
            params = {}
            if params_str:
                for kv in params_str.split('&'):
                    if '=' in kv:
                        k, v = kv.split('=', 1)
                        params[k] = urllib.parse.unquote(v)
            
            proxy = {
                'name': urllib.parse.unquote(name or 'vless')[:50],
                'type': 'vless',
                'server': host,
                'port': int(port),
                'uuid': uuid,
                'tls': params.get('security') == 'tls',
            }
            if params.get('sni'):
                proxy['servername'] = params['sni']
            if params.get('fp'):
                proxy['client-fingerprint'] = params['fp']
            if params.get('type') and params['type'] != 'tcp':
                proxy['network'] = params['type']
            if params.get('type') == 'ws':
                proxy['ws-opts'] = {
                    'path': params.get('path', '/'),
                    'headers': {'Host': params.get('host', host)}
                }
            if params.get('security') == 'reality':
                proxy['reality-opts'] = {
                    'public-key': params.get('pbk', ''),
                }
                if params.get('sid'):
                    proxy['reality-opts']['short-id'] = params['sid']
            return proxy
        
        elif uri.startswith('trojan://'):
            m = re.search(r'trojan://([^@]+)@([^:]+):(\d+)(?:\?(.*))?#(.*)?', uri)
            if not m:
                return None
            password, host, port, params_str, name = m.groups()
            params = {}
            if params_str:
                for kv in params_str.split('&'):
                    if '=' in kv:
                        k, v = kv.split('=', 1)
                        params[k] = urllib.parse.unquote(v)
            
            proxy = {
                'name': urllib.parse.unquote(name or 'trojan')[:50],
                'type': 'trojan',
                'server': host,
                'port': int(port),
                'password': urllib.parse.unquote(password),
            }
            if params.get('sni'):
                proxy['sni'] = params['sni']
            return proxy
        
        elif uri.startswith('ss://'):
            # Парсим SS URI
            after_proto = uri.replace('ss://', '', 1)
            if '#' in after_proto:
                after_proto, name = after_proto.split('#', 1)
            else:
                name = 'ss'
            if '?' in after_proto:
                after_proto = after_proto.split('?')[0]
            
            if '@' in after_proto:
                userinfo, hostport = after_proto.rsplit('@', 1)
                if ':' in userinfo:
                    method, password = userinfo.split(':', 1)
                else:
                    # base64 userinfo
                    try:
                        missing = len(userinfo) % 4
                        if missing:
                            userinfo += '=' * (4 - missing)
                        decoded = base64.b64decode(userinfo).decode('utf-8')
                        method, password = decoded.split(':', 1)
                    except Exception:
                        return None
                host, port = hostport.rsplit(':', 1)
            else:
                return None
            
            proxy = {
                'name': urllib.parse.unquote(name)[:50],
                'type': 'ss',
                'server': host,
                'port': int(port),
                'cipher': method,
                'password': password,
            }
            return proxy
        
        # Другие протоколы
        return None
    except Exception:
        return None

# =====================================================================
#  ГЛАВНАЯ ФУНКЦИЯ
# =====================================================================
def main():
    print("=" * 70)
    print("  ФИЛЬТР ПРОКСИ-КОНФИГУРАЦИЙ v6.0")
    print("  Защита: Karing + V2RayNG + Clash + sing-box-extended")
    print("=" * 70)
    print()
    
    # Загружаем конфиги из всех источников
    print("[1/4] Загрузка источников...")
    all_configs = fetch_all_sources()
    print(f"      Загружено: {len(all_configs)} конфигов")
    print()
    
    if not all_configs:
        print("[ERROR] Не загружено ни одного конфига")
        return
    
    # Фильтруем
    print("[2/4] Фильтрация безопасности...")
    safe_configs, rejected = filter_configs(all_configs)
    print(f"      Прошли фильтр: {len(safe_configs)}")
    print(f"      Отклонены: {len(rejected)}")
    print()
    
    # Дедупликация
    print("[3/4] Дедупликация...")
    deduped_configs = dedup_configs(safe_configs)
    print(f"      После дедупликации: {len(deduped_configs)}")
    print()
    
    # Сохраняем
    print("[4/4] Сохранение результатов...")
    save_results(deduped_configs, rejected)
    print(f"      Сохранено в {OUTPUT_DIR}/")
    print(f"        - filtered.txt ({len(deduped_configs)} конфигов)")
    print(f"        - filtered_base64.txt (base64 версия)")
    print(f"        - rejected/ ({len(rejected)} отклонённых)")
    print(f"        - stats.json (статистика)")
    print(f"        - Clash/config.yaml (Clash формат)")
    print()
    
    # Выводим топ причин отклонения
    if rejected:
        print("Топ причин отклонения:")
        reason_count = defaultdict(int)
        for _, reason in rejected:
            reason_count[reason] += 1
        for reason, count in sorted(reason_count.items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"  {count:5d} — {reason}")
        print()
    
    print("=" * 70)
    print("  ГОТОВО")
    print("=" * 70)

if __name__ == '__main__':
    main()
