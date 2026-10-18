#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Фильтр прокси-конфигураций v6.0 (Karing / NekoBox / v2rayNG + Clash/Mihomo)

Что нового по сравнению с v5.3 (по итогам сверки с Cleaner.py):
  * Каждая ссылка теперь РАЗБИРАЕТСЯ (с раскодированием процентов, &amp;,
    синонимов параметров), а не проверяется регулярками по сырой строке.
    Из-за этого закрыты обходы: &amp;allowInsecure=1, allowlnsecure=1,
    skip-cert-verify=1, insecure=yes, vmess-JSON с "tls":"none" и т.д.
  * Адрес сервера проверяется через модуль ipaddress: 169.254/16, 100.64/10,
    198.18/15, мультикаст, обфусцированные IP (0x7f000001, 2130706433,
    ведущие нули), публичные DNS-резолверы, порты < 22.
  * UUID проверяется у vless/vmess/tuic, пустые/служебные UUID отбрасываются.
  * Reality: pbk — строго 32 байта base64url; sid НЕ вырезается.
  * SS: legacy-формат, ss2022-ключи по частям, плагины, реклама в пароле.
  * Дубликаты схлопываются ДО подсчёта лимитов PBK/UUID/SID/host:port.
  * Clash: безопасное YAML-квотирование, уникальные имена, исправлены
    TUIC/SS-плагины/IPv6/serviceName; skip-cert-verify больше не теряется.
  * SSR удалён (его не поддерживают ни NekoBox, ни v2rayNG, ни ядро sing-box).
  * Источники с 3+ провалами больше не банятся навсегда (cooldown).
"""

import re
import os
import sys
import json
import time
import html
import base64
import calendar
import ipaddress
import threading
import subprocess
import urllib.request
import urllib.parse
import uuid as uuidlib
from urllib.parse import unquote
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict, Counter
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

if not HAS_YAML:
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
RETRY_AFTER_SECONDS = 12 * 3600          # через сколько повторить «мёртвый» источник
FETCH_TIMEOUT = 30
MAX_FETCH_BYTES = 64 * 1024 * 1024       # защита памяти от гигантских/бесконечных ответов

RAW_BASE = os.environ.get(
    'RAW_BASE',
    'https://raw.githubusercontent.com/Trojankill/Safe-server-lists-for-bypassing-whitelists/main/githubmirror'
)

# SSR удалён: его нет ни в v2rayNG, ни в NekoBox/sing-box, а «безопасные» AEAD-методы
# в SSR не существуют (там только потоковые шифры) — проверка всё равно отбрасывала всё.
SUPPORTED_PROTOCOLS = [
    "vless://", "vmess://", "trojan://",
    "hysteria2://", "hy2://",
    "ss://", "tuic://",
]
ACCEPTED = {"vless", "vmess", "trojan", "hysteria2", "ss", "tuic"}
SCHEME_ALIAS = {"hy2": "hysteria2"}

SOURCES_CONFIG = [
    {"name": "FILTER-1", "url": "https://hub.mos.ru/rkp/sub-roskompozor/raw/main/wl"},
    {"name": "FILTER-2", "url": "https://gitverse.ru/api/repos/KOT_ANTIDOT/BUNKER/raw/branch/master/BLWL_MIX.txt"},
    {"name": "FILTER-3", "url": "https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_lite.txt"},
    {"name": "FILTER-4", "url": "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-all.txt"},
    {"name": "FILTER-5", "url": "https://raw.githubusercontent.com/LSO-LinSpisokObhod/LSO-LinSpisokObhod.github.io/refs/heads/main/sub/LTE.txt"},
    {"name": "FILTER-6", "url": "https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/refs/heads/main/output/vless.txt"},
    {"name": "FILTER-7-BASE64", "url": "https://solovyov-jenya2004.vercel.app/final_sorted_base64/"},
    {"name": "FILTER-8-BASE64", "url": "https://raw.githubusercontent.com/Diversan313/apex-parser/refs/heads/main/subs/main/alive_bs.txt"},
    {"name": "FILTER-9-BASE64", "url": "https://raw.githubusercontent.com/Diversan313/apex-parser/main/subs/main/alive_bl.txt"},
    {"name": "FILTER-10", "url": "https://sub.vlessfo.ru/vlessforu/working_configs.txt"},
    {"name": "FILTER-11", "url": "https://hub.mos.ru/akelladejavu/bunker/-/raw/main/WHITE_LIST.txt"},
    {"name": "FILTER-12", "url": "https://p.kfwl.lol/https://tgmansion.fun/sub/3006966d1608d911"},
    {"name": "FILTER-13", "url": "https://github.com/vessel-web/CoolSubs/raw/refs/heads/main/Cool-White.txt"},
]

# Убраны записи-дубли: поддомены, которые и так перекрыты родителем
# (cdn.trahodrom.fun, rruu.persik.host, pol.skysafe.online, vepene.site,
#  gpt-plus.vepene.site -> .site, .grovpn.com.alexandroff.ru -> .alexandroff.ru).
BANNED_DOMAINS = [
    '.fly.dev', '.workers.dev', '.us.kg', '.xyz', '.work', '.site', '.click',
    '.eu.org', '.tk', '.ml', '.cf', '.ga', '.gq', '.mwscdn.ru',
    '.alexandroff.ru', '.qzz.io', '.dynu.net',
    'trahodrom.fun', 'persik.host', 'skysafe.online',
    'boot-lee.ru', 'locklance.lol',
    'xenovpn.top', 'towersflowerss.com',
    'cloudconsole.ru', 'moscow-neversleep.digital', 'amnesia.pw', 'magicvpssub.ru',
    'fromblancwithlove.com', 'koma-yt.pages.dev', 'ripaojiedian',
]

# Имена, которые не бывают публичными серверами (внутренние зоны)
NON_PUBLIC_SUFFIXES = (
    '.local', '.localhost', '.internal', '.lan', '.home.arpa', '.intranet',
    '.invalid', '.test', '.example', '.arpa', '.onion',
)

SAFE_SS_METHODS = {
    'aes-128-gcm', 'aes-256-gcm',
    'chacha20-poly1305', 'chacha20-ietf-poly1305',
    'xchacha20-poly1305', 'xchacha20-ietf-poly1305',
    '2022-blake3-aes-128-gcm', '2022-blake3-aes-256-gcm',
    '2022-blake3-chacha20-poly1305',
}

WEAK_SS_METHODS = {
    'rc4', 'rc4-md5', 'rc4-md5-6', 'des', 'des-cfb', 'bf-cfb', 'cast5-cfb',
    'salsa20', 'xsalsa20', 'chacha20', 'xchacha20', 'chacha20-ietf',
    'aes-128-cfb', 'aes-192-cfb', 'aes-256-cfb',
    'aes-128-cfb8', 'aes-192-cfb8', 'aes-256-cfb8',
    'aes-128-ctr', 'aes-192-ctr', 'aes-256-ctr',
    'camellia-128-cfb', 'camellia-192-cfb', 'camellia-256-cfb',
    'idea-cfb', 'rc2-cfb', 'seed-cfb', 'table', 'plain', 'none', '',
}

SAFE_SS_CANON = {m.replace('chacha20-poly1305', 'chacha20-ietf-poly1305') for m in SAFE_SS_METHODS}

SS_2022_KEY_LENGTHS = {
    '2022-blake3-aes-128-gcm': 16,
    '2022-blake3-aes-256-gcm': 32,
    '2022-blake3-chacha20-poly1305': 32,
}

# Плагины SS: единственный, который доезжает до обоих клиентов без потери
# обфускации, — obfs-local с obfs=http (v2rayNG v2ray-plugin и obfs=tls теряет).
SS_PLUGIN_ALIAS = {'simple-obfs': 'obfs-local', 'simple': 'obfs-local', 'obfs': 'obfs-local'}

SAFE_FINGERPRINTS = {
    'chrome', 'firefox', 'safari', 'ios', 'android',
    'edge', '360', 'qq', 'random', 'randomized',
}

TRUSTED_DNS = {
    '1.1.1.1', '8.8.8.8', '8.8.4.4', '94.140.14.14', '9.9.9.9',
    'cloudflare-dns.com', 'dns.google', 'dns.adguard.com',
}

TUIC_CC_WHITELIST = {'bbr', 'cubic', 'new_reno'}
TUIC_UDP_MODES = {'native', 'quic'}

# Транспорты, которые понимают клиенты. quic в списке нет: v2rayNG при импорте
# молча превращает такую ссылку в tcp.
NETS = {'tcp', 'ws', 'http', 'kcp', 'grpc', 'httpupgrade', 'xhttp'}
# Для TLS-режима (kcp с TLS не бывает). Раньше список был ws/grpc/http/tcp —
# httpupgrade и xhttp (законные транспорты) отбрасывались зря.
TLS_ALLOWED_NETS = {'tcp', 'ws', 'http', 'grpc', 'httpupgrade', 'xhttp'}

# --- политика (как в v5.3; можно ослабить/ужесточить) -----------------
REQUIRE_ALPN_FOR_TLS = True      # vless+tls без alpn — отбраковка (как было)
REQUIRE_HOST_FOR_WS = True       # vless/vmess ws/http без host — отбраковка (как было)
REJECT_PRIVATE = True            # локальные/зарезервированные IP
REJECT_DNS = True                # IP публичных DNS-резолверов как «сервер»
REJECT_IPV6 = False              # True — отбрасывать IPv6-адреса
MIN_PORT = 22                    # порты ниже — мусор из подписок

# Лимиты «публичного пула» (считаются по УНИКАЛЬНЫМ узлам внутри одного источника)
PBK_MAX = 3
UUID_MAX = 3
SID_MAX = 3
TROJAN_PASS_MAX = 3
TUIC_CRED_MAX = 3
HP_MAX = 5

TRUE_SET = {'1', 'true', 'yes', 'on'}
FALSE_SET = {'0', 'false', 'no', 'off'}
SCHEME_RE = re.compile(r'^([A-Za-z][A-Za-z0-9+.\-]*)://')
RANGE_RE = re.compile(r'^\d{1,5}(?:-\d{1,5})?(?:,\d{1,5}(?:-\d{1,5})?)*$')
SNI_RE = re.compile(r'^[A-Za-z0-9_](?:[A-Za-z0-9._\-]*[A-Za-z0-9_])?$')
_LABEL_RE = re.compile(r'^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$')

# Все спелльтинги «не проверять сертификат», которые встречаются в клиентах и
# генераторах (allowlnsecure — с маленькой «L» — реальная опечатка в подписках).
INSECURE_KEYS = {
    'allowinsecure', 'allowlnsecure', 'allow_insecure', 'insecure',
    'skip-cert-verify', 'skipcertverify', 'skip_cert_verify',
    'allowinsecurecipher',
}

# Публичные IP-резолверы: как «VPN-сервер» бессмысленны
IP_BLACKLIST = {
    '1.1.1.1', '1.0.0.1', '8.8.8.8', '8.8.4.4', '9.9.9.9', '149.112.112.112',
    '94.140.14.14', '94.140.15.15',
    '2606:4700:4700::1111', '2606:4700:4700::1001', '2001:4860:4860::8888',
    '2001:4860:4860::8844', '2620:fe::fe', '2620:fe::9',
}
BAD_V4 = [ipaddress.ip_network(x) for x in (
    '0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
    '172.16.0.0/12', '192.0.0.0/29', '192.0.2.0/24', '192.168.0.0/16', '198.18.0.0/15',
    '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4')]
BAD_V6 = [ipaddress.ip_network(x) for x in (
    '::/128', '::1/128', '::ffff:0:0/96', '64:ff9b::/96', '100::/64', '2001:db8::/32',
    'fc00::/7', 'fe80::/10', 'ff00::/8')]

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
    host = host.lower().strip('.')
    return any(_domain_matches(host, d) for d in BANNED_DOMAINS)

# =====================================================================
#  НОРМАЛИЗАЦИЯ СТРОКИ И РАЗБОР ЗАПРОСА (порт из Cleaner.py)
# =====================================================================

class Reject(Exception):
    """Конфиг отбракован; текст — причина (идёт в статистику)."""

_INVISIBLE_RE = re.compile('[\u200b\u200c\u200d\u2060\ufeff]')
_CTRL_RE = re.compile(r'[\x00-\x1f\x7f-\x9f\u2028\u2029]')

def preprocess(s: str) -> str:
    """Чинит типовые поломки ссылок ДО проверки.

    &amp; (бывает двойное), \\u0026, %5Cu0026, '¬' -> '&'. Невидимые символы и
    управляющие символы (в т.ч. \\n из \\u000a) вырезаются — иначе их можно
    использовать, чтобы спрятать параметр или вставить лишнюю строку в выход.
    Схема приводится к нижнему регистру (VLESS:// -> vless://).
    """
    s = _INVISIBLE_RE.sub('', s)
    prev = None
    while prev != s:
        prev = s
        s = re.sub(r'&amp;', '&', s, flags=re.I)
    if '\\u' in s:
        s = re.sub(r'\\u([0-9a-fA-F]{4})', lambda m: chr(int(m.group(1), 16)), s)
    s = re.sub(r'(?i)%5cu0026', '&', s)
    s = s.replace('¬', '&')
    s = _CTRL_RE.sub('', s)
    m = SCHEME_RE.match(s)
    if m:
        s = m.group(1).lower() + s[m.end(1):]
    return s.strip()

def _core(line: str) -> str:
    """Ссылка без имени (#fragment): проверки не должны смотреть на имя."""
    i = line.find('#')
    return line if i < 0 else line[:i]

def b64d(s):
    """base64 в любых написаниях (std/urlsafe, с паддингом и без); None — ошибка."""
    if not s:
        return None
    s = re.sub(r'\s+', '', s).rstrip('=')
    for c in (s, s.replace('-', '+').replace('_', '/')):
        try:
            return base64.b64decode(c + '=' * ((-len(c)) % 4), validate=True)
        except Exception:
            continue
    return None

class Q(dict):
    """Параметры запроса: первый ключ выигрывает (как в клиентах); .pairs — все пары."""
    pairs: list = []

def parse_query(qs: str) -> Q:
    q = Q()
    pairs = []
    for part in qs.split('&'):
        if not part:
            continue
        part = part.lstrip(';')
        if '=' not in part:
            try:
                dec = unquote(part)
            except Exception:
                dec = part
            if '=' in dec:
                part = dec
        k, _, v = part.partition('=')
        try:
            k, v = unquote(k).strip().lower(), unquote(v)
        except Exception:
            continue
        if k:
            pairs.append((k, v))
            if k not in q:
                q[k] = v
    q.pairs = pairs
    return q

def qget(q, *names, default=''):
    """Первое непустое значение параметра по списку синонимов."""
    for n in names:
        v = q.get(n.lower())
        if v not in (None, ''):
            return v
    return default

def _flag_on(v: str) -> bool:
    """Любое непустое значение, кроме явного «выключено», считается ВКЛЮЧЁННЫМ.

    Для флагов небезопасности это осознанно консервативно: 'allowInsecure=1;'
    или 'insecure=y' не должны проходить как «нечитаемо -> false».
    """
    v = str(v).strip().lower()
    return v != '' and v not in FALSE_SET

# =====================================================================
#  ПРОВЕРКА АДРЕСА (порт check_host / parse_hostport из Cleaner.py)
# =====================================================================

def check_host(raw: str) -> str:
    h = (raw or '').strip()
    if not h:
        raise Reject('пустой адрес')
    if h.startswith('[') and h.endswith(']'):
        h = h[1:-1]
    if ':' in h:
        try:
            ip = ipaddress.IPv6Address(h)
        except ValueError:
            raise Reject(f'неверный IPv6: {raw[:60]!r}')
        if REJECT_IPV6:
            raise Reject('IPv6-адрес отбракован настройкой REJECT_IPV6')
        s = str(ip)
        if REJECT_DNS and s in IP_BLACKLIST:
            raise Reject(f'публичный DNS как сервер: {s}')
        if REJECT_PRIVATE:
            for net in BAD_V6:
                if ip in net:
                    raise Reject(f'локальный/зарезервированный IPv6 {ip}')
            if ip.ipv4_mapped is not None:
                raise Reject(f'IPv4-mapped IPv6 {ip}')
        return s
    if re.fullmatch(r'(?:\d{1,3}\.){3}\d{1,3}', h):
        if any(len(o) > 1 and o[0] == '0' for o in h.split('.')):
            raise Reject('обфусцированный IP (ведущие нули)')
        try:
            ip = ipaddress.IPv4Address(h)
        except ValueError:
            raise Reject(f'неверный IPv4: {h[:40]!r}')
        s = str(ip)
        if REJECT_DNS and s in IP_BLACKLIST:
            raise Reject(f'публичный DNS как сервер: {s}')
        if REJECT_PRIVATE:
            for net in BAD_V4:
                if ip in net:
                    raise Reject(f'локальный/зарезервированный IP {ip}')
        return s
    if re.fullmatch(r'[0-9.]+', h) or re.fullmatch(r'0[xX][0-9a-fA-F.]+', h):
        raise Reject('обфусцированный числовой IP (decimal/hex)')
    d = h.rstrip('.').lower()
    if not d or len(d) > 253 or '.' not in d:
        raise Reject(f'невалидный домен: {raw[:60]!r}')
    parts = d.split('.')
    for p in parts:
        if not _LABEL_RE.match(p):
            raise Reject(f'невалидный домен: {raw[:60]!r}')
    if len(parts[-1]) < 2 or parts[-1].isdigit():
        raise Reject(f'невалидный домен: {raw[:60]!r}')
    if REJECT_PRIVATE and ('.' + d).endswith(NON_PUBLIC_SUFFIXES):
        raise Reject(f'внутренний/непубличный домен: {d}')
    return d

def parse_hostport(s: str) -> Tuple[str, int]:
    s = s.strip().strip('/')
    if not s:
        raise Reject('пустой host:port')
    if s.startswith('['):
        m = re.match(r'^\[([^\]]+)\]:(\d+)$', s)
        if not m:
            raise Reject(f'битый IPv6 authority: {s[:70]!r}')
        host, port = m.group(1), m.group(2)
    else:
        host, sep, port = s.rpartition(':')
        if not sep or not port.isdigit():
            raise Reject('не указан порт')
        if host == '':
            raise Reject(f'битый authority: {s[:70]!r}')
        if ':' in host:
            try:
                ipaddress.IPv6Address(host)
            except ValueError:
                raise Reject(f'битый authority: {s[:70]!r}')
    p = int(port)
    if not MIN_PORT <= p <= 65535:
        raise Reject(f'порт вне диапазона: {p} (допустимо {MIN_PORT}–65535)')
    h = check_host(host)
    if _is_host_banned(h):
        raise Reject(f'сервер в чёрном списке доменов: {h}')
    return h, p

def ports_in_range(spec: str) -> bool:
    for part in spec.split(','):
        part = part.strip()
        if '-' in part:
            a, _, b = part.partition('-')
            if not (a.isdigit() and b.isdigit()):
                return False
            if not (MIN_PORT <= int(a) <= int(b) <= 65535):
                return False
        elif not part.isdigit() or not MIN_PORT <= int(part) <= 65535:
            return False
    return True

def valid_sni(s: str) -> bool:
    return bool(s) and len(s) <= 253 and bool(SNI_RE.fullmatch(s))

def _norm_alpn(raw: str) -> List[str]:
    """Глубокий unquote (http%252F1.1), синонимы; остаются только h2/h3/http/1.1."""
    if not raw:
        return []
    r = raw
    for _ in range(3):
        if '%' not in r:
            break
        u = unquote(r)
        if u == r:
            break
        r = u
    amap = {'http1.1': 'http/1.1', 'h1': 'http/1.1', 'http2': 'h2', 'http/2': 'h2',
            'http3': 'h3', 'http/3': 'h3'}
    out = []
    for a in re.split(r'[,\s;]+', r):
        a = amap.get(a.strip().lower(), a.strip().lower())
        if a in ('http/1.1', 'h2', 'h3') and a not in out:
            out.append(a)
    return out

# =====================================================================
#  ОБЩИЕ ПРОВЕРКИ
# =====================================================================

def _check_uuid(s: str, what: str = 'id') -> str:
    try:
        u = uuidlib.UUID(str(s).strip())
    except Exception:
        raise Reject(f'{what} не является UUID: {str(s)[:40]!r}')
    if u.int == 0 or u.int == (1 << 128) - 1:
        raise Reject('нулевой/служебный UUID')
    return str(u)

def _host_param_banned(v: str) -> bool:
    for item in unquote(v).split(','):
        h = item.strip().lower().strip('.')
        if h.count(':') == 1:                # domain:port
            h = h.split(':')[0]
        if h and _is_host_banned(h):
            return True
    return False

def _check_pairs(q: Q):
    """Флаги небезопасности и «плохие» значения — по ВСЕМ парам, с синонимами."""
    for k, v in q.pairs:
        if k in INSECURE_KEYS and _flag_on(v):
            raise Reject(f'небезопасный параметр: {k}={v[:12]}')
        if k in ('disable_sni', 'disablesni') and _flag_on(v):
            raise Reject('disable_sni включён')
        if k in ('verify', 'tls13') and v.strip().lower() in FALSE_SET:
            raise Reject(f'небезопасный параметр: {k}={v[:12]}')
        if k in ('security', 'sec') and v.strip().lower() in ('none', 'false', '0', 'off', 'no'):
            raise Reject('нет TLS (security=none)')
        if k in ('sni', 'peer', 'servername', 'host', 'authority') and _host_param_banned(v):
            raise Reject(f'домен из чёрного списка в параметре {k}')

def _check_suspicious_params(q: Q):
    """Параметры, которых нет в честных ссылках (оставлено из v5.3)."""
    ca = q.get('ca', '')
    if ca and (ca.startswith('http') or len(ca) > 50):
        raise Reject('подозрительный ca= (MITM)')
    for k in ('dns', 'doh', 'dns-server'):
        v = q.get(k)
        if v:
            host = re.sub(r'^https?://', '', v.lower())
            host = host.split('/')[0].split('#')[0].split(':')[0].strip('.')
            if host and host not in TRUSTED_DNS:
                raise Reject('подмена DNS в параметрах')
    for k in ('sniffing', 'destoverride'):
        v = q.get(k, '').lower()
        if v and 'localhost' not in v and re.search(r'[a-z0-9-]+\.[a-z]{2,}', v):
            raise Reject('подозрительный sniffing/destOverride')

def _read_net(q: Q) -> str:
    net = qget(q, 'type', 'network', 'net').strip().lower()
    net = {'h2': 'http', 'websocket': 'ws', 'splithttp': 'xhttp',
           'raw': 'tcp', 'none': 'tcp', '': 'tcp'}.get(net, net)
    if net == 'quic':
        raise Reject('транспорт quic не поддерживается v2rayNG (станет tcp)')
    if net not in NETS:
        raise Reject(f'неизвестный транспорт type={net[:30]!r}')
    return net

def _check_vless_encryption(enc: str) -> str:
    enc = enc.strip()
    if not enc or enc.lower() == 'none':
        return ''
    parts = enc.split('.')
    if (parts[0] != 'mlkem768x25519plus' or len(parts) < 4
            or parts[1] not in ('native', 'xorpub', 'random')
            or parts[2] not in ('0rtt', '1rtt')
            or not all(re.fullmatch(r'[A-Za-z0-9_\-]+', p) for p in parts[3:])):
        raise Reject(f'vless encryption не none и не mlkem768x25519plus: {enc[:40]!r}')
    return enc

def _check_reality(pbk: str, sid: str, fp: str):
    if not pbk:
        raise Reject('reality без pbk')
    key = pbk.rstrip('=')
    # Xray/sing-box принимают только base64url (без + и /), ровно 32 байта
    if not re.fullmatch(r'[A-Za-z0-9_-]{43}', key):
        raise Reject('pbk не 43-символьный base64url X25519-ключ')
    raw = b64d(key)
    if raw is None or len(raw) != 32:
        raise Reject('pbk не декодируется в 32 байта')
    if not fp or fp not in SAFE_FINGERPRINTS:
        raise Reject(f'reality без допустимого fp (fp={fp[:20]!r})')
    if sid and (len(sid) > 16 or len(sid) % 2 != 0 or not re.fullmatch(r'[0-9a-fA-F]+', sid)):
        raise Reject(f'sid не hex ≤16 чётной длины: {sid[:20]!r}')

def _check_tls_block(net: str, sni: str, hhost: str, alpn_raw: str):
    if net not in TLS_ALLOWED_NETS:
        raise Reject(f'транспорт {net} не разрешён для TLS')
    if not sni:
        raise Reject('tls без sni')
    if not valid_sni(sni):
        raise Reject(f'невалидный sni: {sni[:40]!r}')
    if REQUIRE_HOST_FOR_WS and net in ('ws', 'http') and not hhost:
        raise Reject(f'{net} без host')
    if REQUIRE_ALPN_FOR_TLS:
        if not _norm_alpn(alpn_raw):
            raise Reject('tls без допустимого alpn (h2/http/1.1/h3)')

def _is_trojan_public_pool(core: str, q: Q) -> bool:
    markers = ('koma-yt.pages.dev', 'ripaojiedian', 't.me/ripaojiedian', 'trtelegram')
    lower = core.lower()
    if any(m in lower for m in markers):
        return True
    return 'trtelegram' in q.get('path', '').lower()

# =====================================================================
#  РАЗБОР ПРОТОКОЛОВ -> Cfg
# =====================================================================

class Cfg:
    """Результат разбора: только поля, нужные политике, лимитам и дедупликации."""
    __slots__ = ('proto', 'host', 'port', 'uuid', 'password', 'pbk', 'sid', 'key')

    def __init__(self, proto):
        self.proto = proto
        self.host, self.port = '', 0
        self.uuid = self.password = self.pbk = self.sid = ''
        self.key = ()

_KEY_IGNORE = {'fp', 'fingerprint', 'spx', 'spiderx', 'ps', 'remarks', 'remark', 'name',
               'mux', 'tfo', 'fastopen', 'tcp-fast-open', 'fm'}

def _qkey(q: Q):
    return tuple(sorted((k, v) for k, v in q.items() if k not in _KEY_IGNORE))

def _split_authority_uri(core: str):
    rest = core.split('://', 1)[1]
    body, _, qs = rest.partition('?')
    q = parse_query(qs)
    body = body.strip().strip('/')
    if '@' not in body:
        raise Reject("нет '@' в ссылке")
    userinfo, _, hostport = body.rpartition('@')
    hostport = hostport.split('/', 1)[0]
    return unquote(userinfo).strip(), hostport, q

def _common(c: Cfg, q: Q, core: str):
    _check_pairs(q)
    _check_suspicious_params(q)
    if _is_host_banned(c.host):
        raise Reject(f'сервер в чёрном списке доменов: {c.host}')

def _parse_vless(core: str) -> Cfg:
    userinfo, hostport, q = _split_authority_uri(core)
    c = Cfg('vless')
    c.uuid = _check_uuid(userinfo)
    c.host, c.port = parse_hostport(hostport)
    _common(c, q, core)
    sec = qget(q, 'security', 'sec').strip().lower()
    if sec not in ('tls', 'reality'):
        raise Reject(f'vless без TLS/Reality (security={sec[:12] or "нет"})')
    net = _read_net(q)
    _check_vless_encryption(qget(q, 'encryption'))
    sni = qget(q, 'sni', 'peer', 'servername').strip()
    hhost = qget(q, 'host').strip()
    if sec == 'reality':
        c.pbk = qget(q, 'pbk', 'publickey').strip()
        c.sid = qget(q, 'sid', 'shortid').strip()
        fp = qget(q, 'fp', 'fingerprint').strip().lower()
        _check_reality(c.pbk, c.sid, fp)
        flow = qget(q, 'flow').strip().lower()
        if flow not in ('xtls-rprx-vision', 'none', ''):
            raise Reject(f'неизвестный flow: {flow[:30]!r}')
    else:
        _check_tls_block(net, sni, hhost, qget(q, 'alpn'))
    c.key = ('vless', c.host, c.port, c.uuid, _qkey(q))
    return c

def _parse_trojan(core: str) -> Cfg:
    userinfo, hostport, q = _split_authority_uri(core)
    c = Cfg('trojan')
    c.password = userinfo
    if not c.password:
        raise Reject('пустой пароль trojan')
    c.host, c.port = parse_hostport(hostport)
    _common(c, q, core)
    enc = qget(q, 'encryption').strip().lower()
    if enc.startswith('ss'):
        raise Reject('trojan-go (encryption=ss;…) не поддерживается клиентами')
    sec = qget(q, 'security', 'sec').strip().lower()
    if sec not in ('', 'tls'):
        raise Reject(f'trojan с security={sec[:12]}')
    if _flag_on(qget(q, 'ws')) and not qget(q, 'type', 'network', 'net'):
        q['type'] = 'ws'                       # форма ws=1&wspath=… (как в Cleaner)
    _read_net(q)
    if not qget(q, 'sni', 'peer', 'servername').strip():
        raise Reject('trojan без sni')
    if not valid_sni(qget(q, 'sni', 'peer', 'servername').strip()):
        raise Reject('невалидный sni')
    if _is_trojan_public_pool(core, q):
        raise Reject('trojan из публичного пула (маркеры)')
    c.key = ('trojan', c.host, c.port, c.password, _qkey(q))
    return c

def _decode_vmess_body(data: str):
    """base64 -> (json-текст). Лечит мусорный хвост (…fQ==2) и двойной base64."""
    for attempt in range(2):
        dec = b64d(data)
        if dec is None:
            for cut in (1, 2, 3, 4):
                if len(data) > cut + 8:
                    dec = b64d(data[:-cut])
                    if dec is not None:
                        break
        if dec is None:
            raise Reject('тело vmess не является base64')
        try:
            text = dec.decode('utf-8').strip()
        except Exception:
            raise Reject('base64-тело vmess не UTF-8')
        if text.startswith('{'):
            return text
        if attempt == 0 and re.fullmatch(r'[A-Za-z0-9+/=_\-]{8,}', text):
            data = text
            continue
        raise Reject('формат vmess не распознан')
    raise Reject('формат vmess не распознан')

def _parse_vmess(core: str) -> Cfg:
    data = core.split('://', 1)[1]
    data_noq = data.split('?', 1)[0].strip().strip('/')
    c = Cfg('vmess')
    if '@' in data_noq:                         # редкая URL-форма vmess://uuid@host:port?…
        userinfo, hostport, q = _split_authority_uri(core)
        c.uuid = _check_uuid(userinfo)
        c.host, c.port = parse_hostport(hostport)
        _common(c, q, core)
        aid = qget(q, 'alterid', 'aid') or '0'
        if not aid.isdigit() or int(aid) != 0:
            raise Reject('vmess alterId != 0')
        sec = qget(q, 'security', 'sec').strip().lower()
        net = _read_net(q)
        if sec not in ('tls', 'reality'):
            raise Reject('vmess без TLS')
        if sec == 'reality':
            _check_reality(qget(q, 'pbk', 'publickey').strip(), qget(q, 'sid', 'shortid').strip(),
                           qget(q, 'fp', 'fingerprint').strip().lower())
        else:
            _check_tls_block(net, qget(q, 'sni', 'peer', 'servername').strip(),
                             qget(q, 'host').strip(), qget(q, 'alpn') or 'h2')
        c.key = ('vmess', c.host, c.port, c.uuid, _qkey(q))
        return c

    text = data_noq if data_noq.lstrip().startswith('{') else _decode_vmess_body(data_noq)
    try:
        j = json.loads(text)
    except Exception as e:
        raise Reject(f'vmess JSON невалиден: {str(e)[:40]}')
    if not isinstance(j, dict):
        raise Reject('vmess JSON — не объект')
    low = {}
    for k, v in j.items():
        low.setdefault(str(k).lower(), v)

    def g(*keys, d=''):
        for k in keys:
            v = low.get(k.lower())
            if v is not None and str(v).strip() != '':
                return str(v).strip()
        return d

    c.host, c.port = parse_hostport(f"{_bracket(g('add', 'address', 'server'))}:{g('port', 'p')}")
    c.uuid = _check_uuid(g('id', 'uuid', 'user'))
    aid = g('aid', 'alterid', 'alter_id') or '0'
    if not aid.isdigit() or int(aid) != 0:
        raise Reject('vmess alterId != 0')
    if g('v', d='2') not in ('1', '2'):
        raise Reject('vmess: неизвестная версия формата')
    scy = (g('scy', 'security', 'cipher') or 'auto').lower()
    if scy not in ('auto', 'aes-128-gcm', 'chacha20-poly1305'):
        raise Reject(f'vmess: шифр {scy[:20]!r} не разрешён')
    # tls: "tls"/1/true — ок; "none", "", "false", "auto", "xtls" — НЕ ок
    # (раньше "none" считалась непустой строкой и проходила как TLS!)
    if g('tls').lower() not in ('tls', '1', 'true'):
        raise Reject('vmess без TLS')
    for kk in INSECURE_KEYS:
        v = low.get(kk)
        if v is not None and _flag_on(str(v)):
            raise Reject(f'небезопасный параметр: {kk}')
    net = {'h2': 'http', 'websocket': 'ws', 'splithttp': 'xhttp', 'raw': 'tcp', 'none': 'tcp',
           '': 'tcp'}.get((g('net', 'network') or 'tcp').lower(), (g('net', 'network') or 'tcp').lower())
    if net == 'quic':
        raise Reject('транспорт quic не поддерживается v2rayNG (станет tcp)')
    if net not in TLS_ALLOWED_NETS:
        raise Reject(f'vmess: транспорт {net[:20]!r} не разрешён')
    if REQUIRE_HOST_FOR_WS and net in ('ws', 'http') and not g('host'):
        raise Reject(f'vmess {net} без host')
    sni = g('sni', 'sn', 'servername')
    if sni and not valid_sni(sni):
        raise Reject(f'невалидный sni: {sni[:40]!r}')
    for fld in ('sni', 'sn', 'servername', 'host'):
        val = g(fld)
        if val and _host_param_banned(val):
            raise Reject(f'домен из чёрного списка в поле {fld}')
    if _is_host_banned(c.host):
        raise Reject(f'сервер в чёрном списке доменов: {c.host}')
    items = tuple(sorted((k, str(v)) for k, v in low.items() if k not in _KEY_IGNORE))
    c.key = ('vmess', c.host, c.port, c.uuid, items)
    return c

def _bracket(h: str) -> str:
    return f'[{h}]' if ':' in h and not h.startswith('[') else h

def _check_ss_plugin(raw: str):
    plug = unquote(raw)
    for _ in range(2):                          # дважды закодированный плагин
        head = plug.partition(';')[0]
        if '%3b' not in head.lower():
            break
        dec = unquote(plug)
        if ';' not in dec:
            break
        plug = dec
    name, _, opts = plug.partition(';')
    canon = SS_PLUGIN_ALIAS.get(name.strip().lower(), name.strip().lower())
    if canon != 'obfs-local':
        raise Reject(f'ss-плагин {name[:30]!r} не поддерживается клиентами '
                     '(доезжает только obfs-local с obfs=http)')
    kv = {}
    for part in opts.split(';'):
        if part:
            k, _, v = part.partition('=')
            kv[k.strip().lower()] = v
    if kv.get('obfs', 'http') != 'http':
        raise Reject('ss obfs-local: v2rayNG понимает только obfs=http')

def _check_ss2022_password(method: str, password: str):
    want = SS_2022_KEY_LENGTHS[method]
    parts = password.split(':')
    if len(parts) > 2 or (len(parts) == 2 and 'chacha20' in method):
        raise Reject('ss2022: недопустимая структура пароля (EIH)')
    for part in parts:
        if len(part) % 4 == 1:
            raise Reject('ss2022: ключ не base64')
        try:
            raw = base64.b64decode(part + '=' * (-len(part) % 4), validate=True)
        except Exception:
            raise Reject('ss2022: ключ не std-base64')
        if len(raw) != want:
            raise Reject(f'ss2022: ключ {len(raw)} байт, нужно {want}')

def _parse_ss(core: str) -> Cfg:
    body = core.split('://', 1)[1]
    body, _, qs = body.partition('?')
    q = parse_query(qs)
    body = body.strip()
    c = Cfg('ss')
    plugin = qget(q, 'plugin').strip()
    if plugin:
        _check_ss_plugin(plugin)
    if '@' in body:
        userinfo, _, hostport = body.rpartition('@')
        hostport = hostport.split('/', 1)[0]
        c.host, c.port = parse_hostport(hostport)
        ui = unquote(userinfo).strip()
        dec = b64d(ui)
        if dec is not None:
            try:
                t = dec.decode('utf-8').strip()
            except Exception:
                t = ''
            if ':' in t and t.partition(':')[0].strip().lower() in (
                    SAFE_SS_METHODS | WEAK_SS_METHODS):
                ui = t
        if ':' not in ui:
            raise Reject('ss: userinfo не содержит method:password')
        method, _, password = ui.partition(':')
    else:                                       # legacy: ss://base64(method:pass@host:port)
        dec = b64d(body.strip('/'))
        if dec is None:
            raise Reject("ss: нет '@' и тело не base64")
        try:
            t = dec.decode('utf-8')
        except Exception:
            raise Reject('ss legacy-тело не UTF-8')
        m = re.match(r'^([^:@]*):(.*)@(.+)$', t, re.S)
        if not m:
            raise Reject('ss legacy-формат не method:password@host:port')
        method, password = m.group(1), m.group(2)
        c.host, c.port = parse_hostport(m.group(3).split('?', 1)[0].split('/', 1)[0])
    method = method.strip().lower()
    password = password.strip()
    method = {'chacha20-poly1305': 'chacha20-ietf-poly1305',
              'xchacha20-poly1305': 'xchacha20-ietf-poly1305'}.get(method, method)
    if not password:
        raise Reject('ss: пустой пароль')
    if method in WEAK_SS_METHODS or method not in SAFE_SS_CANON:
        raise Reject(f'ss: небезопасный/неизвестный метод {method[:30]!r}')
    if re.search(r'https?://|t\.me', password, re.I):
        raise Reject('ss: пароль-реклама')
    if method in SS_2022_KEY_LENGTHS:
        _check_ss2022_password(method, password)
    _check_pairs(q)
    _check_suspicious_params(q)
    if _is_host_banned(c.host):
        raise Reject(f'сервер в чёрном списке доменов: {c.host}')
    c.password = password
    c.key = ('ss', c.host, c.port, method, password, plugin)
    return c

def _parse_hy2(core: str) -> Cfg:
    userinfo, hostport, q = _split_authority_uri(core)   # '@' обязателен (раньше не требовался)
    c = Cfg('hysteria2')
    c.password = userinfo
    if not c.password:
        raise Reject('hysteria2: пустой auth')
    if hostport.startswith('['):
        m = re.match(r'^\[([^\]]+)\]:(.*)$', hostport)
        if not m:
            raise Reject('hysteria2: битый IPv6 authority')
        host, pr = m.group(1), m.group(2)
    else:
        host, sep, pr = hostport.rpartition(':')
        if not sep or not pr:
            raise Reject('hysteria2: не указан порт')
    if pr.isdigit():
        if not MIN_PORT <= int(pr) <= 65535:
            raise Reject(f'порт вне диапазона: {pr}')
        c.port = int(pr)
    elif RANGE_RE.match(pr) and ports_in_range(pr):
        c.port = int(re.match(r'\d{1,5}', pr).group(0))
    else:
        raise Reject(f'неверный порт: {pr[:30]!r}')
    c.host = check_host(host)
    _common(c, q, core)
    sni = qget(q, 'sni', 'peer').strip()
    if not sni:
        raise Reject('hysteria2 без sni')
    if not valid_sni(sni):
        raise Reject('невалидный sni')
    ob = qget(q, 'obfs').strip().lower()
    if ob:
        if ob != 'salamander':
            raise Reject(f'hysteria2 obfs={ob[:20]!r} не поддерживается (только salamander)')
        if not qget(q, 'obfs-password', 'obfspassword', 'obfs-param', 'obfsparam').strip():
            raise Reject('hysteria2 obfs без пароля')
    mp = qget(q, 'mport', 'ports').strip()
    if mp and not (RANGE_RE.match(mp) and ports_in_range(mp)):
        raise Reject('hysteria2: невалидный mport')
    c.key = ('hysteria2', c.host, c.port, c.password, _qkey(q))
    return c

def _parse_tuic(core: str) -> Cfg:
    userinfo, hostport, q = _split_authority_uri(core)
    c = Cfg('tuic')
    uuid_part, sep, pwd = userinfo.partition(':')
    if not sep:
        raise Reject('tuic: v4-токен не поддерживается (нужен uuid:password)')
    c.uuid = _check_uuid(uuid_part, 'tuic uuid')
    c.password = pwd.strip()
    if not c.password:
        raise Reject('tuic: пустой пароль')
    c.host, c.port = parse_hostport(hostport)
    _common(c, q, core)
    sni = qget(q, 'sni', 'peer').strip()
    if not sni:
        raise Reject('tuic без sni')
    if not valid_sni(sni):
        raise Reject('невалидный sni')
    cc = qget(q, 'congestion_control', 'congestioncontrol', 'cc').strip().lower()
    if cc and cc not in TUIC_CC_WHITELIST:
        raise Reject(f'tuic congestion_control={cc[:20]!r}')
    urm = qget(q, 'udp_relay_mode', 'udprelaymode').strip().lower()
    if urm and urm not in TUIC_UDP_MODES:
        raise Reject(f'tuic udp_relay_mode={urm[:20]!r}')
    alpn_raw = qget(q, 'alpn')
    if alpn_raw and 'h3' not in _norm_alpn(alpn_raw):
        raise Reject('tuic: alpn без h3')
    c.key = ('tuic', c.host, c.port, c.uuid, c.password, _qkey(q))
    return c

_PARSERS = {
    'vless': _parse_vless, 'trojan': _parse_trojan, 'vmess': _parse_vmess,
    'ss': _parse_ss, 'hysteria2': _parse_hy2, 'tuic': _parse_tuic,
}

# =====================================================================
#  ПУБЛИЧНЫЙ API ПРОВЕРКИ
# =====================================================================

def is_supported_protocol(line: str) -> bool:
    low = line.strip()[:12].lower()
    return any(low.startswith(p) for p in SUPPORTED_PROTOCOLS)

@lru_cache(maxsize=131072)
def analyze_config(line: str):
    """-> (причина_отбраковки | '', ids). Пустая причина = конфиг прошёл.

    ids = (key, pbk, vless_uuid, sid, trojan_pass, tuic_cred, 'host:port:proto')
    — всё, что нужно для дедупликации и лимитов «публичного пула».
    """
    try:
        line = preprocess(line)
        if not line or not is_supported_protocol(line):
            raise Reject('протокол не поддерживается')
        m = SCHEME_RE.match(line)
        proto = SCHEME_ALIAS.get(m.group(1).lower(), m.group(1).lower())
        if proto not in ACCEPTED:
            raise Reject(f'протокол {proto} не поддерживается')
        c = _PARSERS[proto](_core(line))
        tcred = f'{c.uuid}:{c.password}' if proto == 'tuic' else ''
        ids = (
            c.key,
            c.pbk,
            c.uuid if proto == 'vless' else '',
            c.sid,
            c.password if proto == 'trojan' else '',
            tcred,
            f'{c.host}:{c.port}:{proto}',
        )
        return '', ids
    except Reject as e:
        return str(e), None
    except Exception as e:
        return f'внутренняя ошибка: {type(e).__name__}', None

def get_reject_reason(line: str) -> str:
    return analyze_config(line)[0]

def is_safe_config_base(line: str) -> bool:
    return analyze_config(line)[0] == ''

def reason_bucket(reason: str) -> str:
    """Укрупняет причину для статистики (без переменных значений)."""
    return re.sub(r'[:=(\[{].*$', '', reason).strip()[:70] or reason[:70]

# =====================================================================
#  ПАРСИНГ МНОГОСТРОЧНЫХ КОНФИГОВ
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
#  CLASH PARSING (YAML -> URI)
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
        for p in data.get('proxies') or []:
            if not isinstance(p, dict):
                continue
            u = _clash_proxy_to_uri(p)
            if u:
                uris.append(u)
        return uris
    except Exception:
        return []

def _clash_flag(p: dict, *keys) -> bool:
    for k in keys:
        v = p.get(k)
        if v is not None and _flag_on(str(v)):
            return True
    return False

def _clash_alpn(p: dict) -> str:
    al = p.get('alpn')
    if isinstance(al, list):
        return ','.join(str(x) for x in al)
    return str(al) if al else ''

def _clash_qs(params: dict) -> str:
    return '&'.join(f'{k}={urllib.parse.quote(str(v), safe="")}'
                    for k, v in params.items() if v not in (None, ''))

def _clash_transport(p: dict, params: dict, net: str):
    """ws/grpc/h2/http-опции Clash -> параметры ссылки."""
    if net == 'ws':
        wo = p.get('ws-opts') or {}
        if isinstance(wo, dict):
            if wo.get('path'):
                params['path'] = str(wo['path'])
            wh = wo.get('headers') or {}
            if isinstance(wh, dict):
                hv = wh.get('Host') or wh.get('host')
                if hv:
                    params['host'] = str(hv)
    elif net == 'grpc':
        go = p.get('grpc-opts') or {}
        if isinstance(go, dict) and go.get('grpc-service-name'):
            params['serviceName'] = str(go['grpc-service-name'])
    elif net in ('h2', 'http'):
        ho = p.get('h2-opts') or p.get('http-opts') or {}
        if isinstance(ho, dict):
            for key, dst in (('path', 'path'), ('host', 'host')):
                v = ho.get(key)
                if isinstance(v, list) and v:
                    v = v[0]
                if v:
                    params[dst] = str(v)

def _clash_proxy_to_uri(p: dict) -> Optional[str]:
    t = str(p.get('type', '')).lower()
    name = str(p.get('name', ''))
    host = str(p.get('server', ''))
    try:
        port = int(p.get('port', 0))
    except (ValueError, TypeError):
        return None
    if not host:
        return None
    frag = urllib.parse.quote(name)
    hp = f"{_bracket(host)}:{port}"
    # skip-cert-verify НЕ теряем: превращаем в allowInsecure=1, и фильтр такой узел отбракует
    # (раньше флаг пропадал, и небезопасный узел выглядел «чистым»)
    insecure = _clash_flag(p, 'skip-cert-verify')

    if t == 'vless':
        params = {}
        if p.get('reality-opts'):
            params['security'] = 'reality'
            ro = p['reality-opts'] if isinstance(p['reality-opts'], dict) else {}
            if ro.get('public-key'):
                params['pbk'] = ro['public-key']
            if ro.get('short-id'):
                params['sid'] = ro['short-id']
        elif p.get('tls'):
            params['security'] = 'tls'
        else:
            params['security'] = 'none'
        params['sni'] = p.get('servername') or p.get('sni')
        params['fp'] = p.get('client-fingerprint')
        params['flow'] = p.get('flow')
        params['alpn'] = _clash_alpn(p)
        if insecure:
            params['allowInsecure'] = '1'
        net = str(p.get('network', 'tcp'))
        params['type'] = 'http' if net == 'h2' else net
        _clash_transport(p, params, net)
        return f"vless://{p.get('uuid', '')}@{hp}?{_clash_qs(params)}#{frag}"
    if t == 'vmess':
        return _clash_vmess_to_uri(p, name, host, port, insecure)
    if t == 'trojan':
        params = {'sni': p.get('sni') or p.get('servername'), 'alpn': _clash_alpn(p)}
        if insecure:
            params['allowInsecure'] = '1'
        net = str(p.get('network', 'tcp'))
        if net != 'tcp':
            params['type'] = 'http' if net == 'h2' else net
            _clash_transport(p, params, net)
        return f"trojan://{urllib.parse.quote(str(p.get('password', '')), safe='')}@{hp}?{_clash_qs(params)}#{frag}"
    if t in ('hysteria2', 'hy2'):
        params = {'sni': p.get('sni'), 'alpn': _clash_alpn(p),
                  'obfs': p.get('obfs'), 'obfs-password': p.get('obfs-password'),
                  'mport': p.get('ports') or p.get('mport')}
        if insecure:
            params['insecure'] = '1'
        qs = _clash_qs(params)
        return (f"hysteria2://{urllib.parse.quote(str(p.get('password', '')), safe='')}@{hp}"
                + (f"?{qs}" if qs else '') + f"#{frag}")
    if t == 'tuic':
        # Clash/Mihomo TUIC v5 хранит uuid + password; token — это v4 (не поддерживается)
        if p.get('uuid'):
            cred = f"{p['uuid']}:{urllib.parse.quote(str(p.get('password', '')), safe='')}"
        else:
            cred = urllib.parse.quote(str(p.get('token', '')), safe='')
        params = {'sni': p.get('sni'), 'alpn': _clash_alpn(p),
                  'congestion_control': p.get('congestion-controller'),
                  'udp_relay_mode': p.get('udp-relay-mode')}
        if insecure:
            params['allow_insecure'] = '1'
        qs = _clash_qs(params)
        return f"tuic://{cred}@{hp}" + (f"?{qs}" if qs else '') + f"#{frag}"
    if t == 'ss':
        try:
            userinfo = f"{p.get('cipher', '')}:{p.get('password', '')}"
            ub = base64.urlsafe_b64encode(userinfo.encode()).decode().rstrip('=')
        except Exception:
            return None
        qs = ''
        plug = str(p.get('plugin') or '')
        if plug:
            po = p.get('plugin-opts') or {}
            if not isinstance(po, dict):
                po = {}
            if plug in ('obfs', 'obfs-local', 'simple-obfs'):
                s = f"obfs-local;obfs={po.get('mode', 'http')}"
                if po.get('host'):
                    s += f";obfs-host={po['host']}"
            else:
                s = plug
                if po.get('mode'):
                    s += f";mode={po['mode']}"
                if po.get('tls'):
                    s += ';tls'
                if po.get('host'):
                    s += f";host={po['host']}"
                if po.get('path'):
                    s += f";path={po['path']}"
            qs = '?plugin=' + urllib.parse.quote(s, safe='')
        return f"ss://{ub}@{hp}{qs}#{frag}"
    return None                       # ssr и прочее — не поддерживаются

def _clash_vmess_to_uri(p: dict, name: str, host: str, port: int,
                        insecure: bool = False) -> Optional[str]:
    net = str(p.get('network', 'tcp'))
    cfg = {
        'v': '2',
        'ps': name,
        'add': host,
        'port': str(port),
        'id': str(p.get('uuid', '')),
        'aid': str(p.get('alterId', 0)),
        'scy': str(p.get('cipher', 'auto')),
        'net': net,
        'tls': 'tls' if p.get('tls') else '',
        'type': 'none',
    }
    sni = p.get('servername') or p.get('sni')
    if sni:
        cfg['sni'] = str(sni)
    if _clash_alpn(p):
        cfg['alpn'] = _clash_alpn(p)
    if insecure:
        cfg['allowInsecure'] = 1
    tmp = {}
    _clash_transport(p, tmp, net)
    if tmp.get('path'):
        cfg['path'] = tmp['path']
    if tmp.get('host'):
        cfg['host'] = tmp['host']
    if tmp.get('serviceName'):
        cfg['path'] = tmp['serviceName']
    j = json.dumps(cfg, separators=(',', ':'), ensure_ascii=False)
    return 'vmess://' + base64.b64encode(j.encode()).decode()

# =====================================================================
#  CLASH OUTPUT (URI -> YAML)
# =====================================================================

def _sanitize_name(s) -> str:
    """Убирает переносы строк, табы, control characters из имени прокси."""
    s = str(s)
    # Убираем newline, carriage return, tab и control characters
    s = re.sub(r'[\x00-\x1f\x7f-\x9f\u2028\u2029]', ' ', s)
    # Убираем множественные пробелы
    s = re.sub(r'\s+', ' ', s).strip()
    return s

def _q(s) -> str:
    """Любая строка -> валидный YAML double-quoted скаляр (через json.dumps).

    Старая версия не экранировала '\\' и использовала bare-скаляры, из-за чего имя вида
    foo'\\ ломало весь YAML, а пароль 123456/yes/null превращался в число/bool/null.
    """
    return json.dumps(_sanitize_name(s), ensure_ascii=False)

def uri_to_clash(uri: str) -> Optional[dict]:
    name = ''
    if '#' in uri:
        uri, _, frag = uri.partition('#')
        try:
            name = urllib.parse.unquote(frag)
        except Exception:
            name = frag
    name = _sanitize_name(name)
    proto = uri.split('://')[0].lower()
    if proto == 'vless':
        return _vless_to_clash(uri, name)
    if proto == 'vmess':
        return _vmess_to_clash(uri, name)
    if proto == 'trojan':
        return _trojan_to_clash(uri, name)
    if proto in ('hysteria2', 'hy2'):
        return _hy2_to_clash(uri, name)
    if proto == 'tuic':
        return _tuic_to_clash(uri, name)
    if proto == 'ss':
        return _ss_to_clash(uri, name)
    return None

def _getparams(uri: str) -> dict:
    """Параметры ссылки с раскодированными значениями; ключи в нижнем регистре."""
    if '?' not in uri:
        return {}
    return dict(parse_query(uri.split('?', 1)[1]))

def _vless_to_clash(uri: str, name: str) -> Optional[dict]:
    # IPv6 bracket
    m6 = re.search(r'vless://([^@]+)@\[([0-9a-fA-F:]+)\]:(\d+)', uri)
    if m6:
        uuid, host, port = m6.group(1), m6.group(2), int(m6.group(3))
    else:
        m = re.search(r'vless://([^@]+)@([^:/?#]+):(\d+)', uri)
        if not m:
            return None
        uuid, host, port = m.group(1), m.group(2), int(m.group(3))
    p = _getparams(uri)
    out = {
        'name': name or f"{host}:{port}",
        'type': 'vless',
        'server': host,
        'port': port,
        'uuid': uuid,
        'udp': True,
    }
    sec = p.get('security', '')
    if sec in ('tls', 'reality'):
        out['tls'] = True
        if p.get('sni'):
            out['servername'] = p['sni']
        if p.get('alpn'):
            out['alpn'] = p['alpn'].split(',')
        if p.get('fp'):
            out['client-fingerprint'] = p['fp']
        if sec == 'reality':
            ro = {}
            if p.get('pbk'):
                ro['public-key'] = p['pbk']
            if p.get('sid'):
                ro['short-id'] = p['sid']
            out['reality-opts'] = ro
        if p.get('flow'):
            out['flow'] = p['flow']
    net = p.get('type', 'tcp')
    out['network'] = net
    if net == 'ws':
        wo = {}
        if p.get('path'):
            wo['path'] = p['path']
        if p.get('host'):
            wo['headers'] = {'Host': p['host']}
        out['ws-opts'] = wo
    elif net == 'grpc':
        go = {}
        if p.get('servicename'):
            go['grpc-service-name'] = p['servicename']
        out['grpc-opts'] = go
    elif net in ('http', 'h2'):
        ho = {}
        if p.get('path'):
            ho['path'] = [p['path']]
        if p.get('host'):
            ho['host'] = [p['host']]
        out['h2-opts'] = ho
        out['network'] = 'h2'
    return out

def _vmess_to_clash(uri: str, name: str) -> Optional[dict]:
    body = uri.replace('vmess://', '', 1)
    if '@' in body.split('?')[0]:
        # IPv6 bracket
        m6 = re.search(r'vmess://([^@]+)@\[([0-9a-fA-F:]+)\]:(\d+)', uri)
        if m6:
            uuid, host, port = m6.group(1), m6.group(2), int(m6.group(3))
        else:
            m = re.search(r'vmess://([^@]+)@([^:/?#]+):(\d+)', uri)
            if not m:
                return None
            uuid, host, port = m.group(1), m.group(2), int(m.group(3))
        p = _getparams(uri)
        try:
            aid = int(p.get('alterid', '0'))
        except ValueError:
            aid = 0
        out = {
            'name': name or f"{host}:{port}",
            'type': 'vmess',
            'server': host,
            'port': port,
            'uuid': uuid,
            'alterId': aid,
            'cipher': p.get('encryption', 'auto'),
            'udp': True,
        }
        sec = p.get('security', '')
        if sec in ('tls', 'reality'):
            out['tls'] = True
            if p.get('sni'):
                out['servername'] = p['sni']
            if p.get('alpn'):
                out['alpn'] = p['alpn'].split(',')
        net = p.get('type', 'tcp')
        out['network'] = net if net != 'h2' else 'h2'
        if net == 'ws':
            wo = {}
            if p.get('path'):
                wo['path'] = p['path']
            if p.get('host'):
                wo['headers'] = {'Host': p['host']}
            out['ws-opts'] = wo
        elif net == 'grpc':
            go = {}
            if p.get('servicename'):
                go['grpc-service-name'] = p['servicename']
            out['grpc-opts'] = go
        return out
    else:
        b64 = body.split('#')[0].split('?')[0]
        try:
            missing = len(b64) % 4
            if missing:
                b64 += '=' * (4 - missing)
            decoded = base64.b64decode(b64).decode('utf-8')
            cfg = json.loads(decoded)
            try:
                aid = int(cfg.get('aid', 0))
            except (ValueError, TypeError):
                aid = 0
            name_val = name or cfg.get('ps', f"{cfg.get('add')}:{cfg.get('port')}")
            out = {
                'name': _sanitize_name(name_val),
                'type': 'vmess',
                'server': str(cfg.get('add', '')),
                'port': int(cfg.get('port', 443)),
                'uuid': str(cfg.get('id', '')),
                'alterId': aid,
                'cipher': str(cfg.get('scy', 'auto')),
                'udp': True,
            }
            if cfg.get('tls') in ('tls', True, 'true'):
                out['tls'] = True
            if cfg.get('sni'):
                out['servername'] = str(cfg['sni'])
            net = str(cfg.get('net', 'tcp')).lower()
            out['network'] = net
            if net == 'ws':
                wo = {}
                if cfg.get('path'):
                    wo['path'] = str(cfg['path'])
                if cfg.get('host'):
                    wo['headers'] = {'Host': str(cfg['host'])}
                out['ws-opts'] = wo
            elif net == 'grpc':
                go = {}
                if cfg.get('path'):
                    go['grpc-service-name'] = str(cfg['path'])
                out['grpc-opts'] = go
            return out
        except Exception:
            return None

def _trojan_to_clash(uri: str, name: str) -> Optional[dict]:
    m6 = re.search(r'trojan://([^@]+)@\[([0-9a-fA-F:]+)\]:(\d+)', uri)
    if m6:
        pwd, host, port = m6.group(1), m6.group(2), int(m6.group(3))
    else:
        m = re.search(r'trojan://([^@]+)@([^:/?#]+):(\d+)', uri)
        if not m:
            return None
        pwd, host, port = m.group(1), m.group(2), int(m.group(3))
    p = _getparams(uri)
    out = {
        'name': name or f"{host}:{port}",
        'type': 'trojan',
        'server': host,
        'port': port,
        'password': pwd,
        'udp': True,
    }
    if p.get('sni'):
        out['sni'] = p['sni']
    if p.get('alpn'):
        out['alpn'] = p['alpn'].split(',')
    net = p.get('type', 'tcp')
    if net == 'ws':
        out['network'] = 'ws'
        wo = {}
        if p.get('path'):
            wo['path'] = p['path']
        if p.get('host'):
            wo['headers'] = {'Host': p['host']}
        out['ws-opts'] = wo
    elif net == 'grpc':
        out['network'] = 'grpc'
        go = {}
        if p.get('servicename'):
            go['grpc-service-name'] = p['servicename']
        out['grpc-opts'] = go
    return out

def _hy2_to_clash(uri: str, name: str) -> Optional[dict]:
    m6 = re.search(r'(?:hysteria2|hy2)://([^@]*)@\[([0-9a-fA-F:]+)\]:(\d+)', uri)
    if m6:
        pwd, host, port = m6.group(1), m6.group(2), int(m6.group(3))
    else:
        m = re.search(r'(?:hysteria2|hy2)://([^@]*)@([^:/?#]+):(\d+)', uri)
        if not m:
            return None
        pwd, host, port = m.group(1), m.group(2), int(m.group(3))
    p = _getparams(uri)
    out = {
        'name': name or f"{host}:{port}",
        'type': 'hysteria2',
        'server': host,
        'port': port,
        'password': pwd,
    }
    if p.get('sni'):
        out['sni'] = p['sni']
    if p.get('insecure'):
        out['skip-cert-verify'] = p['insecure'] in ('1', 'true', 'True')
    if p.get('obfs'):
        out['obfs'] = p['obfs']
    if p.get('obfs-password'):
        out['obfs-password'] = p['obfs-password']
    return out

def _tuic_to_clash(uri: str, name: str) -> Optional[dict]:
    m6 = re.search(r'tuic://([^@]+)@\[([0-9a-fA-F:]+)\]:(\d+)', uri)
    if m6:
        cred, host, port = m6.group(1), m6.group(2), int(m6.group(3))
    else:
        m = re.search(r'tuic://([^@]+)@([^:/?#]+):(\d+)', uri)
        if not m:
            return None
        cred, host, port = m.group(1), m.group(2), int(m.group(3))
    p = _getparams(uri)
    out = {
        'name': name or f"{host}:{port}",
        'type': 'tuic',
        'server': host,
        'port': port,
    }
    if ':' in cred:
        tok, _, pwd = cred.partition(':')
        out['uuid'] = tok
        out['password'] = urllib.parse.unquote(pwd)
    else:
        out['token'] = cred
    if p.get('sni'):
        out['sni'] = p['sni']
    if p.get('congestion_control'):
        out['congestion-controller'] = p['congestion_control']
    if p.get('udp_relay_mode'):
        out['udp-relay-mode'] = p['udp_relay_mode']
    if p.get('alpn'):
        out['alpn'] = p['alpn'].split(',')
    return out

def _ss_to_clash(uri: str, name: str) -> Optional[dict]:
    try:
        after = uri.split('://', 1)[1].split('#')[0].split('?')[0]
        if '@' not in after:
            return None
        userinfo, hostport = after.rsplit('@', 1)
        hostport = hostport.split('/', 1)[0]
        userinfo = unquote(userinfo)
        dec = b64d(userinfo)             # url-safe/std, с паддингом и без
        if dec is not None and b':' in dec:
            t = dec.decode('utf-8', errors='ignore')
            if t.partition(':')[0].lower() in (SAFE_SS_METHODS | WEAK_SS_METHODS):
                userinfo = t
        if ':' not in userinfo:
            return None
        method, password = userinfo.split(':', 1)
        if hostport.startswith('['):
            m6 = re.match(r'\[([0-9a-fA-F:]+)\]:(\d+)', hostport)
            if not m6:
                return None
            host, port = m6.group(1), m6.group(2)
        else:
            if ':' not in hostport:
                return None
            host, port = hostport.rsplit(':', 1)
        out = {
            'name': name or f"{host}:{port}",
            'type': 'ss',
            'server': host,
            'port': int(port),
            'cipher': method,
            'password': password,
            'udp': True,
        }
        p = _getparams(uri)
        if p.get('plugin'):
            plugin = p['plugin'].split(';')
            kv = {}
            for opt in plugin[1:]:
                k, _, v = opt.partition('=')
                kv[k.strip().lower()] = v
            pname = SS_PLUGIN_ALIAS.get(plugin[0].strip().lower(), plugin[0].strip().lower())
            if pname == 'obfs-local':
                out['plugin'] = 'obfs'
                po = {'mode': kv.get('obfs', 'http')}
                if kv.get('obfs-host'):
                    po['host'] = kv['obfs-host']
                out['plugin-opts'] = po
            elif pname == 'v2ray-plugin':
                out['plugin'] = 'v2ray-plugin'
                po = {'mode': 'websocket'}
                if 'tls' in kv:
                    po['tls'] = True
                if kv.get('host'):
                    po['host'] = kv['host']
                if kv.get('path'):
                    po['path'] = kv['path']
                out['plugin-opts'] = po
        return out
    except Exception:
        return None

def _dump_clash_yaml(proxies: List[dict], filepath: str, title: str = 'clash'):
    lines = ['# clash/mihomo subscription']
    lines.append(f'# {time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())}')
    lines.append('proxies:')
    for p in proxies:
        lines.append(f'  - name: {_q(p["name"])}')
        lines.append(f'    type: {_q(p["type"])}')
        lines.append(f'    server: {_q(p["server"])}')
        lines.append(f'    port: {p["port"]}')
        for k, v in p.items():
            if k in ('name', 'type', 'server', 'port'):
                continue
            if isinstance(v, dict):
                lines.append(f'    {k}:')
                _dump_nested(v, lines, '      ')
            elif isinstance(v, list):
                lines.append(f'    {k}:')
                for item in v:
                    lines.append(f'      - {_q(item)}')
            elif isinstance(v, bool):
                lines.append(f'    {k}: {str(v).lower()}')
            elif isinstance(v, int):
                lines.append(f'    {k}: {v}')
            else:
                lines.append(f'    {k}: {_q(v)}')
    lines.append('proxy-groups:')
    lines.append('  - name: PROXY')
    lines.append('    type: select')
    lines.append('    proxies:')
    for p in proxies:
        lines.append(f'      - {_q(p["name"])}')
    lines.append('rules:')
    lines.append('  - MATCH,PROXY')
    with open(filepath, 'w', encoding='utf-8', newline='\n') as f:
        f.write('\n'.join(lines) + '\n')

def _dump_nested(d: dict, lines: List[str], indent: str):
    for k, v in d.items():
        if isinstance(v, dict):
            lines.append(f'{indent}{k}:')
            _dump_nested(v, lines, indent + '  ')
        elif isinstance(v, list):
            lines.append(f'{indent}{k}:')
            for item in v:
                lines.append(f'{indent}  - {_q(item)}')
        elif isinstance(v, bool):
            lines.append(f'{indent}{k}: {str(v).lower()}')
        else:
            lines.append(f'{indent}{k}: {_q(v)}')

def convert_to_clash_and_save(configs: List[str], filename: str) -> int:
    clash_proxies = []
    seen_servers = set()
    used_names = set()
    for uri in configs:
        cp = uri_to_clash(uri)
        if not cp:
            continue
        # Дедупликация по тип+server:port (UDP hy2/tuic и TCP vless на одном порту — разные узлы)
        server_key = f"{cp['type']}:{cp['server']}:{cp['port']}"
        if server_key in seen_servers:
            continue
        seen_servers.add(server_key)
        # Mihomo отвергает ВЕСЬ файл при повторяющихся именах прокси — делаем имена уникальными
        base = cp['name'] or f"{cp['server']}:{cp['port']}"
        nm, i = base, 2
        while nm in used_names:
            nm = f"{base} #{i}"
            i += 1
        used_names.add(nm)
        cp['name'] = nm
        clash_proxies.append(cp)
    if not clash_proxies:
        return 0
    outpath = os.path.join(CLASH_DIR, f"{filename}.yaml")
    _dump_clash_yaml(clash_proxies, outpath, filename)
    return len(clash_proxies)

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

def _generate_qr_index(qr_files: List[Tuple[str, int, str]]):
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
<p style="text-align:center;color:#aaa;">Отсканируй QR-код в клиенте (v2rayNG, Karing, Hiddify, Clash) для добавления подписки</p>
<div class="grid">
""")
        for name, count, filename in qr_files:
            safe_name = html.escape(_sanitize_name(name))
            card_class = 'card all-card' if name == 'ALL' else 'card'
            file_url = html.escape(f"{RAW_BASE}/{name}.txt")
            f.write(f'  <div class="{card_class}">\n')
            f.write(f'    <img src="{html.escape(filename)}" alt="{safe_name}">\n')
            f.write(f'    <div class="name">{safe_name}</div>\n')
            f.write(f'    <div class="count">{count} конфигов</div>\n')
            f.write(f'    <div class="url">{file_url}</div>\n')
            f.write('  </div>\n')
        f.write("</div>\n</body>\n</html>")
    print(f"  📄 HTML-индекс: {index_path}")

# =====================================================================
#  ЗАГРУЗКА ИСТОЧНИКА (с health-учётом)
# =====================================================================

def _cooldown_passed(entry: dict) -> bool:
    """Источник с 3+ провалами не банится навсегда: через RETRY_AFTER_SECONDS пробуем снова."""
    last = entry.get('last_check')
    if not last:
        return True
    try:
        ts = calendar.timegm(time.strptime(str(last).replace(' UTC', ''), '%Y-%m-%d %H:%M:%S'))
    except Exception:
        return True
    return time.time() - ts >= RETRY_AFTER_SECONDS

def fetch_url_with_health(url: str, health: Dict) -> Tuple[Optional[str], bool]:
    with _health_lock:
        entry = health.get(url, {"failures": 0, "last_status": None, "last_check": None})
        failure_count = entry.get("failures", 0)

    if failure_count >= MAX_CONSECUTIVE_FAILURES and not _cooldown_passed(entry):
        print(f"  ⚠️  {url} — {failure_count} провалов подряд, пауза до повторной попытки")
        return None, False

    try:
        if not url.lower().startswith(('http://', 'https://')):
            raise ValueError('разрешены только http/https')
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=FETCH_TIMEOUT) as resp:
            raw = resp.read(MAX_FETCH_BYTES + 1)
        if len(raw) > MAX_FETCH_BYTES:
            raise ValueError(f'ответ больше {MAX_FETCH_BYTES // (1024 * 1024)} МБ')
        content = raw.decode('utf-8', errors='ignore').lstrip('\ufeff')

        with _health_lock:
            entry["failures"] = 0
            entry["last_status"] = "ok"
            entry["last_check"] = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())
            health[url] = entry

        if is_clash_content(content):
            clash_uris = clash_to_uris(content)
            if clash_uris:
                return '\n'.join(clash_uris), False

        stripped = re.sub(r'\s+', '', content.strip())
        if re.fullmatch(r'[A-Za-z0-9+/_=-]+', stripped):
            decoded = _try_b64_decode(stripped)
            if decoded is not None:
                return decoded, True

        return content, False

    except Exception as e:
        with _health_lock:
            entry["failures"] = entry.get("failures", 0) + 1
            entry["last_status"] = str(e)
            entry["last_check"] = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())
            health[url] = entry
            fail_num = entry["failures"]
        print(f"  ❌ {url}: {e} (провал #{fail_num})")
        return None, False

def write_health_report(health: Dict, source_stats: Dict[str, Dict]):
    report_path = os.path.join(OUTPUT_DIR, "URL_HEALTH_REPORT.md")
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write("# URL Health Report\n")
        f.write(f"Generated: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}\n\n")
        f.write("| Source | Status | Fails | Raw | Filtered | Rejected | Duplicates | Last Check |\n")
        f.write("|---|---|---|---|---|---|---|---|\n")
        for src in SOURCES_CONFIG:
            url = src['url']
            entry = health.get(url, {})
            status = "✅" if entry.get("last_status") == "ok" else "❌"
            st = source_stats.get(url, {})
            f.write(f"| {src['name']} | {status} | {entry.get('failures', 0)} | "
                    f"{st.get('raw', '-')} | {st.get('filtered', '-')} | {st.get('rejected', '-')} | "
                    f"{st.get('duplicates', '-')} | {entry.get('last_check', 'N/A')} |\n")
        f.write(f"\n**Авто-очистка:** источник с {MAX_CONSECUTIVE_FAILURES}+ провалами подряд "
                f"ставится на паузу {RETRY_AFTER_SECONDS // 3600} ч и затем пробуется снова.\n")

def write_reject_reasons(reasons: Counter):
    path = os.path.join(REJECT_DIR, "reasons.md")
    with open(path, 'w', encoding='utf-8') as f:
        f.write("# Причины отбраковки\n\n| Причина | Кол-во |\n|---|---|\n")
        for reason, cnt in reasons.most_common(60):
            f.write(f"| {reason.replace('|', '/')} | {cnt} |\n")

# =====================================================================
#  ЗАГРУЗКА + ФИЛЬТРАЦИЯ
# =====================================================================

def load_and_filter(source: Dict, health: Dict) -> Tuple[Set[str], List[str], Dict, bool]:
    name = source['name']
    url = source['url']
    print(f"  [{name}] Загрузка...")

    content, was_base64 = fetch_url_with_health(url, health)

    if not content:
        return set(), [], {"raw": 0, "filtered": 0, "rejected": 0, "duplicates": 0,
                           "reasons": Counter()}, False

    lines = content.splitlines()
    lines = [l.strip() for l in lines if l.strip() and not l.strip().startswith('#')]
    # preprocess чинит &amp; / \u0026 / невидимые символы: в выход попадает уже исправленная ссылка
    raw_configs = [preprocess(c) for c in parse_multiline_configs(lines)]
    raw_count = len(raw_configs)

    reasons: Counter = Counter()
    rejected: List[str] = []
    unique: Dict[tuple, Tuple[str, tuple]] = {}
    duplicates = 0

    for cfg in raw_configs:
        reason, ids = analyze_config(cfg)
        if reason:
            rejected.append(cfg)
            reasons[reason_bucket(reason)] += 1
            continue
        # Дубликаты схлопываем ДО подсчёта лимитов: раньше один и тот же узел с разными
        # именами/порядком параметров раздувал счётчики и выбивал весь легитимный узел.
        if ids[0] in unique:
            duplicates += 1
            continue
        unique[ids[0]] = (cfg, ids)

    pbk_count, uuid_count, sid_count = defaultdict(int), defaultdict(int), defaultdict(int)
    tpass_count, tuic_count, hp_count = defaultdict(int), defaultdict(int), defaultdict(int)
    for cfg, (_, pbk, uuid, sid, tpass, tcred, hp) in unique.values():
        if pbk:
            pbk_count[pbk] += 1
        if uuid:
            uuid_count[uuid] += 1
        if sid:
            sid_count[sid] += 1
        if tpass:
            tpass_count[tpass] += 1
        if tcred:
            tuic_count[tcred] += 1
        hp_count[hp] += 1

    final_filtered: Set[str] = set()
    for cfg, (_, pbk, uuid, sid, tpass, tcred, hp) in unique.values():
        limit_reason = None
        if pbk and pbk_count[pbk] > PBK_MAX:
            limit_reason = 'один Reality-ключ (pbk) у слишком многих узлов'
        elif uuid and uuid_count[uuid] > UUID_MAX:
            limit_reason = 'один UUID у слишком многих узлов'
        elif sid and sid_count[sid] > SID_MAX:
            limit_reason = 'один Reality sid у слишком многих узлов'
        elif tpass and tpass_count[tpass] > TROJAN_PASS_MAX:
            limit_reason = 'один trojan-пароль у слишком многих узлов'
        elif tcred and tuic_count[tcred] > TUIC_CRED_MAX:
            limit_reason = 'одни tuic-учётные данные у слишком многих узлов'
        elif hp_count[hp] > HP_MAX:
            limit_reason = 'слишком много узлов на одном host:port'
        if limit_reason:
            rejected.append(cfg)
            reasons[limit_reason] += 1
            continue
        final_filtered.add(cfg)

    stats = {"raw": raw_count, "filtered": len(final_filtered), "rejected": len(rejected),
             "duplicates": duplicates, "reasons": reasons}
    return final_filtered, rejected, stats, was_base64

# =====================================================================
#  СОРТИРОВКА / ДЕДУПЛИКАЦИЯ
# =====================================================================

def protocol_priority(uri: str) -> int:
    if uri.startswith('vless://'): return 1
    if uri.startswith('trojan://'): return 2
    if uri.startswith('vmess://'): return 3
    if uri.startswith(('hysteria2://', 'hy2://')): return 4
    if uri.startswith('tuic://'): return 5
    if uri.startswith('ss://'): return 6
    return 8

def sort_configs(configs) -> List[str]:
    return sorted(configs, key=lambda u: (protocol_priority(u), u))

def dedupe_by_key(configs) -> List[str]:
    """Один узел — одна строка, даже если он пришёл из разных источников с разными именами."""
    seen, out = set(), []
    for u in sort_configs(configs):
        reason, ids = analyze_config(u)
        k = ids[0] if ids else u
        if k in seen:
            continue
        seen.add(k)
        out.append(u)
    return out

# =====================================================================
#  MAIN
# =====================================================================

def main():
    print("=== Фильтр прокси v6.0 (NekoBox / v2rayNG / Karing + Clash/Mihomo, hardened) ===")
    if not HAS_YAML:
        print("  ⚠️  pyyaml недоступен — Clash подписки не парсятся")
    health = load_health()
    all_filtered = set()
    all_rejected = []
    all_reasons: Counter = Counter()
    source_stats = {}
    file_counts = {}
    clash_counts = {}

    with ThreadPoolExecutor(max_workers=5) as ex:
        futures = {ex.submit(load_and_filter, src, health): src for src in SOURCES_CONFIG}
        for future in as_completed(futures):
            src = futures[future]
            name = src['name']
            try:
                configs, rejected, stats, was_base64 = future.result()
                all_rejected.extend(rejected)
                all_reasons.update(stats.get('reasons', {}))
                source_stats[src['url']] = stats

                out = os.path.join(OUTPUT_DIR, f"{name}.txt")
                sorted_cfg = sort_configs(configs)

                if was_base64 and sorted_cfg:
                    plaintext = '\n'.join(sorted_cfg) + '\n'
                    encoded = base64.b64encode(plaintext.encode('utf-8')).decode('ascii')
                    with open(out, 'w', encoding='utf-8', newline='\n') as f:
                        f.write(encoded)
                    print(f"  ✅ {name}.txt → {len(configs)} конфигов [base64] "
                          f"(отброшено: {stats['rejected']}, дублей: {stats['duplicates']})")
                else:
                    with open(out, 'w', encoding='utf-8', newline='\n') as f:
                        f.write('\n'.join(sorted_cfg))
                        if sorted_cfg:
                            f.write('\n')
                    print(f"  ✅ {name}.txt → {len(configs)} конфигов "
                          f"(отброшено: {stats['rejected']}, дублей: {stats['duplicates']})")

                if sorted_cfg:
                    clash_n = convert_to_clash_and_save(sorted_cfg, name)
                    clash_counts[name] = clash_n
                    if clash_n > 0:
                        print(f"  🔄 Clash: {os.path.join(CLASH_DIR, name + '.yaml')} → {clash_n} прокси")
                else:
                    clash_counts[name] = 0

                all_filtered.update(configs)
                file_counts[name] = len(configs)

            except Exception as e:
                print(f"  ❌ [{name}] Ошибка: {e}")
                file_counts[name] = 0
                clash_counts[name] = 0

    all_file = os.path.join(OUTPUT_DIR, "ALL.txt")
    sorted_all = dedupe_by_key(all_filtered)
    with open(all_file, 'w', encoding='utf-8', newline='\n') as f:
        f.write('\n'.join(sorted_all))
        if sorted_all:
            f.write('\n')
    file_counts["ALL"] = len(sorted_all)

    if sorted_all:
        clash_all_n = convert_to_clash_and_save(sorted_all, "ALL")
        clash_counts["ALL"] = clash_all_n
        if clash_all_n > 0:
            print(f"  🔄 Clash ALL: {os.path.join(CLASH_DIR, 'ALL.yaml')} → {clash_all_n} прокси")

    reject_file = os.path.join(REJECT_DIR, "rejected.txt")
    with open(reject_file, 'w', encoding='utf-8', newline='\n') as f:
        f.write('\n'.join(all_rejected))
        if all_rejected:
            f.write('\n')
    write_reject_reasons(all_reasons)

    save_health(health)
    write_health_report(health, source_stats)
    generate_qr_codes(file_counts)

    print(f"\n✅ ALL.txt: {len(sorted_all)} уникальных конфигов")
    if clash_counts.get("ALL"):
        print(f"🔄 Clash ALL.yaml: {clash_counts['ALL']} прокси → {CLASH_DIR}/")
    print(f"⚠️  Отброшено: {len(all_rejected)} (rejected/rejected.txt, причины — rejected/reasons.md)")
    print(f"📊 URL Health: {os.path.join(OUTPUT_DIR, 'URL_HEALTH_REPORT.md')}")
    print(f"📱 QR-коды: {QR_DIR}/")
    print(f"🔄 Clash подписки: {CLASH_DIR}/")

if __name__ == "__main__":
    main()
