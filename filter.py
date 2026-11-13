#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Фильтр прокси-конфигураций v6.2 (Karing / NekoBox / v2rayNG + Clash/Mihomo)

Цель: в выход не должна попасть ссылка, через которую трафик можно прочитать или
подменить по дороге: туннель без TLS, отключённая проверка сертификата, свой CA,
слабый шифр.

Границы защиты (важно понимать): всё ниже защищает туннель от ТРЕТЬИХ ЛИЦ на пути
(провайдер, ТСПУ). Владелец сервера терминирует туннель и видит SNI, IP, DNS и
открытый HTTP — это не изменит ни один фильтр ссылок. HTTPS-содержимое он не
прочитает, пока пользователь сам не установит чужой корневой сертификат.

Что нового в v6.2:
  * Shadowsocks по умолчанию отбраковывается (ALLOW_SS = False): пароль SS/PSK SS-2022
    — это ключ шифрования, а в публичной подписке он публичен, то есть трафик SS
    читает любой, у кого есть та же подписка. У vless/trojan/hy2/tuic секрет из
    ссылки — только аутентификация, туннель защищён TLS/Reality.
  * vmess JSON-форма публикуется как стандартная ссылка vmess://uuid@host:port?…
    с allowInsecure=0 (VMESS_JSON_MODE = 'std'): в JSON-форме нет поля allowInsecure,
    и v2rayNG брал для неё глобальную настройку «Allow insecure». Повреждённый base64
    (мусорный хвост, двойное кодирование) больше не публикуется «как есть» —
    публикуется только канонический, заново проверенный вид.
  * «Обязательные» поля ещё буквальнее: sni/pbk/sid — только точные ключи (без
    peer/servername/publickey), иначе клиент их не увидит; sni не может быть IP.
  * flow проверяется и в TLS-режиме (мусорный flow — отбраковка); разрешён
    xtls-rprx-vision-udp443; vision только с type=tcp; Reality только с
    tcp/grpc/http/xhttp (ws/httpupgrade/kcp под Reality Xray не умеет).
  * trojan: транспорт только из TLS-набора (kcp/quic — отбраковка); легаси
    ws=1&wspath= больше не трактуется как ws (клиенты его не понимают).
  * pbk публикуется без '=' (Xray/sing-box читают base64url без паддинга).
  * Лимиты «публичного пула» применяются и к объединённому ALL.txt.
  * Clash: дедупликация по полному ключу узла (как в txt), а не по host:port.
  * pyyaml обязателен: без него YAML-источники давали пустые файлы — теперь код
    выхода 2 без перезаписи подписок.

Что нового в v6.1 по сравнению с v6.0:
  * Проверяется ровно та строка, которая публикуется: preprocess доводится до
    неподвижной точки (P(P(x)) == P(x)), ненормализованные строки отбраковываются.
    Закрыты обходы через \\u200b, \\u0026amp;, \\u005cu0026.
  * «Обязательные» параметры читаются так же буквально, как в клиентах: security —
    только точный ключ и точное значение tls/reality (без синонима sec, без
    регистра/процентов и «починок» ';' и '%3D'); повтор любого ключа — отбраковка;
    trojan с пустым security= — отбраковка; пустой флаг insecure — отбраковка.
  * vmess JSON: повторяющиеся ключи (в т.ч. TLS/tls) — отбраковка; TLS только "tls".
  * Свой CA/сертификат (ca=, cert=, certificates, disableSystemRoot…) и xhttp extra
    с downloadSettings/allowInsecure — отбраковка.
  * В каждую TLS-ссылку явно дописывается allowInsecure=0 / insecure=0: v2rayNG без
    этого параметра берёт глобальную настройку «Allow insecure».
  * Clash строится из того же разбора, что и проверка (второго парсера на
    регулярках больше нет); skip-cert-verify: false явно; зарезервированные имена
    Mihomo; финальная проверка «нет TLS — нет прокси».
  * Адреса: IPv6 только в [скобках]; is_global + 6to4/Teredo/NAT64; 127.0.0.1.nip.io
    и подобные — по встроенному IP.
  * Устойчивость: лимит длины строки, YAML-«бомбы» через алиасы, общий дедлайн
    загрузки, только https без даунгрейда на редиректе, url-safe base64, атомарная
    запись файлов, при сбое источника — перепроверенный прошлый файл вместо пустого,
    rejected.txt по умолчанию не публикуется, код выхода 1, если не скачалось ничего.
  * Один файл, без внешних тестов. Каждый запуск начинается с самопроверки защиты
    (доли секунды, без сети): если правка кода или другая версия Python пропускает
    известный обход TLS, подписки не перезаписываются и код выхода 2.
    Полные тесты: python filter.py --selftest
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
import urllib.error
import urllib.request
import urllib.parse
import uuid as uuidlib
from urllib.parse import unquote
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter
from functools import lru_cache
from typing import Set, Dict, Optional, List, Tuple

try:
    import yaml
    HAS_YAML = True
except ImportError:
    # Лучше поставить зависимость в workflow (pip install "pyyaml>=6,<7") и удалить этот блок
    try:
        subprocess.check_call([sys.executable, '-m', 'pip', 'install', '--quiet',
                               '--disable-pip-version-check', 'pyyaml>=6.0.1,<7'])
        import yaml
        HAS_YAML = True
    except Exception:
        yaml = None
        HAS_YAML = False

if not HAS_YAML:
    # Без YAML Clash-источник «декодируется» как пустой текст и его файл перезаписался бы
    # пустым. Это не деградация, а поломка — останавливаемся до записи чего-либо.
    print("❌ pyyaml недоступен (PEP 668 / нет сети). Установите в workflow: "
          "pip install 'pyyaml>=6,<7'. Подписки НЕ обновлены.")
    sys.exit(2)

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
RETRY_AFTER_SECONDS = 3600              # пауза «мёртвого» источника (3 провала подряд);
                                        # при запуске раз в 15 мин — 1 попытка в час
FETCH_TIMEOUT = 30
MAX_FETCH_BYTES = 64 * 1024 * 1024       # защита памяти от гигантских/бесконечных ответов
FETCH_DEADLINE = 120                     # общий лимит на скачивание одного источника, сек
MAX_LINE_LEN = 8192                      # длиннее — не ссылка, а мусор/атака (раздувание выхода)
MAX_NAME_LEN = 200                       # имя прокси в Clash
MAX_CLASH_PROXIES = 50000                # максимум прокси из одного YAML-источника
PUBLISH_REJECTED = False                 # rejected.txt — готовая подписка из НЕБЕЗОПАСНЫХ узлов
FORCE_VERIFY_FLAG = True                 # дописывать allowInsecure=0 / insecure=0 в TLS-ссылки
STALE_MAX_HOURS = 72                     # сколько часов при сбое источника отдавать прошлый файл

# Shadowsocks: пароль (PSK) = ключ шифрования. В ПУБЛИЧНОЙ подписке он публичен, и любой,
# кто читает ту же подписку (ТСПУ в том числе), расшифровывает SS-трафик целиком —
# в отличие от TLS-протоколов, где секрет из ссылки только аутентифицирует клиента.
ALLOW_SS = False

# vmess JSON (vmess://base64{...}) не умеет нести allowInsecure, и v2rayNG берёт для неё
# глобальную настройку «Allow insecure». Режимы публикации:
#   'std'    — стандартная ссылка vmess://uuid@host:port?security=tls&…&allowInsecure=0
#              (её читают v2rayNG, NekoBox/sing-box-клиенты; узел проверяется заново)
#   'json'   — канонически перекодированный base64-JSON (без защиты от глобальной настройки)
#   'reject' — vmess JSON не публиковать вовсе
VMESS_JSON_MODE = 'std'

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
    {"name": "FILTER-2", "url": "https://raw.githubusercontent.com/KoT-ANTIDOT/bunker-subscriptions/refs/heads/main/White_List.txt"},
    {"name": "FILTER-3", "url": "https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_lite.txt"},
    {"name": "FILTER-4", "url": "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-all.txt"},
    {"name": "FILTER-5", "url": "https://raw.githubusercontent.com/LSO-LinSpisokObhod/LSO-LinSpisokObhod.github.io/refs/heads/main/sub/LTE.txt"},
    {"name": "FILTER-6", "url": "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-all.txt"},
    {"name": "FILTER-7", "url": "https://raw.githubusercontent.com/kangaroo255075-collab/Official-KrolekVPNReborn-2/refs/heads/main/Krolek.txt"},
    {"name": "FILTER-8-BASE64", "url": "https://raw.githubusercontent.com/Diversan313/apex-parser/refs/heads/main/subs/main/alive_bs.txt"},
    {"name": "FILTER-9-BASE64", "url": "https://raw.githubusercontent.com/Diversan313/apex-parser/main/subs/main/alive_bl.txt"},
    {"name": "FILTER-10", "url": "https://sub.vlessfo.ru/vlessforu/working_configs.txt"},
    {"name": "FILTER-11", "url": "https://pozor.bond/sub/ry2627uz9cp7"},
    {"name": "FILTER-12", "url": "https://pozor.bond/sub/utcwry9vug6k"},
    {"name": "FILTER-13", "url": "https://gitverse.ru/api/repos/bikinitw22/apelsintel/raw/branch/main/alive_bs.txt"},
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
    'fromblancwithlove.com', 'koma-yt.pages.dev',
]

# Имена, которые не бывают публичными серверами (внутренние зоны)
NON_PUBLIC_SUFFIXES = (
    '.local', '.localhost', '.internal', '.lan', '.home.arpa', '.intranet',
    '.invalid', '.test', '.example', '.arpa', '.onion',
    # публичные домены, которые всегда резолвятся в 127.0.0.1
    '.localtest.me', '.lvh.me', '.vcap.me', '.lacolhost.com', '.localhost.direct', '.local.gd',
)

# Wildcard-DNS: 10.0.0.1.nip.io -> 10.0.0.1. Публичный IP через них — законный приём
# (сертификат для VPS без домена), поэтому проверяется встроенный IP, а не весь домен.
WILDCARD_IP_DOMAINS = ('nip.io', 'sslip.io', 'xip.io', 'traefik.me')

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

# Канонические имена — как после нормализации в _parse_ss. (В v6.0 replace() портил
# '2022-blake3-chacha20-poly1305' в '...-ietf-...', и рабочий SS-2022 отбраковывался.)
SAFE_SS_CANON = {m for m in SAFE_SS_METHODS if m not in ('chacha20-poly1305', 'xchacha20-poly1305')}

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

# Параметры, которые подменяют доверие к сертификату сервера (свой CA, отключение
# системных корней). С ними «проверенный» TLS может оказаться под MITM.
TRUST_OVERRIDE_KEYS = {
    'ca', 'ca-str', 'ca_str', 'castr', 'cacert', 'ca-cert', 'ca_cert',
    'cert', 'certificate', 'certificates', 'cert-path', 'cert_path', 'certpath',
    'disablesystemroot', 'disable-system-root', 'disable_system_root',
}

# Ключи, наличие/значение которых фильтр ТРЕБУЕТ. Клиенты читают их буквально
# (регистр, проценты), поэтому любое другое написание — отбраковка.
STRICT_KEYS = {'security', 'sni', 'pbk', 'sid', 'fp', 'type', 'flow', 'encryption', 'alpn'}

TUIC_CC_WHITELIST = {'bbr', 'cubic', 'new_reno'}
TUIC_UDP_MODES = {'native', 'quic'}

# Транспорты, которые понимают клиенты. quic в списке нет: v2rayNG при импорте
# молча превращает такую ссылку в tcp.
NETS = {'tcp', 'ws', 'http', 'kcp', 'grpc', 'httpupgrade', 'xhttp'}
# Для TLS-режима (kcp с TLS не бывает). Раньше список был ws/grpc/http/tcp —
# httpupgrade и xhttp (законные транспорты) отбрасывались зря.
TLS_ALLOWED_NETS = {'tcp', 'ws', 'http', 'grpc', 'httpupgrade', 'xhttp'}
# Reality в Xray работает только поверх этих транспортов (ws/httpupgrade — нет).
REALITY_NETS = {'tcp', 'grpc', 'http', 'xhttp'}
# flow читается клиентами буквально (регистр важен); vision требует type=tcp.
VLESS_FLOWS = {'', 'none', 'xtls-rprx-vision', 'xtls-rprx-vision-udp443'}
VMESS_CIPHERS = {'auto', 'aes-128-gcm', 'chacha20-poly1305'}

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
    '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24', '192.88.99.0/24', '192.168.0.0/16',
    '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/4', '240.0.0.0/4')]
# 2002::/16 (6to4), 2001::/23 (Teredo и др.), 64:ff9b:1::/48 (локальный NAT64) могут
# прятать внутри 127.0.0.1/10.x; is_global в старых Python их не ловит — список явный.
BAD_V6 = [ipaddress.ip_network(x) for x in (
    '::/96', '::ffff:0:0/96', '64:ff9b::/96', '64:ff9b:1::/48', '100::/64',
    '2001::/23', '2001:db8::/32', '2002::/16', '3fff::/20', '5f00::/16',
    'fc00::/7', 'fe80::/10', 'fec0::/10', 'ff00::/8')]

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

# Невидимые и «переворачивающие» символы (zero-width, bidi-override, soft hyphen):
# ими прячут параметр от глаз и от наивных проверок.
_INVISIBLE_RE = re.compile('[\u00ad\u061c\u180e\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]')
_CTRL_RE = re.compile(r'[\x00-\x1f\x7f-\x9f\u2028\u2029]')
_UESC_RE = re.compile(r'\\u([0-9a-fA-F]{4})')

def preprocess(s: str) -> str:
    """Чинит типовые поломки ссылок ДО проверки.

    &amp; (в т.ч. многократное), \\u0026, %5Cu0026, '¬' -> '&'; невидимые и
    управляющие символы вырезаются. Все шаги повторяются до неподвижной точки:
    повторный вызов результат не меняет, поэтому в выход попадает ровно та строка,
    которую проверили. (В v6.0 \\u200b раскодировался ПОСЛЕ удаления невидимых
    символов и доезжал до клиента внутри имени параметра.)
    Схема приводится к нижнему регистру (VLESS:// -> vless://).
    """
    for _ in range(64):
        prev = s
        s = _INVISIBLE_RE.sub('', s)
        s = re.sub(r'(?i)&amp;', '&', s)
        if '\\u' in s:
            s = _UESC_RE.sub(lambda m: chr(int(m.group(1), 16)), s)
        s = re.sub(r'(?i)%5cu0026', '&', s)
        s = s.replace('¬', '&')
        s = _CTRL_RE.sub('', s)
        if s == prev:
            break
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
    """Параметры запроса: ключ в нижнем регистре -> значение; .pairs — все пары.

    Повтор ключа — отбраковка (в v6.0 побеждал первый, а v2rayNG берёт последний:
    security=tls&security= проходил фильтр, а клиент ехал без TLS).
    """
    def __init__(self):
        super().__init__()
        self.pairs: list = []

def parse_query(qs: str) -> Q:
    """Разбор как у клиентов: split('&'), затем по первому '='. Никаких «починок»:
    ';security=tls' и 'security%3Dtls' клиенты security не считают — фильтр тоже."""
    q = Q()
    for part in qs.split('&'):
        if not part:
            continue
        rk, _, v = part.partition('=')
        k = unquote(rk).strip().lower()
        if not k:
            continue
        if k in q:
            raise Reject(f'повторяющийся параметр: {k[:20]}')
        if k in STRICT_KEYS and rk != k:
            raise Reject(f'нестандартное написание ключа {rk[:20]!r}')
        v = unquote(v)
        q.pairs.append((k, v))
        q[k] = v
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

def _check_ip(ip) -> str:
    s = str(ip)
    if REJECT_DNS and s in IP_BLACKLIST:
        raise Reject(f'публичный DNS как сервер: {s}')
    if REJECT_PRIVATE:
        nets = BAD_V6 if ip.version == 6 else BAD_V4
        if any(ip in net for net in nets) or ip.is_multicast or not ip.is_global:
            raise Reject(f'локальный/зарезервированный IP {s}')
    return s

def _wildcard_ip(d: str) -> Optional[str]:
    """IP, «зашитый» в wildcard-DNS имя: 10.0.0.1.nip.io, 10-0-0-1.sslip.io,
    app-0a000001.nip.io, --1.sslip.io (::1). None — имя не из этих сервисов."""
    for wd in WILDCARD_IP_DOMAINS:
        if d != wd and not d.endswith('.' + wd):
            continue
        prefix = d[:-len(wd)].rstrip('.')
        m = re.search(r'(?:^|[.-])(\d{1,3})[.-](\d{1,3})[.-](\d{1,3})[.-](\d{1,3})$', prefix)
        if m:
            return '.'.join(m.groups())
        m = re.search(r'(?:^|[.-])([0-9a-f]{8})$', prefix)
        if m:
            return str(ipaddress.IPv4Address(int(m.group(1), 16)))
        label = prefix.rsplit('.', 1)[-1]
        if '-' in label:                         # sslip.io: IPv6 через '-', '::' = '--'
            try:
                return str(ipaddress.IPv6Address(label.replace('-', ':')))
            except ValueError:
                pass
        return None
    return None

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
        return _check_ip(ip)
    if re.fullmatch(r'(?:\d{1,3}\.){3}\d{1,3}', h):
        if any(len(o) > 1 and o[0] == '0' for o in h.split('.')):
            raise Reject('обфусцированный IP (ведущие нули)')
        try:
            ip = ipaddress.IPv4Address(h)
        except ValueError:
            raise Reject(f'неверный IPv4: {h[:40]!r}')
        return _check_ip(ip)
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
    if REJECT_PRIVATE:
        emb = _wildcard_ip(d)
        if emb is not None:
            check_host(emb)                      # Reject, если внутри локальный/служебный IP
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
            # 2001:db8::1:443 — это адрес без порта или адрес + порт? Клиенты понимают
            # по-разному, поэтому IPv6 — только в [скобках] (RFC 3986)
            raise Reject(f'IPv6 без квадратных скобок: {s[:70]!r}')
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
    # IP-литерал в SNI запрещён RFC 6066; клиенты либо не шлют его, либо сервер молчит
    return (bool(s) and len(s) <= 253 and bool(SNI_RE.fullmatch(s))
            and not re.fullmatch(r'[\d.]+', s))

def _is_ip_literal(host: str) -> bool:
    return ':' in host or bool(re.fullmatch(r'[\d.]+', host))

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
    """Флаги небезопасности и «плохие» значения — по ВСЕМ парам, с синонимами.

    Здесь нормализация (регистр, синонимы) работает НА безопасность: чем больше
    написаний запрещающего флага ловим, тем лучше.
    """
    for k, v in q.pairs:
        vs = v.strip().lower()
        if k in INSECURE_KEYS and (not vs or _flag_on(v)):
            # пустое значение тоже нельзя: часть клиентов считает «флаг есть» = включён,
            # а v2rayNG при пустом подставляет глобальную настройку «Allow insecure»
            raise Reject(f'небезопасный параметр: {k}={v[:12]}')
        if k in ('disable_sni', 'disablesni') and _flag_on(v):
            raise Reject('disable_sni включён')
        if k in ('verify', 'tls13') and vs in FALSE_SET:
            raise Reject(f'небезопасный параметр: {k}={v[:12]}')
        if k in ('security', 'sec') and vs in ('', 'none', 'false', '0', 'off', 'no'):
            raise Reject('нет TLS (security=none или пусто)')
        if k in TRUST_OVERRIDE_KEYS and vs and vs not in FALSE_SET:
            raise Reject(f'свой CA/сертификат в ссылке ({k}=) — возможен MITM')
        if k in ('extra', 'xhttpextra', 'xhttp-extra'):
            _check_xhttp_extra(v)
        if k in ('sni', 'peer', 'servername', 'host', 'authority') and _host_param_banned(v):
            raise Reject(f'домен из чёрного списка в параметре {k}')

_EXTRA_TLS = ('tls', 'reality')
_NOT_JSON = object()

def _extra_off(v) -> bool:
    return v is None or v is False or (isinstance(v, (str, list, dict)) and not v) or \
        str(v).strip().lower() in FALSE_SET

def _check_xhttp_extra(raw: str):
    """xhttp extra (JSON) может содержать downloadSettings — второй сервер со своим
    security/tlsSettings, то есть «без TLS» или allowInsecure мимо проверок ссылки.
    Xray читает ключи JSON без учёта регистра, поэтому и здесь регистр не важен."""
    if not raw.strip():
        return
    j = _NOT_JSON
    for cand in (raw, unquote(raw)):                 # бывает закодировано дважды
        try:
            j = json.loads(cand)                     # 'null' -> None — это валидно
            break
        except Exception:
            continue
    if j is _NOT_JSON:
        raise Reject('xhttp extra: не JSON')
    stack = [j]
    while stack:
        x = stack.pop()
        if isinstance(x, list):
            stack.extend(x)
            continue
        if not isinstance(x, dict):
            continue
        for k, v in x.items():
            kl = str(k).lower()
            if kl == 'downloadsettings':
                if v is None:                        # полный дамп настроек: "downloadSettings": null
                    continue
                if not isinstance(v, dict):
                    raise Reject('xhttp extra: downloadSettings не объект')
                secs = [s for kk, s in v.items() if str(kk).lower() == 'security']
                if not secs:                         # без security Xray поднимет второй канал БЕЗ TLS
                    raise Reject('xhttp extra: downloadSettings без TLS')
                for kk, vv in v.items():
                    if str(kk).lower() == 'address' and vv not in (None, ''):
                        check_host(str(vv))
            elif kl in TRUST_OVERRIDE_KEYS and not _extra_off(v):
                raise Reject(f'xhttp extra: {kl} не допускается')
            elif kl in INSECURE_KEYS and not _extra_off(v) and _flag_on(str(v)):
                raise Reject(f'xhttp extra: небезопасный {kl}')
            elif kl == 'security' and str(v).strip().lower() not in _EXTRA_TLS:
                raise Reject('xhttp extra: security без TLS')
            stack.append(v)

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
    """Результат разбора. Из него же строится Clash — второго парсера больше нет."""
    __slots__ = ('proto', 'host', 'port', 'uuid', 'password', 'pbk', 'sid', 'key',
                 'q', 'j', 'method', 'plugin', 'ports')

    def __init__(self, proto):
        self.proto = proto
        self.host, self.port = '', 0
        self.uuid = self.password = self.pbk = self.sid = ''
        self.method = self.plugin = self.ports = ''
        self.key = ()
        self.q = Q()
        self.j = None

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
    c.q = q
    _check_pairs(q)
    if _is_host_banned(c.host):
        raise Reject(f'сервер в чёрном списке доменов: {c.host}')

def _tls_mode(q: Q) -> str:
    """security — буквально, как читают клиенты: без синонима sec, strip() и lower().
    (v6.0 принимал sec=tls, Security=tls, TLS, ' tls' — а клиент видел «без TLS».)"""
    return q.get('security', '')

def _parse_vless(core: str) -> Cfg:
    userinfo, hostport, q = _split_authority_uri(core)
    c = Cfg('vless')
    c.uuid = _check_uuid(userinfo)
    c.host, c.port = parse_hostport(hostport)
    _common(c, q, core)
    sec = _tls_mode(q)
    if sec not in ('tls', 'reality'):
        raise Reject(f'vless без TLS/Reality (security={sec[:12] or "нет"})')
    net = _read_net(q)
    _check_vless_encryption(qget(q, 'encryption'))
    # sni/pbk/sid/fp — только точные ключи: синоним (peer=, servername=, publickey=)
    # фильтр бы «увидел», а v2rayNG — нет.
    sni = q.get('sni', '').strip()
    hhost = qget(q, 'host').strip()
    flow = q.get('flow', '')
    if flow not in VLESS_FLOWS:
        raise Reject(f'неизвестный flow: {flow[:30]!r}')
    if flow.startswith('xtls') and net != 'tcp':
        raise Reject(f'flow {flow} только с type=tcp (у ссылки type={net})')
    if sec == 'reality':
        if net not in REALITY_NETS:
            raise Reject(f'Reality поверх {net} Xray не поддерживает')
        c.pbk = q.get('pbk', '').strip()
        c.sid = q.get('sid', '').strip()
        _check_reality(c.pbk, c.sid, q.get('fp', '').strip().lower())
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
    # Ключа security нет -> клиенты сами включают TLS. Любое другое значение, включая
    # пустое security= (v2rayNG подставляет tls только при ОТСУТСТВИИ ключа), — отбраковка.
    if 'security' in q and q['security'] != 'tls':
        raise Reject(f'trojan с security={q["security"][:12] or "пусто"}')
    net = _read_net(q)
    if net not in TLS_ALLOWED_NETS:
        raise Reject(f'trojan: транспорт {net} не разрешён')
    sni = q.get('sni', '').strip()
    if not sni:
        raise Reject('trojan без sni')
    if not valid_sni(sni):
        raise Reject('невалидный sni')
    if _is_trojan_public_pool(core, q):
        raise Reject('trojan из публичного пула (маркеры)')
    c.key = ('trojan', c.host, c.port, c.password, _qkey(q))
    return c

def _decode_vmess_body(data: str):
    """base64 -> (json-текст). Лечит мусорный хвост (…fQ==2) и двойной base64 — это
    безопасно только потому, что публикуется канонический вид (см. _publish_form),
    а не исходная строка, которую клиентский декодер «вылечил» бы иначе."""
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

_VMESS_NET_ALIAS = {'h2': 'http', 'websocket': 'ws', 'splithttp': 'xhttp', 'raw': 'tcp',
                    'none': 'tcp', '': 'tcp'}

def _parse_vmess(core: str) -> Cfg:
    data = core.split('://', 1)[1]
    data_noq = data.split('?', 1)[0].strip().strip('/')
    c = Cfg('vmess')
    if '@' in data_noq:                         # стандартная URL-форма vmess://uuid@host:port?…
        userinfo, hostport, q = _split_authority_uri(core)
        c.uuid = _check_uuid(userinfo)
        c.host, c.port = parse_hostport(hostport)
        _common(c, q, core)
        aid = qget(q, 'alterid', 'aid') or '0'
        if not aid.isdigit() or int(aid) != 0:
            raise Reject('vmess alterId != 0')
        scy = qget(q, 'encryption').strip().lower() or 'auto'
        if scy not in VMESS_CIPHERS:
            raise Reject(f'vmess: шифр {scy[:20]!r} не разрешён')
        sec = _tls_mode(q)
        net = _read_net(q)
        if sec not in ('tls', 'reality'):
            raise Reject('vmess без TLS')
        if sec == 'reality':
            if net not in REALITY_NETS:
                raise Reject(f'Reality поверх {net} Xray не поддерживает')
            _check_reality(q.get('pbk', '').strip(), q.get('sid', '').strip(),
                           q.get('fp', '').strip().lower())
        else:
            _check_tls_block(net, q.get('sni', '').strip(), qget(q, 'host').strip(),
                             qget(q, 'alpn') or 'h2')
        c.key = ('vmess', c.host, c.port, c.uuid, _qkey(q))
        return c

    if VMESS_JSON_MODE == 'reject':
        raise Reject('vmess JSON-форма отключена (VMESS_JSON_MODE)')
    text = data_noq if data_noq.lstrip().startswith('{') else _decode_vmess_body(data_noq)

    def _no_dup_keys(pairs):
        d = {}
        for k, v in pairs:
            if k in d:
                raise Reject(f'vmess JSON: повторяющийся ключ {str(k)[:20]!r}')
            d[k] = v
        return d

    try:
        j = json.loads(text, object_pairs_hook=_no_dup_keys)
    except Reject:
        raise
    except Exception as e:
        raise Reject(f'vmess JSON невалиден: {str(e)[:40]}')
    if not isinstance(j, dict):
        raise Reject('vmess JSON — не объект')
    low = {}
    for k, v in j.items():
        lk = str(k).lower()
        if lk in low:
            # {"TLS":"tls","tls":""}: фильтр видел бы одно, клиент (ключи с учётом регистра) — другое
            raise Reject(f'vmess JSON: ключи различаются только регистром ({lk[:20]})')
        low[lk] = v

    def g(*keys, d=''):
        for k in keys:
            v = low.get(k.lower())
            if v is not None and str(v).strip() != '':
                return str(v).strip()
        return d

    # параметры после '?' у base64-формы часть клиентов тоже читает — проверяем их
    if '?' in data and not data_noq.lstrip().startswith('{'):
        _check_pairs(parse_query(data.split('?', 1)[1]))
    c.host, c.port = parse_hostport(f"{_bracket(g('add', 'address', 'server'))}:{g('port', 'p')}")
    c.uuid = _check_uuid(g('id', 'uuid', 'user'))
    aid = g('aid', 'alterid', 'alter_id') or '0'
    if not aid.isdigit() or int(aid) != 0:
        raise Reject('vmess alterId != 0')
    if g('v', d='2') not in ('1', '2'):
        raise Reject('vmess: неизвестная версия формата')
    scy = (g('scy', 'security', 'cipher') or 'auto').lower()
    if scy not in VMESS_CIPHERS:
        raise Reject(f'vmess: шифр {scy[:20]!r} не разрешён')
    # TLS — только буквально "tls" в точном ключе "tls", как читает v2rayNG.
    # "TLS", "1", "true" клиент TLS-ом не считает — туннель ушёл бы открытым.
    if j.get('tls') != 'tls':
        raise Reject('vmess без TLS')
    for kk, v in low.items():
        sv = '' if v is None else str(v).strip()
        if kk in INSECURE_KEYS and (_flag_on(sv) or (v is not None and not sv)):
            raise Reject(f'небезопасный параметр: {kk}')
        if kk in TRUST_OVERRIDE_KEYS and sv and sv.lower() not in FALSE_SET:
            raise Reject(f'свой CA/сертификат в vmess ({kk}) — возможен MITM')
    net_raw = (g('net', 'network') or 'tcp').lower()
    net = _VMESS_NET_ALIAS.get(net_raw, net_raw)
    if net == 'quic':
        raise Reject('транспорт quic не поддерживается v2rayNG (станет tcp)')
    if net not in TLS_ALLOWED_NETS:
        raise Reject(f'vmess: транспорт {net[:20]!r} не разрешён')
    if REQUIRE_HOST_FOR_WS and net in ('ws', 'http') and not g('host'):
        raise Reject(f'vmess {net} без host')
    # sni — только точный ключ "sni" (v2rayNG другие не читает); без него клиент берёт
    # host (ws/h2/…) или адрес-домен — ровно это и проверяем/публикуем.
    sni = g('sni')
    if not sni:
        hh = g('host').split(',')[0].strip() if net in ('ws', 'http', 'httpupgrade', 'xhttp') else ''
        sni = hh or ('' if _is_ip_literal(c.host) else c.host)
    if not sni:
        raise Reject('vmess tls без sni (адрес — IP, host пуст)')
    if not valid_sni(sni):
        raise Reject(f'невалидный sni: {sni[:40]!r}')
    for fld in ('sni', 'sn', 'servername', 'host'):
        val = g(fld)
        if val and _host_param_banned(val):
            raise Reject(f'домен из чёрного списка в поле {fld}')
    if _is_host_banned(c.host):
        raise Reject(f'сервер в чёрном списке доменов: {c.host}')
    c.j = j
    items = tuple(sorted((k, str(v)) for k, v in low.items() if k not in _KEY_IGNORE))
    c.key = ('vmess', c.host, c.port, c.uuid, items)
    return c

def _vmess_json_to_std(c: Cfg) -> str:
    """vmess JSON -> стандартная ссылка vmess://uuid@host:port?…&allowInsecure=0.
    Поля переносятся так, как их трактует v2rayNG при импорте JSON (grpc: path ->
    serviceName, host -> authority, type -> mode). Результат проверяется заново."""
    low = {str(k).lower(): ('' if v is None else str(v).strip()) for k, v in c.j.items()}

    def g(*keys):
        return next((low[k] for k in keys if low.get(k)), '')

    net_raw = (g('net', 'network') or 'tcp').lower()
    net = _VMESS_NET_ALIAS.get(net_raw, net_raw)
    htype, host, path = g('type').lower(), g('host'), g('path')
    params = [('encryption', (g('scy', 'security', 'cipher') or 'auto').lower()),
              ('security', 'tls'), ('type', net)]
    if net == 'grpc':
        params += [('serviceName', path), ('authority', host),
                   ('mode', htype if htype not in ('', 'none') else '')]
    else:
        if net == 'tcp' and htype == 'http':
            params.append(('headerType', 'http'))
        params += [('host', host), ('path', path)]
    sni = g('sni')
    if not sni:
        hh = host.split(',')[0].strip() if net in ('ws', 'http', 'httpupgrade', 'xhttp') else ''
        sni = hh or ('' if _is_ip_literal(c.host) else c.host)
    params += [('sni', sni), ('alpn', g('alpn')), ('fp', g('fp', 'fingerprint').lower()),
               ('allowInsecure', '0')]
    name = _sanitize_name(g('ps', 'remarks'))[:MAX_NAME_LEN]
    qs = '&'.join(f'{k}={_pq(v)}' for k, v in params if v)
    return f'vmess://{c.uuid}@{_bracket(c.host)}:{c.port}?{qs}' + (f'#{_pq(name)}' if name else '')

def _vmess_json_canonical(c: Cfg) -> str:
    """vmess JSON -> тот же JSON, но в каноническом base64 (без мусорного хвоста и
    двойного кодирования): клиент декодирует ровно то, что проверил фильтр."""
    j = json.dumps(c.j, ensure_ascii=False, separators=(',', ':'))
    return 'vmess://' + base64.b64encode(j.encode('utf-8')).decode('ascii')

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
    if not ALLOW_SS:
        raise Reject('shadowsocks отключён: пароль = ключ шифрования, в публичной подписке он публичен')
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
    if _is_host_banned(c.host):
        raise Reject(f'сервер в чёрном списке доменов: {c.host}')
    c.q = q
    c.method = method
    c.password = password
    c.plugin = plugin
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
        c.ports = pr
    else:
        raise Reject(f'неверный порт: {pr[:30]!r}')
    c.host = check_host(host)
    _common(c, q, core)
    sni = q.get('sni', '').strip()                   # только точный ключ (URI-схема hy2)
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
    sni = q.get('sni', '').strip()
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

@lru_cache(maxsize=65536)
def _parse_line(line: str):
    """-> (причина_отбраковки | '', Cfg | None). Пустая причина = конфиг прошёл."""
    try:
        if len(line) > MAX_LINE_LEN:
            raise Reject(f'слишком длинная строка (> {MAX_LINE_LEN})')
        if preprocess(line) != line:
            # проверяем только то, что опубликуем: строка обязана быть уже нормализована
            raise Reject('ссылка не нормализована')
        if not line or not is_supported_protocol(line):
            raise Reject('протокол не поддерживается')
        m = SCHEME_RE.match(line)
        proto = SCHEME_ALIAS.get(m.group(1).lower(), m.group(1).lower())
        if proto not in ACCEPTED:
            raise Reject(f'протокол {proto} не поддерживается')
        return '', _PARSERS[proto](_core(line))
    except Reject as e:
        return str(e), None
    except Exception as e:
        return f'внутренняя ошибка: {type(e).__name__}', None

def _ids(c: Cfg) -> tuple:
    """(key, pbk, vless_uuid, sid, trojan_pass, tuic_cred, 'host:port:proto') —
    всё, что нужно для дедупликации и лимитов «публичного пула»."""
    p = c.proto
    return (
        c.key,
        c.pbk,
        c.uuid if p == 'vless' else '',
        c.sid,
        c.password if p == 'trojan' else '',
        f'{c.uuid}:{c.password}' if p == 'tuic' else '',
        f'{c.host}:{c.port}:{p}',
    )

def analyze_config(line: str):
    """-> (причина_отбраковки | '', ids). Строка должна быть после preprocess()."""
    reason, c = _parse_line(line)
    return (reason, None) if reason else ('', _ids(c))

# Явный «проверять сертификат»: v2rayNG при отсутствии allowInsecure/insecure берёт
# глобальную настройку «Allow insecure», а её нередко включают «чтобы всё работало».
_VERIFY_FLAG = {'vless': 'allowInsecure', 'trojan': 'allowInsecure', 'vmess': 'allowInsecure',
                'hysteria2': 'insecure', 'tuic': 'allow_insecure'}

def _rewrite_query(line: str, c: Cfg) -> str:
    """Канонизация параметров ссылки (не vmess-JSON): флаг проверки сертификата в точном
    написании клиента (allowinsecure=0 или только insecure=0 v2rayNG не видит и берёт
    глобальную настройку) и pbk без '=' (Xray/sing-box читают base64url без паддинга)."""
    flag = _VERIFY_FLAG.get(c.proto) if FORCE_VERIFY_FLAG else None
    core, sep, frag = line.partition('#')
    base, _, qs = core.partition('?')
    out, found = [], False
    for part in qs.split('&'):
        if not part:
            continue
        k = unquote(part.partition('=')[0]).strip().lower()
        if flag and k == flag.lower():
            # значение уже проверено (иначе ссылку отбраковали бы) — пишем канонически
            found, part = True, f'{flag}=0'
        elif k == 'pbk' and c.pbk:
            part = f'pbk={c.pbk.rstrip("=")}'
        out.append(part)
    if flag and not found:
        out.append(f'{flag}=0')
    if not out:
        return f'{base}{sep}{frag}'
    return f"{base}?{'&'.join(out)}{sep}{frag}"

def _publish_form(line: str, c: Cfg) -> str:
    """Строка для публикации. Для vmess-JSON — std-ссылка или канонический base64 (по
    VMESS_JSON_MODE); для остальных — та же ссылка с канонизированными параметрами."""
    if c.j is not None:
        return _vmess_json_to_std(c) if VMESS_JSON_MODE == 'std' else _vmess_json_canonical(c)
    return _rewrite_query(line, c)

def prepare_config(line: str):
    """Проверка + канонизация. -> (причина | '', ids | None, строка_для_публикации).
    Публикуемая строка проверяется заново и обязана быть неподвижной точкой."""
    reason, c = _parse_line(line)
    if reason:
        return reason, None, line
    pub = _publish_form(line, c)
    if pub != line:
        reason, c = _parse_line(pub)
        if reason:
            return f'после канонизации: {reason}', None, line
        if _publish_form(pub, c) != pub:
            return 'канонизация не сходится', None, line
    return '', _ids(c), pub

def get_reject_reason(line: str) -> str:
    return analyze_config(preprocess(line))[0]

def is_safe_config_base(line: str) -> bool:
    return analyze_config(preprocess(line))[0] == ''

def reason_bucket(reason: str) -> str:
    """Укрупняет причину для статистики (без переменных значений)."""
    return re.sub(r'[:=(\[{].*$', '', reason).strip()[:70] or reason[:70]

# =====================================================================
#  ПАРСИНГ МНОГОСТРОЧНЫХ КОНФИГОВ
# =====================================================================

def parse_multiline_configs(lines: List[str]) -> List[str]:
    """Одна ссылка — одна строка. Продолжение приклеивается, только если это явно
    продолжение запроса: предыдущая строка кончается на '?'/'&' или новая начинается
    с '?'/'&'. (В v6.0 приклеивалась любая строка с '=', например base64 с паддингом.)"""
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
        elif current and '#' not in current and (
                current.endswith(('?', '&')) or stripped.startswith(('?', '&'))):
            if current.endswith(('?', '&')) and stripped.startswith(('?', '&')):
                stripped = stripped[1:]
            elif stripped.startswith('?') and '?' in current:
                stripped = '&' + stripped[1:]
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

# YAML читается ТОЛЬКО чистым SafeLoader: CSafeLoader падает с SIGSEGV на [[[[…]]]]
# глубиной ~1e5 (файл в 200 КБ ронял бы весь процесс), чистый даёт RecursionError.
_YAML_LOADER = getattr(yaml, 'SafeLoader', None) if HAS_YAML else None

def _pq(s: str) -> str:
    return urllib.parse.quote(s, safe='')

def _ys(v, limit: int = 4096) -> str:
    """Скаляр YAML -> строка. Списки/словари -> '': str() от alias-«бомбы»
    (&a [*b,*b,…]) строит гигабайты, поэтому вложенное никогда не превращается в текст."""
    if isinstance(v, bool):
        return 'true' if v else 'false'
    if isinstance(v, (str, int, float)):
        s = str(v).strip()
        return s if len(s) <= limit else ''
    return ''

def _yl(v, limit: int = 16) -> List[str]:
    """Список скаляров или строка 'a,b' -> список строк; всё прочее -> []."""
    items = [_ys(x, 256) for x in v[:limit]] if isinstance(v, list) else _ys(v, 1024).split(',')
    return [x.strip() for x in items if x and x.strip()]

def _yd(v) -> dict:
    return v if isinstance(v, dict) else {}

def _clash_flag(v) -> bool:
    """Флаг небезопасности: всё, кроме явного «выключено», считается ВКЛЮЧЁННЫМ."""
    if v is None or v is False:
        return False
    if v is True:
        return True
    if isinstance(v, (int, float)):
        return v != 0
    if isinstance(v, str):
        return v.strip().lower() not in FALSE_SET     # пустая строка тоже «включено»
    return True                                       # список/словарь — подозрительно

def _clash_true(v) -> bool:
    """tls включён только явным true — как в Mihomo."""
    if isinstance(v, bool):
        return v
    if isinstance(v, int):
        return v == 1
    return isinstance(v, str) and v.strip().lower() in TRUE_SET

def clash_to_uris(content: str) -> List[str]:
    """Clash/Mihomo YAML -> ссылки. Берутся только proxies (proxy-providers с чужими
    URL не скачиваются). Каждая ссылка потом проходит ТУ ЖЕ проверку, что и обычная."""
    if not HAS_YAML:
        return []
    try:
        data = yaml.load(content, Loader=_YAML_LOADER)
    except Exception:                                 # в т.ч. RecursionError
        return []
    proxies = data.get('proxies') if isinstance(data, dict) else None
    if not isinstance(proxies, list):
        return []
    uris = []
    for p in proxies[:MAX_CLASH_PROXIES]:
        if not isinstance(p, dict):
            continue
        try:
            u = _clash_proxy_to_uri(p)
        except Exception:
            u = None
        if u:
            uris.append(u)
    return uris

def _clash_qs(params: dict) -> str:
    return '&'.join(f'{k}={_pq(v)}' for k, v in params.items() if v)

def _clash_trust(p: dict, params: dict, insecure_key: str):
    """Небезопасность НЕ теряется при конверсии — такой узел увидит и отбракует фильтр.
    fingerprint (пин сертификата) отбрасывается: без него клиент проверяет цепочку
    обычным образом, а сервер с самоподписанным сертификатом просто не подключится."""
    if _clash_flag(p.get('skip-cert-verify')):
        params[insecure_key] = '1'
    if p.get('ca') or p.get('ca-str'):
        params['ca'] = 'custom'
    if _clash_flag(p.get('disable-sni')):
        params['disable_sni'] = '1'

def _clash_tls_params(p: dict, params: dict):
    params['sni'] = _ys(p.get('servername')) or _ys(p.get('sni'))
    params['alpn'] = ','.join(_yl(p.get('alpn')))
    params['fp'] = _ys(p.get('client-fingerprint'))

def _clash_transport(p: dict, params: dict) -> bool:
    """network + *-opts Clash -> type/path/host/serviceName ссылки. False — не умеем."""
    net = _ys(p.get('network')).lower() or 'tcp'
    if net == 'ws':
        wo = _yd(p.get('ws-opts'))
        hdr = _yd(wo.get('headers'))
        params['type'] = 'httpupgrade' if _clash_true(wo.get('v2ray-http-upgrade')) else 'ws'
        params['path'] = _ys(wo.get('path'))
        params['host'] = _ys(hdr.get('Host')) or _ys(hdr.get('host'))
    elif net == 'grpc':
        params['type'] = 'grpc'
        params['serviceName'] = _ys(_yd(p.get('grpc-opts')).get('grpc-service-name'))
    elif net == 'h2':                                 # HTTP/2 = «http» в терминах Xray-ссылок
        ho = _yd(p.get('h2-opts'))
        params['type'] = 'http'
        params['path'] = _ys(ho.get('path'))
        params['host'] = ','.join(_yl(ho.get('host')))
    elif net == 'http':                               # HTTP/1.1-маскировка поверх TCP (не h2!)
        ho = _yd(p.get('http-opts'))
        hdr = _yd(ho.get('headers'))
        params['type'] = 'tcp'
        params['headerType'] = 'http'
        params['path'] = ','.join(_yl(ho.get('path')))
        params['host'] = ','.join(_yl(hdr.get('Host') if 'Host' in hdr else hdr.get('host')))
    elif net == 'tcp':
        params['type'] = 'tcp'
    else:
        return False                                  # xhttp/kcp/quic и прочее
    return True

def _clash_proxy_to_uri(p: dict) -> Optional[str]:
    t = _ys(p.get('type')).lower()
    host = _ys(p.get('server'), 255)
    port = p.get('port')
    if (not host or isinstance(port, bool) or not isinstance(port, (int, str))
            or not str(port).strip().isdigit()):
        return None
    port = int(str(port).strip())
    hp = f'{_bracket(host)}:{port}'
    name = _sanitize_name(_ys(p.get('name'), 1024))[:MAX_NAME_LEN]
    frag = '#' + _pq(name) if name else ''
    params: Dict[str, str] = {}

    if t == 'vless':
        ro = _yd(p.get('reality-opts'))
        if not _clash_true(p.get('tls')):
            params['security'] = 'none'               # -> «нет TLS», отбраковка с причиной
        elif _ys(ro.get('public-key')):
            params.update(security='reality', pbk=_ys(ro.get('public-key')),
                          sid=_ys(ro.get('short-id')))
        else:
            params['security'] = 'tls'
        _clash_tls_params(p, params)
        params['flow'] = _ys(p.get('flow'))
        params['encryption'] = _ys(p.get('encryption'))
        if not _clash_transport(p, params):
            return None
        _clash_trust(p, params, 'allowInsecure')
        return f"vless://{_pq(_ys(p.get('uuid')))}@{hp}?{_clash_qs(params)}{frag}"
    if t == 'vmess':
        return _clash_vmess_to_uri(p, name, host, port)
    if t == 'trojan':
        so = _yd(p.get('ss-opts'))
        if so and _clash_flag(so.get('enabled')):
            return None                               # trojan-go + shadowsocks: клиенты не умеют
        if _ys(_yd(p.get('reality-opts')).get('public-key')):
            params['security'] = 'reality'            # -> отбраковка (trojan только с tls)
        _clash_tls_params(p, params)
        if not _clash_transport(p, params):
            return None
        _clash_trust(p, params, 'allowInsecure')
        return f"trojan://{_pq(_ys(p.get('password')))}@{hp}?{_clash_qs(params)}{frag}"
    if t in ('hysteria2', 'hy2'):
        params.update(sni=_ys(p.get('sni')), alpn=','.join(_yl(p.get('alpn'))),
                      obfs=_ys(p.get('obfs')), mport=_ys(p.get('ports')))
        params['obfs-password'] = _ys(p.get('obfs-password'))
        _clash_trust(p, params, 'insecure')
        return f"hysteria2://{_pq(_ys(p.get('password')))}@{hp}?{_clash_qs(params)}{frag}"
    if t == 'tuic':
        uuid = _ys(p.get('uuid'))
        if not uuid:
            return None                               # TUIC v4 (token) клиенты не поддерживают
        params.update(sni=_ys(p.get('sni')), alpn=','.join(_yl(p.get('alpn'))),
                      congestion_control=_ys(p.get('congestion-controller')),
                      udp_relay_mode=_ys(p.get('udp-relay-mode')))
        _clash_trust(p, params, 'allow_insecure')
        return (f"tuic://{_pq(uuid)}:{_pq(_ys(p.get('password')))}@{hp}"
                f"?{_clash_qs(params)}{frag}")
    if t == 'ss':
        cipher, pwd = _ys(p.get('cipher')).lower(), _ys(p.get('password'))
        if not cipher or not pwd:
            return None
        ub = base64.urlsafe_b64encode(f'{cipher}:{pwd}'.encode('utf-8')).decode('ascii').rstrip('=')
        plug = _ys(p.get('plugin')).lower()
        if plug in ('obfs', 'obfs-local', 'simple-obfs'):
            po = _yd(p.get('plugin-opts'))
            plug = f"obfs-local;obfs={_ys(po.get('mode')) or 'http'}"
            if _ys(po.get('host')):
                plug += f";obfs-host={_ys(po.get('host'))}"
        # прочие плагины передаются одним именем: фильтр отбракует их с понятной причиной
        return f"ss://{ub}@{hp}" + (f'?plugin={_pq(plug)}' if plug else '') + frag
    return None                                       # ssr и прочее — не поддерживаются

def _clash_vmess_to_uri(p: dict, name: str, host: str, port: int) -> Optional[str]:
    if _ys(_yd(p.get('reality-opts')).get('public-key')):
        return None                                   # vmess+reality в JSON-форме не выражается
    tp: Dict[str, str] = {}
    if not _clash_transport(p, tp):
        return None
    cfg = {
        'v': '2', 'ps': name, 'add': host, 'port': str(port),
        'id': _ys(p.get('uuid')), 'aid': _ys(p.get('alterId')) or '0',
        'scy': _ys(p.get('cipher')) or 'auto',
        'net': {'http': 'h2'}.get(tp['type'], tp['type']),
        'type': tp.get('headerType', 'none'), 'host': tp.get('host', ''),
        'path': tp.get('serviceName') or tp.get('path', ''),
        'tls': 'tls' if _clash_true(p.get('tls')) else '',
        'sni': _ys(p.get('servername')) or _ys(p.get('sni')),
        'alpn': ','.join(_yl(p.get('alpn'))), 'fp': _ys(p.get('client-fingerprint')),
    }
    if _clash_flag(p.get('skip-cert-verify')):
        cfg['allowInsecure'] = '1'                    # -> отбраковка
    if p.get('ca') or p.get('ca-str'):
        cfg['ca'] = 'custom'                          # -> отбраковка
    j = json.dumps({k: v for k, v in cfg.items() if v != ''},
                   ensure_ascii=False, separators=(',', ':'))
    return 'vmess://' + base64.b64encode(j.encode('utf-8')).decode('ascii')

# =====================================================================
#  CLASH OUTPUT (URI -> YAML)
# =====================================================================

# Встроенные политики/группа Mihomo: прокси с именем «DIRECT» в группе выглядел бы как
# узел, а повтор имени группы ломает загрузку всего файла.
_RESERVED_CLASH_NAMES = {'direct', 'reject', 'reject-drop', 'pass', 'compatible', 'global', 'proxy'}

# Символы, из-за которых go-yaml/PyYAML отвергают ВЕСЬ файл, или ломающие строку.
_YAML_UNSAFE_RE = re.compile('[\x00-\x1f\x7f-\x9f\u2028\u2029\ud800-\udfff\ufffe\uffff]')

def _sanitize_name(s) -> str:
    """Имя прокси: без переносов, управляющих, невидимых и недопустимых в YAML символов."""
    s = _INVISIBLE_RE.sub('', str(s))
    s = _YAML_UNSAFE_RE.sub(' ', s)
    return re.sub(r'\s+', ' ', s).strip()

def _q(s) -> str:
    """Имя -> YAML double-quoted скаляр (JSON-строка — валидный YAML)."""
    return json.dumps(_sanitize_name(s), ensure_ascii=False)

def _qv(v) -> str:
    """Значение (пароль, путь…) -> YAML-строка; пробелы не трогаются."""
    return json.dumps(_YAML_UNSAFE_RE.sub('', str(v)), ensure_ascii=False)

def _clash_tls_fields(q: Q, out: dict, sni_key: str = 'servername'):
    sni = q.get('sni', '').strip()
    if sni:
        out[sni_key] = sni
    alpn = _norm_alpn(qget(q, 'alpn'))
    if alpn:
        out['alpn'] = alpn
    fp = qget(q, 'fp', 'fingerprint').strip().lower()
    if fp in SAFE_FINGERPRINTS:
        out['client-fingerprint'] = fp
    out['skip-cert-verify'] = False                   # явно: сертификат проверяется

_CLASH_TLS_NETS = ('tcp', 'tcp-http', 'ws', 'httpupgrade', 'grpc', 'http')

def _clash_net(q: Q, out: dict, allowed: tuple) -> bool:
    """type/path/host ссылки -> network + *-opts. False — Mihomo так не умеет (xhttp, kcp)."""
    net = _read_net(q)
    if net == 'tcp' and q.get('headertype', '').strip().lower() == 'http':
        net = 'tcp-http'
    if net not in allowed:
        return False
    path = q.get('path') or q.get('wspath', '')
    hosts = [h.strip() for h in q.get('host', '').split(',') if h.strip()]
    if net == 'tcp':
        out['network'] = 'tcp'
    elif net == 'tcp-http':
        ho = {'method': 'GET', 'path': [x.strip() for x in path.split(',') if x.strip()] or ['/']}
        if hosts:
            ho['headers'] = {'Host': hosts}
        out['network'] = 'http'
        out['http-opts'] = ho
    elif net in ('ws', 'httpupgrade'):
        wo = {'path': path or '/'}
        if hosts:
            wo['headers'] = {'Host': hosts[0]}
        if net == 'httpupgrade':
            wo['v2ray-http-upgrade'] = True
        out['network'] = 'ws'
        out['ws-opts'] = wo
    elif net == 'grpc':
        out['network'] = 'grpc'
        out['grpc-opts'] = {'grpc-service-name': qget(q, 'servicename', 'service_name')}
    elif net == 'http':                               # «http» в Xray = HTTP/2
        ho = {'path': path or '/'}
        if hosts:
            ho['host'] = hosts
        out['network'] = 'h2'
        out['h2-opts'] = ho
    return True

def _mlkem768_key_ok(b: bytes) -> bool:
    """FIPS 203: ключ инкапсуляции ML-KEM-768 = 768 коэффициентов по 12 бит (< 3329) + 32 байта."""
    if len(b) != 1184:
        return False
    for i in range(0, 1152, 3):
        x = b[i] | (b[i + 1] << 8) | (b[i + 2] << 16)
        if (x & 0xFFF) >= 3329 or (x >> 12) >= 3329:
            return False
    return True

def _vless_enc_ok(enc: str) -> bool:
    """Ключи VLESS Encryption — как их проверяет Mihomo: один битый ключ ломает
    загрузку ВСЕГО YAML (все узлы подписки), поэтому такой узел в Clash не пишется."""
    keys = 0
    for part in enc.split('.')[3:]:
        if re.fullmatch(r'\d+-\d+-\d+', part):
            continue                                  # блок padding
        raw = b64d(part) if re.fullmatch(r'[A-Za-z0-9_-]+', part) else None
        if raw is None or not (len(raw) == 32 or _mlkem768_key_ok(raw)):
            return False
        keys += 1
    return keys > 0

def _clash_vless(c: Cfg) -> Optional[dict]:
    q = c.q
    out = {'type': 'vless', 'uuid': c.uuid, 'udp': True, 'tls': True}
    flow = q.get('flow', '')
    if flow.startswith('xtls-rprx-vision'):
        out['flow'] = 'xtls-rprx-vision'              # Mihomo не знает суффикс -udp443
    elif flow not in ('', 'none'):
        return None                                   # неизвестный flow Mihomo не грузит
    enc = q.get('encryption', '').strip()
    if enc and enc.lower() != 'none':
        if not _vless_enc_ok(enc):
            return None
        out['encryption'] = enc
    _clash_tls_fields(q, out)
    if q.get('security') == 'reality':
        ro = {'public-key': c.pbk.rstrip('=')}       # Mihomo читает ключ строго без '='
        if c.sid:
            ro['short-id'] = c.sid
        out['reality-opts'] = ro
    return out if _clash_net(q, out, _CLASH_TLS_NETS) else None

def _vmess_json_q(j: dict, server: str) -> Q:
    """Поля vmess JSON -> параметры как у ссылки (для общего построения Clash).
    sni — как его выводит клиент: поле sni, иначе host, иначе адрес-домен."""
    low = {str(k).lower(): ('' if v is None else str(v).strip()) for k, v in j.items()}

    def g(*keys):
        return next((low[k] for k in keys if low.get(k)), '')

    q = Q()
    net_raw = (g('net', 'network') or 'tcp').lower()
    net = _VMESS_NET_ALIAS.get(net_raw, net_raw)
    q['type'] = net
    if g('type').lower() == 'http':
        q['headertype'] = 'http'
    q['host'], q['path'] = g('host'), g('path')
    if net == 'grpc':
        q['servicename'] = g('path')
    sni = g('sni')
    if not sni:
        hh = g('host').split(',')[0].strip() if net in ('ws', 'http', 'httpupgrade', 'xhttp') else ''
        sni = hh or ('' if _is_ip_literal(server) else server)
    q['sni'], q['alpn'], q['fp'] = sni, g('alpn'), g('fp', 'fingerprint')
    q['scy'] = g('scy', 'security', 'cipher').lower()
    return q

def _clash_vmess(c: Cfg) -> Optional[dict]:
    if c.j is None:                                   # URL-форма vmess://uuid@host:port?…
        q = c.q
        if q.get('security') != 'tls':
            return None                               # vmess+reality Mihomo не поддерживает
        scy = q.get('encryption', '').strip().lower()
    else:
        q = _vmess_json_q(c.j, c.host)
        scy = q['scy']
    out = {'type': 'vmess', 'uuid': c.uuid, 'alterId': 0,
           'cipher': scy if scy in ('aes-128-gcm', 'chacha20-poly1305') else 'auto',
           'udp': True, 'tls': True}
    _clash_tls_fields(q, out)
    return out if _clash_net(q, out, _CLASH_TLS_NETS) else None

def _clash_trojan(c: Cfg) -> Optional[dict]:
    q = c.q
    out = {'type': 'trojan', 'password': c.password, 'udp': True}
    _clash_tls_fields(q, out, 'sni')
    if not _clash_net(q, out, ('tcp', 'ws', 'grpc')):
        return None
    if out.get('network') == 'tcp':
        del out['network']
    return out

def _clash_hy2(c: Cfg) -> Optional[dict]:
    q = c.q
    out = {'type': 'hysteria2', 'password': c.password, 'udp': True,
           'sni': q.get('sni', '').strip()}
    alpn = _norm_alpn(qget(q, 'alpn'))
    if alpn:
        out['alpn'] = alpn
    ob = qget(q, 'obfs').strip().lower()
    if ob:
        out['obfs'] = ob
        out['obfs-password'] = qget(q, 'obfs-password', 'obfspassword', 'obfs-param', 'obfsparam')
    ports = qget(q, 'mport', 'ports').strip() or c.ports
    if ports:
        out['ports'] = ports
    out['skip-cert-verify'] = False
    return out

def _clash_tuic(c: Cfg) -> Optional[dict]:
    q = c.q
    out = {'type': 'tuic', 'uuid': c.uuid, 'password': c.password, 'udp': True,
           'sni': q.get('sni', '').strip(),
           'alpn': _norm_alpn(qget(q, 'alpn')) or ['h3']}
    cc = qget(q, 'congestion_control', 'congestioncontrol', 'cc').strip().lower()
    if cc:
        out['congestion-controller'] = cc
    urm = qget(q, 'udp_relay_mode', 'udprelaymode').strip().lower()
    if urm:
        out['udp-relay-mode'] = urm
    out['skip-cert-verify'] = False
    return out

def _clash_ss(c: Cfg) -> Optional[dict]:
    out = {'type': 'ss', 'cipher': c.method, 'password': c.password, 'udp': True}
    if c.plugin:                                      # фильтр пропускает только obfs-local + obfs=http
        plug = unquote(c.plugin)
        if '%3b' in plug.partition(';')[0].lower():
            plug = unquote(plug)
        kv = {}
        for part in plug.partition(';')[2].split(';'):
            k, _, v = part.partition('=')
            if k.strip():
                kv[k.strip().lower()] = v.strip()
        po = {'mode': kv.get('obfs') or 'http'}
        if kv.get('obfs-host'):
            po['host'] = kv['obfs-host']
        out['plugin'] = 'obfs'
        out['plugin-opts'] = po
    return out

_CLASH_BUILDERS = {'vless': _clash_vless, 'vmess': _clash_vmess, 'trojan': _clash_trojan,
                   'hysteria2': _clash_hy2, 'tuic': _clash_tuic, 'ss': _clash_ss}

def _clash_proxy_is_safe(p: dict) -> bool:
    """Последний рубеж перед записью YAML: без TLS / без проверки сертификата — не пишем."""
    t = p.get('type')
    if t not in ('vless', 'vmess', 'trojan', 'hysteria2', 'tuic', 'ss'):
        return False
    if any(k in p for k in ('fingerprint', 'ca', 'ca-str', 'disable-sni')):
        return False
    if t == 'ss':
        return p.get('cipher') in SAFE_SS_CANON and p.get('plugin') in (None, 'obfs')
    if p.get('skip-cert-verify') is not False:
        return False
    if t in ('vless', 'vmess') and p.get('tls') is not True:
        return False
    ro = p.get('reality-opts')
    return ro is None or (isinstance(ro, dict) and bool(ro.get('public-key')))

def uri_to_clash(uri: str) -> Optional[dict]:
    """Clash-прокси из ТОГО ЖЕ разбора (_parse_line), что прошёл проверку. В v6.0 второй
    парсер на регулярках по-своему читал IPv6, пароли и транспорт."""
    reason, c = _parse_line(uri)
    if reason or c is None:
        return None
    try:
        body = _CLASH_BUILDERS[c.proto](c)
    except Exception:
        return None
    if not body:
        return None
    name = unquote(uri.partition('#')[2])
    if not name and c.j is not None:
        ps = next((v for k, v in c.j.items() if str(k).lower() in ('ps', 'remarks')), '')
        name = ps if isinstance(ps, str) else ''
    name = _sanitize_name(name)[:MAX_NAME_LEN].strip() or f'{c.host}:{c.port}'
    p = {'name': name, 'type': body.pop('type'), 'server': c.host, 'port': c.port}
    p.update(body)
    return p if _clash_proxy_is_safe(p) else None

def _yaml_value(v) -> str:
    if isinstance(v, bool):
        return 'true' if v else 'false'
    if isinstance(v, int):
        return str(v)
    return _qv(v)

def _dump_kv(lines: List[str], k: str, v, ind: str):
    if isinstance(v, dict):
        if not v:
            lines.append(f'{ind}{k}: {{}}')
            return
        lines.append(f'{ind}{k}:')
        for kk, vv in v.items():
            _dump_kv(lines, kk, vv, ind + '  ')
    elif isinstance(v, list):
        if not v:
            lines.append(f'{ind}{k}: []')
            return
        lines.append(f'{ind}{k}:')
        lines.extend(f'{ind}  - {_yaml_value(x)}' for x in v)
    else:
        lines.append(f'{ind}{k}: {_yaml_value(v)}')

def _dump_clash_yaml(proxies: List[dict], filepath: str):
    lines = ['# clash/mihomo subscription',
             f'# {time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())}',
             'proxies:']
    for p in proxies:
        lines.append(f'  - name: {_q(p["name"])}')
        for k, v in p.items():
            if k != 'name':
                _dump_kv(lines, k, v, '    ')
    lines += ['proxy-groups:', '  - name: PROXY', '    type: select', '    proxies:']
    lines += [f'      - {_q(p["name"])}' for p in proxies]
    lines += ['rules:', '  - MATCH,PROXY']
    _atomic_write(filepath, '\n'.join(lines) + '\n')

def convert_to_clash_and_save(configs: List[str], filename: str) -> int:
    outpath = os.path.join(CLASH_DIR, f"{filename}.yaml")
    proxies, seen, used = [], set(), set()
    for uri in configs:
        cp = uri_to_clash(uri)
        if not cp:
            continue
        # дедупликация по тому же ключу узла, что и в txt (ws/grpc/tcp на одном
        # host:port — разные узлы; один узел с разными именами — один)
        sk = analyze_config(uri)[1][0]
        if sk in seen:
            continue
        seen.add(sk)
        base = cp['name']
        if base.lower() in _RESERVED_CLASH_NAMES:
            base = f'{base} ({cp["type"]})'
        nm, i = base, 2
        while nm.lower() in used:                     # Mihomo отвергает ВЕСЬ файл при повторе имени
            nm = f'{base} #{i}'
            i += 1
        used.add(nm.lower())
        cp['name'] = nm
        proxies.append(cp)
    if not proxies:
        if os.path.exists(outpath):
            os.remove(outpath)                        # не оставляем устаревший YAML
        return 0
    _dump_clash_yaml(proxies, outpath)
    return len(proxies)

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

def _atomic_write(path: str, text: str):
    """Временный файл + os.replace: при сбое не остаётся обрезанного/пустого файла."""
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    tmp = f'{path}.tmp{os.getpid()}-{threading.get_ident()}'
    try:
        with open(tmp, 'w', encoding='utf-8', newline='\n') as f:
            f.write(text)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)

def save_health(health: Dict):
    with _health_lock:
        text = json.dumps(health, indent=2, ensure_ascii=False)
    _atomic_write(HEALTH_FILE, text)

def _try_b64_decode(s: str) -> Optional[str]:
    """Подписка целиком в base64: std или url-safe, с паддингом и без, в т.ч. дважды.
    (В v6.0 b64decode без validate молча выкидывал '-'/'_', и url-safe не читался.)"""
    text = s
    for _ in range(2):
        raw = b64d(text)
        if raw is None:
            return None
        dec = raw.decode('utf-8', errors='ignore').lstrip('\ufeff')
        if any(p in dec for p in SUPPORTED_PROTOCOLS):
            return dec
        text = re.sub(r'\s+', '', dec)
        if not re.fullmatch(r'[A-Za-z0-9+/_=-]+', text):
            return None
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

class _HttpsOnlyRedirect(urllib.request.HTTPRedirectHandler):
    """Редирект только на https: иначе https-источник могли бы увести на http и
    подменить подписку по дороге."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.lower().startswith('https://'):
            raise urllib.error.HTTPError(newurl, code, 'редирект не на https', headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)

_OPENER = urllib.request.build_opener(_HttpsOnlyRedirect)

def _http_get_inner(url: str) -> bytes:
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0',
                                               'Accept-Encoding': 'identity'})
    deadline = time.monotonic() + FETCH_DEADLINE
    chunks, total = [], 0
    with _OPENER.open(req, timeout=FETCH_TIMEOUT) as resp:
        read = getattr(resp, 'read1', resp.read)
        while True:
            if time.monotonic() > deadline:
                raise TimeoutError(f'загрузка дольше {FETCH_DEADLINE} с')
            chunk = read(65536)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_FETCH_BYTES:
                raise ValueError(f'ответ больше {MAX_FETCH_BYTES // (1024 * 1024)} МБ')
            chunks.append(chunk)
    return b''.join(chunks)

def _http_get(url: str) -> bytes:
    """GET только по https, с лимитом размера и ОБЩИМ дедлайном. timeout в urllib —
    на каждую операцию чтения, и «капающий» по байту сервер держал бы загрузку часами,
    поэтому загрузка идёт в фоновом потоке, который ждут не дольше FETCH_DEADLINE."""
    if not url.lower().startswith('https://'):
        raise ValueError('разрешён только https')
    box: Dict[str, object] = {}

    def run():
        try:
            box['data'] = _http_get_inner(url)
        except BaseException as e:                    # noqa: BLE001 — передаём в вызывающий поток
            box['err'] = e

    t = threading.Thread(target=run, daemon=True)
    t.start()
    t.join(FETCH_DEADLINE + 2)
    if t.is_alive():
        raise TimeoutError(f'загрузка дольше {FETCH_DEADLINE} с')
    if 'err' in box:
        raise box['err']
    return box['data']

def _decode_subscription(content: str) -> Tuple[str, bool]:
    """Clash YAML -> ссылки; base64 -> текст; иначе как есть. -> (текст, был_base64)."""
    if is_clash_content(content):
        uris = clash_to_uris(content)
        if uris:
            return '\n'.join(uris), False
    stripped = re.sub(r'\s+', '', content)
    if stripped and re.fullmatch(r'[A-Za-z0-9+/_=-]+', stripped):
        decoded = _try_b64_decode(stripped)
        if decoded is not None:
            return decoded, True
    return content, False

def _now_utc() -> str:
    return time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())

def _stale_allowed(entry) -> bool:
    """Прошлый файл можно отдать, только если источник отвечал не позже STALE_MAX_HOURS назад."""
    try:
        ts = calendar.timegm(time.strptime(str((entry or {}).get('last_ok')).replace(' UTC', ''),
                                           '%Y-%m-%d %H:%M:%S'))
    except Exception:
        return False
    return time.time() - ts <= STALE_MAX_HOURS * 3600

def _read_previous_output(name: str) -> Optional[Tuple[str, bool]]:
    """Прошлый опубликованный файл источника -> (текст, был_base64). Его строки
    проходят полную проверку заново, как свежие."""
    try:
        with open(os.path.join(OUTPUT_DIR, f'{name}.txt'), 'r', encoding='utf-8',
                  errors='ignore') as f:
            text = f.read(MAX_FETCH_BYTES + 1)
    except OSError:
        return None
    if not text.strip() or len(text) > MAX_FETCH_BYTES:
        return None
    return _decode_subscription(text)

def fetch_url_with_health(url: str, health: Dict) -> Tuple[Optional[str], bool]:
    """-> (текст подписки | None, был_base64). None — не скачалось или источник на паузе."""
    with _health_lock:
        entry = dict(health.get(url) or {})
    try:
        failures = int(entry.get('failures') or 0)
    except (TypeError, ValueError):
        failures = 0
    if failures >= MAX_CONSECUTIVE_FAILURES and not _cooldown_passed(entry):
        print(f"  ⚠️  {url} — {failures} провалов подряд, пауза до повторной попытки")
        return None, False
    try:
        raw = _http_get(url)
    except Exception as e:
        entry.update(failures=failures + 1, last_status=str(e)[:200], last_check=_now_utc())
        with _health_lock:
            health[url] = entry
        print(f"  ❌ {url}: {e} (провал #{failures + 1})")
        return None, False
    now = _now_utc()
    entry.update(failures=0, last_status='ok', last_check=now, last_ok=now)
    with _health_lock:
        health[url] = entry
    return _decode_subscription(raw.decode('utf-8', errors='ignore').lstrip('\ufeff'))

def write_health_report(health: Dict, source_stats: Dict[str, Dict]):
    report_path = os.path.join(OUTPUT_DIR, "URL_HEALTH_REPORT.md")
    out = ["# URL Health Report\n",
           f"Generated: {_now_utc()}\n\n",
           "| Source | Status | Fails | Raw | Filtered | Rejected | Duplicates | Last Check |\n",
           "|---|---|---|---|---|---|---|---|\n"]
    for src in SOURCES_CONFIG:
        url = src['url']
        entry = health.get(url, {})
        st = source_stats.get(url, {})
        if st.get('stale'):
            status = "♻️ прошлый файл"
        elif entry.get("last_status") == "ok":
            status = "✅"
        else:
            status = "❌"
        out.append(f"| {src['name']} | {status} | {entry.get('failures', 0)} | "
                   f"{st.get('raw', '-')} | {st.get('filtered', '-')} | {st.get('rejected', '-')} | "
                   f"{st.get('duplicates', '-')} | {entry.get('last_check', 'N/A')} |\n")
    out.append(f"\n**Авто-очистка:** источник с {MAX_CONSECUTIVE_FAILURES}+ провалами подряд "
               f"ставится на паузу {RETRY_AFTER_SECONDS // 3600} ч и затем пробуется снова. "
               f"Пока источник недоступен (до {STALE_MAX_HOURS} ч), публикуется его прошлый "
               f"файл, перепроверенный текущими правилами.\n")
    _atomic_write(report_path, ''.join(out))

def write_reject_reasons(reasons: Counter):
    path = os.path.join(REJECT_DIR, "reasons.md")
    out = ["# Причины отбраковки\n\n| Причина | Кол-во |\n|---|---|\n"]
    out += [f"| {reason.replace('|', '/')} | {cnt} |\n" for reason, cnt in reasons.most_common(60)]
    _atomic_write(path, ''.join(out))

# =====================================================================
#  ЗАГРУЗКА + ФИЛЬТРАЦИЯ
# =====================================================================

def load_and_filter(source: Dict, health: Dict) -> Tuple[Set[str], List[str], Dict, bool]:
    name = source['name']
    url = source['url']
    print(f"  [{name}] Загрузка...")

    content, was_base64 = fetch_url_with_health(url, health)
    fetched, stale = content is not None, False
    if content is None:
        with _health_lock:
            entry = dict(health.get(url) or {})
        prev = _read_previous_output(name) if _stale_allowed(entry) else None
        if prev is not None:
            (content, was_base64), stale = prev, True
            print(f"  ♻️  [{name}] источник недоступен — перепроверяю прошлый файл")

    reasons: Counter = Counter()
    stats = {"raw": 0, "filtered": 0, "rejected": 0, "duplicates": 0, "reasons": reasons,
             "fetched": fetched, "stale": stale}
    if not content:
        return set(), [], stats, was_base64

    lines = [l.strip() for l in content.splitlines()]
    lines = [l for l in lines if l and not l.startswith('#')]
    rejected: List[str] = []
    raw_configs: List[str] = []
    parsed = parse_multiline_configs(lines)
    for cfg in parsed:
        if len(cfg) > MAX_LINE_LEN:                   # до preprocess: мегабайтная строка — мусор
            reasons[f'слишком длинная строка (> {MAX_LINE_LEN})'] += 1
            continue
        # preprocess чинит &amp; / \u0026 / невидимые символы; проверяется и публикуется
        # ровно эта строка (с добавленным allowInsecure=0)
        raw_configs.append(preprocess(cfg))
    raw_count = len(parsed)

    unique: Dict[tuple, Tuple[str, tuple]] = {}
    duplicates = 0
    for cfg in raw_configs:
        reason, ids, pub = prepare_config(cfg)
        if reason:
            rejected.append(cfg)
            reasons[reason_bucket(reason)] += 1
            continue
        # Дубликаты схлопываем ДО подсчёта лимитов: один и тот же узел с разными
        # именами/порядком параметров не должен раздувать счётчики.
        if ids[0] in unique:
            duplicates += 1
            continue
        unique[ids[0]] = (pub, ids)

    final_filtered: Set[str] = set()
    limit_reason = _pool_limit_checker([ids for _, ids in unique.values()])
    for cfg, ids in unique.values():
        why = limit_reason(ids)
        if why:
            rejected.append(cfg)
            reasons[why] += 1
            continue
        final_filtered.add(cfg)

    stats.update(raw=raw_count, filtered=len(final_filtered),
                 rejected=len(rejected) + sum(1 for c in parsed if len(c) > MAX_LINE_LEN),
                 duplicates=duplicates)
    return final_filtered, rejected, stats, was_base64

# ids = (key, pbk, uuid, sid, trojan_pass, tuic_cred, host:port:proto) — см. _ids()
_POOL_REASONS = (None,
                 'один Reality-ключ (pbk) у слишком многих узлов',
                 'один UUID у слишком многих узлов',
                 'один Reality sid у слишком многих узлов',
                 'один trojan-пароль у слишком многих узлов',
                 'одни tuic-учётные данные у слишком многих узлов',
                 'слишком много узлов на одном host:port')

def _pool_limit_checker(all_ids):
    """Лимиты «публичного пула» по множеству УНИКАЛЬНЫХ узлов. -> f(ids) = причина | ''.
    Превышение отбрасывает всю группу: один ключ/UUID на десятках узлов — это раздача,
    а не чей-то личный сервер."""
    all_ids = list(all_ids)
    limits = (None, PBK_MAX, UUID_MAX, SID_MAX, TROJAN_PASS_MAX, TUIC_CRED_MAX, HP_MAX)
    counts = [None] + [Counter(ids[i] for ids in all_ids if ids[i]) for i in range(1, 7)]

    def reason(ids) -> str:
        for i in range(1, 7):
            if ids[i] and counts[i][ids[i]] > limits[i]:
                return _POOL_REASONS[i]
        return ''
    return reason

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

def merge_all(configs) -> Tuple[List[str], Counter]:
    """ALL.txt: дедупликация между источниками + те же лимиты «публичного пула», что и
    внутри источника (иначе 3 узла с одним UUID из каждого из N источников давали бы 3N).
    -> (строки, причины отбраковки)."""
    kept = [(u, analyze_config(u)[1]) for u in dedupe_by_key(configs)]
    kept = [(u, ids) for u, ids in kept if ids]
    limit_reason = _pool_limit_checker([ids for _, ids in kept])
    out, reasons = [], Counter()
    for u, ids in kept:
        why = limit_reason(ids)
        if why:
            reasons[f'ALL: {why}'] += 1
            continue
        out.append(u)
    return out, reasons

# =====================================================================
#  MAIN
# =====================================================================

def _write_output(path: str, configs: List[str], as_base64: bool):
    text = '\n'.join(configs) + ('\n' if configs else '')
    if as_base64 and configs:
        text = base64.b64encode(text.encode('utf-8')).decode('ascii')
    _atomic_write(path, text)

def main() -> int:
    print("=== Фильтр прокси v6.2 (NekoBox / v2rayNG / Karing + Clash/Mihomo, hardened) ===")
    try:
        problems = _selftest()
    except Exception as e:                        # noqa: BLE001 — сломанная проверка = стоп
        problems = [f'самопроверка упала: {type(e).__name__}: {e}']
    if problems:
        print("❌ Самопроверка защиты не пройдена — подписки НЕ обновлены:")
        for p in problems[:30]:
            print(f"   • {p}")
        return 2
    health = load_health()
    all_filtered: Set[str] = set()
    all_rejected: List[str] = []
    all_reasons: Counter = Counter()
    source_stats, file_counts, clash_counts = {}, {}, {}
    fetched_ok = 0

    with ThreadPoolExecutor(max_workers=5) as ex:
        futures = {ex.submit(load_and_filter, src, health): src for src in SOURCES_CONFIG}
        for future in as_completed(futures):
            src = futures[future]
            name = src['name']
            try:
                configs, rejected, stats, was_base64 = future.result()
                source_stats[src['url']] = stats
                all_rejected.extend(rejected)
                all_reasons.update(stats.get('reasons', {}))
                fetched_ok += bool(stats.get('fetched'))

                sorted_cfg = sort_configs(configs)
                _write_output(os.path.join(OUTPUT_DIR, f"{name}.txt"), sorted_cfg, was_base64)
                tags = (' [base64]' if was_base64 and sorted_cfg else '') + \
                       (' [прошлый файл]' if stats.get('stale') else '')
                print(f"  ✅ {name}.txt → {len(sorted_cfg)} конфигов{tags} "
                      f"(отброшено: {stats['rejected']}, дублей: {stats['duplicates']})")

                clash_n = convert_to_clash_and_save(sorted_cfg, name)
                clash_counts[name] = clash_n
                if clash_n:
                    print(f"  🔄 Clash: {os.path.join(CLASH_DIR, name + '.yaml')} → {clash_n} прокси")

                all_filtered.update(configs)
                file_counts[name] = len(sorted_cfg)
            except Exception as e:
                print(f"  ❌ [{name}] Ошибка: {type(e).__name__}: {e}")
                file_counts[name] = 0
                clash_counts[name] = 0

    sorted_all, all_limit_reasons = merge_all(all_filtered)
    all_reasons.update(all_limit_reasons)
    _write_output(os.path.join(OUTPUT_DIR, "ALL.txt"), sorted_all, False)
    file_counts["ALL"] = len(sorted_all)
    clash_counts["ALL"] = convert_to_clash_and_save(sorted_all, "ALL")
    if clash_counts["ALL"]:
        print(f"  🔄 Clash ALL: {os.path.join(CLASH_DIR, 'ALL.yaml')} → {clash_counts['ALL']} прокси")

    # rejected.txt — готовая подписка из НЕБЕЗОПАСНЫХ узлов; публикуется только по флагу
    reject_file = os.path.join(REJECT_DIR, "rejected.txt")
    if PUBLISH_REJECTED:
        _write_output(reject_file, all_rejected, False)
    elif os.path.exists(reject_file):
        os.remove(reject_file)
    write_reject_reasons(all_reasons)

    save_health(health)
    write_health_report(health, source_stats)
    generate_qr_codes(file_counts)

    print(f"\n✅ ALL.txt: {len(sorted_all)} уникальных конфигов")
    if clash_counts.get("ALL"):
        print(f"🔄 Clash ALL.yaml: {clash_counts['ALL']} прокси → {CLASH_DIR}/")
    print(f"⚠️  Отброшено: {len(all_rejected)} (причины — rejected/reasons.md)")
    print(f"📊 URL Health: {os.path.join(OUTPUT_DIR, 'URL_HEALTH_REPORT.md')}")
    print(f"📱 QR-коды: {QR_DIR}/")
    if fetched_ok == 0:
        print("❌ Ни один источник не скачался — проверьте сеть и список источников")
        return 1
    return 0


# =====================================================================
#  САМОПРОВЕРКА ЗАЩИТЫ
#  main() начинает каждый запуск с быстрой проверки (доли секунды, без сети):
#  известные обходы проверки сертификата должны отбраковываться, а пропущенные
#  TLS-ссылки — публиковаться с включённой проверкой. Если правка кода или другая
#  версия Python это сломала, подписки НЕ перезаписываются (код выхода 2).
#  Полные регрессионные тесты: python filter.py --selftest
# =====================================================================

def _selftest(full: bool = False) -> List[str]:
    """full=False — быстрая проверка защиты (без сети и без записи файлов);
    full=True — все тесты во временном каталоге. -> список проблем (пусто — всё в порядке)."""
    import contextlib, io, random, shutil, string, tempfile
    f = sys.modules[__name__]

    U, H = 'a3482e88-686a-4a58-8126-99c9df64b7bf', 'node1.mydomain.de'
    T = f'sni={H}&fp=chrome&alpn=h2&type=tcp'
    PBK = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip('=')
    SS16 = base64.b64encode(bytes(range(16))).decode()
    SS32 = base64.b64encode(bytes(range(32))).decode()

    def vm(**kw):
        j = {"v": "2", "ps": "vm", "add": H, "port": "443", "id": U, "aid": "0", "scy": "auto",
             "net": "ws", "type": "none", "host": H, "path": "/vm", "tls": "tls", "sni": H}
        j.update(kw)
        return 'vmess://' + base64.b64encode(json.dumps(j).encode()).decode()

    def vm_raw(text):
        return 'vmess://' + base64.b64encode(text.encode()).decode()

    def vm_tail(link):
        return link + '2'                                # мусорный хвост после паддинга

    def ss(method, pw, tail=''):
        ub = base64.urlsafe_b64encode(f'{method}:{pw}'.encode()).decode().rstrip('=')
        return f'ss://{ub}@{H}:8388{tail}#ss'

    def XH(u, extra):
        h = f'x{u[-2:]}.mydomain.de'                     # свой host: лимит HP_MAX на host:port
        return (f'vless://{u}@{h}:443?security=tls&sni={h}&fp=chrome&alpn=h2&type=xhttp&path=%2Fx&extra='
                + urllib.parse.quote(json.dumps(extra), safe=''))

    def prep(raw):
        """Как в load_and_filter: preprocess -> prepare_config. -> (причина, публикуемая строка)."""
        reason, _, pub = f.prepare_config(f.preprocess(raw))
        return reason, pub

    def passes(raw):
        return prep(raw)[0] == ''

    def uid(i):
        return f'a3482e88-686a-4a58-8126-{i:012d}'   # у каждого узла свой UUID (лимит UUID_MAX)

    TPW = 'p@ss:w/rd?#&=% x'
    GOOD = {
        'vless_tls_ws':  f'vless://{uid(1)}@{H}:443?security=tls&sni={H}&fp=chrome&alpn=h2,http/1.1&type=ws&host={H}&path=%2Fws#good',
        'vless_reality': f'vless://{uid(2)}@{H}:443?security=reality&sni=www.microsoft.com&fp=chrome&pbk={PBK}&sid=6ba85179&type=tcp&flow=xtls-rprx-vision#r',
        'vless_ipv6':    f'vless://{uid(3)}@[2a01:4f8:c17:1::1]:443?security=tls&{T}#v6',
        'vless_nip_pub': f'vless://{uid(4)}@1.2.3.4.nip.io:443?security=tls&sni=1.2.3.4.nip.io&fp=chrome&alpn=h2&type=tcp#nip',
        'vless_flag0':   f'vless://{uid(5)}@{H}:443?security=tls&{T}&allowInsecure=0#f0',
        'vless_lc_flag': f'vless://{uid(11)}@n11.mydomain.de:443?security=tls&sni=n11.mydomain.de&fp=chrome&alpn=h2&type=tcp&allowinsecure=false#lc',
        'vless_ins_only': f'vless://{uid(12)}@n12.mydomain.de:443?security=tls&sni=n12.mydomain.de&fp=chrome&alpn=h2&type=tcp&insecure=0#io',
        'vless_trail_amp': f'vless://{uid(13)}@n13.mydomain.de:443/?security=tls&sni=n13.mydomain.de&fp=chrome&alpn=h2&type=tcp&#ta',
        'trojan_ws':     f'trojan://{urllib.parse.quote(TPW, safe="")}@{H}:443?sni={H}&alpn=h2&type=ws&host={H}&path=%2Ft#t',
        'vmess_json':    vm(),
        'hy2_obfs':      f'hysteria2://pw123@{H}:443?sni={H}&obfs=salamander&obfs-password=xyz#h',
        'tuic':          f'tuic://{U}:pw@{H}:443?sni={H}&alpn=h3&congestion_control=bbr#tu',
        'xhttp_dl_null': XH(uid(9), {"xPaddingBytes": "100-1000", "downloadSettings": None, "xmux": {"maxConcurrency": "16-32"}}),
        'xhttp_dl_tls':  XH(uid(10), {"downloadSettings": {"address": "cdn.example.de", "port": 443, "network": "xhttp",
                                                           "security": "tls", "tlsSettings": {"serverName": "cdn.example.de"}}}),
        'reality_udp443': f'vless://{uid(14)}@n14.mydomain.de:443?security=reality&sni=www.microsoft.com&fp=chrome&pbk={PBK}&type=tcp&flow=xtls-rprx-vision-udp443#u',
        'vmess_tail':    vm_tail(vm(id=uid(15), add='n15.mydomain.de', host='n15.mydomain.de', sni='n15.mydomain.de')),
    }
    # Shadowsocks: корректные по шифру ссылки, которые при ALLOW_SS=False обязаны отбраковываться
    SS_LINKS = {
        'ss_2022_aes':   ss('2022-blake3-aes-128-gcm', SS16),
        'ss_2022_chacha': ss('2022-blake3-chacha20-poly1305', SS32),
        'ss_aes_gcm':    ss('aes-256-gcm', 'Str0ngPassw0rd'),
    }
    if f.ALLOW_SS:
        GOOD.update(SS_LINKS)
    VMESS_JSON_LINK = GOOD['vmess_json']
    if f.VMESS_JSON_MODE == 'reject':
        del GOOD['vmess_json'], GOOD['vmess_tail']

    # Фильтр видит «TLS с проверкой сертификата», клиент — нет (или сертификат не проверяется).
    BYPASSES = {
        # --- 12 обходов v6.0 (ещё 3 — в ESCAPES)
        'sec_synonym':   f'vless://{U}@{H}:443?sec=tls&{T}',
        'key_case':      f'vless://{U}@{H}:443?Security=tls&{T}',
        'key_encoded':   f'vless://{U}@{H}:443?secur%69ty=tls&{T}',
        'eq_encoded':    f'vless://{U}@{H}:443?security%3Dtls&{T}',
        'semicolon':     f'vless://{U}@{H}:443?;security=tls&{T}',
        'dup_empty':     f'vless://{U}@{H}:443?security=tls&{T}&security=',
        'dup_other':     f'vless://{U}@{H}:443?security=tls&{T}&security=x',
        'trojan_empty':  f'trojan://Xk29fLq81pZ@{H}:443?security=&sni={H}&alpn=h2',
        'ipv6_nobrackets': f'vless://{U}@2a01:4f8:c17:1::1:443?security=tls&{T}',
        'ipv6_6to4_loopback': f'vless://{U}@[2002:7f00:1::1]:443?security=tls&{T}',
        'ipv6_nat64_loopback': f'vless://{U}@[64:ff9b:1::7f00:1]:443?security=tls&{T}',
        'huge_name':     f'vless://{U}@{H}:443?security=tls&{T}#' + 'A' * 100_000,
        # --- значение security не буквально
        'security_upper': f'vless://{U}@{H}:443?security=TLS&{T}',
        'security_space': f'vless://{U}@{H}:443?security=%20tls&{T}',
        'trojan_none':   f'trojan://Xk29fLq81pZ@{H}:443?security=none&sni={H}',
        'trojan_reality': f'trojan://Xk29fLq81pZ@{H}:443?security=reality&sni={H}&pbk={PBK}&fp=chrome',
        # --- отключённая/подменённая проверка сертификата
        'insecure_empty': f'vless://{U}@{H}:443?security=tls&{T}&allowInsecure=',
        'insecure_1':    f'vless://{U}@{H}:443?security=tls&{T}&allowInsecure=1',
        'insecure_typo': f'vless://{U}@{H}:443?security=tls&{T}&allowlnsecure=true',
        'skip_cert':     f'trojan://Xk29fLq81pZ@{H}:443?sni={H}&skip-cert-verify=true',
        'hy2_insecure':  f'hysteria2://pw123@{H}:443?sni={H}&insecure=1',
        'tuic_insecure': f'tuic://{U}:pw@{H}:443?sni={H}&alpn=h3&allow_insecure=1',
        'custom_ca':     f'vless://{U}@{H}:443?security=tls&{T}&ca=-----BEGIN%20CERTIFICATE-----',
        'certificates':  f'trojan://Xk29fLq81pZ@{H}:443?sni={H}&certificates=MIIB',
        'no_sys_root':   f'vless://{U}@{H}:443?security=tls&{T}&disableSystemRoot=true',
        'xhttp_download': (f'vless://{U}@{H}:443?security=tls&sni={H}&fp=chrome&alpn=h2&type=xhttp&path=%2Fx&extra='
                           + urllib.parse.quote('{"downloadSettings":{"address":"x.de","security":"none"}}', safe='')),
        'xhttp_insecure': (f'vless://{U}@{H}:443?security=tls&sni={H}&fp=chrome&alpn=h2&type=xhttp&path=%2Fx&extra='
                           + urllib.parse.quote('{"tlsSettings":{"allowInsecure":true}}', safe='')),
        'xhttp_dl_nosec': XH(uid(20), {"downloadSettings": {"address": "cdn.example.de", "port": 443, "network": "xhttp"}}),
        'xhttp_dl_case':  XH(uid(21), {"downloadSettings": {"address": "cdn.example.de", "Security": "none", "security": "tls"}}),
        'xhttp_dl_local': XH(uid(22), {"downloadSettings": {"address": "10.0.0.1", "security": "tls"}}),
        'xhttp_dl_ca':    XH(uid(23), {"downloadSettings": {"address": "cdn.example.de", "security": "tls",
                                                             "tlsSettings": {"certificates": [{"usage": "verify"}]}}}),
        'xhttp_double_enc': (f'vless://{uid(24)}@{H}:443?security=tls&sni={H}&fp=chrome&alpn=h2&type=xhttp&path=%2Fx&extra='
                             + urllib.parse.quote(urllib.parse.quote('{"tlsSettings":{"allowInsecure":true}}', safe=''), safe='')),
        'xhttp_broken':   f'vless://{uid(25)}@{H}:443?security=tls&sni={H}&fp=chrome&alpn=h2&type=xhttp&path=%2Fx&extra=%7B',
        # --- vmess JSON
        'vmess_TLS_value': vm(tls='TLS'),
        'vmess_tls_1':   vm(tls='1'),
        'vmess_case_dup': vm(TLS=''),
        'vmess_dup_key': vm_raw(json.dumps(json.loads(base64.b64decode(vm()[8:])))[:-1] + ', "tls": ""}'),
        'vmess_insecure': vm(allowInsecure=True),
        'vmess_skipcert': vm(**{'skip-cert-verify': 'true'}),
        'vmess_ca':      vm(ca='-----BEGIN'),
        # --- адреса, ведущие во внутреннюю сеть
        'nip_private':   f'vless://{U}@10.0.0.1.nip.io:443?security=tls&{T}',
        'sslip_private': f'vless://{U}@192-168-1-1.sslip.io:443?security=tls&{T}',
        'nip_loopback':  f'vless://{U}@127.0.0.1.nip.io:443?security=tls&{T}',
        'nip_hex':       f'vless://{U}@app-7f000001.nip.io:443?security=tls&{T}',
        'localtest':     f'vless://{U}@x.localtest.me:443?security=tls&{T}',
        # --- прочее
        'reality_no_pbk': f'vless://{U}@{H}:443?security=reality&sni=www.microsoft.com&fp=chrome&type=tcp',
        'ss_weak':       ss('aes-256-cfb', 'pw'),
        # --- v6.2: «обязательное» поле под синонимом фильтр видел, клиент — нет
        'pbk_synonym':   f'vless://{U}@{H}:443?security=reality&sni=www.microsoft.com&fp=chrome&publickey={PBK}&type=tcp',
        'sni_synonym':   f'vless://{U}@{H}:443?security=tls&servername={H}&fp=chrome&alpn=h2&type=tcp',
        'trojan_peer':   f'trojan://Xk29fLq81pZ@{H}:443?peer={H}&alpn=h2',
        'hy2_peer':      f'hysteria2://pw123@{H}:443?peer={H}',
        'sni_ip':        f'vless://{U}@{H}:443?security=tls&sni=1.2.3.4&fp=chrome&alpn=h2&type=tcp',
        'flow_garbage':  f'vless://{U}@{H}:443?security=tls&{T}&flow=xtls-rprx-direct',
        'flow_case':     f'vless://{U}@{H}:443?security=reality&sni=www.microsoft.com&fp=chrome&pbk={PBK}&type=tcp&flow=XTLS-RPRX-Vision',
        'vision_ws':     f'vless://{U}@{H}:443?security=tls&sni={H}&fp=chrome&alpn=h2&type=ws&host={H}&path=%2F&flow=xtls-rprx-vision',
        'reality_ws':    f'vless://{U}@{H}:443?security=reality&sni=www.microsoft.com&fp=chrome&pbk={PBK}&type=ws&host={H}&path=%2F',
        'trojan_kcp':    f'trojan://Xk29fLq81pZ@{H}:443?sni={H}&type=kcp',
        'vmess_std_none': f'vmess://{U}@{H}:443?encryption=auto&security=none&type=ws&host={H}&path=%2F&sni={H}',
        'vmess_std_insecure': f'vmess://{U}@{H}:443?encryption=auto&security=tls&type=ws&host={H}&path=%2F&sni={H}&allowInsecure=1',
        'vmess_std_zero': f'vmess://{U}@{H}:443?encryption=zero&security=tls&type=ws&host={H}&path=%2F&sni={H}',
        'vmess_ip_no_sni': vm(add='1.2.3.4', host='', net='tcp', sni=''),
    }

    # В v6.0 публиковалась P(raw), а проверялась P(P(raw)). В v6.1 preprocess доводится до
    # неподвижной точки: такие ссылки либо отбраковываются, либо публикуются уже исправленными.
    ESCAPES = {
        'zwsp_escape':   f'vless://{uid(6)}@{H}:443?secur\\u200bity=tls&{T}',
        'amp_escape':    f'vless://{uid(7)}@{H}:443?sni={H}\\u0026amp;security=tls&fp=chrome&alpn=h2',
        'bslash_escape': f'vless://{uid(8)}@{H}:443?sni={H}\\u005cu0026security=tls&fp=chrome&alpn=h2',
    }

    PROTO_FLAG = {'vless': 'allowInsecure', 'trojan': 'allowInsecure', 'hysteria2': 'insecure',
                  'tuic': 'allow_insecure'}
    if f.VMESS_JSON_MODE == 'std':
        PROTO_FLAG['vmess'] = 'allowInsecure'            # JSON-форма публикуется std-ссылкой

    def test_good_pass_with_verify_flag():
        for name, raw in GOOD.items():
            reason, pub = prep(raw)
            assert reason == '', f'{name}: {reason}'
            proto = pub.split('://')[0]
            if proto in PROTO_FLAG:
                qs = urllib.parse.parse_qs(urllib.parse.urlsplit(pub).query, keep_blank_values=True)
                assert qs.get(PROTO_FLAG[proto]) == ['0'], f'{name}: нет {PROTO_FLAG[proto]}=0: {pub[:120]}'

    def test_client_view_of_published_links():
        """Так ссылку читает клиент (Go url.ParseQuery / parse_qs): ровно один security=tls|reality."""
        for name, raw in GOOD.items():
            pub = prep(raw)[1]
            if pub.startswith('vless://') or (pub.startswith('vmess://') and '@' in pub.partition('?')[0]):
                qs = urllib.parse.parse_qs(urllib.parse.urlsplit(pub).query, keep_blank_values=True)
                assert qs.get('security') in (['tls'], ['reality']), name
                assert qs.get('sni') or qs.get('security') == ['reality'], name

    def test_escapes_rejected_or_published_safely():
        for name, raw in ESCAPES.items():
            reason, pub = prep(raw)
            if reason:
                continue
            assert f.preprocess(pub) == pub, name
            qs = urllib.parse.parse_qs(urllib.parse.urlsplit(pub).query, keep_blank_values=True)
            assert qs.get('security') == ['tls'] and qs.get('allowInsecure') == ['0'], f'{name}: {pub}'
            assert all(k == k.strip().lower() or k == 'allowInsecure' for k in qs), f'{name}: {list(qs)}'

    def test_bypasses_rejected():
        leaked = [name for name, raw in BYPASSES.items() if passes(raw)]
        assert not leaked, f'проходят фильтр: {leaked}'

    def test_publish_is_idempotent():
        for name, raw in {**GOOD, **BYPASSES, **ESCAPES}.items():
            once = f.preprocess(raw)
            assert f.preprocess(once) == once, name
        for name, raw in GOOD.items():
            pub = prep(raw)[1]
            assert prep(pub) == ('', pub), f'{name}: повторная обработка меняет ссылку'

    def test_clash_output_is_verified_tls():
        for name, raw in GOOD.items():
            pub = prep(raw)[1]
            cp = f.uri_to_clash(pub)
            if 'type=xhttp' in pub:
                assert cp is None, name                  # Mihomo не умеет xhttp — в YAML не пишем
                continue
            assert cp, f'{name}: нет Clash-прокси'
            if cp['type'] != 'ss':
                assert cp.get('skip-cert-verify') is False, name
            if cp['type'] in ('vless', 'vmess'):
                assert cp.get('tls') is True, name
        tr = f.uri_to_clash(prep(GOOD['trojan_ws'])[1])
        assert tr['password'] == TPW, tr['password']
        v6 = f.uri_to_clash(prep(GOOD['vless_ipv6'])[1])
        assert (v6['server'], v6['port']) == ('2a01:4f8:c17:1::1', 443), v6

    def test_clash_proxy_is_safe_guard():
        base = {'name': 'x', 'type': 'vless', 'server': H, 'port': 443, 'uuid': U, 'tls': True,
                'skip-cert-verify': False}
        assert f._clash_proxy_is_safe(base)
        for bad in ({'skip-cert-verify': True}, {'tls': False}, {'fingerprint': 'aa'},
                    {'ca-str': 'x'}, {'reality-opts': {}}):
            assert not f._clash_proxy_is_safe({**base, **bad}), bad

    def test_clash_yaml_valid_unique_reserved():
        names = ['DIRECT', 'direct', 'PROXY', 'emoji 🇩🇪', 'q"uo\\te: #x & *a !b', 'bad\uffffchar', 'same', 'same']
        links = []
        for i, nm in enumerate(names):
            h = f'n{i}.mydomain.de'
            links.append(prep(f'vless://{U}@{h}:443?security=tls&sni={h}&fp=chrome&alpn=h2&type=tcp#'
                              + urllib.parse.quote(nm, safe=''))[1])
        links += [prep(r)[1] for r in GOOD.values()]
        n = f.convert_to_clash_and_save(links, 'T_NAMES')
        data = yaml.safe_load(open(os.path.join(f.CLASH_DIR, 'T_NAMES.yaml'), encoding='utf-8'))
        got = [p['name'] for p in data['proxies']]
        keys = {f.analyze_config(l)[1][0] for l in links if f.uri_to_clash(l)}
        assert n == len(got) == len(keys), (n, len(got), len(keys))     # дедупликация по ключу узла
        assert len({g.lower() for g in got}) == len(got), got
        assert not ({g.lower() for g in got} & f._RESERVED_CLASH_NAMES), got
        assert data['proxy-groups'][0]['proxies'] == got
        for p in data['proxies']:
            if p['type'] != 'ss':
                assert p['skip-cert-verify'] is False, p['name']
        assert f.convert_to_clash_and_save([], 'T_NAMES') == 0
        assert not os.path.exists(os.path.join(f.CLASH_DIR, 'T_NAMES.yaml'))

    def test_clash_input_converts_and_keeps_insecure():
        y = f"""proxies:
      - {{name: ok-vless, type: vless, server: {H}, port: 443, uuid: {U}, tls: true, servername: {H},
          client-fingerprint: chrome, alpn: [h2], network: ws, ws-opts: {{path: /ws, headers: {{Host: {H}}}}}}}
      - {{name: ok-trojan, type: trojan, server: {H}, port: 443, password: "a:b@c", sni: {H}}}
      - {{name: ok-hy2, type: hysteria2, server: {H}, port: 443, password: pw, sni: {H}, obfs: salamander, obfs-password: x}}
      - {{name: ok-ss, type: ss, server: {H}, port: 8388, cipher: aes-256-gcm, password: "p:w@"}}
      - {{name: ok-vmess, type: vmess, server: {H}, port: 443, uuid: {U}, alterId: 0, cipher: auto, tls: true,
          servername: {H}, network: ws, ws-opts: {{path: /v, headers: {{Host: {H}}}}}}}
      - {{name: bad1, type: trojan, server: {H}, port: 443, password: x, sni: {H}, skip-cert-verify: true}}
      - {{name: bad2, type: trojan, server: {H}, port: 443, password: x, sni: {H}, skip-cert-verify: ""}}
      - {{name: bad3, type: trojan, server: {H}, port: 443, password: x, sni: {H}, skip-cert-verify: [1]}}
      - {{name: bad4, type: trojan, server: {H}, port: 443, password: x, sni: {H}, ca-str: "-----BEGIN"}}
      - {{name: bad5, type: vless, server: {H}, port: 443, uuid: {U}, tls: false, servername: {H}, alpn: [h2]}}
      - {{name: bad6, type: vmess, server: {H}, port: 443, uuid: {U}, alterId: 0, cipher: auto, tls: true,
          servername: {H}, network: ws, ws-opts: {{headers: {{Host: {H}}}}}, skip-cert-verify: true}}
      - {{name: bad7, type: hysteria2, server: {H}, port: 443, password: pw, sni: {H}, skip-cert-verify: yes}}
    """
        uris = f.clash_to_uris(y)
        res = {urllib.parse.unquote(u.partition('#')[2]) or json.loads(base64.b64decode(u[8:]))['ps']: passes(u)
               for u in uris}
        for k, ok in res.items():
            expect = k.startswith('ok-') and (f.ALLOW_SS or k != 'ok-ss') \
                and (f.VMESS_JSON_MODE != 'reject' or k != 'ok-vmess')
            assert ok == expect, (k, ok)
        assert sum(res.values()) == 5 - (not f.ALLOW_SS) - (f.VMESS_JSON_MODE == 'reject'), res

    def test_urlsafe_base64_subscription():
        random.seed(1)
        for i in range(300):
            pw = ''.join(random.choice(string.ascii_letters + '~?>') for _ in range(24))
            plain = f'trojan://{pw}@{H}:443?sni={H}#n{i}\n' * 3
            enc = base64.urlsafe_b64encode(plain.encode()).decode().rstrip('=')
            assert f._try_b64_decode(enc) == plain, enc[:40]

    def test_yaml_alias_bomb_and_deep_nesting():
        y = 'a0: &a0 [x,x,x,x,x,x,x,x,x]\n' + ''.join(
            f"a{i}: &a{i} [{','.join(['*a%d' % (i - 1)] * 9)}]\n" for i in range(1, 8))
        y += f'proxies:\n  - {{name: *a7, type: vless, server: {H}, port: 443, uuid: {U}, tls: true, alpn: *a7}}\n'
        t = time.time()
        assert all(len(u) < 8192 for u in f.clash_to_uris(y))
        assert time.time() - t < 5
        assert f.clash_to_uris('proxies: ' + '[' * 100000 + ']' * 100000) == []   # раньше — SIGSEGV в C-парсере

    def test_https_only_fetch():
        for url in ('http://example.com/sub', 'file:///etc/passwd', 'ftp://x/y'):
            try:
                f._http_get(url)
                assert False, url
            except ValueError:
                pass
        h = f._HttpsOnlyRedirect()
        req = urllib.request.Request('https://example.com/a')
        try:
            h.redirect_request(req, None, 302, 'Found', {}, 'http://evil.example/sub')
            assert False, 'редирект на http разрешён'
        except urllib.error.HTTPError:
            pass
        assert h.redirect_request(req, None, 302, 'Found', {}, 'https://ok.example/sub') is not None

    def test_fetch_total_deadline():
        old_inner, old_dl = f._http_get_inner, f.FETCH_DEADLINE
        f._http_get_inner, f.FETCH_DEADLINE = (lambda url: time.sleep(30)), 0.3
        t = time.time()
        try:
            f._http_get('https://slow.example/')
            assert False
        except TimeoutError:
            pass
        finally:
            f._http_get_inner, f.FETCH_DEADLINE = old_inner, old_dl
        assert time.time() - t < 5

    def _down(url):
        raise OSError('source down')

    def test_stale_fallback_refilters_previous_file():
        old = f._http_get
        f._http_get = _down
        try:
            src = {'name': 'T_STALE', 'url': 'https://down.example/sub'}
            bad = BYPASSES['insecure_1']
            prev = GOOD['vless_tls_ws'] + '\n' + bad + '\n'
            with open(os.path.join(f.OUTPUT_DIR, 'T_STALE.txt'), 'w', encoding='utf-8') as fh:
                fh.write(base64.b64encode(prev.encode()).decode())
            health = {src['url']: {'failures': 0, 'last_ok': f._now_utc()}}
            cfgs, _, st, was_b64 = f.load_and_filter(src, health)
            assert st['stale'] and not st['fetched'] and was_b64
            assert cfgs == {prep(GOOD['vless_tls_ws'])[1]}, cfgs
            health = {src['url']: {'failures': 0, 'last_ok': '2000-01-01 00:00:00 UTC'}}
            cfgs, _, st, _ = f.load_and_filter(src, health)
            assert not cfgs and not st['stale']
        finally:
            f._http_get = old

    def test_main_end_to_end():
        plain = '\n'.join(list(GOOD.values()) + list(BYPASSES.values())) + '\n'
        clash = (f'proxies:\n  - {{name: c1, type: trojan, server: {H}, port: 443, password: pw1, sni: {H}}}\n'
                 f'  - {{name: c2, type: trojan, server: {H}, port: 444, password: pw2, sni: {H}, skip-cert-verify: true}}\n')
        content = {'https://s.example/plain': plain,
                   'https://s.example/b64': base64.b64encode(plain.encode()).decode(),
                   'https://s.example/clash': clash}
        old_src, old_get, old_pub = f.SOURCES_CONFIG, f._http_get, f.PUBLISH_REJECTED
        f.SOURCES_CONFIG = [{'name': 'E_PLAIN', 'url': 'https://s.example/plain'},
                            {'name': 'E_B64', 'url': 'https://s.example/b64'},
                            {'name': 'E_CLASH', 'url': 'https://s.example/clash'}]
        f._http_get = lambda url: content[url].encode()
        f.PUBLISH_REJECTED = False
        open(os.path.join(f.REJECT_DIR, 'rejected.txt'), 'w').write('old')
        try:
            assert f.main() == 0
            out = lambda n: open(os.path.join(f.OUTPUT_DIR, n), encoding='utf-8').read()
            good_pub = {prep(r)[1] for r in GOOD.values()}
            assert set(out('E_PLAIN.txt').split()) == good_pub
            assert set(base64.b64decode(out('E_B64.txt')).decode().split()) == good_pub
            assert out('E_CLASH.txt').count('://') == 1 and 'pw1@' in out('E_CLASH.txt')
            assert not os.path.exists(os.path.join(f.REJECT_DIR, 'rejected.txt'))
            allp = yaml.safe_load(open(os.path.join(f.CLASH_DIR, 'ALL.yaml'), encoding='utf-8'))['proxies']
            assert allp and all(p['skip-cert-verify'] is False for p in allp if p['type'] != 'ss')
            f._http_get = _down
            f.SOURCES_CONFIG = [{'name': 'E_DOWN', 'url': 'https://down2.example/x'}]
            assert f.main() == 1                         # ничего не скачалось -> код 1
        finally:
            f.SOURCES_CONFIG, f._http_get, f.PUBLISH_REJECTED = old_src, old_get, old_pub

    def qs_of(link):
        return urllib.parse.parse_qs(urllib.parse.urlsplit(link).query, keep_blank_values=True)

    CLASH_BAD = (f'proxies:\n'
                 f'  - {{name: b1, type: trojan, server: {H}, port: 443, password: x, sni: {H}, skip-cert-verify: true}}\n'
                 f'  - {{name: b2, type: trojan, server: {H}, port: 443, password: x, sni: {H}, ca-str: "-----BEGIN"}}\n'
                 f'  - {{name: b3, type: vless, server: {H}, port: 443, uuid: {U}, tls: false, servername: {H}, alpn: [h2]}}\n'
                 f'  - {{name: b4, type: hysteria2, server: {H}, port: 443, password: pw, sni: {H}, skip-cert-verify: yes}}\n')

    def security_problems() -> List[str]:
        """Проверяет только безопасность, а не политику: если более строгие правила
        отбросят эталонную хорошую ссылку, это не ошибка."""
        problems = [f'обход проходит фильтр: {n}' for n, raw in BYPASSES.items() if passes(raw)]
        for n, raw in ESCAPES.items():
            reason, pub = prep(raw)
            if reason:
                continue
            qs = qs_of(pub)
            if (f.preprocess(pub) != pub or qs.get('security') != ['tls']
                    or (f.FORCE_VERIFY_FLAG and qs.get('allowInsecure') != ['0'])
                    or not all(k == k.strip().lower() or k == 'allowInsecure' for k in qs)):
                problems.append(f'escape-ссылка публикуется небезопасно: {n}')
        for n, raw in GOOD.items():
            reason, pub = prep(raw)
            if reason:
                continue
            proto, qs = pub.split('://')[0], qs_of(pub)
            flag = PROTO_FLAG.get(proto)
            if f.FORCE_VERIFY_FLAG and flag and qs.get(flag) != ['0']:
                problems.append(f'нет {flag}=0: {n}')
            if proto == 'vless' and qs.get('security') not in (['tls'], ['reality']):
                problems.append(f'vless без tls/reality: {n}')
            cp = f.uri_to_clash(pub)
            if cp is not None and not f._clash_proxy_is_safe(cp):
                problems.append(f'Clash-прокси без проверки сертификата: {n}')
        if f.HAS_YAML:
            problems += [f'Clash: небезопасный прокси проходит фильтр: {u[:60]}'
                         for u in f.clash_to_uris(CLASH_BAD) if passes(u)]
        if not f.ALLOW_SS:
            problems += [f'shadowsocks проходит при ALLOW_SS=False: {n}' for n, raw in SS_LINKS.items() if passes(raw)]
        if f.VMESS_JSON_MODE == 'reject' and passes(VMESS_JSON_LINK):
            problems.append('vmess JSON проходит при VMESS_JSON_MODE=reject')
        return problems

    if not full:
        return security_problems()

    def test_v62_rules():
        # vmess JSON -> std-ссылка с теми же полями и allowInsecure=0; мусорный хвост и
        # двойной base64 публикуются только в каноническом виде (неподвижная точка)
        if f.VMESS_JSON_MODE == 'std':
            pub = prep(VMESS_JSON_LINK)[1]
            qs = qs_of(pub)
            assert pub.startswith(f'vmess://{U}@{H}:443?'), pub
            assert (qs['security'], qs['type'], qs['host'], qs['path'], qs['sni'], qs['encryption']) == \
                   (['tls'], ['ws'], [H], ['/vm'], [H], ['auto']), qs
            assert qs['allowInsecure'] == ['0'] and urllib.parse.unquote(pub.partition('#')[2]) == 'vm'
        for raw in (vm_tail(VMESS_JSON_LINK), vm_raw(VMESS_JSON_LINK[8:])):
            reason, pub = prep(raw)
            if f.VMESS_JSON_MODE == 'reject':
                assert reason, pub[:80]
                continue
            assert reason == '' and pub != raw and prep(pub) == ('', pub), (reason, pub[:80])
        # pbk публикуется без паддинга; reality + udp443 проходит и в Clash даёт vision
        pub = prep(f'vless://{uid(16)}@n16.mydomain.de:443?security=reality&sni=www.microsoft.com&fp=chrome'
                   f'&pbk={PBK}%3D&type=tcp&flow=xtls-rprx-vision-udp443')[1]
        assert qs_of(pub)['pbk'] == [PBK] and prep(pub) == ('', pub), pub
        assert f.uri_to_clash(pub)['flow'] == 'xtls-rprx-vision'
        # trojan: легаси ws=1 больше не делает ws — клиент его не понимает; type читается буквально
        pub = prep(f'trojan://Xk29fLq81pZ@{H}:443?sni={H}&ws=1&wspath=%2Fx')[1]
        assert f.uri_to_clash(pub).get('network') is None
        # лимиты пула действуют и на ALL: 3 + 3 узла с одним UUID из двух «источников»
        same = [f'vless://{U}@a{i}.mydomain.de:443?security=tls&sni=a{i}.mydomain.de&fp=chrome&alpn=h2&type=tcp#a{i}'
                for i in range(6)]
        merged, why = f.merge_all([prep(l)[1] for l in same])
        assert merged == [] and sum(why.values()) == 6, (merged, why)
        merged, why = f.merge_all([prep(l)[1] for l in same[:3]])
        assert len(merged) == 3 and not why
        # Clash: три транспорта на одном host:port — три разных узла (как и в txt)
        tr = [prep(f'vless://{uid(17)}@n17.mydomain.de:443?security=tls&sni=n17.mydomain.de&fp=chrome&alpn=h2'
                   f'&type={t}{x}#{t}')[1]
              for t, x in (('ws', '&host=n17.mydomain.de&path=%2Fa'), ('grpc', '&serviceName=g'), ('tcp', ''))]
        assert f.convert_to_clash_and_save(tr, 'T_TRANSPORTS') == 3
        # shadowsocks: политика ALLOW_SS
        for n, raw in SS_LINKS.items():
            assert passes(raw) == f.ALLOW_SS, n

    def test_security_guard_clean():
        assert security_problems() == [], security_problems()

    def test_guard_ignores_stricter_policy():
        old = f.prepare_config
        f.prepare_config = lambda line: ('политика', None, line)     # отбросить всё — безопасно
        try:
            assert security_problems() == []
        finally:
            f.prepare_config = old

    def test_guard_blocks_broken_filter():
        old = f.prepare_config
        f.prepare_config = lambda line: ('', None, line)             # «сломанный» фильтр
        marker = os.path.join(f.OUTPUT_DIR, 'ALL.txt')
        with open(marker, 'w', encoding='utf-8') as fh:
            fh.write('old')
        try:
            assert security_problems(), 'самопроверка не заметила сломанный фильтр'
            assert f.main() == 2
            with open(marker, encoding='utf-8') as fh:
                assert fh.read() == 'old', 'подписка перезаписана сломанным фильтром'
        finally:
            f.prepare_config = old

    tests = [test_good_pass_with_verify_flag, test_client_view_of_published_links,
             test_escapes_rejected_or_published_safely, test_bypasses_rejected,
             test_publish_is_idempotent, test_clash_output_is_verified_tls,
             test_clash_proxy_is_safe_guard, test_clash_yaml_valid_unique_reserved,
             test_clash_input_converts_and_keeps_insecure,
             test_urlsafe_base64_subscription, test_yaml_alias_bomb_and_deep_nesting,
             test_https_only_fetch, test_fetch_total_deadline,
             test_stale_fallback_refilters_previous_file, test_main_end_to_end,
             test_security_guard_clean, test_guard_ignores_stricter_policy,
             test_guard_blocks_broken_filter, test_v62_rules]
    paths = ('OUTPUT_DIR', 'HEALTH_FILE', 'REJECT_DIR', 'CLASH_DIR', 'QR_DIR')
    saved, cwd = {k: getattr(f, k) for k in paths}, os.getcwd()
    tmp = tempfile.mkdtemp(prefix='filter-selftest-')
    failures: List[str] = []
    try:                                  # настоящие подписки тесты не трогают
        f.OUTPUT_DIR = os.path.join(tmp, 'githubmirror')
        f.HEALTH_FILE = os.path.join(f.OUTPUT_DIR, 'url_health.json')
        f.REJECT_DIR = os.path.join(f.OUTPUT_DIR, 'rejected')
        f.CLASH_DIR = os.path.join(f.OUTPUT_DIR, 'Clash')
        f.QR_DIR = os.path.join(tmp, 'QR-CODE')
        for d in (f.REJECT_DIR, f.CLASH_DIR, f.QR_DIR):
            os.makedirs(d, exist_ok=True)
        os.chdir(tmp)
        for fn in tests:
            try:
                with contextlib.redirect_stdout(io.StringIO()):
                    fn()
                print('PASS', fn.__name__)
            except Exception as e:                    # noqa: BLE001
                kind = 'FAIL' if isinstance(e, AssertionError) else 'ERROR'
                msg = f'{kind} {fn.__name__} — {type(e).__name__}: {e}'[:300]
                failures.append(msg)
                print(msg)
    finally:
        os.chdir(cwd)
        for k, v in saved.items():
            setattr(f, k, v)
        shutil.rmtree(tmp, ignore_errors=True)
    return failures

if __name__ == "__main__":
    if '--selftest' in sys.argv[1:]:
        _failed = _selftest(full=True)
        print('\n✅ Все тесты пройдены' if not _failed else f'\n❌ Не пройдено тестов: {len(_failed)}')
        sys.exit(1 if _failed else 0)
    sys.exit(main())
