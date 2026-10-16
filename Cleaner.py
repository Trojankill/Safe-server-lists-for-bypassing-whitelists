#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Cleaner.py — чистка и проверка VPN-конфигов.

Что делает скрипт
-----------------
Берёт строки из входного файла (по умолчанию temp/configs.txt), каждую
ссылку разбирает, проверяет и пересобирает в единый канонический вид.
Результат — выходной файл (temp/clean.txt): только уникальные рабочие
конфиги, которые можно заливать в VPN-клиенты или в ядро
sing-box-extended (https://github.com/shtorm-7/sing-box-extended).

Что происходит с конфигами по ходу чистки:
  - понимаются протоколы vless, vmess, ss, trojan, hysteria2 (hy2), tuic;
  - битые ссылки чинятся до разбора: двойное HTML-экранирование &amp;,
    процентно-закодированный экран \u0026, форма trojan ws=1&wspath=...,
    мусорные хвосты base64;
  - отсекается заведомый мусор: локальные/зарезервированные IP, IP
    публичных DNS, порты ниже 53, мёртвые шифры ss, транспорт quic,
    плагины, которые клиенты теряют при импорте;
  - по настройкам бракуются allowInsecure=1, конфиги без TLS, IPv6-адреса;
    имя после «#» можно сохранить, а из reality удаляются spx/sid — на
    связь они не влияют, зато плодят мнимые дубликаты;
  - дубликаты схлопываются по отпечатку узла; что считать дублем,
    задаётся в «Настройки → Правила чистки» (от «только адрес» до
    «все параметры»).

Режимы работы
-------------
  - «Конвейерная чистка» (пункт 1 меню): скрипт следит за входным файлом,
    новые строки чистит по мере дописывания, уникальные конфиги сразу
    дописываются в выход. Каждый обработанный кусок строк — это цикл;
    после цикла держится пауза, число циклов можно ограничить. CTRL+C
    останавливает конвейер и возвращает в меню;
  - «Одиночный цикл» (пункт 2 меню): одна полная чистка входа в выход;
  - без меню: python Cleaner.py --stream (конвейер, --from-eof — начать
    с конца файла) и python Cleaner.py --once (один цикл).

Файлы и каталоги
----------------
  temp/configs.txt               вход (общий для всех скриптов проекта)
  temp/clean.txt                 выход
  temp/Cleaner/settings.json     настройки из меню
  temp/Cleaner/cleaner.log       журнал разработчика (выключен по умолчанию)

Настройки
---------
Живут в temp/Cleaner/settings.json, правятся в меню «Настройки».
Пути входа и выхода — тоже настройки (группа «Файлы»): можно указать
относительный путь (считается от папки скрипта) или абсолютный.
Файла нет, он битый или остался от старой версии — берутся умолчания
из схемы DEFAULT_SETTINGS_SCHEMA.

Самопроверка
------------
    python Cleaner.py --selftest
Прогоняет контрольные ссылки через парсеры, фильтры безопасности,
фильтр совместимости и дедупликацию на всех уровнях строгости. Код
возврата 1 — есть проваленные проверки.

Память и скорость
-----------------
Строки уходят в пул воркеров задачами не больше 8 000 строк (крупный
размер батча из настроек режется до этого потолка — память от этого не
прыгает, на скорость это не влияет). Счётчики статистики ограничены,
результаты хранятся компактно: даже на нескольких сотнях тысяч конфигов
процесс не выходит за ~400 МБ. Чтение входа и запись выхода — обычные
последовательные проходы по файлу, HDD это любит.

Разделы кода
------------
  1. Пути и файлы
  2. Настройки: схема и значения по умолчанию
  3. Загрузка, сохранение и применение настроек
  4. Консоль: цвета, логотип, живой прогресс
  5. Справочники протоколов и регулярки
  6. Базовые функции разбора ссылок
  7. Парсеры протоколов
  8. Каноническая сборка ссылок (build_uri)
  9. Отпечатки узлов и дедупликация
  10. Фильтры чистки: безопасность и совместимость
  11. Воркер и пул процессов
  12. Цикл чистки
  13. Итоговая панель
  14. Режимы запуска: одиночный цикл и конвейер
  15. Меню
  16. Самопроверка (--selftest)
  17. Точка входа
"""
import base64, hashlib, ipaddress, json, os, random, re, shutil, signal, sys, time
import multiprocessing as mp
from collections import Counter, deque
from urllib.parse import unquote, quote
import uuid as uuidlib

# =========================================================================
# 1. ПУТИ И ФАЙЛЫ
# =========================================================================
# Все пути якорятся к папке скрипта, а не к текущему рабочему каталогу:
# запуск из ярлыка или планировщика не порождает второй temp/ в другом
# месте. Вход и выход — настройки (группа «Файлы»), здесь их стартовые
# значения; apply_settings() пересчитывает их после загрузки settings.json.
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMP = os.path.join(BASE_DIR, "temp")
INPUT_FILE = os.path.join(TEMP, "configs.txt")      # вход (по умолчанию)
CLEAN_FILE = os.path.join(TEMP, "clean.txt")        # выход (по умолчанию)
SERVICE_DIR = os.path.join(TEMP, "Cleaner")         # служебные файлы чистки
SETTINGS_FILE = os.path.join(SERVICE_DIR, "settings.json")
DEVLOG_FILE = os.path.join(SERVICE_DIR, "cleaner.log")   # журнал разработчика
LEGACY_SERVICE_DIR = os.path.join(TEMP, "Clean")    # имя папки до переименования


def migrate_legacy_dirs() -> None:
    """Переносит служебные файлы из temp/Clean в temp/Cleaner.

    Стандартизация temp-папок: у каждого скрипта — папка с его именем.
    Старая папка переезжает целиком один раз; если новая уже существует,
    старая не трогается (вдруг туда кто-то пишет руками).
    """
    if not os.path.isdir(LEGACY_SERVICE_DIR) or os.path.isdir(SERVICE_DIR):
        return
    try:
        shutil.move(LEGACY_SERVICE_DIR, SERVICE_DIR)
    except OSError:
        pass  # переезд не удался — работаем на умолчаниях, это не смертельно

# =========================================================================
# 2. НАСТРОЙКИ: СХЕМА И ЗНАЧЕНИЯ ПО УМОЛЧАНИЮ
# =========================================================================
# Схема настроек: группа -> список полей. Поле = (ключ в settings.json,
# тип, подпись для меню, значение по умолчанию). Порядок групп здесь —
# порядок пунктов в меню настроек. Новая настройка добавляется одной
# строкой в нужную группу: загрузка, сохранение, меню и apply_settings
# подхватят её сами.
DEFAULT_SETTINGS_SCHEMA = {
    "Производительность и работа": [
        ("workers",              "int",   "Воркеров чистки",                                         4),
        ("chunk_size",           "int",   "Строк в одном воркере",                                   100000),
        ("auto_start",           "bool",  "Сразу начинать чистку при запуске (минуя меню)",          False),
        ("pause_after_cycle",    "float", "Пауза после завершённого цикла чистки (сек)",             5.0),
        ("max_cycles",           "int",   "Лимит циклов чистки (0 - без лимита)",                    0),
        ("stream_poll_interval", "float", "Интервал опроса configs.txt в конвейере (сек)",           3.0),
    ],
    "Правила чистки": [
        ("fp_value",             "str",   "Значение FingerPrint (fp) для всех конфигов",             "random"),
        ("add_fp_for_reality",   "bool",  "Добавлять FingerPrint (fp) для reality, если не указан",  True),
        ("drop_spx",             "bool",  "Удалять spiderX (spx) reality",                           True),
        ("drop_sid",             "bool",  "Удалять shortId (sid) reality",                           True),
        ("reject_insecure",      "bool",  "Удалять конфиги с allowInsecure=1 (Небезопасные)",        True),
        ("reject_no_tls",        "bool",  "Удалять конфиги без TLS (security=none - без шифрования)", True),
        ("reject_mkcp",          "bool",  "Отбраковывать транспорт mKCP/kcp (неактуален)",           False),
        ("reject_private",       "bool",  "Отбраковывать локальные/зарезервированные IP",            True),
        ("reject_dns",           "bool",  "Отбраковывать IP публичных DNS (1.1.1.1, 8.8.8.8…)",      True),
        ("reject_ipv6",          "bool",  "Исключать конфиги с iPv6",                                False),
        ("checker_filter",       "bool",  "Отсекать конфиги, которые Sing-box Extended не поддерживает", True),
        ("clean_name",           "bool",  "Чистить название после # (если есть)",                    True),
        ("dup_policy",           "choice", "Политика дубликатов",                                    "best"),
        ("dup_scope",            "choice", "Строгость дедупликации (что считать дублем)",             "nekobox"),
    ],
    "Консоль": [
        ("color_level",          "int",   "Уровень логов (0 - тихий, 1 - обычный, 2 - подробный)",   1),
        ("use_colors",           "bool",  "Цветной вывод (ANSI)",                                    True),
        ("accent_color",         "choice", "Акцентный цвет (логотип, заголовки, меню)",              "blue"),
        ("logo_pause",           "float", "Пауза после первого показа логотипа, сек",                1.0),
        ("clear_screen_in_menu", "bool",  "Очищать экран при переходах между меню",                  True),
        ("bar_width",            "int",   "Ширина прогресс-бара",                                    20),
        ("show_progress_bar",    "bool",  "Прогресс-бар во время чистки",                            True),
        ("show_summary",         "bool",  "Итоговая статистика после чистки",                        True),
        ("show_proto_stats",     "bool",  "Блок протоколов/транспортов в статистике",                True),
        ("show_top_reasons",     "bool",  "Топ причин отбраковки в статистике",                      True),
        ("show_top_ports",       "bool",  "Топ портов в статистике",                                 True),
    ],
    "Файлы": [
        ("input_file",           "str",   "Вход конфигов для чистки",                                "temp/configs.txt"),
        ("output_file",          "str",   "Выход конфигов после чистки",                             "temp/clean.txt"),
        ("output_sort",          "choice", "Сортировка clean.txt",                                   "line"),
        ("backup_clean",         "bool",  "Бэкап прошлой чистки (temp/Cleaner)",                     False),
    ],
    "Логи и диагностика (для разработчиков)": [
        ("log_batches",          "bool",  "Строка в лог по каждому батчу",                           False),
        ("log_rejects",          "bool",  "Все отбраковки в лог-файл (temp/Cleaner/cleaner.log)",    False),
        ("log_fixes",            "bool",  "Пометки правок конфигов в лог-файл",                      False),
        ("log_stream",           "bool",  "События конвейера в лог-файл (опросы, чтения, дописи)",   False),
    ],
}

# Диапазоны для числовых настроек: ключ -> (мин, макс). Ввод в меню
# и значения из settings.json зажимаются в эти пределы.
NUM_RANGE = {
    "workers": (1, 64), "chunk_size": (100, 1_000_000),
    "pause_after_cycle": (0, 3600), "max_cycles": (0, 1_000_000),
    "stream_poll_interval": (0.5, 60),
    "color_level": (0, 2), "logo_pause": (0, 10), "bar_width": (10, 60),
}

# Варианты для настроек типа 'choice': ключ -> кортеж вариантов.
CHOICES = {
    "dup_policy": ("best", "first"),
    "dup_scope": ("exclave", "nekobox", "incy", "full"),
    "accent_color": ("cyan", "blue", "magenta", "green", "yellow", "red", "white"),
    "output_sort": ("line", "alpha"),
}

# Полные подписи вариантов — их видно при выборе значения в меню.
CHOICE_LABELS = {
    "dup_policy": {"best": "оставлять самый полный экземпляр",
                   "first": "оставлять первый найденный"},
    "dup_scope": {
        "exclave": "Сильный (рекомендуется): протокол и адрес:порт",
        "nekobox": "Оптимальный (рекомендуется): учитывание адрес:порт, "
                   "mode, grpc/xhttp и spx reality",
        "incy": "Стандартный (мягкий): учитывание SNI, sid reality "
                "и packetEncoding",
        "full": "Слабый: все параметры подключения (тип: full)"},
    "output_sort": {"line": "порядок входного файла", "alpha": "по алфавиту"},
}

# Короткие подписи уровней дедупликации — для списка настроек и итоговой
# панели. Полные описания длинные, их показываем только при выборе.
DUP_SCOPE_SHORT = {
    "exclave": "протокол и адрес:порт",
    "nekobox": "адрес:порт, mode, type и spx",
    "incy": "адрес:порт, mode, type, spx, SNI и sid",
    "full": "все параметры подключения",
}


def _flatten_schema():
    """Схема одним плоским списком (ключ, тип, подпись, умолчание)."""
    out = []
    for items in DEFAULT_SETTINGS_SCHEMA.values():
        out.extend(items)
    return out


def _default_settings():
    """Умолчания из схемы — словарём ключ -> значение."""
    return {key: default for key, _, _, default in _flatten_schema()}


# ---- Живые копии настроек для движка ----
# Парсеры и воркеры читают эти переменные напрямую. apply_settings()
# перезаписывает их значениями из settings.json, поэтому начальные
# значения здесь обязаны совпадать со схемой выше.
# drop_fp/drop_defaults и другие правила, которых нет в меню, — просто
# внутренние умолчания движка.
FP_VALUE = "random"           # fp, который пишется всем конфигам
ADD_FP_FOR_REALITY = True     # дописывать fp для reality, если его не было
DROP_SPX = True               # spx (spiderX) reality — маскировочный адрес
                              # паука, на связь не влияет, только мешает
                              # дедупликации — удаляем
DROP_SID = True               # sid (shortId) reality — анти-replay токен,
                              # в публичных подписках обычно случайный,
                              # из-за него дубликаты не схлопываются
DROP_FP = False               # False — fp нормализуется в FP_VALUE и
                              # остаётся в конфигах (этого ждёт меню);
                              # True — fp вырезается совсем
DROP_DEFAULTS = True          # не писать дефолтные encryption=none (vless)
                              # и type=tcp — клиенты подставят их сами;
                              # не-дефолтные значения сохраняются
CHUNK = 100_000               # «Строк в одном воркере» из настроек; в пул
                              # задача уходит кусками не больше TASK_CAP (см. раздел 11)
CAP_COUNTERS = 100_000        # потолок элементов в счётчиках статистики
REJECT_PRIVATE = True         # браковать локальные/зарезервированные IP
REJECT_DNS = True             # браковать IP публичных DNS-резолверов
REJECT_IPV6 = False           # браковать конфиги, чей адрес — IPv6 (меню: «Нет»)
REJECT_INSECURE = True        # удалять конфиги с allowInsecure=1
REJECT_NO_TLS = True          # удалять vless/vmess/trojan без TLS (security=none)
REJECT_MKCP = False           # mKCP/kcp по умолчанию проходит (меню: «Нет»)
DUP_POLICY = "best"           # best — остаётся самый полный экземпляр дубликата
DUP_SCOPE = "nekobox"         # уровень строгости: exclave/nekobox/incy/full
CHECKER_FILTER = True         # отсекать то, что не конвертирует чекер
OUTPUT_SORT = "line"          # line — как во входе, alpha — по алфавиту
BACKUP_CLEAN = False          # бэкап прошлой версии clean.txt в temp/Cleaner
CLEAN_NAME = True             # имя после '#' срезается — клиенты дадут своё

WORKERS = 4                   # воркеров в пуле процессов
PAUSE_AFTER_CYCLE = 5.0       # пауза (сек) после обработанного цикла конвейера
MAX_CYCLES = 0                # лимит циклов конвейера (0 — без лимита)
STREAM_POLL_INTERVAL = 3.0    # опрос входного файла в конвейере (сек)
AUTO_START = False            # запускать чистку сразу при старте, без меню
TOP_SHOW = 5                  # строк в каждом топе итоговой панели
TASK_CAP = 8_000              # потолок строк в одной задаче пула: большой
                              # chunk_size режется до него, чтобы память не
                              # прыгала и процесс не раздувался. На скорость
                              # не влияет: разбор строки дороже передачи.

# --- Консоль ---
BAR_WIDTH = 20                # ширина прогресс-бара |████░░░░|
SHOW_PROGRESS_BAR = True      # бар и сводка во время чистки
LOG_BATCHES = False           # строка в лог по каждому батчу
LOG_REJECTS = False           # все отбраковки в лог-файл
LOG_FIXES = False             # пометки правок в лог-файл
LOG_STREAM = False            # события конвейера в лог-файл
SHOW_SUMMARY = True           # итоговая панель после чистки
SHOW_PROTO_STATS = True       # блок «Протоколы/Транспорты/Security/Хосты»
SHOW_TOP_REASONS = True       # топ причин отбраковки
SHOW_TOP_PORTS = True         # топ портов
LOGO_PAUSE = 1.0              # пауза после первого показа логотипа (сек)
USE_COLORS = True             # общий выключатель ANSI-цветов
ACCENT_COLOR = "blue"         # акцент интерфейса (логотип, заголовки, значения)

# =========================================================================
# 3. ЗАГРУЗКА, СОХРАНЕНИЕ И ПРИМЕНЕНИЕ НАСТРОЕК
# =========================================================================
def load_settings():
    """Читает settings.json и накладывает поверх умолчаний.

    Нет файла, битый или от старой версии — работаем на умолчаниях.
    Старый файл узнаём по отсутствию ключа input_file: до появления
    путей в настройках его просто не было. Лишние ключи выбрасываются,
    недостающие добираются из схемы.
    """
    settings = _default_settings()
    if not os.path.isfile(SETTINGS_FILE):
        return settings
    try:
        with open(SETTINGS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return settings
    except (OSError, json.JSONDecodeError, ValueError) as e:
        con.error(f"Не удалось прочитать {SETTINGS_FILE}: {e}. "
                  f"Используются значения по умолчанию.")
        return settings
    if "input_file" not in data:
        return settings          # файл от старой версии — стартуем с умолчаний
    for key, ftype, _, _ in _flatten_schema():
        if key in data:
            try:
                settings[key] = _coerce_value(data[key], ftype, key)
            except (TypeError, ValueError):
                pass      # битое значение в файле — остаёмся на умолчании
    return settings


def save_settings(settings) -> bool:
    """Сохраняет настройки атомарно, через временный файл."""
    try:
        os.makedirs(SERVICE_DIR, exist_ok=True)
        tmp = SETTINGS_FILE + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(settings, f, ensure_ascii=False, indent=2)
        os.replace(tmp, SETTINGS_FILE)
        return True
    except OSError as e:
        con.error(f"Не удалось сохранить настройки: {e}")
        return False


def _coerce_value(value, ftype, key=None):
    """Приводит значение к типу поля из схемы.

    Не получилось — бросает TypeError/ValueError, вызывающий сам решает,
    что с этим делать. Для 'choice' вариант сверяется с CHOICES[key].
    """
    if ftype == "int":
        return int(value)
    if ftype == "float":
        return float(value)
    if ftype == "bool":
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return bool(value)
        if isinstance(value, str):
            v = value.strip().lower()
            if v in ("да", "yes", "true", "1", "y", "+"):
                return True
            if v in ("нет", "no", "false", "0", "n", "-"):
                return False
        raise ValueError(f"не логическое значение: {value!r}")
    if ftype == "choice":
        v = str(value).strip().lower()
        if v in CHOICES.get(key, ()):
            return v
        raise ValueError(f"недопустимый вариант: {value!r}")
    if ftype == "str":
        return str(value)
    raise ValueError(f"неизвестный тип поля: {ftype}")


def _clamp_num(key, value):
    """Зажимает число в диапазон настройки из NUM_RANGE (если он задан)."""
    lo, hi = NUM_RANGE.get(key, (None, None))
    if lo is not None:
        value = max(lo, value)
    if hi is not None:
        value = min(hi, value)
    return value


def _resolve_path(p, fallback):
    """Путь из настройки -> рабочий путь.

    Относительный путь считается от папки скрипта (как и раньше:
    temp/configs.txt рядом со скриптом), абсолютный берётся как есть.
    Пустое значение заменяется умолчанием, кавычки по краям снимаются —
    проводник Windows копирует путь вместе с ними.
    """
    p = str(p or "").strip().strip('"').strip("'").strip()
    if not p:
        p = fallback
    if not os.path.isabs(p):
        p = os.path.join(BASE_DIR, p)
    return os.path.normpath(p)


def apply_settings(s) -> None:
    """Раскладывает словарь настроек по глобальным переменным.

    Движок, парсеры и меню читают настройки из глобальных переменных,
    эта функция делает новые значения доступными без перезапуска.
    Значения вне допустимых вариантов и диапазонов заменяются умолчанием.
    """
    global WORKERS, CHUNK, PAUSE_AFTER_CYCLE, MAX_CYCLES, STREAM_POLL_INTERVAL
    global FP_VALUE, ADD_FP_FOR_REALITY, DROP_SPX, DROP_SID, DROP_FP, DROP_DEFAULTS
    global REJECT_INSECURE, REJECT_NO_TLS, REJECT_PRIVATE, REJECT_DNS, REJECT_MKCP
    global REJECT_IPV6, CLEAN_NAME
    global DUP_POLICY, DUP_SCOPE, CHECKER_FILTER, OUTPUT_SORT, BACKUP_CLEAN
    global COLOR_LEVEL, AUTO_START, TOP_SHOW, CAP_COUNTERS
    global BAR_WIDTH, SHOW_PROGRESS_BAR, LOG_BATCHES, LOG_REJECTS, LOG_FIXES, LOG_STREAM
    global SHOW_SUMMARY, SHOW_PROTO_STATS, SHOW_TOP_REASONS, SHOW_TOP_PORTS
    global LOGO_PAUSE, USE_COLORS, ACCENT_COLOR, _LOGO_ANIMATE
    global INPUT_FILE, CLEAN_FILE

    def _i(k, cur):
        return _clamp_num(k, int(s.get(k, cur)))

    def _f(k, cur):
        return _clamp_num(k, float(s.get(k, cur)))

    WORKERS = _i("workers", WORKERS)
    CHUNK = _i("chunk_size", CHUNK)
    PAUSE_AFTER_CYCLE = _f("pause_after_cycle", PAUSE_AFTER_CYCLE)
    MAX_CYCLES = _i("max_cycles", MAX_CYCLES)
    STREAM_POLL_INTERVAL = _f("stream_poll_interval", STREAM_POLL_INTERVAL)
    FP_VALUE = str(s.get("fp_value", FP_VALUE)).strip() or "random"
    ADD_FP_FOR_REALITY = bool(s.get("add_fp_for_reality", ADD_FP_FOR_REALITY))
    DROP_SPX = bool(s.get("drop_spx", DROP_SPX))
    DROP_SID = bool(s.get("drop_sid", DROP_SID))
    DROP_FP = bool(s.get("drop_fp", DROP_FP))
    DROP_DEFAULTS = bool(s.get("drop_defaults", DROP_DEFAULTS))
    REJECT_INSECURE = bool(s.get("reject_insecure", REJECT_INSECURE))
    REJECT_NO_TLS = bool(s.get("reject_no_tls", REJECT_NO_TLS))
    REJECT_MKCP = bool(s.get("reject_mkcp", REJECT_MKCP))
    REJECT_PRIVATE = bool(s.get("reject_private", REJECT_PRIVATE))
    REJECT_DNS = bool(s.get("reject_dns", REJECT_DNS))
    REJECT_IPV6 = bool(s.get("reject_ipv6", REJECT_IPV6))
    CLEAN_NAME = bool(s.get("clean_name", CLEAN_NAME))
    CHECKER_FILTER = bool(s.get("checker_filter", CHECKER_FILTER))
    DUP_POLICY = str(s.get("dup_policy", DUP_POLICY)).strip().lower()
    if DUP_POLICY not in CHOICES["dup_policy"]:
        DUP_POLICY = "best"
    DUP_SCOPE = str(s.get("dup_scope", DUP_SCOPE)).strip().lower()
    if DUP_SCOPE not in CHOICES["dup_scope"]:
        DUP_SCOPE = "nekobox"
    # пути входа/выхода — настройки, относительные считаем от папки скрипта
    INPUT_FILE = _resolve_path(s.get("input_file"), "temp/configs.txt")
    CLEAN_FILE = _resolve_path(s.get("output_file"), "temp/clean.txt")
    try:
        COLOR_LEVEL = _clamp_num("color_level", int(s.get("color_level", COLOR_LEVEL)))
    except (TypeError, ValueError):
        pass
    USE_COLORS = bool(s.get("use_colors", USE_COLORS))
    new_accent = str(s.get("accent_color", ACCENT_COLOR)).strip().lower()
    if new_accent not in CHOICES["accent_color"]:
        new_accent = "blue"
    if new_accent != ACCENT_COLOR:
        _LOGO_ANIMATE = True    # сменился акцент — логотип покажем с анимацией
    ACCENT_COLOR = new_accent
    LOGO_PAUSE = _f("logo_pause", LOGO_PAUSE)
    BAR_WIDTH = _i("bar_width", BAR_WIDTH)
    SHOW_PROGRESS_BAR = bool(s.get("show_progress_bar", SHOW_PROGRESS_BAR))
    LOG_BATCHES = bool(s.get("log_batches", LOG_BATCHES))
    LOG_REJECTS = bool(s.get("log_rejects", LOG_REJECTS))
    LOG_FIXES = bool(s.get("log_fixes", LOG_FIXES))
    LOG_STREAM = bool(s.get("log_stream", LOG_STREAM))
    SHOW_SUMMARY = bool(s.get("show_summary", SHOW_SUMMARY))
    SHOW_PROTO_STATS = bool(s.get("show_proto_stats", SHOW_PROTO_STATS))
    SHOW_TOP_REASONS = bool(s.get("show_top_reasons", SHOW_TOP_REASONS))
    SHOW_TOP_PORTS = bool(s.get("show_top_ports", SHOW_TOP_PORTS))
    OUTPUT_SORT = str(s.get("output_sort", OUTPUT_SORT)).strip().lower()
    if OUTPUT_SORT not in CHOICES["output_sort"]:
        OUTPUT_SORT = "line"
    BACKUP_CLEAN = bool(s.get("backup_clean", BACKUP_CLEAN))
    AUTO_START = bool(s.get("auto_start", AUTO_START))


# Текущие настройки. Заполняется в main().
SETTINGS = _default_settings()


# =========================================================================
# 4. КОНСОЛЬ: ЦВЕТА, ЛОГОТИП, ЖИВОЙ ПРОГРЕСС
# =========================================================================
# Единая точка вывода в stdout. Палитра — яркие ANSI-коды с акцентным
# цветом. Строка прогресса рисуется без перевода строки и перезатирает
# саму себя; любая обычная строка сначала стирает её, печатается, а потом
# прогресс мгновенно перерисовывается — вывод не мерцает и не
# перемешивается.
COLOR_CODES = {
    "cyan": "\033[96m", "green": "\033[92m", "yellow": "\033[93m",
    "red": "\033[91m", "blue": "\033[94m", "magenta": "\033[95m",
    "white": "\033[97m", "gray": "\033[90m",
}
_RESET = "\033[0m"
_BOLD = "\033[1m"
_CLEAR_LINE = "\r\033[2K"

# Уровень логов (настройка color_level):
#   0 — тихий: меню, итоговая панель и ошибки;
#   1 — обычный: плюс предупреждения и служебные сообщения;
#   2 — подробный: плюс серые отладочные строки.
COLOR_LEVEL = 1

ANSI_RE = re.compile(r"\033\[[0-9;]*m")


class Console:
    """Писатель в stdout с покраской и однострочным прогрессом."""

    def __init__(self):
        if os.name == "nt":
            os.system("")          # включает обработку ANSI в терминалах Windows
        self.tty = sys.stdout.isatty()
        self._progress_text = None

    @staticmethod
    def _width() -> int:
        """Ширина терминала; за пределами TTY — разумное умолчание."""
        try:
            return shutil.get_terminal_size((120, 30)).columns
        except Exception:
            return 120

    # ------------------------------------------------------------- покраска
    def paint(self, text, color=None, bold=False):
        """Покраска текста, если включены цвета и stdout — терминал."""
        if not USE_COLORS or not self.tty:
            return text
        prefix = (_BOLD if bold else "") + (COLOR_CODES.get(color, "") if color else "")
        return f"{prefix}{text}{_RESET}" if prefix else text

    def bar(self, done, total, width=None):
        """Прогресс-бар вида |████░░░░| (заполнение — blue, фон — gray)."""
        w = int(width or BAR_WIDTH)
        frac = 1.0 if total <= 0 else min(1.0, max(0.0, done / total))
        filled = int(round(frac * w))
        core = self.paint("█" * filled, "blue") + self.paint("░" * (w - filled), "gray")
        return self.paint("|", "gray") + core + self.paint("|", "gray")

    # ------------------------------------------------------------- прогресс
    def _write_progress(self) -> None:
        if self._progress_text is not None:
            sys.stdout.write(_CLEAR_LINE + self._progress_text + "\033[K")
            sys.stdout.flush()

    def progress(self, text) -> None:
        """Перерисовывает однострочный прогресс (текст уже покрашен)."""
        if COLOR_LEVEL < 1 or not self.tty:
            return
        self._progress_text = text
        self._write_progress()

    def clear(self) -> None:
        """Стирает строку прогресса."""
        if self._progress_text is not None:
            sys.stdout.write(_CLEAR_LINE)
            sys.stdout.flush()
            self._progress_text = None

    # --------------------------------------------------------------- строки
    def _emit(self, text, color=None, min_level=1, bold=False) -> None:
        if COLOR_LEVEL < min_level:
            return
        had_progress = self._progress_text is not None
        if had_progress:
            sys.stdout.write(_CLEAR_LINE)
        sys.stdout.write(self.paint(text, color, bold) + "\n")
        if had_progress:
            self._write_progress()   # прогресс не гаснет — сразу перерисовываем
        else:
            sys.stdout.flush()

    def always(self, text: str = "") -> None:          # видно даже на тихом уровне
        self._emit(text, None, 0)

    def error(self, text: str) -> None:
        self._emit("[ОШИБКА] " + text, "red", 0)

    def warn(self, text: str) -> None:
        self._emit("[!] " + text, "yellow", 1)

    def info(self, text: str = "") -> None:
        self._emit(text, None, 1)

    def ok(self, text: str) -> None:
        self._emit("[OK] " + text, "green", 1)

    def header(self, text: str) -> None:
        self._emit(text, ACCENT_COLOR, 0, bold=True)

    def banner(self, text: str) -> None:
        """Многострочный логотип — виден всегда."""
        self._emit(text, ACCENT_COLOR, 0, bold=True)


con = Console()

# Логотип зашит в код и ни от каких внешних файлов не зависит. При первом
# показе он «расшифровывается» волной, не меняя текст.
LOGO_TEXT = r"""
   _  _     ____  _  __ _____
 _| || |_  |  _ \| |/ /|  _  |
|_  ..  _| | |_) | ' / | | | |
|_      _| |  __/| . \ | | | |
  |_||_|   |_|   |_|\_\|_| |_|
          Cleaner.py
"""

LOGO = LOGO_TEXT.strip("\n")

# Глифы расшифровки: только ASCII — наборы символов терминалов Windows
# различаются, а спецэффект не должен рассыпаться на квадратики.
_DECODE_GLYPHS = "01<>*+=#$%&@?/\\|"

_LOGO_ANIMATE = True                   # первый показ логотипа — с анимацией


def _accent_pair() -> tuple:
    """Пара кодов акцентного цвета (яркий, приглушённый) для анимации.

    COLOR_CODES хранит яркие варианты (90–97); приглушённый получается
    переводом в обычную интенсивность (30–37) вычитанием 60 из кода.
    Анимация красится этими же кодами, что и статичный логотип, поэтому
    её цвет всегда совпадает с цветом интерфейса.
    """
    bright = COLOR_CODES.get(ACCENT_COLOR, COLOR_CODES["blue"])
    dim = "\033[" + str(int(bright[2:-1]) - 60) + "m"
    return bright, dim


def _logo_decode() -> None:
    """Логотип «расшифровывается»: глифы перебираются и закрепляются волной.

    Анимация первого показа логотипа. Время закрепления клетки растёт
    слева направо и сверху вниз, поэтому логотип проявляется диагональной
    волной. Кадры перерисовывают блок логотипа на месте: курсор поднимается
    на высоту блока. Закреплённые символы красятся тем же кодом, что и
    статичный логотип, поэтому последний кадр с ним совпадает.
    """
    bright, dim = _accent_pair()
    on_code = "\033[1m" + bright
    lines = LOGO.split("\n")
    out = sys.stdout
    trail = max(len(l) for l in lines) // 2
    try:
        out.write("\033[?25l")
        for t in range(len(lines) + trail + 2):
            if t:
                time.sleep(0.03)
                out.write(f"\033[{len(lines)}A")
            buf = []
            for r, line in enumerate(lines):
                row = []
                for c, ch in enumerate(line):
                    if ch == " ":
                        row.append(" ")
                    elif t >= r + c // 2:
                        row.append(on_code + ch)
                    else:
                        row.append(dim + random.choice(_DECODE_GLYPHS))
                buf.append("".join(row) + _RESET + "\033[K")
            out.write("\n".join(buf) + "\n")
            out.flush()
    finally:
        out.write("\033[?25h")
        out.flush()


def show_logo() -> None:
    """Отступ (пустая строка) и логотип.

    Первый показ (и показ после смены акцентного цвета) идёт с анимацией
    «расшифровки», если она возможна: вывод — терминал, цвета включены,
    уровень логов не тихий и logo_pause не обнулён. Сбойная анимация не
    роняет запуск — логотип печатается статично.
    """
    global _LOGO_ANIMATE
    con.always("")
    animate = _LOGO_ANIMATE
    _LOGO_ANIMATE = False
    if animate and USE_COLORS and con.tty and COLOR_LEVEL >= 1 \
            and LOGO_PAUSE > 0:
        try:
            _logo_decode()
            return
        except (KeyboardInterrupt, Exception):
            pass
    con.banner(LOGO)


def clear_screen() -> None:
    """Полная очистка экрана и возврат курсора в левый верхний угол.

    Очистка идёт всегда, когда её просят, — и в обычной консоли, и в
    оболочках вроде PyCharm, где stdout не tty и ANSI-очистка не срабатывает.
    """
    if os.name == "nt":
        os.system("cls")
    else:
        sys.stdout.write("\033[2J\033[H")
        sys.stdout.flush()

# -------------------------------------------------------------------------
# Журнал разработчика: temp/Cleaner/cleaner.log
# -------------------------------------------------------------------------
# Включается пунктами группы «Логи и диагностика». Все записи идут через
# _devlog: строка с меткой времени дописывается в конец файла. Файл
# растёт только пока журнал включён; при переполнении свыше 20 МБ он
# обнуляется — на диске всегда свежие записи.
_DEVLOG_LIMIT = 20 * 1024 * 1024


def _devlog(text: str) -> None:
    """Дописывает текст (возможно многострочный) в журнал разработчика."""
    try:
        os.makedirs(SERVICE_DIR, exist_ok=True)
        if os.path.isfile(DEVLOG_FILE) \
                and os.path.getsize(DEVLOG_FILE) > _DEVLOG_LIMIT:
            os.remove(DEVLOG_FILE)      # журнал распух — начинаем заново
        with open(DEVLOG_FILE, "a", encoding="utf-8") as f:
            # первая строка с меткой времени, остальные — с отступом,
            # чтобы журнал читался ровно
            rows = text.split("\n")
            f.write(time.strftime("[%Y-%m-%d %H:%M:%S] ") + rows[0] + "\n")
            for extra in rows[1:]:
                f.write("    " + extra + "\n")
    except OSError:
        pass                            # журнал не критичен, тише едешь…


# =========================================================================
# 5. СПРАВОЧНИКИ ПРОТОКОЛОВ И РЕГУЛЯРКИ
# =========================================================================
# Что разрешено в ссылках. Любая правка этих наборов сразу меняет
# правила чистки — здесь «руль» того, что проходит, а что бракуется.
ACCEPTED = {"vless", "vmess", "ss", "trojan", "hysteria2", "tuic"}
SCHEME_ALIAS = {"hy2": "hysteria2", "shadowsocks": "ss"}
# Транспорты, которые работают и в ядре, и в клиентах. quic в списке нет:
# v2rayNG его не поддерживает и при импорте молча превращает ссылку в
# tcp — такие конфиги бракуются в fill_transport().
NETS = {"tcp", "ws", "http", "kcp", "grpc", "httpupgrade", "xhttp"}
KCP_HT = {"none", "srtp", "utp", "wechat-video", "dtls", "wireguard", "dns"}
# Шифры vmess, которые принимает ядро sing-box-extended. Остальные
# встречающиеся значения ядро отвергает, поэтому их канонизируем в auto.
VMESS_SCY = {"auto", "aes-128-gcm", "aes-128-cfb", "chacha20-poly1305", "none", "zero"}

# Методы ss, которые знают клиенты и ядро: AEAD, SS2022 и «без
# шифрования» (plain — синоним none). Имена AEAD — в ietf-написании:
# ядро знает только его, поэтому chacha20-poly1305 (как пишет Xray)
# переименовывается при разборе.
SS_AEAD = {"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305",
           "xchacha20-ietf-poly1305"}
SS_AEAD_ALIAS = {"chacha20-poly1305": "chacha20-ietf-poly1305",
                 "xchacha20-poly1305": "xchacha20-ietf-poly1305"}
SS_2022 = {"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305"}
SS_PLAIN = {"none", "plain"}
# Устаревшие стримовые шифры. Ядро их поддерживает, поэтому парсеры
# пропускают; но в v2rayNG их нет и конвертер чекера не принимает —
# окончательно их отсекает checker_compat() при включённом checker_filter.
SS_LEGACY = {"aes-128-cfb", "aes-192-cfb", "aes-256-cfb",
             "aes-128-ctr", "aes-192-ctr", "aes-256-ctr",
             "rc4-md5", "chacha20-ietf", "xchacha20"}
SS_METHODS = SS_AEAD | SS_2022 | SS_PLAIN | SS_LEGACY

# Мёртвые шифры: их нет ни в одном актуальном клиенте — бракуем сразу
# парсером, не доходя до фильтров.
SS_UNSUPPORTED = {
    "camellia-128-cfb", "camellia-192-cfb", "camellia-256-cfb",
    "chacha20", "rc4-md5-6",
    "bf-cfb", "cast5-cfb", "des-cfb", "idea-cfb", "rc2-cfb",
    "seed-cfb", "table",
}
SS2022_KEYLEN = {"2022-blake3-aes-128-gcm": 16, "2022-blake3-aes-256-gcm": 32,
                 "2022-blake3-chacha20-poly1305": 32}

# SIP003-плагины, которые умеет ядро, и их синонимы из других клиентов.
# Всё остальное ядро отвергает с «plugin not found». До конца конвейера
# доезжает только obfs-local с режимом http — почему, см. norm_ss_plugin().
SS_PLUGINS = {"obfs-local", "v2ray-plugin"}
SS_PLUGIN_ALIAS = {"simple-obfs": "obfs-local", "simple": "obfs-local",
                   "obfs": "obfs-local", "v2ray": "v2ray-plugin"}

# Методы ss, которые принимают и конвертер чекера, и v2rayNG.
# Список уже реестра ядра: стримовые шифры SS_LEGACY ядро умеет, но
# чекер их не берёт — их отсекает checker_compat(). Если конвертер
# расширят, достаточно дополнить этот набор.
CHECKER_SS_METHODS = {
    "aes-128-gcm", "aes-256-gcm",
    "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305",
    "none",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
}
CHECKER_SS_ALIAS = {"chacha20-poly1305": "chacha20-ietf-poly1305"}

TRUE_SET = {"1", "true", "yes", "on"}
FALSE_SET = {"0", "false", "no", "off"}
SCHEME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]*)://")
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}@")
RANGE_RE = re.compile(r"^\d{1,5}(?:-\d{1,5})?(?:,\d{1,5}(?:-\d{1,5})?)*$")
VENC_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+\-_]{1,254}$")   # чистый токен encryption
# В SNI допустимо подчёркивание: реальные серверы за такими доменами
# (fast_s24…) требуют точного совпадения SNI, а check_host() те же имена
# пропускает — отбраковка sni рвала рабочие конфиги на CDN-связках.
SNI_RE = re.compile(r"^[A-Za-z0-9_](?:[A-Za-z0-9._\-]*[A-Za-z0-9_])?$")

# Параметры запроса, которые парсеры понимают; остальные удаляются
# с пометкой в notes. Параметры из числа «понимаемых, но не переносимых»
# (tfo/fastopen — клиентская оптимизация, mux — клиентский мультиплексор,
# fm — маскировка FinalMask из свежего Xray, которой ядро не умеет; в
# реальных ссылках её маски выключены) снимаются молча: Node их не
# моделирует, на подключаемость они не влияют.
KNOWN_COMMON = {
    "encryption", "flow", "security", "sec", "sni", "peer", "servername", "host",
    "path", "p", "type", "network", "net", "fp", "fingerprint", "alpn", "pbk",
    "publickey", "sid", "shortid", "spx", "spiderx", "ech", "echconfiglist",
    "echconfig", "allowinsecure", "allowlnsecure", "insecure", "skip-cert-verify",
    "allow_insecure", "servicename", "service", "mode", "headertype", "header",
    "obfs", "seed", "ed", "max-early-data", "maxearlydata", "eh",
    "earlydataheadername", "early-data-header-name", "authority", "extra", "qsec",
    "quicsecurity", "key", "packetencoding", "packet-encoding", "pktenc",
    "grpc-service-name", "fm", "tfo", "tcp-fast-open", "tcp_fast_open",
    "fastopen", "mux", "ws", "wspath",
}
HY2_KNOWN = {"sni", "peer", "insecure", "allowinsecure", "allowlnsecure",
             "skip-cert-verify", "obfs", "obfs-password", "obfspassword",
             "obfs-param", "obfsparam", "pinsha256", "pin-sha256", "mport", "ports",
             "alpn", "fp", "fingerprint", "upmbps", "downmbps", "up-mbps",
             "down-mbps", "up", "down", "hop_interval", "hopinterval",
             "hop-interval", "fastopen", "fm"}

# TUIC: QUIC-протокол, TLS у него всегда, транспорт не выбирается.
# Чужие значения алгоритма перегрузки и релея UDP канонизируем в дефолт
# ядра (cubic/native), а не бракуем.
TUIC_CC = {"cubic", "new_reno", "bbr"}
TUIC_URM = {"native", "quic"}
TUIC_KNOWN = {
    "sni", "peer", "alpn",
    "congestion_control", "congestioncontrol", "cc",
    "udp_relay_mode", "udprelaymode",
    "udp_over_stream", "udp-over-stream", "udpoverstream",
    "reduce_rtt", "reducertt", "zero_rtt_handshake", "zerortthandshake",
    "heartbeat", "disable_sni", "disablesni",
    "allow_insecure", "allowinsecure", "allowlnsecure", "insecure",
    "skip-cert-verify", "skipcertverify",
    "mtu", "ecn", "max_udp_relay_packet_size",
}

# Локальные и зарезервированные сети, публичные DNS-серверы: конфиги
# на таких адресах в реальной работе бессмысленны — бракуем по настройкам.
BAD_V4 = [ipaddress.ip_network(x) for x in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.0.0.0/29", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15",
    "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4")]
BAD_V6 = [ipaddress.ip_network(x) for x in (
    "::/128", "::1/128", "::ffff:0:0/96", "fc00::/7", "fe80::/10", "ff00::/8", "2001:db8::/32")]
IP_BLACKLIST = {"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9", "149.112.112.112",
                "2606:4700:4700::1111", "2606:4700:4700::1001", "2001:4860:4860::8888",
                "2001:4860:4860::8844", "2620:fe::fe", "2620:fe::9"}

# Порты ниже 22 — мусор из подписок: на них ничего не слушается, ядра
# клиентов на них ломаются. 22 — минимальный реальный порт (DNS, туннели).
MIN_PORT = 22


# =========================================================================
# 6. БАЗОВЫЕ ФУНКЦИИ РАЗБОРА ССЫЛОК
# =========================================================================
class Rej(Exception):
    """«Конфиг бракуем» с причиной — текст уедет в статистику отбраковки."""


def b64d(s):
    """base64 в любых написаниях (std/urlsafe, с паддингом и без); None — ошибка."""
    if not s:
        return None
    s = re.sub(r"\s+", "", s).rstrip("=")
    for c in (s, s.replace("-", "+").replace("_", "/")):
        try:
            return base64.b64decode(c + "=" * ((-len(c)) % 4), validate=True)
        except Exception:
            continue
    return None


def preprocess(s):
    """Чинит типовые поломки ссылок до разбора.

    &amp; разворачиваем в & (бывает и двойное — крутим в цикле),
    процентно-закодированный экран (след JSON-экранирования) возвращаем
    в разделитель параметров: без этого хвост параметров прилипает к
    предыдущему значению и теряется. Заодно чистим юникод-экраны,
    «¬» и нулевые символы.
    """
    prev = None
    while prev != s:
        prev = s
        s = re.sub(r"&amp;", "&", s, flags=re.I)
    if "\\u" in s:
        s = re.sub(r"\\u([0-9a-fA-F]{4})", lambda m: chr(int(m.group(1), 16)), s)
    s = re.sub(r"(?i)%5cu0026", "&", s)    # процентно-закодированный \u0026
    if "¬" in s:
        s = s.replace("¬", "&")
    return s.replace("\u200b", "")


def strip_fragment(body):
    """Отрезает имя и комментарии — всё от первой '#' и дальше.

    Вторая решётка уходит вместе с хвостом: в канонический вывод имя
    и комментарии не попадают никогда.
    """
    i = body.find("#")
    return body[:i] if i >= 0 else body


def parse_query(qs):
    """Строка запроса -> словарь параметров; первый ключ выигрывает.

    Кусок без '=' пробуем раскодировать: 'insecure%3D1' — это прилипший
    параметр, а не голый флаг. Ведущие ';' у ключа снимаем: часть
    генераторов путает '&' и ';'.
    """
    q = {}
    for part in qs.split("&"):
        if not part:
            continue
        part = part.lstrip(";")
        if "=" not in part:
            try:
                dec = unquote(part)
            except Exception:
                dec = part
            if "=" in dec:
                part = dec
        k, _, v = part.partition("=")
        try:
            k, v = unquote(k).strip().lower(), unquote(v)
        except Exception:
            continue
        if k and k not in q:
            q[k] = v
    return q


def _q(q, *names, default=""):
    """Первое непустое значение параметра по списку имён-синонимов."""
    for n in names:
        v = q.get(n.lower())
        if v not in (None, ""):
            return v
    return default


def as_bool(v, n):
    """Флаг из запроса -> bool; нечитаемое значение трактуется как False."""
    if v == "":
        return False
    v = v.lower()
    if v in TRUE_SET:
        return True
    if v in FALSE_SET:
        return False
    n.notes.append("нечитаемый флаг → false")
    return False


def trim_enum(v):
    """Первый токен вида [a-z0-9-]+ из значения — обрезка мусорных суффиксов."""
    m = re.match(r"[a-z0-9\-]+", v)
    return m.group(0) if m else ""


def valid_sni(s):
    """SNI/домен: буквы, цифры, точки и дефисы, до 253 символов."""
    return bool(s) and len(s) <= 253 and bool(SNI_RE.fullmatch(s))


def norm_alpn(raw, n):
    """Нормализует alpn: глубокий unquote, синонимы, только h2/h3/http/1.1."""
    if not raw:
        return []
    r = raw
    for _ in range(3):                      # глубокий unquote: http%2f1.1, h2%2chttp%2f1.1
        if "%" not in r:
            break
        u = unquote(r)
        if u == r:
            break
        r = u
    amap = {"http1.1": "http/1.1", "h1": "http/1.1", "http2": "h2", "http/2": "h2",
            "http3": "h3", "http/3": "h3"}
    out = []
    for a in re.split(r"[,\s;]+", r):
        a = a.strip().lower()
        if not a:
            continue
        a = amap.get(a, a)
        if a in ("http/1.1", "h2", "h3"):
            if a not in out:
                out.append(a)
        else:
            n.notes.append(f"alpn-токен {a[:20]!r} удалён")
    return out


def check_host(raw):
    """Проверяет адрес (IPv4/IPv6/домен) и приводит к единому виду.

    Локальные/зарезервированные адреса и публичные DNS бракуются
    по настройкам reject_private/reject_dns.
    """
    h = (raw or "").strip()
    if not h:
        raise Rej("пустой адрес")
    if h.startswith("[") and h.endswith("]"):
        h = h[1:-1]
    if ":" in h:
        try:
            ip = ipaddress.IPv6Address(h)
        except ValueError:
            raise Rej(f"неверный IPv6: {raw[:60]!r}")
        if REJECT_IPV6:
            raise Rej("IPv6-адрес — отбракован настройкой reject_ipv6")
        s = str(ip)
        if REJECT_DNS and s in IP_BLACKLIST:
            raise Rej(f"чёрный список IP: {s}")
        if REJECT_PRIVATE:
            for net in BAD_V6:
                if ip in net:
                    raise Rej(f"локальный/зарезервированный IPv6 {ip}")
        return s
    if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", h):
        if any(len(o) > 1 and o[0] == "0" for o in h.split(".")):
            raise Rej("обфусцированный IP (ведущие нули)")
        try:
            ip = ipaddress.IPv4Address(h)
        except ValueError:
            raise Rej(f"неверный IPv4: {h[:40]!r}")
        s = str(ip)
        if REJECT_DNS and s in IP_BLACKLIST:
            raise Rej(f"чёрный список IP: {s}")
        if REJECT_PRIVATE:
            for net in BAD_V4:
                if ip in net:
                    raise Rej(f"локальный/зарезервированный IP {ip}")
        return s
    if re.fullmatch(r"[0-9.]+", h) or re.fullmatch(r"0[xX][0-9a-fA-F.]+", h):
        raise Rej("обфусцированный числовой IP")
    d = h.rstrip(".").lower()
    if not d or len(d) > 253 or "." not in d:
        raise Rej(f"невалидный домен: {raw[:60]!r}")
    label = re.compile(r"^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$")
    parts = d.split(".")
    for p in parts:
        if not label.match(p):
            raise Rej(f"невалидный домен: {raw[:60]!r}")
    if len(parts[-1]) < 2 or parts[-1].isdigit():
        raise Rej(f"невалидный домен: {raw[:60]!r}")
    return d


def parse_hostport(s):
    """Разбирает 'host:port' или '[ipv6]:port' в (host, port)."""
    s = s.strip().strip("/")
    if not s:
        raise Rej("пустой host:port")
    if s.startswith("["):
        m = re.match(r"^\[([^\]]+)\]:(\d+)$", s)
        if not m:
            raise Rej(f"битый IPv6 authority: {s[:70]!r}")
        host, port = m.group(1), m.group(2)
    else:
        host, sep, port = s.rpartition(":")
        if not sep or not port.isdigit():
            raise Rej("не указан порт")
        if host == "":
            raise Rej(f"битый authority: {s[:70]!r}")
        if ":" in host:                      # голый IPv6 — спасаем
            try:
                ipaddress.IPv6Address(host)
            except ValueError:
                raise Rej(f"битый authority: {s[:70]!r}")
    p = int(port)
    if not MIN_PORT <= p <= 65535:
        raise Rej(f"порт вне диапазона: {p} (допустимо {MIN_PORT}–65535)")
    return check_host(host), p


def ports_in_range(spec):
    """Все порты в списке 'a-b,c,…' в пределах MIN_PORT..65535.

    Сюда попадает и mport hysteria2: прыжок на мусорный порт ломает
    ядро так же, как и прямой порт из ссылки.
    """
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            a, _, b = part.partition("-")
            if not (a.isdigit() and b.isdigit()):
                return False
            if not (MIN_PORT <= int(a) <= int(b) <= 65535):
                return False
        else:
            if not part.isdigit() or not MIN_PORT <= int(part) <= 65535:
                return False
    return True


def fh(h):
    """IPv6-адрес в квадратных скобках для URL, остальное — как есть."""
    try:
        if ipaddress.ip_address(h).version == 6:
            return f"[{h}]"
    except ValueError:
        pass
    return h


def _enc(v):
    """Процентное кодирование значения параметра URL (безопасно для '&' и '#')."""
    return quote(str(v), safe="")


class Node:
    """Конфиг после разбора: все поля нормализованы.

    Слоты — ровно те поля, из которых build_uri собирает каноническую
    ссылку; notes копит пометки о внесённых правках.
    """
    __slots__ = ("proto", "host", "port", "uuid", "password", "method", "scy", "aid",
                 "venc", "net", "sec", "flow", "sni", "hhost", "alpn", "fp",
                 "insecure", "pbk", "sid", "spx", "ech", "path", "service", "mode",
                 "htype", "seed", "qsec", "qkey", "ed", "eh", "authority", "plugin",
                 "obfs", "obfsp", "pins", "mport", "upm", "dnm", "hop", "pkte",
                 "cc", "urm", "uds", "zrtt", "hbeat", "dsni",
                 "extra", "notes")

    def __init__(self, proto):
        self.proto = proto
        self.host, self.port = "", 0
        self.uuid = self.password = self.method = self.venc = ""
        self.scy, self.aid = "auto", 0
        self.net, self.sec, self.flow = "tcp", "none", ""
        self.sni = self.hhost = ""
        self.alpn, self.fp, self.insecure = [], "", False
        self.pbk = self.sid = self.spx = self.ech = ""
        self.path = self.service = self.mode = self.htype = ""
        self.seed = self.qsec = self.qkey = ""
        self.ed, self.eh, self.authority = None, "", ""
        self.plugin = self.obfs = self.obfsp = ""
        self.pins, self.mport, self.pkte, self.extra = [], "", "", ""
        self.upm = self.dnm = self.hop = ""
        # параметры tuic: cc — congestion_control, urm — udp_relay_mode,
        # uds — udp_over_stream, zrtt — reduce_rtt (zero_rtt_handshake),
        # hbeat — heartbeat, dsni — disable_sni
        self.cc = self.urm = self.hbeat = ""
        self.uds = self.zrtt = self.dsni = False
        self.notes = []


def fix_wslike_path(p, n):
    """Чистит path у ws-подобных транспортов.

    Вытаскивает ed=... из самого пути, режет рекламные хвосты,
    следит, чтобы путь начинался с '/'.
    """
    m = re.search(r"[?&]ed=(\d+)", p)
    if m:
        n.ed = int(m.group(1))
        p = re.sub(r"[?&]ed=\d+", "", p)
        # ed мог быть первым параметром: вместе с ним уходит '?',
        # а оставшиеся параметры склеиваются через '&' — восстанавливаем
        if "?" not in p and "&" in p:
            p = p.replace("&", "?", 1)
        n.notes.append("ed извлечён из path")
    if not p.lower().startswith("/socks5://"):
        m = re.search(r"https?://|t\.me/", p, re.I)
        if m:
            n.notes.append("реклама в path вырезана")
            p = p[:m.start()].rstrip("&?=@") or "/"
    if "://" in p.lower() and not p.lower().startswith("/socks5://"):
        raise Rej(f"path не похож на путь: {p[:60]!r}")
    if not p.startswith("/"):
        p = "/" + p
        n.notes.append("path исправлен (добавлен '/')")
    return p or "/"


def fill_transport(n, q, sec_default):
    """Разбирает транспортный блок параметров (net, security, sni, path…).

    Общая для vless/vmess/trojan: приводит type/security к допустимым
    значениям, обрабатывает TLS/reality, заголовок Host, alpn, fp и
    специфичные для транспортов параметры.
    """
    net = _q(q, "type", "network", "net", default="").strip().lower()
    ob = _q(q, "obfs").strip().lower()
    if not net and ob:
        if ob in ("websocket", "ws"):
            net, _ = "ws", n.notes.append("obfs=websocket → type=ws")
        elif ob == "http":
            net, _ = "tcp", n.notes.append("obfs=http → headerType=http")
        else:
            n.notes.append(f"obfs={ob[:20]!r} удалён")
    net = {"h2": "http", "websocket": "ws", "splithttp": "xhttp"}.get(net, net)
    if net in ("raw", "none", ""):
        if net:
            n.notes.append(f"type={net} → tcp")
        net = "tcp"
    if net == "quic":
        raise Rej("транспорт quic не поддерживается v2rayNG — "
                  "при импорте ссылка становится tcp")
    if net == "kcp" and REJECT_MKCP:
        raise Rej("транспорт mKCP неактуален — отбракован настройкой reject_mkcp")
    if net not in NETS:
        t = trim_enum(net)
        if t in NETS:
            n.notes.append(f"type={net[:25]!r} → {t}")
            net = t
        else:
            raise Rej(f"неизвестный транспорт type={net[:30]!r}")
    n.net = net

    sec = _q(q, "security", "sec").strip().lower() or sec_default
    sec = trim_enum(sec) or sec_default
    if sec in ("false", "0", "auto", "off", "no"):
        n.notes.append(f"security={sec} → none")
        sec = "none"
    if sec == "xtls":
        sec = "reality" if _q(q, "pbk", "publickey") else "tls"
        n.notes.append(f"security=xtls → {sec}")
    if sec not in ("none", "tls", "reality"):
        raise Rej(f"неизвестный security={sec[:30]!r}")
    n.sec = sec

    n.hhost = _q(q, "host").strip()
    sni = _q(q, "sni", "peer", "servername").strip()
    if sni and not valid_sni(sni):
        n.notes.append(f"sni невалиден ({sni[:20]!r}) — удалён")
        sni = ""
    if sec in ("tls", "reality"):
        n.sni = sni or n.hhost or n.host
    elif sni:
        n.notes.append("sni при security=none удалён")

    n.alpn = norm_alpn(_q(q, "alpn"), n)
    fp = _q(q, "fp", "fingerprint").strip()
    if fp:
        if DROP_FP:
            # fp — отпечаток uTLS на стороне клиента, сервер его не
            # требует; с включённым DROP_FP fp удаляется целиком и
            # перекрывает fp_value/add_fp_for_reality
            n.notes.append("fp удалён (drop_fp)")
        else:
            n.fp = FP_VALUE
            if fp.lower() != FP_VALUE:
                n.notes.append(f"fp={fp[:20]} → {FP_VALUE}")
    n.insecure = as_bool(_q(q, "allowinsecure", "allowlnsecure", "insecure",
                            "skip-cert-verify", "allow_insecure"), n)
    n.ech = _q(q, "ech", "echconfiglist", "echconfig").strip()
    n.pkte = _q(q, "packetencoding", "packet-encoding", "pktenc").strip().lower()

    pbk = _q(q, "pbk", "publickey").strip()
    sid = _q(q, "sid", "shortid").strip()
    spx = _q(q, "spx", "spiderx").strip()
    if sec == "reality":
        if n.insecure:
            n.insecure = False
            n.notes.append("allowInsecure убран (несовместим с reality)")
        if not pbk:
            n.sec, _ = "tls", n.notes.append("reality без pbk → tls")
        else:
            r = b64d(pbk)
            if r is None or len(r) != 32:
                raise Rej("pbk не является 32-байтовым base64url-ключом")
            n.pbk = pbk
            # spx/sid на связь не влияют и по умолчанию удаляются
            # (drop_spx/drop_sid): в публичных подписках они обычно
            # случайные и мешают дедупликации схлопывать конфиги
            # одного сервера. Пока настройка включена, sid даже не
            # проверяется — мусор в удаляемом параметре не убивает конфиг.
            if sid:
                if DROP_SID:
                    n.notes.append("sid удалён (drop_sid)")
                elif re.fullmatch(r"[0-9a-fA-F]{1,16}", sid):
                    n.sid = sid.lower()
                else:
                    raise Rej(f"sid не hex≤16: {sid[:30]!r}")
            if spx:
                if DROP_SPX:
                    n.notes.append("spx удалён (drop_spx)")
                else:
                    n.spx = spx
            if not n.fp and not DROP_FP and ADD_FP_FOR_REALITY:
                n.fp, _ = FP_VALUE, n.notes.append(f"fp добавлен ({FP_VALUE}) для reality")
    elif pbk or sid or spx:
        n.notes.append("pbk/sid/spx без reality удалены")

    if net == "ws":
        n.path = fix_wslike_path(_q(q, "path", "p", default="/") or "/", n)
        if n.ed is None:
            ed = _q(q, "ed", "max-early-data", "maxearlydata")
            if ed.isdigit():
                n.ed = int(ed)
            elif ed:
                n.notes.append("нечисловой ed удалён")
        n.eh = _q(q, "eh", "earlydataheadername", "early-data-header-name").strip()
    elif net in ("http", "httpupgrade", "xhttp"):
        n.path = fix_wslike_path(_q(q, "path", default="/") or "/", n)
        n.authority = _q(q, "authority").strip() or n.hhost
        if net == "xhttp":
            m_ = trim_enum(_q(q, "mode").strip().lower()) or "auto"
            if m_ not in ("auto", "packet-up", "stream-up", "stream-one"):
                n.notes.append(f"xhttp mode={m_[:20]!r} → auto")
                m_ = "auto"
            n.mode = m_
            ex = _q(q, "extra").strip()
            if ex:
                try:
                    json.loads(ex)
                    n.extra = ex
                except Exception:
                    n.notes.append("extra не JSON — удалён")
    elif net == "grpc":
        n.service = _q(q, "servicename", "service", "grpc-service-name", "path").strip()
        m_ = trim_enum(_q(q, "mode").strip().lower())
        if m_ and m_ not in ("gun", "multi"):
            n.notes.append(f"grpc mode={m_[:20]!r} удалён")
            m_ = ""
        n.mode = m_
    elif net == "tcp":
        ht = _q(q, "headertype", "header", "obfs").strip().lower() or "none"
        ht = trim_enum(ht) or "none"
        if ht not in ("none", "http"):
            n.notes.append(f"tcp headerType={ht[:20]!r} → none")
            ht = "none"
        n.htype = ht
        if ht == "http":
            n.path = fix_wslike_path(_q(q, "path", default="/") or "/", n)
    elif net == "kcp":
        ht = trim_enum(_q(q, "headertype", "header").strip().lower()) or "none"
        if ht not in KCP_HT:
            n.notes.append(f"kcp headerType={ht[:20]!r} → none")
            ht = "none"
        n.htype = ht
        n.seed = _q(q, "seed").strip()

    unk = sorted(k for k in q if k not in KNOWN_COMMON)
    if unk:
        n.notes.append("неизвестные параметры удалены: " + ",".join(unk[:12]))


def _split_query(body):
    """Отделяет строку запроса от тела: 'тело?query' -> (тело, словарь)."""
    q = {}
    if "?" in body:
        body, qs = body.split("?", 1)
        q = parse_query(qs)
    return body, q

# =========================================================================
# 7. ПАРСЕРЫ ПРОТОКОЛОВ
# =========================================================================
# Каждый парсер принимает строку и возвращает заполненный Node.
# Любая проблема — исключение Rej с понятной причиной: текст уедет
# в статистику отбраковки.
def parse_vless(s):
    n = Node("vless")
    body = strip_fragment(preprocess(s))[s.index("://") + 3:]
    body, q = _split_query(body)
    if "@" not in body:
        raise Rej("нет '@' в ссылке")
    userinfo, _, hostport = body.rpartition("@")
    cred = unquote(userinfo).strip()
    try:
        n.uuid = str(uuidlib.UUID(cred))
    except Exception:
        raise Rej(f"id не является UUID: {cred[:48]!r}")
    n.host, n.port = parse_hostport(hostport)
    enc_raw = _q(q, "encryption").strip()
    if enc_raw and enc_raw.lower() != "none":
        if VENC_RE.fullmatch(enc_raw):
            n.venc = enc_raw               # mlkem768x25519plus… и др. PQ-токены — сохраняем
        else:
            n.notes.append(f"encryption={enc_raw[:20]!r} → none")
    fl = trim_enum(_q(q, "flow").strip().lower())
    if fl and fl != "xtls-rprx-vision":
        n.notes.append(f"flow={fl[:30]!r} удалён")
        fl = ""
    n.flow = fl
    fill_transport(n, q, "none")
    if n.flow and (n.net != "tcp" or n.sec != "reality"):
        n.notes.append("flow удалён: требует tcp+reality")
        n.flow = ""
    return n


def parse_trojan(s):
    n = Node("trojan")
    body = strip_fragment(preprocess(s))[s.index("://") + 3:]
    body, q = _split_query(body)
    if "@" not in body:
        raise Rej("нет '@' в ссылке")
    userinfo, _, hostport = body.rpartition("@")
    n.password = unquote(userinfo).strip()
    if not n.password:
        raise Rej("пустой пароль trojan")
    n.host, n.port = parse_hostport(hostport)
    enc = _q(q, "encryption").lower()
    if enc and enc != "none":
        if enc.startswith("ss"):
            raise Rej("trojan-go (encryption=ss;…) не поддерживается")
        n.notes.append(f"encryption={enc[:20]!r} удалён")
    # нестандартная форма ws-транспорта «ws=1&wspath=…» (генерируется рядом
    # клиентов и ботов вместо type=ws&path=…) переводится в каноническую;
    # при явно заданном type/ws=0 форма игнорируется
    if _q(q, "ws").strip().lower() in ("1", "true", "yes", "on"):
        if not _q(q, "type", "network", "net").strip():
            q["type"] = "ws"
            n.notes.append("ws=1 → type=ws")
        wsp = _q(q, "wspath").strip()
        if wsp and not _q(q, "path", "p").strip():
            q["path"] = wsp
            n.notes.append("wspath → path")
    fill_transport(n, q, "tls")
    return n


def norm_ss_plugin(n):
    """Приводит плагин ss к виду, который понимают ядро и v2rayNG.

    Ядро умеет создавать только obfs-local и v2ray-plugin; синонимы из
    других клиентов (simple-obfs, obfs, v2ray) переименовываем, дважды
    закодированные значения раскрываем. До клиента доезжает только
    «obfs=http»: v2rayNG понимает именно его (превращая в tcp с
    http-камуфляжем), а v2ray-plugin и «obfs=tls» при импорте
    выбрасывает — конфиг теряет обфускацию. Остальные имена ядро
    отвергает с «plugin not found».
    """
    # Повторное процентное кодирование ловим по имени плагина: если в
    # сегменте до первой ';' есть закодированная ';', значение
    # кодировали дважды (часто — с одним «протёкшим» хвостовым ';').
    unquoted = False
    for _ in range(2):
        head = n.plugin.partition(";")[0]
        if "%3b" not in head.lower():
            break
        dec = unquote(n.plugin)
        if ";" not in dec:
            break
        n.plugin = dec
        unquoted = True
    if unquoted:
        n.notes.append("повторное процентное кодирование плагина раскрыто")
    name, sep, opts = n.plugin.partition(";")
    name_l = name.strip().lower()
    canon = SS_PLUGIN_ALIAS.get(name_l, name_l)
    if canon != name:
        n.notes.append(f"плагин {name[:24]!r} → {canon}")
    if canon not in SS_PLUGINS:
        raise Rej(f"плагин ss {name[:30]!r} не поддерживается ядром "
                  "(доступны obfs-local, v2ray-plugin)")
    kv = {}
    for part in opts.split(";"):
        if part:
            k, _, v = part.partition("=")
            kv[k.strip().lower()] = v
    if canon == "obfs-local":
        mode = kv.get("obfs", "http")
        if mode not in ("http", "tls"):
            raise Rej(f"плагин obfs-local: неизвестный режим {mode[:20]!r} "
                      "(доступны http, tls)")
        if mode == "tls":
            # v2rayNG распознаёт только «obfs=http»; «obfs=tls» при импорте
            # выбрасывается — конфиг доходит до клиента без обфускации
            raise Rej("плагин obfs-local с режимом tls не поддерживается v2rayNG")
    else:
        # v2ray-plugin v2rayNG не понимает вовсе: при импорте плагин
        # выбрасывается, конфиг теряет обфускацию
        raise Rej("плагин v2ray-plugin не поддерживается v2rayNG")
    n.plugin = canon + (sep + opts if sep else "")


def parse_ss(s):
    n = Node("ss")
    body = strip_fragment(preprocess(s))[s.index("://") + 3:]
    body, q = _split_query(body)
    n.plugin = _q(q, "plugin").strip()
    if n.plugin:
        norm_ss_plugin(n)
    if "@" in body:
        userinfo, _, hostport = body.rpartition("@")
        m = re.match(r"^([^/?]+)(?:/.*)?$", hostport)
        if not m:
            raise Rej(f"битый host:port: {hostport[:60]!r}")
        if m.group(0) != m.group(1):
            n.notes.append("мусор после host:port удалён")
        n.host, n.port = parse_hostport(m.group(1))
        ui = unquote(userinfo).strip()          # percent ДО base64
        dec = b64d(ui)
        if dec is not None:
            try:
                t = dec.decode("utf-8").strip()
            except Exception:
                t = ""
            if t.startswith("ss://"):           # вложенный ss:// в userinfo
                inner = t[5:]
                if "@" in inner:
                    d2 = b64d(inner.rpartition("@")[0].strip())
                    if d2 is not None:
                        try:
                            t2 = d2.decode("utf-8")
                            if ":" in t2:
                                ui, _ = t2, n.notes.append("вложенный ss:// раскрыт")
                        except Exception:
                            pass
            elif ":" in t:
                meth = t.partition(":")[0].strip().lower()
                if meth in SS_METHODS or meth in SS_AEAD_ALIAS:
                    ui = t                      # base64(method:password) — раскрываем
                elif meth in SS_UNSUPPORTED:
                    raise Rej(f"метод ss {meth[:40]!r} не поддерживается клиентами")
        if ":" not in ui:
            raise Rej("userinfo не содержит method:password")
        n.method, _, n.password = ui.partition(":")
    else:
        dec = b64d(body)
        if dec is None:
            raise Rej("нет '@' и тело не base64")
        try:
            t = dec.decode("utf-8")
        except Exception:
            raise Rej("legacy-тело не UTF-8")
        m = re.match(r"^([^:@]*):(.*)@(.+)$", t, re.S)
        if not m:
            raise Rej("legacy-формат не method:password@host:port")
        n.method, n.password = m.group(1), m.group(2)
        hp = m.group(3).split("?", 1)[0].split("/", 1)[0]
        n.host, n.port = parse_hostport(hp)
        if not n.method.strip():
            raise Rej("пустой method в legacy-ss")
    n.method = n.method.strip().lower()
    n.password = n.password.strip()
    if not n.method:
        raise Rej("пустой method ss")
    if n.method == "plain":
        n.method = "none"          # каноническое имя «без шифрования»
        n.notes.append("метод plain → none")
    elif n.method in SS_AEAD_ALIAS:
        canon = SS_AEAD_ALIAS[n.method]
        n.notes.append(f"метод {n.method} → {canon}")
        n.method = canon
    if n.method not in SS_METHODS:
        raise Rej(f"метод ss {n.method[:40]!r} не поддерживается клиентами")
    if not n.password:
        raise Rej("пустой пароль ss")
    if re.search(r"https?://|t\.me", n.password, re.I):
        raise Rej("пароль-реклама (ссылка) — мусор")
    if n.method in SS2022_KEYLEN:
        ln = SS2022_KEYLEN[n.method]
        for part in n.password.split(":"):
            r = b64d(part)
            if r is None or len(r) != ln:
                raise Rej(f"пароль {n.method} должен быть base64-ключом {ln} байт")
    unk = sorted(k for k in q if k != "plugin")
    if unk:
        n.notes.append("неизвестные параметры удалены: " + ",".join(unk[:12]))
    return n


def parse_hy2(s):
    n = Node("hysteria2")
    n.sec = "tls"
    body = strip_fragment(preprocess(s))[s.index("://") + 3:]
    body, q = _split_query(body)
    body = body.strip().strip("/")
    if "@" not in body:
        raise Rej("нет auth@host")
    userinfo, _, hostport = body.rpartition("@")
    n.password = unquote(userinfo).strip()
    if not n.password:
        raise Rej("пустой auth")
    if hostport.startswith("["):
        m = re.match(r"^\[([^\]]+)\]:(.*)$", hostport)
        if not m:
            raise Rej(f"битый IPv6 authority: {hostport[:70]!r}")
        host, pr = m.group(1), m.group(2)
    else:
        host, sep, pr = hostport.rpartition(":")
        if not sep or not pr:
            raise Rej("не указан порт")
        if ":" in host:
            try:
                ipaddress.IPv6Address(host)
            except ValueError:
                raise Rej(f"битый authority: {hostport[:70]!r}")
    if pr.isdigit():
        p = int(pr)
        if not MIN_PORT <= p <= 65535:
            raise Rej(f"порт вне диапазона: {p} (допустимо {MIN_PORT}–65535)")
        n.port = p
    elif RANGE_RE.match(pr) and ports_in_range(pr):
        n.port = int(re.match(r"\d{1,5}", pr).group(0))
        n.mport, _ = pr, n.notes.append("диапазон портов перенесён в mport")
    else:
        raise Rej(f"неверный порт: {pr[:30]!r}")
    n.host = check_host(host)
    sni = _q(q, "sni", "peer").strip()
    if sni and not valid_sni(sni):
        n.notes.append(f"sni невалиден ({sni[:20]!r}) — удалён")
        sni = ""
    n.sni = sni
    n.insecure = as_bool(_q(q, "insecure", "allowinsecure", "allowlnsecure",
                            "skip-cert-verify"), n)
    fp = _q(q, "fp", "fingerprint").strip()
    if fp:
        if DROP_FP:
            n.notes.append("fp удалён (drop_fp)")
        else:
            n.fp = FP_VALUE
            if fp.lower() != FP_VALUE:
                n.notes.append(f"fp={fp[:20]} → {FP_VALUE}")
    ob = trim_enum(_q(q, "obfs").strip().lower())
    obp = _q(q, "obfs-password", "obfspassword", "obfs-param", "obfsparam").strip()
    if ob:
        if ob != "salamander":
            raise Rej(f"obfs={ob!r} не поддерживается (только salamander)")
        if not obp:
            n.notes.append("obfs без пароля — удалён")
        else:
            n.obfs, n.obfsp = ob, obp
    elif obp:
        n.notes.append("obfs-password без obfs — удалён")
    for p in filter(None, (x.strip() for x in _q(q, "pinsha256", "pin-sha256").split(","))):
        r = b64d(p)
        if r is None or len(r) != 32:
            n.notes.append("невалидный pinSHA256 удалён")
        else:
            n.pins.append(p)
    mp_ = _q(q, "mport", "ports").strip()
    if mp_:
        if RANGE_RE.match(mp_) and ports_in_range(mp_):
            n.mport = n.mport or mp_
        else:
            n.notes.append("mport невалиден — удалён")
    # пропускная способность и интервал прыжка портов — клиентские параметры
    # hysteria2 (пишут v2rayN, NekoBox, sing-box); нечисловые снимаются
    up = _q(q, "upmbps", "up-mbps", "up").strip()
    if up.isdigit():
        n.upm = up
    elif up:
        n.notes.append("нечисловой upmbps удалён")
    down = _q(q, "downmbps", "down-mbps", "down").strip()
    if down.isdigit():
        n.dnm = down
    elif down:
        n.notes.append("нечисловой downmbps удалён")
    hop = _q(q, "hop_interval", "hopinterval", "hop-interval").strip()
    if hop.isdigit():
        n.hop = hop
    elif hop:
        n.notes.append("нечисловой hop_interval удалён")
    n.alpn = norm_alpn(_q(q, "alpn"), n)
    unk = sorted(k for k in q if k not in HY2_KNOWN)
    if unk:
        n.notes.append("неизвестные параметры удалены: " + ",".join(unk[:12]))
    return n


def parse_tuic(s):
    """tuic://uuid:password@host:port?params — QUIC-протокол, TLS в нём всегда.

    v4-токен (голый userinfo без ':') ядро не поддерживает — бракуем.
    Чужие congestion_control/udp_relay_mode канонизируем в дефолты
    ядра (cubic/native), голое число heartbeat считаем секундами
    (ядро требует суффикс).
    """
    n = Node("tuic")
    n.sec = "tls"          # TLS — часть протокола, отключить нельзя
    n.net = "quic"         # для статистики транспортов
    body = strip_fragment(preprocess(s))[s.index("://") + 3:]
    body, q = _split_query(body)
    body = body.strip().strip("/")
    if "@" not in body:
        raise Rej("нет uuid:password@host")
    userinfo, _, hostport = body.rpartition("@")
    cred = unquote(userinfo).strip()
    uuid_part, sep, pwd_part = cred.partition(":")
    if not sep:
        raise Rej("userinfo без ':' — v4-токен не поддерживается (нужен uuid:password)")
    try:
        n.uuid = str(uuidlib.UUID(uuid_part))
    except Exception:
        raise Rej(f"uuid не является UUID: {uuid_part[:48]!r}")
    n.password = pwd_part.strip()
    if not n.password:
        n.notes.append("пустой пароль tuic — оставлен пустым")
    n.host, n.port = parse_hostport(hostport)
    sni = _q(q, "sni", "peer").strip()
    if sni and not valid_sni(sni):
        n.notes.append(f"sni невалиден ({sni[:20]!r}) — удалён")
        sni = ""
    n.sni = sni
    n.alpn = norm_alpn(_q(q, "alpn"), n)
    n.insecure = as_bool(_q(q, "allowinsecure", "allowlnsecure", "allow_insecure",
                            "insecure", "skip-cert-verify", "skipcertverify"), n)
    cc = trim_enum(_q(q, "congestion_control", "congestioncontrol", "cc")
                   .strip().lower())
    if cc:
        if cc not in TUIC_CC:
            n.notes.append(f"congestion_control={cc[:20]!r} → cubic")
            cc = "cubic"
    n.cc = cc or "cubic"
    urm = trim_enum(_q(q, "udp_relay_mode", "udprelaymode").strip().lower())
    if urm:
        if urm not in TUIC_URM:
            n.notes.append(f"udp_relay_mode={urm[:20]!r} → native")
            urm = "native"
    n.urm = urm or "native"
    n.uds = as_bool(_q(q, "udp_over_stream", "udp-over-stream", "udpoverstream"), n)
    n.zrtt = as_bool(_q(q, "reduce_rtt", "reducertt",
                        "zero_rtt_handshake", "zerortthandshake"), n)
    n.dsni = as_bool(_q(q, "disable_sni", "disablesni"), n)
    hbeat = _q(q, "heartbeat").strip()
    if hbeat:
        if re.fullmatch(r"\d+", hbeat):
            n.hbeat = f"{hbeat}s"
            n.notes.append(f"heartbeat={hbeat} → {hbeat}s (добавлена секунда)")
        elif re.fullmatch(r"\d+(?:\.\d+)?(?:ms|s|m|h)", hbeat):
            n.hbeat = hbeat
        else:
            n.notes.append(f"нечитаемый heartbeat удалён ({hbeat[:20]!r})")
    unk = sorted(k for k in q if k not in TUIC_KNOWN)
    if unk:
        n.notes.append("неизвестные параметры удалены: " + ",".join(unk[:12]))
    return n


def parse_vmess(s):
    """vmess:// зашифрован целиком: base64 -> JSON или legacy-строка."""
    n = Node("vmess")
    data = strip_fragment(preprocess(s))[s.index("://") + 3:]
    if "?" in data:
        data = data.split("?", 1)[0]
    data = data.strip().strip("/")
    if data.lstrip().startswith("{"):
        return vmess_json(n, data.lstrip())
    for attempt in range(2):
        dec = b64d(data)
        if dec is None:
            for cut in (1, 2, 3, 4):            # мусорный хвост base64 (…fQ==2, …Cn1ss)
                if len(data) > cut + 8:
                    dec = b64d(data[:-cut])
                    if dec is not None:
                        n.notes.append(f"мусорный хвост base64 обрезан ({cut})")
                        break
        if dec is None:
            raise Rej("тело не является base64")
        try:
            text = dec.decode("utf-8")
        except Exception:
            raise Rej("base64-тело не UTF-8")
        t = text.strip()
        if t.startswith("{"):
            return vmess_json(n, t)
        if UUID_RE.match(t):
            t2, q = _split_query(t)
            return vmess_legacy(n, t2, q)
        if attempt == 0 and re.fullmatch(r"[A-Za-z0-9+/=_\-]{8,}", t):
            data = t                            # двойное base64 — пробуем ещё раз
            continue
        raise Rej("формат vmess не распознан (ни JSON, ни uuid@host)")


def vmess_json(n, text):
    """Разбор vmess-JSON (поля читаются регистронезависимо)."""
    try:
        j = json.loads(text)
    except Exception as e:
        raise Rej(f"JSON невалиден: {e}")
    if not isinstance(j, dict):
        raise Rej("JSON — не объект")
    low = {}
    for k, v in j.items():
        lk = str(k).lower()
        if lk not in low:
            low[lk] = v

    def g(*keys, d=""):
        for k in keys:
            v = low.get(k.lower())
            if v is not None and str(v).strip() != "":
                return str(v).strip()
        return d

    n.host = check_host(g("add", "address", "server"))
    port = g("port", "p")
    if not port.isdigit():
        raise Rej(f"неверный порт: {port[:20]!r}")
    p = int(port)
    if not MIN_PORT <= p <= 65535:
        raise Rej(f"порт вне диапазона: {p} (допустимо {MIN_PORT}–65535)")
    n.port = p
    idv = g("id", "uuid", "user")
    try:
        n.uuid = str(uuidlib.UUID(idv))
    except Exception:
        raise Rej(f"id не UUID: {idv[:48]!r}")
    aid = g("aid", "alterid", "alter_id") or "0"
    if not aid.isdigit():
        n.notes.append("alterId невалиден → 0")
        aid = "0"
    n.aid = int(aid)
    scy = g("scy", "security", "cipher").lower() or "auto"
    if scy not in VMESS_SCY:
        n.notes.append(f"шифр {scy[:20]!r} → auto")
        scy = "auto"
    n.scy = scy
    tlsraw = g("tls").lower()
    if tlsraw in ("", "none", "0", "false"):
        sec = "none"
    elif tlsraw in ("tls", "1", "true"):
        sec = "tls"
    elif tlsraw == "reality":
        sec = "reality"
    elif tlsraw == "xtls":
        sec = "xtls"
    elif tlsraw == "auto":
        sec = "tls" if (p == 443 or g("sni", "sn", "servername")) else "none"
        n.notes.append(f"tls=auto → {sec}")
    else:
        raise Rej(f"неизвестный tls={tlsraw[:20]!r}")
    # vmess-JSON собирается в единый словарь параметров и разбирается
    # общим fill_transport(); "type" в JSON — это headerType, сеть идёт в "net"
    q = {"type": g("net", "network") or "tcp", "security": sec,
         "host": g("host"), "path": g("path"),
         "sni": g("sni", "sn", "servername"), "alpn": g("alpn"),
         "fp": g("fp", "fingerprint"), "pbk": g("pbk", "publickey"),
         "sid": g("sid", "shortid"), "spx": g("spx", "spiderx"),
         "servicename": g("servicename", "service"), "mode": g("mode"),
         "seed": g("seed"), "ed": g("ed"), "eh": g("eh"),
         "headertype": g("type") or "none", "authority": g("authority"),
         "extra": g("extra")}
    fill_transport(n, q, "none")
    ai = g("allowinsecure", "allowlnsecure", "allow_insecure", "insecure",
           "skip-cert-verify", "skipcertverify")
    if ai != "":
        n.insecure = as_bool(ai, n)
    return n


def vmess_legacy(n, t, q):
    """Разбор строки вида vmess://uuid@host:port?params (редкий вариант)."""
    cred, _, hostport = t.partition("@")
    try:
        n.uuid = str(uuidlib.UUID(cred.strip()))
    except Exception:
        raise Rej(f"id не UUID: {cred[:48]!r}")
    n.host, n.port = parse_hostport(hostport.strip())
    scy = _q(q, "encryption", "scy").lower() or "auto"
    if scy not in VMESS_SCY:
        n.notes.append(f"encryption={scy[:20]!r} → auto")
        scy = "auto"
    n.scy = scy
    fill_transport(n, q, "none")
    return n


PARSERS = {"vless": parse_vless, "trojan": parse_trojan, "vmess": parse_vmess,
           "ss": parse_ss, "hysteria2": parse_hy2, "tuic": parse_tuic}


def _host_kind(h):
    """Категория адреса для статистики: v4 / v6 / домен."""
    try:
        return "v4" if ipaddress.ip_address(h).version == 4 else "v6"
    except ValueError:
        return "dom"

# =========================================================================
# 8. КАНОНИЧЕСКАЯ СБОРКА ССЫЛОК (build_uri)
# =========================================================================
# Ссылка собирается заново только из проверенных полей Node: имена,
# комментарии и мусор не переносятся, значения процентно кодируются.
# В конце дописывается пустой фрагмент '#': каждая строка выхода
# заканчивается '#' (разделитель имени, который клиенты отбрасывают).
def build_uri(n):
    if n.proto == "vmess":
        if n.net in ("ws", "http", "httpupgrade", "xhttp"):
            path, host = n.path or "/", n.hhost
        elif n.net == "grpc":
            # парсер vmess в ядре берёт имя grpc-сервиса из поля host,
            # v2rayNG — из path: пишем оба
            path, host = n.service or "", n.service or ""
        elif n.net == "tcp" and n.htype == "http":
            path, host = n.path or "/", n.hhost
        else:
            path, host = "", ""
        if n.net == "ws" and n.ed:
            path = (path or "/") + ("&" if "?" in path else "?") + f"ed={n.ed}"
        j = {"v": "2", "ps": "", "add": n.host, "port": str(n.port), "id": n.uuid,
             "aid": str(n.aid), "scy": n.scy, "net": {"http": "h2"}.get(n.net, n.net),
             "type": n.htype or "none", "host": host, "path": path,
             "tls": "tls" if n.sec == "tls" else "reality" if n.sec == "reality" else ""}
        if n.sni:
            j["sni"] = n.sni
        if n.alpn:
            j["alpn"] = ",".join(n.alpn)
        if n.fp and not DROP_FP:
            j["fp"] = n.fp
        if n.sec == "reality":
            j["pbk"] = n.pbk
            if n.sid:
                j["sid"] = n.sid
            if n.spx:
                j["spx"] = n.spx
        if n.net == "xhttp" and n.mode:
            j["mode"] = n.mode
        if n.net == "kcp" and n.seed:
            j["seed"] = n.seed
        if n.insecure:
            # ядро читает только insecure/skip-cert-verify, v2rayNG —
            # allowInsecure: пишем оба имени одного флага
            j["allowInsecure"] = 1
            j["insecure"] = 1
        blob = base64.b64encode(json.dumps(j, ensure_ascii=False,
                                           separators=(",", ":")).encode()).decode()
        return "vmess://" + blob + "#"
    if n.proto == "ss":
        ui = base64.urlsafe_b64encode(f"{n.method}:{n.password}".encode()).decode().rstrip("=")
        qs = f"?plugin={_enc(n.plugin)}" if n.plugin else ""
        return f"ss://{ui}@{fh(n.host)}:{n.port}{qs}#"
    if n.proto == "hysteria2":
        prm = []
        if n.sni:
            prm.append(("sni", n.sni))
        if n.fp and not DROP_FP:
            prm.append(("fp", n.fp))
        if n.insecure:
            prm.append(("insecure", "1"))
        if n.alpn:
            prm.append(("alpn", ",".join(n.alpn)))
        if n.obfs:
            prm += [("obfs", n.obfs), ("obfs-password", n.obfsp)]
        if n.pins:
            prm.append(("pinSHA256", ",".join(n.pins)))
        if n.mport:
            prm.append(("mport", n.mport))
        if n.upm:
            prm.append(("upmbps", n.upm))
        if n.dnm:
            prm.append(("downmbps", n.dnm))
        if n.hop:
            prm.append(("hop_interval", n.hop))
        qs = "&".join(f"{k}={_enc(v)}" for k, v in prm)
        return (f"hysteria2://{_enc(n.password)}@{fh(n.host)}:{n.port}"
                + (f"?{qs}" if qs else "") + "#")
    if n.proto == "tuic":
        # канон: v5-формат uuid:password, дефолтные cubic/native не пишутся —
        # round-trip (разбор собственного вывода) даёт тот же отпечаток
        prm = []
        if n.sni:
            prm.append(("sni", n.sni))
        if n.alpn:
            prm.append(("alpn", ",".join(n.alpn)))
        if n.insecure:
            # флаг пишется под обоими именами: ядро и конвертер читают
            # allow_insecure, ряд клиентов и панелей — insecure
            prm += [("allow_insecure", "1"), ("insecure", "1")]
        if n.cc and n.cc != "cubic":
            prm.append(("congestion_control", n.cc))
        if n.urm and n.urm != "native":
            prm.append(("udp_relay_mode", n.urm))
        if n.uds:
            prm.append(("udp_over_stream", "1"))
        if n.zrtt:
            prm.append(("reduce_rtt", "1"))
        if n.hbeat:
            prm.append(("heartbeat", n.hbeat))
        if n.dsni:
            prm.append(("disable_sni", "1"))
        qs = "&".join(f"{k}={_enc(v)}" for k, v in prm)
        return (f"tuic://{_enc(n.uuid)}:{_enc(n.password)}@{fh(n.host)}:{n.port}"
                + (f"?{qs}" if qs else "") + "#")
    creds = n.uuid if n.proto == "vless" else _enc(n.password)
    # encryption=none и type=tcp — дефолты, которые клиенты подставляют
    # сами при отсутствии параметра: при включённом drop_defaults они
    # не выводятся. Не-дефолтные значения (PQ-шифрование vless,
    # транспорт ws/grpc/…) сохраняются всегда.
    prm = []
    if n.proto == "vless" and (n.venc or not DROP_DEFAULTS):
        prm.append(("encryption", n.venc if n.venc else "none"))
    if n.flow:
        prm.append(("flow", n.flow))
    prm.append(("security", n.sec))
    if n.sni:
        prm.append(("sni", n.sni))
    if n.alpn:
        prm.append(("alpn", ",".join(n.alpn)))
    if n.fp and not DROP_FP:
        prm.append(("fp", n.fp))
    if n.sec == "reality":
        prm.append(("pbk", n.pbk))
        if n.sid:
            prm.append(("sid", n.sid))
        if n.spx:
            prm.append(("spx", n.spx))
    if n.insecure:
        # флаг небезопасной проверки сертификата пишется под обоими именами:
        # ядро у vless понимает только insecure/skip-cert-verify, v2rayNG
        # и конвертер чекера — allowInsecure
        prm.append(("allowInsecure", "1"))
        prm.append(("insecure", "1"))
    if n.net != "tcp" or not DROP_DEFAULTS:
        prm.append(("type", n.net))
    if n.net == "ws":
        prm.append(("path", n.path or "/"))
        if n.hhost:
            prm.append(("host", n.hhost))
        if n.ed is not None:
            prm.append(("ed", str(n.ed)))
        if n.eh:
            prm.append(("eh", n.eh))
    elif n.net in ("http", "httpupgrade", "xhttp"):
        prm.append(("path", n.path or "/"))
        hh = n.authority or n.hhost
        if hh:
            prm.append(("host", hh))
        if n.net == "xhttp" and n.mode:
            prm.append(("mode", n.mode))
        if n.extra:
            prm.append(("extra", n.extra))
    elif n.net == "grpc":
        # у trojan ядро ищет grpc-сервис в параметре grpc-service-name,
        # а serviceName трактует как SNI — такое значение ломало бы
        # проверку сертификата; у vless canonical — serviceName
        prm.append(("grpc-service-name" if n.proto == "trojan" else "serviceName",
                    n.service or ""))
        if n.mode:
            prm.append(("mode", n.mode))
    elif n.net == "tcp" and n.htype == "http":
        prm += [("headerType", "http"), ("path", n.path or "/")]
    elif n.net == "kcp":
        if n.htype != "none":
            prm.append(("headerType", n.htype))
        if n.seed:
            prm.append(("seed", n.seed))
    if n.pkte:
        prm.append(("packetEncoding", n.pkte))
    if n.ech:
        prm.append(("ech", n.ech))
    qs = "&".join(f"{k}={_enc(v)}" for k, v in prm)
    return f"{n.proto}://{creds}@{fh(n.host)}:{n.port}?{qs}#"


# =========================================================================
# 9. ОТПЕЧАТКИ УЗЛОВ И ДЕДУПЛИКАЦИЯ
# =========================================================================
# Уровни строгости (exclave → nekobox → incy → full) описаны в
# докстринге node_fingerprint. Ключ уровня — кортеж значимых полей
# после нормализации, свёрнутый в 16-байтовый дайджест. Косметика
# (имя в #, регистр имён, порядок параметров, fp) узел не различает
# ни на одном уровне: поля spx/sid различают только при выключенных
# drop_spx/drop_sid, а fp в списках полей нет вовсе — после чистки
# он у всех одинаковый.
# числа дедупликации.
FP_FIELDS_FULL = (
    "proto", "host", "port", "uuid", "password", "method", "scy", "aid",
    "venc", "flow", "net", "sec", "sni", "hostp", "path",
    "service", "mode", "htype", "seed", "qsec", "qkey", "ed", "eh", "pbk",
    "sid", "spx", "ech", "alpn", "insecure", "plugin", "obfs", "obfsp",
    "pins", "mport", "upm", "dnm", "hop", "pkte", "extra",
    "cc", "urm", "uds", "zrtt", "hbeat", "dsni",
)


def _norm_extra(ex):
    """JSON extra канонизируется: порядок ключей и пробелы не важны."""
    if not ex:
        return ""
    try:
        return json.dumps(json.loads(ex), ensure_ascii=False,
                          separators=(",", ":"), sort_keys=True)
    except Exception:
        return ex


def _norm_mport(m):
    """mport — список портов/диапазонов: порядок элементов не важен."""
    if not m:
        return ""
    return ",".join(sorted(p.strip() for p in m.split(",") if p.strip()))


def _cred_core(n):
    """Учётные данные узла для мягких уровней дедупликации."""
    if n.proto == "vless":
        return (n.uuid, n.venc, n.flow)
    if n.proto == "vmess":
        return (n.uuid, n.aid, n.scy)
    if n.proto == "ss":
        return (n.method, n.password)
    if n.proto == "tuic":
        return (n.uuid, n.password)
    return (n.password,)          # trojan, hysteria2


def _host_param(n):
    """Host-параметр транспорта так, как его реально пишет build_uri.

    У grpc и «голого» tcp заголовок в вывод не попадает; у vmess-grpc
    host дублирует имя grpc-сервиса; у http-подобных транспортов
    authority сливается с hhost. Отпечаток обязан совпадать там, где
    совпадает вывод, иначе в clean.txt появятся буквальные дубли.
    """
    if n.proto == "vmess":
        return n.hhost.lower() if n.net in ("ws", "http", "httpupgrade",
                                            "xhttp") or (
            n.net == "tcp" and n.htype == "http") else ""
    if n.net == "ws":
        return n.hhost.lower()
    if n.net in ("http", "httpupgrade", "xhttp"):
        return (n.authority or n.hhost).lower()
    return ""          # grpc, tcp (в т.ч. http-заголовок), kcp


def node_identity(n):
    """Поля узла в нормализованном виде — база отпечатка.

    Проекция повторяет правила build_uri: в отпечаток идут только те
    поля, которые попадают в канонический вывод. Всё, что вывод
    теряет (например eh/extra у vmess), узел различать не должно.
    """
    vmess = n.proto == "vmess"
    return {
        "proto": n.proto,
        "host": n.host,                      # уже нормализован в check_host
        "port": n.port,
        "uuid": n.uuid.lower(),
        "password": n.password,
        "method": n.method,
        "scy": n.scy,
        "aid": n.aid,
        "venc": n.venc,
        "flow": n.flow,
        "net": n.net,
        "sec": n.sec,
        "sni": n.sni.lower(),                # DNS-имена нечувствительны к регистру
        "hostp": _host_param(n),             # host/authority как в выводе
        "path": n.path,
        "service": n.service,
        "mode": n.mode,
        "htype": n.htype,
        "seed": n.seed,
        "qsec": n.qsec.lower(),
        "qkey": n.qkey,
        # ed=0 == без early data; параметр ed в вывод попадает только
        # у ws (см. build_uri) — для остальных транспортов ed выводом
        # теряется и узел различать не должен
        "ed": None if (n.ed == 0 or n.net != "ws") else n.ed,
        "eh": "" if vmess else n.eh.lower(), # имя HTTP-заголовка регистронезависимо
        "pbk": n.pbk,
        "sid": n.sid,
        "spx": n.spx,
        "ech": "" if vmess else n.ech,
        "alpn": tuple(sorted(n.alpn)),       # порядок протоколов не важен
        "insecure": n.insecure,
        "plugin": n.plugin,
        "obfs": n.obfs,
        "obfsp": n.obfsp,
        "pins": tuple(sorted(n.pins)),
        "mport": _norm_mport(n.mport),
        "upm": n.upm,
        "dnm": n.dnm,
        "hop": n.hop,
        "pkte": "" if vmess else n.pkte,
        "extra": "" if vmess else _norm_extra(n.extra),
        "cc": n.cc,
        "urm": n.urm,
        "uds": n.uds,
        "zrtt": n.zrtt,
        "hbeat": n.hbeat,
        "dsni": n.dsni,
    }


def node_fingerprint(n, scope="nekobox"):
    """Отпечаток узла для заданного уровня строгости дедупликации.

    Уровни упорядочены от самого жёсткого (максимальное схлопывание) к
    самому мягкому; каждый следующий добавляет свою группу полей к ключу
    предыдущего, поэтому число конфигов с уровня на уровень только
    растёт:

      exclave  — «Сильный»: протокол + адрес:порт. Один сервер — один
                  конфиг: учётка, транспорт, SNI и прочие параметры
                  подключения не сравниваются;
      nekobox  — «Оптимальный»: плюс учётные данные (uuid/пароль, метод
                  ss, scy/aid vmess, flow/encryption vless), mode
                  grpc/xhttp и spx reality; TLS-контекст (SNI, pbk/sid)
                  и транспорт не сравниваются; при включённом drop_spx
                  поле spx пусто и не различает;
      incy     — «Стандартный»: плюс SNI, sid reality и packetEncoding;
                  при включённом drop_sid поле sid пусто и не различает;
      full     — «Слабый»: все параметры подключения — сверху добавляются
                  транспорт и TLS-контекст, extra, пропускная способность
                  и hop_interval hysteria2; схлопывания нет, конфиги
                  остаются даже при мелких различиях. Единственное
                  исключение — spx/sid при включённых drop-настройках:
                  поля удалены на разборе и пусты у всех узлов, поэтому
                  различие только в них схлопывается и здесь.

    fp исключён на всех уровнях: после чистки он у всех одинаковый, к
    подключаемости отношения не имеет. Результат — 16-байтовый дайджест
    blake2b: компактен в памяти, шанс коллизии пренебрежим.
    """
    i = node_identity(n)
    if scope == "exclave":
        core = (i["proto"], i["host"], i["port"])
    elif scope == "nekobox":
        core = ((i["proto"], i["host"], i["port"]) + _cred_core(n)
                + (i["mode"], i["spx"]))
    elif scope == "incy":
        core = ((i["proto"], i["host"], i["port"]) + _cred_core(n)
                + (i["mode"], i["spx"])
                + (i["sni"], i["sid"], i["pkte"]))
    else:                    # full — все параметры подключения
        core = tuple(i[k] for k in FP_FIELDS_FULL)
    return hashlib.blake2b(repr(core).encode("utf-8", "replace"),
                           digest_size=16).digest()


# =========================================================================
# 10. ФИЛЬТРЫ ЧИСТКИ: БЕЗОПАСНОСТЬ И СОВМЕСТИМОСТЬ
# =========================================================================
# ---- Фильтр небезопасных конфигов (reject_insecure, reject_no_tls) -----
# Вызывается в воркере сразу после разбора ссылки, поэтому правило
# работает во всех режимах чистки — и в одиночном цикле, и в конвейере.


def security_filter(n):
    """Отсекает небезопасные конфиги по настройкам reject_*.

    reject_insecure — allowInsecure=1 (и все синонимы, которые читают
    клиенты): клиент отключает проверку сертификата, канал вскрывается
    MITM-подменой. reject_no_tls — нет шифрования канала: это
    vless/vmess/trojan с security=none (отсутствие security у vless/
    vmess — тоже none; у trojan TLS — часть протокола). hysteria2 и
    tuic всегда поверх QUIC+TLS, а защищённость ss определяется
    методом шифрования — их фильтр не трогает.
    """
    if REJECT_INSECURE and n.insecure:
        raise Rej("allowInsecure=1 — отбракован настройкой reject_insecure")
    if REJECT_NO_TLS and n.proto in ("vless", "vmess", "trojan") \
            and n.sec == "none":
        raise Rej("нет TLS (security=none) — отбракован настройкой reject_no_tls")


# ---- Фильтр совместимости с чекером и ядром -----------------------------
# Зеркало правил конвертера Sing-Box_Checker.py (цель — ядро
# sing-box-extended): всё, на чём конвертер бросает LinkError («не
# смог конвертировать»), отсекается здесь — до чекера доезжают только
# конвертируемые конфиги. Проверяется то, что build_uri реально
# пишет в выходную ссылку; ограничения ядра, которые можно починить
# на стороне сборщика, уже учтены в build_uri.
def _rawurl_b64_len(seg):
    """Длина декода сегмента как base64.RawURLEncoding (зеркало чекера)."""
    if not re.fullmatch(r"[A-Za-z0-9_-]*", seg) or len(seg) % 4 == 1:
        return None
    try:
        return len(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))
    except Exception:
        return None


def _checker_padding_seg(seg, idx):
    """Зеркало ParsePadding ядра: 'X-Y-Z', первый сегмент >= 100/35/35."""
    bad = (f"не конвертируется чекером: битый padding-сегмент encryption: "
           f"{seg[:40]!r}")
    x = seg.split("-")
    if len(x) < 3 or not x[0] or not x[1] or not x[2]:
        raise Rej(bad)
    try:
        y0, y1, y2 = int(x[0]), int(x[1]), int(x[2])
    except ValueError:
        raise Rej(bad)
    if idx == 0 and (y0 < 100 or y1 < 35 or y2 < 35):
        raise Rej("не конвертируется чекером: первый padding encryption "
                  "< 100/35/35")
    return max(y1, y2) if idx % 2 == 0 else 0


def _checker_encryption(enc):
    """Зеркало _validate_client_encryption чекера (vless encryption=…).

    Ядро принимает только mlkem768x25519plus.<режим>.<rtt>.<ключи>:
    сегменты — base64url-ключи 32/1184 байта или padding 'X-Y-Z'
    до первого ключа."""
    parts = enc.strip().split(".")
    if len(parts) < 4:
        raise Rej(f"не конвертируется чекером: encryption без компонентов: {enc[:60]}")
    if parts[0] != "mlkem768x25519plus":
        raise Rej(f"не конвертируется чекером: encryption {parts[0]!r} — "
                  "ядро знает только mlkem768x25519plus")
    if parts[1] not in ("native", "xorpub", "random"):
        raise Rej(f"не конвертируется чекером: encryption mode={parts[1]!r}")
    if parts[2] not in ("0rtt", "1rtt"):
        raise Rej(f"не конвертируется чекером: encryption rtt={parts[2]!r}")
    has_key, padding_phase, max_len, pad_idx = False, True, 0, 0
    for seg in parts[3:]:
        seg = seg.strip()
        if not seg:
            raise Rej("не конвертируется чекером: пустой сегмент encryption")
        ln = _rawurl_b64_len(seg)
        if ln is not None:
            if ln in (32, 1184):
                has_key, padding_phase = True, False
                continue
            raise Rej(f"не конвертируется чекером: ключ encryption {ln} байт "
                      "(нужен 32 или 1184)")
        if padding_phase:
            max_len += _checker_padding_seg(seg, pad_idx)
            pad_idx += 1
            continue
        raise Rej(f"не конвертируется чекером: ключ encryption после "
                  f"padding: {seg[:40]!r}")
    if not has_key:
        raise Rej("не конвертируется чекером: encryption без ключей")
    if max_len > 18 + 65535:
        raise Rej("не конвертируется чекером: суммарный padding encryption > 65553")


def _checker_b64_any(s):
    """Зеркало _b64decode_any чекера: bytes или None (у чекера — LinkError)."""
    s = s.strip().replace("\n", "").replace("\r", "")
    variants = [s, s.replace("-", "+").replace("_", "/"),
                s.replace("-", "_").replace("+", "-")]
    for v in variants:
        for cand in (v, v + "=" * (-len(v) % 4)):
            try:
                return base64.b64decode(cand, validate=False)
            except Exception:
                continue
    return None


def _checker_ss_rebuild_ok(method, password):
    """Повторяет путь конвертера чекера по пересобранной ss-ссылке.

    build_uri пишет ss://b64url(method:password)@host:port — чекер
    декодирует блоб и пытается развернуть «вложенное» кодирование.
    Если пароль содержит '@' и повторное декодирование падает,
    ссылка теряется. True — чекер получит method/password.
    """
    decoded = f"{method}:{password}"
    for _ in range(3):
        s = decoded.strip()
        if s.lower().startswith("ss://"):
            s = s[5:]
        if "://" in s:
            break
        if ":" in s and "@" not in s:
            break
        nxt = _checker_b64_any(s)
        if nxt is None:
            return False          # LinkError чекера → ссылка потеряна
        nxt = nxt.decode("utf-8", "replace")
        if not nxt or not re.fullmatch(r"[\x20-\x7e]+", nxt):
            break                 # дальше мусор — чекер оставляет decoded
        decoded = nxt
    if re.match(r"^([^:@]+):([^@]*)@([^:@]+):(\d+)$", decoded):
        return True               # legacy-сальвация чекера (весь @host:port)
    return ":" in decoded


def checker_compat(n):
    """Отсекает конфиги, которые конвертер чекера отклонит (LinkError).

    Точные условия конвертера для полей, попадающих в выходную
    ссылку: vless encryption, reality pbk (алфавит base64url),
    методы ss и структура пароля ss2022. Остальное чекер чинит сам
    при конвертации — такие конфиги остаются в чистке.
    """
    if n.proto == "vless" and n.venc:
        _checker_encryption(n.venc)
    if n.sec == "reality" and n.pbk:
        # 32 байта уже проверены в fill_transport; чекер строже: ровно 43
        # символа base64url после снятия '=' (std-base64 с '+/' ядро
        # FATAL-ит 'invalid public_key')
        if not re.fullmatch(r"[A-Za-z0-9_-]{43}", n.pbk.rstrip("=")):
            raise Rej("не конвертируется чекером: pbk не 43-символьный "
                      "base64url-ключ X25519")
    if n.proto == "ss":
        method = CHECKER_SS_ALIAS.get(n.method, n.method)
        if method not in CHECKER_SS_METHODS:
            raise Rej(f"не конвертируется чекером: метод ss {n.method[:40]!r} "
                      "не вшит в конвертер (ядро его поддерживает)")
        if not _checker_ss_rebuild_ok(n.method, n.password):
            raise Rej("не конвертируется чекером: пароль ss ломает "
                      "разворачивание base64 в конвертере ('@' в пароле)")
        if method.startswith("2022-"):
            parts = n.password.split(":")
            if len(parts) > 2:
                raise Rej("не конвертируется чекером: ss2022 — более одного "
                          "':' в пароле")
            if len(parts) == 2 and "chacha20" in method:
                raise Rej("не конвертируется чекером: ss2022 EIH (iPSK) "
                          "только для AES-методов")
            want = 16 if method.endswith("aes-128-gcm") else 32
            for kp in parts:
                try:
                    raw = base64.b64decode(kp, validate=True)
                except Exception:
                    raise Rej(f"не конвертируется чекером: ss2022 ключ не "
                              f"std-base64: {kp[:12]}…")
                if len(raw) != want:
                    raise Rej(f"не конвертируется чекером: ss2022 ключ "
                              f"{len(raw)} байт, требуется {want}")


# =========================================================================
# 11. ВОРКЕР И ПУЛ ПРОЦЕССОВ
# =========================================================================
def _keep_name(raw):
    """Имя конфига из фрагмента после '#' (настройка clean_name = Нет).

    Процентное кодирование разворачивается — клиенты показывают имя
    раскодированным, управляющие символы и переводы строк выкидываются:
    имя не должно ломать строку выходного файла. Слишком длинные имена
    обрезаются — в подписках встречаются хвосты на тысячи символов.
    """
    s = raw
    for _ in range(2):
        if "%" not in s:
            break
        u = unquote(s)
        if u == s:
            break
        s = u
    s = re.sub(r"[\x00-\x1f\x7f]", "", s).strip()
    return s[:256]


def worker(batch):
    """Обрабатывает кусок строк: (номер, строка) -> список записей.

    Запись «kept» — конфиг прошёл чистку, уходит в дедупликацию:
        ("k", номер, каноническая строка, пометки правок одним текстом,
         мета (протокол, транспорт, security, тип адреса, порт),
         короткий слепок входной строки, отпечаток узла, был ли fp)
    Запись «reject» — строка отбракована, нужна только для статистики:
        ("r", номер, причина, протокол, входная строка)

    Вместо полного входа в «kept» кладётся 8-байтовый слепок: он нужен
    только чтобы отличить точный дубль от нормализованного, а тащить
    всю строку — зря раздувать память и передачу в пул.
    """
    out = []
    for line_no, line in batch:
        proto = "?"
        name = ""
        if not CLEAN_NAME:
            # имя после '#' оставляем в выводе (настройка clean_name выключена)
            i = line.find("#")
            if i >= 0:
                name = _keep_name(line[i + 1:])
        try:
            m = SCHEME_RE.match(line)
            if not m:
                raise Rej("строка не является URI (нет схемы)")
            raw = m.group(1).lower()
            proto = SCHEME_ALIAS.get(raw, raw)
            if proto not in ACCEPTED:
                raise Rej(f"протокол '{raw}' не поддерживается")
            n = PARSERS[proto](line)
            security_filter(n)      # отсев небезопасных (reject_insecure/no_tls)
            if CHECKER_FILTER:
                checker_compat(n)   # отсев того, что не конвертирует чекер
            canon = build_uri(n)
            if name:
                canon += name          # каноническая ссылка всегда кончается '#'
            meta = (proto, n.net, n.sec, _host_kind(n.host), n.port)
            fp = node_fingerprint(n, DUP_SCOPE)
            odig = hashlib.blake2b(line.encode("utf-8", "replace"),
                                   digest_size=8).digest()
            out.append(("k", line_no, canon, "\n".join(n.notes), meta,
                        odig, fp, bool(n.fp)))
        except Rej as e:
            out.append(("r", line_no, str(e), proto, line))
        except Exception as e:
            out.append(("r", line_no, f"внутренняя ошибка: {type(e).__name__}: {e}", proto, line))
    return out


def _worker_init(fp_value, add_fp_for_reality, reject_private=True, reject_dns=True,
                 dup_scope="nekobox", checker_filter=True, reject_mkcp=False,
                 reject_insecure=True, reject_no_tls=True, reject_ipv6=False,
                 drop_spx=True, drop_sid=True, drop_fp=False, drop_defaults=True,
                 clean_name=True):
    """Задаёт правила чистки в каждом процессе пула.

    Настройки передаются явно: на Windows воркеры рождаются заново через
    spawn и правки глобальных переменных родителя не видят.
    """
    # Воркеры игнорируют CTRL+C: сигнал приходит всей группе процессов,
    # и воркер, убитый посреди чтения очереди задач, оставляет её семафор
    # захваченным — пересозданный воркер вешается на нём навсегда, и пул
    # перестаёт принимать задачи. Остановкой рулит родитель: он аккуратно
    # забирает результаты, а воркеры спокойно дожимают текущую задачу.
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    global FP_VALUE, ADD_FP_FOR_REALITY, REJECT_PRIVATE, REJECT_DNS, DUP_SCOPE
    global CHECKER_FILTER, REJECT_MKCP, REJECT_INSECURE, REJECT_NO_TLS, REJECT_IPV6
    global DROP_SPX, DROP_SID, DROP_FP, DROP_DEFAULTS, CLEAN_NAME
    FP_VALUE = fp_value
    ADD_FP_FOR_REALITY = add_fp_for_reality
    REJECT_PRIVATE = reject_private
    REJECT_DNS = reject_dns
    DUP_SCOPE = dup_scope
    CHECKER_FILTER = checker_filter
    REJECT_MKCP = reject_mkcp
    REJECT_INSECURE = reject_insecure
    REJECT_NO_TLS = reject_no_tls
    REJECT_IPV6 = reject_ipv6
    DROP_SPX = drop_spx
    DROP_SID = drop_sid
    DROP_FP = drop_fp
    DROP_DEFAULTS = drop_defaults
    CLEAN_NAME = clean_name


# Пул живёт между циклами чистки: пересоздаётся только когда меняются
# настройки, от которых зависит инициализация воркеров.
_POOL = None
_POOL_KEY = None


def _pool_key():
    """Слепок настроек, от которых зависит инициализация воркеров."""
    return (WORKERS, FP_VALUE, ADD_FP_FOR_REALITY, REJECT_PRIVATE,
            REJECT_DNS, DUP_SCOPE, CHECKER_FILTER, REJECT_MKCP,
            REJECT_INSECURE, REJECT_NO_TLS, REJECT_IPV6, DROP_SPX, DROP_SID,
            DROP_FP, DROP_DEFAULTS, CLEAN_NAME)


def _get_pool():
    """Пул текущего размера с актуальными правилами чистки."""
    global _POOL, _POOL_KEY
    key = _pool_key()
    if _POOL is not None and _POOL_KEY != key:
        _drop_pool()
    if _POOL is None:
        _POOL = mp.Pool(WORKERS, initializer=_worker_init,
                        initargs=(FP_VALUE, ADD_FP_FOR_REALITY, REJECT_PRIVATE,
                                  REJECT_DNS, DUP_SCOPE, CHECKER_FILTER,
                                  REJECT_MKCP, REJECT_INSECURE, REJECT_NO_TLS,
                                  REJECT_IPV6, DROP_SPX, DROP_SID, DROP_FP,
                                  DROP_DEFAULTS, CLEAN_NAME))
        _POOL_KEY = key
    return _POOL


def _drop_pool():
    """Гасит пул (при ошибке или смене правил) — процессы завершатся сами."""
    global _POOL, _POOL_KEY
    if _POOL is not None:
        try:
            _POOL.terminate()
        except Exception:
            pass
    _POOL = None
    _POOL_KEY = None


def _task_size() -> int:
    """Строк в одной задаче пула.

    Размер из настроек режется потолком TASK_CAP: задача на 100 000 строк
    держит в памяти десятки мегабайт входа и результата, и таких задач
    может быть сразу несколько в полёте. Потолок держит потребление
    памяти предсказуемым, а скорость не трогает — разбор строки всё
    равно дороже передачи куска в пул.
    """
    return max(100, min(CHUNK, TASK_CAP))


# =========================================================================
# 12. ЦИКЛ ЧИСТКИ
# =========================================================================
def _fmt(n) -> str:
    """1234567 -> '1 234 567' — для панели и строки статуса."""
    try:
        return f"{int(n):,}".replace(",", " ")
    except (TypeError, ValueError):
        return str(n)


def _fmt_elapsed(sec: float) -> str:
    """Секунды в человеческий срок: '42 с', '5 мин 07 с', '2 ч 05 мин', '1 д 03 ч'.

    Сокращения без склонений — формат растёт сам собой: секунды видны
    только в первую минуту, дальше часы и дни.
    """
    d, rem = divmod(max(0, int(sec)), 86400)
    h, rem = divmod(rem, 3600)
    m, s = divmod(rem, 60)
    if d:
        return f"{d} д {h:02d} ч"
    if h:
        return f"{h} ч {m:02d} мин"
    if m:
        return f"{m} мин {s:02d} с"
    return f"{s} с"


def _progress_line(done, total, processed, unique, dups, rej) -> None:
    """Живая строка прогресса — один формат для одиночного цикла и конвейера:

    |████░░░░░░░░░░░░░░░░|   7% | Обработано: … | Очищенных: … | Дубликаты: … | Отброшено: …

    «Обработано» сюда приходит уже посчитанным как уникальные + дубли +
    отбраковка, поэтому сумма счётчиков сходится в любой момент, даже
    когда хвост строк ещё крутится в воркерах. Если строка не влезает в
    терминал, части убираются справа налево.
    """
    bar = con.bar(done, total)
    pct = con.paint(f"{int(done / max(1, total) * 100):4d}%", "cyan", bold=True)
    p = con.paint(f"Обработано: {_fmt(processed)}", "cyan")
    u = con.paint(f"Очищенных: {_fmt(unique)}", "green")
    d = con.paint(f"Дубликаты: {_fmt(dups)}", "yellow")
    r = con.paint(f"Отброшено: {_fmt(rej)}", "red")
    variants = [
        f"{bar} {pct} | {p} | {u} | {d} | {r}",
        f"{bar} {pct} | {p} | {u} | {r}",
        f"{bar} {pct} | {u} | {r}",
    ]
    limit = con._width() - 2
    for v in variants:
        if len(ANSI_RE.sub("", v)) <= limit:
            con.progress(v)
            return
    con.progress(variants[-1])


def run_clean_cycle(cycle_no: int):
    """Полная чистка: входной файл -> выходной + итоговая панель.

    Файл читается построчно в бинарном режиме, строки уходят в пул
    воркеров. В полёте держится не больше WORKERS задач: пока результаты
    старших не забраны, новая задача не отправляется — так память не
    растёт вместе с файлом, а воркеры при этом заняты все. Результаты
    дедуплицируются в памяти по отпечатку узла; выходной файл
    перезаписывается атомарно в самом конце — прерывание в любой момент
    оставляет прошлый результат нетронутым.
    """
    t0 = time.time()
    total_bytes = os.path.getsize(INPUT_FILE) or 1
    C = {"lines": 0, "blank": 0, "kept": 0, "dup": 0, "dup_exact": 0, "dup_norm": 0,
         "rej": 0, "compat": 0}
    proto_c, net_c, sec_c, kind_c = Counter(), Counter(), Counter(), Counter()
    port_c, reason_c = Counter(), Counter()
    dedup = {}
    task = _task_size()
    log_buf = []                       # накопитель строк для журнала разработчика

    def cadd(c, key):
        # потолок на число разных элементов: память счётчиков не растёт
        # бесконечно даже на миллионах отбраковок
        if len(c) < CAP_COUNTERS or key in c:
            c[key] += 1

    def handle(rec):
        """Одна запись из воркера: в статистику, дедуп или журнал."""
        if rec[0] == "r":
            _, _, reason, proto, orig = rec
            cadd(reason_c, reason)
            C["rej"] += 1
            if reason.startswith("не конвертируется чекером"):
                C["compat"] += 1
            if LOG_REJECTS:
                log_buf.append(f"отбраковка [{proto}] {reason} :: {orig}")
            return
        _, no, canon, fixes, meta, odig, fp, has_fp = rec
        proto, net, sec, kind, port = meta
        C["kept"] += 1
        proto_c[proto] += 1
        net_c[net] += 1
        sec_c[sec] += 1
        kind_c[kind] += 1
        cadd(port_c, port)
        if LOG_FIXES and fixes:
            log_buf.append(f"правки [{proto}] строка {no}: " + fixes.replace("\n", "; "))
        nfix = min(fixes.count("\n") + 1 if fixes else 0, 127)
        # Метаданные записи пакуются в одно число — словарь дедупа ест
        # заметно меньше памяти на сотнях тысяч конфигов:
        #   бит 0     — был ли fp у исходной строки (нужно политике «best»)
        #   биты 1-7  — число правок
        #   биты 8-71 — слепок входной строки (отличить точный дубль)
        #   биты 72+  — номер строки (порядок выхода)
        packed = ((no << 72) | (int.from_bytes(odig, "big") << 8)
                  | (nfix << 1) | (1 if has_fp else 0))
        # ключ дедупликации — отпечаток узла, а не строка: косметика
        # (регистр sni, порядок alpn и т.п.) не плодит фантомных дублей
        old = dedup.get(fp)
        if old is None:
            dedup[fp] = (packed, canon)
            return
        C["dup"] += 1
        if (packed >> 8) & 0xFFFFFFFFFFFFFFFF == (old[0] >> 8) & 0xFFFFFFFFFFFFFFFF:
            C["dup_exact"] += 1
        else:
            C["dup_norm"] += 1
        # политика «best»: остаётся самый полный экземпляр (с fp; при
        # равенстве — с меньшим числом правок, затем более ранний).
        # «first» — всегда первый найденный.
        o_has, o_nfix, o_no = old[0] & 1, (old[0] >> 1) & 0x7F, old[0] >> 72
        if DUP_POLICY == "best" and (has_fp, -nfix, -no) > (o_has, -o_nfix, -o_no):
            dedup[fp] = (packed, canon)

    def flush_log():
        if log_buf:
            _devlog("\n".join(log_buf))
            log_buf.clear()

    def log_batch(batch_no):
        """Строка по обработанному батчу (настройка log_batches)."""
        if LOG_BATCHES and batch_no:
            con.info(con.paint(
                f"  батч {batch_no}: строк {_fmt(C['lines'])}, "
                f"уник {_fmt(len(dedup))}, отброшено {_fmt(C['rej'])}", "gray"))

    def draw_status(done_bytes):
        """Однострочный прогресс: бар и счётчики, перезатирает сам себя."""
        if not SHOW_PROGRESS_BAR:
            return
        # «Обработано» = уникальные + дубли + отбраковка: столько строк уже
        # получили свою судьбу. Сумма счётчиков сходится всегда, а непрочитанный
        # хвост в счёт не попадает — раньше из-за него числа разъезжались.
        processed = len(dedup) + C["dup"] + C["rej"]
        _progress_line(done_bytes, total_bytes,
                       processed, len(dedup), C["dup"], C["rej"])

    pool = _get_pool()
    results = deque()                  # задачи в полёте, забираем по порядку
    batch_no = 0
    pos = 0                            # сколько байт входа прочитано

    def take():
        """Забирает результат старшей задачи: в статистику и прогресс."""
        nonlocal batch_no
        for rec in results.popleft().get():
            handle(rec)
        batch_no += 1
        flush_log()
        log_batch(batch_no)
        draw_status(pos)

    try:
        buf = []
        with open(INPUT_FILE, "rb") as f:
            for raw in f:
                C["lines"] += 1
                s = raw.decode("utf-8", errors="replace")
                s = s.lstrip("\ufeff").strip().strip("\"'").strip()
                if not s:
                    C["blank"] += 1
                    continue
                buf.append((C["lines"], s))
                if len(buf) >= task:
                    # очередь не длиннее пула — новая задача уйдёт только
                    # после того, как результат одной из старших забран
                    while len(results) >= WORKERS:
                        take()
                    pos = f.tell()
                    results.append(pool.apply_async(worker, (buf,)))
                    buf = []
            if buf:
                pos = f.tell()
                results.append(pool.apply_async(worker, (buf,)))
                buf = []
        while results:
            take()
        draw_status(total_bytes)
    except BaseException:
        _drop_pool()
        con.clear()
        con.warn("Чистка прервана — выходной файл остался прежним.")
        raise

    parse_t = time.time() - t0
    out_dir = os.path.dirname(CLEAN_FILE)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    os.makedirs(SERVICE_DIR, exist_ok=True)
    if BACKUP_CLEAN and os.path.isfile(CLEAN_FILE):
        try:
            shutil.copy2(CLEAN_FILE, os.path.join(SERVICE_DIR, "clean.txt.bak"))
        except OSError:
            pass
    # временный файл кладём рядом с выходом: os.replace не умеет
    # перееезжать между дисками, а выход может быть на другом диске
    tmp = CLEAN_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fc:
        if OUTPUT_SORT == "alpha":
            items = sorted(dedup.values(), key=lambda v: v[1])
        else:
            items = sorted(dedup.values(), key=lambda v: v[0] >> 72)
        for v in items:
            fc.write(v[1] + "\n")
    # выход может быть открыт другим процессом (например чекером) —
    # пара ретраев это переживает, весь цикл из-за него гасить не надо
    for _attempt in range(5):
        try:
            os.replace(tmp, CLEAN_FILE)
            break
        except PermissionError:
            if _attempt == 4:
                raise
            time.sleep(0.4)
    elapsed = time.time() - t0
    con.clear()
    if SHOW_SUMMARY:
        _print_summary(C, dedup, parse_t, elapsed,
                       proto_c, net_c, sec_c, kind_c, port_c, reason_c)
    elif len(dedup) == 0:
        con.warn("валидных конфигов 0 — выходной файл перезаписан пустым.")
    return C, len(dedup)

# =========================================================================
# 13. ИТОГОВАЯ ПАНЕЛЬ
# =========================================================================
def _oneline(c: Counter, k: int, labels=None) -> str:
    """Счётчик одной строкой: 'Vless: 40 000 | Trojan: 20 000 | …'."""
    parts = [f"{(labels or {}).get(key, key)}: {_fmt(v)}"
             for key, v in c.most_common(k)]
    return " | ".join(parts) or "—"


# Подписи для блока «Статистика по чистке»: сырые ключи счётчиков ->
# имена, как их пишут клиенты и панели.
PROTO_LABELS = {"vless": "Vless", "vmess": "VMess", "ss": "SS",
                "trojan": "Trojan", "hysteria2": "Hysteria2", "hy2": "Hysteria2",
                "tuic": "TUIC"}
NET_LABELS = {"tcp": "TCP", "ws": "WebSocket", "grpc": "gRPC", "xhttp": "XHTTP",
              "http": "Http", "httpupgrade": "httpupgrade", "quic": "QUIC",
              "kcp": "(m)kcp"}
SEC_LABELS = {"tls": "TLS", "reality": "Reality", "none": "None"}


def _print_summary(C, dedup, parse_t: float, elapsed: float,
                   proto_c, net_c, sec_c, kind_c, port_c, reason_c) -> None:
    """Панель итогов после одиночной чистки; блоки включаются настройками show_*.

    «Итоги чистки:» всегда зелёный — финальный акцент цикла, его видно
    и при любом акцентном цвете интерфейса. Заголовки блоков статистики —
    акцентным цветом, сами числа — обычным.
    """
    rate = C["lines"] / max(parse_t, 0.001)
    con.always("")
    con.always(con.paint("Итоги чистки:", "green", True))
    con.always(f"  Прочитано строк : {con.paint(_fmt(C['lines']), 'white', True)}")
    con.always(f"  Пустых строк: {_fmt(C['blank'])}")
    con.always(f"  Валидных: {con.paint(_fmt(C['kept']), 'green', True)}")
    con.always(f"  Дубликатов: {_fmt(C['dup'])} "
               f"(exact {_fmt(C['dup_exact'])} / norm {_fmt(C['dup_norm'])})")
    con.always(f"  Строгость чистки: {DUP_SCOPE_SHORT.get(DUP_SCOPE, DUP_SCOPE)}")
    con.always(f"  Отброшено: {con.paint(_fmt(C['rej']), 'red', True)}")
    con.always(f"  Исключено (Sing-Box не поддерживает): {_fmt(C.get('compat', 0))}")
    con.always(f"  Уникальных: {con.paint(_fmt(len(dedup)), 'cyan', True)}")
    con.always(f"  Время: {elapsed:.1f} с (парсинг {parse_t:.1f} с), "
               f"воркеров {WORKERS}, скорость {_fmt(int(rate))} строк/с")
    if SHOW_PROTO_STATS:
        con.always("")
        con.always(con.paint("Статистика по чистке:", ACCENT_COLOR, True))
        con.always("Протоколы:")
        con.always(_oneline(proto_c, 8, PROTO_LABELS))
        con.always("Транспорты:")
        con.always(_oneline(net_c, 10, NET_LABELS))
        con.always("Security:")
        con.always(_oneline(sec_c, 6, SEC_LABELS))
        con.always("Хосты:")
        con.always(_oneline(kind_c, 5))
    if SHOW_TOP_REASONS:
        con.always("")
        con.always(con.paint(f"Топ-{TOP_SHOW} причин отбраковки:", ACCENT_COLOR, True))
        reasons = reason_c.most_common(TOP_SHOW)
        if reasons:
            for r, cnt in reasons:
                con.always(f"    {_fmt(cnt):>7}  {r}")
        else:
            con.always("    —")
    if SHOW_TOP_PORTS:
        con.always("")
        con.always(con.paint(f"Топ-{TOP_SHOW} портов:", ACCENT_COLOR, True))
        ports = port_c.most_common(TOP_SHOW)
        if ports:
            for p, cnt in ports:
                con.always(f"    Port {p}:  {_fmt(cnt)}")
        else:
            con.always("    —")
    if BACKUP_CLEAN:
        con.always("")
        con.always(f"Бэкап прошлой версии: {os.path.join(SERVICE_DIR, 'clean.txt.bak')}")
    if len(dedup) == 0:
        con.warn("валидных конфигов 0 — clean.txt перезаписан пустым.")
    con.always("")


# =========================================================================
# 14. РЕЖИМЫ ЗАПУСКА: ОДИНОЧНЫЙ ЦИКЛ И КОНВЕЙЕР
# =========================================================================
def _input_has_lines() -> bool:
    """Есть ли во входном файле хоть одна непустая строка.

    Пустой вход — штатное «нет работы»: чистить нечего и выходной файл
    затирать нельзя.
    """
    try:
        with open(INPUT_FILE, "r", encoding="utf-8", errors="replace") as f:
            return any(ln.strip() for ln in f)
    except OSError:
        return False


def run_single_clean() -> None:
    """Одна полная чистка входа в выход (пункт меню «Одиночный цикл»)."""
    if not os.path.isfile(INPUT_FILE) or not _input_has_lines():
        con.warn(f"Входной файл пуст/отсутствует — выход не трогаю "
                 f"({INPUT_FILE})")
        return
    con.always("")
    con.header(" Одиночный цикл запущен.")
    run_clean_cycle(1)


# -------------------------------------------------------------------------
# Конвейер: чистка входного файла по мере его дописывания
# -------------------------------------------------------------------------
def _stream_read_lines(path: str, state: dict) -> list:
    """Дописанные в файл строки с прошлого чтения (режим конвейера).

    state хранит offset (байт) и хвост последней недописанной строки.
    Файл переписали целиком (стал короче) — читаем с нуля: повторные
    строки отсеет дедупликация. Возвращаются только ЗАВЕРШЁННЫЕ строки:
    недописанный хвост ждёт продолжения на следующем опросе.
    """
    try:
        size = os.path.getsize(path)
    except OSError:
        return []
    offset = state["offset"]
    if size < offset:
        offset = 0
        state["tail"] = b""
    if size == offset:
        return []
    try:
        with open(path, "rb") as f:
            f.seek(offset)
            data = f.read(size - offset)
    except OSError:
        return []
    state["offset"] = size
    data = state["tail"] + data
    state["tail"] = b""
    if not data.endswith(b"\n"):
        nl = data.rfind(b"\n")
        if nl == -1:
            state["tail"] = data
            return []
        state["tail"] = data[nl + 1:]
        data = data[:nl + 1]
    out = []
    for raw in data.split(b"\n"):
        s = raw.decode("utf-8", errors="replace")
        s = s.lstrip("\ufeff").strip().strip("\"'").strip()
        if s:
            out.append(s)
    return out


def run_stream_clean(from_eof: bool = False) -> None:
    """Конвейер: чистит входной файл по мере дописывания строк.

    Новые строки уходят в пул воркеров, уникальные валидные конфиги
    сразу ДОПИСЫВАЮТСЯ в выход — префильтр забирает их на лету, не дожидаясь
    конца «цикла». Полная перезапись с сортировкой остаётся за одиночным
    циклом.

    Циклом здесь считается один заход обработки новых строк. Каждый цикл
    печатает «Информация:», живую строку прогресса (как в одиночном
    цикле), [OK] и накопленные итоги; в простое перерисовывается строка
    «Слежу за входным файлом уже …» — время тикает от старта конвейера.
    После цикла держится пауза (pause_after_cycle), число циклов можно
    ограничить (max_cycles) — по достижении лимита конвейер сам
    останавливается.

    Отпечатки уже выписанных конфигов собираются при старте из текущего
    выхода и пополняются на ходу, поэтому повторный запуск конвейера
    (и дубликаты внутри самой дописки) второй раз конфиг не запишет.

    from_eof (--from-eof): стартовать с конца входного файла, не собирая
    отпечатки из выхода — для рестарта поверх уже выписанного файла,
    когда старый объём повторно чистить не нужно.
    """
    pool = _get_pool()
    C = {"lines": 0, "kept": 0, "dup": 0, "rej": 0}
    dedup: set = set()
    line_no = 0
    cycles = 0
    task = _task_size()

    # Шапка конвейера. Строку про CTRL+C красим в зелёный независимо от
    # акцентного цвета интерфейса — эту подсказку пользователь ищет глазами
    # в любой цветовой схеме.
    con.always("")
    con.header(" Конвейерный режим запущен.")
    con.always("  Новые строки входного файла чистятся по мере дописывания,")
    con.always("  уникальные конфиги сразу дописываются в выходной файл.")
    con.always("")
    con.always(con.paint(
        "  Комбинацией CTRL + C можно остановить конвейер и вернуться в меню.",
        "green"))

    if from_eof:
        con.info("Старт с конца входного файла (--from-eof): старый объём уже "
                 "выписан, чищу только новые строки.")
    elif os.path.isfile(CLEAN_FILE):
        # дедуп по уже выписанным конфигам: прогоняем выход через воркеры
        # и собираем отпечатки — после рестарта дубль второй раз не допишется
        con.info("Собираю отпечатки уже выписанных конфигов…")
        batch: list = []
        try:
            with open(CLEAN_FILE, "r", encoding="utf-8", errors="replace") as f:
                for ln in f:
                    s = ln.strip()
                    if not s:
                        continue
                    batch.append((0, s))
                    if len(batch) >= task:
                        for rec in pool.apply(worker, (batch,)):
                            if rec[0] == "k":
                                dedup.add(rec[6])
                        batch = []
            if batch:
                for rec in pool.apply(worker, (batch,)):
                    if rec[0] == "k":
                        dedup.add(rec[6])
        except OSError as e:
            con.warn(f"Выходной файл не прочитан ({e}) — дедупликация только "
                     "по новым строкам.")
        con.ok(f"Уже выписано: {_fmt(len(dedup))} — повторно дописаны не будут.")

    log_buf = []

    def handle(rec):
        """Запись воркера -> каноническая строка для дописи (None — отбраковка
        или дубль). Отбраковки и правки по флагам уходят в журнал."""
        if rec[0] == "r":
            C["rej"] += 1
            if LOG_REJECTS:
                log_buf.append(f"отбраковка [{rec[3]}] {rec[2]} :: {rec[4]}")
            return None
        _, _no, canon, fixes, _meta, _odig, fp, _has_fp = rec
        if LOG_FIXES and fixes:
            log_buf.append("правки: " + fixes.replace("\n", "; "))
        if fp in dedup:
            C["dup"] += 1
            return None
        dedup.add(fp)
        C["kept"] += 1
        return canon

    def totals_line() -> None:
        """Накопленный итог конвейера одной строкой.

        В конвейере kept — уже только уникальные дописанные конфиги
        (дубли в него не попадают), поэтому сумма трёх счётчиков всегда
        равна числу обработанных строк.
        """
        con.always(f"  Всего конфигов: {_fmt(C['lines'])} | "
                   f"Очищенных: {_fmt(C['kept'])} | "
                   f"Дубликаты: {_fmt(C['dup'])} | "
                   f"Отброшено: {_fmt(C['rej'])}")

    def watch() -> None:
        """Живая строка ожидания: сколько времени следим за входным файлом.

        Время тикает от старта конвейера и показывается по-человечески:
        секунды, минуты, часы, дни. Перерисовывается на месте — в логах
        и не-терминалах не печатается вовсе.
        """
        con.progress(f"Слежу за входным файлом уже "
                     f"{_fmt_elapsed(time.time() - started)}…")

    def batch_bar(total: int, base: tuple) -> None:
        """Прогресс текущего куска строк — ровно как в одиночном цикле.

        base — снимок накопленных счётчиков на начало цикла, разница
        даёт цифры именно этого куска. В конвейере kept — уникальные,
        дубли считаются отдельно, обработано — сумма всех трёх.
        """
        if not SHOW_PROGRESS_BAR:
            return
        kept_d = C["kept"] - base[0]
        dup_d = C["dup"] - base[1]
        rej_d = C["rej"] - base[2]
        done = kept_d + dup_d + rej_d
        _progress_line(done, total, done, kept_d, dup_d, rej_d)

    if from_eof and os.path.isfile(INPUT_FILE):
        state = {"offset": os.path.getsize(INPUT_FILE), "tail": b""}
    else:
        state = {"offset": 0, "tail": b""}
    buf: list = []
    pending = deque()                  # задачи в полёте; допись — строго по порядку
    started = time.time()
    out_dir = os.path.dirname(CLEAN_FILE)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    out = open(CLEAN_FILE, "a", encoding="utf-8")

    def drain_one() -> int:
        """Забирает старшую задачу, дописывает конфиги; возвращает число дописанных."""
        written = 0
        for rec in pending.popleft().get():
            canon = handle(rec)
            if canon:
                out.write(canon + "\n")
                written += 1
        if log_buf:
            _devlog("\n".join(log_buf))
            log_buf.clear()
        return written

    try:
        while True:
            lines = _stream_read_lines(INPUT_FILE, state)
            processed = False
            if lines:
                con.clear()
                con.always("")
                con.header("Информация:")
                con.info(f"Обработка {_fmt(len(lines))} новых строк — чищу…")
                if LOG_STREAM:
                    _devlog(f"конвейер: прочитано {len(lines)} новых строк, "
                            f"offset={state['offset']}")
                C["lines"] += len(lines)
                base = (C["kept"], C["dup"], C["rej"])
                wrote = 0
                for s in lines:
                    line_no += 1
                    buf.append((line_no, s))
                    if len(buf) >= task:
                        # держим в полёте не больше WORKERS задач, допись
                        # идёт в порядке отправки — порядок clean.txt
                        # совпадает с порядком входа
                        while len(pending) >= WORKERS:
                            wrote += drain_one()
                            batch_bar(len(lines), base)
                        pending.append(pool.apply_async(worker, (buf,)))
                        buf = []
                if buf:
                    pending.append(pool.apply_async(worker, (buf,)))
                    buf = []
                while pending:
                    wrote += drain_one()
                    batch_bar(len(lines), base)
                if wrote:
                    out.flush()
                    con.clear()
                    con.info(con.paint(
                        f"  [OK] Конвейер: новых конфигов дописано: "
                        f"{_fmt(wrote)}", "green"))
                    if LOG_STREAM:
                        _devlog(f"конвейер: дописано {wrote} конфигов")
                totals_line()
                processed = True
                cycles += 1
                if MAX_CYCLES and cycles >= MAX_CYCLES:
                    con.warn(f"Достигнут лимит циклов ({MAX_CYCLES}) — "
                             "конвейер остановлен.")
                    break
            watch()
            # после цикла — пауза из настроек, в простое — обычный опрос
            if processed and PAUSE_AFTER_CYCLE > 0:
                time.sleep(PAUSE_AFTER_CYCLE)
            else:
                time.sleep(STREAM_POLL_INTERVAL)
    except KeyboardInterrupt:
        con.clear()
        con.always("")
        con.warn("Конвейер остановлен пользователем.")
    except BaseException:
        con.clear()
        con.warn("Конвейер прерван ошибкой — дописанное уже на диске.")
        raise
    finally:
        try:
            while pending:                     # добираем хвост в порядке очереди
                drain_one()
            out.flush()
        except Exception:
            pass
        try:
            out.close()
        except Exception:
            pass
        totals_line()


def _run_stream_with_message() -> None:
    """Пункт меню «Конвейерная чистка»: шапку печатает сам конвейер."""
    apply_settings(SETTINGS)
    try:
        run_stream_clean()
    except KeyboardInterrupt:
        con.clear()
        con.always("")
        con.warn("Конвейер остановлен.")
    con.always("")
    try:
        time.sleep(1.0)
    except KeyboardInterrupt:
        pass


def _run_single_with_message() -> None:
    """Пункт меню «Одиночный цикл»: одна чистка и возврат в меню."""
    apply_settings(SETTINGS)
    try:
        run_single_clean()
    except KeyboardInterrupt:
        con.clear()
        con.always("")
        con.warn("Чистка прервана пользователем.")
    con.always("")
    try:
        time.sleep(1.0)
    except KeyboardInterrupt:
        pass


# =========================================================================
# 15. МЕНЮ
# =========================================================================
# Здесь весь текстовый интерфейс: главное меню, меню настроек и диалоги
# правки отдельных параметров. Правило по цветам одно: пункты меню —
# обычным цветом терминала, заголовки групп и значения настроек —
# акцентным цветом из настроек интерфейса. Ввод устойчив к CTRL+C/EOF:
# вместо ввода функция получает None и трактуется как «назад/отмена».


def _ask(prompt: str):
    """Один ввод с клавиатуры; CTRL+C/EOF -> None (назад/отмена)."""
    try:
        return input(prompt)
    except (KeyboardInterrupt, EOFError):
        print()
        return None


def _print_main_menu(first_show: bool) -> None:
    """Логотип и главное меню. first_show — первый показ за запуск:
    после него держится пауза, чтобы логотип успели увидеть."""
    if SETTINGS.get('clear_screen_in_menu', True):
        clear_screen()
    show_logo()
    if first_show and LOGO_PAUSE > 0:
        try:
            time.sleep(LOGO_PAUSE)
        except KeyboardInterrupt:
            pass
    con.always("")
    con.header("══════════ Главное меню ══════════")
    con.always(" 1) Запустить конвейерную чистку")
    con.always(" 2) Одиночный цикл")
    con.always(" 3) Настройки")
    con.always(" 4) Выход")
    con.always("")


# Типы полей схемы одним словарём: key -> тип. Нужен, чтобы при показе
# значения не пересобирать схему каждый раз.
SCHEMA_TYPES = {key: ftype for key, ftype, _, _ in _flatten_schema()}


def _format_value(key: str, value) -> str:
    """Значение настройки в виде для показа.

    bool — «Да»/«Нет», целый float — без дробной части, choice — подпись.
    У строгости дедупликации подпись короткая (DUP_SCOPE_SHORT): полные
    описания слишком длинные для списка, их видно только при выборе.
    """
    if key == 'color_level':
        names = {0: '0 (тихий)', 1: '1 (обычный)', 2: '2 (подробный)'}
        return names.get(value, str(value))
    if key == 'dup_scope':
        return DUP_SCOPE_SHORT.get(value, value)
    if key in CHOICE_LABELS and value in CHOICE_LABELS[key]:
        return CHOICE_LABELS[key][value]
    ftype = SCHEMA_TYPES.get(key, "str")
    if ftype == 'bool':
        return 'Да' if value else 'Нет'
    if ftype == 'float':
        if isinstance(value, float) and value == int(value):
            return str(int(value))
        return str(value)
    return str(value)


def _reset_settings() -> None:
    """Сброс всех настроек к значениям по умолчанию (пункт «r»)."""
    con.always("")
    con.always("  Сбросить ВСЕ настройки к значениям по умолчанию? (Да/Нет):")
    answer = _ask("  > ")
    if answer is None or answer.strip().lower() not in ("да", "д", "y", "yes", "1", "+"):
        con.always(con.paint("  Отменено.", "yellow"))
        return
    global SETTINGS
    SETTINGS = _default_settings()
    if save_settings(SETTINGS):
        apply_settings(SETTINGS)
        con.ok("Настройки сброшены к значениям по умолчанию.")
    else:
        con.error("Не удалось сохранить настройки на диск.")


def _edit_setting(group_title: str, item_index: int) -> None:
    """Диалог правки одного параметра.

    bool правится без ввода: выбор пункта просто переключает Да <-> Нет.
    Остальные типы спрашивают значение: числа зажимаются в диапазон,
    choice выбирается номером или именем варианта, строки вводятся
    текстом (пути можно вставлять в кавычках — они снимутся). Успех —
    сразу сохраняем на диск и применяем.
    """
    items = DEFAULT_SETTINGS_SCHEMA[group_title]
    if item_index < 1 or item_index > len(items):
        return
    key, ftype, label, _ = items[item_index - 1]
    current = SETTINGS.get(key)
    lo, hi = NUM_RANGE.get(key, (None, None))
    con.always("")
    con.always(f"  Параметр: {label}")
    con.always(f"  Текущее значение: {con.paint(_format_value(key, current), ACCENT_COLOR)}")

    def _saved(value):
        """Общая развязка: запомнить, сохранить, применить, отчитаться."""
        SETTINGS[key] = value
        if save_settings(SETTINGS):
            con.ok(f"Сохранено: {_format_value(key, value)}")
        else:
            con.error("Не удалось сохранить настройки на диск.")
        apply_settings(SETTINGS)

    def _cancel():
        con.always(con.paint("  Отменено.", "yellow"))

    if ftype == 'bool':
        # никакого ввода: выбрал пункт — значение перевернулось
        _saved(not current)
        return
    if ftype == 'int':
        rng = f" от {lo} до {hi}" if lo is not None and hi is not None else ""
        con.always(f"  Введите целое число{rng} (или пустую строку для отмены):")
        raw = _ask("  > ")
        if raw is None:
            return
        if not raw.strip():
            _cancel()
            return
        try:
            val = int(raw.strip())
        except ValueError:
            con.always(con.paint("  Нужно ввести целое число.", "yellow"))
            return
        new_value = _clamp_num(key, val)
        if lo is not None and val != new_value:
            con.always(con.paint(f"  Значение скорректировано до диапазона: {new_value}", "yellow"))
        _saved(new_value)
        return
    if ftype == 'float':
        rng = f" от {lo} до {hi}" if lo is not None and hi is not None else ""
        con.always(f"  Введите число{rng} (или пустую строку для отмены):")
        raw = _ask("  > ")
        if raw is None:
            return
        if not raw.strip():
            _cancel()
            return
        try:
            val = float(raw.strip().replace(",", "."))
        except ValueError:
            con.always(con.paint("  Нужно ввести число.", "yellow"))
            return
        new_value = _clamp_num(key, val)
        if lo is not None and val != new_value:
            con.always(con.paint(f"  Значение скорректировано до диапазона: {new_value}", "yellow"))
        _saved(new_value)
        return
    if ftype == 'choice':
        options = list(CHOICES.get(key, ()))
        for i, opt in enumerate(options, 1):
            shown = CHOICE_LABELS.get(key, {}).get(opt, opt)
            con.always(f"    {i}. {shown}")
        con.always("  Введите номер или имя варианта (или пустую строку для отмены):")
        raw = _ask("  > ")
        if raw is None:
            return
        if not raw.strip():
            _cancel()
            return
        text = raw.strip().lower()
        if text.isdigit() and 1 <= int(text) <= len(options):
            new_value = options[int(text) - 1]
        elif text in options:
            new_value = text
        else:
            con.always(con.paint("  Некорректный выбор.", "yellow"))
            return
        _saved(new_value)
        return
    # str — например пути входа/выхода в группе «Файлы»
    con.always("  Введите новое значение (или пустую строку для отмены):")
    raw = _ask("  > ")
    if raw is None:
        return
    if not raw.strip():
        _cancel()
        return
    new_value = raw.strip().strip('"').strip("'").strip()
    _saved(new_value)


def _settings_loop() -> None:
    """Меню настроек: список групп, «0» — назад, «r» — сброс."""
    groups = list(DEFAULT_SETTINGS_SCHEMA.keys())
    while True:
        if SETTINGS.get('clear_screen_in_menu', True):
            clear_screen()
        show_logo()
        con.always("")
        con.header("=== Настройки ===")
        for i, title in enumerate(groups, 1):
            con.always(con.paint(f"  {i}. {title}", ACCENT_COLOR))
        con.always("")
        con.always("  0. Назад")
        con.always("  r. Сбросить значения по умолчанию")
        con.always("")
        raw = _ask("  Выберите номер группы: ")
        if raw is None:
            return
        text = raw.strip()
        if text == '0':
            return
        if text == '':
            continue
        if text.lower() == 'r':
            _reset_settings()
        elif text.isdigit() and 1 <= int(text) <= len(groups):
            _group_loop(groups[int(text) - 1])
        elif text.isdigit():
            con.always(con.paint("  Нет такой группы.", "yellow"))
        else:
            con.always(con.paint("  Введите номер группы или r.", "yellow"))


def _group_loop(group_title: str) -> None:
    """Список параметров одной группы с правкой по номеру.

    Название группы и значения — акцентным цветом, названия параметров —
    обычным. После каждого изменения список перерисовывается с новым
    значением.
    """
    items = DEFAULT_SETTINGS_SCHEMA[group_title]
    while True:
        if SETTINGS.get('clear_screen_in_menu', True):
            clear_screen()
        show_logo()
        con.always("")
        con.header(f"=== {group_title} ===")
        con.always("")
        for idx, (key, _ftype, label, _) in enumerate(items, start=1):
            con.always(f"  {idx}. {label}: "
                       f"{con.paint(_format_value(key, SETTINGS.get(key)), ACCENT_COLOR)}")
        con.always("")
        con.always("  0. Назад")
        con.always("")
        raw = _ask("  Выберите номер параметра: ")
        if raw is None:
            return
        text = raw.strip()
        if text == '0':
            return
        if text == '':
            continue
        if text.isdigit() and 1 <= int(text) <= len(items):
            _edit_setting(group_title, int(text))
        elif text.isdigit():
            con.always(con.paint("  Нет такого параметра.", "yellow"))
        else:
            con.always(con.paint("  Нужно ввести число.", "yellow"))


def _exit_script() -> None:
    """Аккуратное закрытие скрипта с короткой паузой."""
    con.info("Завершение работы...")
    try:
        time.sleep(1.0)
    except KeyboardInterrupt:
        pass
    sys.exit(0)

# =========================================================================
# 16. САМОПРОВЕРКА (--selftest)
# =========================================================================
def _selftest():
    """Контрольный прогон: python Cleaner.py --selftest.

    Проверяет: парсеры и сборку канона (ровно один хвостовой '#'),
    проход mKCP при выключенном reject_mkcp, отбраковку портов ниже 53
    (включая mport hysteria2), мёртвые методы ss, дедупликацию на всех
    уровнях строгости (exclave → nekobox → incy → full), фильтры
    безопасности (reject_insecure/reject_no_tls), фильтр совместимости
    с чекером, drop_spx/drop_sid (spx/sid не в выводе, различие только
    в них схлопывается, битый sid не убивает конфиг), drop_fp/
    drop_defaults (fp, encryption=none и type=tcp не выводятся,
    не-дефолтные значения живут), плагины ss и транспорт quic, отдельным
    блоком tuic. Код возврата 1 — есть проваленные проверки.
    """
    global DUP_SCOPE, CHECKER_FILTER, REJECT_PRIVATE, REJECT_DNS
    global REJECT_INSECURE, REJECT_NO_TLS, DROP_SPX, DROP_SID
    global DROP_FP, DROP_DEFAULTS
    DUP_SCOPE = "full"       # базовые проверки дедупликации — на мягком
                             # уровне full; лестница уровней — отдельным блоком ниже
    CHECKER_FILTER = True
    REJECT_PRIVATE = True
    REJECT_DNS = True
    # базовые прогоны идут с выключенным фильтром безопасности:
    # контрольные ссылки ниже специально содержат allowInsecure=1 и
    # security=none; сам фильтр проверяется своим блоком ниже
    REJECT_INSECURE = False
    REJECT_NO_TLS = False
    REJECT_NO_TLS = False

    fails = 0

    # ---- парсеры и каноническая сборка ----
    tests = [
        "vless://9288f4f6-29a1-4d96-b65f-3a2b3d0b6b53@example.com:443?type=ws&security=tls"
        "&path=%2Fws%3Fed%3D2048&host=cdn.example.com&fp=chrome&sni=example.com#n",
        "vless://9288f4f6-29a1-4d96-b65f-3a2b3d0b6b53@95.1.2.3:443?type=raw&fp=qq#r",
        "vless://9288f4f6-29a1-4d96-b65f-3a2b3d0b6b53@95.1.2.4:443?encryption="
        "mlkem768x25519plus.random.68c6b6&type=tcp&security=reality"
        "&pbk=AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8&sni=a.ru#pq",
        "ss://" + base64.b64encode(b"aes-256-gcm:pw@93.184.216.34:8388").decode() + "#",
        "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTpwdw%3D%3D@51.195.126.38:8388#",
        "vmess://" + base64.b64encode(json.dumps(
            {"v": "2", "ps": "x", "add": "example.net", "port": 443,
             "id": "9288f4f6-29a1-4d96-b65f-3a2b3d0b6b53", "aid": "0", "scy": "auto",
             "net": "ws", "type": "none", "host": "c.example.net", "path": "/w",
             "tls": "auto", "sni": "c.example.net", "fp": "chrome"}).encode()).decode() + "#",
        "hy2://pw@93.184.216.34:8443/?obfs=salamander&obfs-password=z&insecure=1#h",
        "tuic://9288f4f6-29a1-4d96-b65f-3a2b3d0b6b53:pw@93.184.216.35:8443"
        "?sni=t.example.com&congestion_control=bbr&udp_relay_mode=quic"
        "&reduce_rtt=1&alpn=h3#t",
        "vless://9288f4f6-29a1-4d96-b65f-3a2b3d0b6b53@95.1.2.5:443"
        "?type=kcp&headerType=none&seed=abc123&security=tls&sni=a.com#k",
        "vless://9288f4f6-29a1-4d96-b65f-3a2b3d0b6b53@127.0.0.1:443#loc",
        "ssr://AAAA#x",
    ]
    def _canon_hash_ok(canon):
        """Ровно один '#' — пустой фрагмент в конце канонической строки."""
        return canon.endswith("#") and canon.count("#") == 1

    print("--- парсеры и каноническая сборка (хвостовой '#') ---")
    for s in tests:
        rec = worker([(0, s)])[0]
        if rec[0] == "k":
            ok = _canon_hash_ok(rec[2])
            if not ok:
                fails += 1
            print("KEEP", "OK " if ok else "FAIL", rec[2])
        else:
            print("REJ ", f"{rec[3]} | {rec[2]}")

    # ---- методы ss, не поддерживаемые клиентами, отбраковываются ----
    print("--- устаревшие методы ss отбракованы, актуальные остаются ---")
    legacy = [
        ("ss aes-256-cfb (b64-userinfo)",
         "ss://" + base64.b64encode(b"aes-256-cfb:pw@93.184.216.34:8388").decode() + "#",
         False),
        ("ss aes-256-cfb (открытый userinfo)",
         "ss://aes-256-cfb:pw@93.184.216.34:8388#",
         False),
        ("ss aes-128-cfb",
         "ss://" + base64.b64encode(b"aes-128-cfb:pw@93.184.216.34:8388").decode() + "#",
         False),
        ("ss aes-256-ctr",
         "ss://" + base64.b64encode(b"aes-256-ctr:pw@93.184.216.34:8388").decode() + "#",
         False),
        ("ss rc4-md5",
         "ss://" + base64.b64encode(b"rc4-md5:pw@93.184.216.34:8388").decode() + "#",
         False),
        ("ss chacha20-ietf (стрим, не AEAD)",
         "ss://" + base64.b64encode(b"chacha20-ietf:pw@93.184.216.34:8388").decode() + "#",
         False),
        ("ss bf-cfb",
         "ss://" + base64.b64encode(b"bf-cfb:pw@93.184.216.34:8388").decode() + "#",
         False),
        ("ss table",
         "ss://" + base64.b64encode(b"table:pw@93.184.216.34:8388").decode() + "#",
         False),
        ("ss aes-256-gcm — поддерживается",
         "ss://" + base64.b64encode(b"aes-256-gcm:pw@93.184.216.34:8388").decode() + "#",
         True),
        ("ss none — поддерживается",
         "ss://none:pw@93.184.216.34:8388#",
         True),
    ]
    for name, s, must in legacy:
        rec = worker([(0, s)])[0]
        ok = (rec[0] == "k") == must and (rec[0] != "k" or _canon_hash_ok(rec[2]))
        got = "KEEP" if rec[0] == "k" else "REJ"
        print("CIPHER", "OK " if ok else "FAIL", "-", name,
              "" if ok else f"(получено {got}: {rec[2] if rec[0] == 'r' else rec[2]})")
        if not ok:
            fails += 1

    # ---- '#' не проходит в вывод: имена, вторая решётка, хвостовой '#' ----
    print("--- '#' во входе (имя, вторая решётка, хвост) не попадает в вывод ---")
    U = "9288f4f6-29a1-4d96-b65f-3a2b3d0b6b53"
    hash_cases = [
        ("имя и вторая решётка отброшены, остаётся пустой фрагмент",
         f"vless://{U}@example.com:443?type=ws&security=tls&path=%2Fws#имя#хвост",
         f"vless://{U}@example.com:443?type=ws&security=tls&path=%2Fws#b",
         True),
        ("хвостовой '#' входной строки не попадает в вывод",
         "ss://" + base64.b64encode(b"aes-256-gcm:pw@93.184.216.34:8388").decode() + "#",
         "ss://" + base64.b64encode(b"aes-256-gcm:pw@93.184.216.34:8388").decode(),
         True),
    ]
    for name, a, b, must in hash_cases:
        ra, rb = worker([(0, a)])[0], worker([(0, b)])[0]
        eq = (ra[0] == "k" and rb[0] == "k" and ra[6] == rb[6]
              and _canon_hash_ok(ra[2]) and _canon_hash_ok(rb[2]))
        ok = (eq == must)
        print("HASH", "OK " if ok else "FAIL", "-", name)
        if not ok:
            fails += 1

    # ---- дедупликация: косметические копии схлопываются по отпечатку узла ----
    print("--- дедупликация по отпечатку узла (уровень full) ---")
    dup_cases = [
        ("sni-регистр и наличие fp",
         f"vless://{U}@example.com:443?type=ws&security=tls&path=%2Fws&sni=Example.com&fp=chrome#a",
         f"vless://{U}@example.com:443?type=ws&security=tls&path=%2Fws&sni=example.com#b",
         True),
        ("порядок alpn",
         f"vless://{U}@example.com:443?type=ws&security=tls&path=%2Fws&alpn=h2,http/1.1#a",
         f"vless://{U}@example.com:443?type=ws&security=tls&path=%2Fws&alpn=http%2F1.1%2Ch2#b",
         True),
        ("ed=0 и отсутствие ed",
         f"vless://{U}@example.com:443?type=ws&security=tls&path=%2Fws%3Fed%3D0#a",
         f"vless://{U}@example.com:443?type=ws&security=tls&path=%2Fws#b",
         True),
        ("регистр домена в адресе",
         "trojan://pw@EXAMPLE.com:443#a",
         "trojan://pw@example.com:443#b",
         True),
        ("разные узлы (разный путь)",
         f"vless://{U}@example.com:443?type=ws&security=tls&path=%2Fws1#a",
         f"vless://{U}@example.com:443?type=ws&security=tls&path=%2Fws2#b",
         False),
        ("один сервер на разных портах (full — разные)",
         "hysteria2://pw@example.com:443#a",
         "hysteria2://pw@example.com:8443#b",
         False),
    ]
    for name, a, b, must in dup_cases:
        ra, rb = worker([(0, a)])[0], worker([(0, b)])[0]
        if ra[0] != "k" or rb[0] != "k":
            print("DEDUP FAIL (не распарсилось):", name)
            fails += 1
            continue
        eq = ra[6] == rb[6]
        ok = eq == must
        print("DEDUP", "OK " if ok else "FAIL", "-", name)
        if not ok:
            fails += 1

    def _fp(line, scope):
        m = SCHEME_RE.match(line)
        raw = m.group(1).lower()
        proto = SCHEME_ALIAS.get(raw, raw)
        return node_fingerprint(PARSERS[proto](line), scope)

    # Лестница строгости: exclave → nekobox → incy → full. Пара
    # должна схлопываться на указанном уровне и на всех более
    # жёстких, но различаться на более мягких. Прогон с выключенными
    # drop-настройками: сначала убеждаемся, что сами уровни различают
    # spx/sid; поведение с настройками по умолчанию — блоком ниже.
    sp_prev = (DROP_SPX, DROP_SID, DROP_FP, DROP_DEFAULTS)
    DROP_SPX, DROP_SID, DROP_FP, DROP_DEFAULTS = False, False, False, False
    U2 = "11111111-2222-4333-8444-555555555555"
    PBK = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("=")
    r_base = (f"vless://{U}@1.2.3.4:443?security=reality&pbk={PBK}"
              f"&sni=a.com&sid=abcd1234&type=tcp#x")
    r_cred = (f"vless://{U2}@1.2.3.4:443?security=reality&pbk={PBK}"
              f"&sni=a.com&sid=abcd1234&type=tcp#x")              # другая учётка
    r_spx = (f"vless://{U}@1.2.3.4:443?security=reality&pbk={PBK}"
             f"&sni=a.com&sid=abcd1234&spx=%2Fsp&type=tcp#x")     # другой spx
    r_sni = (f"vless://{U}@1.2.3.4:443?security=reality&pbk={PBK}"
             f"&sni=b.com&sid=abcd1234&type=tcp#x")               # другой SNI
    r_sid = (f"vless://{U}@1.2.3.4:443?security=reality&pbk={PBK}"
             f"&sni=a.com&sid=ffff4321&type=tcp#x")               # другой sid
    r_pkte = (f"vless://{U}@1.2.3.4:443?security=reality&pbk={PBK}"
              f"&sni=a.com&sid=abcd1234&packetEncoding=packetaddr&type=tcp#x")
    a_port = (f"vless://{U}@1.2.3.4:8443?security=reality&pbk={PBK}"
              f"&sni=a.com&sid=abcd1234&type=tcp#x")              # другой порт
    b_proto = (f"trojan://pw2@1.2.3.4:443?security=reality&pbk={PBK}"
               f"&sni=a.com&sid=abcd1234#x")                      # другой протокол
    x_base = f"vless://{U}@5.6.7.8:443?security=tls&sni=a.com&type=xhttp&path=%2Fx#x"
    x_mode = (f"vless://{U}@5.6.7.8:443?security=tls&sni=a.com"
              f"&type=xhttp&path=%2Fx&mode=stream-up#x")          # другой mode
    x_extra = (f"vless://{U}@5.6.7.8:443?security=tls&sni=a.com&type=xhttp"
               f"&path=%2Fx&extra=%7B%22x%22%3A1%7D#x")           # другой extra
    t_base = f"vless://{U}@5.6.7.8:443?security=tls&sni=a.com&type=ws&path=%2Fx#x"
    t_path = (f"vless://{U}@5.6.7.8:443?security=tls&sni=a.com&type=ws"
              f"&path=%2Fy#x")                                    # другой путь
    t_tcp = f"vless://{U}@5.6.7.8:443?security=tls&sni=a.com&type=tcp#x"  # другой транспорт

    ladder_cases = [
        ("exclave", "другая учётка, SNI и транспорт — один узел",
         r_base, r_cred, True),
        ("exclave", "другой протокол — разные узлы",
         r_base, b_proto, False),
        ("exclave", "другой порт — разные узлы",
         r_base, a_port, False),
        ("nekobox", "другая учётка — разные узлы",
         r_base, r_cred, False),
        ("nekobox", "другой spx reality — разные узлы",
         r_base, r_spx, False),
        ("nekobox", "другой mode xhttp — разные узлы",
         x_base, x_mode, False),
        ("nekobox", "другой SNI — один узел (SNI не сравнивается)",
         r_base, r_sni, True),
        ("incy", "другой SNI — разные узлы",
         r_base, r_sni, False),
        ("incy", "другой sid reality — разные узлы",
         r_base, r_sid, False),
        ("incy", "другой packetEncoding — разные узлы",
         r_base, r_pkte, False),
        ("incy", "другой extra — один узел (extra различает только full)",
         x_base, x_extra, True),
        ("full", "другой extra — разные узлы",
         x_base, x_extra, False),
        ("full", "другой путь — разные узлы",
         t_base, t_path, False),
        ("full", "другой транспорт — разные узлы",
         t_base, t_tcp, False),
        ("incy", "другой путь — один узел",
         t_base, t_path, True),
        ("incy", "другой транспорт (ws против tcp) — один узел",
         t_base, t_tcp, True),
    ]
    for scope, name, x, y, must in ladder_cases:
        ok = (_fp(x, scope) == _fp(y, scope)) == must
        print("LADDER", "OK " if ok else "FAIL", f"- [{scope}] {name}")
        if not ok:
            fails += 1

    # full vs incy: у hysteria2 различие только в hop_interval
    hy_t = "hysteria2://pw@93.184.216.50:443?sni=x.com#1"
    hy_f = "hysteria2://pw@93.184.216.50:443?sni=x.com&hop_interval=10#2"
    ok = (_fp(hy_t, "incy") == _fp(hy_f, "incy")
          and _fp(hy_t, "full") != _fp(hy_f, "full"))
    print("LADDER", "OK " if ok else "FAIL",
          "- [full] hop_interval hysteria2 различает узлы, incy — нет")
    if not ok:
        fails += 1
    DROP_SPX, DROP_SID, DROP_FP, DROP_DEFAULTS = sp_prev      # возврат к исходному

    # ---- drop_spx/drop_sid (умолчание): spx/sid удаляются на разборе ----
    # Настройки включены: параметров нет в каноническом выводе, а пары,
    # различавшиеся только spx/sid, схлопываются на всех уровнях.
    print("--- drop_spx/drop_sid: spx и sid reality удаляются из конфигов ---")
    rec_d1 = worker([(0, r_base)])[0]
    rec_d2 = worker([(0, r_spx)])[0]
    rec_d3 = worker([(0, r_sid)])[0]
    ok = all(r[0] == "k" for r in (rec_d1, rec_d2, rec_d3))
    ok &= all("sid=" not in r[2] and "spx=" not in r[2] and _canon_hash_ok(r[2])
              for r in (rec_d1, rec_d2, rec_d3))
    ok &= rec_d1[6] == rec_d2[6] == rec_d3[6]
    print("DROP", "OK " if ok else "FAIL",
          "- sid=/spx= нет в выводе; различие только в них — один узел (full)")
    if not ok:
        fails += 1

    ok = (_fp(r_base, "nekobox") == _fp(r_spx, "nekobox")
          and _fp(r_base, "incy") == _fp(r_sid, "incy")
          and _fp(r_base, "full") == _fp(r_sid, "full"))
    print("DROP", "OK " if ok else "FAIL",
          "- различающая способность полей снята: nekobox без spx, incy без sid")
    if not ok:
        fails += 1

    # битый sid (не hex≤16): с включённым drop_sid конфиг живёт — параметр
    # всё равно удаляется, мусор в нём не важен; с выключенным — отбраковка
    bad_sid = (f"vless://{U}@1.2.3.4:443?security=reality&pbk={PBK}"
               f"&sni=a.com&sid=zzz99999zzz&type=tcp#x")
    rec = worker([(0, bad_sid)])[0]
    ok = rec[0] == "k" and "sid=" not in rec[2]
    print("DROP", "OK " if ok else "FAIL", "- битый sid при drop_sid не убивает конфиг")
    if not ok:
        fails += 1
    DROP_SID = False
    rec = worker([(0, bad_sid)])[0]
    ok = rec[0] == "r"
    print("DROP", "OK " if ok else "FAIL", "- битый sid без drop_sid отбраковывается")
    if not ok:
        fails += 1
    DROP_SID = True

    # round-trip: канон без sid/spx повторно разбирается в тот же узел —
    # отпечаток обязан совпадать там, где совпадает канонический вывод
    rec = worker([(0, r_base)])[0]
    rt = worker([(0, rec[2])])[0] if rec[0] == "k" else rec
    ok = rt[0] == "k" and rt[6] == rec[6]
    print("DROP", "OK " if ok else "FAIL", "- round-trip канона без sid/spx")
    if not ok:
        fails += 1

    # ---- drop_fp/drop_defaults: fp и дефолтные параметры не выводятся;
    # отпечатки не меняются — эти поля узел не различал ни на одном
    # уровне строгости. Настройка drop_fp в меню не вынесена, поэтому
    # здесь явно включаем оба режима и возвращаем всё обратно. ----
    DROP_FP, DROP_DEFAULTS = True, True
    print("--- drop_fp/drop_defaults: fp, encryption=none и type=tcp не выводятся ---")
    f_fp = (f"vless://{U}@1.2.3.4:443?security=reality&pbk={PBK}&sni=a.com"
            f"&fp=chrome&encryption=none&type=tcp#x")
    f_fp2 = (f"vless://{U}@1.2.3.4:443?security=reality&pbk={PBK}&sni=a.com"
             f"&fp=firefox&type=tcp#x")
    f_bare = f"vless://{U}@1.2.3.4:443?security=reality&pbk={PBK}&sni=a.com#x"
    recs = [worker([(0, c)])[0] for c in (f_fp, f_fp2, f_bare)]
    ok = all(r[0] == "k" for r in recs)
    ok &= all("fp=" not in r[2] and "encryption=" not in r[2]
              and "type=tcp" not in r[2] and _canon_hash_ok(r[2])
              for r in recs)
    ok &= recs[0][6] == recs[1][6] == recs[2][6]
    print("DROP", "OK " if ok else "FAIL",
          "- fp=/encryption=none/type=tcp нет в выводе; различие только в них — один узел")
    if not ok:
        fails += 1

    # не-дефолтные значения живут: PQ-шифрование vless и транспорт ws
    # (токен с ключом 32 байта — проходит и фильтр чекера)
    rec = worker([(0, f"vless://{U}@1.2.3.4:443?security=reality&pbk={PBK}&sni=a.com"
                    "&encryption=mlkem768x25519plus.random.1rtt."
                    f"{base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip('=')}"
                    "&type=ws&path=%2Fw#x")])[0]
    ok = rec[0] == "k" and "encryption=mlkem768" in rec[2] and "type=ws" in rec[2]
    print("DROP", "OK " if ok else "FAIL",
          "- не-дефолтные encryption (PQ-токен) и type=ws сохраняются")
    if not ok:
        fails += 1

    # fp у hysteria2 снимается тем же правилом (парсер hy2 свой)
    rec = worker([(0, "hysteria2://pw@93.184.216.34:8443/?sni=x.com&fp=chrome#h")])[0]
    ok = rec[0] == "k" and "fp=" not in rec[2]
    print("DROP", "OK " if ok else "FAIL", "- fp у hysteria2 не выводится")
    if not ok:
        fails += 1

    # выключенные настройки возвращают прежнее поведение: fp нормали-
    # зуется в fp_value и добавляется для reality, дефолты пишутся
    DROP_FP, DROP_DEFAULTS = False, False
    rec = worker([(0, f_bare)])[0]
    ok = (rec[0] == "k" and "fp=random" in rec[2] and "encryption=none" in rec[2]
          and "type=tcp" in rec[2])
    print("DROP", "OK " if ok else "FAIL",
          "- без drop_fp/drop_defaults прежний вывод: fp=random, encryption=none, type=tcp")
    if not ok:
        fails += 1
    # возврат к рабочим умолчаниям движка: fp пишется, дефолты — нет
    DROP_FP, DROP_DEFAULTS = False, True

    print("--- проекция отпечатка повторяет правила build_uri ---")
    proj = [
        ("ed у tcp-http выводом теряется",
         f"vless://{U}@example.com:443?type=tcp&headerType=http&security=tls&sni=x.com&path=%2Ft%3Fed%3D2048#a",
         f"vless://{U}@example.com:443?type=tcp&headerType=http&security=tls&sni=x.com&path=%2Ft#b",
         True),
        ("host-заголовок у tcp-http выводом теряется",
         f"vless://{U}@example.com:443?type=tcp&headerType=http&security=tls&sni=x.com&path=%2Ft&host=cdn1#a",
         f"vless://{U}@example.com:443?type=tcp&headerType=http&security=tls&sni=x.com&path=%2Ft&host=cdn2#b",
         True),
        ("host-заголовок у grpc не влияет на узел",
         f"vless://{U}@example.com:443?type=grpc&security=tls&sni=x.com&host=cdn1#a",
         f"vless://{U}@example.com:443?type=grpc&security=tls&sni=x.com&host=cdn2#b",
         True),
        ("host-заголовок у ws влияет на узел",
         f"vless://{U}@example.com:443?type=ws&security=tls&path=%2Fw&host=cdn1#a",
         f"vless://{U}@example.com:443?type=ws&security=tls&path=%2Fw&host=cdn2#b",
         False),
    ]
    for name, a, b, must in proj:
        ra, rb = worker([(0, a)])[0], worker([(0, b)])[0]
        eq = ra[0] == "k" and rb[0] == "k" and ra[6] == rb[6]
        ok = eq == must
        print("DEDUP", "OK " if ok else "FAIL", "-", name)
        if not ok:
            fails += 1

    # ---- фильтр совместимости с чекером ----
    print("--- фильтр совместимости с чекером ---")
    key32 = base64.urlsafe_b64encode(bytes(range(32))).decode().rstrip("=")
    pbk_std = base64.b64encode(b"\xfb" * 32).decode()          # '+' — std-алфавит
    key_url = base64.urlsafe_b64encode(b"\xff" * 32).decode()  # '-'/'_' — std не декодирует
    k16 = base64.b64encode(bytes(16)).decode()
    k32 = base64.b64encode(bytes(32)).decode()
    compat = [
        ("vless encryption mlkem768x25519plus валиден",
         f"vless://{U}@example.com:443?security=tls&encryption=mlkem768x25519plus.native.0rtt.{key32}#a",
         True),
        ("vless encryption: ключ не 32/1184 байт",
         f"vless://{U}@example.com:443?security=tls&encryption=mlkem768x25519plus.native.0rtt.zzz#a",
         False),
        ("vless encryption: чужой префикс",
         f"vless://{U}@example.com:443?security=tls&encryption=foo.native.0rtt.{key32}#a",
         False),
        ("reality pbk base64url (43 симв.) — ок",
         f"vless://{U}@example.com:443?security=reality&pbk={key32}#a",
         True),
        ("reality pbk std-base64 с '+' — чекер не примет",
         f"vless://{U}@example.com:443?security=reality&pbk={pbk_std}#a",
         False),
        ("ss 'chacha20-poly1305' — алиас чекера, ок",
         "ss://" + base64.b64encode(b"chacha20-poly1305:pw@93.184.216.34:8388").decode() + "#a",
         True),
        ("ss 'xchacha20-poly1305' — алиас, канонизируется в ietf, ок",
         "ss://" + base64.b64encode(b"xchacha20-poly1305:pw@93.184.216.34:8388").decode() + "#a",
         True),
        ("ss пароль с '@' ломает разворачивание base64 у чекера",
         "ss://" + base64.b64encode(b"aes-256-gcm:1234!@#$").decode() + "@49.254.204.134:1774#a",
         False),
        ("ss2022 urlsafe-ключ — std-base64 чекер не примет",
         f"ss://2022-blake3-aes-256-gcm:{key_url}@93.184.216.34:8388#a",
         False),
        ("ss2022 три части пароля (iPSK > 1)",
         f"ss://2022-blake3-aes-256-gcm:{k32}:{k32}:{k32}@93.184.216.34:8388#a",
         False),
        ("ss2022 chacha20 с iPSK — только AES",
         f"ss://2022-blake3-chacha20-poly1305:{k32}:{k32}@93.184.216.34:8388#a",
         False),
        ("ss2022 валидный (aes-128, ключ 16 байт)",
         f"ss://2022-blake3-aes-128-gcm:{k16}@93.184.216.34:8388#a",
         True),
    ]
    for name, s, must in compat:
        rec = worker([(0, s)])[0]
        got = "KEEP" if rec[0] == "k" else "REJ"
        ok = (rec[0] == "k") == must
        print("COMPAT", "OK " if ok else "FAIL", "-", name,
              "" if ok else f"(получено {got}: {rec[2] if rec[0] == 'r' else ''})")
        if not ok:
            fails += 1

    # ---- фильтр небезопасных конфигов (reject_insecure / reject_no_tls) ----
    print("--- фильтр небезопасных конфигов ---")
    sec_prev = (REJECT_INSECURE, REJECT_NO_TLS)
    REJECT_INSECURE, REJECT_NO_TLS = True, True
    sec_cases = [
        ("vless allowInsecure=1 отбракован",
         f"vless://{U}@example.com:443?security=tls&allowInsecure=1&type=ws&path=%2Fw#",
         False),
        ("hysteria2 skip-cert-verify=1 отбракован",
         "hysteria2://pw@example.com:8443/?skip-cert-verify=1#", False),
        ("vless без TLS (security нет — это none) отбракован",
         f"vless://{U}@95.1.2.3:443?type=raw#", False),
        ("vmess без TLS (tls нет — это none) отбракован",
         "vmess://" + base64.b64encode(json.dumps(
             {"add": "example.net", "port": "80", "id": U, "aid": "0",
              "net": "tcp", "scy": "auto"}).encode()).decode(), False),
        ("trojan security=none отбракован",
         "trojan://pw@example.com:443?security=none#", False),
        ("vless с TLS остаётся",
         f"vless://{U}@example.com:443?security=tls&type=ws&path=%2Fw#", True),
        ("trojan без security (по умолчанию tls) остаётся",
         "trojan://pw@example.com:443#", True),
        ("hysteria2 (всегда QUIC+TLS) остаётся",
         "hysteria2://pw@example.com:8443/#", True),
        ("ss фильтром без TLS не трогается (шифрует метод)",
         "ss://" + base64.b64encode(b"aes-256-gcm:pw@93.184.216.34:8388").decode() + "#",
         True),
        ("vmess с tls=tls остаётся",
         "vmess://" + base64.b64encode(json.dumps(
             {"add": "example.net", "port": "443", "id": U, "aid": "0",
              "net": "ws", "path": "/w", "tls": "tls",
              "scy": "auto"}).encode()).decode(), True),
        ("reality остаётся",
         f"vless://{U}@example.com:443?security=reality&pbk={key32}&sni=a.com#",
         True),
    ]
    for name, s, must in sec_cases:
        rec = worker([(0, s)])[0]
        got = "KEEP" if rec[0] == "k" else "REJ"
        ok = (rec[0] == "k") == must
        print("SEC", "OK " if ok else "FAIL", "-", name,
              "" if ok else f"(получено {got}: {rec[2] if rec[0] == 'r' else ''})")
        if not ok:
            fails += 1
    REJECT_INSECURE, REJECT_NO_TLS = sec_prev

    # ---- порты: нижняя граница 53 (мусорные порты ломают ядра) ----
    print("--- порты ниже 53 отбраковываются ---")
    port_cases = [
        ("ss порт 24 (мусор из подписок)",
         "ss://" + base64.b64encode(b"aes-256-gcm:pw@93.184.216.34:24").decode() + "#",
         False),
        ("vless порт 4",
         f"vless://{U}@93.184.216.34:4?security=tls&sni=a.com#", False),
        ("vmess порт 1",
         "vmess://" + base64.b64encode(json.dumps(
             {"add": "93.184.216.34", "port": "1", "id": U, "aid": "0",
              "net": "tcp", "scy": "auto", "tls": "tls"}).encode()).decode(), False),
        ("hysteria2 порт 22", "hysteria2://pw@93.184.216.34:22#", False),
        ("trojan порт 0", "trojan://pw@93.184.216.34:0#", False),
        ("порт 53 (минимальный допустимый) остаётся",
         f"vless://{U}@93.184.216.34:53?security=tls&sni=a.com#", True),
    ]
    for name, s, must in port_cases:
        rec = worker([(0, s)])[0]
        got = "KEEP" if rec[0] == "k" else "REJ"
        ok = (rec[0] == "k") == must
        print("PORT", "OK " if ok else "FAIL", "-", name,
              "" if ok else f"(получено {got}: {rec[2] if rec[0] == 'r' else rec[2][:60]})")
        if not ok:
            fails += 1
    rec = worker([(0, "hysteria2://pw@93.184.216.34:443?mport=4-65535#")])[0]
    ok = rec[0] == "k" and "mport" not in rec[2]
    print("PORT", "OK " if ok else "FAIL", "- hy2 mport с портом < 53 удаляется")
    if not ok:
        fails += 1
    rec = worker([(0, "hysteria2://pw@93.184.216.34:4-100#")])[0]
    ok = rec[0] == "r"
    print("PORT", "OK " if ok else "FAIL",
          "- hy2 диапазон портов в authority с нижней границей < 53 отбракован")
    if not ok:
        fails += 1
    rec = worker([(0, "hysteria2://pw@93.184.216.34:443?mport=20000-30000#")])[0]
    ok = rec[0] == "k" and "mport=20000-30000" in rec[2]
    print("PORT", "OK " if ok else "FAIL", "- hy2 корректный mport сохраняется")
    if not ok:
        fails += 1

    # ---- канон всех 6 протоколов: хвостовой '#' и round-trip ----
    print("--- канон всех 6 протоколов: кончается '#', round-trip сходится ---")
    rt_samples = {
        "vless": f"vless://{U}@example.com:443?type=ws&security=tls&path=%2Fw&sni=a.com#",
        "vmess": "vmess://" + base64.b64encode(json.dumps(
            {"v": "2", "ps": "", "add": "example.net", "port": "443", "id": U,
             "aid": "0", "scy": "auto", "net": "ws", "type": "none",
             "host": "c.example.net", "path": "/w", "tls": "tls",
             "sni": "c.example.net"}).encode()).decode(),
        "ss": "ss://" + base64.b64encode(b"aes-256-gcm:pw@93.184.216.34:8388").decode() + "#",
        "trojan": "trojan://pw@example.com:443?security=tls&sni=a.com#",
        "hysteria2": "hysteria2://pw@example.com:8443?sni=a.com&alpn=h3#",
        "tuic": f"tuic://{U}:pw@example.com:8443?sni=a.com&alpn=h3#",
    }
    for proto, s in rt_samples.items():
        rec = worker([(0, s)])[0]
        rt = worker([(0, rec[2])])[0] if rec[0] == "k" else rec
        ok = (rec[0] == "k" and rt[0] == "k"
              and _canon_hash_ok(rec[2]) and _canon_hash_ok(rt[2])
              and rt[6] == rec[6])
        print("RT", "OK " if ok else "FAIL",
              f"- {proto}: вывод кончается '#', повторный разбор — тот же узел")
        if not ok:
            fails += 1

    # ---- спасение повреждённых ссылок ----
    print("--- спасение повреждённых ссылок ---")
    rescue = [
        ("двойное &amp;amp; разворачивается в разделители",
         f"vless://{U}@example.com:443?type=ws&amp;amp;security=tls&amp;amp;path=%2Fw#",
         "type=ws&path=%2Fw"),
        ("процентный \\u0026 возвращает срезанные параметры",
         "hysteria2://pw@example.com:443?insecure=1&sni=example.com%5Cu0026mport%3D20000-30000#",
         "mport=20000-30000"),
        ("часть без '=' ('upmbps%3D…') разбирается",
         "hysteria2://pw@example.com:443?insecure=1&sni=example.com%5Cu0026upmbps%3D100#",
         "upmbps=100"),
        ("trojan ws=1&wspath → type=ws&path",
         "trojan://pw@116.47.10.236:27335?allowInsecure=1&sni=trojan.freenods.sbs&ws=1&wspath=%2F#",
         "type=ws&path=%2F"),
        ("hy2 upmbps/downmbps сохраняются",
         "hysteria2://pw@cdntw.xhl666.top:13456?downmbps=300&insecure=1&sni=cdntw.xhl666.top&upmbps=300#",
         "upmbps=300&downmbps=300"),
    ]
    for name, s, marker in rescue:
        rec = worker([(0, s)])[0]
        ok = rec[0] == "k" and marker in rec[2]
        print("RESCUE", "OK " if ok else "FAIL", "-", name,
              "" if ok else f"(получено: {rec[2][:70] if rec[0] == 'k' else rec[2]})")
        if not ok:
            fails += 1

    # ---- отсев v2rayNG: транспорт quic клиентом не поддерживается ----
    print("--- отсев v2rayNG: транспорт quic ---")
    quic_cases = [
        ("vless", f"vless://{U}@example.com:443?type=quic&security=tls#"),
        ("vmess", "vmess://" + base64.b64encode(json.dumps(
            {"add": "example.net", "port": "443", "id": U, "aid": "0",
             "net": "quic", "scy": "auto"}).encode()).decode()),
    ]
    for name, line in quic_cases:
        rec = worker([(0, line)])[0]
        ok = rec[0] == "r"
        print("V2RAYNG", "OK " if ok else "FAIL",
              f"- транспорт quic отсечён ({name})")
        if not ok:
            fails += 1

    # ---- tuic: парсер, канон, отбраковка, дедупликация ----
    print("--- tuic ---")
    T = "9288f4f6-29a1-4d96-b65f-3a2b3d0b6b53"
    # 1. каноническая сборка: uuid канонизируется, дефолты не пишутся
    rec = worker([(0, f"tuic://{T.upper()}:secret@93.184.216.36:8443"
                      "?sni=t.example.com&congestion_control=bbr"
                      "&udp_relay_mode=quic&udp_over_stream=1&reduce_rtt=1"
                      "&heartbeat=10&alpn=h3&disable_sni=1#t1")])[0]
    canon_ok = (rec[0] == "k" and
                rec[2].startswith(f"tuic://{T}:secret@93.184.216.36:8443?") and
                "congestion_control=bbr" in rec[2] and
                "udp_relay_mode=quic" in rec[2] and
                "udp_over_stream=1" in rec[2] and
                "reduce_rtt=1" in rec[2] and
                "heartbeat=10s" in rec[2] and
                "disable_sni=1" in rec[2] and
                "sni=t.example.com" in rec[2] and
                "alpn=h3" in rec[2] and
                "allow_insecure" not in rec[2] and
                _canon_hash_ok(rec[2]))
    print("TUIC", "OK " if canon_ok else "FAIL", "- каноническая сборка tuic")
    if not canon_ok:
        fails += 1
        print("      получено:", rec[2] if rec[0] == "k" else rec[2])
    # 2. round-trip: собственный вывод парсится в тот же узел
    rec2 = worker([(0, rec[2] + "#x")])[0] if rec[0] == "k" else rec
    rt_ok = (rec2[0] == "k" and rec2[6] == rec[6])
    print("TUIC", "OK " if rt_ok else "FAIL", "- round-trip канонического tuic")
    if not rt_ok:
        fails += 1
    # 3. дефолты (cubic/native) канонизируются и схлопываются дедупликацией
    ra = worker([(0, f"tuic://{T}:pw@93.184.216.37:443?congestion_control=cubic"
                     "&udp_relay_mode=native#a")])[0]
    rb = worker([(0, f"tuic://{T}:pw@93.184.216.37:443#b")])[0]
    ok = (ra[0] == "k" and rb[0] == "k" and ra[6] == rb[6] and
          "congestion_control" not in ra[2])
    print("TUIC", "OK " if ok else "FAIL",
          "- дефолтные cc/urm не пишутся и не различают узлы")
    if not ok:
        fails += 1
    # 4. чужие cc/urm канонизируются в дефолт (не отбраковка)
    rec = worker([(0, f"tuic://{T}:pw@93.184.216.38:443"
                      "?congestion_control=vegas&udp_relay_mode=weird#t")])[0]
    ok = (rec[0] == "k" and "congestion_control" not in rec[2]
          and "udp_relay_mode" not in rec[2])
    print("TUIC", "OK " if ok else "FAIL", "- чужие cc/urm → дефолт")
    if not ok:
        fails += 1
    # 5. отбраковка: v4-токен и битый uuid
    for name, s in (
        ("v4-токен (userinfo без ':')",
         "tuic://token123456@93.184.216.39:443#v4"),
        ("битый uuid", f"tuic://неuuid:pw@93.184.216.40:443#bad"),
    ):
        rec = worker([(0, s)])[0]
        ok = rec[0] == "r"
        print("TUIC", "OK " if ok else "FAIL", f"- отбраковка: {name}")
        if not ok:
            fails += 1
    # 6. разная учётка — разные узлы (учётка в ключе с уровня nekobox)
    rc = worker([(0, f"tuic://{T}:pw1@93.184.216.41:443#c")])[0]
    rd = worker([(0, f"tuic://{T}:pw2@93.184.216.41:443#d")])[0]
    ok = (rc[0] == "k" and rd[0] == "k"
          and node_fingerprint(PARSERS["tuic"](rc[2]), "nekobox")
          != node_fingerprint(PARSERS["tuic"](rd[2]), "nekobox"))
    print("TUIC", "OK " if ok else "FAIL", "- nekobox-уровень: другой пароль — другой узел")
    if not ok:
        fails += 1

    # ---- совместимость с ядром sing-box-extended ----
    print("--- совместимость с ядром sing-box-extended ---")

    def _vmess_json_out(line):
        """Разбирает канонический vmess-вывод обратно в словарь JSON."""
        rec = worker([(0, line)])[0]
        if rec[0] != "k":
            return None, rec
        blob = rec[2][8:]
        return json.loads(base64.b64decode(blob).decode()), rec

    U3 = "9288f4f6-29a1-4d96-b65f-3a2b3d0b6b53"

    core_ok = True

    # 1. plain — синоним none, канонизируется
    rec = worker([(0, "ss://plain:pw@93.184.216.34:8388#")])[0]
    want_ui = base64.urlsafe_b64encode(b"none:pw").decode().rstrip("=")
    ok = rec[0] == "k" and rec[2].startswith(f"ss://{want_ui}@")
    print("CORE", "OK " if ok else "FAIL", "- ss 'plain' канонизируется в 'none'")
    core_ok &= ok

    # 2. плагины: синонимы канонизируются, остальное отбраковывается
    #    (правила ядра и v2rayNG)
    plug_cases = [
        ("simple-obfs;obfs=http", "obfs-local%3Bobfs%3Dhttp", True,
         "plugin=obfs-local%3Bobfs%3Dhttp"),
        ("неизвестный плагин ck-client", "ck-client%3Bargs", False, ""),
        ("obfs-local с чужим режимом", "obfs-local%3Bobfs%3Dwebsocket", False, ""),
        ("obfs-local с режимом tls (v2rayNG выбрасывает плагин)",
         "obfs-local%3Bobfs%3Dtls", False, ""),
        ("obfs с режимом tls (синоним simple-obfs)",
         "obfs%3Bobfs%3Dtls", False, ""),
        ("v2ray;mode=websocket (v2rayNG выбрасывает плагин)",
         "v2ray%3Bmode%3Dwebsocket", False, ""),
        ("v2ray-plugin;mode=websocket;mux=0",
         "v2ray-plugin%3Bmode%3Dwebsocket%3Bmux%3D0", False, ""),
    ]
    for name, raw_plugin, must, marker in plug_cases:
        s = f"ss://aes-256-gcm:pw@93.184.216.34:8388?plugin={raw_plugin}#"
        rec = worker([(0, s)])[0]
        ok = (rec[0] == "k") == must and (not must or marker in rec[2])
        print("CORE", "OK " if ok else "FAIL", f"- плагин ss: {name}")
        core_ok &= ok

    # 3. legacy-шифры: чекер их отсекает, но ядро поддерживает —
    #    с выключенным фильтром они проходят до конца
    prev = CHECKER_FILTER
    CHECKER_FILTER = False
    legacy_keep = [
        "ss://" + base64.b64encode(b"aes-256-cfb:pw@93.184.216.34:8388").decode() + "#",
        "ss://" + base64.b64encode(b"rc4-md5:pw@93.184.216.34:8388").decode() + "#",
        "ss://" + base64.b64encode(b"chacha20-ietf:pw@93.184.216.34:8388").decode() + "#",
        "ss://" + base64.b64encode(b"aes-256-ctr:pw@93.184.216.34:8388").decode() + "#",
        "ss://aes-256-cfb:pw@93.184.216.34:8388#",
    ]
    for s in legacy_keep:
        rec = worker([(0, s)])[0]
        ok = rec[0] == "k" and _canon_hash_ok(rec[2])
        print("CORE", "OK " if ok else "FAIL",
              f"- legacy-шифр без фильтра чекера проходит: {rec[2][:44]}…")
        core_ok &= ok
    rec = worker([(0, "ss://table:pw@93.184.216.34:8388#")])[0]
    ok = rec[0] == "r"
    print("CORE", "OK " if ok else "FAIL", "- мёртвый шифр table отбракован всегда")
    core_ok &= ok
    CHECKER_FILTER = prev

    # 4. trojan-grpc: имя сервиса уезжает в grpc-service-name (ядро),
    #    без serviceName, который ядро трактует как SNI
    rec = worker([(0, "trojan://pw@example.com:443?type=grpc&serviceName=svc#a")])[0]
    ok = (rec[0] == "k" and "grpc-service-name=svc" in rec[2]
          and "serviceName=" not in rec[2])
    print("CORE", "OK " if ok else "FAIL", "- trojan grpc: grpc-service-name без подмены SNI")
    core_ok &= ok
    # обратная совместимость: собственный вывод парсится без потерь
    rec2 = worker([(0, rec[2] + "#x")])[0] if rec[0] == "k" else rec
    ok = rec2[0] == "k" and rec2[6] == rec[6]
    print("CORE", "OK " if ok else "FAIL", "- trojan grpc: round-trip канонического вывода")
    core_ok &= ok

    # 5. vmess-grpc: имя сервиса дублируется в host (его читает ядро)
    jj, rec = _vmess_json_out("vmess://" + base64.b64encode(json.dumps(
        {"add": "example.net", "port": "443", "id": U3, "aid": "0",
         "net": "grpc", "path": "/svc", "scy": "auto"}).encode()).decode())
    ok = rec[0] == "k" and jj.get("host") == "/svc" and jj.get("path") == "/svc"
    print("CORE", "OK " if ok else "FAIL", "- vmess grpc: service продублирован в host")
    core_ok &= ok

    # 6. insecure пишется под обоими именами (ядро читает insecure)
    rec = worker([(0, f"vless://{U3}@example.com:443?security=tls"
                      "&allowInsecure=1&type=ws&path=%2Fw#a")])[0]
    ok = (rec[0] == "k" and "allowInsecure=1" in rec[2] and "insecure=1" in rec[2])
    print("CORE", "OK " if ok else "FAIL", "- vless insecure: оба имени флага в выводе")
    core_ok &= ok
    jj, rec = _vmess_json_out("vmess://" + base64.b64encode(json.dumps(
        {"add": "example.net", "port": "443", "id": U3, "aid": "0",
         "net": "ws", "path": "/w", "tls": "tls",
         "allowInsecure": 1}).encode()).decode())
    ok = rec[0] == "k" and str(jj.get("allowInsecure")) == "1" and str(jj.get("insecure")) == "1"
    print("CORE", "OK " if ok else "FAIL", "- vmess insecure: оба ключа в JSON")
    core_ok &= ok

    # 7. legacy-шифр vmess (aes-128-cfb) сохраняется как есть
    jj, rec = _vmess_json_out("vmess://" + base64.b64encode(json.dumps(
        {"add": "example.net", "port": "443", "id": U3, "aid": "0",
         "net": "tcp", "scy": "aes-128-cfb"}).encode()).decode())
    ok = rec[0] == "k" and jj.get("scy") == "aes-128-cfb"
    print("CORE", "OK " if ok else "FAIL", "- vmess scy aes-128-cfb не переписывается")
    core_ok &= ok

    # 8. AEAD-алиасы Xray канонизируются в ietf-имена (их знает только ядро)
    rec = worker([(0, "ss://chacha20-poly1305:pw@93.184.216.34:8388#")])[0]
    want_ui = base64.urlsafe_b64encode(b"chacha20-ietf-poly1305:pw").decode().rstrip("=")
    ok = rec[0] == "k" and rec[2].startswith(f"ss://{want_ui}@")
    print("CORE", "OK " if ok else "FAIL", "- ss 'chacha20-poly1305' → 'chacha20-ietf-poly1305'")
    core_ok &= ok
    rec = worker([(0, "ss://" + base64.b64encode(
        b"xchacha20-poly1305:pw@93.184.216.34:8388").decode() + "#")])[0]
    want_ui = base64.urlsafe_b64encode(b"xchacha20-ietf-poly1305:pw").decode().rstrip("=")
    ok = rec[0] == "k" and rec[2].startswith(f"ss://{want_ui}@")
    print("CORE", "OK " if ok else "FAIL", "- ss 'xchacha20-poly1305' → 'xchacha20-ietf-poly1305'")
    core_ok &= ok

    if not core_ok:
        fails += 1

    print()
    print("ИТОГ:", "все проверки пройдены" if fails == 0
          else f"провалено проверок: {fails}")
    if fails:
        sys.exit(1)


# =========================================================================
# 17. ТОЧКА ВХОДА
# =========================================================================
def main() -> None:
    """Точка входа: загрузка настроек, логотип, главное меню в цикле.

    Пункт 1 — конвейер (чистка по мере дописывания configs.txt),
    пункт 2 — одна полная чистка, пункт 3 — настройки, пункт 4 — выход.
    При включённом auto_start конвейер запускается сразу, минуя меню.
    """
    global SETTINGS
    migrate_legacy_dirs()
    SETTINGS = load_settings()
    apply_settings(SETTINGS)
    os.makedirs(SERVICE_DIR, exist_ok=True)

    if AUTO_START:
        _run_stream_with_message()

    first_show = True
    while True:
        _print_main_menu(first_show)
        first_show = False
        raw = _ask("  Выберите пункт: ")
        if raw is None:
            _exit_script()
            return
        choice = raw.strip()
        if choice == '1':
            _run_stream_with_message()
        elif choice == '2':
            _run_single_with_message()
        elif choice == '3':
            _settings_loop()
        elif choice == '4':
            _exit_script()
        else:
            con.warn("Неверный пункт. Введите число от 1 до 4.")


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        _selftest()
    elif "--once" in sys.argv:
        # Автоматизация: одна чистка входного файла и выход,
        # без меню (для планировщика и других скриптов проекта)
        migrate_legacy_dirs()
        SETTINGS = load_settings()
        apply_settings(SETTINGS)
        os.makedirs(SERVICE_DIR, exist_ok=True)
        try:
            run_single_clean()
        except KeyboardInterrupt:
            con.warn("Прервано пользователем — прогресс сохранён.")
            sys.exit(1)
    elif "--stream" in sys.argv:
        # Автоматизация: конвейер без меню, CTRL+C — остановка.
        # --from-eof — начать с конца входного файла (см. run_stream_clean)
        migrate_legacy_dirs()
        SETTINGS = load_settings()
        apply_settings(SETTINGS)
        os.makedirs(SERVICE_DIR, exist_ok=True)   # заодно создаёт temp/
        try:
            run_stream_clean(from_eof="--from-eof" in sys.argv)
        except KeyboardInterrupt:
            pass
    else:
        main()
