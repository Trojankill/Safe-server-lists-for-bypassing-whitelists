# 🛡️ VPN Config Security Filter

<p align="center">
  <a href="https://github.com/Trojankill/Safe-server-lists-for-bypassing-whitelists/actions">
    <img src="https://img.shields.io/github/actions/workflow/status/Trojankill/Safe-server-lists-for-bypassing-whitelists/update.yml?label=auto-update&style=for-the-badge&logo=githubactions&logoColor=white" alt="CI">
  </a>
  <a href="https://github.com/Trojankill/Safe-server-lists-for-bypassing-whitelists/commits/main">
    <img src="https://img.shields.io/github/last-commit/Trojankill/Safe-server-lists-for-bypassing-whitelists?style=for-the-badge&logo=github&logoColor=white&color=orange" alt="Last commit">
  </a>
  <a href="https://github.com/Trojankill/Safe-server-lists-for-bypassing-whitelists/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/Trojankill/Safe-server-lists-for-bypassing-whitelists?style=for-the-badge&color=green" alt="License">
  </a>
  <img src="https://img.shields.io/badge/version-6.0-blueviolet?style=for-the-badge" alt="Version">
  <img src="https://img.shields.io/badge/refresh-every_15_minutes-blue?style=for-the-badge&logo=clockify&logoColor=white" alt="Refresh">
  <img src="https://img.shields.io/badge/python-3.8%2B-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python">
</p>

<p align="center">
  <a href="https://github.com/Trojankill/Safe-server-lists-for-bypassing-whitelists">
    <img src="https://img.shields.io/badge/mirror-GitHub-181717?style=for-the-badge&logo=github&logoColor=white" alt="GitHub">
  </a>
  <a href="https://bitbucket.org/trojankill/safe-server-lists">
    <img src="https://img.shields.io/badge/mirror-Bitbucket-205081?style=for-the-badge&logo=bitbucket&logoColor=white" alt="Bitbucket">
  </a>
  <a href="https://hub.mos.ru/Trojankill/safe-server-list">
    <img src="https://img.shields.io/badge/mirror-Mos.Hub-FC6D26?style=for-the-badge&logo=gitlab&logoColor=white" alt="Mos.Hub">
  </a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/VLESS-00D4FF?style=flat-square" alt="VLESS">
  <img src="https://img.shields.io/badge/VMess-FF6B6B?style=flat-square" alt="VMess">
  <img src="https://img.shields.io/badge/Trojan-4ECDC4?style=flat-square" alt="Trojan">
  <img src="https://img.shields.io/badge/Hysteria2-FFE66D?style=flat-square" alt="Hysteria2">
  <img src="https://img.shields.io/badge/TUIC-1DD3B0?style=flat-square" alt="TUIC">
  <img src="https://img.shields.io/badge/Shadowsocks-95E1D3?style=flat-square" alt="Shadowsocks">
  <img src="https://img.shields.io/badge/Clash%2FMihomo-7159C6?style=flat-square" alt="Clash">
</p>

<p align="center">
  <b>🔒 Автоматизированный аудит и фильтрация публичных прокси-конфигураций</b><br>
  <sub>Полный разбор ссылок · Защита от MITM · Sybil-детекция · Fail-closed валидация · Потокобезопасность · IPv6 · Clash/Mihomo</sub>
</p>

---

<a id="whats-new"></a>
## 🚀 Что нового в v6.0

Главное изменение: **каждая ссылка теперь разбирается по-настоящему**, а не проверяется регулярками по сырой строке. Проценты раскодируются, `&amp;` и `\u0026` чинятся, синонимы параметров сводятся к одному имени. Всё, что раньше проходило как «нечитаемо — значит нормально», теперь отбраковывается.

<table>
<tr>
<td width="50%">

### 🔬 Разбор и нормализация

- ✅ **URI-парсер вместо regex** — vless / vmess / trojan / hysteria2 / ss / tuic разбираются в структуру
- ✅ **Двойное декодирование** — `&amp;amp;`, `\u0026`, `%5Cu0026`, `¬`
- ✅ **Невидимые символы** — zero-width, BOM, `\n`, control chars вырезаются до проверки
- ✅ **Синонимы параметров** — `allowlnsecure` (с маленькой L), `skip-cert-verify`, `skip_cert_verify`, `insecure`
- ✅ **Схема в нижнем регистре** — `VLESS://` больше не ломает разбор
- ✅ **Флаги небезопасности** — любое значение кроме явного `0/false/no/off` считается включённым
- ✅ **vmess `"tls":"none"`** — больше не проходит как валидный TLS
- ✅ **Дубликаты до лимитов** — один узел с разными именами не выбивает честные конфиги

</td>
<td width="50%">

### 🌐 Адреса и протоколы

- ✅ **`ipaddress` вместо regex** — 169.254/16, 100.64/10, 198.18/15, мультикаст, ULA
- ✅ **Обфусцированные IP** — `0x7f000001`, `2130706433`, ведущие нули
- ✅ **Публичные DNS** — 1.1.1.1, 8.8.8.8 и ещё 10 адресов как «сервер» отбраковываются
- ✅ **Порты < 22** — мусор из подписок
- ✅ **UUID-валидация** — у vless / vmess / tuic, нулевые и служебные отбрасываются
- ✅ **Reality** — `pbk` строго 43 символа base64url / 32 байта, `sid` сохраняется
- ✅ **SS legacy** — `ss://base64(method:pass@host:port)` поддержан
- ✅ **SS 2022** — ключи проверяются по частям, EIH-структура, длина
- ✅ **SSR удалён** — ни NekoBox, ни v2rayNG, ни sing-box его не понимают

</td>
</tr>
<tr>
<td width="50%">

### 🎨 Clash / Mihomo

- ✅ **YAML-квотирование** — `json.dumps` вместо bare-скаляров: `123456`, `yes`, `null` остаются строками
- ✅ **Экранирование `\` и `'`** — имя вида `foo'\` больше не рвёт весь файл
- ✅ **Уникальные имена** — `name #2`, `name #3`, Mihomo не отвергает подписку целиком
- ✅ **TUIC и SS-плагины** — конвертируются без потерь
- ✅ **IPv6** — `[2001:db8::1]:443` в обе стороны
- ✅ **`serviceName`** — grpc-сервис не теряется
- ✅ **`skip-cert-verify`** — превращается в `allowInsecure=1` и отбраковывается, а не исчезает

</td>
<td width="50%">

### ⚙️ Инфраструктура

- ✅ **Cooldown источников** — 3 провала = пауза 12 часов, не вечный бан
- ✅ **Лимит ответа** — 64 МБ, защита от бесконечных подписок
- ✅ **Таймауты** — 30 с на загрузку
- ✅ **`@lru_cache`** — горячие проверки не пересчитываются
- ✅ **`ThreadPoolExecutor`** — источники грузятся параллельно
- ✅ **`threading.Lock`** — health-трекинг потокобезопасен
- ✅ **`RAW_BASE` через env** — форки не привязаны к чужому репозиторию
- ✅ **Отчёт по причинам** — `rejected/reasons.md` со статистикой

</td>
</tr>
</table>

### 🗑️ Что удалено и почему

| Удалено | Причина |
|---|---|
| **ShadowsocksR** | Нет ни в v2rayNG, ни в NekoBox, ни в sing-box. AEAD-методов в SSR не существует, проверка отбрасывала всё — смысла держать парсер нет |
| **Дубли поддоменов в банлисте** | `cdn.trahodrom.fun` перекрыт `trahodrom.fun`, `gpt-plus.vepene.site` — `.site` |
| **Вечный бан мёртвых источников** | Источник может ожить. Теперь cooldown 12 ч |

---

<a id="warning"></a>
## ⚠️ Прежде чем использовать

> [!WARNING]
> Все подписки предназначены для обхода **белых списков**. Прошу вас **не использовать** их с включённым Wi-Fi — работать они будут даже на Wi-Fi. Дайте пользоваться серверами тем, у кого действительно включены белые списки: мощность серверов и производительность сильно падают из-за наплыва пользователей.

> [!CAUTION]
> **НАСТОЯТЕЛЬНО РЕКОМЕНДУЮ НЕ ИСПОЛЬЗОВАТЬ ЭТИ VPN-СЕРВЕРЫ ДЛЯ БАНКОВСКИХ ПЕРЕВОДОВ.**
> Даже если конфигурация прошла фильтр, это не означает, что оператор сервера безопасен. Также не рекомендуется использование государственных приложений без нормальной split-маршрутизации: **Yandex, VK, MAX, Госуслуги** и т.п. — чтобы снизить риск блокировок серверов.

> [!IMPORTANT]
> **«Прошёл фильтр» ≠ «оператору можно доверять».**
> Скрипт проверяет только техническую корректность конфигурации: TLS-параметры, домены, порты, транспорты, креды, Sybil-повторы, слабые шифры и опасные флаги. Он не проверяет репутацию владельца сервера. Оператор может видеть ваш SNI без ECH, plaintext HTTP и DNS, если он не резолвится локально.

> [!WARNING]
> Из-за атак по инфраструктуре Яндекса способ с Яндекс.Переводчиком временно не работает или работает нестабильно. Используйте **hub.mos.ru** для обновления в условиях БС — ниже все ссылки предоставлены.

---

<a id="toc"></a>
## 📑 Содержание

- [Что нового в v6.0](#whats-new)
- [Прежде чем использовать](#warning)
- [Что делает проект](#what-it-does)
- [Зеркала](#mirrors)
- [Источники данных](#sources)
- [Подписки и QR-коды](#subscriptions)
- [Как сканировать](#scan)
- [Локальный запуск](#local)
- [Настройки политики](#policy)
- [Выходные файлы](#outputs)
- [FAQ](#faq)
- [Дисклеймер](#disclaimer)

---

<a id="what-it-does"></a>
## 🔍 Что делает проект

Скрипт `filter.py` выполняет **статический анализ** конфигурационных строк из публичных подписок и отбраковывает записи по критериям:

### 🛡️ Базовая безопасность

| Категория | Примеры | Статус |
|---|---|:---:|
| 🔓 Небезопасные TLS-параметры | `allowInsecure=1`, `allowlnsecure=1`, `security=none`, `verify=false`, `disable_sni`, `skip-cert-verify=1`, `insecure=yes` | ✅ |
| 🚫 Запрещённые / скомпрометированные домены | бесплатные хостинги, известные пулы, подозрительные зоны | ✅ |
| ⚡ Опасные транспортные комбинации | `type=quic` (станет `tcp`), `xhttp` без `host`, TLS на `kcp` | ✅ |
| 🏠 Приватные / loopback адреса | `127.0.0.1`, `localhost`, `10.x`, `192.168.x`, `172.16-31.x`, `169.254.x`, `100.64/10`, IPv6 ULA | ✅ |
| 🔢 Обфусцированные IP | `0x7f000001`, `2130706433`, ведущие нули `010.0.0.1` | ✅ |
| 📡 Публичные DNS как сервер | `1.1.1.1`, `8.8.8.8`, `9.9.9.9`, AdGuard, Quad9 | ✅ |
| 🔌 Некорректные порты | порт `< 22`, `> 65535`, нечисловой порт | ✅ |
| 🕵️ MITM / DNS-подмена | кастомные CA, нестандартные DNS, sniffing на внешние домены | ✅ |
| 🔑 Слабое шифрование SS | RC4, DES, CFB, CTR, Salsa20, ChaCha20 non-IETF, `none` | ✅ |
| 🧮 SS 2022 key validation | неверная длина base64-ключа для `2022-blake3-*`, лишние EIH-части | ✅ |
| 🌐 IPv6 support | `[2001:db8::1]:443`, проверка link-local / ULA / loopback | ✅ |

### 📦 Протокол-специфичные проверки

| Протокол | Проверки | Статус |
|---|---|:---:|
| **VLESS Reality** | отсутствие `pbk` / `fp`, невалидный `flow`, `pbk` ≠ 43 символа base64url, невалидный `sid` | ✅ |
| **VLESS TLS** | отсутствие `sni` / `host` / `alpn`, невалидный transport, `encryption` не `none` и не `mlkem768x25519plus` | ✅ |
| **VMess fmt-1** | `alterId > 0`, `allowInsecure`, отсутствие TLS, `tls:"none"`, `scy=none`, `v` не `1/2` | ✅ |
| **VMess fmt-2** | `alterId > 0`, `security=none`, отсутствие `sni` при TLS/Reality | ✅ |
| **Trojan** | пустой пароль, отсутствие SNI, публичные пулы, опасные domain-параметры, `trojan-go` | ✅ |
| **Hysteria2** | `insecure=1`, отсутствие SNI, пустой пароль, `obfs` без пароля | ✅ |
| **TUIC** | отсутствие creds/SNI, невалидный `congestion_control`, невалидный `udp_relay_mode`, ALPN без `h3` | ✅ |
| **Shadowsocks** | слабые методы, пустой пароль, невалидный 2022-ключ, плагин кроме `obfs-local;obfs=http` | ✅ |
| **ShadowsocksR** | — | ❌ удалён |

### 🔒 Продвинутая защита

| Категория | Описание | Статус |
|---|---|:---:|
| 🐝 **Sybil-детекция** | дедуп по `pbk` / `uuid` / `sid` / Trojan password / TUIC creds, лимит `3` | ✅ |
| 🧵 **Endpoint-дедуп** | `host:port:proto`, лимит `5` на один endpoint | ✅ |
| 🧵 **Потокобезопасность** | `threading.Lock` на health-tracking при параллельной загрузке | ✅ |
| 🎯 **Точный домен-матч** | `.cf` матчит только TLD, `boot-lee.ru` только exact/subdomain | ✅ |
| 🛡️ **Fail-closed** | битая кодировка = reject, не тихий пропуск | ✅ |
| 🔐 **Post-quantum checks** | валидация ML-KEM + X25519 hybrid параметров | ✅ |
| 🎭 **Placeholder UUID** | блокировка `0000...` и `ffff...` UUID | ✅ |
| 📡 **Base64 round-trip** | подписки декодируются → фильтруются → кодируются обратно | ✅ |
| 🌐 **Точный DNS-матч** | `dns=` проверяется как точный host против whitelist | ✅ |
| 🔄 **Clash/Mihomo export** | отдельная генерация YAML-подписок в `githubmirror/Clash/` | ✅ |

Результат — очищенные списки в `githubmirror/`, обновляемые каждые **15 минут** через GitHub Actions.

---

<a id="mirrors"></a>
## 🪞 Зеркала

Проект автоматически зеркалируется в несколько источников. Если один зеркальный хост недоступен, используй другой.

| Зеркало | Репозиторий | Raw base для подписок |
|---|---|---|
| **GitHub** | [Trojankill/Safe-server-lists-for-bypassing-whitelists](https://github.com/Trojankill/Safe-server-lists-for-bypassing-whitelists) | `https://raw.githubusercontent.com/Trojankill/Safe-server-lists-for-bypassing-whitelists/main/githubmirror` |
| **Bitbucket** | [trojankill/safe-server-lists](https://bitbucket.org/trojankill/safe-server-lists) | `https://bitbucket.org/trojankill/safe-server-lists/raw/main/githubmirror` |
| **Mos.Hub (работает при БС)** | [Trojankill/safe-server-list](https://hub.mos.ru/Trojankill/safe-server-list) | `https://hub.mos.ru/Trojankill/safe-server-list/-/raw/main/githubmirror` |

> [!NOTE]
> QR-коды в папке `QR-CODE/` генерируются переменной окружения `RAW_BASE`.
> Если в workflow сейчас указан `hub.mos.ru`, то QR будут вести на Mos.Hub.
> Если хочешь, чтобы QR вели именно на Bitbucket, замени в workflow:
>
> ```yaml
> RAW_BASE: https://bitbucket.org/trojankill/safe-server-lists/raw/main/githubmirror
> ```

---

<a id="sources"></a>
## 📥 Источники данных

Конфигурации берутся из публичных открытых источников. Актуальный статус доступности каждого источника пишется в:

```text
githubmirror/URL_HEALTH_REPORT.md
githubmirror/url_health.json
```

| ID | Источник | Формат |
|:---:|---|:---:|
| `FILTER-1` | [hub.mos.ru/rkp/sub-roskompozor](https://hub.mos.ru/rkp/sub-roskompozor/raw/main/wl) | plaintext |
| `FILTER-2` | [gitverse.ru/KOT_ANTIDOT/BUNKER](https://gitverse.ru/api/repos/KOT_ANTIDOT/BUNKER/raw/branch/master/BLWL_MIX.txt) | plaintext |
| `FILTER-3` | [GitHub: zieng2/wl](https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_lite.txt) | plaintext |
| `FILTER-4` | [GitHub: whoahaow/rjsxrd](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-all.txt) | plaintext |
| `FILTER-5` | [GitHub: LSO-LinSpisokObhod](https://raw.githubusercontent.com/LSO-LinSpisokObhod/LSO-LinSpisokObhod.github.io/refs/heads/main/sub/LTE.txt) | plaintext |
| `FILTER-6` | [GitHub: kort0881/vpn-vless-configs-russia](https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/refs/heads/main/output/vless.txt) | plaintext |
| `FILTER-7` | [sub.snowdnvpn.com](https://sub.snowdnvpn.com/X7-1DWP_9Qyu1wrC) | plaintext |
| `FILTER-8-BASE64` | [GitHub: Diversan313/apex-parser — alive_bs](https://raw.githubusercontent.com/Diversan313/apex-parser/refs/heads/main/subs/main/alive_bs.txt) | **base64** |
| `FILTER-9-BASE64` | [GitHub: Diversan313/apex-parser — alive_bl](https://raw.githubusercontent.com/Diversan313/apex-parser/main/subs/main/alive_bl.txt) | **base64** |
| `FILTER-10` | [sub.vlessfo.ru](https://sub.vlessfo.ru/vlessforu/working_configs.txt) | plaintext |
| `FILTER-11` | [hub.mos.ru/akelladejavu/bunker](https://hub.mos.ru/akelladejavu/bunker/-/raw/main/WHITE_LIST.txt) | plaintext |
| `FILTER-12` | [p.kfwl.lol proxy](https://p.kfwl.lol/https://tgmansion.fun/sub/3006966d1608d911) | plaintext |
| `FILTER-13` | [GitHub: vessel-web/CoolSubs](https://github.com/vessel-web/CoolSubs/raw/refs/heads/main/Cool-White.txt) | plaintext |

> [!TIP]
> Источник с `3+` провалами подряд ставится на паузу на **12 часов**, после чего пробуется снова. Это защищает общий `ALL.txt` от зависания из-за одного мёртвого upstream, но не банит источник навсегда.

---

<a id="subscriptions"></a>
## 📱 Подписки и QR-коды

Все QR-коды также собраны в HTML-индексе:

- [Открыть `QR-CODE/index.html`](QR-CODE/index.html)

Ниже для каждой подписки даны:
- GitHub raw;
- Bitbucket raw;
- Яндекс.Переводчик поверх Bitbucket raw;
- Mos.Hub raw;
- Clash/Mihomo YAML, если нужен именно Clash.

<details open>
<summary><b>📡 ALL</b> — все конфиги, рекомендуется</summary>

<p align="center">
  <img src="QR-CODE/ALL.png" width="280" alt="ALL QR">
</p>

| Сервис | Ссылка |
|---|---|
| GitHub | [`ALL.txt`](https://raw.githubusercontent.com/Trojankill/Safe-server-lists-for-bypassing-whitelists/main/githubmirror/ALL.txt) |
| Bitbucket | [`ALL.txt`](https://bitbucket.org/trojankill/safe-server-lists/raw/main/githubmirror/ALL.txt) |
| Яндекс переводчик | [`ALL.txt через Яндекс`](https://translate.yandex.ru/translate?url=https%3A%2F%2Fbitbucket.org%2Ftrojankill%2Fsafe-server-lists%2Fraw%2Fmain%2Fgithubmirror%2FALL.txt&lang=de-de) |
| Mos.Hub | [`ALL.txt`](https://hub.mos.ru/Trojankill/safe-server-list/-/raw/main/githubmirror/ALL.txt) |
| Clash GitHub | [`ALL.yaml`](https://raw.githubusercontent.com/Trojankill/Safe-server-lists-for-bypassing-whitelists/main/githubmirror/Clash/ALL.yaml) |
| Clash Bitbucket | [`ALL.yaml`](https://bitbucket.org/trojankill/safe-server-lists/raw/main/githubmirror/Clash/ALL.yaml) |

</details>

<details>
<summary><b>📡 FILTER-1</b> — Mos.Hub: rkp/sub-roskompozor</summary>

<p align="center">
  <img src="QR-CODE/FILTER-1.png" width="280" alt="FILTER-1 QR">
</p>

| Сервис | Ссылка |
|---|---|
| GitHub | [`FILTER-1.txt`](https://raw.githubusercontent.com/Trojankill/Safe-server-lists-for-bypassing-whitelists/main/githubmirror/FILTER-1.txt) |
| Bitbucket | [`FILTER-1.txt`](https://bitbucket.org/trojankill/safe-server-lists/raw/main/githubmirror/FILTER-1.txt) |
| Яндекс переводчик | [`FILTER-1.txt через Яндекс`](https://translate.yandex.ru/translate?url=https%3A%2F%2Fbitbucket.org%2Ftrojankill%2Fsafe-server-lists%2Fraw%2Fmain%2Fgithubmirror%2FFILTER-1.txt&lang=de-de) |
| Mos.Hub | [`FILTER-1.txt`](https://hub.mos.ru/Trojankill/safe-server-list/-/raw/main/githubmirror/FILTER-1.txt) |
| Clash GitHub | [`FILTER-1.yaml`](https://raw.githubusercontent.com/Trojankill/Safe-server-lists-for-bypassing-whitelists/main/githubmirror/Clash/FILTER-1.yaml) |
| Clash Bitbucket | [`FILTER-1.yaml`](https://bitbucket.org/trojankill/safe-server-lists/raw/main/githubmirror/Clash/FILTER-1.yaml) |

</details>

<details>
<summary><b>📡 FILTER-2</b> — GitVerse: KOT_ANTIDOT/BUNKER</summary>

<p align="center">
  <img src="QR-CODE/FILTER-2.png" width="280" alt="FILTER-2 QR">
</p>

| Сервис | Ссылка |
|---|---|
| GitHub | [`FILTER-2.txt`](https://raw.githubusercontent.com/Trojankill/Safe-server-lists-for-bypassing-whitelists/main/githubmirror/FILTER-2.txt) |
| Bitbucket | [`FILTER-2.txt`](https://bitbucket.org/trojankill/safe-server-lists/raw/main/githubmirror/FILTER-2.txt) |
| Яндекс переводчик | [`FILTER-2.txt через Яндекс`](https://translate.yandex.ru/translate?url=https%3A%2F%2Fbitbucket.org%2Ftrojankill%2Fsafe-server-lists%2Fraw%2Fmain%2Fgithubmirror%2FFILTER-2.txt&lang=de-de) |
| Mos.Hub | [`FILTER-2.txt`](https://hub.mos.ru/Trojankill/safe-server-list/-/raw/main/githubmirror/FILTER-2.txt) |
| Clash GitHub | [`FILTER-2.yaml`](https://raw.githubusercontent.com/Trojankill/Safe-server-lists-for-bypassing-whitelists/main/githubmirror/Clash/FILTER-2.yaml) |
| Clash Bitbucket | [`FILTER-2.yaml`](https://bitbucket.org/trojankill/safe-server-lists/raw/main/githubmirror/Clash/FILTER-2.yaml) |

</details>

<details>
<summary><b>📡 FILTER-3</b> — GitHub: zieng2/wl</summary>

<p align="center">
  <img src="QR-CODE/FILTER-3.png" width="280" alt="FILTER-3 QR">
</p>

| Сервис | Ссылка |
|---|---|
| GitHub | [`FILTER-3.txt`](https://raw.githubusercontent.com/Trojankill/Safe-server-lists-for-bypassing-whitelists/main/githubmirror/FILTER-3.txt) |
| Bitbucket | [`FILTER-3.txt`](https://bitbucket.org/trojankill/safe-server-lists/raw/main/githubmirror/FILTER-3.txt) |
| Яндекс переводчик | [`FILTER-3.txt через Яндекс`](https://translate.yandex.ru/translate?url=https%3A%2F%2Fbitbucket.org%2Ftrojankill%2Fsafe-server-lists%2Fraw%2Fmain%2Fgithubmirror%2FFILTER-3.txt&lang=de-de) |
| Mos.Hub | [`FILTER-3.txt`](https://hub.mos.ru/Trojankill/safe-server-list/-/raw/main/githubmirror/FILTER-3.txt) |
| Clash GitHub | [`FILTER-3.yaml`](https://raw.githubusercontent.com/Trojankill/Safe-server-lists-for-bypassing-whitelists/main/githubmirror/Clash/FILTER-3.yaml) |
| Clash Bitbucket | [`FILTER-3.yaml`](https://bitbucket.org/trojankill/safe-server-lists/raw/main/githubmirror/Clash/FILTER-3.yaml) |

</details>

<details>
<summary><b>📡 FILTER-4</b> — GitHub: whoahaow/rjsxrd</summary>

<p align="center">
  <img src="QR-CODE/FILTER-4.png" width="280" alt="FILTER-4 QR">
</p>

| Сервис | Ссылка |
|---|---|
| GitHub | [`FILTER-4.txt`](https://raw.githubusercontent.com/Trojankill/Safe-server-lists-for-bypassing-whitelists/main/githubmirror/FILTER-4.txt) |
| Bitbucket | [`FILTER-4.txt`](https://bitbucket.org/trojankill/safe-server-lists/raw/main/githubmirror/FILTER-4.txt) |
| Яндекс переводчик | [`FILTER-4.txt через Яндекс`](https://translate.yandex.ru/translate?url=https%3A%2F%2Fbitbucket.org%2Ftrojankill%2Fsafe-server-lists%2Fraw%2Fmain%2Fgithubmirror%2FFILTER-4.txt&lang=de-de) |
| Mos.Hub | [`FILTER-4.txt`](https://hub.mos.ru/Trojankill/safe-server-list/-/raw/main/githubmirror/FILTER-4.txt) |
| Clash GitHub | [`FILTER-4.yaml`](https://raw.githubusercontent.com/Trojankill/Safe-server-lists-for-bypassing-whitelists/main/githubmirror/Clash/FILTER-4.yaml) |
| Clash Bitbucket | [`FILTER-4.yaml`](https://bitbucket.org/trojankill/safe-server-lists/raw/main/githubmirror/Clash/FILTER-4.yaml) |

</details>

<details>
<summary><b>📡 FILTER-5</b> — GitHub: LSO-LinSpisokObhod</summary>

<p align="center">
  <img src="QR-CODE/FILTER-5.png" width="280" alt="FILTER-5 QR">
</p>

| Сервис | Ссылка |
|---|---|
| GitHub | [`FILTER-5.txt`](https://raw.githubusercontent.com/Trojankill/Safe-server-lists-for-bypassing-whitelists/main/githubmirror/FILTER-5.txt) |
| Bitbucket | [`FILTER-5.txt`](https://bitbucket.org/trojankill/safe-server-lists/raw/main/githubmirror/FILTER-5.txt) |
| Яндекс переводчик | [`FILTER-5.txt через Яндекс`](https://translate.yandex.ru/translate?url=https%3A%2F%2Fbitbucket.org%2Ftrojankill%2Fsafe-server-lists%2Fraw%2Fmain%2Fgithubmirror%2FFILTER-5.txt&lang=de-de) |
| Mos.Hub | [`FILTER-5.txt`](https://hub.mos.ru/Trojankill/safe-server-list/-/raw/main/githubmirror/FILTER-5.txt) |
| Clash GitHub | [`FILTER-5.yaml`](https://raw.githubusercontent.com/Trojankill/Safe-server-lists-for-bypassing-whitelists/main/githubmirror/Clash/FILTER-5.yaml) |
| Clash Bitbucket | [`FILTER-5.yaml`](https://bitbucket.org/trojankill/safe-server-lists/raw/main/githubmirror/Clash/FILTER-5.yaml) |

</details>

<details>
<summary><b>📡 FILTER-6</b> — GitHub: kort0881/vpn-vless-configs-russia</summary>

<p align="center">
  <img src="QR-CODE/FILTER-6.png" width="280" alt="FILTER-6 QR">
</p>

| Сервис | Ссылка |
|---|---|
| GitHub | [`FILTER-6.txt`](https://raw.githubusercontent.com/Trojankill/Safe-server-lists-for-bypassing-whitelists/main/githubmirror/FILTER-6.txt) |
| Bitbucket | [`FILTER-6.txt`](https://bitbucket.org/trojankill/safe-server-lists/raw/main/githubmirror/FILTER-6.txt) |
| Яндекс переводчик | [`FILTER-6.txt через Яндекс`](https://translate.yandex.ru/translate?url=https%3A%2F%2Fbitbucket.org%2Ftrojankill%2Fsafe-server-lists%2Fraw%2Fmain%2Fgithubmirror%2FFILTER-6.txt&lang=de-de) |
| Mos.Hub | [`FILTER-6.txt`](https://hub.mos.ru/Trojankill/safe-server-list/-/raw/main/githubmirror/FILTER-6.txt) |
| Clash GitHub | [`FILTER-6.yaml`](https://raw.githubusercontent.com/Trojankill/Safe-server-lists-for-bypassing-whitelists/main/githubmirror/Clash/FILTER-6.yaml) |
| Clash Bitbucket | [`FILTER-6.yaml`](https://bitbucket.org/trojankill/safe-server-lists/raw/main/githubmirror/Clash/FILTER-6.yaml) |

</details>

<details>
<summary><b>📡 FILTER-7</b> — sub.snowdnvpn.com</summary>

<p align="center">
  <img src="QR-CODE/FILTER-7.png" width="280" alt="FILTER-7 QR">
</p>

| Сервис | Ссылка |
|---|---|
| GitHub | [`FILTER-7.txt`](https://raw.githubusercontent.com/Trojankill/Safe-server-lists-for-bypassing-whitelists/main/githubmirror/FILTER-7.txt) |
| Bitbucket | [`FILTER-7.txt`](https://bitbucket.org/trojankill/safe-server-lists/raw/main/githubmirror/FILTER-7.txt) |
| Яндекс переводчик | [`FILTER-7.txt через Яндекс`](https://translate.yandex.ru/translate?url=https%3A%2F%2Fbitbucket.org%2Ftrojankill%2Fsafe-server-lists%2Fraw%2Fmain%2Fgithubmirror%2FFILTER-7.txt&lang=de-de) |
| Mos.Hub | [`FILTER-7.txt`](https://hub.mos.ru/Trojankill/safe-server-list/-/raw/main/githubmirror/FILTER-7.txt) |
| Clash GitHub | [`FILTER-7.yaml`](https://raw.githubusercontent.com/Trojankill/Safe-server-lists-for-bypassing-whitelists/main/githubmirror/Clash/FILTER-7.yaml) |
| Clash Bitbucket | [`FILTER-7.yaml`](https://bitbucket.org/trojankill/safe-server-lists/raw/main/githubmirror/Clash/FILTER-7.yaml) |

</details>

<details>
<summary><b>📡 FILTER-8-BASE64</b> — GitHub: Diversan313/apex-parser — alive_bs</summary>

<p align="center">
  <img src="QR-CODE/FILTER-8-BASE64.png" width="280" alt="FILTER-8-BASE64 QR">
</p>

| Сервис | Ссылка |
|---|---|
| GitHub | [`FILTER-8-BASE64.txt`](https://raw.githubusercontent.com/Trojankill/Safe-server-lists-for-bypassing-whitelists/main/githubmirror/FILTER-8-BASE64.txt) |
| Bitbucket | [`FILTER-8-BASE64.txt`](https://bitbucket.org/trojankill/safe-server-lists/raw/main/githubmirror/FILTER-8-BASE64.txt) |
| Яндекс переводчик | [`FILTER-8-BASE64.txt через Яндекс`](https://translate.yandex.ru/translate?url=https%3A%2F%2Fbitbucket.org%2Ftrojankill%2Fsafe-server-lists%2Fraw%2Fmain%2Fgithubmirror%2FFILTER-8-BASE64.txt&lang=de-de) |
| Mos.Hub | [`FILTER-8-BASE64.txt`](https://hub.mos.ru/Trojankill/safe-server-list/-/raw/main/githubmirror/FILTER-8-BASE64.txt) |
| Clash GitHub | [`FILTER-8-BASE64.yaml`](https://raw.githubusercontent.com/Trojankill/Safe-server-lists-for-bypassing-whitelists/main/githubmirror/Clash/FILTER-8-BASE64.yaml) |
| Clash Bitbucket | [`FILTER-8-BASE64.yaml`](https://bitbucket.org/trojankill/safe-server-lists/raw/main/githubmirror/Clash/FILTER-8-BASE64.yaml) |

> [!NOTE]
> Файл закодирован в base64. Клиенты v2rayNG / Karing / Hiddify обычно декодируют автоматически.

</details>

<details>
<summary><b>📡 FILTER-9-BASE64</b> — GitHub: Diversan313/apex-parser — alive_bl</summary>

<p align="center">
  <img src="QR-CODE/FILTER-9-BASE64.png" width="280" alt="FILTER-9-BASE64 QR">
</p>

| Сервис | Ссылка |
|---|---|
| GitHub | [`FILTER-9-BASE64.txt`](https://raw.githubusercontent.com/Trojankill/Safe-server-lists-for-bypassing-whitelists/main/githubmirror/FILTER-9-BASE64.txt) |
| Bitbucket | [`FILTER-9-BASE64.txt`](https://bitbucket.org/trojankill/safe-server-lists/raw/main/githubmirror/FILTER-9-BASE64.txt) |
| Яндекс переводчик | [`FILTER-9-BASE64.txt через Яндекс`](https://translate.yandex.ru/translate?url=https%3A%2F%2Fbitbucket.org%2Ftrojankill%2Fsafe-server-lists%2Fraw%2Fmain%2Fgithubmirror%2FFILTER-9-BASE64.txt&lang=de-de) |
| Mos.Hub | [`FILTER-9-BASE64.txt`](https://hub.mos.ru/Trojankill/safe-server-list/-/raw/main/githubmirror/FILTER-9-BASE64.txt) |
| Clash GitHub | [`FILTER-9-BASE64.yaml`](https://raw.githubusercontent.com/Trojankill/Safe-server-lists-for-bypassing-whitelists/main/githubmirror/Clash/FILTER-9-BASE64.yaml) |
| Clash Bitbucket | [`FILTER-9-BASE64.yaml`](https://bitbucket.org/trojankill/safe-server-lists/raw/main/githubmirror/Clash/FILTER-9-BASE64.yaml) |

> [!NOTE]
> Файл закодирован в base64. Клиенты v2rayNG / Karing / Hiddify обычно декодируют автоматически.

</details>

<details>
<summary><b>📡 FILTER-10</b> — sub.vlessfo.ru</summary>

<p align="center">
  <img src="QR-CODE/FILTER-10.png" width="280" alt="FILTER-10 QR">
</p>

| Сервис | Ссылка |
|---|---|
| GitHub | [`FILTER-10.txt`](https://raw.githubusercontent.com/Trojankill/Safe-server-lists-for-bypassing-whitelists/main/githubmirror/FILTER-10.txt) |
| Bitbucket | [`FILTER-10.txt`](https://bitbucket.org/trojankill/safe-server-lists/raw/main/githubmirror/FILTER-10.txt) |
| Яндекс переводчик | [`FILTER-10.txt через Яндекс`](https://translate.yandex.ru/translate?url=https%3A%2F%2Fbitbucket.org%2Ftrojankill%2Fsafe-server-lists%2Fraw%2Fmain%2Fgithubmirror%2FFILTER-10.txt&lang=de-de) |
| Mos.Hub | [`FILTER-10.txt`](https://hub.mos.ru/Trojankill/safe-server-list/-/raw/main/githubmirror/FILTER-10.txt) |
| Clash GitHub | [`FILTER-10.yaml`](https://raw.githubusercontent.com/Trojankill/Safe-server-lists-for-bypassing-whitelists/main/githubmirror/Clash/FILTER-10.yaml) |
| Clash Bitbucket | [`FILTER-10.yaml`](https://bitbucket.org/trojankill/safe-server-lists/raw/main/githubmirror/Clash/FILTER-10.yaml) |

</details>

<details>
<summary><b>📡 FILTER-11</b> — Mos.Hub: akelladejavu/bunker</summary>

<p align="center">
  <img src="QR-CODE/FILTER-11.png" width="280" alt="FILTER-11 QR">
</p>

| Сервис | Ссылка |
|---|---|
| GitHub | [`FILTER-11.txt`](https://raw.githubusercontent.com/Trojankill/Safe-server-lists-for-bypassing-whitelists/main/githubmirror/FILTER-11.txt) |
| Bitbucket | [`FILTER-11.txt`](https://bitbucket.org/trojankill/safe-server-lists/raw/main/githubmirror/FILTER-11.txt) |
| Яндекс переводчик | [`FILTER-11.txt через Яндекс`](https://translate.yandex.ru/translate?url=https%3A%2F%2Fbitbucket.org%2Ftrojankill%2Fsafe-server-lists%2Fraw%2Fmain%2Fgithubmirror%2FFILTER-11.txt&lang=de-de) |
| Mos.Hub | [`FILTER-11.txt`](https://hub.mos.ru/Trojankill/safe-server-list/-/raw/main/githubmirror/FILTER-11.txt) |
| Clash GitHub | [`FILTER-11.yaml`](https://raw.githubusercontent.com/Trojankill/Safe-server-lists-for-bypassing-whitelists/main/githubmirror/Clash/FILTER-11.yaml) |
| Clash Bitbucket | [`FILTER-11.yaml`](https://bitbucket.org/trojankill/safe-server-lists/raw/main/githubmirror/Clash/FILTER-11.yaml) |

</details>

<details>
<summary><b>📡 FILTER-12</b> — p.kfwl.lol proxy → tgmansion</summary>

<p align="center">
  <img src="QR-CODE/FILTER-12.png" width="280" alt="FILTER-12 QR">
</p>

| Сервис | Ссылка |
|---|---|
| GitHub | [`FILTER-12.txt`](https://raw.githubusercontent.com/Trojankill/Safe-server-lists-for-bypassing-whitelists/main/githubmirror/FILTER-12.txt) |
| Bitbucket | [`FILTER-12.txt`](https://bitbucket.org/trojankill/safe-server-lists/raw/main/githubmirror/FILTER-12.txt) |
| Яндекс переводчик | [`FILTER-12.txt через Яндекс`](https://translate.yandex.ru/translate?url=https%3A%2F%2Fbitbucket.org%2Ftrojankill%2Fsafe-server-lists%2Fraw%2Fmain%2Fgithubmirror%2FFILTER-12.txt&lang=de-de) |
| Mos.Hub | [`FILTER-12.txt`](https://hub.mos.ru/Trojankill/safe-server-list/-/raw/main/githubmirror/FILTER-12.txt) |
| Clash GitHub | [`FILTER-12.yaml`](https://raw.githubusercontent.com/Trojankill/Safe-server-lists-for-bypassing-whitelists/main/githubmirror/Clash/FILTER-12.yaml) |
| Clash Bitbucket | [`FILTER-12.yaml`](https://bitbucket.org/trojankill/safe-server-lists/raw/main/githubmirror/Clash/FILTER-12.yaml) |

</details>

<details>
<summary><b>📡 FILTER-13</b> — GitHub: vessel-web/CoolSubs</summary>

<p align="center">
  <img src="QR-CODE/FILTER-13.png" width="280" alt="FILTER-13 QR">
</p>

| Сервис | Ссылка |
|---|---|
| GitHub | [`FILTER-13.txt`](https://raw.githubusercontent.com/Trojankill/Safe-server-lists-for-bypassing-whitelists/main/githubmirror/FILTER-13.txt) |
| Bitbucket | [`FILTER-13.txt`](https://bitbucket.org/trojankill/safe-server-lists/raw/main/githubmirror/FILTER-13.txt) |
| Яндекс переводчик | [`FILTER-13.txt через Яндекс`](https://translate.yandex.ru/translate?url=https%3A%2F%2Fbitbucket.org%2Ftrojankill%2Fsafe-server-lists%2Fraw%2Fmain%2Fgithubmirror%2FFILTER-13.txt&lang=de-de) |
| Mos.Hub | [`FILTER-13.txt`](https://hub.mos.ru/Trojankill/safe-server-list/-/raw/main/githubmirror/FILTER-13.txt) |
| Clash GitHub | [`FILTER-13.yaml`](https://raw.githubusercontent.com/Trojankill/Safe-server-lists-for-bypassing-whitelists/main/githubmirror/Clash/FILTER-13.yaml) |
| Clash Bitbucket | [`FILTER-13.yaml`](https://bitbucket.org/trojankill/safe-server-lists/raw/main/githubmirror/Clash/FILTER-13.yaml) |

</details>


---

<a id="scan"></a>
## 🔎 Как сканировать

| Клиент | Путь |
|:---:|---|
| **v2rayNG** | `+` → Import config from QR code |
| **Karing** | `+` → Scan QR Code |
| **Hiddify** | `+` → Import from QR |
| **NekoBox** | `+` → Scan QR code |
| **Clash / Mihomo** | использовать YAML из `githubmirror/Clash/` |

---

<a id="local"></a>
## 🧪 Локальный запуск

```bash
# клонировать
git clone https://github.com/Trojankill/Safe-server-lists-for-bypassing-whitelists.git
cd Safe-server-lists-for-bypassing-whitelists

# установить зависимости
pip install qrcode[pil] pyyaml

# запустить с GitHub raw base по умолчанию
python filter.py
```

Если хочешь генерировать QR-коды под Bitbucket:

```bash
RAW_BASE=https://bitbucket.org/trojankill/safe-server-lists/raw/main/githubmirror python filter.py
```

Если хочешь генерировать QR-коды под Mos.Hub:

```bash
RAW_BASE=https://hub.mos.ru/Trojankill/safe-server-list/-/raw/main/githubmirror python filter.py
```

Для Windows PowerShell:

```powershell
$env:RAW_BASE = "https://bitbucket.org/trojankill/safe-server-lists/raw/main/githubmirror"
python filter.py
```

> [!NOTE]
> Результат:
> - `githubmirror/` — очищенные TXT-подписки;
> - `githubmirror/Clash/` — YAML-подписки для Clash/Mihomo;
> - `githubmirror/rejected/` — отбракованные конфиги и статистика причин;
> - `githubmirror/URL_HEALTH_REPORT.md` — статус источников;
> - `QR-CODE/` — PNG-QR-коды и HTML-индекс.

---

<a id="policy"></a>
## 🎛️ Настройки политики

Всё в верхней части `filter.py`. Меняешь константу — меняется поведение, код трогать не нужно.

| Константа | По умолчанию | Что делает |
|---|:---:|---|
| `REQUIRE_ALPN_FOR_TLS` | `True` | VLESS+TLS без `alpn` отбраковывается |
| `REQUIRE_HOST_FOR_WS` | `True` | `ws` / `http` без `host` отбраковывается |
| `REJECT_PRIVATE` | `True` | локальные и зарезервированные IP |
| `REJECT_DNS` | `True` | IP публичных резолверов как «сервер» |
| `REJECT_IPV6` | `False` | `True` — выкинуть все IPv6-узлы |
| `MIN_PORT` | `22` | нижняя граница портов |
| `PBK_MAX` / `UUID_MAX` / `SID_MAX` | `3` | sybil-лимиты |
| `TROJAN_PASS_MAX` / `TUIC_CRED_MAX` | `3` | sybil-лимиты по кредам |
| `HP_MAX` | `5` | узлов на один `host:port` |
| `MAX_CONSECUTIVE_FAILURES` | `3` | провалов до паузы |
| `RETRY_AFTER_SECONDS` | `12 * 3600` | длительность паузы |
| `FETCH_TIMEOUT` | `30` | таймаут загрузки, секунды |
| `MAX_FETCH_BYTES` | `64 МБ` | лимит размера ответа |

Ослабить политику — больше узлов и больше мусора. Ужесточить — меньше, но чище. Оба направления — одна строка.

---

<a id="outputs"></a>
## 📂 Выходные файлы

```text
githubmirror/
├── ALL.txt                    # все уникальные конфиги, отсортированы по протоколу
├── FILTER-1.txt               # по одному файлу на источник
├── ...
├── FILTER-13.txt
├── url_health.json            # состояние источников (машиночитаемое)
├── URL_HEALTH_REPORT.md       # статус, провалы, сырых, прошло, дублей
├── Clash/
│   ├── ALL.yaml               # YAML-подписка для Clash / Mihomo
│   └── FILTER-N.yaml
└── rejected/
    ├── rejected.txt           # все отбракованные строки
    └── reasons.md             # статистика причин (топ-60)

QR-CODE/
├── ALL.png
├── FILTER-N.png
└── index.html                 # тёмный HTML-индекс со всеми QR
```

Порядок в `ALL.txt`: `vless → trojan → vmess → hysteria2 → tuic → ss`, внутри протокола — лексикографически.

Источники, которые пришли в base64, отдаются в base64 — клиенты (v2rayNG, Karing, Hiddify, NekoBox) декодируют подписку сами.

---

<a id="faq"></a>
## ❓ FAQ

<details>
<summary><b>Почему мой любимый узел не попал в ALL.txt?</b></summary>

Посмотри `githubmirror/rejected/rejected.txt` — там исходная строка, и `githubmirror/rejected/reasons.md` — там причина. Чаще всего: `allowInsecure`, `pbk` не 43 символа, порт ниже 22 или сработал sybil-лимит.
</details>

<details>
<summary><b>Почему ShadowsocksR больше нет?</b></summary>

Его не поддерживает ни один из целевых клиентов, а «безопасных» AEAD-методов в SSR не существует — там только потоковые шифры. Парсер всё равно отбрасывал 100% SSR-строк, поэтому он удалён.
</details>

<details>
<summary><b>Clash пишет «proxy name duplicated». Что делать?</b></summary>

В v6.0 это исправлено: имена делаются уникальными автоматически (`name #2`, `name #3`), а все скаляры проходят через JSON-квотирование. Если ошибка осталась — обнови YAML, старый мог быть сгенерирован до фикса.
</details>

<details>
<summary><b>Источник умер. Он выпадет навсегда?</b></summary>

Нет. После 3 провалов подряд он уходит в паузу на 12 часов, потом пробуется снова. Успешная загрузка сбрасывает счётчик в ноль.
</details>

<details>
<summary><b>Можно добавить свой источник?</b></summary>

Да — одна строка в `SOURCES_CONFIG`:

```python
{"name": "FILTER-14", "url": "https://example.com/sub.txt"},
```

Формат определится сам: plaintext, base64 или Clash YAML.
</details>

<details>
<summary><b>Скрипт гарантирует безопасность сервера?</b></summary>

Нет. Он проверяет только техническую корректность конфигурации. Оператор сервера всё ещё видит твой SNI (если нет ECH), plaintext HTTP и DNS, который не резолвится локально. Репутацию владельца скрипт не проверяет и проверить не может.
</details>

---

<a id="disclaimer"></a>
## ⚖️ Дисклеймер и правовая информация

<details>
<summary>🇷🇺 <b>Русский</b></summary>

- Автор не является владельцем/разработчиком/поставщиком перечисленных VPN-конфигураций. Это независимый информационный обзор и результаты тестирования.
- Данный пост не является рекламой VPN. Весь материал предназначен исключительно в информационных целях, и только для граждан тех стран, где эта информация легальна, как минимум — в научных целях. Если вам такое читать нельзя — закройте эту страницу немедленно!
- Автор не имеет никаких намерений, не побуждает, не поощряет и не оправдывает использование VPN и любых других программ ни при каких обстоятельствах.
- Ответственность за любое применение данных VPN-конфигураций — на их пользователе.
- Отказ от ответственности: автор не несёт ответственность за действия третьих лиц и не поощряет противоправное использование VPN.
- Автор не несет ответственности за точность, полноту и достоверность опубликованных данных. Все совпадения случайны. Вся информация предоставлена «как есть» и может не соответствовать действительности.
- Используйте в соответствии с местным законодательством.
- Используйте VPN только в законных целях: в частности — для обеспечения вашей безопасности в сети и защищённого удалённого доступа, и ни в коем случае не применяйте данную технологию для обхода блокировок.
- Проект некоммерческий, бесплатный, вся представленная «платежная» информация найдена случайным образом где-то в интернет-пространстве, скопирована «как есть» для демонстрации возможного примера и автору не принадлежит.
- Совет — закройте эту страницу, удалите все VPN с вашего компьютера, поставьте MAX и Yandex на все устройства, чтобы «ловило» даже на парковке, и пользуйтесь только интернет-ресурсами, которые разрешены вашим интернет-провайдером, ну вы поняли.

</details>

<details>
<summary>🇬🇧 <b>English</b></summary>

- The author is not the owner, developer, or provider of the listed VPN configurations. This is an independent informational review presenting test results.
- This post is not an advertisement for VPNs. All material is intended solely for informational purposes and is directed only at citizens of countries where accessing this information is legal — at the very least, for research purposes. If you are prohibited from reading this content, close this page immediately!
- The author has no intention of — nor does the author incite, encourage, or condone — the use of VPNs or any other software under any circumstances.
- The user bears full responsibility for any use of these VPN configurations.
- The author is not liable for the actions of third parties and does not condone the unlawful use of VPNs.
- The author assumes no responsibility for the accuracy, completeness, or reliability of the published data. Any resemblance to actual events or persons is purely coincidental. All information is provided "as is" and may not reflect reality.
- Use in accordance with local laws.
- Use the VPN only for lawful purposes — specifically, to ensure your online security and secure remote access — and under no circumstances use this technology to bypass blocks.
- This is a free, non-commercial project; all "payment" information presented here was found randomly online, copied "as is" to demonstrate a potential example, and does not belong to the author.

</details>

---

<p align="center">
  <sub>Обновляется каждые 15 минут через GitHub Actions · собрано на тапках, собрано с умом 🥔</sub>
</p>
