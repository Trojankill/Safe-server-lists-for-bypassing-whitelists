<!-- Markdown file: README.md | runtime: GitHub / Bitbucket / Mos.Hub Markdown renderer -->

# 🛡️ VPN Config Security Filter

<p align="center">
  <a href="https://github.com/Trojankill/Safe-server-lists-for-bypassing-whitelists/actions">
    <img src="https://img.shields.io/github/actions/workflow/status/Trojankill/Safe-server-lists-for-bypassing-whitelists/update.yml?label=auto-update&style=for-the-badge&logo=githubactions&logoColor=white" alt="CI">
  </a>
  <a href="https://github.com/Trojankill/Safe-server-lists-for-bypassing-whitelists/commits/main">
    <img src="https://img.shields.io/github/last-commit/Trojankill/Safe-server-lists-for-bypassing-whitelists?style=for-the-badge&logo=git&logoColor=white&color=orange" alt="Last commit">
  </a>
  <a href="https://github.com/Trojankill/Safe-server-lists-for-bypassing-whitelists/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/Trojankill/Safe-server-lists-for-bypassing-whitelists?style=for-the-badge&color=green" alt="License">
  </a>
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
  <img src="https://img.shields.io/badge/ShadowsocksR-AAD6E7?style=flat-square" alt="ShadowsocksR">
  <img src="https://img.shields.io/badge/Clash%2FMihomo-7159C6?style=flat-square" alt="Clash">
</p>

<p align="center">
  <b>🔒 Автоматизированный аудит и фильтрация публичных прокси-конфигураций</b><br>
  <sub>Статический анализ · Защита от MITM · Sybil-детекция · Fail-closed валидация · Потокобезопасность · IPv6 · Clash/Mihomo</sub>
</p>

---

<a id="whats-new"></a>
## 🚀 Что нового в v5.3

<table>
<tr>
<td width="50%">

### 🛡️ Безопасность и валидация

- ✅ **IPv6 host extraction** — поддержка `[2001:db8::1]:443` bracket notation
- ✅ **SSR param validation** — проверка `obfs_param` / `protocol_param` на banned domains и private IPs
- ✅ **SS 2022 fail-closed** — явный reject при `base64 length % 4 == 1`
- ✅ **Потокобезопасность** — `threading.Lock` на health-tracking
- ✅ **Порт-валидация** — порты `1–65535` проверяются универсально
- ✅ **Точный домен-матч** — `.cf` не матчит `cfire.ru`, только TLD `*.cf`
- ✅ **Fail-closed SSR** — битая кодировка = reject, а не тихий пропуск
- ✅ **VMess format-2 `alterId`** — защита от replay для нового формата
- ✅ **Валидация `pbk`** — длина ровно 43 символа, X25519 public key
- ✅ **Post-quantum checks** — валидация ML-KEM + X25519 hybrid параметров

</td>
<td width="50%">

### ⚡ Удобство и совместимость

- ✅ **Clash/Mihomo output** — генерация YAML-подписок в `githubmirror/Clash/`
- ✅ **Clash name sanitization** — очистка имён прокси от control characters
- ✅ **Clash dedup by `host:port`** — аккуратная дедупликация для Mihomo
- ✅ **LRU-кэширование** — `@lru_cache` для горячих проверок
- ✅ **Параллельная загрузка** — `ThreadPoolExecutor` для источников
- ✅ **URL Health tracking** — автопропуск мёртвых источников после 3+ провалов
- ✅ **Base64 round-trip** — декодирование → фильтрация → обратное кодирование
- ✅ **QR-коды + HTML-индекс** — удобно добавлять подписки с телефона
- ✅ **`RAW_BASE` через env** — форки не захардкожены на чужой репозиторий
- ✅ **Точный DNS-матч** — `1.1.1.1.evil-logger.com` больше не проходит

</td>
</tr>
</table>

---

<a id="warning"></a>
## ⚠️ Прежде чем использовать

> [!WARNING]
> Все подписки предназначены для обхода **белых списков**. Прошу вас **не использовать** их с включённым Wi-Fi — работать они будут даже на Wi-Fi. Дайте пользоваться серверами тем, у кого действительно включены белые списки: мощность серверов и производительность сильно падают из-за наплыва пользователей.

> [!CAUTION]
> **НАСТОЯТЕЛЬНО РЕКОМЕНДУЮ НЕ ИСПОЛЬЗОВАТЬ ЭТИ VPN-СЕРВЕРЫ ДЛЯ БАНКОВСКИХ ПЕРЕВОДОВ.**  
> Даже если конфигурация прошла фильтр, это не означает, что оператор сервера безопасен. Также не рекомендуется использование государственных приложений без нормальной split-маршрутизации: **Yandex, VK, MAX, Госуслуги** и т.п. — чтобы снизить риск блокировок серверов.

> [!IMPORTANT]
> **“Прошёл фильтр” ≠ “оператору можно доверять”.**  
> Скрипт проверяет только техническую корректность конфигурации: TLS-параметры, домены, порты, транспорты, креды, Sybil-повторы, слабые шифры и опасные флаги. Он не проверяет репутацию владельца сервера. Оператор может видеть ваш SNI без ECH, plaintext HTTP и DNS, если он не резолвится локально.

---

<a id="toc"></a>
## 📑 Содержание

- [Что делает проект](#what-it-does)
- [Зеркала](#mirrors)
- [Источники данных](#sources)
- [Подписки и QR-коды](#subscriptions)
- [Как сканировать](#scan)
- [Локальный запуск](#local)
- [Дисклеймер](#disclaimer)

---

<a id="what-it-does"></a>
## 🔍 Что делает проект

Скрипт `filter.py` выполняет **статический анализ** конфигурационных строк из публичных подписок и отбраковывает записи по критериям:

### 🛡️ Базовая безопасность

| Категория | Примеры | Статус |
|---|---|:---:|
| 🔓 Небезопасные TLS-параметры | `allowInsecure=1`, `security=none`, `verify=false`, `disable_sni` | ✅ |
| 🚫 Запрещённые / скомпрометированные домены | бесплатные хостинги, известные пулы, подозрительные зоны | ✅ |
| ⚡ Опасные транспортные комбинации | `type=raw` без шифрования, `xhttp` без `host` | ✅ |
| 🏠 Приватные / loopback адреса | `127.0.0.1`, `localhost`, `10.x`, `192.168.x`, `172.16-31.x`, IPv6 ULA | ✅ |
| 🔢 Некорректные порты | порт `0`, порт `> 65535`, нечисловой порт | ✅ |
| 🕵️ MITM / DNS-подмена | кастомные CA, нестандартные DNS, sniffing на внешние домены | ✅ |
| 🔑 Слабое шифрование SS | RC4, DES, CFB, Salsa20, ChaCha20 non-IETF, `none` | ✅ |
| 🧮 SS 2022 key validation | неверная длина base64-ключа для `2022-blake3-*` | ✅ |
| 🌐 IPv6 support | `[2001:db8::1]:443`, проверка link-local / ULA / loopback | 🆕 |

### 📦 Протокол-специфичные проверки

| Протокол | Проверки | Статус |
|---|---|:---:|
| **VLESS Reality** | отсутствие `pbk` / `fp`, невалидный `flow`, длина `pbk != 43`, невалидный `sid` | ✅ |
| **VLESS TLS** | отсутствие `sni` / `host` / `alpn`, невалидный transport | ✅ |
| **VMess fmt-1** | `alterId > 0`, `allowInsecure`, отсутствие TLS, `scy=none`, `v` не `1/2` | ✅ |
| **VMess fmt-2** | `alterId > 0`, `security=none`, отсутствие `sni` при TLS/Reality | ✅ |
| **Trojan** | пустой пароль, отсутствие SNI, публичные пулы, опасные domain-параметры | ✅ |
| **Hysteria2** | `insecure=1`, отсутствие SNI, пустой пароль | ✅ |
| **TUIC** | отсутствие creder/SNI, невалидный `congestion_control`, невалидный `udp_relay_mode` | ✅ |
| **Shadowsocks** | слабые методы, пустой пароль, невалидный 2022-ключ | ✅ |
| **ShadowsocksR** | слабые методы, пустой пароль, битый base64, опасные `obfs_param` / `protocol_param` | 🆕 |

### 🔒 Продвинутая защита

| Категория | Описание | Статус |
|---|---|:---:|
| 🐝 **Sybil-детекция** | дедуп по `pbk` / `uuid` / `sid` / Trojan password / TUIC creds, лимит `3` | ✅ |
| 🧵 **Endpoint-дедуп** | `host:port:proto`, лимит `5` на один endpoint | ✅ |
| 🧵 **Потокобезопасность** | `threading.Lock` на health-tracking при параллельной загрузке | ✅ |
| 🎯 **Точный домен-матч** | `.cf` матчит только TLD, `boot-lee.ru` только exact/subdomain | ✅ |
| 🛡️ **Fail-closed SSR** | битая кодировка = reject, не тихий пропуск | ✅ |
| 🔐 **Post-quantum checks** | валидация ML-KEM + X25519 hybrid параметров | ✅ |
| 🎭 **Placeholder UUID** | блокировка `0000...` и `ffff...` UUID | ✅ |
| 📡 **Base64 round-trip** | подписки декодируются → фильтруются → кодируются обратно | ✅ |
| 🌐 **Точный DNS-матч** | `dns=` проверяется как точный host против whitelist | ✅ |
| 🔄 **Clash/Mihomo export** | отдельная генерация YAML-подписок в `githubmirror/Clash/` | 🆕 |

Результат — очищенные списки в `githubmirror/`, обновляемые каждые **15 минут** через GitHub Actions.

---

<a id="mirrors"></a>
## 🪞 Зеркала

Проект автоматически зеркалируется в несколько источников. Если один зеркальный хост недоступен, используй другой.

| Зеркало | Репозиторий | Raw base для подписок |
|---|---|---|
| **GitHub** | [Trojankill/Safe-server-lists-for-bypassing-whitelists](https://github.com/Trojankill/Safe-server-lists-for-bypassing-whitelists) | `https://raw.githubusercontent.com/Trojankill/Safe-server-lists-for-bypassing-whitelists/main/githubmirror` |
| **Bitbucket** | [trojankill/safe-server-lists](https://bitbucket.org/trojankill/safe-server-lists) | `https://bitbucket.org/trojankill/safe-server-lists/raw/main/githubmirror` |
| **Mos.Hub** | [Trojankill/safe-server-list](https://hub.mos.ru/Trojankill/safe-server-list) | `https://hub.mos.ru/Trojankill/safe-server-list/-/raw/main/githubmirror` |

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
| `FILTER-1` | [Mos.Hub: rkp/sub-roskompozor](https://hub.mos.ru/rkp/sub-roskompozor/raw/main/wl) | plaintext |
| `FILTER-2` | [GitHub: regionovec-jpg/subs_pars](https://github.com/regionovec-jpg/subs_pars/raw/refs/heads/main/subs_wl.txt) | plaintext |
| `FILTER-3` | [GitHub: zieng2/wl](https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_lite.txt) | plaintext |
| `FILTER-4` | [GitHub: whoahaow/rjsxrd](https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-all.txt) | plaintext |
| `FILTER-5` | [GitHub: LSO-LinSpisokObhod](https://raw.githubusercontent.com/LSO-LinSpisokObhod/LSO-LinSpisokObhod.github.io/refs/heads/main/sub/LTE.txt) | plaintext |
| `FILTER-6` | [GitHub: kort0881/vpn-vless-configs-russia](https://raw.githubusercontent.com/kort0881/vpn-vless-configs-russia/refs/heads/main/output/vless.txt) | plaintext |
| `FILTER-7-BASE64` | [solovyov-jenya2004.vercel.app](https://solovyov-jenya2004.vercel.app/final_sorted_base64/) | **base64** |
| `FILTER-8-BASE64` | [GitHub: Diversan313/apex-parser alive_bs](https://raw.githubusercontent.com/Diversan313/apex-parser/refs/heads/main/subs/main/alive_bs.txt) | **base64** |
| `FILTER-9-BASE64` | [GitHub: Diversan313/apex-parser alive_bl](https://raw.githubusercontent.com/Diversan313/apex-parser/main/subs/main/alive_bl.txt) | **base64** |
| `FILTER-10` | [sub.vlessfo.ru](https://sub.vlessfo.ru/vlessforu/working_configs.txt) | plaintext |
| `FILTER-11` | [Mos.Hub: akelladejavu/bunker](https://hub.mos.ru/akelladejavu/bunker/-/raw/main/WHITE_LIST.txt) | plaintext |
| `FILTER-12` | [Bitbucket через Turbopages proxy: igareck/vpn-configs-for-russia](https://translated.turbopages.org/proxy_u/de-de.ru.e6e5a2dd-6ac65a76-30ee4feb-74722d776562/https/bitbucket.org/igareck/vpn-configs-for-russia/raw/main/WHITE-CIDR-RU-all.txt) | plaintext |
| `FILTER-13` | [GitHub: regionovec-jpg/subs_pars](https://raw.githubusercontent.com/regionovec-jpg/subs_pars/refs/heads/main/subs_wl.txt) | plaintext |

> [!TIP]
> Источники с `3+` провалами подряд автоматически пропускаются до следующего успешного цикла. Это защищает общий `ALL.txt` от зависания из-за одного мёртвого upstream.

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
<summary><b>📡 FILTER-2</b> — GitHub: regionovec-jpg/subs_pars</summary>

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
<summary><b>📡 FILTER-7-BASE64</b> — solovyov-jenya2004.vercel.app</summary>

<p align="center">
  <img src="QR-CODE/FILTER-7-BASE64.png" width="280" alt="FILTER-7-BASE64 QR">
</p>

| Сервис | Ссылка |
|---|---|
| GitHub | [`FILTER-7-BASE64.txt`](https://raw.githubusercontent.com/Trojankill/Safe-server-lists-for-bypassing-whitelists/main/githubmirror/FILTER-7-BASE64.txt) |
| Bitbucket | [`FILTER-7-BASE64.txt`](https://bitbucket.org/trojankill/safe-server-lists/raw/main/githubmirror/FILTER-7-BASE64.txt) |
| Яндекс переводчик | [`FILTER-7-BASE64.txt через Яндекс`](https://translate.yandex.ru/translate?url=https%3A%2F%2Fbitbucket.org%2Ftrojankill%2Fsafe-server-lists%2Fraw%2Fmain%2Fgithubmirror%2FFILTER-7-BASE64.txt&lang=de-de) |
| Mos.Hub | [`FILTER-7-BASE64.txt`](https://hub.mos.ru/Trojankill/safe-server-list/-/raw/main/githubmirror/FILTER-7-BASE64.txt) |
| Clash GitHub | [`FILTER-7-BASE64.yaml`](https://raw.githubusercontent.com/Trojankill/Safe-server-lists-for-bypassing-whitelists/main/githubmirror/Clash/FILTER-7-BASE64.yaml) |
| Clash Bitbucket | [`FILTER-7-BASE64.yaml`](https://bitbucket.org/trojankill/safe-server-lists/raw/main/githubmirror/Clash/FILTER-7-BASE64.yaml) |

> [!NOTE]
> Файл закодирован в base64. Клиенты v2rayNG / Karing / Hiddify обычно декодируют автоматически.

</details>

<details>
<summary><b>📡 FILTER-8-BASE64</b> — GitHub: Diversan313/apex-parser alive_bs</summary>

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
<summary><b>📡 FILTER-9-BASE64</b> — GitHub: Diversan313/apex-parser alive_bl</summary>

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
<summary><b>📡 FILTER-12</b> — Bitbucket igareck через Turbopages proxy</summary>

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
<summary><b>📡 FILTER-13</b> — GitHub: regionovec-jpg/subs_pars</summary>

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
> - `githubmirror/rejected/` — отбракованные конфиги;
> - `githubmirror/URL_HEALTH_REPORT.md` — статус источников;
> - `QR-CODE/` — PNG-QR-коды и HTML-индекс.

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
