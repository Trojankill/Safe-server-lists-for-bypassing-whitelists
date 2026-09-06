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
  <img src="https://img.shields.io/badge/refresh-every_1_hour-blue?style=for-the-badge&logo=clockify&logoColor=white" alt="Refresh">
  <img src="https://img.shields.io/badge/python-3.8+-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/VLESS-00D4FF?style=flat-square" alt="VLESS">
  <img src="https://img.shields.io/badge/VMess-FF6B6B?style=flat-square" alt="VMess">
  <img src="https://img.shields.io/badge/Trojan-4ECDC4?style=flat-square" alt="Trojan">
  <img src="https://img.shields.io/badge/Hysteria2-FFE66D?style=flat-square" alt="Hysteria2">
  <img src="https://img.shields.io/badge/TUIC-1DD3B0?style=flat-square" alt="TUIC">
  <img src="https://img.shields.io/badge/Shadowsocks-95E1D3?style=flat-square" alt="Shadowsocks">
</p>

<p align="center">
  <b>🔒 Автоматизированный аудит и фильтрация публичных прокси-конфигураций</b><br>
  <sub>Статический анализ · Защита от MITM · Sybil-детекция · Fail-closed валидация · Потокобезопасность</sub>
</p>

---

## 🚀 Что нового в v5.1

<table>
<tr>
<td width="50%">

### 🛡️ Улучшения безопасности

- ✅ **Потокобезопасность** — `threading.Lock` на health-tracking, корректная работа с 5 параллельными воркерами
- ✅ **Порт-валидация** — порты 1–65535 проверяются на всех протоколах
- ✅ **Точный домен-матч** — `.cf` больше не матчит `cfire.ru`, только TLD `*.cf`
- ✅ **Fail-closed SSR** — битая кодировка = reject, а не тихий пропуск
- ✅ **VMess формат-2 `alterId`** — replay-атака защита для нового формата
- ✅ **Валидация `pbk`** — длина ровно 43 символа (X25519 public key)
- ✅ **SS 2022 fail-closed** — невалидный base64-ключ = reject
- ✅ **Пост-квантовая криптография** — валидация ML-KEM-768 + X25519 гибридов

</td>
<td width="50%">

### ⚡ Производительность и UX

- ✅ **LRU-кэширование** — `@lru_cache` для часто используемых проверок
- ✅ **Параллельная загрузка** — `ThreadPoolExecutor` для источников
- ✅ **URL Health tracking** — автопропуск мёртвых источников (3+ провала подряд)
- ✅ **Base64 round-trip** — декодирование → фильтрация → кодирование
- ✅ **QR-коды с HTML-индексом** — удобно на мобильных
- ✅ **Мультипротокол на endpoint** — `host:port:proto` тройка, не режет валидные комбинации
- ✅ **`RAW_BASE` через env** — форки не захардкожены на чужой репозиторий
- ✅ **Точный DNS-матч** — `1.1.1.1.evil-logger.com` больше не проходит

</td>
</tr>
</table>

</details>

---

## ⚠️ Прежде чем использовать

> [!WARNING]
> Все подписки предназначены для обхода **белых списков**. Прошу вас **не использовать** их с включённым Wi-Fi (работать они будут даже на Wi-Fi). Дайте людям пользоваться серверами, у кого действительно включены белые списки — мощность серверов и производительность сильно падают из-за наплыва пользователей.

> [!CAUTION]
> **НАСТОЯТЕЛЬНО РЕКОМЕНДУЮ НЕ ИСПОЛЬЗОВАТЬ ЭТИ VPN-СЕРВЕРЫ ДЛЯ БАНКОВСКИХ ПЕРЕВОДОВ.** Хоть репозиторий и блокирует большинство небезопасных серверов, всегда есть свои риски. Также не рекомендуется использование государственных приложений без хорошей split-маршрутизации. Например: **Yandex, VK, MAX, Госуслуги** и так далее — для снижения риска блокировок серверов из-за Роскомнадзора.

> [!IMPORTANT]
> **"Прошёл фильтр" ≠ "оператору можно доверять"** — этот скрипт проверяет только техническую корректность конфигурации, а не репутацию оператора сервера. Оператор видит ваш SNI (без ECH), весь plaintext HTTP и DNS, если тот не резолвится локально.

---

## 📑 Содержание

- [Что делает проект](#-что-делает-проект)
- [Источники данных](#-источники-данных)
- [Подписки и QR-коды](#-подписки-и-qr-коды)
- [Как сканировать](#-как-сканировать)
- [Дисклеймер](#️-дисклеймер-и-правовая-информация)

---

## 🔍 Что делает проект

Скрипт `filter.py` выполняет **статический анализ** конфигурационных строк из публичных подписок и отбраковывает записи по следующим критериям:

### 🛡️ Базовая безопасность

| Категория | Примеры | Статус |
|---|---|:---:|
| 🔓 Небезопасные TLS-параметры | `allowInsecure=1`, `security=none`, `verify=false`, `disable_sni` | ✅ |
| 🚫 Запрещённые / скомпрометированные домены | Бесплатные хостинги, известные пулы, подозрительные зоны | ✅ |
| ⚡ Опасные транспортные комбинации | `type=raw` без шифрования, `xhttp` без `host` | ✅ |
| 🏠 Приватные / loopback адреса | `127.0.0.1`, `localhost`, `10.x`, `192.168.x`, `172.16-31.x`, IPv6 ULA | ✅ |
| 🔢 Некорректные порты | порт 0, порт > 65535, нечисловой порт | ✅ |
| 🕵️ MITM / DNS-подмена | Кастомные CA, нестандартные DNS, sniffing на внешние домены | ✅ |
| 🔑 Слабое шифрование SS | RC4, DES, CFB, CTR, Salsa20, Chacha20 non-IETF, `none` | ✅ |
| 🧮 SS 2022 key validation | Неверная длина base64-ключа для `2022-blake3-*` | ✅ |

### 📦 Протокол-специфичные проверки

| Протокол | Проверки | Статус |
|---|---|:---:|
| **VMess** (fmt-1) | `alterId > 0`, `allowInsecure`, отсутствие TLS, `scy=none`, `v` не 1/2 | ✅ |
| **VMess** (fmt-2) | `alterId > 0`, `security=none`, отсутствие `sni` при TLS/Reality | 🆕 |
| **VLESS Reality** | Отсутствие `pbk` / `fp`, невалидный `flow`, длина pbk ≠ 43, невалидный `sid` | ✅ |
| **VLESS TLS** | Отсутствие `sni` / `host` / `alpn`, невалидный transport | ✅ |
| **Trojan** | Пустой пароль, отсутствие SNI, публичные пулы | ✅ |
| **Hysteria2** | `insecure=1`, отсутствие SNI, пустой пароль | ✅ |
| **TUIC** | Отсутствие кредов/SNI, невалидный congestion_control, невалидный udp_relay_mode | 🆕 |
| **Shadowsocks** | Слабые методы, пустой пароль, невалидный 2022-ключ | ✅ |
| **ShadowsocksR** | Слабые методы, пустой пароль, битый base64 (fail-closed) | ✅ |

### 🔒 Продвинутая защита

| Категория | Описание | Статус |
|---|---|:---:|
| 🐝 **Sybil-детекция** | Дедуп по `pbk` / `uuid` / `sid` / trojan-password / TUIC-кредам (лимит 3) и `host:port:proto` (лимит 5) | ✅ |
| 🧵 **Потокобезопасность** | `threading.Lock` на health-tracking при параллельной загрузке | 🆕 |
| 🎯 **Точный домен-матч** | `.cf` матчит только TLD, `boot-lee.ru` только exact/subdomain | 🆕 |
| 🛡️ **Fail-closed SSR** | Битая кодировка = reject, не тихий пропуск | 🆕 |
| 🔐 **Пост-квантовая криптография** | Валидация ML-KEM-768 + X25519 гибридов | ✅ |
| 🎭 **Placeholder UUID** | Блокировка `0000...` и `ffff...` UUID | ✅ |
| 📡 **Base64 round-trip** | Подписки декодируются → фильтруются → кодируются обратно | ✅ |
| 🔁 **Повторяющиеся идентификаторы** | Один `pbk` / `uuid` / `sid` / пароль в >3 конфигах | ✅ |
| 🌐 **Точный DNS-матч** | `dns=` параметр проверяется как точный host против whitelist | ✅ |

Результат — очищенные списки в `githubmirror/`, обновляемые каждый **1 час** через GitHub Actions.

## 📥 Источники данных

Конфигурации берутся из **публичных открытых репозиториев**:

| ID | Источник | Формат | Статус |
|:---:|---|:---:|:---:|
| `FILTER-1` | [RKPchannel/RKP_bypass_configs](https://github.com/RKPchannel/RKP_bypass_configs) | plaintext | ✅ |
| `FILTER-2` | [PizdukVPN](https://gitverse.ru/api/repos/Pizduk/PizdukVPN/raw/branch/master/WlSubPiz.txt) | plaintext | ✅ |
| `FILTER-3` | [zieng2/wl](https://github.com/zieng2/wl) | plaintext | ✅ |
| `FILTER-4` | [whoahaow/rjsxrd](https://github.com/whoahaow/rjsxrd) | plaintext | ✅ |
| `FILTER-5` | [prominbro](https://github.com/prominbro/sub) | plaintext | ✅ |
| `FILTER-6` | [kort0881/vpn-vless-configs-russia](https://github.com/kort0881/vpn-vless-configs-russia) | plaintext | ✅ |
| `FILTER-7-BASE64` | [solovyov-jenya2004](https://solovyov-jenya2004.vercel.app/final_sorted_base64) | **base64** | ✅ |
| `FILTER-8-BASE64` | [Diversan313 WHITELIST](https://github.com/Diversan313/apex-parser) | **base64** | ✅ |
| `FILTER-9-BASE64` | [Diversan313 BLACKLIST](https://github.com/Diversan313/apex-parser) | **base64** | ✅ |
| `FILTER-10` | [igareck/vpn-configs-for-russia](https://github.com/igareck/vpn-configs-for-russia) | plaintext | ✅ |
> [!TIP]
> Все источники проверяются на доступность через `URL Health Report`. Источники с 3+ провалами подряд автоматически пропускаются до следующего успешного цикла.

---

## 💫 Зеркала

<table>
<tr>
<td width="50%">

### 💠 Bitbucket

```
https://bitbucket.org/trojankill/safe-server-lists/src/main
```

</td>
<td width="50%">

### 🌐 Яндекс.Переводчик + Bitbucket

```
https://translate.yandex.ru/translate?url=ПОДПИСКА&lang=de-de
```

</td>
</tr>
</table>

---

## 📱 Подписки и QR-коды

<details>
<summary><b>📡 FILTER-ALL</b> — все конфиги (рекомендуется)</summary>

<p align="center">
  <img src="QR-CODE/ALL.png" width="300" alt="ALL QR">
</p>

**URL подписки:**

```
https://raw.githubusercontent.com/Trojankill/Safe-server-lists-for-bypassing-whitelists/main/githubmirror/ALL.txt
```

</details>

<details>
<summary><b>📡 FILTER-1</b> — RKPchannel/RKP_bypass_configs</summary>

<p align="center">
  <img src="QR-CODE/FILTER-1.png" width="300" alt="FILTER-1 QR">
</p>

**URL подписки:**

```
https://raw.githubusercontent.com/Trojankill/Safe-server-lists-for-bypassing-whitelists/main/githubmirror/FILTER-1.txt
```

</details>

<details>
<summary><b>📡 FILTER-2</b> — AvenCores/goida-vpn-configs</summary>

<p align="center">
  <img src="QR-CODE/FILTER-2.png" width="300" alt="FILTER-2 QR">
</p>

**URL подписки:**

```
https://raw.githubusercontent.com/Trojankill/Safe-server-lists-for-bypassing-whitelists/main/githubmirror/FILTER-2.txt
```

</details>

<details>
<summary><b>📡 FILTER-3</b> — zieng2/wl</summary>

<p align="center">
  <img src="QR-CODE/FILTER-3.png" width="300" alt="FILTER-3 QR">
</p>

**URL подписки:**

```
https://raw.githubusercontent.com/Trojankill/Safe-server-lists-for-bypassing-whitelists/main/githubmirror/FILTER-3.txt
```

</details>

<details>
<summary><b>📡 FILTER-4</b> — whoahaow/rjsxrd</summary>

<p align="center">
  <img src="QR-CODE/FILTER-4.png" width="300" alt="FILTER-4 QR">
</p>

**URL подписки:**

```
https://raw.githubusercontent.com/Trojankill/Safe-server-lists-for-bypassing-whitelists/main/githubmirror/FILTER-4.txt
```

</details>

<details>
<summary><b>📡 FILTER-5</b> — igareck/vpn-configs-for-russia</summary>

<p align="center">
  <img src="QR-CODE/FILTER-5.png" width="300" alt="FILTER-5 QR">
</p>

**URL подписки:**

```
https://raw.githubusercontent.com/Trojankill/Safe-server-lists-for-bypassing-whitelists/main/githubmirror/FILTER-5.txt
```

</details>

<details>
<summary><b>📡 FILTER-6</b> — kort0881/vpn-vless-configs-russia</summary>

<p align="center">
  <img src="QR-CODE/FILTER-6.png" width="300" alt="FILTER-6 QR">
</p>

**URL подписки:**

```
https://raw.githubusercontent.com/Trojankill/Safe-server-lists-for-bypassing-whitelists/main/githubmirror/FILTER-6.txt
```

</details>

<details>
<summary><b>📡 FILTER-7-BASE64</b> — solovyov-jenya2004</summary>

<p align="center">
  <img src="QR-CODE/FILTER-7-BASE64.png" width="300" alt="FILTER-7-BASE64 QR">
</p>

**URL подписки (base64):**

```
https://raw.githubusercontent.com/Trojankill/Safe-server-lists-for-bypassing-whitelists/main/githubmirror/FILTER-7-BASE64.txt
```

> [!NOTE]
> Файл закодирован в base64. Клиенты v2rayNG / Karing / Hiddify декодируют автоматически.

</details>

<details>
<summary><b>📡 FILTER-8-BASE64</b> — Diversan313/apex-parser</summary>

<p align="center">
  <img src="QR-CODE/FILTER-8-BASE64.png" width="300" alt="FILTER-8-BASE64 QR">
</p>

**URL подписки (base64):**

```
https://raw.githubusercontent.com/Trojankill/Safe-server-lists-for-bypassing-whitelists/main/githubmirror/FILTER-8-BASE64.txt
```

> [!NOTE]
> Файл закодирован в base64. Клиенты v2rayNG / Karing / Hiddify декодируют автоматически.

</details>

---

## 🔎 Как сканировать

| Клиент | Путь |
|:---:|---|
| **v2rayNG** | `+` → Import config from QR code |
| **Karing** | `+` → Scan QR Code |
| **Hiddify** | `+` → Import from QR |
| **Nekobox** | `+` → Scan QR code |

---

## 🧪 Локальный запуск

```bash
# клонировать
git clone https://github.com/Trojankill/Safe-server-lists-for-bypassing-whitelists.git
cd Safe-server-lists-for-bypassing-whitelists

# установить зависимости (опционально для QR)
pip install qrcode[pil]

# запустить (RAW_BASE по умолчанию → этот репозиторий)
python filter.py

# или с кастомным base для форка
RAW_BASE=https://your-repo.com/path python filter.py
```

> [!NOTE]
> Результат: `githubmirror/` — очищенные списки, `rejected/` — отбракованные, `QR-CODE/` — QR-коды + HTML-индекс.

---

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
