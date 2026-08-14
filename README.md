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
  <img src="https://img.shields.io/badge/refresh-every_9_min-blue?style=for-the-badge&logo=clockify&logoColor=white" alt="Refresh">
  <img src="https://img.shields.io/badge/python-3.8+-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/VLESS-00D4FF?style=flat-square" alt="VLESS">
  <img src="https://img.shields.io/badge/VMess-FF6B6B?style=flat-square" alt="VMess">
  <img src="https://img.shields.io/badge/Trojan-4ECDC4?style=flat-square" alt="Trojan">
  <img src="https://img.shields.io/badge/Hysteria2-FFE66D?style=flat-square" alt="Hysteria2">
  <img src="https://img.shields.io/badge/Shadowsocks-95E1D3?style=flat-square" alt="Shadowsocks">
</p>

<p align="center">
  <b>🔒 Автоматизированный аудит и фильтрация публичных прокси-конфигураций</b><br>
  <sub>Статический анализ · Защита от MITM · Sybil-детекция · Пост-квантовая криптография</sub>
</p>

---

## 🚀 Что нового в v4.2

<table>
<tr>
<td width="50%">

### 🛡️ Улучшения безопасности

- ✅ **Универсальный host-чек** — теперь защищает все протоколы (SS/SSR/Hysteria), а не только VLESS/Trojan
- ✅ **Sybil-флуд защита** — дедупликация по `host:port`, блокирует фермы серверов
- ✅ **Точная валидация X25519** — проверка длины `pbk` (ровно 43 символа)
- ✅ **Поддержка ML-KEM** — пост-квантовая криптография X25519 + Kyber768
- ✅ **VMess `aid` фикс** — корректная обработка строковых значений
- ✅ **Защита от placeholder UUID** — блокировка нулевых и `ffffffff` UUID

</td>
<td width="50%">

### ⚡ Производительность

- ✅ **LRU-кэширование** — `@lru_cache` для часто используемых проверок
- ✅ **Параллельная загрузка** — `ThreadPoolExecutor` для источников
- ✅ **URL Health tracking** — автопропуск источников с повторяющимися ошибками
- ✅ **Base64 round-trip** — корректная обработка закодированных подписок
- ✅ **QR-коды с HTML-индексом** — удобное сканирование на мобильных устройствах

</td>
</tr>
</table>

---

## ⚠️ Прежде чем использовать

> [!WARNING]
> Все подписки предназначены для обхода **белых списков**. Прошу вас **не использовать** их с включённым Wi-Fi (работать они будут даже на Wi-Fi). Дайте людям пользоваться серверами, у кого действительно включены белые списки — мощность серверов и производительность сильно падают из-за наплыва пользователей.

> [!CAUTION]
> **НАСТОЯТЕЛЬНО РЕКОМЕНДУЮ НЕ ИСПОЛЬЗОВАТЬ ЭТИ VPN-СЕРВЕРЫ ДЛЯ БАНКОВСКИХ ПЕРЕВОДОВ.** Хоть репозиторий и блокирует большинство небезопасных серверов, всегда есть свои риски. Также не рекомендуется использование государственных приложений без хорошей split-маршрутизации, которая позволяет VPN-трафику идти напрямую через приложения. Например: **Yandex, VK, MAX, Госуслуги** и так далее — для снижения риска блокировок серверов из-за Роскомнадзора.

> [!IMPORTANT]
> **"Прошёл фильтр" ≠ "оператору можно доверять"** — этот скрипт проверяет только техническую корректность конфигурации, а не репутацию оператора сервера. Оператор видит ваш SNI (без ECH), весь plaintext HTTP и DNS, если тот не резолвится локально.

---

## 📑 Содержание

- [Что делает проект](#-что-делает-проект)
- [Архитектура фильтрации](#️-архитектура-фильтрации)
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
| 🔓 Небезопасные TLS-параметры | `allowInsecure=1`, `security=none`, `verify=false` | ✅ |
| 🚫 Запрещённые / скомпрометированные домены | Бесплатные хостинги, известные пулы, подозрительные зоны | ✅ |
| ⚡ Опасные транспортные комбинации | `type=raw` без шифрования, `xhttp` без `host` | ✅ |
| 🏠 Приватные / loopback адреса | `127.0.0.1`, `localhost`, `10.x`, `192.168.x` | ✅ |
| 🕵️ MITM / DNS-подмена | Кастомные CA, нестандартные DNS, sniffing на внешние домены | ✅ |
| 🔑 Слабое шифрование SS | RC4, DES, CFB, CTR, Salsa20, Chacha20 non-IETF | ✅ |
| 🧮 SS 2022 key validation | Неверная длина base64-ключа для `2022-blake3-*` | ✅ |

### 📦 Протокол-специфичные проверки

| Протокол | Проверки | Статус |
|---|---|:---:|
| **VMess** | `alterId > 0`, `allowInsecure`, отсутствие TLS, `scy=none` | ✅ |
| **VLESS Reality** | Отсутствие `pbk` / `fp`, невалидный `flow`, длина pbk ≠ 43 | ✅ |
| **VLESS TLS** | Отсутствие `sni` / `host` / `alpn` | ✅ |
| **Hysteria2 / v1** | `insecure=1`, отсутствие SNI, пустой пароль | ✅ |
| **ShadowsocksR** | Слабые методы шифрования, пустой пароль | ✅ |

### 🔒 Продвинутая защита (v4.2+)

| Категория | Описание | Статус |
|---|---|:---:|
| 🐝 **Sybil-детекция** | Дедуп по `host:port` (лимит 2 на сокет) | 🆕 |
| 🛡️ **Универсальный host-чек** | Защита всех протоколов, а не только VLESS/Trojan | 🆕 |
| 🔐 **Пост-квантовая криптография** | Валидация ML-KEM-768 + X25519 гибридов | 🆕 |
| 🎯 **Placeholder UUID** | Блокировка `0000...` и `ffff...` UUID | 🆕 |
| 📡 **Base64 round-trip** | Подписки в base64 декодируются → фильтруются → кодируются обратно | ✅ |
| 🔁 **Повторяющиеся идентификаторы** | Один `pbk` / `uuid` / `sid` в >3 конфигах | ✅ |

Результат — очищенные списки в `githubmirror/`, обновляемые каждые **9 минут** через GitHub Actions.

---



## 📥 Источники данных

Конфигурации берутся из **публичных открытых репозиториев**:

| ID | Источник | Формат | Статус |
|:---:|---|:---:|:---:|
| `FILTER-1` | [RKPchannel/RKP_bypass_configs](https://github.com/RKPchannel/RKP_bypass_configs) | plaintext | ✅ |
| `FILTER-2` | [AvenCores/goida-vpn-configs](https://github.com/AvenCores/goida-vpn-configs) | plaintext | ✅ |
| `FILTER-3` | [zieng2/wl](https://github.com/zieng2/wl) | plaintext | ✅ |
| `FILTER-4` | [whoahaow/rjsxrd](https://github.com/whoahaow/rjsxrd) | plaintext | ✅ |
| `FILTER-5` | [igareck/vpn-configs-for-russia](https://github.com/igareck/vpn-configs-for-russia) | plaintext | ✅ |
| `FILTER-6` | [kort0881/vpn-vless-configs-russia](https://github.com/kort0881/vpn-vless-configs-russia) | plaintext | ✅ |
| `FILTER-7-BASE64` | [solovyov-jenya2004](https://solovyov-jenya2004.vercel.app/final_sorted_base64) | **base64** | ✅ |

> [!TIP]
> Все источники проверяются на доступность через `URL Health Report`. Источники с повторяющимися ошибками автоматически пропускаются.

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

---

## 🔎 Как сканировать

| Клиент | Путь |
|:---:|---|
| **v2rayNG** | `+` → Import config from QR code |
| **Karing** | `+` → Scan QR Code |
| **Hiddify** | `+` → Import from QR |
| **Nekobox** | `+` → Scan QR code |

> [!TIP]
> Для автоматического обновления используйте URL подписки напрямую — клиент будет обновлять список каждый час.

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
<summary>🇬 <b>English</b></summary>

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
