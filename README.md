# 🛡️ VPN Config Security Filter

<p align="center">
  <img src="https://img.shields.io/github/actions/workflow/status/Trojankill/Safe-server-lists-for-bypassing-whitelists/update.yml?label=auto-update&style=for-the-badge&logo=githubactions&logoColor=white" alt="CI">
  <img src="https://img.shields.io/github/last-commit/Trojankill/Safe-server-lists-for-bypassing-whitelists?style=for-the-badge&logo=git&logoColor=white&color=orange" alt="Last commit">
  <img src="https://img.shields.io/github/license/Trojankill/Safe-server-lists-for-bypassing-whitelists?style=for-the-badge&color=green" alt="License">
  <img src="https://img.shields.io/badge/refresh-every_9_min-blue?style=for-the-badge&logo=clockify&logoColor=white" alt="Refresh">
</p>

<p align="center">
  <b>Автоматизированный аудит и фильтрация публичных прокси-конфигураций.</b><br>
  VLESS · VMess · Trojan · Hysteria2 · Shadowsocks · ShadowsocksR
</p>

---

## ⚠️ Прежде чем использовать

> Все подписки предназначены для обхода **белых списков**. Прошу вас **не использовать** их с включённым Wi-Fi (работать они будут даже на Wi-Fi). Дайте людям пользоваться серверами, у кого действительно включены белые списки — мощность серверов и производительность сильно падают из-за наплыва пользователей.

> **НАСТОЯТЕЛЬНО РЕКОМЕНДУЮ НЕ ИСПОЛЬЗОВАТЬ ЭТИ VPN-СЕРВЕРЫ ДЛЯ БАНКОВСКИХ ПЕРЕВОДОВ.** Хоть репозиторий и блокирует большинство небезопасных серверов, всегда есть свои риски. Также не рекомендуется использование государственных приложений без хорошей split-маршрутизации, которая позволяет VPN-трафику идти напрямую через приложения. Например: **Yandex, VK, MAX, Госуслуги** и так далее — для снижения риска блокировок серверов из-за Роскомнадзора.

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

| Категория | Примеры |
|---|---|
| 🔓 Небезопасные TLS-параметры | `allowInsecure=1`, `security=none`, `verify=false` |
| 🚫 Запрещённые / скомпрометированные домены | Бесплатные хостинги, известные пулы, подозрительные зоны |
| ⚡ Опасные транспортные комбинации | `type=raw` без шифрования, `xhttp` без `host` |
| 🔑 Слабое шифрование SS | RC4, DES, CFB, CTR, Salsa20, Chacha20 non-IETF |
| 🧮 SS 2022 key validation | Неверная длина base64-ключа для `2022-blake3-*` |
| 📦 VMess | `alterId > 0`, `allowInsecure`, отсутствие TLS |
| 🛡️ VLESS Reality | Отсутствие `pbk` / `fp`, невалидный `flow` |
| 🌐 VLESS TLS | Отсутствие `sni` / `host` / `alpn` |
| 💨 Hysteria2 / v1 | `insecure=1`, отсутствие SNI, пустой пароль |
| 🗝️ ShadowsocksR | Слабые методы шифрования, пустой пароль |
| 🔁 Повторяющиеся идентификаторы | Один `pbk` / `uuid` / `sid` в >3 конфигах |
| 🏠 Приватные / loopback адреса | `127.0.0.1`, `localhost`, `10.x`, `192.168.x` |
| 🕵️ MITM / DNS-подмена | Кастомные CA, нестандартные DNS, sniffing на внешние домены |
| 📡 Base64 round-trip | Подписки в base64 декодируются → фильтруются → кодируются обратно |

Результат — очищенные списки в `githubmirror/`, обновляемые каждые **9 минут** через GitHub Actions.

---

## 📥 Источники данных

Конфигурации берутся из **публичных открытых репозиториев**:

| ID | Источник | Формат |
|---|---|---|
| FILTER-1 | [RKPchannel](https://github.com/RKPchannel/RKP_bypass_configs) | plaintext |
| FILTER-2 | [AvenCores/goida-vpn-configs](https://github.com/AvenCores/goida-vpn-configs) | plaintext |
| FILTER-3 | [zieng2/wl](https://github.com/zieng2/wl) | plaintext |
| FILTER-4 | [whoahaow/rjsxrd](https://github.com/whoahaow/rjsxrd) | plaintext |
| FILTER-5 | [igareck/vpn-configs-for-russia](https://github.com/igareck/vpn-configs-for-russia) | plaintext |
| FILTER-6 | [AetrisVPN](https://gitverse.ru/flaafix/AetrisVPN) | plaintext |
| FILTER-7-BASE64 | [solovyov-jenya2004](https://solovyov-jenya2004.vercel.app/final_sorted_base64) | **base64** |

---

## 📱 Подписки и QR-коды

Нажми на название, чтобы раскрыть QR-код. Отсканируй в клиенте (**v2rayNG**, **Karing**, **Hiddify**, **Nekobox**).

<details>
<summary><b>📡 FILTER-ALL</b> — все конфиги (рекомендуется)</summary>

<p align="center">
  <img src="QR-CODE/ALL.png" width="300" alt="ALL QR">
</p>

<p><b>URL подписки:</b></p>

<pre>
https://raw.githubusercontent.com/Trojankill/Safe-server-lists-for-bypassing-whitelists/main/githubmirror/ALL.txt
</pre>

</details>

<details>
<summary><b>📡 FILTER-1</b> — VAL41K/bypass-rkn-blocks</summary>

<p align="center">
  <img src="QR-CODE/FILTER-1.png" width="300" alt="FILTER-1 QR">
</p>

<p><b>URL подписки:</b></p>

<pre>
https://raw.githubusercontent.com/Trojankill/Safe-server-lists-for-bypassing-whitelists/main/githubmirror/FILTER-1.txt
</pre>

</details>

<details>
<summary><b>📡 FILTER-2</b> — AvenCores/goida-vpn-configs</summary>

<p align="center">
  <img src="QR-CODE/FILTER-2.png" width="300" alt="FILTER-2 QR">
</p>

<p><b>URL подписки:</b></p>

<pre>
https://raw.githubusercontent.com/Trojankill/Safe-server-lists-for-bypassing-whitelists/main/githubmirror/FILTER-2.txt
</pre>

</details>

<details>
<summary><b>📡 FILTER-3</b> — zieng2/wl</summary>

<p align="center">
  <img src="QR-CODE/FILTER-3.png" width="300" alt="FILTER-3 QR">
</p>

<p><b>URL подписки:</b></p>

<pre>
https://raw.githubusercontent.com/Trojankill/Safe-server-lists-for-bypassing-whitelists/main/githubmirror/FILTER-3.txt
</pre>

</details>

<details>
<summary><b>📡 FILTER-4</b> — whoahaow/rjsxrd</summary>

<p align="center">
  <img src="QR-CODE/FILTER-4.png" width="300" alt="FILTER-4 QR">
</p>

<p><b>URL подписки:</b></p>

<pre>
https://raw.githubusercontent.com/Trojankill/Safe-server-lists-for-bypassing-whitelists/main/githubmirror/FILTER-4.txt
</pre>

</details>

<details>
<summary><b>📡 FILTER-5</b> — igareck/vpn-configs-for-russia</summary>

<p align="center">
  <img src="QR-CODE/FILTER-5.png" width="300" alt="FILTER-5 QR">
</p>

<p><b>URL подписки:</b></p>

<pre>
https://raw.githubusercontent.com/Trojankill/Safe-server-lists-for-bypassing-whitelists/main/githubmirror/FILTER-5.txt
</pre>

</details>

<details>
<summary><b>📡 FILTER-6</b> — AetrisVPN</summary>

<p align="center">
  <img src="QR-CODE/FILTER-6.png" width="300" alt="FILTER-6 QR">
</p>

<p><b>URL подписки:</b></p>

<pre>
https://raw.githubusercontent.com/Trojankill/Safe-server-lists-for-bypassing-whitelists/main/githubmirror/FILTER-6.txt
</pre>

</details>

<details>
<summary><b>📡 FILTER-7-BASE64</b> — solovyov-jenya2004</summary>

<p align="center">
  <img src="QR-CODE/FILTER-7-BASE64.png" width="300" alt="FILTER-7-BASE64 QR">
</p>

<p><b>URL подписки (base64):</b></p>

<pre>
https://raw.githubusercontent.com/Trojankill/Safe-server-lists-for-bypassing-whitelists/main/githubmirror/FILTER-7-BASE64.txt
</pre>

<p><i>⚠️ Файл закодирован в base64. Клиенты v2rayNG / Karing / Hiddify декодируют автоматически.</i></p>

</details>

---

## 🔎 Как сканировать

| Клиент | Путь |
|---|---|
| **v2rayNG** | `+` → Import config from QR code |
| **Karing** | `+` → Scan QR Code |
| **Hiddify** | `+` → Import from QR |
| **Nekobox** | `+` → Scan QR code |


## ⚖️ Дисклеймер и правовая информация

### 🇷🇺 Русский

> - Автор не является владельцем/разработчиком/поставщиком перечисленных VPN-конфигураций. Это независимый информационный обзор и результаты тестирования.
> - Данный пост не является рекламой VPN. Весь материал предназначен исключительно в информационных целях, и только для граждан тех стран, где эта информация легальна, как минимум — в научных целях. Если вам такое читать нельзя — закройте эту страницу немедленно!
> - Автор не имеет никаких намерений, не побуждает, не поощряет и не оправдывает использование VPN и любых других программ ни при каких обстоятельствах.
> - Ответственность за любое применение данных VPN-конфигураций — на их пользователе.
> - Отказ от ответственности: автор не несёт ответственность за действия третьих лиц и не поощряет противоправное использование VPN.
> - Автор не несет ответственности за точность, полноту и достоверность опубликованных данных. Все совпадения случайны. Вся информация предоставлена «как есть» и может не соответствовать действительности.
> - Используйте в соответствии с местным законодательством.
> - Используйте VPN только в законных целях: в частности — для обеспечения вашей безопасности в сети и защищённого удалённого доступа, и ни в коем случае не применяйте данную технологию для обхода блокировок.
> - Проект некоммерческий, бесплатный, вся представленная «платежная» информация найдена случайным образом где-то в интернет-пространстве, скопирована «как есть» для демонстрации возможного примера и автору не принадлежит.
> - Совет — закройте эту страницу, удалите все VPN с вашего компьютера, поставьте MAX и Yandex на все устройства, чтобы «ловило» даже на парковке, и пользуйтесь только интернет-ресурсами, которые разрешены вашим интернет-провайдером, ну вы поняли.

### 🇬🇧 English

> - The author is not the owner, developer, or provider of the listed VPN configurations. This is an independent informational review presenting test results.
> - This post is not an advertisement for VPNs. All material is intended solely for informational purposes and is directed only at citizens of countries where accessing this information is legal — at the very least, for research purposes. If you are prohibited from reading this content, close this page immediately!
> - The author has no intention of — nor does the author incite, encourage, or condone — the use of VPNs or any other software under any circumstances.
> - The user bears full responsibility for any use of these VPN configurations.
> - The author is not liable for the actions of third parties and does not condone the unlawful use of VPNs.
> - The author assumes no responsibility for the accuracy, completeness, or reliability of the published data. Any resemblance to actual events or persons is purely coincidental. All information is provided "as is" and may not reflect reality.
> - Use in accordance with local laws.
> - Use the VPN only for lawful purposes — specifically, to ensure your online security and secure remote access — and under no circumstances use this technology to bypass blocks.
> - This is a free, non-commercial project; all "payment" information presented here was found randomly online, copied "as is" to demonstrate a potential example, and does not belong to the author.

---
