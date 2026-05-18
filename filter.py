#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import os
import json
import base64
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Set, Dict, Optional, List, Tuple

OUTPUT_DIR = "githubmirror"
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Используем те же ключи, что и раньше, но с явными номерами
SOURCES_CONFIG = [
    {"id": "1", "url": "https://gist.githubusercontent.com/flaafix/c79a81037d15163360571c7a7331b153/raw/AetrisVPN.txt"},
    {"id": "2", "url": "https://github.com/AvenCores/goida-vpn-configs/raw/refs/heads/main/githubmirror/26.txt"},
    {"id": "3", "url": "https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_universal.txt"},
    {"id": "4", "url": "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-all.txt"},
    {"id": "5", "url": "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt"}
]

# ... (все функции is_safe_*, parse_multiline_configs, fetch_and_process без изменений) ...

def main():
    print("=== Фильтрация + сырые копии (FILTER-* и UNFILTER-*) ===")
    all_filtered = set()
    all_raw = []

    with ThreadPoolExecutor(max_workers=5) as ex:
        futures = {ex.submit(process_source, src): src for src in SOURCES_CONFIG}
        for future in as_completed(futures):
            src = futures[future]
            idx = src['id']
            try:
                filtered, raw_lines = future.result()
                # FILTER-id.txt
                filt_path = os.path.join(OUTPUT_DIR, f"FILTER-{idx}.txt")
                with open(filt_path, 'w', encoding='utf-8', newline='\n') as f:
                    f.write('\n'.join(sorted(filtered)))
                    if filtered:
                        f.write('\n')
                print(f"  Сохранён FILTER-{idx}.txt → {len(filtered)} конфигов")
                all_filtered.update(filtered)

                # UNFILTER-id.txt
                unfilt_path = os.path.join(OUTPUT_DIR, f"UNFILTER-{idx}.txt")
                with open(unfilt_path, 'w', encoding='utf-8', newline='\n') as f:
                    f.write('\n'.join(raw_lines))
                    if raw_lines:
                        f.write('\n')
                print(f"  Сохранён UNFILTER-{idx}.txt → {len(raw_lines)} строк (сырые)")
                all_raw.extend(raw_lines)
            except Exception as e:
                print(f"  [{idx}] Ошибка: {e}")

    # FILTER-ALL.txt и UNFILTER-ALL.txt (опционально)
    # ...

if __name__ == "__main__":
    main()
