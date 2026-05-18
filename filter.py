def main():
    print("=== Фильтр подписок (с UNFILTER-3 для отладки) ===")
    all_filtered = set()
    with ThreadPoolExecutor(max_workers=5) as ex:
        futures = {ex.submit(load_and_filter, src): src for src in SOURCES_CONFIG}
        for future in as_completed(futures):
            src = futures[future]
            name = src['name']
            try:
                filtered, raw = future.result()
                # Сохраняем отфильтрованные
                out = os.path.join(OUTPUT_DIR, f"{name}.txt")
                with open(out, 'w', encoding='utf-8', newline='\n') as f:
                    f.write('\n'.join(sorted(filtered)))
                    if filtered:
                        f.write('\n')
                print(f"  Сохранён {name}.txt → {len(filtered)} конфигов")
                all_filtered.update(filtered)

                # ДЛЯ FILTER-3 ВСЕГДА СОЗДАЁМ UNFILTER-3.txt (даже пустой)
                if name == "FILTER-3":
                    unfiltered_path = os.path.join(OUTPUT_DIR, "UNFILTER-3.txt")
                    with open(unfiltered_path, 'w', encoding='utf-8', newline='\n') as f:
                        f.write('\n'.join(raw))
                        if raw:
                            f.write('\n')
                    print(f"  Сохранён UNFILTER-3.txt → {len(raw)} сырых конфигов (если 0 — значит не удалось собрать конфиги из источника)")
            except Exception as e:
                print(f"  [{name}] Ошибка: {e}")

    # Общий ALL.txt
    all_file = os.path.join(OUTPUT_DIR, "ALL.txt")
    with open(all_file, 'w', encoding='utf-8', newline='\n') as f:
        f.write('\n'.join(sorted(all_filtered)))
        if all_filtered:
            f.write('\n')
    print(f"\n✅ Создан ALL.txt с {len(all_filtered)} уникальными конфигами")
