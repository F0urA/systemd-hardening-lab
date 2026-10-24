# Диагностика истечения срока memcached, 24.10.2026

Выполнена после эксперимента по `scripts_v005/protocol_memcached_ttl.md`; протокол, драйвер и помощник
были на GitHub в коммите `7d15f516626503dcac2daf70a1a38857816e3045` до запуска. Выводы этапа 3 не меняет:
P1 memcached остаётся исключённым. Итог и его толкование — `../README.md`, «Известные особенности».

## Как выполнялась

ВМ повтора этапа 3, та же, что 19–20.10 (на снапшот не откатывалась). Перед запуском, 24.10 16:36–16:38 UTC:

1. клон `/root/src` обновлён с `6eb755e` до `7d15f51` (`git fetch origin main`, `git merge --ff-only`),
   рабочее дерево чистое;
2. `systemctl start slab-memcached-v005.service`: unit статический и после перезагрузки ВМ не запускается
   сам, а драйвер требует работающую службу. Drop-in при этом — сохранённый P4, обвязка совпадает с
   `fixture.sha256` (драйвер проверяет и то и другое);
3. `systemd-run --unit=slab-ttl-diag bash /root/src/scripts_v005/memcached_ttl_diagnostic.sh`, вывод — в
   `../vm-logs/memcached-ttl-diagnostic.log`.

Прогон 16:38:35–17:02:21 UTC, код выхода 0, после него служба снова под P4 (`RESTORE_P4 memcached=PASS`).
Запуск один, повторов не было.

## Файлы

`20261024T163835Z/` — каталог результатов с ВМ без изменений (имя дал драйвер): `source.txt` (коммит,
регистрация, версия), `platform.txt`, `code.sha256`, `check-R<раунд>-<профиль>.json` (150 проверок),
`rows.csv`, `summary.txt` (вердикт `UNCLASSIFIED`), `journal.txt`, `kernel.txt`; манифест `sha256-all.txt`.
Архив с ВМ — `../archives/memcached-ttl-diagnostic-20261024T163835Z.tar.gz` (на ВМ —
`/tmp/20261024T163835Z.tar.gz`, SHA256 тот же).

`python reproduce.py rerun` сверяет файлы с манифестом и заново считает `summary.txt` из `rows.csv`.
