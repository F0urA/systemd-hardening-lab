# Повторение этапа 3, 19–20.10.2026

Этап 3 повторён на новой ВМ одной очередью `run_stage3.sh` из коммита
`6eb755e48c43625964c5a202f8e5eaa59393cccc` этого репозитория. Коммит был на GitHub с 19.10 14:44 UTC;
на ВМ он склонирован без локальных изменений и разложен `deploy_stage3.sh` в 16:48 UTC
(`vm-logs/src-head.txt`, `vm-logs/deployed-from.txt`), первое измерение — в 17:01 UTC. Все 334 разложенных
файла совпадают с файлами коммита (`vm-logs/deployed-sha256.txt`; проверяет `python reproduce.py rerun`).
Это данные статьи; прогон 12–14.10.2026 — `data/main/`.

## Стенд

ВМ VirtualBox 7.2.16 на настольном компьютере с AMD Ryzen 5 3600 (6 ядер, 12 потоков), 32 ГиБ, Windows;
процесс VirtualBox к ядрам не привязывался, загрузка хоста не записывалась. ВМ: 4 vCPU, 4 ГиБ ОЗУ,
ALT Server 11.1, Linux 6.12.74-6.12-alt1, systemd 257.9-alt1, PostgreSQL 14.24, Python 3.12.7 — как в
прогоне `data/main`. Отличия пакетов (`raw-vm/driver/versions-vs-executed.txt`): nginx 1.30.5 (было 1.30.4),
Redis 8.6.6 (8.6.5), strace 7.0 (6.19). memcached 1.6.42-alt1 — тот же. Часы синхронизированы chrony перед
каждой фазой (`raw-vm/driver/*-clock.txt`).

## Порядок (UTC)

| Время | Что |
|---|---|
| 19.10 16:48 | `deploy_stage3.sh`, `run_stage3.sh stand` → STAND_READY; снапшот ВМ |
| 19.10 16:55 | preflight, попытка 1: RC=2 на шаге `context` — после восстановления из снапшота не работали `lab-proc-target@{root,labweb,labredis,labpg}` (static, не в автозапуске). ВМ откачена на снапшот, записи попытки не сохранились |
| 19.10 17:01–17:21 | preflight, попытка 2 (мишени запущены вручную `systemctl start`): 5/5 RC=0 |
| 19.10 17:21–22:24 | primary: пилот OK (CV P0 0,60 %), R1, R2, R3, R5 RC=0 с первой попытки; R4 = FAILED (ни одно C=1…16 не дало CPU(P0) 40–70 %) |
| 19.10 22:24–20.10 00:43 | post: первый анализ → добор R1 (P4, P6; 60 блоков) и R3 (P1 P2 P1d P4 P6; 10 блоков), окончательный анализ, CAP, mount states — RC=0; `memcached-install` RC=2 |
| 20.10 00:43 | seal: 7178 файлов, `archives/results_v005-closed.tar.gz` |
| 20.10 03:24 | memcached, попытка 1 (`memcached-attempt1/memcached_addendum.sh`): установка RC=0, register RC=1 |
| 20.10 03:25–03:37 | memcached, попытка 2 (`memcached/memcached_addendum2.sh`): все шаги RC=0 |

## Почему memcached измерен отдельно

1. `install_memcached` в `run_stage3.sh` 6eb755e сравнивал версию из `apt-get -s` целиком:
   `1.6.42-alt1:p11+418735.100.1.1@1779279920` ≠ `1.6.42-alt1`, хотя пакет тот же. В дополнении
   сравнивается часть до `:`.
2. `memcached_stage3_v005.sh` принимает версию только по шаблону `[a-zA-Z0-9.-]`, а `memcached -V` на ALT
   печатает `1.6.42_alt1`. В попытке 2 скрипт запущен из копии `memcached/frozen-memcached-addendum` с `_` в
   обоих шаблонах; других изменений нет (`memcached/results_v005/driver/addendum2-memcached-stage3.diff`;
   `reproduce.py` проверяет, что остальные 108 файлов копии совпадают с разложенными). Пакет повторно не
   ставился.

Остальное — `phase_memcached` из `run_stage3.sh` без изменений. Обе ошибки и неработающие после снапшота
мишени исправлены в `run_stage3.sh` после повтора. Опечатанные результаты основного прогона не тронуты:
файлы каждой попытки перечислены в своём манифесте (`SHA256-ADDENDUM-MEMCACHED.txt`,
`SHA256-ADDENDUM2-MEMCACHED.txt`) и лежат в своём архиве.

## Итог memcached

P1 исключён обязательным функциональным контрактом: проверка `expiration` (TTL 2 с, ожидание 3,2 с) нашла
ключ после ожидания; P2, в который входят все директивы P1, эту проверку прошёл, причина не выяснялась.
P0, P2, P4, P6 — по 20 блоков, отказов нет; добор не потребовался (`needs_extension: false`).
Правило A → P4; правило B → TIE(P2/P4/P6); B + политика оператора → P4; стоимость P2/P4/P6 ≈ 1,8 %
(`memcached/post-analysis/memcached-analysis-first-look/`).

## Содержимое

| Каталог | Что |
|---|---|
| `raw-vm/` | опечатанные результаты основного прогона (`results_v005` на ВМ), манифест `SHA256-CLOSED-RESULTS.txt` |
| `analysis-first-look/`, `analysis-final/`, `extension-plan.json` | первый и окончательный анализ, план добора (`post-analysis/` на ВМ) |
| `memcached/` | попытка 2: драйвер, исправленная копия скриптов, результаты с манифестом, анализ memcached |
| `memcached-attempt1/` | попытка 1: драйвер и её 8 файлов с манифестом |
| `vm-logs/` | логи фаз (`stand.log`, `preflight.log` — попытка 2, `stage3.log`, `memcached-addendum*.log`), записи раскладки |
| `archives/` | три архива с ВМ и их SHA256 (совпадают с посчитанными на ВМ) |
| `derived/` | точечные оценки, проверка PostgreSQL перестановочными границами, выбор с обязательными целями — посчитаны после эксперимента `point_estimates_v005.py`, `pg_contrasts.py`, `select_profile_v005.py --require` |

Имена каталогов внутри — те, что дали скрипты на ВМ (их SHA256 записаны под этими именами).

## Соответствие разделам статьи

Пути относительно `raw-vm/`, если не указано иное.

| Раздел | Измерение | Результат |
|---|---|---|
| 6.1, табл. 2, 7 | Контракт, TLS, миграция на P1c | `functional-v005/20261019-170059` |
| 6.2, табл. 8 | 36 микропроверок | `probe-v005/20261019-172028` |
| 6.3 | Реальный и модельный процесс, проверки изнутри unit | `context-v005/20261019-171452` |
| 6.4, табл. 9, 10 | Цели G1–G4 | `scenarios-v005/20261019-171608` |
| 6.3, 6.6 | G1 изнутри unit, унаследованный дескриптор | `supplement-goals-v005/20261019-171708` |
| 6.5, табл. 11 | Абляция capabilities | `functional-v005/20261020-003653`, `scenarios-v005/20261020-004151` |
| 6.6, табл. 12 | Монтирование после запуска | `mount-states-v005/20261020-004217-…` |
| 5.5 | Пилот P0/P4, 10 пар | `nginx/benchmark-v005/20261019-172127` |
| 6.7, табл. 13 | R1: Nginx P0/P1c/P4/P5/P6, 60 блоков | `nginx/benchmark-v005/20261019-172537` |
| 6.7 | R2: Redis, 20 блоков | `redis/benchmark-v005/20261019-184311` |
| 6.7 | R3: PostgreSQL, 10 блоков | `postgresql/benchmark-v005/20261019-194432` |
| 6.7 | R5: Nginx P0/P1/P2/P1r, 60 блоков | `nginx/benchmark-v005/20261019-211626` |
| 6.8, табл. 15 | Пилоты R4, C = 1…16 | `nginx/benchmark-v005/20261019-221621` … `-222305` |
| 6.7 | Добор R1д (P0, P4, P6) и R3д (P0, P1, P2, P1d, P4, P6) | `nginx/benchmark-v005/20261019-222428`, `postgresql/benchmark-v005/20261019-230632` |
| 6.7–6.9, табл. 13, 16, 17 | Анализ и выбор | `../analysis-final/`, `../derived/` |
| 6.7, рис. 1, табл. 14 | PostgreSQL: t-границы и перестановочные границы | `../derived/pg_contrasts.csv` |
| 6.1, 6.7, 6.9, 7 | memcached | `../memcached/results_v005/memcached/`, `../memcached/post-analysis/` |

## Проверка

```
python reproduce.py rerun          # из корня репозитория: манифесты, происхождение, все таблицы
```
