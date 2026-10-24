# Карта измерений: раздел статьи → скрипт → данные

Этап 3 выполнен дважды на ВМ ALT Server 11.1:

- 12–14.10.2026, хост AMD Ryzen 5 2600 — `data/main/`; этот файл описывает его, пути в последнем
  столбце таблицы ниже указаны относительно `data/main/raw-vm/`;
- 19–20.10.2026, хост AMD Ryzen 5 3600, одной очередью `run_stage3.sh` из коммита `6eb755e` —
  `data/rerun/`, данные статьи. Его каталоги по разделам статьи, хронология и отступления —
  `data/rerun/README.md`; скрипты и параметры те же, что в таблице ниже, порядок — `run_stage3.sh`.

Номера таблиц — по окончательной редакции статьи (в ней числа — по `data/rerun/`); табл. S1–S7 и рис. S1 —
`docs/SUPPLEMENT.md`.

## Исполнявшиеся версии и эта редакция

Точные версии, которые исполнялись на стенде, лежат в пакете результатов: архивы фиксации
`data/main/protocol/*-frozen.zip` (их SHA256 записаны в `data/main/protocol/*_FREEZE*` до измерений)
и их распакованные копии `data/main/frozen-primary/`, `frozen-timing/`, `frozen-mount-states/`,
`frozen-analysis-queue/`. `python reproduce.py` сверяет их с записями.

`scripts_v005/` — те же скрипты в переносимой редакции: всё, что было привязано к машине и к
человеку, проводившему этап (каталог на ВМ, SSH-псевдоним, пути к Python и sh на Windows, раскладка
папок исполнителя), вынесено в параметры. Логика измерений и анализа не менялась; скрипты анализа,
которые использует `reproduce.py` (`build_criteria`, `select_profile`, `order_sensitivity`,
`robustness`, `audit_benchmark_csv`), не правились вовсе и совпадают с исполнявшимися побайтно.

| Параметр | Значение по умолчанию | Где используется |
|---|---|---|
| `SLAB_BASE` | `/root/systemd-hardening-lab` | рабочий каталог на ВМ: драйверы очереди, подготовка стенда, memcached, матрица монтирования, анализатор, сборщики результатов |
| `SLAB_RESULTS_ROOT` | `$SLAB_BASE/results_v005` | каталог результатов на ВМ |
| `SLAB_SSH_HOST` | `slab-vm` | SSH-хост ВМ для сборщиков на Windows (`~/.ssh/config`) |
| `SLAB_PYTHON` | `python` из PATH | Python на Windows для сборщиков и их тестов |
| `SLAB_SH` | `sh` или `bash` из PATH | оболочка для синтаксических проверок в тестах |
| `SLAB_SCRIPTS` | `frozen-primary/...` рядом с анализатором, иначе `scripts_v005/` | где анализатор и пересчёт архива берут общие модули |
| `SLAB_ARCHIVE`, `SLAB_OUT` | `results_v005/` (в репозитории — `data/preliminary/`), `./archive-retrospective` | `recompute_archive_v005.py` |

Изменённые относительно исполнявшихся файлы (только перечисленные строки путей и имён):
драйверы `orchestration_v005/*.sh`, `resume_transport_v005.py`, `driver_preflight_v005.sh`,
`prepare_existing_v005.sh`, `memcached_stage3_v005.sh`, `supplement_mount_states_v005.sh`,
`analysis_v005/analyze_v005.py`, `check_closed_environment_v005.py`, `recompute_archive_v005.py`,
`host_v005/collect_results*_v005.ps1` и тесты `tests_v005/*`. Тесты Python (35, и ещё 6 в
`test_run_stage3.py`) проходят из репозитория; тесты сборщиков требуют PowerShell 7. После публикации в
комментариях `make_ablation_v005.sh` и `ablation_report_v005.py` исправлена ссылка на протокол абляции: он —
раздел 6 `protocol_load_v005.txt`, отдельного `protocol_ablation_v005.txt` не было.

## Раскладка на стенде

Скрипты ожидают такой каталог на ВМ (`BASE=$SLAB_BASE`):

| На ВМ | В репозитории |
|---|---|
| `$BASE/frozen-timing/v005/scripts_v005/` | `scripts_v005/` (основные скрипты) |
| `$BASE/frozen-timing/v005/stand_v005/` | `stand_v005/` |
| `$BASE/post-analysis/` | `scripts_v005/analysis_v005/` (`analyze_v005.py`, `analyze_memcached_v005.py`, `inspect_series_v005.py`) |
| `$BASE/post-analysis/frozen-primary/v005/scripts_v005/`, `$BASE/post-analysis/frozen-timing/v005/scripts_v005/` | `scripts_v005/` (модули, которые импортируют анализаторы) |
| `$BASE/post-analysis/raw-vm` | ссылка на `$BASE/results_v005` |
| `$BASE/frozen-mount-states/scripts_v005/` | `scripts_v005/` (`supplement_mount_states_v005.sh`, `mount_state_helper_v005.py`) |
| `$BASE/` | `scripts_v005/orchestration_v005/` (драйверы очереди) |
| `$BASE/results_v005/` | `data/main/raw-vm/` |

Эту раскладку из клона репозитория создаёт `orchestration_v005/deploy_stage3.sh` (добавлен после эксперимента), а всю очередь
этапа 3 на новом стенде запускает `orchestration_v005/run_stage3.sh` — см. `scripts_v005/GUIDE_v005.md`, раздел
«Повторение этапа 3 с нуля одной очередью».

Подготовка существующего стенда — `prepare_existing_v005.sh` (точечное дооснащение, без
`setup_stand_v005.sh`), профили-кандидаты строит `make_candidates_v005.sh`, варианты абляции —
`make_ablation_v005.sh`.

## Соответствие разделам статьи

| Раздел статьи | Измерение | Скрипт и параметры | Результат в `raw-vm/` |
|---|---|---|---|
| 6.1, табл. 2, 5 | Обязательный контракт, TLS, миграция P0/P1→P1c | `functional_ext_v005.sh` (из `driver_preflight_v005.sh`) | `functional-v005/20261012-104934` |
| 6.2, табл. 6 | 36 микропроверок | `probe_all_v005.sh`; пробы `stand_v005/probes/*` | `probe-v005/20261012-110043` |
| 6.3 | Реальный и модельный процесс, проверки изнутри unit | `PROFILES='P0 P1 P1r P1c P4' context_compare_v005.sh`; `slab_inservice_v005.sh`, `slab_fp_v005.sh`, `slab_dropuser_v005.py` | `context-v005/20261012-105616` |
| 6.4, табл. 7, 8 | Цели G1–G4 (диагностический повтор) | `scenarios_v005.sh` (версия из `v005-goal-diagnostic-frozen.zip`, совпадает с текущей) | `scenarios-v005/20261012-110837` |
| 6.3, 6.6 | G1 изнутри unit и унаследованный дескриптор | `supplement_goals_v005.sh`, `inherited_fd_v005.py` | `supplement-goals-v005/20261012-105904` |
| 6.5, табл. 9 | Абляция capabilities | `NGINX_PROFILES='P0 P1r P1c P1cADMIN P1cPTRACE P1cDAC P1cCHROOT'` → `functional_ext_v005.sh nginx`, `scenarios_v005.sh nginx` (`driver_post_primary_resume_v005.sh`) | `functional-v005/20261014-002104`, `scenarios-v005/20261014-002436` |
| 6.6, табл. S3 | Монтирование после запуска | `supplement_mount_states_v005.sh check`, затем `run`; `mount_state_helper_v005.py`; протокол `protocol_mount_states_v005.md` | `mount-states-v005/20261014-002458-…` |
| 5.5 | Пилот P0/P4, 10 пар | `benchmark_v005.sh nginx 10 P4` | `nginx/benchmark-v005/20261012-175204` |
| 6.7, табл. 10 | R1: Nginx P0/P1c/P4/P5/P6, 60 блоков | `NGINX_N=100000 NGINX_C=25 KEEPALIVE=0 PIN=1 STALL_MS=500 benchmark_v005.sh nginx 60 P1c P4 P5 P6` | `nginx/benchmark-v005/20261012-175912` |
| 6.7 | R2: Redis, 20 блоков | `REDIS_N=3000000 REDIS_THREADS=3 benchmark_v005.sh redis 20 P1 P2 P1d P4 P6` | `redis/benchmark-v005/20261012-194224` |
| 6.7 | R3: PostgreSQL, 10 блоков (полный повтор) | `PG_T=60 benchmark_v005.sh postgresql 10 P1 P2 P1d P4 P6` (`driver_primary_resume_v005.sh`, порт — `resume_transport_v005.py`) | `postgresql/benchmark-v005/20261013-193448` |
| 6.7 | R5: Nginx P0/P1/P2/P1r, 60 блоков | `benchmark_v005.sh nginx 60 P1 P2 P1r` (`driver_primary_resume_v005.sh`) | `nginx/benchmark-v005/20261013-204356` |
| 6.8, табл. S5 | Пилоты R4, C = 1…16 | `NGINX_C=$C benchmark_v005.sh nginx 3 P4` (`driver_primary_resume_v005.sh`) | `nginx/benchmark-v005/20261013-220413` … `-221223` |
| 6.7 | Анализ, добор R1д/R3д, окончательный анализ | `analyze_v005.py`, затем `driver_extensions_v005.sh` по `extension-plan.json`, затем `analyze_v005.py --final` (`driver_post_primary_resume_v005.sh`) | `nginx/…/20261013-221436`, `postgresql/…/20261013-233151`; анализ — `data/main/analysis-first-look/`, `data/main/analysis-final/` |
| 6.9, табл. 11, S6 | Выбор, 24 политики, обязательные цели | `build_criteria_v005.py`, `select_profile_v005.py` (`--require nginx=G2-read-app-secret`), `order_sensitivity_v005.py` | `data/main/analysis-final/`, `data/derived/selection_required_g2_v005.txt` |
| 6.7 | Точечные оценки | `point_estimates_v005.py data/main` (после эксперимента, только чтение CSV) | `data/derived/point_estimates_v005.txt` |
| 6.7, рис. S1, табл. S4 | PostgreSQL: распределение контрастов, t-границы и перестановочные границы | `pg_contrasts.py data/main` (после эксперимента) | `data/derived/pg_contrasts.csv` |
| 7, 8 | Новая служба memcached | `memcached_stage3_v005.sh register/prepare/check/probe/measure`, `memcached_client_v005.py`, `analyze_memcached_v005.py`; протокол `protocol_memcached_v005.txt` | исполнение остановилось на `register` (`driver/post-memcached-register.out`): установленный на стенде `/usr/local/bin/ptrace_seize.py` отличался от `stand_v005/probes/ptrace_seize.py` — стенд собирался прежней редакцией; на стенде из `setup_stand_v005.sh` они совпадают, `run_stage3.sh stand` это проверяет. В повторении memcached измерен: `data/rerun/memcached/` |
| 5.6, 6.7, 7, 8 | Измерения, повторённые из-за паузы ВМ, и границы по первым попыткам | `stall_sensitivity.py data/main`, `stall_sensitivity.py data/rerun` (после эксперимента, только чтение CSV) | `data/derived/stall_sensitivity.txt`, `data/rerun/derived/stall_sensitivity.txt` |
| 6.1, 8 | Диагностика отказа P1 memcached по истечению срока (после эксперимента, в выбор не входит) | `memcached_ttl_diagnostic.sh` на ВМ повторения, помощник `memcached_ttl_diagnostic.py`; протокол `protocol_memcached_ttl.md` зафиксирован коммитом до запуска | `data/rerun/memcached-ttl-diagnostic/` (24.10.2026, исход `UNCLASSIFIED`: отказов P1 нет) |
| 7 | Системные вызовы на операцию | `syscall_count_v005.sh` — **этап 2**, на этапе 3 не запускался | `data/preliminary/syscalls-v005` |

Пауза ВМ отслеживается `slab_heartbeat_v005.py` (два метронома, CLOCK_MONOTONIC_RAW); проверка CSV —
`audit_benchmark_csv_v005.py`.

## На стороне Windows

| Скрипт | Назначение |
|---|---|
| `host_v005/host-monitor-v005.ps1` | Запись загрузки и частоты процессоров хоста (`data/main/logs/host-activity-*.csv`), временный запрет сна |
| `host_v005/collect_results_v005.ps1`, `collect_results_resume_v005.ps1` | Выгрузка результатов с ВМ и сверка SHA256 |
| `analysis_v005/verify_raw_v005.py` | Сверка выгруженных файлов с манифестом |
| `analysis_v005/audit_report_v005.py`, `verify_report_v005.py` | Независимый пересчёт таблиц отчёта, проверка его чисел и ссылок |
| `analysis_v005/check_closed_environment_v005.py` | Проверка состояния ВМ после очереди (P4, отсутствие нагрузок) |
| `analysis_v005/recompute_archive_v005.py` | Отдельный пересчёт архивных серий этапов 1–2 (в новые данные не входит) |

Тесты оркестрации и анализа — `tests_v005/`.

## Чего в репозитории нет

- Драйверы первого запуска очереди `driver_primary_v005.sh` и `driver_primary_corrected_v005.sh`
  (запуск пилота, R1, R2 и первой попытки R3) в присланный архив не вошли; известны только их SHA256
  (`raw-vm/driver/orchestration-sha256.txt`, `corrected-orchestration-sha256.txt`). Они вызывали
  `benchmark_v005.sh` с параметрами из таблицы выше; фактические параметры записаны в `platform.txt`
  каждого каталога серии. Файлы нужно запросить у того, кто проводил измерения, и сверить по хешу.
  Их часть очереди (пилот, R1, R2, R3 с одним техническим повтором) восстановлена по протоколу в
  `orchestration_v005/run_stage3.sh`; остальные драйверы (`driver_primary_resume_v005.sh`,
  `driver_post_primary*_v005.sh`, `start_resume_v005.sh`) сверяют архивы и журналы того запуска и на новом
  стенде намеренно не запускаются.
- Профили `stand_v005/profiles/*/P4.conf` и `nginx/P5.conf` взяты из ВМ (`raw-vm/*/profiles/`), а
  не из архива фиксации: на стенде действовали сохранённые P4/P5 с теми же директивами и другими
  комментариями, поэтому их хеш отличается от манифеста. Все 22 файла `stand_v005/profiles/` побайтно
  совпадают с профилями, действовавшими на стенде (`raw-vm/initial-state/profile-sha256.txt`).
- Прежние редакции скриптов и стенда (этапы 1–2) — `docs/history/v003/`, `docs/history/v004/`: состояния
  тегов `v003` (`f49be6b`) и `v004` (`9c847d7`) прежней истории репозитория, которой после перезаливки на
  GitHub нет.
