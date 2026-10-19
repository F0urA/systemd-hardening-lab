# Подготовка пакета к публикации

Пакет собран скриптом из рабочего дерева репозитория. Ниже — что при этом изменено. Всё, что здесь не
перечислено, совпадает с исходными файлами байт в байт.

## 1. Раскладка

| Было | Стало |
|---|---|
| `results_v005/run-20261012-v005/` (каталоги `raw-vm`, `analysis-*`, `frozen-*`, `archive-retrospective`, `resume-context-*`) | `data/main/` — те же каталоги, без изменений |
| `results_v005/run-20261012-v005/` — записи фиксации (`*_FREEZE*`, `*ADDENDUM*`, `RUN_PROTOCOL.md`, `CLOCK_CORRECTION.md`, `*-frozen.zip`, `extension-plan.json`) | `data/main/protocol/` |
| `results_v005/run-20261012-v005/` — отчёты и проверки исполнителя (`*.md`, `*.json`, `HOST_BASELINE.txt`) | `data/main/reports/` |
| `results_v005/run-20261012-v005/` — журналы сборщика и монитора хоста, снимок закрытых результатов | `data/main/logs/` |
| `results_v005/run-20261012-v005/` — копии скриптов, исполнявшихся на хосте исполнителя (`*.py`, `*.ps1`) | `data/main/executed/` |
| `results_v005/{pg_contrasts_v007.csv, point_estimates_v005.txt, selection_required_g2_v005.txt}` | `data/derived/` (`pg_contrasts_v007.csv` — под именем `pg_contrasts.csv`, см. ниже) |
| остальное `results_v005/` (предварительные этапы 1–2) | `data/preliminary/` |
| `scripts_v005/EXPERIMENTS_v005.md` | `docs/EXPERIMENTS_v005.md` |
| `HANDOFF_v005.md`, `EXPERIMENT_READINESS.md` | `docs/history/` |

Имена файлов не менялись, кроме перечисленных в последнем разделе. Записи фиксации и отчёты исполнителя называют файлы по исходной раскладке:
каталог `results/` исполнителя — это `data/main/`.

## 2. Удаление локальных путей

Записи этапа 3 сделаны на компьютере исполнителя, и в части из них были пути его профиля Windows. Они
заменены метками; остальные байты, окончания строк, порядок и даты записей в архивах сохранены.

| Было | Стало |
|---|---|
| каталог проекта исполнителя в его профиле | `<OPERATOR_ROOT>` |
| каталог среды исполнения (интерпретаторы Python и sh) | `<OPERATOR_RUNTIME>` |
| прочие пути профиля | `<OPERATOR_HOME>` |

## 3. Ссылки в отчётах

В отчётах исполнителя (`data/main/reports/*.md`) относительные ссылки и ссылки вида
`<OPERATOR_ROOT>/results/…` указывают на те же файлы на их новых местах.

Не изменялись: сырые данные `data/main/raw-vm/` (манифест `SHA256-CLOSED-RESULTS.txt`), архивы
`v005-primary-frozen.zip`, `v005-timing-frozen.zip`, `v005-mount-states-frozen.zip`,
`v005-goal-diagnostic-frozen.zip`, копии `frozen-*/` и записи фиксации: в них остаются исходные
хеши, записанные до измерений. Неочищенные оригиналы хранятся у авторов и предоставляются редакции по
запросу.

`reproduce.py` принимает очищенный архив, только если его хеш «до» совпадает с записью фиксации,
а хеш «после» — с файлом пакета; неизменённые файлы внутри очищенных архивов он сверяет с их
собственными хешами в записях фиксации.

## Изменённые файлы

| Файл | SHA256 до | SHA256 после | Замен путей | Ссылок | Хеш «до» записан в |
|---|---|---|---|---|---|
| `docs/history/EXPERIMENT_READINESS.md` | 40c494023c87488fbef896f255d6c36bdb7e2d3d3073f210d3cab2ff4f36cf41 | 24e08753e952570050e1cb04ea6ccbc65c30f17f169860ce8aaf4c2d19299271 | 1 | 0 | — |
| `data/main/reports/closed-before-resume-verification.json` | 42079a9936ea81223b712880f971200de030522ffe467b914bc6c63d9bfee430 | 940fa20dee48a97f060b6ea1621b566d1cf5d4ad7a2cb76fc361a116d31f3033 | 1 | 0 | — |
| `data/main/executed/collect_results_resume_v005.ps1` | e618963620db24a92181a5bc5bff3b712091fb30b2319883f0e4f7d336e3a358 | 754ee59227bd7813cc121151c008e5b5b1e5461feaa9c310ad1f31d99297a0b4 | 1 | 0 | `data/main/raw-vm/driver/RESUME_FREEZE.txt`, `data/main/protocol/RESUME_FREEZE.txt` |
| `data/main/executed/collect_results_v005.ps1` | ec6fcb80b92971bda21fb30e364ba8cb3d3f1214fe4694bee0b71dcc3a86a70f | de4acaf2f66a7f67c8df21685882be2e279e2a596d97e4aff39ca1ddeb90fe0b | 1 | 0 | `data/main/protocol/COLLECTOR_FREEZE.md` |
| `data/main/logs/collector-20261012T210650Z-25452-fa2ef9c0.raw-verification.json` | e2d75a5ff68c5f25c78b663d6dcbfd43131bcad7f78abbcd581342181ce3dd5a | 5d0e8df64262e158f69b5abd45e208c718b71684505aee45539430efb2beb8cc | 2 | 0 | — |
| `data/main/logs/collector-20261012T210650Z-25452-fa2ef9c0.status.json` | 0fdd60f7e36c462fce5fdf8c961a13bde3ef2639698616e8530eb993af98a6f4 | 9dbea656313dddd33810143a8b7ad21dd0e004caa564656f5bc3c7efad7b5936 | 2 | 0 | — |
| `data/main/logs/collector-20261013T193543Z-30072-1cc23b0e.raw-verification.json` | 2462b127425deca14ac333c38d60707318ff9d94a4814eff58b84f02a7e8128f | 1d9d6ea08bf31c45e00f9cd3750e5a4ddebf0bf048642b253f27f3b938d2e4f5 | 2 | 0 | — |
| `data/main/logs/collector-20261013T193543Z-30072-1cc23b0e.status.json` | 456e99474903a2b5c2b8c604d0ed545532b06b96eb43c4ba8a9082c723f71d35 | f09a77e37d5c25eff035bda17e0eb3e77634b60ea10534c16d5415d0f4d8cb5c | 2 | 0 | — |
| `data/main/frozen-analysis-queue/tests/test_analysis_v005.py` | 1d5de03df5be2bd5c12016c1c848f9967d5ef848fa07f59fbde156f5e5ab57d3 | 6ff66bd091958bccc1c1bcee376bce018d012c458311772480b11433e63b961e | 1 | 0 | — |
| `data/main/reports/interim_v005_20261014.md` | 7df6f9a1396ab7d1911c7bf3c7f506b290e5f730f589fedef02dd954b9fa26cb | 687ddb06efeadc3fd850c749e4d9007e1267300c4953794ea001f98eea0223b4 | 0 | 7 | — |
| `data/main/reports/PREFLIGHT_FINDINGS.md` | 8e908f793598f4d4f248fa3e1c30d3214cd63bf579080fab637132f319576f9d | 22c761cc605cb7384bfd8cada4086e8198970554516d996c7d3c0aaac30eaa29 | 29 | 29 | — |
| `data/main/reports/R1-download-verification.json` | 63e6f2ba2aa78c651d17d857c35febc5c640e30b9c18de7551ffe9e05966b53e | 95ec54e0ffaa39d42b6124f4f57a2b18c91ff6d7594f252665949d5193bdd0cd | 1 | 0 | — |
| `data/main/reports/README.md` | 8a223b57f0b663e7cee31c819f674f5ca150f080a575f745cda3edb09152343b | aec50ab50c7e9a298c13216cb190ca3c7a8e2755681b84a3abb9503ffdd910a1 | 7 | 7 | — |
| `data/main/reports/REPORT_RAW_VERIFICATION.json` | 9a3d290d39b134e1106038cabe9c6d6a41758474b79e08746dbd76c5deb95ab4 | a06fed33f70a3988af437cb913c8b74c132024277194e30c727a72c5f29987fc | 1 | 0 | — |
| `data/main/reports/REPORT_RAW_VERIFICATION_FINAL.json` | 9a3d290d39b134e1106038cabe9c6d6a41758474b79e08746dbd76c5deb95ab4 | a06fed33f70a3988af437cb913c8b74c132024277194e30c727a72c5f29987fc | 1 | 0 | — |
| `data/main/reports/report_v005.md` | 14c4d67a4ea8d8fde7ae488b9622fb5ce2d86ad65a80dbc653aefe25eecc699a | f91b60ff73becefcc09e581cd3b0054b1e551a46d562ba66a6a7ba44aadee1db | 34 | 34 | `data/main/reports/MONITOR_STOPPED_v005.json`, `data/main/reports/REPORT_VERIFICATION.json` |
| `data/main/reports/resume-context-verification.json` | 1c850663344ed1dd6298b0e29ac24afd88c3a5dce1dbce2f09893aa986b50ebc | e5a999284adec5f283dd10331c0a89eef05b9053ea7686f081f9c688ff86ae3a | 1 | 0 | — |
| `data/main/reports/STATUS.md` | 5bc1db4268eea0a3a3ce3b758aad3e147e439504aef96ed1a71fc1940b2581a1 | 8ccb2b0abdebdba030c844ba2d653e91e0f3736ddbc346681a1b8fd7487d32d3 | 1 | 1 | — |
| `data/main/protocol/v005-analysis-queue-frozen.zip` | b5ebcb3217abc81aa3a3ff51a36c03de634979e603274559c2c92b436a7ace63 | 7770840f23e4d2ab8da54b32b9c84ee0c804aba447a72fd6f88c486e0472259c | 1 | 0 | `data/main/protocol/ANALYSIS_QUEUE_FREEZE.txt` |
| `data/main/protocol/v005-collector-frozen.zip` | 2639f3cbb7aea3fd98dc7e4171ba26b67691dd1e0470d25deeb8c42404c88201 | 394a44538999ea7f87f28881b87d4547298fb7ad556ff9d372805e61a2ac03fe | 2 | 0 | `data/main/protocol/COLLECTOR_FREEZE.md` |
| `data/main/protocol/v005-resume-frozen.zip` | cf4b55e6fbde44b7f3dd5e41ab88050d78f0795f35e8489b1fd9fef8dcd16550 | 9ac7ad72e76d5680708813f24a0d3b9d2428e567c04c38decd1c8e9e6f7f103d | 3 | 0 | `data/main/raw-vm/driver/RESUME_FREEZE.txt`, `data/main/protocol/RESUME_FREEZE.txt`, `data/main/reports/STATUS.md` |

## Изменённые файлы внутри архивов

| Архив → файл | SHA256 до | SHA256 после | Замен путей | Хеш «до» записан в |
|---|---|---|---|---|
| `data/main/protocol/v005-analysis-queue-frozen.zip` → `tests/test_analysis_v005.py` | 1d5de03df5be2bd5c12016c1c848f9967d5ef848fa07f59fbde156f5e5ab57d3 | 6ff66bd091958bccc1c1bcee376bce018d012c458311772480b11433e63b961e | 1 | — |
| `data/main/protocol/v005-collector-frozen.zip` → `collect_results_v005.ps1` | ec6fcb80b92971bda21fb30e364ba8cb3d3f1214fe4694bee0b71dcc3a86a70f | de4acaf2f66a7f67c8df21685882be2e279e2a596d97e4aff39ca1ddeb90fe0b | 1 | `data/main/protocol/COLLECTOR_FREEZE.md` |
| `data/main/protocol/v005-collector-frozen.zip` → `test_collect_results_v005.ps1` | acfd205dc8917a8892855672fc4c1c4bd2d7c5da91fd7da97dd0d2425dc1344c | 76c0ae76b085d31a1a7966b8aaff871a0afe5eb3e5e01ca15be2e6ab493913f4 | 1 | `data/main/protocol/COLLECTOR_FREEZE.md` |
| `data/main/protocol/v005-resume-frozen.zip` → `collect_results_resume_v005.ps1` | e618963620db24a92181a5bc5bff3b712091fb30b2319883f0e4f7d336e3a358 | 754ee59227bd7813cc121151c008e5b5b1e5461feaa9c310ad1f31d99297a0b4 | 1 | `data/main/raw-vm/driver/RESUME_FREEZE.txt`, `data/main/protocol/RESUME_FREEZE.txt` |
| `data/main/protocol/v005-resume-frozen.zip` → `test_primary_resume_v005.py` | 027d9f265ff8c993a2c33470c22dcbc66a97d009aa9998d16514824e2e4dd9ef | 1850e0c086f6132d1123f316a8db839ec7ed672cfb96653db14150aa6d8b9631 | 1 | `data/main/raw-vm/driver/RESUME_FREEZE.txt`, `data/main/protocol/RESUME_FREEZE.txt` |
| `data/main/protocol/v005-resume-frozen.zip` → `test_collect_results_resume_v005.ps1` | 4db09f0e0f52f194bceb381d8adb95741bdefd6d32a76933eecee36ed7d76abe | 067cfafc593019c9fa26bb513dfb746b3d60d6974b04a65eb9d040bbe8c95dcb | 1 | `data/main/raw-vm/driver/RESUME_FREEZE.txt`, `data/main/protocol/RESUME_FREEZE.txt` |

## Переименования после публикации

19.10.2026 у инструментов, сделанных после эксперимента, убран номер редакции рукописи: в репозитории
остался один номер, `v005`, — редакция скриптов, которой выполнены измерения и которая под этими именами
записана в данных и протоколах. Содержимое файлов при этом не менялось, кроме ссылок на новые имена.

| Было | Стало |
|---|---|
| `reproduce_v007.py` | `reproduce.py` |
| `docs/SANITIZATION_v007.md` | `docs/SANITIZATION.md` |
| `scripts_v005/pg_contrasts_v007.py` | `scripts_v005/pg_contrasts.py` |
| `data/derived/pg_contrasts_v007.csv` | `data/derived/pg_contrasts.csv` |
| `scripts_v005/orchestration_v005/run_stage3_v008.sh`, `deploy_stage3_v008.sh` | `run_stage3.sh`, `deploy_stage3.sh` |
| `scripts_v005/tests_v005/test_run_stage3_v008.py` | `test_run_stage3.py` |
