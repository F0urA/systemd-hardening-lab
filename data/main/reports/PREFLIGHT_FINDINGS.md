# v005: завершённые функциональные и защитные проверки

Локальная сверка 12.10.2026. Это отчёт только о завершённых диагностических этапах, не итог нагрузочных серий и не решение правила выбора. Частичные нагрузочные CSV не анализировались. Исходные CSV, журналы, замороженные сценарии и архивные материалы не изменялись. Доступа к ВМ при этой сверке не было.

Основные результаты: все 20 контрактов нагрузочных профилей прошли; обе отдельные TLS-проверки прошли. Ожидания E1, E2, E4 и E5 поддержаны в проверенных состояниях с ограничениями ниже. E3 пока не проверено: четыре варианта capabilities были пропущены из-за несовпадения имён файлов. E6 опровергнуто в явно добавленном состоянии с унаследованным дескриптором каталога, но не в исходном статическом состоянии unit.

## 1. Какие данные использованы

Нумерация E1–E6 относится к четвёртому дополнению [protocol_review2_v005.txt][protocol], а не к одноимённым ожиданиям более раннего основного протокола.

| Набор | Локальный источник | Роль в отчёте |
| --- | --- | --- |
| F | [contract.csv][f-contract], [functional.csv][f-detail] | Контракт, 8 миграционных ячеек, TLS, описание crash/JIT |
| C | [context run.log][context-log], [transient metrics.csv][context-model], [in-service metrics.csv][context-service] | Сопоставление проверяемых свойств и 36 статусов |
| S0 | [первый goals.csv][scenarios-first] | Первоначальная диагностика с 8 неопределёнными Redis-ответами; не подмешивается в исправленный набор |
| S1 | [исправленный goals.csv][scenarios-corrected], [candidates.csv][candidates-corrected], [run.log][scenarios-log] | Основные цели Nginx, Redis, PostgreSQL после уточнения диагностики Redis |
| CAP | [CAP run.log][cap-log], [CAP candidates.csv][cap-candidates] | Документирование пропущенных профилей, не результат абляции |
| D | [supplement goals.csv][supplement-goals], [run.log][supplement-log] | G1 внутри unit и отдельное состояние inherited-directory-FD |
| Регистрация | [RUN_PROTOCOL.md][run-protocol], [GOAL_DIAGNOSTIC_ADDENDUM.md][goal-addendum], [CLOCK_CORRECTION.md][clock-correction] | Отклонения стенда, границы целей, история исправлений |

Имена каталогов до коррекции часов используют прежнюю гостевую шкалу UTC. Они сохранены как идентификаторы наборов. Их нельзя выдавать за синхронизированные с Windows временные метки. Наличие exit_status=0 в [preflight-ledger.csv][preflight-ledger] само по себе не доказывает полноту CAP-проверки или пригодность пилота.

## 2. Функциональный контракт, TLS и миграция

[F summary][f-contract] содержит ровно 22 строки PASS: Nginx P0/P1/P2/P1r/P1c/P4/P5/P6; Redis и PostgreSQL P0/P1/P2/P1d/P4/P6; отдельно nginx-tls P0/P1c. Основных контрактов 20, отдельные TLS-контракты в F нагрузочного Nginx не смешиваются.

В [F detail][f-detail] для Nginx прошли start и все пять обязательных операций: USR1, reload с двумя рабочими процессами, ответ 404, restart и crash-recovery. Между операциями этого контракта владелец журнала не исправлялся. После USR1 под P0/P1/P2/P1r журнал принадлежит labweb; под P1c/P4/P5/P6 остаётся root. Под P1c последующий restart прошёл. Поэтому наблюдения не подтверждают предположение, что собственный USR1 P1c обязательно приводит к отказу restart.

Redis прошёл BGSAVE, BGREWRITEAOF и restart с сохранением значения во всех шести профилях. PostgreSQL прошёл CHECKPOINT, reload, restart и запрос с jit=on во всех шести профилях. Однако во всех строках query-with-jit записано `jit_used=no`. Подтверждена работоспособность запроса с такой настройкой, а не исполнение настоящего JIT под sandbox. Crash-recovery Redis/PG тоже PASS, но помечено `mandatory=0` и остаётся описательным результатом, не новым обязательным условием.

TLS проверялся отдельно на loopback 8443 с локальным upstream 18080. У P0 и P1c прошли запуск, HTTPS с проверкой синтетического CA и точного ответа upstream, затем reload с повторной проверкой ответа и двумя workers. Это один конфигурационный вариант, не TLS-нагрузочная серия и не доказательство совместимости всех TLS-конфигураций.

### 8 независимых миграционных ячеек

Каждая ячейка начиналась с отдельной подготовки журнала root-owned. Далее исходная операция выполнялась без скрытого chown; возврат владельца root выполнялся только в отдельной ветви «с шагом». Все восемь исходных операций и все восемь переходов с явным шагом прошли. Источник: строки `migrate-*` в [F detail][f-detail].

| Переход | Исходная операция | Владелец после неё | Без шага миграции | С явным возвратом владельца root |
| --- | --- | --- | --- | --- |
| P0 → P1c | reopen | labweb | BLOCKED: P1c не запустился | PASS |
| P0 → P1c | reload | root | STARTED | PASS |
| P0 → P1c | restart | root | STARTED | PASS |
| P0 → P1c | crash | root | STARTED | PASS |
| P1 → P1c | reopen | labweb | BLOCKED: P1c не запустился | PASS |
| P1 → P1c | reload | root | STARTED | PASS |
| P1 → P1c | restart | root | STARTED | PASS |
| P1 → P1c | crash | root | STARTED | PASS |

E5 подтверждено именно после переоткрытия журнала. Отказ без миграционного шага нельзя распространять на остальные три операции: там переход прошёл. Это не F=0 для самостоятельно развёрнутого P1c и не разрешение незаметно менять владельца внутри его контракта.

## 3. E1–E6 и границы выводов

| Ожидание | Что установлено | Что этим не установлено |
| --- | --- | --- |
| E1, real/model | Nginx P0/P1/P1r/P1c/P4: проверенные UID/GID, groups, capabilities, NoNewPrivs и seccomp совпадают. 36 статусов in-service/transient совпадают в master/worker-контекстах. Различия mount-таблиц рассмотрены ниже. | Не универсальная эквивалентность всех состояний/атак. Отдельные mount namespace имеют разные идентификаторы, что журнал прямо помечает DIFF_EXPECTED. |
| E2, G1 in-service | P1r master достигает G1 в обоих DAC-состояниях, worker блокируется; P1c блокирует все четыре статические ячейки. Исходы совпадают с модельными. | ExecStartPost с переключением UID не является настоящим скомпрометированным worker. Не доказана передача ему любых дополнительных FD/состояний. |
| E3, capabilities | Базовые P1r/P1c проверены, но четыре добавления capabilities отсутствуют в выполненных ячейках из-за ошибки имён. | Нельзя заявлять подтверждение E3, фактический отказ запуска этих вариантов, минимальность набора или доказанную причинность конкретной capability. |
| E4, дополнительные цели | P1c блокирует статический G1 и G3, но не G2 и master-ячейку G4. Остаточный риск наблюдался. | Цели составлены автором на том же стенде; это не внешняя независимая экспертиза. G4 проверяет запись, хотя записанное правило для записываемого пути требует чтения. |
| E5, migration | После USR1 P0/P1 переход к P1c требует явного возврата владельца root. После reload/restart/crash без шага стартует. | Нельзя считать все переходы одинаковыми или подменять чистый F успешностью после ручного восстановления. |
| E6, новые FD/FS-состояния | В добавленном inherited-directory-FD состоянии P1c имеет два ACHIEVED и два BLOCKED. Это контрпример к абсолютному E6. | Он не является наблюдением компрометации исходного unit: стандартный unit не получает такой writable-directory-FD. Остальные изменённые mount-состояния не покрыты здесь независимыми полными матрицами. |

### E1: что именно совпало

В [context run.log][context-log] имеются 13 сравнений `inservice_vs_transient=IDENTICAL (36 probes)`: 10 Nginx и 3 PostgreSQL P0/P1/P4. Для Redis P0/P1/P4 сохранено сопоставление fingerprint, но in-service набор недоступен. Для лёгких профилей Nginx P1/P1r/P1c mount-таблица real/transient различается только именем unit в источнике `/run/systemd/incoming`; real/in-service таблицы идентичны. Для P4 дополнительная пара строк связана с `memory.pressure` cgroup соответствующего unit. Это проверено непосредственно по [P1c mount diff][p1c-mount] и [P4 mount diff][p4-mount], а не только по одинаковому числу монтирований.

Пример без переинтерпретации знаменателя: P1c master Emicro=18/35=0.514286, worker=6/19=0.315789 и в transient, и in-service. Число eligible не равно 36: операции, недоступные уже в P0, не становятся новыми заслугами профиля. Это диагностическая метрика, не итоговый выбор кандидата.

### E2/E4: статические цели и исходная доступность

В [S1][scenarios-corrected] у Nginx P1c G1 BLOCKED во всех четырёх ячейках. В P0 достижимы три из четырёх; worker/rootown блокируется уже исходным DAC. Поэтому эта четвёртая блокировка не является дополнительным эффектом P1c.

У P1c G2 (секрет, нужный приложению) ACHIEVED в master и worker; G3 BLOCKED в обоих контекстах; G4 ACHIEVED в master и BLOCKED в worker. Worker-ячейки G3/G4 уже блокируются в P0. P6 блокирует обе ячейки G4. G3 использует синтетический соседний файл для проверки конфигурационного пути, не изменяет настоящий nginx.conf; G2 тоже синтетический. Такие наблюдения не подтверждают защиту любого реально настроенного файла/секрета.

У Redis и PostgreSQL G1 собственный каталог вне разрешённого data dir достижим в P0/P1/P2/P4 и блокируется в P1d/P6 в обоих контекстах server/process. Root-owned каталог блокируется во всех профилях уже из-за DAC. PostgreSQL G2 COPY PROGRAM достигается во всех шести профилях и остаётся остаточным риском.

### Redis: неопределённость первого запуска и доказательства второго

[S0][scenarios-first] содержит 135 строк: 63 ACHIEVED, 63 BLOCKED, 1 INFO и 8 UNEXPECTED. Причина UNEXPECTED — общий ERR при SAVE без errno в клиентском ответе. Они сохранены как неопределённая первоначальная диагностика, не перекодированы задним числом в защиту.

[S1][scenarios-corrected] тоже содержит 135 строк: 63 ACHIEVED, 71 BLOCKED, 1 INFO, без UNEXPECTED. Проверен журнал каждой из восьми соответствующих server-ячеек: совпадают точный target и server_pid, присутствует явный отказ доступа. В этом локальном снимке для этих восьми ячеек неопределённых ошибок не осталось.

| Профиль/каталог | server_pid | Явное доказательство в журнале |
| --- | --- | --- |
| P0/root | 41840 | [Permission denied][redis-p0-root], точный redis-g1-v005-root |
| P1/root | 42046 | [Permission denied][redis-p1-root], точный redis-g1-v005-root |
| P2/root | 42260 | [Permission denied][redis-p2-root], точный redis-g1-v005-root |
| P4/root | 42713 | [Permission denied][redis-p4-root], точный redis-g1-v005-root |
| P1d/own | 42474 | [Read-only file system][redis-p1d-own], точный redis-g1-v005-own |
| P1d/root | 42474 | [Read-only file system][redis-p1d-root], отдельная строка точного root-target |
| P6/own | 42928 | [Read-only file system][redis-p6-own], точный redis-g1-v005-own |
| P6/root | 42928 | [Read-only file system][redis-p6-root], отдельная строка точного root-target |

Исправление диагностики сделано после первого наблюдения, что прямо раскрыто в [addendum][goal-addendum]. Это не новая независимая предрегистрация. Сценарий сначала показывает INFO: штатный application guard Redis запрещает CONFIG SET dir. Затем он явно временно разрешает protected configs, чтобы проверить защиту ОС. Вывод относится к этому ослабленному application-состоянию, а не к штатному guard. В конце [S1 run.log][scenarios-log] записаны REDIS_CONF_RESTORED и RESTORE_P4=PASS для всех трёх служб.

### E3: missing-profile отличается от actual-start-fail

[CAP run.log][cap-log] явно содержит SKIP на строках 42/46/50/54 для P1c+ADMIN/P1c+PTRACE/P1c+DAC/P1c+CHROOT. Сразу следующие NOT_FUNCTIONAL имеют объединённую причину `excluded ... or missing`. [Генератор][cap-source] создал имена без плюса: P1cADMIN/P1cPTRACE/P1cDAC/P1cCHROOT. В [CAP candidates.csv][cap-candidates] есть только P0/P1r/P1c, а результатов четырёх вариантов нет.

Корректная квалификация: **E3 не проверено; F добавленных вариантов неизвестно**. Причину нельзя кодировать как F=0 или фактическую несовместимость. Оркестратор планирует отдельный последовательный повтор с правильными именами после завершения текущей нагрузки. В этот отчёт его будущие результаты не входят. Менять nginx unit во время нагрузочной серии нельзя.

### E6: отдельный контрпример с inherited FD

[D][supplement-goals] содержит 64 ячейки: 34 ACHIEVED и 30 BLOCKED, без неопределённых исходов. Для P1c:

| DAC/контекст | Статический in-service G1 | Добавленное inherited-directory-FD состояние |
| --- | --- | --- |
| rootown/master | BLOCKED | ACHIEVED, uid=0 |
| rootown/worker | BLOCKED | BLOCKED, errno=13 |
| labweb/master | BLOCKED | BLOCKED, errno=13 |
| labweb/worker | BLOCKED | ACHIEVED, uid=969 |

Открытый до sandbox дескриптор является существенным дополнительным условием. Суженный вывод: P1c блокирует проверенный G1 в исходной статической конфигурации, но не гарантирует запрет записи при передаче такого FD. Нельзя удалять этот результат из отчёта или выдавать исходный статический вывод за абсолютную защиту каталога. P5/P6 в том же добавленном FD-состоянии тоже имеют эти два ACHIEVED.

Проверки обхода через proc1root/remount в S1 и отдельный FD в D не являются полной независимой проверкой всех возможных late-mount/nested-bind состояний. Для состояний без отдельных воспроизводимых строк утверждение остаётся ограниченным проверенной статической конфигурацией и конкретным зарегистрированным FD-контрпримером.

## 4. Время, переносимость и незавершённые части

Согласно [CLOCK_CORRECTION.md][clock-correction], chronyd устранял большое отставание гостя через slew. Старый пилот Nginx с каталогом 20261012-110140 и неполная R1 с каталогом 20261012-110940 объявлены TIMING_INVALID и сохранены. Ни exit=0 старого пилота, ни его успешные HTTP-запросы не являются действительным допуском к нагрузочным сериям. Они не включаются в новые блоки, статистические границы или заявления о производительности. Этот отчёт не оценивает старые или новые throughput/CPU/op, CV, допуск по бюджетам либо итог выбора A+/B.

Новая редакция benchmark/heartbeat использует CLOCK_MONOTONIC_RAW для длительности и пауз, UTC только для labels/journal. Коррекция сделана после обнаружения проблемы с часами, до нового пилота; она не делает старые измерения пригодными. Дискретные функциональные/защитные исходы выше рассматриваются самостоятельно. Проверка TTL и стоимости операций относится к ещё не выполненной новой службе, а не к этому отчёту.

Стенд из [RUN_PROTOCOL.md][run-protocol]: ALT Server 11.1, Linux 6.12.74-6.12-alt1, systemd 257.9, VirtualBox 7.2.16, 4 vCPU, 4 GiB; Windows-хост AMD Ryzen 5 2600. Это не архивный Intel Core Ultra. Гостевая CPU-привязка не равна архивной host-affinity. Старые результаты ВМ, results_v005 из ZIP и v004 известны как reference, но не заменяют новые наблюдения и не объединяются с ними. Публичный коммит/независимая предрегистрация, требуемые архивным протоколом, не выполнены; локальная фиксация хешей не равнозначна им. Цели и стенд авторские, независимость частичная.

Для завершения доказательной части остаются: корректная E3-абляция; действительные завершённые нагрузочные серии и их заранее предусмотренный анализ; отдельная новая служба этапа 26. Локально подготовленный memcached-комплект имеет собственный протокол, реальные 36 микропроб, четыре разных ограниченных кандидата и RAW-часы. Его локальные тесты не являются экспериментом на ALT. Для in-memory конфигурации G=∅, что явно ограничивает переносимость path-части метода; g=0 не означает отсутствие риска. Если у memcached выявится F=0, автоматический шаг минимального ослабления не реализован: это заранее отмеченное PARTIAL_PROCEDURE, а не скрытая полнота применения исходной процедуры. В этом отчёте нет результатов memcached и нет утверждений его эффективности.

## 5. Проверка идентичности использованных CSV

12.10.2026 локально проверены SHA256 основных CSV; совпадают с хешами сохранённых наборов. Это проверка идентичности файлов, не независимая валидация всех семантических решений.

| Файл | SHA256 |
| --- | --- |
| F functional.csv | 846df06e429aa7a69eea7a327c28b301cba23fe1481e4fa147e2d9c6d82e0e40 |
| F contract.csv | 5881803f0ffcf3d80100d07fad0dd536b2d470ff1cddace97407db877cb86e67 |
| S1 goals.csv | 1f9c9323b1b82969646004485f02973896d0bb28a0053ad2cc4e5a3f6b970efd |
| S1 candidates.csv | 8a3640520533f58cbd3800a1b7027a2ae47bfee05e89e425b3434c35cd2fde92 |
| D goals.csv | 07ed7186c6f0ab874c8acf69d0e3ef653db7ceed6401f2a1f8795455d2a6153d |

[protocol]: ../frozen-primary/v005/scripts_v005/protocol_review2_v005.txt
[f-contract]: ../raw-vm/functional-v005/20261012-104934/contract.csv
[f-detail]: ../raw-vm/functional-v005/20261012-104934/functional.csv
[context-log]: ../raw-vm/context-v005/20261012-105616/run.log
[context-model]: ../raw-vm/context-v005/20261012-105616/transient/metrics.csv
[context-service]: ../raw-vm/context-v005/20261012-105616/inservice/metrics.csv
[scenarios-first]: ../raw-vm/scenarios-v005/20261012-105745/goals.csv
[scenarios-corrected]: ../raw-vm/scenarios-v005/20261012-110837/goals.csv
[candidates-corrected]: ../raw-vm/scenarios-v005/20261012-110837/candidates.csv
[scenarios-log]: ../raw-vm/scenarios-v005/20261012-110837/run.log
[cap-log]: ../raw-vm/scenarios-v005/20261012-105855/run.log
[cap-candidates]: ../raw-vm/scenarios-v005/20261012-105855/candidates.csv
[cap-source]: ../frozen-primary/v005/scripts_v005/cap_ablation_v005.sh
[supplement-goals]: ../raw-vm/supplement-goals-v005/20261012-105904/goals.csv
[supplement-log]: ../raw-vm/supplement-goals-v005/20261012-105904/run.log
[run-protocol]: ../raw-vm/driver/RUN_PROTOCOL.md
[goal-addendum]: ../raw-vm/driver/GOAL_DIAGNOSTIC_ADDENDUM.md
[clock-correction]: ../raw-vm/driver/CLOCK_CORRECTION.md
[preflight-ledger]: ../raw-vm/driver/preflight-ledger.csv
[p1c-mount]: ../raw-vm/context-v005/20261012-105616/transient/nginx-master-P1c.mnt.diff
[p4-mount]: ../raw-vm/context-v005/20261012-105616/transient/nginx-master-P4.mnt.diff
[redis-p0-root]: ../raw-vm/scenarios-v005/20261012-110837/redis-P0-root.journal.txt
[redis-p1-root]: ../raw-vm/scenarios-v005/20261012-110837/redis-P1-root.journal.txt
[redis-p2-root]: ../raw-vm/scenarios-v005/20261012-110837/redis-P2-root.journal.txt
[redis-p4-root]: ../raw-vm/scenarios-v005/20261012-110837/redis-P4-root.journal.txt
[redis-p1d-own]: ../raw-vm/scenarios-v005/20261012-110837/redis-P1d-own.journal.txt
[redis-p1d-root]: ../raw-vm/scenarios-v005/20261012-110837/redis-P1d-root.journal.txt
[redis-p6-own]: ../raw-vm/scenarios-v005/20261012-110837/redis-P6-own.journal.txt
[redis-p6-root]: ../raw-vm/scenarios-v005/20261012-110837/redis-P6-root.journal.txt
