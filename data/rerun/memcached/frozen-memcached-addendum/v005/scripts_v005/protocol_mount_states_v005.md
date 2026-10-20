# v005 §6: отдельные exploratory mount-state проверки

Эта рабочая редакция подготовлена ПОСЛЕ знания результата inherited-directory-FD,
который уже опроверг абсолютное E6. Новые наблюдения его не отменяют. Это отдельное
exploratory дополнение для двух ранее не изолированных состояний, не независимая
предрегистрация и не первичные данные для правила выбора. Код/этот документ/хеши
родитель фиксирует отдельным пакетом до первого запуска. Изменений benchmark,
кандидатов, исходного protocol/procedure и статистических порогов нет.

## Порядок и матрица

Запуск родителем только ПОСЛЕ всех нагрузочных серий, последовательно с другими
диагностическими действиями. `check` выполняет только проверки чтением.
`SLAB_AFTER_PRIMARY=1 ... run` разрешается только в родительской serial queue;
эта метка сама не является доказательством отсутствия параллельной нагрузки.
Дополнительно требуется active Nginx в точном сохранённом P4 и отсутствие любых
других live drop-in (в том числе benchmark-affinity).

40 новых независимых ячеек: режим late, затем nested; в каждом режиме профили
P0/P1r/P1c/P5/P6 в этом фиксированном порядке; rootown/labweb × master/worker.
Каждая ячейка получает новые SOURCE, TARGET, control dir и процесс. Повторов для
выбора желаемого исхода нет. Невоспроизводимый/ошибочный исход сохраняется.

Реальная служба Nginx получает неизменный выбранный профиль из сохранённого файла.
Модель запускается systemd-run с теми же profile properties; master UID=root,
worker User=labweb, Group=labweb. UID-fallback, proc1root, remount исходного SITE,
переход в чужой namespace, rbind и другие способы атаки не выполняются.

## Одинаковый safety harness для всех моделей

Дополнительно и одинаково: PrivateMounts=yes + MountFlags=slave. Это variation
harness, особенно **P0+namespace-harness, не точный первичный P0**. Содержимое
файлов профилей не меняется. Причина: P0 иначе мог бы монтировать в host namespace;
в systemd PrivateMounts отделяет пространство, а MountFlags=slave явно задаёт
финальную propagation. Host→model может передаваться; model→host не разрешается.
Документация: [systemd v257 systemd.exec, PrivateMounts/MountFlags, строки
2183–2235](https://raw.githubusercontent.com/systemd/systemd/v257/man/systemd.exec.xml).

Перед nested mount дополнительно проверяется фактическое ns_mnt != host, а
covering mounts SOURCE/TARGET и fresh-directory parent не имеют shared-поля.
При shared, отсутствии отдельного namespace или невоспроизводимом состоянии —
NO nested mount, NOT_REPRODUCED и raw mountinfo. Широкого изменения propagation
для `/`, `/run`, SITE или любых существующих mountpoints нет. Неподдерживаемые
harness properties фиксируются по явному сообщению launcher как NOT_REPRODUCED;
прочая неизвестная ошибка запуска остаётся ERROR, не BLOCKED.

Type=exec, RuntimeMaxSec=35s, TimeoutStopSec=3s, KillMode=control-group — одинаковые
ограничения жизненного цикла моделей. READY deadline 15s, trigger deadline 20s.
Длительность ожиданий CLOCK_MONOTONIC_RAW; UTC — только labels/journal, не эффект.

## Только новые synthetic fixtures

SITE строго `/var/lib/systemd-lab/nginx-www`. TARGET каждой ячейки — только новый
`SITE/mountstate-v005-<token>-<cell>`. SOURCE вне SITE, в новом фиксированном
`/var/lib/systemd-lab/mountstate-v005/<cell>`. Base SOURCE уже существует — отказ,
ничего не перезаписывается. Control отдельный `/run/slab-mountstate-v005-<token>`.
Новые helper/control/target/source paths проверяются на конфликты, канонический
путь без symlink, device+inode и ownership registry. Host runner должен находиться
в mount namespace PID1. Подготовка только этих synthetic dirs; index.html,
настоящий nginx.conf, пользовательские файлы и credential/SSH-секреты не меняются.

SOURCE/TARGET dir 0755, владелец root или labweb по DAC. document.txt сначала
root-owned 0444 с точными байтами `G1_ORIGINAL_DOCUMENT\n`. Отдельный .state-token
различает SOURCE/TARGET, чтобы одинаковый HTTP payload не маскировал отсутствие
propagation. Атака — только mkstemp в тестовом dir, запись
`G1_REPLACED_DOCUMENT\n`, fchmod 0644 и atomic os.replace(document.txt).

## Late host bind ПОСЛЕ sandbox

1. Модель уже запущена; сохраняет READY с PID/start_ticks/ns и raw mountinfo/status.
2. Host подтверждает READY=MainPID именно своего unit; сохраняет host/model и
   настоящий nginx-master + 2 worker namespace snapshots.
3. Host mount --bind только точный SOURCE→TARGET, изначально TARGET не mounted.
   Проверяются источник, target inode, единственный новый точный mount record.
   Bind выполняет доверенный host-root, не модель. Это не способность P1c
   самостоятельно менять host mounts.
4. После снимков host/model/application namespace host даёт trigger. Модель
   проверяет, что в её namespace появился именно mount зарегистрированного SOURCE
   (exact target/device/root/fstype, directory identity и SOURCE marker).
5. Нет такого mount — NOT_REPRODUCED, atomic replace НЕ запускается. Есть mount —
   один atomic replace через TARGET, без альтернативных путей.

## Nested bind-remount в model namespace

После READY и trigger модель создаёт только собственный свежий mkdtemp под своим
control dir. После safety guards выполняет mount(TARGET, fresh, MS_BIND), проверяет
bind identity/не-shared propagation, затем MS_BIND|MS_REMOUNT с очисткой только
per-mount read-only и сохранением прочих исходных flags. После подтверждения rw
делает один atomic replace через fresh. Только подтверждённый собственный bind
размонтируется обычным umount; никаких lazy/force/recursive fallback. Ошибка
cleanup — ERROR независимо от прежнего результата попытки.

Исход mount/replace с EPERM/EACCES/EROFS сохраняет точный errno и phase bind,
remount-rw или replace как raw DENIED; другой errno/неожиданная ошибка — ERROR.
Даже если сама операция запрещена, строка не автоматически становится новым
достижением защиты.

## HTTP, baseline eligibility и классификация

Host HTTP обычного loopback 127.0.0.1:808: exact code+payload до попытки и после
неё (для late — ДО unmount). ALLOWED + 200/точный replaced → ACHIEVED; DENIED +
200/точный original → provisional BLOCKED. Любое настоящее application-view
несовпадение → UNEXPECTED. Missing result/неизвестная ошибка → ERROR.
Неполные обязательные namespace snapshots/неожиданный host mount под model
control dir — ERROR с отдельным evidence_errors, не успешная защита.

Для каждой mode/DAC/context имеется свой P0+namespace-harness контроль. eligible=1
только если этот точный контроль ACHIEVED. Provisional BLOCKED без положительного
контроля публикуется NOT_REPRODUCED + eligible=0 с исходным DENIED/errno/phase.
Так отмечается и intrinsic worker отсутствие CAP_SYS_ADMIN, и исходный DAC отказ,
и неработающий harness. Это не новое защитное действие профиля. state_reproduced
сохраняется отдельно: NOT_REPRODUCED может означать отсутствие положительного
контроля даже при переданном late mount. Наблюдаемый ACHIEVED не скрывается при
неуспешном baseline, но всё равно не становится primary-selection input.

## Выход и восстановление

Только `$SLAB_RESULTS_ROOT/mount-states-v005/<UTC>-<token>` (default отдельный
`/root/article-experiment/20261012-v005/results_v005`). Старый
`/root/systemd-lab-results` запрещён. Отдельные goals.csv (совместимый 7-field
формат), observations.csv (mode/eligible/control), summary.json. Не добавляются
строки в primary goals.csv и не пересчитывается g/Emicro/правило выбора.

Сохраняются source hashes, неизменные profile copies, PARAMETERS, ownership
registry, каждый PID/start_ticks/ns, stdout/stderr/status/launcher rc, все raw
mountinfo этапов, exact HTTP bodies/code/rc, journals и ошибки. Interrupted/error
серия остаётся FAILED_OR_INCOMPLETE с исходными файлами, не перезаписывается.

Cleanup останавливает только собственный token-scoped model unit, размонтирует
только подтверждённый неизменённый host TARGET, затем удаляет только явно
зарегистрированные новые fixture paths/файлы. Неизвестные файлы, изменённые inode,
неподтверждённый или busy mount сохраняются с ошибкой. rmdir не recursive delete;
широкого rm, umount /SITE или очистки исходного сайта нет. Nginx возвращается в
сохранённый P4, проверяются исходные code/profile/config/index хеши. run.log
исключён из streaming manifest; закрытый log/архив хеширует родитель отдельно.

Локальные mock/AST/bash-n проверки не воспроизводят kernel/systemd propagation.
Дополнение с таким harness проверяет только эти состояния на текущем стенде,
не все возможные mount states и не абсолютную гарантию каталога. Семантика bind,
per-mount remount и errno сверена с [Linux mount(2)](https://man7.org/linux/man-pages/man2/mount.2.html),
propagation — с [mount_namespaces(7)](https://man7.org/linux/man-pages/man7/mount_namespaces.7.html).
