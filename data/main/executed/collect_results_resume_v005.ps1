#requires -Version 7.0
param([Parameter(Mandatory)][int]$MonitorPid)
# Preparation only: launch explicitly, after review, in a hidden pwsh window.
# Does not start measurements, change services/power policy, or stop processes.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:V005GuestReadCode = @'
import errno, hashlib, json, os, shlex, stat, subprocess
from pathlib import Path

BASE = Path('/root/article-experiment/20261012-v005')
ROOT = BASE / 'results_v005'
DRIVER = ROOT / 'driver'
ANALYSIS = BASE / 'post-analysis'
NAMES = ('analysis-first-look', 'analysis-final',
         'memcached-analysis-first-look', 'memcached-analysis-final')
CONTROLLERS = ('driver_primary_resume_v005.sh', 'driver_post_primary_resume_v005.sh')

def check_root():
    if ROOT.is_symlink() or not ROOT.is_dir() or ROOT.resolve(strict=True) != ROOT:
        raise RuntimeError('Result root is absent, a symlink, or outside its exact canonical path')

def read_small(path):
    if not path.exists() and not path.is_symlink():
        return None
    if path.parent.resolve(strict=True) != DRIVER or path.is_symlink():
        raise RuntimeError('Unsafe queue marker: ' + str(path))
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        meta = os.fstat(stream.fileno())
        if not stat.S_ISREG(meta.st_mode) or meta.st_size > 4096:
            raise RuntimeError('Queue marker is not a small regular file')
        return stream.read().decode('utf-8').strip()

def controller_roles(argv, cwd):
    # Shell wrappers may use `bash -c 'rc=0; bash driver_name.sh ...'`.
    # Match exact tokens, not only an absolute substring or similar filenames.
    tokens = []
    for argument in argv:
        tokens.append(argument)
        try:
            tokens.extend(shlex.split(argument, posix=True))
        except ValueError:
            pass
    return [{'name': name, 'mode': 'absolute' if str(BASE / name) in tokens else 'relative+cwd'}
            for name in CONTROLLERS if str(BASE / name) in tokens or
            cwd == str(BASE) and any(token in tokens for token in (name, './' + name))]

def process_identity(proc):
    def start_info():
        # Field 22, counted after the final `) ` of the potentially spaced comm.
        fields = (proc / 'stat').read_text().rpartition(') ')[2].split()
        return fields[0], int(fields[19])
    state, started = start_info()
    raw = (proc / 'cmdline').read_bytes()
    command_hash = hashlib.sha256(raw).hexdigest()
    if state == 'Z':
        return {'pid': int(proc.name), 'status': 'EXITED', 'start_ticks': started,
                'cwd': None, 'command_sha256': command_hash, 'roles': []}
    cwd = str((proc / 'cwd').resolve(strict=True)) if raw else None
    argv = [value.decode('utf-8', 'replace') for value in raw.split(b'\0') if value]
    roles = controller_roles(argv, cwd)
    if start_info()[1] != started:
        raise RuntimeError('PID identity changed while inspecting /proc/' + proc.name)
    return {'pid': int(proc.name), 'status': 'RUNNING_OWN' if roles else 'ALIVE_UNCONFIRMED',
            'start_ticks': started, 'cwd': cwd, 'command_sha256': command_hash, 'roles': roles}

def controller_scan(known):
    matches, errors, recorded = [], [], {}
    # Inspect both recorded wrappers separately, including their cwd/start.
    # An alive PID with an unconfirmed signature never proves our job exited.
    for name, pid in known.items():
        try:
            entry = process_identity(Path('/proc') / str(pid))
            if name not in [role['name'] for role in entry['roles']] and entry['status'] != 'EXITED':
                entry['status'] = 'ALIVE_UNCONFIRMED'
            recorded[name] = entry
        except OSError as exc:
            if exc.errno in (errno.ENOENT, errno.ESRCH):
                recorded[name] = {'pid': pid, 'status': 'EXITED', 'start_ticks': None,
                                  'cwd': None, 'command_sha256': None, 'roles': []}
            else:
                errors.append({'pid': pid, 'errno': exc.errno})
        except (RuntimeError, ValueError, IndexError) as exc:
            errors.append({'pid': pid, 'error': str(exc)})
    for proc in Path('/proc').iterdir():
        if not proc.name.isdecimal():
            continue
        try:
            entry = process_identity(proc)
            if entry['roles']:
                matches.append({'pid': entry['pid'], 'controllers': entry['roles'],
                    'start_ticks': entry['start_ticks'], 'cwd': entry['cwd'],
                    'command_sha256': entry['command_sha256']})
        except OSError as exc:
            if exc.errno not in (errno.ENOENT, errno.ESRCH):
                errors.append({'pid': int(proc.name), 'errno': exc.errno})
        except (RuntimeError, ValueError, IndexError) as exc:
            errors.append({'pid': int(proc.name), 'error': str(exc)})
    return matches, errors, recorded

def snapshot():
    check_root()
    identifiers = {name: read_small(DRIVER / name) for name in
        ('corrected-controller.pid', 'post-primary-controller.pid', 'post-primary-resume-started.txt')}
    identity_ready = all(identifiers.values()) and all(
        identifiers[name].isdecimal() and int(identifiers[name]) > 0 for name in
        ('corrected-controller.pid', 'post-primary-controller.pid'))
    boot_id = Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    token = hashlib.sha256(json.dumps([identifiers, boot_id], sort_keys=True).encode()).hexdigest() if identity_ready else None
    value = read_small(DRIVER / 'post-primary-driver-exit.txt')
    code = int(value) if value and value.isdecimal() and 0 <= int(value) <= 255 else None
    known = {CONTROLLERS[0]: int(identifiers['corrected-controller.pid']),
             CONTROLLERS[1]: int(identifiers['post-primary-controller.pid'])} if identity_ready else {}
    matches, errors, recorded = controller_scan(known)
    both_exited = len(recorded) == 2 and all(entry['status'] == 'EXITED' for entry in recorded.values())
    return {'schema': 'v005-queue-snapshot-1', 'queue_token': token,
            'identity_ready': bool(identity_ready), 'identifiers': identifiers,
            'post_exit_present': value is not None, 'post_exit_code': code,
            'scan_complete': not errors, 'scan_errors': errors,
            'matching_controllers': matches, 'recorded_controllers': recorded,
            'terminal': bool(identity_ready and code is not None and both_exited and not matches and not errors)}

def regular_tree(path):
    if path.is_symlink() or not path.is_dir() or path.resolve(strict=True) != path:
        raise RuntimeError('Unsafe result tree: ' + str(path))
    # Explicit -P: never follow any guest symlink. Reject links/special files
    # as scp -r could otherwise traverse them outside the approved tree.
    raw = subprocess.check_output(['find', '-P', '.', '-print0'], cwd=path)
    files = []
    for item in raw.split(b'\0'):
        if not item:
            continue
        name = os.fsdecode(item)
        if any(c in name for c in ('\n', '\r', '\\', ':')):
            raise RuntimeError('Name cannot be safely represented by the Windows/hash manifest')
        target = path / name
        meta = target.lstat()
        if stat.S_ISREG(meta.st_mode):
            files.append(name)
        elif not stat.S_ISDIR(meta.st_mode):
            raise RuntimeError('Symlink or special file in result tree: ' + name)
    return sorted(files)

def open_writers():
    writers, errors = [], []
    prefix = str(ROOT) + '/'
    for proc in Path('/proc').iterdir():
        if not proc.name.isdecimal():
            continue
        try:
            fds = list((proc / 'fd').iterdir())
        except OSError as exc:
            if exc.errno not in (errno.ENOENT, errno.ESRCH):
                errors.append({'pid': int(proc.name), 'errno': exc.errno})
            continue
        for fd in fds:
            try:
                target = os.readlink(fd)
                if not target.startswith(prefix):
                    continue
                info = (proc / 'fdinfo' / fd.name).read_text()
                flags = next(int(line.split()[1], 8) for line in info.splitlines() if line.startswith('flags:'))
                if flags & os.O_ACCMODE in (os.O_WRONLY, os.O_RDWR):
                    writers.append({'pid': int(proc.name), 'fd': fd.name, 'path': target})
            except OSError as exc:
                if exc.errno not in (errno.ENOENT, errno.ESRCH):
                    errors.append({'pid': int(proc.name), 'errno': exc.errno})
            except (StopIteration, ValueError):
                errors.append({'pid': int(proc.name), 'error': 'unreadable fd flags'})
    return writers, errors

def derived_inventory():
    entries = []
    for name in NAMES:
        path = ANALYSIS / name
        present = path.exists() or path.is_symlink()
        entry = {'name': name, 'present': present, 'safe': False}
        if present:
            try:
                entry['file_count'] = len(regular_tree(path))
                entry['safe'] = True
            except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
                entry['error'] = str(exc)
        entries.append(entry)
    path = ANALYSIS / 'extension-plan.json'
    present = path.exists() or path.is_symlink()
    plan = {'present': present, 'safe': bool(present and not path.is_symlink()
        and path.is_file() and path.resolve(strict=True) == path)}
    if present and not plan['safe']:
        plan['error'] = 'Extension plan is not an exact regular file'
    return entries, plan
'@

$script:V005GuestProbeTail = @'
try:
    print(json.dumps(snapshot()))
except (OSError, RuntimeError, ValueError) as exc:
    print('QUEUE_PROBE_ERROR: ' + str(exc), file=__import__('sys').stderr)
    raise SystemExit(2)
'@

$script:V005GuestSealTail = @'
try:
    state = snapshot()
    if state['queue_token'] != '__QUEUE_TOKEN__':
        raise RuntimeError('Queue identity changed before sealing')
    if not state['terminal']:
        print(json.dumps({'schema': 'v005-closed-results-1', 'ready': False,
                          'reason': 'CONTROLLER_OR_EXIT_NOT_TERMINAL'}))
        raise SystemExit(0)
    writers, errors = open_writers()
    if writers or errors:
        print(json.dumps({'schema': 'v005-closed-results-1', 'ready': False,
                          'reason': 'RESULT_WRITER_NOT_CLOSED', 'open_writers': writers,
                          'scan_errors': errors}))
        raise SystemExit(0)
    names = [name for name in regular_tree(ROOT) if name != './SHA256-CLOSED-RESULTS.txt']
    if not names:
        raise RuntimeError('Empty result tree; no meaningful closed manifest')
    manifest = ROOT / 'SHA256-CLOSED-RESULTS.txt'
    if manifest.exists() or manifest.is_symlink():
        meta = manifest.lstat()
        if not stat.S_ISREG(meta.st_mode) or meta.st_nlink != 1:
            raise RuntimeError('Existing manifest is a link or special file')
    # The only guest mutation: this exact manifest inside ROOT/results_v005.
    fd = os.open(manifest, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8', newline='\n') as output:
        for name in names:
            source = ROOT / name
            read_fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
            with os.fdopen(read_fd, 'rb') as stream:
                before = os.fstat(stream.fileno())
                if not stat.S_ISREG(before.st_mode):
                    raise RuntimeError('File changed type during sealing')
                value = hashlib.file_digest(stream, 'sha256').hexdigest()
                after = os.fstat(stream.fileno())
                if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != \
                   (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
                    raise RuntimeError('Result changed during hashing: ' + name)
            output.write(value + '  ' + name + '\n')
        output.flush()
        os.fsync(output.fileno())
    after_names = [name for name in regular_tree(ROOT) if name != './SHA256-CLOSED-RESULTS.txt']
    if names != after_names:
        raise RuntimeError('Result inventory changed during sealing')
    final_state = snapshot()
    if not final_state['terminal'] or final_state['queue_token'] != state['queue_token']:
        raise RuntimeError('Controller restarted during sealing; do not call the manifest closed')
    derived, plan = derived_inventory()
    print(json.dumps({'schema': 'v005-closed-results-1', 'ready': True,
        'queue_token': state['queue_token'], 'post_exit_code': state['post_exit_code'],
        'manifest': str(manifest), 'listed_files': len(names),
        'derived': derived, 'extension_plan': plan}))
except (OSError, RuntimeError, ValueError, subprocess.SubprocessError) as exc:
    print('RESULT_SEAL_ERROR: ' + str(exc), file=__import__('sys').stderr)
    raise SystemExit(2)
'@

$script:V005GuestFinalGuardTail = @'
try:
    state = snapshot()
    writers, errors = open_writers() if state['terminal'] else ([], [])
    state['fresh_guard_schema'] = 'v005-monitor-stop-guard-1'
    state['open_writers'] = writers
    state['writer_scan_errors'] = errors
    print(json.dumps(state))
except (OSError, RuntimeError, ValueError) as exc:
    print('MONITOR_STOP_PROBE_ERROR: ' + str(exc), file=__import__('sys').stderr)
    raise SystemExit(2)
'@

function Get-V005RemainingSeconds {
    $remaining = 36 * 3600 - $script:V005Clock.Elapsed.TotalSeconds
    if ($remaining -le 0) { throw 'Collector deadline of 36 hours reached; completion remains unconfirmed.' }
    return $remaining
}

function Assert-V005LocalPath {
    param([Parameter(Mandatory)][string]$Path)
    $full = [IO.Path]::GetFullPath($Path)
    $root = $script:V005LocalRoot.TrimEnd([IO.Path]::DirectorySeparatorChar)
    if ($full -ne $root -and -not $full.StartsWith($root + [IO.Path]::DirectorySeparatorChar, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Local path escaped the task results folder: $full"
    }
    $probe = $full
    while ($probe -and $probe.Length -ge $root.Length) {
        if (Test-Path -LiteralPath $probe) {
            $item = Get-Item -LiteralPath $probe -Force -ErrorAction Stop
            if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Local reparse point is not allowed: $probe" }
        }
        if ($probe -eq $root) { break }
        $probe = [IO.Path]::GetDirectoryName($probe)
    }
    return $full
}

function Write-V005Log {
    param([string]$Message)
    $line = [DateTime]::UtcNow.ToString('o') + ' ' + $Message
    [IO.File]::AppendAllText($script:V005Log, $line + [Environment]::NewLine, $script:V005Encoding)
    Write-Host $line
}

function Save-V005Status {
    $script:V005State.updated_utc = [DateTime]::UtcNow.ToString('o')
    $script:V005State.elapsed_seconds = [Math]::Round($script:V005Clock.Elapsed.TotalSeconds, 3)
    $json = $script:V005State | ConvertTo-Json -Depth 16
    [IO.File]::WriteAllText($script:V005Status + '.tmp', $json, $script:V005Encoding)
    [IO.File]::Move($script:V005Status + '.tmp', $script:V005Status, $true)
}

function Invoke-V005Native {
    param([Parameter(Mandatory)][string]$Executable,
          [Parameter(Mandatory)][string[]]$Arguments,
          [string]$InputText = '', [int]$TimeoutSeconds = 45)
    # ArgumentList, never one string-built Windows command line: spaces and
    # absolute destination paths remain individual native arguments.
    $taskInfo = [Diagnostics.ProcessStartInfo]::new()
    $taskInfo.FileName = $Executable
    $taskInfo.UseShellExecute = $false
    $taskInfo.CreateNoWindow = $true
    $taskInfo.RedirectStandardInput = $true
    $taskInfo.RedirectStandardOutput = $true
    $taskInfo.RedirectStandardError = $true
    $taskInfo.StandardInputEncoding = $script:V005Encoding
    $taskInfo.StandardOutputEncoding = $script:V005Encoding
    $taskInfo.StandardErrorEncoding = $script:V005Encoding
    foreach ($argument in $Arguments) { $taskInfo.ArgumentList.Add($argument) }
    $taskProcess = [Diagnostics.Process]::new()
    $taskProcess.StartInfo = $taskInfo
    $script:LASTEXITCODE = $null  # No stale native status on start/timeout errors.
    try {
        $budget = [Math]::Min($TimeoutSeconds, (Get-V005RemainingSeconds))
        if (-not $taskProcess.Start()) { throw 'Native process could not start.' }
        $taskOut = $taskProcess.StandardOutput.ReadToEndAsync()
        $taskErr = $taskProcess.StandardError.ReadToEndAsync()
        if ($InputText) { $taskProcess.StandardInput.Write($InputText) }
        $taskProcess.StandardInput.Close()
        if (-not $taskProcess.WaitForExit([int][Math]::Max(1, $budget * 1000))) {
            $script:V005State.unfinished_native_processes.Add([ordered]@{
                pid = $taskProcess.Id; executable = [IO.Path]::GetFileName($Executable)
                reason = 'native timeout; process was not killed'
            })
            throw "Native command exceeded ${budget}s (PID $($taskProcess.Id)); preserved, not killed."
        }
        # Process.ExitCode is authoritative; mirror only a known completed
        # status into LASTEXITCODE rather than reading a stale automatic value.
        $script:LASTEXITCODE = $taskProcess.ExitCode
        $reads = [Threading.Tasks.Task]::WhenAll([Threading.Tasks.Task[]]@($taskOut, $taskErr))
        if (-not $reads.Wait([int][Math]::Min(2000, (Get-V005RemainingSeconds) * 1000))) {
            throw 'Native output pipes did not close; collection is incomplete.'
        }
        return [pscustomobject]@{ ExitCode = $script:LASTEXITCODE
            Stdout = $taskOut.GetAwaiter().GetResult(); Stderr = $taskErr.GetAwaiter().GetResult() }
    } finally {
        # Dispose owned pipes/handles only. Never Kill/Stop-Process a controller,
        # monitor, measurement, or even a timed-out transport process.
        $taskProcess.Dispose()
    }
}

function Invoke-V005Guest {
    param([Parameter(Mandatory)][string]$Program, [int]$TimeoutSeconds = 45)
    $native = Invoke-V005Native -Executable $script:V005Ssh -Arguments @(
        '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes', '-o', 'ConnectionAttempts=1',
        '-o', 'ConnectTimeout=20', '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=2',
        'alt-article-root', 'python3 -') -InputText ($Program + "`n") -TimeoutSeconds $TimeoutSeconds
    if ($native.ExitCode -ne 0) {
        throw "SSH alt-article-root exited $($native.ExitCode): $($native.Stderr.Trim())"
    }
    return $native.Stdout | ConvertFrom-Json -AsHashtable -ErrorAction Stop
}

function Test-V005Snapshot {
    param([Parameter(Mandatory)]$Snapshot)
    if ($Snapshot -isnot [Collections.IDictionary]) {
        throw 'Malformed guest queue snapshot; no completion can be inferred.'
    }
    foreach ($key in @('schema', 'terminal', 'identity_ready', 'queue_token', 'scan_complete',
        'matching_controllers', 'recorded_controllers', 'post_exit_present', 'post_exit_code')) {
        if (-not $Snapshot.Contains($key)) { throw "Malformed guest queue snapshot: missing $key." }
    }
    if ($Snapshot.schema -ne 'v005-queue-snapshot-1' -or $Snapshot.terminal -isnot [bool] -or
        $Snapshot.identity_ready -isnot [bool] -or $Snapshot.scan_complete -isnot [bool] -or
        $Snapshot.post_exit_present -isnot [bool]) { throw 'Malformed guest queue snapshot types.' }
    if ($null -ne $Snapshot.post_exit_code -and ($Snapshot.post_exit_code -isnot [int] -and
        $Snapshot.post_exit_code -isnot [long] -or $Snapshot.post_exit_code -lt 0 -or $Snapshot.post_exit_code -gt 255)) {
        throw 'Malformed guest exit code.'
    }
    if ($Snapshot.identity_ready -and $Snapshot.queue_token -notmatch '^[0-9a-f]{64}$') { throw 'Invalid guest queue identity.' }
    $bothExited = $Snapshot.recorded_controllers.Count -eq 2 -and
        @($Snapshot.recorded_controllers.Values | Where-Object { $_.status -ne 'EXITED' }).Count -eq 0
    if ($Snapshot.terminal -and (-not $Snapshot.identity_ready -or -not $Snapshot.scan_complete -or
        -not $Snapshot.post_exit_present -or -not $bothExited -or $null -eq $Snapshot.post_exit_code -or @($Snapshot.matching_controllers).Count -ne 0)) {
        throw 'Contradictory terminal guest snapshot.'
    }
}

function Wait-V005Terminal {
    $queueToken = $null
    $expectedBirths = @{}
    while ($true) {
        [void](Get-V005RemainingSeconds)
        try {
            $snapshot = Invoke-V005Guest -Program ($script:V005GuestReadCode + "`n" + $script:V005GuestProbeTail)
            Test-V005Snapshot $snapshot
            if ($snapshot.identity_ready) {
                if ($queueToken -and $queueToken -ne $snapshot.queue_token) { throw 'QUEUE_IDENTITY_CHANGED' }
                $queueToken = $snapshot.queue_token
            }
            foreach ($name in $snapshot.recorded_controllers.Keys) {
                $identity = $snapshot.recorded_controllers[$name]
                if ($identity.status -eq 'RUNNING_OWN') {
                    if ($expectedBirths.Contains($name) -and $expectedBirths[$name] -ne $identity.start_ticks) {
                        throw 'QUEUE_IDENTITY_CHANGED'
                    }
                    $expectedBirths[$name] = $identity.start_ticks
                }
            }
            $script:V005State.controller_births = $expectedBirths
            $script:V005State.last_snapshot = $snapshot
            Save-V005Status
            if ($snapshot.terminal) { return $snapshot }
            Write-V005Log "Waiting for existing queue: exit=$($snapshot.post_exit_code); controllers=$(@($snapshot.matching_controllers).Count)."
        } catch {
            if ($_.Exception.Message -eq 'QUEUE_IDENTITY_CHANGED') { throw 'Queue identity changed: collector refuses a different queue.' }
            $message = $_.Exception.Message
            $script:V005State.connection_errors.Add([ordered]@{ utc = [DateTime]::UtcNow.ToString('o'); error = $message })
            Write-V005Log "Probe unavailable; no completion assumed. $message"
            Save-V005Status
        }
        Start-Sleep -Seconds ([Math]::Min(60, (Get-V005RemainingSeconds)))
    }
}

function Test-V005MonitorStop {
    param([bool]$ClosedReady, $Snapshot, [string]$ExpectedQueueToken)
    if (-not $ClosedReady) { return $false }
    Test-V005Snapshot $Snapshot
    if (-not $Snapshot.Contains('fresh_guard_schema') -or
        $Snapshot.fresh_guard_schema -ne 'v005-monitor-stop-guard-1' -or
        -not $Snapshot.Contains('open_writers') -or -not $Snapshot.Contains('writer_scan_errors')) {
        throw 'Missing fresh writer/controller guard; host monitor must continue.'
    }
    return $Snapshot.terminal -and $Snapshot.queue_token -ceq $ExpectedQueueToken -and
        @($Snapshot.open_writers).Count -eq 0 -and @($Snapshot.writer_scan_errors).Count -eq 0
}

function Copy-V005GuestPath {
    param([Parameter(Mandatory)][string]$Remote, [Parameter(Mandatory)][string]$Local, [switch]$Recursive)
    $localPath = Assert-V005LocalPath $Local
    $args = [Collections.Generic.List[string]]::new()
    foreach ($value in @('-B', '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
        '-o', 'ConnectionAttempts=1', '-o', 'ConnectTimeout=20',
        '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=2')) { $args.Add($value) }
    if ($Recursive) { $args.Add('-r') }
    $args.Add('alt-article-root:' + $Remote)
    $args.Add($localPath)
    $native = Invoke-V005Native -Executable $script:V005Scp -Arguments $args.ToArray() -TimeoutSeconds 3600
    if ($native.ExitCode -ne 0) { throw "SCP exited $($native.ExitCode): $($native.Stderr.Trim())" }
}

function Invoke-V005Collection {
    $script:V005LocalRoot = [IO.Path]::GetFullPath($PSScriptRoot)
    $script:V005Clock = [Diagnostics.Stopwatch]::StartNew()
    $script:V005Encoding = [Text.UTF8Encoding]::new($false)
    $lockPath = Assert-V005LocalPath (Join-Path $script:V005LocalRoot 'collect-results-v005.lock')
    $taskLock = $null
    try {
        $taskLock = [IO.FileStream]::new($lockPath, [IO.FileMode]::OpenOrCreate,
            [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    } catch {
        Write-Error "Another collector owns the scoped lock, or results is not writable: $($_.Exception.Message)" -ErrorAction Continue
        return 2
    }
    $runId = [DateTime]::UtcNow.ToString('yyyyMMddTHHmmssZ') + '-' + $PID + '-' + [Guid]::NewGuid().ToString('N').Substring(0,8)
    $script:V005Log = Assert-V005LocalPath (Join-Path $script:V005LocalRoot "collector-$runId.log")
    $script:V005Status = Assert-V005LocalPath (Join-Path $script:V005LocalRoot "collector-$runId.status.json")
    $script:V005State = [ordered]@{
        schema = 'v005-windows-collector-1'; run_id = $runId; phase = 'WAITING_FOR_EXISTING_QUEUE'
        updated_utc = ''; elapsed_seconds = 0; incomplete = $true; collection_complete = $false
        measurement_success_not_asserted = $true; monitor_pid = $MonitorPid; monitor_stop_requested = $false
        last_snapshot = $null; closed_guest = $null; verification = $null; controller_births = $null
        final_monitor_guard = $null
        copies = [Collections.Generic.List[object]]::new()
        connection_errors = [Collections.Generic.List[object]]::new()
        unfinished_native_processes = [Collections.Generic.List[object]]::new()
        errors = [Collections.Generic.List[string]]::new()
    }
    $closedConfirmed = $false
    $exitCode = 2
    try {
        $raw = Assert-V005LocalPath (Join-Path $script:V005LocalRoot 'raw-vm')
        if (-not (Test-Path -LiteralPath $raw -PathType Container)) { throw 'Existing results/raw-vm directory is required; collector does not replace it.' }
        if (@(Get-ChildItem -LiteralPath $raw -Recurse -Force -Attributes ReparsePoint -ErrorAction Stop).Count) {
            throw 'Local raw-vm contains a reparse point; refuse recursive download through it.'
        }
        $script:V005Ssh = (Get-Command ssh.exe -CommandType Application -ErrorAction Stop).Source
        $script:V005Scp = (Get-Command scp.exe -CommandType Application -ErrorAction Stop).Source
        $python = '<OPERATOR_RUNTIME>\python\python.exe'
        $verifier = Assert-V005LocalPath (Join-Path $script:V005LocalRoot 'verify_raw_v005.py')
        if (-not (Test-Path -LiteralPath $python -PathType Leaf) -or -not (Test-Path -LiteralPath $verifier -PathType Leaf)) {
            throw 'Bundled Python or the existing raw verifier is missing.'
        }
        Save-V005Status
        Write-V005Log 'Collector started: existing queue only; 60-second polling, 36-hour total deadline.'
        $terminal = Wait-V005Terminal
        $script:V005State.phase = 'WAITING_FOR_CLOSED_RESULT_FILES'
        Save-V005Status
        while ($true) {
            $program = $script:V005GuestReadCode + "`n" + $script:V005GuestSealTail.Replace('__QUEUE_TOKEN__', $terminal.queue_token)
            $closed = Invoke-V005Guest -Program $program -TimeoutSeconds 1800
            if ($closed.schema -ne 'v005-closed-results-1') { throw 'Malformed closed-result inventory.' }
            if ($closed.ready) {
                if ($closed.queue_token -cne $terminal.queue_token) { throw 'Closed result belongs to a changed queue.' }
                $closedConfirmed = $true
                break
            }
            Write-V005Log "Terminal queue, but result files not yet closed: $($closed.reason)."
            $script:V005State.closed_guest = $closed
            Save-V005Status
            Start-Sleep -Seconds ([Math]::Min(60, (Get-V005RemainingSeconds)))
        }
        $script:V005State.closed_guest = $closed
        $script:V005State.phase = 'DOWNLOADING'
        Save-V005Status
        Copy-V005GuestPath -Remote '/root/article-experiment/20261012-v005/results_v005/.' -Local $raw -Recursive
        $script:V005State.copies.Add([ordered]@{ source = 'results_v005'; status = 'DOWNLOADED' })
        foreach ($entry in $closed.derived) {
            if (-not $entry.present) {
                $script:V005State.copies.Add([ordered]@{ source = $entry.name; status = 'NOT_PRODUCED' })
                continue
            }
            try {
                if (-not $entry.safe) { throw "Unsafe derived tree $($entry.name): $($entry.error)" }
                $destination = Assert-V005LocalPath (Join-Path $script:V005LocalRoot $entry.name)
                if ((Test-Path -LiteralPath $destination) -and
                    @(Get-ChildItem -LiteralPath $destination -Recurse -Force -Attributes ReparsePoint -ErrorAction Stop).Count) {
                    throw "Local derived tree $($entry.name) has a reparse point."
                }
                Copy-V005GuestPath -Remote ('/root/article-experiment/20261012-v005/post-analysis/' + $entry.name) -Local $script:V005LocalRoot -Recursive
                $script:V005State.copies.Add([ordered]@{ source = $entry.name; status = 'DOWNLOADED' })
            } catch {
                $script:V005State.errors.Add($_.Exception.Message)
                $script:V005State.copies.Add([ordered]@{ source = $entry.name; status = 'INCOMPLETE' })
                Write-V005Log $_.Exception.Message
            }
            Save-V005Status
        }
        if ($closed.extension_plan.present) {
            try {
                if (-not $closed.extension_plan.safe) { throw 'Unsafe guest extension-plan.json; not followed.' }
                $destination = Assert-V005LocalPath (Join-Path $script:V005LocalRoot 'extension-plan.json')
                Copy-V005GuestPath -Remote '/root/article-experiment/20261012-v005/post-analysis/extension-plan.json' -Local $destination
                $script:V005State.copies.Add([ordered]@{ source = 'extension-plan.json'; status = 'DOWNLOADED' })
            } catch { $script:V005State.errors.Add($_.Exception.Message); Write-V005Log $_.Exception.Message }
        } else { $script:V005State.copies.Add([ordered]@{ source = 'extension-plan.json'; status = 'NOT_PRODUCED' }) }
        $script:V005State.phase = 'VERIFYING_DOWNLOADED_RAW'
        Save-V005Status
        $verificationFile = Assert-V005LocalPath (Join-Path $script:V005LocalRoot "collector-$runId.raw-verification.json")
        $manifest = Assert-V005LocalPath (Join-Path $raw 'SHA256-CLOSED-RESULTS.txt')
        $native = Invoke-V005Native -Executable $python -Arguments @('-B', $verifier, $raw, $manifest, '--out', $verificationFile) -TimeoutSeconds 3600
        if (-not (Test-Path -LiteralPath $verificationFile -PathType Leaf)) {
            throw "Raw verifier did not save its report (exit=$($native.ExitCode)): $($native.Stderr.Trim())"
        }
        $verification = Get-Content -LiteralPath $verificationFile -Raw -ErrorAction Stop | ConvertFrom-Json -AsHashtable -ErrorAction Stop
        $script:V005State.verification = $verification
        if ($native.ExitCode -ne 0 -or -not $verification.verified) { $script:V005State.errors.Add('Raw SHA256 verification failed; all downloaded files preserved.') }
        if (@($verification.unlisted_local_files).Count) { $script:V005State.errors.Add('Unlisted local raw files remain; preserved, but this is not an exact clean mirror.') }
        $script:V005State.collection_complete = $script:V005State.errors.Count -eq 0
        if ($terminal.post_exit_code -ne 0) { $script:V005State.errors.Add("Queue ended with terminal exit $($terminal.post_exit_code); raw failed results preserved.") }
        $script:V005State.incomplete = $script:V005State.errors.Count -gt 0
        $script:V005State.phase = if ($script:V005State.incomplete) { 'COLLECTED_WITH_LIMITATIONS' } else { 'COLLECTED_REQUIRES_SCIENTIFIC_REVIEW' }
        $exitCode = if ($script:V005State.incomplete) { 2 } else { 0 }
        Write-V005Log "Collection ended: phase=$($script:V005State.phase); raw_verified=$($verification.verified); files=$($verification.listed_files)."
    } catch {
        $script:V005State.incomplete = $true
        $script:V005State.phase = 'INCOMPLETE'
        $script:V005State.errors.Add($_.Exception.Message)
        Write-V005Log "Collection incomplete; existing/downloaded raw retained. $($_.Exception.Message)"
    } finally {
        try {
            if ($closedConfirmed) {
                $fresh = Invoke-V005Guest -Program ($script:V005GuestReadCode + "`n" + $script:V005GuestFinalGuardTail)
                $script:V005State.final_monitor_guard = $fresh
                if (-not (Test-V005MonitorStop -ClosedReady $closedConfirmed -Snapshot $fresh -ExpectedQueueToken $terminal.queue_token)) {
                    throw 'Fresh monitor guard unconfirmed: controller/writer active or queue changed; monitor stop withheld.'
                }
                $stop = Assert-V005LocalPath (Join-Path $script:V005LocalRoot 'host-monitor-resume-20261013.stop')
                [IO.File]::WriteAllText($stop, [DateTime]::UtcNow.ToString('o') + " terminal resumed v005 queue; monitor PID $MonitorPid`n", $script:V005Encoding)
                $script:V005State.monitor_stop_requested = $true
                Write-V005Log 'Scoped host-monitor-resume-20261013.stop written; no process killed and no permanent power settings changed.'
            } else { Write-V005Log 'Closed result files unconfirmed (including seal failure/deadline); monitor stop marker was not created.' }
            Save-V005Status
        } catch {
            $script:V005State.incomplete = $true
            $script:V005State.errors.Add($_.Exception.Message)
            $script:V005State.phase = 'INCOMPLETE_MONITOR_STOP_UNCONFIRMED'
            Write-Error "Host monitor kept running or final status could not be saved: $($_.Exception.Message)" -ErrorAction Continue
            try { Save-V005Status } catch { Write-Error $_.Exception.Message -ErrorAction Continue }
            $exitCode = 2
        } finally { $taskLock.Dispose() }
    }
    return $exitCode
}

exit (Invoke-V005Collection)
