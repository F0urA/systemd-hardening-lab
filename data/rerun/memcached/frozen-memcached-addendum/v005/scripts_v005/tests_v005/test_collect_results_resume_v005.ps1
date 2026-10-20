#requires -Version 7.0
# Pure AST/mocked helpers only: never dot-source or launch the collector/main.
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$taskPath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '../host_v005/collect_results_resume_v005.ps1'))
$taskTokens = $null; $taskErrors = $null
$taskAst = [Management.Automation.Language.Parser]::ParseFile($taskPath, [ref]$taskTokens, [ref]$taskErrors)
$script:TaskChecks = 0
function Assert-Task([bool]$Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
    $script:TaskChecks++
}
function Assert-TaskThrows([scriptblock]$Action, [string]$Pattern) {
    $failed = $false
    try { & $Action } catch { $failed = $true; Assert-Task ($_.Exception.Message -match $Pattern) "Wrong failure: $($_.Exception.Message)" }
    Assert-Task $failed 'Expected rejection did not happen.'
}
Assert-Task ($taskErrors.Count -eq 0) ('PowerShell parser: ' + (@($taskErrors | ForEach-Object Message) -join '; '))
$source = $taskAst.Extent.Text
$commands = @($taskAst.FindAll({param($node) $node -is [Management.Automation.Language.CommandAst]}, $true) |
    ForEach-Object { $_.GetCommandName() })
foreach ($name in @('Start-Process','Stop-Process','Remove-Item','Move-Item','powercfg','powercfg.exe')) {
    Assert-Task ($name -notin $commands) "Forbidden lifecycle/mutation command: $name"
}
foreach ($literal in @('[IO.FileShare]::None', 'ArgumentList.Add', 'StrictHostKeyChecking=yes',
    'BatchMode=yes', 'ServerAliveCountMax=2', 'host-monitor-resume-20261013.stop', '$script:V005SshHost')) {
    Assert-Task ($source.Contains($literal)) "Missing safety guard $literal"
}
Assert-Task (-not $source.Contains('StrictHostKeyChecking=no')) 'Host-key verification was bypassed.'
Assert-Task (-not $source.Contains('UserKnownHostsFile=/dev/null')) 'Known-host inventory was bypassed.'
Assert-Task ($source.Contains('$script:LASTEXITCODE = $taskProcess.ExitCode')) 'Native exit is not captured authoritatively.'
Assert-Task ($source.Contains('$script:LASTEXITCODE = $null')) 'Stale native status is possible.'
Assert-Task ($source.Contains('36 * 3600')) 'Total deadline differs from 36 hours.'
Assert-Task ($source.Contains('Start-Sleep -Seconds ([Math]::Min(60')) 'Polling differs from 60 seconds.'
Assert-Task ($source.Contains('if ($closedConfirmed)')) 'Monitor stop is not gated on closed result evidence.'
Assert-Task ($source.Contains('Test-V005MonitorStop -ClosedReady')) 'No fresh finally stop guard.'
Assert-Task (-not $source.Contains('.Kill(')) 'Collector kills processes.'

# Retrieve literal embedded guest programs, then AST-parse using bundled Python.
# This executes no guest function, opens no guest path and makes no network call.
$assignments = $taskAst.FindAll({param($node) $node -is [Management.Automation.Language.AssignmentStatementAst]}, $true)
foreach ($name in @('V005GuestReadCode','V005GuestProbeTail','V005GuestSealTail','V005GuestFinalGuardTail')) {
    $node = @($assignments | Where-Object { $_.Left.Extent.Text -eq ('$script:' + $name) })
    Assert-Task ($node.Count -eq 1) "Embedded program definition count: $name"
    $literal = $node[0].Right.Find({param($item) $item -is [Management.Automation.Language.StringConstantExpressionAst]}, $true)
    Assert-Task ($null -ne $literal -and $literal.StringConstantType.ToString() -eq 'SingleQuotedHereString') "Nonliteral embedded program: $name"
    Set-Variable -Name $name -Scope Script -Value $literal.Value
}
$python = if ($env:SLAB_PYTHON) { $env:SLAB_PYTHON } else { @(Get-Command python, python3 -CommandType Application -ErrorAction SilentlyContinue)[0].Source }
foreach ($tail in @($script:V005GuestProbeTail,$script:V005GuestSealTail,$script:V005GuestFinalGuardTail)) {
    ($script:V005GuestReadCode + "`n" + $tail) | & $python -B -c 'import ast,sys; ast.parse(sys.stdin.read()); print("embedded Python AST PASS")'
    $taskNativeExit = $LASTEXITCODE
    Assert-Task ($taskNativeExit -eq 0) 'Embedded guest Python syntax failed.'
}
Assert-Task ($script:V005GuestReadCode.Contains("['find', '-P', '.', '-print0']")) 'find would follow links or use a broad root.'
Assert-Task ($script:V005GuestSealTail.Contains("manifest = ROOT / 'SHA256-CLOSED-RESULTS.txt'")) 'Guest mutation target changed.'
Assert-Task ($script:V005GuestSealTail.Contains("if name != './SHA256-CLOSED-RESULTS.txt'")) 'Manifest hashes itself.'
Assert-Task (-not $script:V005GuestReadCode.Contains('mkdir')) 'Guest probe creates directories.'
Assert-Task (-not $script:V005GuestSealTail.Contains('mkdir')) 'Guest seal creates directories.'

# Execute only guest definitions with a synthetic /proc and mocked marker
# reads. Neither real /proc nor any real dataset is accessed.
$mockProcTests = @'
import errno, json, sys
from pathlib import PurePosixPath

program = json.load(sys.stdin)['program']
scope = {}
# Emulate guest POSIX lexical paths on Windows; all filesystem methods below
# are supplied by FakePath, never by a real host/guest Path.
program = program.replace('from pathlib import Path', 'from pathlib import PurePosixPath as Path')
exec(compile(program, '<guest-definitions-on-mocks>', 'exec'), scope)
base = str(scope['BASE'])
primary, post = scope['CONTROLLERS']
roles = scope['controller_roles']
assert roles(['bash', '-c', 'rc=0; bash '+primary+' > results_v005/out 2>&1 || rc=$?'], base) == [
    {'name': primary, 'mode': 'relative+cwd'}]
assert roles(['bash', './'+post], base) == [{'name': post, 'mode': 'relative+cwd'}]
assert roles(['bash', base+'/'+primary], '/tmp') == [{'name': primary, 'mode': 'absolute'}]
assert roles(['bash', primary], '/tmp') == []
assert roles(['bash', 'not-'+primary], base) == []

processes = {101: {'argv': ['bash', '-c', 'rc=0; bash '+primary+' > results_v005/out 2>&1 || rc=$?'],
                   'cwd': base, 'start': 9876, 'state': 'S'}}
class FakePath:
    def __init__(self, text): self.text = str(text)
    def __truediv__(self, name): return FakePath(self.text+'/'+str(name))
    @property
    def name(self): return PurePosixPath(self.text).name
    def iterdir(self):
        assert self.text == '/proc'
        return [FakePath('/proc/'+str(pid)) for pid in sorted(processes)]
    def record(self):
        pid = int(PurePosixPath(self.text).parts[2])
        if pid not in processes: raise FileNotFoundError(errno.ENOENT, 'mock process exited')
        return processes[pid]
    def read_text(self):
        if self.text == '/proc/sys/kernel/random/boot_id': return 'mock-boot-id'
        record = self.record()
        assert self.name == 'stat'
        return '101 (bash) '+record['state']+' '+' '.join(['0']*18+[str(record['start'])])
    def read_bytes(self):
        assert self.name == 'cmdline'
        return ('\0'.join(self.record()['argv'])+'\0').encode()
    def resolve(self, strict=False):
        assert self.name == 'cwd'
        return PurePosixPath(self.record()['cwd'])
scope['Path'] = FakePath
scope['check_root'] = lambda: None
markers = {'corrected-controller.pid':'101', 'post-primary-controller.pid':'202',
           'post-primary-resume-started.txt':'2026-10-13T00:00:00+00:00', 'post-primary-driver-exit.txt':'2'}
scope['read_small'] = lambda path: markers.get(path.name)
state = scope['snapshot']()
assert state['post_exit_code'] == 2 and not state['terminal']
assert state['matching_controllers'][0]['controllers'] == [{'name': primary,'mode':'relative+cwd'}]
assert state['recorded_controllers'][primary]['start_ticks'] == 9876
assert state['recorded_controllers'][primary]['cwd'] == base
assert state['recorded_controllers'][post]['status'] == 'EXITED'
# A live recorded PID with an unconfirmed cwd is not proof of its exit.
processes[101]['cwd'] = '/tmp'
state = scope['snapshot']()
assert not state['terminal'] and state['matching_controllers'] == []
assert state['recorded_controllers'][primary]['status'] == 'ALIVE_UNCONFIRMED'
processes.clear()
state = scope['snapshot']()
assert state['terminal'] and state['post_exit_code'] == 2
print('relative-controller, early-post-error and recorded-PID mock PASS')
'@
@{program=$script:V005GuestReadCode} | ConvertTo-Json -Depth 4 -Compress | & $python -B -c $mockProcTests
$taskNativeExit = $LASTEXITCODE
Assert-Task ($taskNativeExit -eq 0) 'Guest controller detection on pure mocks failed.'

# Compile definitions only, not the main entry point. Native transport is mocked.
$functions = $taskAst.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst]}, $true)
foreach ($name in @('Get-V005RemainingSeconds','Test-V005Snapshot','Test-V005MonitorStop','Invoke-V005Guest','Wait-V005Terminal','Copy-V005GuestPath')) {
    $definition = @($functions | Where-Object Name -eq $name)
    Assert-Task ($definition.Count -eq 1) "Helper definition count: $name"
    Invoke-Expression $definition[0].Extent.Text
}
$token = 'a' * 64
$good = @{schema='v005-queue-snapshot-1';terminal=$true;identity_ready=$true;queue_token=$token;
    scan_complete=$true;matching_controllers=@();post_exit_present=$true;post_exit_code=0;
    recorded_controllers=@{'driver_primary_corrected_v005.sh'=@{status='EXITED';start_ticks=$null};
        'driver_post_primary_v005.sh'=@{status='EXITED';start_ticks=$null}}}
Test-V005Snapshot $good
Assert-Task $true 'Valid terminal snapshot rejected.'
$fresh=$good.Clone(); $fresh.fresh_guard_schema='v005-monitor-stop-guard-1'
$fresh.open_writers=@(); $fresh.writer_scan_errors=@()
Assert-Task (Test-V005MonitorStop -ClosedReady $true -Snapshot $fresh -ExpectedQueueToken $token) 'Closed/fresh same queue stop rejected.'
Assert-Task (-not (Test-V005MonitorStop -ClosedReady $false -Snapshot $fresh -ExpectedQueueToken $token)) 'Terminal exit alone stops monitor before sealing.'
$writer=$fresh.Clone(); $writer.open_writers=@(@{pid=777;path='mock ROOT/run.log'})
Assert-Task (-not (Test-V005MonitorStop -ClosedReady $true -Snapshot $writer -ExpectedQueueToken $token)) 'A reopened writer stops host monitoring.'
Assert-Task (-not (Test-V005MonitorStop -ClosedReady $true -Snapshot $fresh -ExpectedQueueToken ('b'*64))) 'A different queue stops host monitoring.'
$sealClosed=$false
try {
    $seal=@{ready=$false;reason='RESULT_WRITER_NOT_CLOSED';open_writers=@(@{pid=777})}
    if($seal.ready){$sealClosed=$true}
    throw 'synthetic seal failure/deadline while writer remains open'
} catch { Assert-Task ($_.Exception.Message -match 'synthetic seal') 'Wrong seal failure fixture.' }
Assert-Task (-not (Test-V005MonitorStop -ClosedReady $sealClosed -Snapshot $null -ExpectedQueueToken $token)) 'Seal failure after terminal exit would stop monitor.'
Assert-TaskThrows { Test-V005MonitorStop -ClosedReady $true -Snapshot $good -ExpectedQueueToken $token } 'Missing fresh'
foreach ($changes in @(@{matching_controllers=@(@{pid=123})},@{scan_complete=$false},
    @{post_exit_code=$null},@{post_exit_present=$false},@{identity_ready=$false},
    @{terminal='true'},@{post_exit_code=256},@{post_exit_code='0'},@{queue_token='bad'},
    @{recorded_controllers=@{'driver_primary_corrected_v005.sh'=@{status='RUNNING_OWN';start_ticks=123};
        'driver_post_primary_v005.sh'=@{status='EXITED';start_ticks=$null}}})) {
    $bad=$good.Clone(); foreach($key in $changes.Keys){$bad[$key]=$changes[$key]}
    Assert-TaskThrows { Test-V005Snapshot $bad } 'Contradictory|Malformed|Invalid'
}
$script:V005Clock=[pscustomobject]@{Elapsed=[TimeSpan]::FromSeconds(0)}
Assert-Task ((Get-V005RemainingSeconds) -eq 129600) 'Deadline budget is wrong.'
$script:V005Clock=[pscustomobject]@{Elapsed=[TimeSpan]::FromHours(36)}
Assert-TaskThrows { Get-V005RemainingSeconds } '36 hours'
$script:V005Clock=[pscustomobject]@{Elapsed=[TimeSpan]::FromSeconds(0)}

$script:TaskNativeResult = [pscustomobject]@{ExitCode=0;Stdout=($good | ConvertTo-Json);Stderr=''}
$script:TaskNativeArguments=@(); $script:V005Ssh='mock ssh.exe'; $script:V005Scp='mock scp.exe'
function Invoke-V005Native { param($Executable,$Arguments,$InputText='',$TimeoutSeconds=45)
    $script:TaskNativeArguments=@($Arguments); return $script:TaskNativeResult }
$response=Invoke-V005Guest -Program '# synthetic; no execution'
Assert-Task $response.terminal 'Mock native JSON was not parsed.'
Assert-Task ('BatchMode=yes' -in $script:TaskNativeArguments) 'SSH batch option lost.'
Assert-Task ('StrictHostKeyChecking=yes' -in $script:TaskNativeArguments) 'SSH strict host option lost.'
Assert-Task ($script:TaskNativeArguments[-1] -eq 'python3 -') 'Guest program placed into unsafe shell command arguments.'
$script:TaskNativeResult=[pscustomobject]@{ExitCode=255;Stdout='';Stderr='mock connection refused'}
Assert-TaskThrows { Invoke-V005Guest -Program '# no execution' } 'exited 255.*connection refused'
$script:TaskNativeResult=[pscustomobject]@{ExitCode=0;Stdout='';Stderr=''}
function Assert-V005LocalPath { param([string]$Path) return $Path }
$destination='C:\mock results with spaces\raw-vm'
$script:V005SshHost = 'slab-vm'; $script:V005Base = '/root/systemd-hardening-lab'
Copy-V005GuestPath -Remote ($script:V005Base + '/results_v005/.') -Local $destination -Recursive
Assert-Task ($script:TaskNativeArguments[-1] -ceq $destination) 'Windows destination was split or shell-quoted into data.'
Assert-Task ('-r' -in $script:TaskNativeArguments) 'Recursive scp flag missing.'
Assert-Task ($script:TaskNativeArguments[-2] -ceq 'slab-vm:/root/systemd-hardening-lab/results_v005/.') 'Remote scope escaped.'

# Fake one busy poll and terminal success; fake sleep/status/log have no effects.
$script:TaskPolls=0; $script:TaskSleeps=@()
$waiting=$good.Clone(); $waiting.terminal=$false; $waiting.post_exit_code=$null
$waiting.post_exit_present=$false; $waiting.matching_controllers=@(@{pid=123})
$waiting.recorded_controllers=@{'driver_primary_corrected_v005.sh'=@{status='RUNNING_OWN';start_ticks=123};
    'driver_post_primary_v005.sh'=@{status='EXITED';start_ticks=$null}}
$script:TaskSnapshots=@($waiting,$good)
$script:V005State=@{last_snapshot=$null;controller_births=$null;connection_errors=[Collections.Generic.List[object]]::new()}
function Invoke-V005Guest {param($Program,$TimeoutSeconds=45)
    $value=$script:TaskSnapshots[$script:TaskPolls]; $script:TaskPolls++; return $value }
function Save-V005Status {}
function Write-V005Log {param($Message)}
function Start-Sleep {param($Seconds) $script:TaskSleeps+= $Seconds}
$observed=Wait-V005Terminal
Assert-Task ($observed.terminal -and $script:TaskPolls -eq 2) 'Busy/terminal state machine failed.'
Assert-Task ($script:TaskSleeps.Count -eq 1 -and $script:TaskSleeps[0] -eq 60) 'Polling is not exactly once per 60 seconds.'
$changed=$good.Clone(); $changed.queue_token='b'*64
$script:TaskPolls=0; $script:TaskSnapshots=@($waiting,$changed)
Assert-TaskThrows { Wait-V005Terminal } 'identity changed'
$birthChanged=$waiting.Clone()
$birthChanged.recorded_controllers=@{'driver_primary_corrected_v005.sh'=@{status='RUNNING_OWN';start_ticks=124};
    'driver_post_primary_v005.sh'=@{status='EXITED';start_ticks=$null}}
$script:TaskPolls=0; $script:TaskSnapshots=@($waiting,$birthChanged)
Assert-TaskThrows { Wait-V005Terminal } 'identity changed'
Write-Host "PASS: $script:TaskChecks collector AST/mocked checks; no collector launch, VM, network or real data processing."
