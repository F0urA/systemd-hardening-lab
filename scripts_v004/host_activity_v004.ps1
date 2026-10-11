# host_activity_v004.ps1 -Out FILE [-IntervalSec 2] -- runs on the Windows host
# during the load series (protocol_review_v004.txt, section 6).
#
# Every IntervalSec seconds one line is appended to FILE:
#   time            local date and time, ISO
#   vm_pct_of_core  processor time of the VirtualBox machine processes,
#                   percent of one logical processor
#   u<i>, f<i>      for every logical processor i: utility, percent, and
#                   performance, percent of the nominal frequency
# The log is used by freq_adjust_v004.py. While the script runs it asks
# Windows not to enter sleep; no power setting is changed, and the request
# ends with the process. Stop it with Ctrl+C or by ending the process.
param(
    [Parameter(Mandatory = $true)][string]$Out,
    [int]$IntervalSec = 2
)
$ErrorActionPreference = 'Stop'
Add-Type -Namespace Slab -Name Power -MemberDefinition '[DllImport("kernel32.dll")] public static extern uint SetThreadExecutionState(uint esFlags);'
[void][Slab.Power]::SetThreadExecutionState([uint32]'0x80000001')   # ES_CONTINUOUS | ES_SYSTEM_REQUIRED

$n = [Environment]::ProcessorCount
$counters = '\Processor Information(*)\% Processor Utility',
            '\Processor Information(*)\% Processor Performance',
            '\Process(VirtualBoxVM*)\% Processor Time'
if (-not (Test-Path $Out)) {
    $header = 'time,vm_pct_of_core'
    foreach ($i in 0..($n - 1)) { $header += ",u$i,f$i" }
    Set-Content -Path $Out -Value $header -Encoding ascii
}
while ($true) {
    try {
        $sample = Get-Counter -Counter $counters -SampleInterval $IntervalSec -MaxSamples 1
    } catch {
        Start-Sleep -Seconds $IntervalSec
        continue
    }
    $u = @{}; $f = @{}; $vm = 0.0
    foreach ($c in $sample.CounterSamples) {
        if ($c.Path -like '*\process(*') { $vm += $c.CookedValue; continue }
        if ($c.InstanceName -notmatch '^0,(\d+)$') { continue }
        $i = [int]$Matches[1]
        if ($c.Path -like '*processor utility') { $u[$i] = $c.CookedValue } else { $f[$i] = $c.CookedValue }
    }
    $line = '{0},{1}' -f (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss'), [int][math]::Round($vm)
    foreach ($i in 0..($n - 1)) {
        $line += ',{0},{1}' -f [int][math]::Round([double]$u[$i]), [int][math]::Round([double]$f[$i])
    }
    Add-Content -Path $Out -Value $line -Encoding ascii
}
