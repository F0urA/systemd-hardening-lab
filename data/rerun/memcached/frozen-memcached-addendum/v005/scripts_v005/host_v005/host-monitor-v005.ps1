param(
    [Parameter(Mandatory=$true)][string]$Out,
    [Parameter(Mandatory=$true)][string]$StopFile,
    [int]$IntervalSec=2
)
$ErrorActionPreference='Stop'
Add-Type -Namespace V005 -Name KeepAwake -MemberDefinition '[DllImport("kernel32.dll")] public static extern uint SetThreadExecutionState(uint flags);'
[void][V005.KeepAwake]::SetThreadExecutionState([uint32]'0x80000001')
$taskWriter=[IO.StreamWriter]::new($Out,$false,[Text.UTF8Encoding]::new($false))
$taskErrors=[IO.StreamWriter]::new($Out+'.errors.log',$true,[Text.UTF8Encoding]::new($false))
$taskCpuCount=[Environment]::ProcessorCount
$taskHeader='time,vm_pct_of_core'
for($i=0;$i -lt $taskCpuCount;$i++){$taskHeader+=",u$i,f$i"}
$taskWriter.WriteLine($taskHeader)
$taskWriter.Flush()
$taskPreviousTime=[DateTime]::UtcNow
$taskPreviousCpu=@{}
try{
    while(-not (Test-Path -LiteralPath $StopFile)){
        $taskNow=[DateTime]::UtcNow
        $taskElapsed=($taskNow-$taskPreviousTime).TotalSeconds
        $taskVmPct=0.0
        foreach($taskProcess in @(Get-Process -Name VirtualBoxVM,VBoxHeadless -ErrorAction SilentlyContinue)){
            $taskCpu=$taskProcess.TotalProcessorTime.TotalSeconds
            if($taskPreviousCpu.ContainsKey($taskProcess.Id) -and $taskElapsed -gt 0){
                $taskVmPct+=100.0*($taskCpu-$taskPreviousCpu[$taskProcess.Id])/$taskElapsed
            }
            $taskPreviousCpu[$taskProcess.Id]=$taskCpu
        }
        $taskPreviousTime=$taskNow
        $taskMetrics=@{}
        try{
            foreach($taskMetric in Get-CimInstance Win32_PerfFormattedData_Counters_ProcessorInformation){
                if($taskMetric.Name -match '^0,(\d+)$'){$taskMetrics[[int]$Matches[1]]=$taskMetric}
            }
        }catch{
            $taskErrors.WriteLine("$($taskNow.ToString('o')) $($_.Exception.Message)")
            $taskErrors.Flush()
        }
        $taskLine=$taskNow.ToString('yyyy-MM-ddTHH:mm:ssZ')+','+$taskVmPct.ToString('F3',[Globalization.CultureInfo]::InvariantCulture)
        for($i=0;$i -lt $taskCpuCount;$i++){
            if($taskMetrics.ContainsKey($i)){
                $taskMetric=$taskMetrics[$i]
                $taskLine+=",$($taskMetric.PercentProcessorUtility),$($taskMetric.PercentProcessorPerformance)"
            }else{$taskLine+=',,'}
        }
        $taskWriter.WriteLine($taskLine)
        $taskWriter.Flush()
        Start-Sleep -Seconds $IntervalSec
    }
}finally{
    [void][V005.KeepAwake]::SetThreadExecutionState([uint32]'0x80000000')
    $taskWriter.Dispose()
    $taskErrors.Dispose()
}
