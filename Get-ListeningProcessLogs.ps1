########################################################
# This approach only returns process if they have logs #
########################################################


function Get-ListeningProcessLogs {
    
    <#
    .SYNOPSIS
    Tool to correlate listening ports with Windows event logs.

    .DESCRIPTION
    Uses NetTCPConnection to get the owiniing processes of network connections.  Take the owning process and usese Win32_Process to get the name of the ProcessID/OwingProcess.  Then Converts the ProcessID to hex and searches the Windows Event Viewer for EventID 4688 and ProcessID. If the record has not been over written it will produce the log information with the network information; this is the default output.  Use the -All if you want output all the listening processes with and without Event logs.

    .PARAMETER ALL
    Use this switch to output all listening process, even if it doesn't have a corresponding event log.

    #>

    [CmdletBinding()]
    param (
        [switch]$All = $false
    )

    Write-Verbose "Getting network connections and corresponding process names"
    # This portion get the network conections then matches the Listening connections with their Proces Names
    $NetConnections = Get-NetTCPConnection
    $ListeningProcess = (get-ciminstance win32_process | Where-Object {$NetConnections.owningprocess -eq $_.ProcessID})

    Write-Verbose "Taking the ProcessIDs and getting corresponding event logs"
    # To properly filter the EventLogs, we need the hex value of the listening process. This section of the code formats the hex version of the Process ID then takes the hex value and grabs the corresponding event logs.
    $ListeningLogs = @()

    if ($PSVersionTable.PSVersion.Major -gt 5) {
        foreach ($process in $ListeningProcess) { 
            $hexProcess = ('0x{0:X}' -f [convert]::ToString($process.ProcessID,16)) 
            $ListeningLogs += Get-WinEvent -FilterHashtable @{LogName="Security"; ID="4688"; 'NewProcessID'= $hexProcess } -ErrorAction SilentlyContinue
        }
    else {
        foreach ($process in $ListeningProcess) { 
            $hexProcess = ('0x{0:X}' -f [convert]::ToString($process.ProcessID,16))
            $ListeningLogs += Get-WinEvent -LogName Security -FilterXPath "*[System[EventID=4688] and EventData[Data[@Name='NewProcessID']='$hexProcess']]"
        }
    }

    Write-Verbose "Converting the xml logs to an object"
    # This sections takes the texted based logs message field and converts them to an object
    $MessageArr = @()

    ForEach ($log in $ListeningLogs) {
        $log | ForEach-Object {
            $logProperties = $log | Select-Object -ExpandProperty Properties
            $MessageObj = [PSCustomObject]@{
                TimeCreated = $log.TimeCreated
                TaskDisplayName = $log.TaskDisplayName
                RecordId = $log.RecordId
                ProviderName = $log.ProviderName
                MachineName = $log.MachineName
                LogName = $log.LogName
                LevelDisplayName = $log.LevelDisplayName
                KeywordsDisplayNames = $log.KeywordsDisplayNames
                Id = $log.Id
                ContainerLog = $log.ContainerLog
                UserSid = $logProperties[0].value.value
                UserName = $logProperties[1].value
                DomainName = $logProperties[2].value
                LogonIDHex = ('0x{0:X}' -f [convert]::ToString($logProperties[3].value,16))
                LogonIDDEC = $logProperties[3].value
                NewProcessIdHex = ('0x{0:X}' -f [convert]::ToString($logProperties[4].value,16))
                NewProcessIdDEC = $logProperties[4].value
                NewProcessName = $logProperties[5].value
                TokenElevationType = $logProperties[6].value
                ProcessIDHex = ('0x{0:X}' -f [convert]::ToString($logProperties[7].value,16))
                ProcessIDDec = $logProperties[7].value
                CommandLine = $logProperties[8].value

            }
            $MessageArr += $MessageObj
        }  
    }

    Write-Verbose "Creating a new process object with event log and network information"
    # This block of code creates the new Process Information Object.  More properties can be added from the variables used in the script.
    $ProcessInfo = @()

    if ($all -eq $false){
        foreach ($Message in $MessageArr){$info = [PSCustomObject]@{
            LocalAddress = ($NetConnections | Where-Object {$Message.NewProcessIdDEC -eq $_.Owningprocess}).LocalAddress
            LocalPort = ($NetConnections | Where-Object {$Message.NewProcessIdDEC -eq $_.Owningprocess}).LocalPort
            RemoteAddress = ($NetConnections | Where-Object {$Message.NewProcessIdDEC -eq $_.Owningprocess}).RemoteAddress
            RemotePort = ($NetConnections | Where-Object {$Message.NewProcessIdDEC -eq $_.Owningprocess}).RemotePort
            State = ($NetConnections | Where-Object {$Message.NewProcessIdDEC -eq $_.Owningprocess}).State
            ProcessIDDec = $Message.NewProcessIdDEC
            ProcessIDHex = $Message.NewProcessIdHex
            ProcessName = $Message.NewProcessName
            ProcessPath = ($ListeningProcess | Where-Object {$_.ProcessID -eq $Message.NewProcessIDDec}).path
            ProcessCMD = ($ListeningProcess | Where-Object {$_.ProcessID -eq $Message.NewProcessIDDec}).CommandLine
            LogTimeCreated = $Message.TimeCreated
            LogRecordId = $Message.RecordId
            LogProviderName = $Message.ProviderName
            LogName = $Message.LogName
            LogId = $Message.Id
            UserSid = $Message.UserSid
            UserName = $Message.UserName
            MachineName = $Message.MachineName
            DomainName = $Message.DomainName
            TokenElevationType = $Message.TokenElevationType
            
            }
            $ProcessInfo += $info
        }
    }
    else {
        foreach ($connection in $NetConnections){$info = [PSCustomObject]@{
            LocalAddress = $connection.LocalAddress
            LocalPort = $connection.LocalPort
            RemoteAddress = $connection.RemoteAddress
            RemotePort = $connection.RemotePort
            State = $connection.State
            ProcessIDDec = $connection.OwningProcess
            ProcessIDHex = ($MessageArr | Where-Object {$connection.OwningProcess -eq $_.processIDDec}).ProcessIDHex
            ProcessName = ($ListeningProcess | Where-Object {$connection.OwningProcess -eq $_.ProcessId}).ProcessName
            ProcessPath = ($ListeningProcess | Where-Object {$connection.OwningProcess -eq $_.ProcessId}).Path
            ProcessCMD = ($ListeningProcess | Where-Object {$connection.OwningProcess -eq $_.ProcessId}).CommandLine
            LogTimeCreated = ($MessageArr | Where-Object {$connection.OwningProcess -eq $_.processIDDec}).TimeCreated
            LogRecordId = ($MessageArr | Where-Object {$connection.OwningProcess -eq $_.processIDDec}).RecordId
            LogProviderName = ($MessageArr | Where-Object {$connection.OwningProcess -eq $_.processIDDec}).ProviderName
            LogName = ($MessageArr | Where-Object {$connection.OwningProcess -eq $_.processIDDec}).LogName
            LogId = ($MessageArr | Where-Object {$connection.OwningProcess -eq $_.processIDDec}).Id
            UserSid = ($MessageArr | Where-Object {$connection.OwningProcess -eq $_.processIDDec}).UserSid
            UserName = ($MessageArr | Where-Object {$connection.OwningProcess -eq $_.processIDDec}).UserName
            MachineName = ($MessageArr | Where-Object {$connection.OwningProcess -eq $_.processIDDec}).MachineName
            DomainName = ($MessageArr | Where-Object {$connection.OwningProcess -eq $_.processIDDec}).DomainName
            TokenElevationType = ($MessageArr | Where-Object {$connection.OwningProcess -eq $_.processIDDec}).TokenElevationType
            
            }
            $ProcessInfo += $info
        }
    }

    $ProcessInfo
    }
}

Get-ListeningProcessLogs
