#########################################################################
# This approach returns all listening process even if there are no logs #
#########################################################################

function Get-ListeningProcessInfo {


    # This portion get the network conections then matches the Listening connections with their Proces Names
    $NetConnections = Get-NetTCPConnection
    $ListeningProcess = (get-ciminstance win32_process | Where-Object {$NetConnections.owningprocess -eq $_.ProcessID})

    # To properly filter the EventLogs, we need the hex value of the listening process. This section of the code formats the hex version of the Process ID then takes the hex value and grabs the corrisponding event logs.
    $ListeningLogs = @()

    foreach ($process in $ListeningProcess) { 
        $hexProcess = ('0x{0:X}' -f [convert]::ToString($process.ProcessID,16)) 
        $ListeningLogs += Get-WinEvent -FilterHashtable @{LogName="Security"; ID="4688"; 'NewProcessID'= $hexProcess } -ErrorAction SilentlyContinue
    }

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

    # This block of code creates the new Process Information Object.  More properties can be added from the variables used in the script.
    $ProcessInfo = @()

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

    $ProcessInfo

}

Get-ListeningProcessInfo