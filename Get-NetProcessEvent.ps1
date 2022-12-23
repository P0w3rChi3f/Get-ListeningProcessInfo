Param([string]$Path)

filter Read-WinEvent {
    $WinEvent = [ordered]@{} 
    $XmlData = [xml]$_.ToXml()
    $SystemData = $XmlData.Event.System
    $SystemData | Get-Member -MemberType Properties | Select-Object -ExpandProperty Name |
    ForEach-Object {
        $Field = $_
        if ($Field -eq 'TimeCreated') {
            $WinEvent.$Field = Get-Date -Format 'yyyy-MM-dd hh:mm:ss' $SystemData[$Field].SystemTime
        } elseif ($SystemData[$Field].'#text') {
            $WinEvent.$Field = $SystemData[$Field].'#text'
        } else {
            $SystemData[$Field] | Get-Member -MemberType Properties | Select-Object -ExpandProperty Name |
            ForEach-Object { 
                $WinEvent.$Field = @{}
                $WinEvent.$Field.$_ = $SystemData[$Field].$_
            }
        }
    }
    $XmlData.Event.EventData.Data |
    ForEach-Object {
        if ($_.Name -in "SubjectLogonId","NewProcessId","ProcessId","TargetLogonId") {
            $WinEvent.$($_.Name) = [Convert]::ToInt64($_.'#text',16) # reformats hex chars to decimal
        } else { $WinEvent.$($_.Name) = $_.'#text' }
    }
    return New-Object -TypeName PSObject -Property $WinEvent
}

function Get-LogArchive { Get-WinEvent -Path $Path -FilterXPath $FilterXPath -ErrorAction SilentlyContinue }
function Get-Log { Get-WinEvent -LogName Security -FilterXPath $FilterXPath -ErrorAction SilentlyContinue }
if ($Path) { Set-Alias -Name Get-Event -Value Get-LogArchive } 
else { Set-Alias -Name Get-Event -Value Get-Log }

Get-NetTCPConnection | ForEach-Object {
    $Connection = $_
    $NewProcessId = '0x{0:X}' -f [convert]::ToString($Connection.OwningProcess,16) # reformats decimal chars to hex
    $FilterXPath = "*[System[EventID=4688] and EventData[Data[@Name='NewProcessID']='$NewProcessId']]"
    Get-Event | Read-WinEvent | ForEach-Object {
        $Log = $_
        $Connection | Get-Member -MemberType Properties | Select-Object -ExpandProperty Name |
        ForEach-Object {
            if ($_ -in "LocalAddress","LocalPort","RemoteAddress","RemotePort","State") { 
                $Log | Add-Member -MemberType NoteProperty -Name $_ -Value $Connection.$_
            }
        }
        return $Log
    }
} 
