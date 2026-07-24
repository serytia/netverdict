<#
.SYNOPSIS
Capture assistee netverdict (Windows) : trafic reseau + etat hote, en un coup.

.DESCRIPTION
Lance une capture pktmon (natif Windows 10+/Server 2019+, rien a installer)
et prend un snapshot de l'etat de la machine AU MILIEU de la capture :
connexions TCP avec process proprietaire, CPU, memoire, disque.
Le pcap dit ce qui passe sur le fil ; le snapshot dit QUI tenait la socket
et dans quel etat etait la machine — c'est le croisement des deux qui permet
de trancher APP vs OS.

Par defaut la capture est EN-TETES SEULS (128 octets/paquet) : suffisant pour
l'analyse netverdict, fichiers legers, et aucun payload (donc aucun secret)
dans le bundle. -FullPackets pour capturer les paquets entiers.

.EXAMPLE
.\capture.ps1 -DurationSec 60 -TargetIP 10.0.0.5
netverdict analyze <bundle>\capture.pcapng --snapshot <bundle>\snapshot.json
#>
[CmdletBinding()]
param(
    [int]$DurationSec = 60,
    [string]$OutDir = "",
    [string]$TargetIP = "",
    [int]$TargetPort = 0,
    [switch]$FullPackets
)

$ErrorActionPreference = "Stop"

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
           ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "pktmon exige une console Administrateur. Relancer en admin."
    exit 2
}

if (-not $OutDir) {
    $OutDir = Join-Path (Get-Location) ("netverdict-capture-" + (Get-Date -Format "yyyyMMdd-HHmmss"))
}
New-Item -ItemType Directory -Force $OutDir | Out-Null
$etl  = Join-Path $OutDir "capture.etl"
$pcap = Join-Path $OutDir "capture.pcapng"
$snap = Join-Path $OutDir "snapshot.json"

# --- Filtres pktmon (reset puis cible eventuelle) ---------------------------
pktmon filter remove | Out-Null
if ($TargetIP)  { pktmon filter add -i $TargetIP  | Out-Null }
if ($TargetPort -gt 0) { pktmon filter add -p $TargetPort | Out-Null }

$pktSize = if ($FullPackets) { 0 } else { 128 }
Write-Host "Capture pktmon ${DurationSec}s (pkt-size=$pktSize) -> $etl"
# --comp nics : capturer au niveau des cartes reseau UNIQUEMENT. Par defaut
# pktmon capture a CHAQUE couche NDIS -> le meme paquet apparait plusieurs
# fois et fabrique de faux echantillons RTT (~0 ms) dans l'analyse
# (constate sur capture reelle). Limite connue et assumee : le trafic
# loopback pur (127.0.0.1) est invisible a pktmon de toute facon — le TCP
# Loopback Fast Path de Windows court-circuite la pile NDIS.
pktmon start --capture --comp nics --pkt-size $pktSize --file-name $etl | Out-Null

# --- Snapshot hote au milieu de la fenetre de capture -----------------------
Start-Sleep -Seconds ([math]::Max(1, [int]($DurationSec / 2)))
Write-Host "Snapshot etat hote..."

# Connexions TCP -> process. CIM plutot que Get-Counter : les noms de
# compteurs Get-Counter sont LOCALISES (piege classique des Windows FR).
$procNames = @{}
Get-Process | ForEach-Object { $procNames[$_.Id] = $_.ProcessName }
$conns = Get-NetTCPConnection -ErrorAction SilentlyContinue | ForEach-Object {
    [pscustomobject]@{
        local_ip    = $_.LocalAddress
        local_port  = [int]$_.LocalPort
        remote_ip   = $_.RemoteAddress
        remote_port = [int]$_.RemotePort
        state       = "$($_.State)"
        pid         = [int]$_.OwningProcess
        process     = $procNames[[int]$_.OwningProcess]
    }
}

$cpu = (Get-CimInstance Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
$os  = Get-CimInstance Win32_OperatingSystem
$memFreeMb = [math]::Round($os.FreePhysicalMemory / 1024, 0)
$disk = Get-CimInstance Win32_PerfFormattedData_PerfDisk_PhysicalDisk |
        Where-Object Name -eq "_Total" | Select-Object -First 1
$topCpu = Get-CimInstance Win32_PerfFormattedData_PerfProc_Process |
          Where-Object { $_.Name -notin @("Idle", "_Total") } |
          Sort-Object PercentProcessorTime -Descending |
          Select-Object -First 10 | ForEach-Object {
              [pscustomobject]@{
                  pid     = [int]$_.IDProcess
                  process = $_.Name
                  cpu_pct = [double]$_.PercentProcessorTime
              }
          }

$snapshot = [pscustomobject]@{
    host          = $env:COMPUTERNAME
    os            = "windows"
    taken_at      = (Get-Date).ToString("o")
    cpu_pct       = [double]$cpu
    mem_free_mb   = [double]$memFreeMb
    disk_busy_pct = if ($disk) { [double]$disk.PercentDiskTime } else { $null }
    connections   = @($conns)
    top_cpu       = @($topCpu)
}
$snapshot | ConvertTo-Json -Depth 4 | Out-File -Encoding utf8 $snap

# --- Fin de capture et conversion -------------------------------------------
Start-Sleep -Seconds ([math]::Max(1, $DurationSec - [int]($DurationSec / 2)))
pktmon stop | Out-Null
Write-Host "Conversion etl -> pcapng..."
pktmon etl2pcap $etl -o $pcap | Out-Null
pktmon filter remove | Out-Null
Remove-Item $etl -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "Bundle pret :"
Write-Host "  $pcap"
Write-Host "  $snap"
Write-Host ""
Write-Host "Analyse :"
Write-Host "  netverdict analyze `"$pcap`" --snapshot `"$snap`""
