<#
.SYNOPSIS
Full OSI Layer Analyzer - Professional Extended Version
Author: Yousef Abdelhakim
Description: Sequential analysis of URLs simulating all OSI layers
with latency, bandwidth, TCP/UDP analysis, TLS handshake, HTML/JSON logging, and popups.
#>

param(
    [Parameter(Mandatory=$true)]
    [string[]]$TargetURLs,

    [switch]$EnableScreenshot,
    [switch]$EnableJSONValidation
)

# ============================
# Logging Function
# ============================
function Write-Log {
    param(
        [string]$Message,
        [string]$LogFile,
        [ValidateSet("INFO","WARN","ERROR")] [string]$Level = "INFO"
    )
    $Prefix = "[$Level]"
    $Line = "$Prefix $Message"
    Write-Host $Line
    $Line | Out-File $LogFile -Append
}

# ============================
# Measure Latency
# ============================
function Get-Latency {
    param([string]$HostName)
    try {
        $PingResults = Test-Connection -ComputerName $HostName -Count 3 -ErrorAction Stop
        return [math]::Round(($PingResults | Measure-Object ResponseTime -Average).Average,2)
    } catch {
        return -1
    }
}

# ============================
# OSI Analysis Function
# ============================
function Analyze-Website-FullOSI {
    param(
        [string]$WebsiteURL,
        [switch]$ScreenshotEnabled,
        [switch]$JSONValidationEnabled
    )

    # -----------------------------
    # Prepare Output Folder
    # -----------------------------
    $TimeStamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $SafeFolderName = ($WebsiteURL -replace "[:/.]", "_")
    $OutputFolder = Join-Path "F:\OSI-Model" "$SafeFolderName`_$TimeStamp"
    if (-not (Test-Path $OutputFolder)) { New-Item -ItemType Directory -Path $OutputFolder | Out-Null }

    $LogFile = Join-Path $OutputFolder "OSI_Report.txt"
    $HTMLFile = Join-Path $OutputFolder "Response.html"
    $JSONReportFile = Join-Path $OutputFolder "OSI_Report.json"
    $CSVReportFile  = Join-Path $OutputFolder "OSI_Report.csv"
    $ScreenshotFile = Join-Path $OutputFolder "Screenshot.png"

    $OSIReport = [PSCustomObject]@{
        Timestamp        = $TimeStamp
        URL              = $WebsiteURL
        LatencyMs        = $null
        BandwidthKBps    = $null
        Layers           = @()
        Processes        = @()
        JSONValidation   = $null
    }

    Write-Log "================ Full OSI Analyzer ================" $LogFile
    Write-Log "Target URL: $WebsiteURL" $LogFile
    Write-Log "Output Folder: $OutputFolder" $LogFile
    Write-Log "===================================================" $LogFile

    # ============================
    # LAYER 1 - PHYSICAL
    # ============================
    $Layer1Details = @()
    $Adapters = Get-NetAdapter | Where-Object Status -eq "Up"
    foreach ($Adapter in $Adapters) {
        $info = "Adapter: $($Adapter.Name) | Speed: $($Adapter.LinkSpeed) | Status: $($Adapter.Status)"
        Write-Log $info $LogFile
        $Layer1Details += $info
    }
    $OSIReport.Layers += [PSCustomObject]@{ Layer="1-PHYSICAL"; Status="Success"; Details=$Layer1Details }

    # ============================
    # LAYER 2 - DATA LINK
    # ============================
    $Layer2Details = @()
    $Gateway = (Get-NetRoute -DestinationPrefix "0.0.0.0/0").NextHop
    Write-Log "`n[LAYER 2] DATA LINK" $LogFile
    Write-Log "Default Gateway: $Gateway" $LogFile
    $ARPEntry = arp -a | Select-String $Gateway
    if ($ARPEntry) { Write-Log "ARP Entry: $ARPEntry" $LogFile } 
    else { Write-Log "ARP Entry: Not Found" $LogFile "WARN" }
    $Layer2Details += "Gateway: $Gateway"
    $Layer2Details += "ARP Entry: $ARPEntry"
    $OSIReport.Layers += [PSCustomObject]@{ Layer="2-DATA LINK"; Status="Success"; Details=$Layer2Details }

    # ============================
    # LAYER 3 - NETWORK (DNS + Routing)
    # ============================
    $Layer3Details = @()
    try {
        $UriObj = [Uri]$WebsiteURL
        $DNSResults = Resolve-DnsName $UriObj.Host -ErrorAction Stop
        foreach ($r in $DNSResults | Where-Object Type -eq "A") {
            Write-Log "Resolved IP: $($r.IPAddress)" $LogFile
            $Layer3Details += "Resolved IP: $($r.IPAddress)"
        }
    } catch { Write-Log "DNS Resolution Failed: $_" $LogFile "WARN" }

    $RouteTest = Test-NetConnection $UriObj.Host -Port 443 -InformationLevel Detailed
    Write-Log "TCP 443 Reachable: $($RouteTest.TcpTestSucceeded)" $LogFile
    $Layer3Details += "TCP 443 Reachable: $($RouteTest.TcpTestSucceeded)"
    $OSIReport.Layers += [PSCustomObject]@{ Layer="3-NETWORK"; Status="Success"; Details=$Layer3Details }

    # ============================
    # LAYER 4 - TRANSPORT
    # ============================
    $Layer4Details = @()
    $TCPConnections = Get-NetTCPConnection | Where-Object { $_.RemoteAddress -in ($DNSResults.IPAddress) -and $_.State -eq "Established" }
    foreach ($Conn in $TCPConnections) {
        $info = "LocalPort: $($Conn.LocalPort) | RemotePort: $($Conn.RemotePort) | State: $($Conn.State) | PID: $($Conn.OwningProcess)"
        Write-Log $info $LogFile
        $Layer4Details += $info
    }
    $OSIReport.Layers += [PSCustomObject]@{ Layer="4-TRANSPORT"; Status="Success"; Details=$Layer4Details }

    # ============================
    # LAYER 5 - SESSION
    # ============================
    $Layer5Details = @()
    $ActiveSessionsCount = $TCPConnections.Count
    Write-Log "`n[LAYER 5] SESSION" $LogFile
    Write-Log "Active TCP Sessions: $ActiveSessionsCount" $LogFile
    $Layer5Details += "Active Sessions: $ActiveSessionsCount"
    $OSIReport.Layers += [PSCustomObject]@{ Layer="5-SESSION"; Status="Success"; Details=$Layer5Details }

    # ============================
    # LAYER 6 - PRESENTATION (TLS)
    # ============================
    $Layer6Details = @()
    Write-Log "`n[LAYER 6] PRESENTATION (TLS)" $LogFile
    try {
        Invoke-WebRequest $WebsiteURL -Method Head -TimeoutSec 10 | Out-Null
        Write-Log "TLS Handshake: SUCCESS" $LogFile
        $Layer6Details += "TLS Handshake: SUCCESS"
    } catch {
        Write-Log "TLS Handshake Failed: $_" $LogFile "WARN"
        $Layer6Details += "TLS Handshake: FAILED"
    }
    $OSIReport.Layers += [PSCustomObject]@{ Layer="6-PRESENTATION"; Status="Success"; Details=$Layer6Details }

    # ============================
    # LAYER 7 - APPLICATION (HTTP + Bandwidth + JSON Validation)
    # ============================
    $Layer7Details = @()
    try {
        $StartTime = Get-Date
        $Response = Invoke-WebRequest $WebsiteURL -UseBasicParsing -TimeoutSec 15
        $EndTime = Get-Date
        $Elapsed = ($EndTime - $StartTime).TotalSeconds
        $ContentBytes = if ($Response.RawContentLength) { $Response.RawContentLength } else { ($Response.Content.Length * 2) }
        $Bandwidth = [math]::Round(($ContentBytes/1024)/$Elapsed,2)
        $OSIReport.BandwidthKBps = $Bandwidth
        Write-Log "Bandwidth: $Bandwidth KB/s" $LogFile

        if ($Response.Content -and $Response.Content.Length -gt 0) {
            $Response.Content | Out-File $HTMLFile -Encoding UTF8
            Write-Log "HTML Response saved: $HTMLFile" $LogFile
        }

        Write-Log "Status Code: $($Response.StatusCode)" $LogFile
        $Layer7Details += "Status Code: $($Response.StatusCode)"

        if ($EnableJSONValidation) {
            try { $Response.Content | ConvertFrom-Json | Out-Null; $OSIReport.JSONValidation = $true; Write-Log "JSON Validation: SUCCESS" $LogFile }
            catch { $OSIReport.JSONValidation = $false; Write-Log "JSON Validation: FAILED" $LogFile "WARN" }
        }

        $Layer7Status = "Success"
    } catch {
        Write-Log "HTTP Request Failed: $_" $LogFile "ERROR"
        $Layer7Details += "HTTP Request Failed"
        $Layer7Status = "Error"
    }
    $OSIReport.Layers += [PSCustomObject]@{ Layer="7-APPLICATION"; Status=$Layer7Status; Details=$Layer7Details }

    # ============================
    # EXTRA LAYER - PROCESSES
    # ============================
    $ExtraProcesses = @()
    Write-Log "`n[EXTRA] PROCESS ↔ NETWORK" $LogFile
    Get-NetTCPConnection | Where-Object RemotePort -eq 443 | ForEach-Object {
        $Proc = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        if ($Proc) {
            $Info = "Port $($_.LocalPort) → $($Proc.ProcessName)"
            Write-Log $Info $LogFile
            $ExtraProcesses += $Info
        }
    }
    $OSIReport.Processes = $ExtraProcesses

    # ============================
    # Optional Screenshot
    # ============================
    if ($ScreenshotEnabled) {
        try {
            Add-Type -AssemblyName System.Windows.Forms
            $Browser = New-Object System.Windows.Forms.WebBrowser
            $Browser.ScrollBarsEnabled = $false
            $Browser.ScriptErrorsSuppressed = $true
            $Browser.Width = 1200
            $Browser.Height = 800
            $Browser.Navigate($WebsiteURL)
            while ($Browser.ReadyState -ne "Complete") { Start-Sleep -Milliseconds 100 }
            $Bitmap = New-Object System.Drawing.Bitmap $Browser.Width, $Browser.Height
            $Browser.DrawToBitmap($Bitmap, [System.Drawing.Rectangle]::FromLTRB(0,0,$Browser.Width,$Browser.Height))
            $Bitmap.Save($ScreenshotFile, [System.Drawing.Imaging.ImageFormat]::Png)
            Write-Log "Screenshot saved: $ScreenshotFile" $LogFile
        } catch { Write-Log "Screenshot Failed: $_" $LogFile "WARN" }
    }

    # ============================
    # Export JSON + CSV
    # ============================
    $OSIReport | ConvertTo-Json -Depth 6 | Out-File $JSONReportFile -Encoding UTF8
    Write-Log "JSON Report saved: $JSONReportFile" $LogFile

    $CSVData = @()
    foreach ($Layer in $OSIReport.Layers) {
        foreach ($Detail in $Layer.Details) {
            $CSVData += [PSCustomObject]@{
                Layer  = $Layer.Layer
                Status = $Layer.Status
                Detail = $Detail
            }
        }
    }
    $CSVData | Export-Csv $CSVReportFile -NoTypeInformation -Encoding UTF8
    Write-Log "CSV Report saved: $CSVReportFile" $LogFile

    # ============================
    # Completion Popup
    # ============================
    Add-Type -AssemblyName PresentationFramework
    [System.Windows.MessageBox]::Show("Analysis completed for: $WebsiteURL`nReports saved in $OutputFolder","OSI Analyzer Complete",[System.Windows.MessageBoxButton]::OK,[System.Windows.MessageBoxImage]::Information)
}

# ============================
# MAIN LOOP SEQUENTIAL
# ============================
foreach ($URL in $TargetURLs) {
    Analyze-Website-FullOSI -WebsiteURL $URL -ScreenshotEnabled:$EnableScreenshot -JSONValidationEnabled:$EnableJSONValidation
}

Write-Host "`nAll URLs analyzed successfully! Reports ready in F:\OSI-Model"
