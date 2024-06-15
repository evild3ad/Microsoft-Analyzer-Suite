# UAL-Analyzer v0.2
#
# @author:    Martin Willing
# @copyright: Copyright (c) 2024 Martin Willing. All rights reserved.
# @contact:   Any feedback or suggestions are always welcome and much appreciated - mwilling@lethal-forensics.com
# @url:       https://lethal-forensics.com/
# @date:      2024-06-15
#
#
# ██╗     ███████╗████████╗██╗  ██╗ █████╗ ██╗      ███████╗ ██████╗ ██████╗ ███████╗███╗   ██╗███████╗██╗ ██████╗███████╗
# ██║     ██╔════╝╚══██╔══╝██║  ██║██╔══██╗██║      ██╔════╝██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝██║██╔════╝██╔════╝
# ██║     █████╗     ██║   ███████║███████║██║█████╗█████╗  ██║   ██║██████╔╝█████╗  ██╔██╗ ██║███████╗██║██║     ███████╗
# ██║     ██╔══╝     ██║   ██╔══██║██╔══██║██║╚════╝██╔══╝  ██║   ██║██╔══██╗██╔══╝  ██║╚██╗██║╚════██║██║██║     ╚════██║
# ███████╗███████╗   ██║   ██║  ██║██║  ██║███████╗ ██║     ╚██████╔╝██║  ██║███████╗██║ ╚████║███████║██║╚██████╗███████║
# ╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝ ╚═════╝╚══════╝
#
#
# Dependencies:
#
# ImportExcel v7.8.9 (2024-05-18)
# https://github.com/dfinke/ImportExcel
#
# IPinfo CLI 3.3.1 (2024-03-01)
# https://ipinfo.io/signup?ref=cli --> Sign up for free
# https://github.com/ipinfo/cli
#
# xsv v0.13.0 (2018-05-12)
# https://github.com/BurntSushi/xsv
#
#
# Changelog:
# Version 0.1
# Release Date: 2023-05-06
# Initial Release
#
# Version 0.2
# Release Date: 2024-06-14
# Added: Email Forwarding Rules via UpdateInboxRules (EWS)
# Added: Inbox Rules via UpdateInboxRules (EWS)
# Added: Suspicious SessionIds
# Added: Sessions Duration
# Fixed: Other minor fixes and improvements
#
#
# Tested on Windows 10 Pro (x64) Version 22H2 (10.0.19045.4529) and PowerShell 5.1 (5.1.19041.4522)
#
#
#############################################################################################################################################################################################
#############################################################################################################################################################################################

<#
.SYNOPSIS
  UAL-Analyzer v0.2 - Automated Processing of M365 Unified Audit Logs for DFIR

.DESCRIPTION
  UAL-Analyzer.ps1 is a PowerShell script utilized to simplify the analysis of M365 Unified Audit Logs extracted via "Microsoft Extractor Suite" by Invictus Incident Response.

  https://microsoft-365-extractor-suite.readthedocs.io/en/latest/functionality/UnifiedAuditLog.html

  Single User Audit

.EXAMPLE
  PS> .\UAL-Analyzer.ps1

.NOTES
  Author - Martin Willing

.LINK
  https://lethal-forensics.com/
#>

#############################################################################################################################################################################################
#############################################################################################################################################################################################

# Notes

# Audit (Standard)
# The default retention period for Audit (Standard) has changed from 90 days to 180 days. 
# Audit (Standard) logs generated before October 17, 2023 are retained for 90 days. Audit (Standard) logs generated on or after October 17, 2023 follow the new default retention of 180 days.

# Audit (Premium)
# To retain an audit log for longer than 180 days (and up to 1 year), the user who generates the audit log (by performing an audited activity) must be assigned an Office 365 E5 or Microsoft 365 E5 license or have a Microsoft 365 E5 Compliance or E5 eDiscovery and Audit add-on license. 
# To retain audit logs for 10 years, the user who generates the audit log must also be assigned a 10-year audit log retention add-on license in addition to an E5 license.

# https://learn.microsoft.com/en-us/purview/audit-log-retention-policies#default-audit-log-retention-policy

##############################################################################################################################
# Audit (Standard) # Audit (Premium)                                                                                         #
##############################################################################################################################
# 180 days         # 180 days --> 365 days         # 10 years                                                                #
##############################################################################################################################
#                  # Office 365 E5                 # 10-year audit log retention add-on license in addition to an E5 license #
#                  # Microsoft 365 E5              #                                                                         #
#                  # Microsoft 365 E5 Compliance   #                                                                         #
#                  # E5 eDiscovery                 #                                                                         #
#                  # Audit add-on license          #                                                                         #
##############################################################################################################################

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region CmdletBinding

[CmdletBinding()]
Param(
	[string]$Path
)

#endregion CmdletBinding

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Initialisations

# Set Progress Preference to Silently Continue
$OriginalProgressPreference = $Global:ProgressPreference
$Global:ProgressPreference = 'SilentlyContinue'

#endregion Initialisations

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Declarations

# Declarations

# Script Root
if ($PSVersionTable.PSVersion.Major -gt 2)
{
    # PowerShell 3+
    $SCRIPT_DIR = $PSScriptRoot
}
else
{
    # PowerShell 2
    $SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Definition
}

# Output Directory
$OUTPUT_FOLDER = "$env:USERPROFILE\Desktop\UAL-Analyzer"

# Tools

# IPinfo CLI
$script:IPinfo = "$SCRIPT_DIR\Tools\IPinfo\ipinfo.exe"

# IPinfo CLI - Access Token
$script:Token = "access_token" # Please insert your Access Token here (Default: access_token)

# xsv
$script:xsv = "$SCRIPT_DIR\Tools\xsv\xsv.exe"

# ASN Whitelist
$script:Whitelist = (Import-Csv "$SCRIPT_DIR\Whitelists\ASN-Whitelist.csv" -Delimiter "," | Select-Object -ExpandProperty ASN) -join "|"

#endregion Declarations

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Header

# Windows Title
$DefaultWindowsTitle = $Host.UI.RawUI.WindowTitle
$Host.UI.RawUI.WindowTitle = "UAL-Analyzer v0.2 - Automated Processing of M365 Unified Audit Logs for DFIR"

# Check if the PowerShell script is being run with admin rights
if (!([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
    Write-Host "[Error] This PowerShell script must be run with admin rights." -ForegroundColor Red
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

# Flush Output Directory
if (Test-Path "$OUTPUT_FOLDER")
{
    Get-ChildItem -Path "$OUTPUT_FOLDER" -Force -Recurse -ErrorAction SilentlyContinue | Remove-Item -Force -Recurse
    New-Item "$OUTPUT_FOLDER" -ItemType Directory -Force | Out-Null
}
else 
{
    New-Item "$OUTPUT_FOLDER" -ItemType Directory -Force | Out-Null
}

# Add the required MessageBox class (Windows PowerShell)
Add-Type -AssemblyName System.Windows.Forms

# Function Get-FileSize
Function Get-FileSize()
{
    Param ([long]$Length)
    If ($Length -gt 1TB) {[string]::Format("{0:0.00} TB", $Length / 1TB)}
    ElseIf ($Length -gt 1GB) {[string]::Format("{0:0.00} GB", $Length / 1GB)}
    ElseIf ($Length -gt 1MB) {[string]::Format("{0:0.00} MB", $Length / 1MB)}
    ElseIf ($Length -gt 1KB) {[string]::Format("{0:0.00} KB", $Length / 1KB)}
    ElseIf ($Length -gt 0) {[string]::Format("{0:0.00} Bytes", $Length)}
    Else {""}
}

# Select Log File
if(!($Path))
{
    Function Get-LogFile($InitialDirectory)
    { 
        [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
        $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
        $OpenFileDialog.InitialDirectory = $InitialDirectory
        $OpenFileDialog.Filter = "Unified Audit Log Files |UAL-Combined.csv|All Files (*.*)|*.*"
        $OpenFileDialog.ShowDialog()
        $OpenFileDialog.Filename
        $OpenFileDialog.ShowHelp = $true
        $OpenFileDialog.Multiselect = $false
    }

    $Result = Get-LogFile

    if($Result -eq "OK")
    {
        $script:LogFile = $Result[1]
    }
    else
    {
        $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
        Exit
    }
}
else
{
    $script:LogFile = $Path
}

# Create a record of your PowerShell session to a text file
Start-Transcript -Path "$OUTPUT_FOLDER\Transcript.txt"

# Get Start Time
$startTime = (Get-Date)

# Logo
$Logo = @"
██╗     ███████╗████████╗██╗  ██╗ █████╗ ██╗      ███████╗ ██████╗ ██████╗ ███████╗███╗   ██╗███████╗██╗ ██████╗███████╗
██║     ██╔════╝╚══██╔══╝██║  ██║██╔══██╗██║      ██╔════╝██╔═══██╗██╔══██╗██╔════╝████╗  ██║██╔════╝██║██╔════╝██╔════╝
██║     █████╗     ██║   ███████║███████║██║█████╗█████╗  ██║   ██║██████╔╝█████╗  ██╔██╗ ██║███████╗██║██║     ███████╗
██║     ██╔══╝     ██║   ██╔══██║██╔══██║██║╚════╝██╔══╝  ██║   ██║██╔══██╗██╔══╝  ██║╚██╗██║╚════██║██║██║     ╚════██║
███████╗███████╗   ██║   ██║  ██║██║  ██║███████╗ ██║     ╚██████╔╝██║  ██║███████╗██║ ╚████║███████║██║╚██████╗███████║
╚══════╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═╝      ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝ ╚═════╝╚══════╝
"@

Write-Output ""
Write-Output "$Logo"
Write-Output ""

# Header
Write-Output "UAL-Analyzer v0.2 - Automated Processing of M365 Unified Audit Logs for DFIR"
Write-Output "(c) 2024 Martin Willing at Lethal-Forensics (https://lethal-forensics.com/)"
Write-Output ""

# Analysis date (ISO 8601)
$script:AnalysisDate = [datetime]::Now.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
Write-Output "Analysis date: $AnalysisDate UTC"
Write-Output ""

# Create HashTable and import 'Application-Blacklist.csv'
$script:ApplicationBlacklist_HashTable = [ordered]@{}
if (Test-Path "$SCRIPT_DIR\Blacklists\Application-Blacklist.csv")
{
    if([int](& $xsv count "$SCRIPT_DIR\Blacklists\Application-Blacklist.csv") -gt 0)
    {
        Import-Csv "$SCRIPT_DIR\Blacklists\Application-Blacklist.csv" -Delimiter "," | ForEach-Object { $ApplicationBlacklist_HashTable[$_.AppId] = $_.AppDisplayName,$_.Severity }

        # Count Ingested Properties
        $Count = $ApplicationBlacklist_HashTable.Count
        Write-Output "[Info]  Initializing 'Application-Blacklist.csv' Lookup Table ($Count) ..."
    }
}

# Create HashTable and import 'ASN-Blacklist.csv'
$script:AsnBlacklist_HashTable = [ordered]@{}
if (Test-Path "$SCRIPT_DIR\Blacklists\ASN-Blacklist.csv")
{
    if([int](& $xsv count "$SCRIPT_DIR\Blacklists\ASN-Blacklist.csv") -gt 0)
    {
        Import-Csv "$SCRIPT_DIR\Blacklists\ASN-Blacklist.csv" -Delimiter "," | ForEach-Object { $AsnBlacklist_HashTable[$_.ASN] = $_.OrgName,$_.Info }

        # Count Ingested Properties
        $Count = $AsnBlacklist_HashTable.Count
        Write-Output "[Info]  Initializing 'ASN-Blacklist.csv' Lookup Table ($Count) ..."
    }
}

# Create HashTable and import 'Country-Blacklist.csv'
$script:CountryBlacklist_HashTable = [ordered]@{}
if (Test-Path "$SCRIPT_DIR\Blacklists\Country-Blacklist.csv")
{
    if([int](& $xsv count "$SCRIPT_DIR\Blacklists\Country-Blacklist.csv") -gt 0)
    {
        Import-Csv "$SCRIPT_DIR\Blacklists\Country-Blacklist.csv" -Delimiter "," | ForEach-Object { $CountryBlacklist_HashTable[$_."Country Name"] = $_.Country }

        # Count Ingested Properties
        $Count = $CountryBlacklist_HashTable.Count
        Write-Output "[Info]  Initializing 'Country-Blacklist.csv' Lookup Table ($Count) ..."
    }
}

#endregion Header

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Analysis

# Unified Audit Logs

Function Start-Processing {

$StartTime_Processing = (Get-Date)

# Input-Check
if (!(Test-Path "$LogFile"))
{
    Write-Host "[Error] $LogFile does not exist." -ForegroundColor Red
    Write-Host ""
    Stop-Transcript
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

# Check File Extension
$Extension = [IO.Path]::GetExtension($LogFile)
if (!($Extension -eq ".csv" ))
{
    Write-Host "[Error] No CSV File provided." -ForegroundColor Red
    Write-Host ""
    Stop-Transcript
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

# Check IPinfo CLI Access Token 
if ("$Token" -eq "access_token")
{
    Write-Host "[Error] No IPinfo CLI Access Token provided. Please add your personal access token in Line 138." -ForegroundColor Red
    Write-Host ""
    Stop-Transcript
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

# UserId
$UserIds = Import-Csv -Path "$LogFile" -Delimiter "," | Select-Object UserIds | Sort-Object -Unique
$Count = ($UserIds | Measure-Object).Count
if ($Count -gt 1)
{
    Write-Host "[Error] Single User Audit ONLY." -ForegroundColor Red
    Stop-Transcript
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}
else
{
    $UserId = ($UserIds).UserIds
}

# Input Size
$InputSize = Get-FileSize((Get-Item "$LogFile").Length)
Write-Output "[Info]  Total Input Size: $InputSize"

# Count rows of CSV (w/ thousands separators)
[int]$Count = & $xsv count "$LogFile"
$Rows = '{0:N0}' -f $Count | ForEach-Object {$_ -replace ' ','.'} # Replace Space with a dot (e.g. de-AT)
Write-Output "[Info]  Total Lines: $Rows"

# Estimated Time (Average: 15 lines per second)
[int]$Average = "15"
$TotalSeconds = $Count / $Average
$TimeSpan = [TimeSpan]::FromSeconds($TotalSeconds)

# Processing M365 Unified Audit Logs
Write-Output "[Info]  Processing M365 Unified Audit Logs ($UserId) ..."
New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV" -ItemType Directory -Force | Out-Null
New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\XLSX" -ItemType Directory -Force | Out-Null

# Get-Culture
# Get-Date

# Set-Culture -CultureInfo de-DE --> Get-Date => Dienstag, 27. Februar 2024 07:01:30
# Set-Culture -CultureInfo en-US --> Get-Date => Tuesday, February 27, 2024 7:00:43 AM
# Note: Restart PowerShell Console

# Check Thousands Separator
# (Get-Culture).NumberFormat.NumberGroupSeparator

# Check Timestamp Format
$Timestamp = (Import-Csv -Path "$LogFile" -Delimiter "," | Select-Object CreationDate -First 1).CreationDate

# de-DE
if ($Timestamp -match "\d{2}\.\d{2}\.\d{4} \d{2}:\d{2}:\d{2}")
{
    $script:TimestampFormat = "dd.MM.yyyy HH:mm:ss"
}

# en-US
if ($Timestamp -match "\d{1,2}/\d{1,2}/\d{4} \d{1,2}:\d{2}:\d{2} (AM|PM)")
{
    $script:TimestampFormat = "M/d/yyyy h:mm:ss tt"
}

# Time Frame
$StartDate = (Import-Csv -Path "$LogFile" -Delimiter "," | Select-Object @{Name="CreationDate";Expression={([DateTime]::ParseExact($_.CreationDate, "$TimestampFormat", [cultureinfo]::InvariantCulture).ToString("yyyy-MM-dd HH:mm:ss"))}} | Sort-Object { $_.CreationDate -as [datetime] } -Descending | Select-Object -Last 1).CreationDate
$EndDate = (Import-Csv -Path "$LogFile" -Delimiter "," | Select-Object @{Name="CreationDate";Expression={([DateTime]::ParseExact($_.CreationDate, "$TimestampFormat", [cultureinfo]::InvariantCulture).ToString("yyyy-MM-dd HH:mm:ss"))}} | Sort-Object { $_.CreationDate -as [datetime] } -Descending | Select-Object -First 1).CreationDate
Write-Output "[Info]  Log data from $StartDate UTC until $EndDate UTC"

('[Info]  Estimated Analysis Time: {0} h {1} min {2} sec' -f $TimeSpan.Hours, $TimeSpan.Minutes, $TimeSpan.Seconds)

# XLSX

# Untouched
if (Get-Module -ListAvailable -Name ImportExcel)
{
    if (Test-Path "$LogFile")
    {
        if([int](& $xsv count -d "," "$LogFile") -gt 0)
        {
            $IMPORT = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Sort-Object { $_.CreationDate -as [datetime] } -Descending
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\XLSX\Untouched.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "UAL- Untouched" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:J1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-D and F-J
            $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["F:J"].Style.HorizontalAlignment="Center"
            }
        }
    }
}

# File Size (XLSX)
if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\XLSX\1-Untouched.xlsx")
{
    $Size = Get-FileSize((Get-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\XLSX\1-Untouched.xlsx").Length)
    Write-Output "[Info]  File Size (XLSX) : $Size"
}

# AuditData

# CSV
Import-Csv -Path "$LogFile" -Delimiter "," | Select-Object -ExpandProperty AuditData | ConvertFrom-Json | Sort-Object { $_.CreationDate -as [datetime] } -Descending | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\AuditData.csv" -NoTypeInformation -Encoding UTF8

# XLSX
if (Get-Module -ListAvailable -Name ImportExcel)
{
    if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\AuditData.csv")
    {
        if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\AuditData.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\AuditData.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\XLSX\AuditData.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "AuditData" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:AA1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-AA
            $WorkSheet.Cells["A:AA"].Style.HorizontalAlignment="Center"
            }
        }
    }
}

# Custom CSV
$Data = Import-Csv -Path "$LogFile" -Delimiter "," | Sort-Object { $_.CreationDate -as [datetime] } -Descending

$Results = @()
ForEach($Record in $Data)
{
    $AuditData = $Record.AuditData | ConvertFrom-Json

    $ClientIP = $AuditData.ClientIP | & $IPinfo grepip -o # Remove Port Number from IPv4 (if existing)

    $UserLoggedIn = $AuditData | Where-Object { $_.Operation -eq "UserLoggedIn" }

    if ($null -ne $UserLoggedIn)
    {
        $SessionId = ($AuditData | Where-Object { $_.Operation -eq "UserLoggedIn" } | Select-Object -ExpandProperty DeviceProperties | Where-Object {$_.Name -eq 'SessionId'}).Value
    }
    else
    {
        $SessionId = ($AuditData | Select-Object SessionId).SessionId
    }

    $Line = [PSCustomObject]@{
    "CreationDate"          = ($Record | Select-Object @{Name="CreationDate";Expression={([DateTime]::ParseExact($_.CreationDate, "$TimestampFormat", [cultureinfo]::InvariantCulture).ToString("yyyy-MM-dd HH:mm:ss"))}}).CreationDate
    "UserId"                = $Record.UserIds
    "RecordType"            = $Record.RecordType
    "Operation"             = $Record.Operations
    "ObjectId"              = $AuditData.ObjectId
    "ClientIP"              = $ClientIP
    "ClientIPAddress"       = $AuditData.ClientIPAddress
    "UserAgent"             = $AuditData.UserAgent
    "ClientInfoString"      = $AuditData.ClientInfoString
    "SessionId"             = $SessionId
    "InterSystemsId"        = $AuditData.InterSystemsId # The GUID that track the actions across components within the Office 365 service
    "OS"                    = ($AuditData | Where-Object { $_.Operation -eq "UserLoggedIn" } | Select-Object -ExpandProperty DeviceProperties | Where-Object {$_.Name -eq 'OS'}).Value
    "BrowserType"           = ($AuditData | Where-Object { $_.Operation -eq "UserLoggedIn" } | Select-Object -ExpandProperty DeviceProperties | Where-Object {$_.Name -eq 'BrowserType'}).Value
    "IsCompliantAndManaged" = ($AuditData | Where-Object { $_.Operation -eq "UserLoggedIn" } | Select-Object -ExpandProperty DeviceProperties | Where-Object {$_.Name -eq 'IsCompliantAndManaged'}).Value
    "Workload"              = $AuditData.Workload
    }

    $Results += $Line
}

$Results | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Custom.csv" -NoTypeInformation

# Custom XLSX
if (Get-Module -ListAvailable -Name ImportExcel)
{
    if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Custom.csv")
    {
        if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Custom.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Custom.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\XLSX\Custom.xlsx" -NoNumberConversion * -FreezePane 2,5 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Custom View" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:O1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-D and F-O
            $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["F:N"].Style.HorizontalAlignment="Center"
            }
        }
    }
}

# Session Cookie Theft

# Adversary-in-The-Middle (AiTM) Phishing Attack

# Step 1: User enters credentials on the phishing page.
# Step 2: AiTM server relays credentials to the Microsoft server and authenticates.
# Step 3: User is redirected to the Microsoft portal.

# In the Unified Audit Logs (UAL), steps 2 and 3 are recorded as consecutive logins from different IPs which occur within about 30 seconds of each other—and often within only a couple of seconds. 
# The first login will be the AiTM server (step 2), with the second login being from the user’s legitimate IP address (step 3).

# SessionCookieTheft.csv
if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Custom.csv")
{
    if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Custom.csv") -gt 0)
    {
        Write-output "[Info]  Hunting for Session Cookie Theft ..."

        $Import = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Custom.csv" -Delimiter "," | Where-Object { $_.Operation -eq "UserLoggedIn" } | Where-Object { $_.SessionId -ne "" } | Select-Object -ExpandProperty SessionId -Unique

        $Total = ($Import | Measure-Object).Count

        $Results = @()
        ForEach($SessionId in $Import)
        {
            $Line = [PSCustomObject]@{
            "SessionId"   = $SessionId # This SessionId is NOT available in Microsoft Entra ID Sign-In Logs!
            "ClientIP"    = (Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Custom.csv" -Delimiter "," | Where-Object { $_.SessionId -eq "$SessionId" } | Select-Object ClientIP -Unique | Measure-Object).Count # ClientIPAddress NOT needed
            "OS"          = (Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Custom.csv" -Delimiter "," | Where-Object { $_.SessionId -eq "$SessionId" } | Select-Object OS -Unique | Measure-Object).Count
            "BrowserType" = (Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Custom.csv" -Delimiter "," | Where-Object { $_.SessionId -eq "$SessionId" } | Select-Object BrowserType -Unique | Measure-Object).Count
            }

            $Results += $Line
        }

        $Results | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\SessionCookieTheft.csv" -NoTypeInformation

        Write-Output "[Info]  $Total SessionIds found"
    }
}

# XLSX
if (Get-Module -ListAvailable -Name ImportExcel)
{
    if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\SessionCookieTheft.csv")
    {
        if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\SessionCookieTheft.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\SessionCookieTheft.csv" -Delimiter "," | Sort-Object @{Expression={ $_."ClientIP" -as [Int] }} -Descending
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\XLSX\SessionCookieTheft.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "SessionCookieTheft" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of column A-D
            $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting - Different IP addresses (and User-Agents) indicate Session Cookie Theft
            $LastRow = $WorkSheet.Dimension.End.Row
            Add-ConditionalFormatting -Address $WorkSheet.Cells["B2:B$LastRow"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '=$B2>=2' -BackgroundColor Red # ClientIP
            Add-ConditionalFormatting -Address $WorkSheet.Cells["C2:C$LastRow"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '=$C2>=2' -BackgroundColor Red # OS
            Add-ConditionalFormatting -Address $WorkSheet.Cells["D2:D$LastRow"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '=$D2>=2' -BackgroundColor Red # BrowserType
            }
        }
    }
}

# ObjectId
# 00000002-0000-0ff1-ce00-000000000000   Office 365 Exchange Online
# 394866fc-eedb-4f01-8536-3ff84b16be2a   Microsoft People Cards Service
# 00000003-0000-0ff1-ce00-000000000000   Office 365 SharePoint Online
# 4765445b-32c6-49b0-83e6-1d93765276ca   OfficeHome --> Suspicious

# Stats
New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Stats\CSV" -ItemType Directory -Force | Out-Null
New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Stats\XLSX" -ItemType Directory -Force | Out-Null

# ClientInfoString (Stats)
$Total = (Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Custom.csv" -Delimiter "," | Select-Object ClientInfoString | Measure-Object).Count
Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Custom.csv" -Delimiter "," -Encoding UTF8 | Group-Object ClientInfoString | Select-Object @{Name='ClientInfoString'; Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Stats\CSV\ClientInfoString.csv" -NoTypeInformation -Encoding UTF8

# XLSX
if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Stats\CSV\ClientInfoString.csv")
{
    if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Stats\CSV\ClientInfoString.csv") -gt 0)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Stats\CSV\ClientInfoString.csv" -Delimiter ","
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Stats\XLSX\ClientInfoString.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ClientInfoString" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
        Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
        # HorizontalAlignment "Center" of columns B-C
        $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
        # ConditionalFormatting
        Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Client=OWA;Action=ViaProxy",$A1)))' -BackgroundColor Red # AiTM Server
        }
    }
}

# Operations (Stats)
# https://learn.microsoft.com/en-us/purview/audit-log-activities
# https://learn.microsoft.com/en-us/purview/ediscovery-search-for-activities-in-the-audit-log
# https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities
$Total = (Import-Csv -Path "$LogFile" -Delimiter "," | Select-Object Operations | Measure-Object).Count
Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Group-Object Operations | Select-Object @{Name='Operation'; Expression={$_.Name}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Stats\CSV\Operation.csv" -NoTypeInformation -Encoding UTF8
$Operations = (Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Select-Object Operations | Sort-Object Operations -Unique | Measure-Object).Count

# XLSX
if (Get-Module -ListAvailable -Name ImportExcel)
{
    if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Stats\CSV\Operation.csv")
    {
        if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Stats\CSV\Operation.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Stats\CSV\Operation.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Stats\XLSX\Operation.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Operations" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of column B-C
            $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting - New mail box rule
            $Cells = "A:C"
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("DeliverToMailboxAndForward",$A1)))' -BackgroundColor Red # M365 Portal
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("ForwardingAddress",$A1)))' -BackgroundColor Red # M365 Portal
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("ForwardingSmtpAddress",$A1)))' -BackgroundColor Red # M365 Portal
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("New-InboxRule",$A1)))' -BackgroundColor Red # PowerShell/API or M365 Portal
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Set-Mailbox",$A1)))' -BackgroundColor Red # M365 Portal
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("UpdateInboxRules",$A1)))' -BackgroundColor Red # Outlook client
            # ConditionalFormatting - Modified or Deleted email box rule
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Set-InboxRule",$A1)))' -BackgroundColor Red # PowerShell/API or M365 Portal
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Remove-InboxRule",$A1)))' -BackgroundColor Red # PowerShell/API or M365 Portal
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Enable-InboxRule",$A1)))' -BackgroundColor Red # PowerShell/API or M365 Portal
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Disable-InboxRule",$A1)))' -BackgroundColor Red # PowerShell/API or M365 Portal
            # ConditionalFormatting - New transport rule (Microsoft 365 Exchange Transport Rule Creation)
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("New-TransportRule",$A1)))' -BackgroundColor Red # PowerShell/API or M365 Portal
            # ConditionalFormatting - Modified or Deleted transport rule (Microsoft 365 Exchange Transport Rule Modification)
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Set-TransportRule",$A1)))' -BackgroundColor Red # PowerShell/API or M365 Portal
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Remove-TransportRule",$A1)))' -BackgroundColor Red # PowerShell/API or M365 Portal
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Enable-TransportRule",$A1)))' -BackgroundColor Red # PowerShell/API or M365 Portal
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Disable-TransportRule",$A1)))' -BackgroundColor Red # PowerShell/API or M365 Portal
            # ConditionalFormatting - Content Search Abuse
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("SearchStarted",$A1)))' -BackgroundColor Red # Content Search started
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("SearchExportDownloaded",$A1)))' -BackgroundColor Red # Export Content Search
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("ViewedSearchExported",$A1)))' -BackgroundColor Red # A user viewed a content search export in the compliance portal
            # ConditionalFormatting - eDiscovery Abuse
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("CaseAdded",$A1)))' -BackgroundColor Red # An eDiscovery case was created
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("New-ComplianceSearch",$A1)))' -BackgroundColor Red # A new content search was created.
            # ConditionalFormatting - OAuth Applications
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Add application.",$A1)))' -BackgroundColor Red # Add application
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Add app role assignment grant to user.",$A1)))' -BackgroundColor Red # Adding application permission to an app registration. For example, when you add delegated Graph API permissions.
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Add delegated permission grant.",$A1)))' -BackgroundColor Red # API permissions have been delegated to an application.
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Add owner to application.",$A1)))' -BackgroundColor Red
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Add owner to service principal.",$A1)))' -BackgroundColor Red
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Add service principal.",$A1)))' -BackgroundColor Red # Added service principal
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Consent to application.",$A1)))' -BackgroundColor Red # A user granted authorization to an application to access protected resources on their behalf
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Update application.",$A1)))' -BackgroundColor Red
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Update application Certificates and secrets management",$A1)))' -BackgroundColor Red # Update application - Certificates and secrets management
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Update service principal.",$A1)))' -BackgroundColor Red
            # ConditionalFormatting - Business E-Mail Compromise (BEC)
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Add-MailboxPermission",$A1)))' -BackgroundColor Red # An administrator assigned the FullAccess mailbox permission to a user (known as a delegate) to another person's mailbox. The FullAccess permission allows the delegate to open the other person's mailbox, and read and manage the contents of the mailbox.
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Disable-InboxRule",$A1)))' -BackgroundColor Red
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Enable-InboxRule",$A1)))' -BackgroundColor Red
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("MoveToDeletedItems",$A1)))' -BackgroundColor Red # Moved messages to Deleted Items folder
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("HardDelete",$A1)))' -BackgroundColor Red # Purged messages from the mailbox
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("SendAs",$A1)))' -BackgroundColor Red # A message was sent using the SendAs permission. This means that another user sent the message as though it came from the mailbox owner.
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Set-MailboxJunkEmailConfiguration",$A1)))' -BackgroundColor Red # Bypass spam filters and successfully deliver spoofed messages to a targeted user’s mailbox
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("SoftDelete",$A1)))' -BackgroundColor Red # Deleted messages from Deleted Items folder
            # ConditionalFormatting - SharePoint Auditing
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("AddedToSecureLink",$A1)))' -BackgroundColor Red # A user was added to the list of entities who can use a secure sharing link. A link that only works for specific people was secured to a user.
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("SearchQueryPerformed",$A1)))' -BackgroundColor Red # A user performed a search in SharePoint or OneDrive for Business. 
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("SecureLinkCreated",$A1)))' -BackgroundColor Red # A secure sharing link was created to this item. A link that only works for specific people was created. It's usually followed by a series of AddedToSecureLink operations, which signify the users who were secured to the link.
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("SecureLinkUpdated",$A1)))' -BackgroundColor Red # A secure sharing link was updated. A link that only works for specific people was updated.
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("SharingInvitationCreated",$A1)))' -BackgroundColor Red # A user shared a resource in SharePoint Online or OneDrive for Business with a user who isn't in your organization's directory.
            # ConditionalFormatting - Account Manipulation
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Add user.",$A1)))' -BackgroundColor Red # A user account was created
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Added member to group",$A1)))' -BackgroundColor Red # A member was added to a group
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Added member to role",$A1)))' -BackgroundColor Red # A member was added to a role
            # ConditionalFormatting - Power Automate
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("CreateFlow",$A1)))' -BackgroundColor Red # A new flow was created (MicrosoftFlow)
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("PutConnection",$A1)))' -BackgroundColor Red # A connection was created or edited (MicrosoftFlow)
            # ConditionalFormatting - Unified Audit Log Retention Policy Manipulation
            # Note: UAL are retained for 180 days by default for all plans. However, if you have Office 365 E5, Microsoft 365 E5 or Microsoft 365 E5 Compliance add-on license you can enable an audit retention policy for up to 10 years.
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("New-UnifiedAuditLogRetentionPolicy",$A1)))' -BackgroundColor Red # This operation is recorded when a new retention policy is created in the Microsoft 365 Defender portal or the Microsoft Purview compliance portal.
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Set-UnifiedAuditLogRetentionPolicy",$A1)))' -BackgroundColor Red # This operation is recorded when an existing retention policy is modified in the Microsoft 365 Defender portal or the Microsoft Purview compliance portal.
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Remove-UnifiedAuditLogRetentionPolicy",$A1)))' -BackgroundColor Red # This operation is recorded when an existing retention policy is removed in the Microsoft 365 Defender portal or the Microsoft Purview compliance portal.
            }
        }
    }
}

# RecordType (Stats)
$Total = (Import-Csv -Path "$LogFile" -Delimiter "," | Select-Object "File Path" | Measure-Object).Count
Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Group-Object RecordType | Select-Object @{Name='RecordType'; Expression={$_.Name}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Stats\CSV\RecordType.csv" -NoTypeInformation -Encoding UTF8
$RecordTypes = (Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Select-Object RecordType | Sort-Object RecordType -Unique | Measure-Object).Count

# XLSX
if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Stats\CSV\RecordType.csv")
{
    if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Stats\CSV\RecordType.csv") -gt 0)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Stats\CSV\RecordType.csv" -Delimiter ","
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Stats\XLSX\RecordType.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "RecordType" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
        Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
        # HorizontalAlignment "Center" of column B-C
        $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
        }
    }
}

Write-Output "[Info]  $RecordTypes RecordTypes and $Operations Operations found"

# User-Agent (Stats)
$Total = (Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Custom.csv" -Delimiter "," | Select-Object UserAgent | Where-Object {$_.UserAgent -ne '' } | Measure-Object).Count
Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Custom.csv" -Delimiter "," | Select-Object UserAgent | Where-Object {$_.UserAgent -ne '' } | Where-Object {$null -ne ($_.PSObject.Properties | ForEach-Object {$_.Value})} | Group-Object UserAgent | Select-Object @{Name='UserAgent'; Expression={$_.Name}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Stats\CSV\UserAgent.csv" -NoTypeInformation -Encoding UTF8

# XLSX
if (Get-Module -ListAvailable -Name ImportExcel)
{
    if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Stats\CSV\UserAgent.csv")
    {
        if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Stats\CSV\UserAgent.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Stats\CSV\UserAgent.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Stats\XLSX\UserAgent.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "UserAgent" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of column B-C
            $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
            }
        }
    }
}

# Suspicious Operations

# Inbox Rules
# Inbox Rules let users automate actions on incoming emails when they match specific criteria, such as containing certain words in the subject line or coming from a particular sender. 
# These actions can include moving messages to designated folders, marking them as read, or forwarding them to external addresses. 

# New-InboxRule
# RecordType: ExchangeAdmin
# Operation: New-InboxRule --> Create a new Inbox Rule in a mailbox
# https://learn.microsoft.com/en-us/powershell/module/exchange/new-inboxrule?view=exchange-ps
# Hide Artifacts: Email Hiding Rules [T1564.008] --> https://attack.mitre.org/techniques/T1564/008/
$Import = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object { $_.RecordType -eq "ExchangeAdmin" } | Where-Object { $_.Operations -eq "New-InboxRule" } | Sort-Object { $_.CreationDate -as [datetime] } -Descending
$Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
if ($Count -gt 0)
{
    Write-Host "[Alert] Suspicious Operation(s) detected: New-InboxRule ($Count)" -ForegroundColor Red
    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV" -ItemType Directory -Force | Out-Null
    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\XLSX" -ItemType Directory -Force | Out-Null

    # CSV
    $Import | Select-Object @{Name="CreationDate";Expression={([DateTime]::ParseExact($_.CreationDate, "$TimestampFormat", [cultureinfo]::InvariantCulture).ToString("yyyy-MM-dd HH:mm:ss"))}},UserIds,RecordType,Operations,AuditData,ResultIndex,ResultCount,Identity,IsValid,ObjectState | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\New-InboxRule.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Get-Module -ListAvailable -Name ImportExcel)
    {
        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\New-InboxRule.csv")
        {
            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\New-InboxRule.csv") -gt 0)
            {
                $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\New-InboxRule.csv" -Delimiter ","
                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\XLSX\New-InboxRule.xlsx" -FreezePane 2,2 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "New-InboxRule" -CellStyleSB {
                param($WorkSheet)
                # BackgroundColor and FontColor for specific cells of TopRow
                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                Set-Format -Address $WorkSheet.Cells["A1:J1"] -BackgroundColor $BackgroundColor -FontColor White
                # HorizontalAlignment "Center" of columns A-D and F-J
                $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"
                $WorkSheet.Cells["F:J"].Style.HorizontalAlignment="Center"
                # ConditionalFormatting
                Add-ConditionalFormatting -Address $WorkSheet.Cells["C:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("New-InboxRule",$D1)))' -BackgroundColor Red
                }
            }
        }
    }

    # AuditData

    # CSV
    $Results = @()
    ForEach($Record in $Import)
    {
        $AuditData = $Record.AuditData | ConvertFrom-Json
        $Parameters = $AuditData.Parameters

        # Parameters
        New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\TXT" -ItemType Directory -Force | Out-Null
        $Parameters | Out-File "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\TXT\New-InboxRule_Parameters.txt" -Append

        $Line = [PSCustomObject]@{
        "CreationDate"                 = $Record.CreationDate
        "Id"                           = $AuditData.Id
        "RecordType"                   = $Record.RecordType
        "Operation"                    = $AuditData.Operation
        "OrganizationId"               = $AuditData.OrganizationId
        "RecordType_AuditData"         = $AuditData.RecordType
        "ResultStatus"                 = $AuditData.ResultStatus
        "UserKey"                      = $AuditData.UserKey
        "UserType"                     = $AuditData.UserType
        "Version"                      = $AuditData.Version
        "Workload"                     = $AuditData.Workload
        "ClientIP"                     = $AuditData.ClientIP
        "ObjectId"                     = $AuditData.ObjectId
        "UserId"                       = $AuditData.UserId
        "AppId"                        = $AuditData.AppId
        "ClientAppId"                  = $AuditData.ClientAppId
        "ExternalAccess"               = $AuditData.ExternalAccess
        "OrganizationName"             = $AuditData.OrganizationName
        "OriginatingServer"            = $AuditData.OriginatingServer
        "AlwaysDeleteOutlookRulesBlob" = $Parameters | Where-Object { $_.Name -eq "AlwaysDeleteOutlookRulesBlob" } | Select-Object -ExpandProperty Value
        "DeleteMessage"                = $Parameters | Where-Object { $_.Name -eq "DeleteMessage" } | Select-Object -ExpandProperty Value # Hiding
        "Force"                        = $Parameters | Where-Object { $_.Name -eq "Force" } | Select-Object -ExpandProperty Value
        "From"                         = $Parameters | Where-Object { $_.Name -eq "From" } | Select-Object -ExpandProperty Value # Monitoring
        "MoveToFolder"                 = $Parameters | Where-Object { $_.Name -eq "MoveToFolder" } | Select-Object -ExpandProperty Value # Hiding
        "Name"                         = $Parameters | Where-Object { $_.Name -eq "Name" } | Select-Object -ExpandProperty Value
        "FromAddressContainsWords"     = $Parameters | Where-Object { $_.Name -eq "FromAddressContainsWords" } | Select-Object -ExpandProperty Value # Monitoring
        "MyNameInToOrCcBox"            = $Parameters | Where-Object { $_.Name -eq "MyNameInToOrCcBox" } | Select-Object -ExpandProperty Value # Hiding
        "SubjectContainsWords"         = $Parameters | Where-Object { $_.Name -eq "SubjectContainsWords" } | Select-Object -ExpandProperty Value # Monitoring
        "MarkAsRead"                   = $Parameters | Where-Object { $_.Name -eq "MarkAsRead" } | Select-Object -ExpandProperty Value # Hiding
        "StopProcessingRules"          = $Parameters | Where-Object { $_.Name -eq "StopProcessingRules" } | Select-Object -ExpandProperty Value
        "SessionId"                    = ($AuditData | Select-Object SessionId).SessionId
        }

        $Results += $Line
    }

    $Results | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\New-InboxRule_AuditData.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Get-Module -ListAvailable -Name ImportExcel)
    {
        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\New-InboxRule_AuditData.csv")
        {
            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\New-InboxRule_AuditData.csv") -gt 0)
            {
                $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\New-InboxRule_AuditData.csv" -Delimiter ","
                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\XLSX\New-InboxRule_AuditData.xlsx" -FreezePane 2,5 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "New-InboxRule" -CellStyleSB {
                param($WorkSheet)
                # BackgroundColor and FontColor for specific cells of TopRow
                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                Set-Format -Address $WorkSheet.Cells["A1:AE1"] -BackgroundColor $BackgroundColor -FontColor White
                # HorizontalAlignment "Center" of columns A-AE
                $WorkSheet.Cells["A:AE"].Style.HorizontalAlignment="Center"
                # ConditionalFormatting - New-InboxRule
                Add-ConditionalFormatting -Address $WorkSheet.Cells["C:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("New-InboxRule",$D1)))' -BackgroundColor Red
                # ConditionalFormatting - DeleteMessage
                Add-ConditionalFormatting -Address $WorkSheet.Cells["U:U"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("True",$U1)))' -BackgroundColor Red
                # ConditionalFormatting - MoveToFolder
                Add-ConditionalFormatting -Address $WorkSheet.Cells["X:X"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Archive",$X1)))' -BackgroundColor Red
                Add-ConditionalFormatting -Address $WorkSheet.Cells["X:X"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Conversation History",$X1)))' -BackgroundColor Red
                Add-ConditionalFormatting -Address $WorkSheet.Cells["X:X"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("RSS-подписки",$X1)))' -BackgroundColor Red
                Add-ConditionalFormatting -Address $WorkSheet.Cells["X:X"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("RSS-Feeds",$X1)))' -BackgroundColor Red
                Add-ConditionalFormatting -Address $WorkSheet.Cells["X:X"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("RSS Subscriptions",$X1)))' -BackgroundColor Red
                Add-ConditionalFormatting -Address $WorkSheet.Cells["X:X"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Junk-E-Mail",$X1)))' -BackgroundColor Red
                # ConditionalFormatting - MarkAsRead
                Add-ConditionalFormatting -Address $WorkSheet.Cells["AC:AC"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("True",$AC1)))' -BackgroundColor Red
                # ConditionalFormatting - Name
                Add-ConditionalFormatting -Address $WorkSheet.Cells["Y:Y"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '$Y1="."' -BackgroundColor Red
                Add-ConditionalFormatting -Address $WorkSheet.Cells["Y:Y"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '$Y1=";"' -BackgroundColor Red
                Add-ConditionalFormatting -Address $WorkSheet.Cells["Y:Y"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '$Y1="|"' -BackgroundColor Red
                Add-ConditionalFormatting -Address $WorkSheet.Cells["Y:Y"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '$Y1=".."' -BackgroundColor Red
                Add-ConditionalFormatting -Address $WorkSheet.Cells["Y:Y"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '$Y1="..."' -BackgroundColor Red
                Add-ConditionalFormatting -Address $WorkSheet.Cells["Y:Y"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '$Y1=".;"' -BackgroundColor Red
                Add-ConditionalFormatting -Address $WorkSheet.Cells["Y:Y"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '$Y1=".,.,"' -BackgroundColor Red
                # ConditionalFormatting - StopProcessingRules
                Add-ConditionalFormatting -Address $WorkSheet.Cells["AD:AD"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("True",$AD1)))' -BackgroundColor Red
                }
            }
        }
    }
}

# Set-InboxRule
# RecordType: ExchangeAdmin
# Operation: Set-InboxRule --> Change an existing mailbox, often used for setting up forwarding rules
# The Set-InboxRule cmdlet allows you to modify the rule conditions, exceptions, and actions. When you create, modify, remove, enable, or disable an Inbox rule in Exchange PowerShell, any client-side rules created by Microsoft Outlook are removed.
# https://learn.microsoft.com/en-us/powershell/module/exchange/set-inboxrule?view=exchange-ps
$Import = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object { $_.RecordType -eq "ExchangeAdmin" } | Where-Object { $_.Operations -eq "Set-InboxRule" } | Sort-Object { $_.CreationDate -as [datetime] } -Descending
$Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
if ($Count -gt 0)
{
    Write-Host "[Alert] Suspicious Operation(s) detected: Set-InboxRule ($Count)" -ForegroundColor Red
    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV" -ItemType Directory -Force | Out-Null
    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\XLSX" -ItemType Directory -Force | Out-Null

    # CSV
    $Import | Select-Object @{Name="CreationDate";Expression={([DateTime]::ParseExact($_.CreationDate, "$TimestampFormat", [cultureinfo]::InvariantCulture).ToString("yyyy-MM-dd HH:mm:ss"))}},UserIds,RecordType,Operations,AuditData,ResultIndex,ResultCount,Identity,IsValid,ObjectState | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Set-InboxRule.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Get-Module -ListAvailable -Name ImportExcel)
    {
        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Set-InboxRule.csv")
        {
            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Set-InboxRule.csv") -gt 0)
            {
                $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Set-InboxRule.csv" -Delimiter ","
                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\XLSX\Set-InboxRule.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Set-InboxRule" -CellStyleSB {
                param($WorkSheet)
                # BackgroundColor and FontColor for specific cells of TopRow
                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                Set-Format -Address $WorkSheet.Cells["A1:J1"] -BackgroundColor $BackgroundColor -FontColor White
                # HorizontalAlignment "Center" of columns A-D and F-J
                $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"
                $WorkSheet.Cells["F:J"].Style.HorizontalAlignment="Center"
                # ConditionalFormatting
                Add-ConditionalFormatting -Address $WorkSheet.Cells["C:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Set-InboxRule",$D1)))' -BackgroundColor Red
                }
            }
        }
    }

    # AuditData

    # CSV
    $Results = @()
    ForEach($Record in $Import)
    {
        $AuditData = $Record.AuditData | ConvertFrom-Json
        $Parameters = $AuditData.Parameters

        # Parameters
        New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\TXT" -ItemType Directory -Force | Out-Null
        $Parameters | Out-File "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\TXT\Set-InboxRule_Parameters.txt" -Append

        $Line = [PSCustomObject]@{
        "CreationDate"                 = $Record.CreationDate
        "Id"                           = $AuditData.Id
        "RecordType"                   = $Record.RecordType
        "Operation"                    = $AuditData.Operation
        "OrganizationId"               = $AuditData.OrganizationId
        "RecordType_AuditData"         = $AuditData.RecordType
        "ResultStatus"                 = $AuditData.ResultStatus
        "UserKey"                      = $AuditData.UserKey
        "UserType"                     = $AuditData.UserType
        "Version"                      = $AuditData.Version
        "Workload"                     = $AuditData.Workload
        "ClientIP"                     = $AuditData.ClientIP
        "ObjectId"                     = $AuditData.ObjectId
        "UserId"                       = $AuditData.UserId
        "AppId"                        = $AuditData.AppId
        "ClientAppId"                  = $AuditData.ClientAppId
        "ExternalAccess"               = $AuditData.ExternalAccess
        "OrganizationName"             = $AuditData.OrganizationName
        "OriginatingServer"            = $AuditData.OriginatingServer
        "AlwaysDeleteOutlookRulesBlob" = $Parameters | Where-Object { $_.Name -eq "AlwaysDeleteOutlookRulesBlob" } | Select-Object -ExpandProperty Value
        "DeleteMessage"                = $Parameters | Where-Object { $_.Name -eq "DeleteMessage" } | Select-Object -ExpandProperty Value # Hiding
        "Force"                        = $Parameters | Where-Object { $_.Name -eq "Force" } | Select-Object -ExpandProperty Value
        "From"                         = $Parameters | Where-Object { $_.Name -eq "From" } | Select-Object -ExpandProperty Value # Monitoring
        "MoveToFolder"                 = $Parameters | Where-Object { $_.Name -eq "MoveToFolder" } | Select-Object -ExpandProperty Value # Hiding
        "Name"                         = $Parameters | Where-Object { $_.Name -eq "Name" } | Select-Object -ExpandProperty Value
        "FromAddressContainsWords"     = $Parameters | Where-Object { $_.Name -eq "FromAddressContainsWords" } | Select-Object -ExpandProperty Value # Monitoring
        "MyNameInToOrCcBox"            = $Parameters | Where-Object { $_.Name -eq "MyNameInToOrCcBox" } | Select-Object -ExpandProperty Value # Hiding
        "SubjectContainsWords"         = $Parameters | Where-Object { $_.Name -eq "SubjectContainsWords" } | Select-Object -ExpandProperty Value # Monitoring
        "MarkAsRead"                   = $Parameters | Where-Object { $_.Name -eq "MarkAsRead" } | Select-Object -ExpandProperty Value # Hiding
        "StopProcessingRules"          = $Parameters | Where-Object { $_.Name -eq "StopProcessingRules" } | Select-Object -ExpandProperty Value
        "SessionId"                    = ($AuditData | Select-Object SessionId).SessionId
        }

        $Results += $Line
    }

    $Results | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Set-InboxRule_AuditData.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Get-Module -ListAvailable -Name ImportExcel)
    {
        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Set-InboxRule_AuditData.csv")
        {
            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Set-InboxRule_AuditData.csv") -gt 0)
            {
                $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Set-InboxRule_AuditData.csv" -Delimiter ","
                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\XLSX\Set-InboxRule_AuditData.xlsx" -FreezePane 2,2 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Set-InboxRule" -CellStyleSB {
                param($WorkSheet)
                # BackgroundColor and FontColor for specific cells of TopRow
                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                Set-Format -Address $WorkSheet.Cells["A1:AE1"] -BackgroundColor $BackgroundColor -FontColor White
                # HorizontalAlignment "Center" of columns A-AE
                $WorkSheet.Cells["A:AE"].Style.HorizontalAlignment="Center"
                # ConditionalFormatting - Set-InboxRule
                Add-ConditionalFormatting -Address $WorkSheet.Cells["C:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Set-InboxRule",$D1)))' -BackgroundColor Red
                # ConditionalFormatting - DeleteMessage
                Add-ConditionalFormatting -Address $WorkSheet.Cells["U:U"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("True",$U1)))' -BackgroundColor Red
                # ConditionalFormatting - MoveToFolder
                Add-ConditionalFormatting -Address $WorkSheet.Cells["X:X"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Archive",$X1)))' -BackgroundColor Red
                Add-ConditionalFormatting -Address $WorkSheet.Cells["X:X"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("RSS-подписки",$X1)))' -BackgroundColor Red
                Add-ConditionalFormatting -Address $WorkSheet.Cells["X:X"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("RSS-Feeds",$X1)))' -BackgroundColor Red
                Add-ConditionalFormatting -Address $WorkSheet.Cells["X:X"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("RSS Subscriptions",$X1)))' -BackgroundColor Red
                Add-ConditionalFormatting -Address $WorkSheet.Cells["X:X"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Junk-E-Mail",$X1)))' -BackgroundColor Red
                # ConditionalFormatting - MarkAsRead
                Add-ConditionalFormatting -Address $WorkSheet.Cells["AC:AC"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("True",$AC1)))' -BackgroundColor Red
                # ConditionalFormatting - Name
                Add-ConditionalFormatting -Address $WorkSheet.Cells["Y:Y"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '$Y1="."' -BackgroundColor Red
                Add-ConditionalFormatting -Address $WorkSheet.Cells["Y:Y"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '$Y1=";"' -BackgroundColor Red
                Add-ConditionalFormatting -Address $WorkSheet.Cells["Y:Y"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '$Y1="|"' -BackgroundColor Red
                Add-ConditionalFormatting -Address $WorkSheet.Cells["Y:Y"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '$Y1=".."' -BackgroundColor Red
                Add-ConditionalFormatting -Address $WorkSheet.Cells["Y:Y"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '$Y1="..."' -BackgroundColor Red
                Add-ConditionalFormatting -Address $WorkSheet.Cells["Y:Y"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '$Y1=".;"' -BackgroundColor Red
                Add-ConditionalFormatting -Address $WorkSheet.Cells["Y:Y"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '$Y1=".,.,"' -BackgroundColor Red
                # ConditionalFormatting - StopProcessingRules
                Add-ConditionalFormatting -Address $WorkSheet.Cells["AD:AD"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("True",$AD1)))' -BackgroundColor Red
                }
            }
        }
    }
}

# Interesting Parameters
# AlwaysDeleteOutlookRulesBlob - The AlwaysDeleteOutlookRulesBlob switch hides a warning message when you use Outlook on the web (formerly known as Outlook Web App) or Exchange PowerShell to modify Inbox rules.
# DeleteMessage                - The DeleteMessage parameter specifies an action for the Inbox rule that sends messages to the Deleted Items folder.
# Force                        - The Force switch hides warning or confirmation messages. 
# MarkAsRead                   - The MarkAsRead parameter specifies an action for the Inbox rule that marks messages as read.
# MoveToFolder                 - The MoveToFolder parameter specifies an action for the Inbox rule that moves messages to the specified mailbox folder.
# StopProcessingRules          - The StopProcessingRules parameter specifies an action for the Inbox rule that stops processing additional rules if the conditions of this Inbox rule are met.

# Client-Side vs Server-Side Outlook Rules
# There are two types of Inbox rules that can be configured in Outlook: client-side and server-side rules.
# - Server-side
# - Client-side
#
# Inbox Rules (Server-side)
# Server-side Outlook rules are executed on the Exchange server side when an email is received. They always work, it doesn’t matter if the user is running an Outlook client or not (rules created with Outlook Web App are always server-side). The following rules can be applied on the Exchange server side: mark an email as important, move an email to another mailbox folder, delete a message, forward an email to another mailbox.
#
# Inbox Rules (Client-side)
# Client-side rules are applied only when the Outlook client is started. Examples of rules include moving an e-mail to a PST file, marking an email as read, displaying an alert, or playing a sound. You cannot manage these rules through PowerShell. These rules have a ‘client-only’ status in the Outlook interface.

# Exchange Web Services
# Exchange Web Services (EWS) is a robust SOAP-based API that allows interaction with EOL, offering a comprehensive suite of functionalities for managing mailboxes. 
# It stands out for its wide range of features, making it a potent tool for administrators and users with sufficient permissions. 
# This API can also be a target for adversaries looking to exploit its extensive access to organizational communications.

# UpdateInboxRules (EWS --> Exchange Web Services)
# Note: The operation 'UpdateInboxRules' is typically seen when rules are created or modified via an Outlook Desktop client using the EWS API.
# https://learn.microsoft.com/en-us/exchange/client-developer/web-service-reference/updateinboxrules-operation
# https://redcanary.com/blog/threat-detection/email-forwarding-rules/
# https://invictus-ir.medium.com/email-forwarding-rules-in-microsoft-365-295fcb63d4fb
# https://www.splunk.com/en_us/blog/security/hunting-m365-invaders-dissecting-email-collection-techniques.html
$Records = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object { $_.Operations -eq "UpdateInboxRules" } | Sort-Object { $_.CreationDate -as [datetime] } -Descending
[int]$Count = $Records.Count
if ($Count -gt 0)
{
    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV" -ItemType Directory -Force | Out-Null
    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\XLSX" -ItemType Directory -Force | Out-Null

    # CSV
    $Records | Select-Object @{Name="CreationDate";Expression={([DateTime]::ParseExact($_.CreationDate, "$TimestampFormat", [cultureinfo]::InvariantCulture).ToString("yyyy-MM-dd HH:mm:ss"))}},UserIds,RecordType,Operations,AuditData,ResultIndex,ResultCount,Identity,IsValid,ObjectState | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\UpdateInboxRules.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Get-Module -ListAvailable -Name ImportExcel)
    {
        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\UpdateInboxRules.csv")
        {
            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\UpdateInboxRules.csv") -gt 0)
            {
                $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\UpdateInboxRules.csv" -Delimiter ","
                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\XLSX\UpdateInboxRules.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "UpdateInboxRules" -CellStyleSB {
                param($WorkSheet)
                # BackgroundColor and FontColor for specific cells of TopRow
                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                Set-Format -Address $WorkSheet.Cells["A1:J1"] -BackgroundColor $BackgroundColor -FontColor White
                # HorizontalAlignment "Center" of columns A-D and F-J
                $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"
                $WorkSheet.Cells["F:J"].Style.HorizontalAlignment="Center"
                }
            }
        }
    }

    $AuditData = $Records.AuditData | ConvertFrom-Json

    # Actions --> Email Forwarding Rules [T1114.003]

    # ForwardToRecipientsAction
    $ForwardToRecipientsAction = $AuditData.OperationProperties | Where-Object {($_.Value -like "ForwardToRecipientsAction")}
    [int]$Count = $ForwardToRecipientsAction.Count
    if ($Count -gt 0)
    {
        Write-Host "[Alert] Suspicious Operation(s) detected: UpdateInboxRules + ForwardToRecipientsAction ($Count)" -ForegroundColor Red

        # CSV
        ForEach ($Record in $Records)
        {
            $AuditData = $Record.AuditData | ConvertFrom-Json
            if ($AuditData.OperationProperties | Where-Object {($_.Value -like "ForwardToRecipientsAction")})
            {
                $Record | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\UpdateInboxRules-ForwardToRecipientsAction.csv" -NoTypeInformation -Encoding UTF8 -Append
            }
        }

        # XLSX
        if (Get-Module -ListAvailable -Name ImportExcel)
        {
            if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\UpdateInboxRules-ForwardToRecipientsAction.csv")
            {
                if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\UpdateInboxRules-ForwardToRecipientsAction.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\UpdateInboxRules-ForwardToRecipientsAction.csv" -Delimiter ","
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\XLSX\UpdateInboxRules-ForwardToRecipientsAction.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ForwardToRecipientsAction" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:J1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-D and F-J
                    $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["F:J"].Style.HorizontalAlignment="Center"
                    }
                }
            }
        }
    }

    # ForwardAsAttachmentToRecipientsAction
    $ForwardAsAttachmentToRecipientsAction = $AuditData.OperationProperties | Where-Object {($_.Value -like "ForwardAsAttachmentToRecipientsAction")}
    [int]$Count = $ForwardAsAttachmentToRecipientsAction.Count
    if ($Count -gt 0)
    {
        Write-Host "[Alert] Suspicious Operation(s) detected: UpdateInboxRules + ForwardAsAttachmentToRecipientsAction ($Count)" -ForegroundColor Red

        # CSV
        ForEach ($Record in $Records)
        {
            $AuditData = $Record.AuditData | ConvertFrom-Json
            if ($AuditData.OperationProperties | Where-Object {($_.Value -like "ForwardAsAttachmentToRecipientsAction")})
            {
                $Record | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\UpdateInboxRules-ForwardAsAttachmentToRecipientsAction.csv" -NoTypeInformation -Encoding UTF8 -Append
            }
        }

        # XLSX
        if (Get-Module -ListAvailable -Name ImportExcel)
        {
            if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\UpdateInboxRules-ForwardAsAttachmentToRecipientsAction.csv")
            {
                if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\UpdateInboxRules-ForwardAsAttachmentToRecipientsAction.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\UpdateInboxRules-ForwardAsAttachmentToRecipientsAction.csv" -Delimiter ","
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\XLSX\UpdateInboxRules-ForwardAsAttachmentToRecipientsAction.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ForwardAsAttachmentToRecipientsAction" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:J1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-D and F-J
                    $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["F:J"].Style.HorizontalAlignment="Center"
                    }
                }
            }
        }
    }

    # RedirectToRecipientsAction
    $RedirectToRecipientsAction = $AuditData | Where-Object {($AuditData.OperationProperties.Value -like "RedirectToRecipientsAction")}
    [int]$Count = $RedirectToRecipientsAction.Count
    if ($Count -gt 0)
    {
        Write-Host "[Alert] Suspicious Operation(s) detected: UpdateInboxRules + RedirectToRecipientsAction ($Count)" -ForegroundColor Red

        # CSV
        ForEach ($Record in $Records)
        {
            $AuditData = $Record.AuditData | ConvertFrom-Json
            if ($AuditData.OperationProperties | Where-Object {($_.Value -like "RedirectToRecipientsAction")})
            {
                $Record | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\UpdateInboxRules-RedirectToRecipientsAction.csv" -NoTypeInformation -Encoding UTF8 -Append
            }
        }

        # XLSX
        if (Get-Module -ListAvailable -Name ImportExcel)
        {
            if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\UpdateInboxRules-RedirectToRecipientsAction.csv")
            {
                if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\UpdateInboxRules-RedirectToRecipientsAction.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\UpdateInboxRules-RedirectToRecipientsAction.csv" -Delimiter "," | Select-Object @{Name="CreationDate";Expression={([DateTime]::ParseExact($_.CreationDate, "$TimestampFormat", [cultureinfo]::InvariantCulture).ToString("yyyy-MM-dd HH:mm:ss"))}},UserIds,RecordType,Operations,AuditData,ResultIndex,ResultCount,Identity,IsValid,ObjectState | Sort-Object Identity -Unique | Sort-Object { $_.CreationDate -as [datetime] } -Descending
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\XLSX\UpdateInboxRules-RedirectToRecipientsAction.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "RedirectToRecipientsAction" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:J1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-D and F-J
                    $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["F:J"].Style.HorizontalAlignment="Center"
                    }
                }
            }
        }

        # Custom CSV
        $Data = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\UpdateInboxRules-RedirectToRecipientsAction.csv" -Delimiter "," | Sort-Object { $_.CreationDate -as [datetime] } -Descending

        $Results = @()
        ForEach($Record in $Data)
        {
            $AuditData = $Record.AuditData | ConvertFrom-Json
            $OperationProperties = $AuditData.OperationProperties
            $ServerRule = ($OperationProperties | Where-Object {$_.Name -eq 'ServerRule'}).Value | ConvertFrom-Json

            $Line = [PSCustomObject]@{
            "CreationDate"          = ($Record | Select-Object @{Name="CreationDate";Expression={([DateTime]::ParseExact($_.CreationDate, "$TimestampFormat", [cultureinfo]::InvariantCulture).ToString("yyyy-MM-dd HH:mm:ss"))}}).CreationDate
            "Id"                    = $AuditData.Id
            "MailboxGuid"           = $AuditData.MailboxGuid
            "UserId"                = $Record.UserIds
            "RecordType"            = $Record.RecordType
            "Operation"             = $Record.Operations
            "ClientIP"              = $AuditData.ClientIP
            "ClientIPAddress"       = $AuditData.ClientIPAddress
            "ClientInfoString"      = $AuditData.ClientInfoString
            "ClientRequestId"       = $AuditData.ClientRequestId
            "AppId"                 = $AuditData.AppId
            "Actions"               = ($OperationProperties | Where-Object {$_.Name -eq 'Actions'}).Value
            "Provider"              = ($OperationProperties | Where-Object {$_.Name -eq 'Provider'}).Value
            "RemoveOutlookRuleBlob" = ($OperationProperties | Where-Object {$_.Name -eq 'RemoveOutlookRuleBlob'}).Value
            "Name"                  = ($OperationProperties | Where-Object {$_.Name -eq 'Name'}).Value
            "IsNew"                 = ($OperationProperties | Where-Object {$_.Name -eq 'IsNew'}).Value
            "IsDirty"               = ($OperationProperties | Where-Object {$_.Name -eq 'IsDirty'}).Value
            "RuleOperation"         = ($OperationProperties | Where-Object {$_.Name -eq 'RuleOperation'}).Value
            "Recipients"            = ($ServerRule | Select-Object -ExpandProperty Actions | Select-Object -ExpandProperty Recipients).Values | Where-Object {$_.Value -like '*@*'} | Select-Object -ExpandProperty Value -Unique
            "Workload"              = $AuditData.Workload
            }

            $Results += $Line
        }

        $Results | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\UpdateInboxRules-RedirectToRecipientsAction_Custom.csv" -NoTypeInformation
    }

    # Custom XLSX
    if (Get-Module -ListAvailable -Name ImportExcel)
    {
        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\UpdateInboxRules-RedirectToRecipientsAction_Custom.csv")
        {
            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\UpdateInboxRules-RedirectToRecipientsAction_Custom.csv") -gt 0)
            {
                $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\UpdateInboxRules-RedirectToRecipientsAction_Custom.csv" -Delimiter "," | Sort-Object Id -Unique | Sort-Object { $_.CreationDate -as [datetime] } -Descending
                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\XLSX\UpdateInboxRules-RedirectToRecipientsAction_Custom.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "RedirectToRecipientsAction" -CellStyleSB {
                param($WorkSheet)
                # BackgroundColor and FontColor for specific cells of TopRow
                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                Set-Format -Address $WorkSheet.Cells["A1:T1"] -BackgroundColor $BackgroundColor -FontColor White
                # HorizontalAlignment "Center" of columns A-T
                $WorkSheet.Cells["A:T"].Style.HorizontalAlignment="Center"
                # ConditionalFormatting
                Add-ConditionalFormatting -Address $WorkSheet.Cells["E:F"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("UpdateInboxRules",$F1)))' -BackgroundColor Red
                Add-ConditionalFormatting -Address $WorkSheet.Cells["L:L"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("RedirectToRecipientsAction",$L1)))' -BackgroundColor Red
                }
            }
        }
    }

    # Whitelist???
    # Name: CI-Out-of-Office Manager - https://appsource.microsoft.com/en-us/product/office/WA200005043?tab=Overview

    # RuleOperation --> Inbox Rules [T1564.008]

    # AddMailboxRule
    $AddMailboxRule = $AuditData.OperationProperties | Where-Object {($_.Value -like "AddMailboxRule")}
    [int]$Count = $AddMailboxRule.Count
    if ($Count -gt 0)
    {
        Write-Host "[Alert] Suspicious Operation(s) detected: UpdateInboxRules + AddMailboxRule ($Count)" -ForegroundColor Red

        # CSV
        ForEach ($Record in $Records)
        {
            $AuditData = $Record.AuditData | ConvertFrom-Json
            if ($AuditData.OperationProperties | Where-Object {($_.Value -like "AddMailboxRule")})
            {
                $Record | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\UpdateInboxRules-AddMailboxRule.csv" -NoTypeInformation -Encoding UTF8 -Append
            }
        }

        # XLSX
        if (Get-Module -ListAvailable -Name ImportExcel)
        {
            if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\UpdateInboxRules-AddMailboxRule.csv")
            {
                if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\UpdateInboxRules-AddMailboxRule.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\UpdateInboxRules-AddMailboxRule.csv" -Delimiter ","
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\XLSX\UpdateInboxRules-AddMailboxRule.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "AddMailboxRule" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:J1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-D and F-J
                    $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["F:J"].Style.HorizontalAlignment="Center"
                    }
                }
            }
        }
    }

    # ModifyMailboxRule
    $ModifyMailboxRule = $AuditData.OperationProperties | Where-Object {($_.Value -like "ModifyMailboxRule")}
    [int]$Count = $ModifyMailboxRule.Count
    if ($Count -gt 0)
    {
        Write-Host "[Alert] Suspicious Operation(s) detected: UpdateInboxRules + ModifyMailboxRule ($Count)" -ForegroundColor Red

        # CSV
        ForEach ($Record in $Records)
        {
            $AuditData = $Record.AuditData | ConvertFrom-Json
            if ($AuditData.OperationProperties | Where-Object {($_.Value -like "ModifyMailboxRule")})
            {
                $Record | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\UpdateInboxRules-ModifyMailboxRule.csv" -NoTypeInformation -Encoding UTF8 -Append
            }
        }

        # XLSX
        if (Get-Module -ListAvailable -Name ImportExcel)
        {
            if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\UpdateInboxRules-ModifyMailboxRule.csv")
            {
                if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\UpdateInboxRules-ModifyMailboxRule.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\UpdateInboxRules-ModifyMailboxRule.csv" -Delimiter ","
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\XLSX\UpdateInboxRules-ModifyMailboxRule.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ModifyMailboxRule" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:J1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-D and F-J
                    $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["F:J"].Style.HorizontalAlignment="Center"
                    }
                }
            }
        }
    }

    # RemoveMailboxRule
    $RemoveMailboxRule = $AuditData.OperationProperties | Where-Object {($_.Value -like "RemoveMailboxRule")}
    [int]$Count = $RemoveMailboxRule.Count
    if ($Count -gt 0)
    {
        Write-Host "[Alert] Suspicious Operation(s) detected: UpdateInboxRules + RemoveMailboxRule ($Count)" -ForegroundColor Red

        # CSV
        ForEach ($Record in $Records)
        {
            $AuditData = $Record.AuditData | ConvertFrom-Json
            if ($AuditData.OperationProperties | Where-Object {($_.Value -like "RemoveMailboxRule")})
            {
                $Record | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\UpdateInboxRules-RemoveMailboxRule.csv" -NoTypeInformation -Encoding UTF8 -Append
            }
        }

        # XLSX
        if (Get-Module -ListAvailable -Name ImportExcel)
        {
            if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\UpdateInboxRules-RemoveMailboxRule.csv")
            {
                if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\UpdateInboxRules-RemoveMailboxRule.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\UpdateInboxRules-RemoveMailboxRule.csv" -Delimiter ","
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\XLSX\UpdateInboxRules-RemoveMailboxRule.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "RemoveMailboxRule" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:J1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-D and F-J
                    $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["F:J"].Style.HorizontalAlignment="Center"
                    }
                }
            }
        }
    }
}

# Transport Rules
# Transport Rules (or Mail Flow Rules) are similar to the Inbox Rules. The main difference is that the Transport Rule take action on messages while they're in transit, and not after the message is delivered to the mailbox. 
# An adversary or insider threat may create/modify a transport rule to exfiltrate data or evade defenses.

# New-TransportRule
$Import = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object { $_.Operations -eq "New-TransportRule" } | Sort-Object { $_.CreationDate -as [datetime] } -Descending
$Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
if ($Count -gt 0)
{
    Write-Host "[Alert] Suspicious Operation(s) detected: New-TransportRule ($Count)" -ForegroundColor Red
}

# Set-TransportRule
$Import = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object { $_.Operations -eq "Set-TransportRule" } | Sort-Object { $_.CreationDate -as [datetime] } -Descending
$Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
if ($Count -gt 0)
{
    Write-Host "[Alert] Suspicious Operation(s) detected: Set-TransportRule ($Count)" -ForegroundColor Red
}

# Parameters
# - AddToRecipients
# - BlindCopyTo
# - CopyTo
# - RedirectMessageTo

# Set-Mailbox - Change an existing mailbox, often used for setting up forwarding rules --> Email Collection: Email Forwarding Rule [T1114.003]
# https://attack.mitre.org/techniques/T1114/003/
$Import = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object { $_.Operations -eq "Set-Mailbox" } | Sort-Object { $_.CreationDate -as [datetime] } -Descending
$Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
if ($Count -gt 0)
{
    Write-Host "[Alert] Suspicious Operation(s) detected: Set-Mailbox ($Count)" -ForegroundColor Red
    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV" -ItemType Directory -Force | Out-Null
    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\XLSX" -ItemType Directory -Force | Out-Null

    # CSV
    $Import | Select-Object @{Name="CreationDate";Expression={([DateTime]::ParseExact($_.CreationDate, "$TimestampFormat", [cultureinfo]::InvariantCulture).ToString("yyyy-MM-dd HH:mm:ss"))}},UserIds,RecordType,Operations,AuditData,ResultIndex,ResultCount,Identity,IsValid,ObjectState | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Set-Mailbox.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Get-Module -ListAvailable -Name ImportExcel)
    {
        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Set-Mailbox.csv")
        {
            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Set-Mailbox.csv") -gt 0)
            {
                $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Set-Mailbox.csv" -Delimiter ","
                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\XLSX\Set-Mailbox.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Set-Mailbox" -CellStyleSB {
                param($WorkSheet)
                # BackgroundColor and FontColor for specific cells of TopRow
                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                Set-Format -Address $WorkSheet.Cells["A1:J1"] -BackgroundColor $BackgroundColor -FontColor White
                # HorizontalAlignment "Center" of columns A-D and F-J
                $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"
                $WorkSheet.Cells["F:J"].Style.HorizontalAlignment="Center"
                }
            }
        }
    }

    # AuditData

    # CSV
    $Results = @()
    ForEach($Record in $Import)
    {
        $AuditData = $Record.AuditData | ConvertFrom-Json
        $AppAccessContext = $AuditData.AppAccessContext
        $Parameters = $AuditData.Parameters

        $Line = [PSCustomObject]@{
        "CreationDate"               = $Record.CreationDate
        "IssuedAtTime"               = $AppAccessContext.IssuedAtTime
        "RecordType"                 = $Record.RecordType
        "Operation"                  = $Record.Operations
        "ResultStatus"               = $AuditData.ResultStatus
        "UserKey"                    = $AuditData.UserKey
        "UserType"                   = $AuditData.UserType
        "Version"                    = $AuditData.Version
        "Workload"                   = $AuditData.Workload
        "ClientIP"                   = $AuditData.ClientIP | & $IPinfo grepip -o # Remove Port Number
        "ObjectId"                   = $AuditData.ObjectId
        "UserId"                     = $AuditData.UserId
        "AppId"                      = $AuditData.AppId
        "AppPoolName"                = $AuditData.AppPoolName
        "ClientAppId"                = $AuditData.ClientAppId
        "ExternalAccess"             = $AuditData.ExternalAccess
        "OrganizationName"           = $AuditData.OrganizationName
        "OriginatingServer"          = $AuditData.OriginatingServer
        "Identity"                   = $Parameters | Where-Object { $_.Name -eq "Identity" } | Select-Object -ExpandProperty Value
        "ForwardingSmtpAddress"      = $Parameters | Where-Object { $_.Name -eq "ForwardingSmtpAddress" } | Select-Object -ExpandProperty Value | ForEach-Object{($_ -split ":")[1]} # Remove Prefix
        "DeliverToMailboxAndForward" = $Parameters | Where-Object { $_.Name -eq "DeliverToMailboxAndForward" } | Select-Object -ExpandProperty Value
        "RequestId"                  = $AuditData.RequestId
        "SessionId"                  = $AuditData.SessionId
        }

        $Results += $Line
    }

    $Results | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Set-Mailbox_AuditData.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Get-Module -ListAvailable -Name ImportExcel)
    {
        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Set-Mailbox_AuditData.csv")
        {
            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Set-Mailbox_AuditData.csv") -gt 0)
            {
                $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Set-Mailbox_AuditData.csv" -Delimiter ","
                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\XLSX\Set-Mailbox_AuditData.xlsx" -NoNumberConversion * -FreezePane 2,5 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Set-Mailbox" -CellStyleSB {
                param($WorkSheet)
                # BackgroundColor and FontColor for specific cells of TopRow
                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                Set-Format -Address $WorkSheet.Cells["A1:W1"] -BackgroundColor $BackgroundColor -FontColor White
                # HorizontalAlignment "Center" of columns A-W
                $WorkSheet.Cells["A:W"].Style.HorizontalAlignment="Center"
                # ConditionalFormatting - Set-Mailbox
                Add-ConditionalFormatting -Address $WorkSheet.Cells["C:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Set-Mailbox",$D1)))' -BackgroundColor Red
                # ConditionalFormatting - ForwardingSmtpAddress
                Add-ConditionalFormatting -Address $WorkSheet.Cells["T:T"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("@gmail.com",$T1)))' -BackgroundColor Red
                }
            }
        }
    }
}

# Suspicious E-Mail Forwarding Rules (DeliverToMailboxAndForward)
if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Set-Mailbox_AuditData.csv")
{
    $Import = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Set-Mailbox_AuditData.csv" -Delimiter "," -Encoding UTF8 | Where-Object { $_.Operation -eq "Set-Mailbox" } | Where-Object { $_.DeliverToMailboxAndForward -ne "" } | Sort-Object { $_.CreationDate -as [datetime] } -Descending
    $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
    if ($Count -gt 0)
    {
        Write-Host "[Alert] Suspicious E-Mail Forwarding Rule(s) detected: DeliverToMailboxAndForward ($Count)" -ForegroundColor Red
    }
}

# Suspicious E-Mail Forwarding Rules (ForwardingAddress)
if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Set-Mailbox_AuditData.csv")
{
    $Import = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Set-Mailbox_AuditData.csv" -Delimiter "," -Encoding UTF8 | Where-Object { $_.Operation -eq "Set-Mailbox" } | Where-Object { $_.ForwardingAddress -ne "" } | Sort-Object { $_.CreationDate -as [datetime] } -Descending
    $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
    if ($Count -gt 0)
    {
        Write-Host "[Alert] Suspicious E-Mail Forwarding Rule(s) detected: ForwardingAddress ($Count)" -ForegroundColor Red
    }
}

# Suspicious E-Mail Forwarding Rules (ForwardingSmtpAddress)
if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Set-Mailbox_AuditData.csv")
{
    $Import = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Set-Mailbox_AuditData.csv" -Delimiter "," -Encoding UTF8 | Where-Object { $_.Operation -eq "Set-Mailbox" } | Where-Object { $_.ForwardingSmtpAddress -ne "" } | Sort-Object { $_.CreationDate -as [datetime] } -Descending
    $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
    if ($Count -gt 0)
    {
        Write-Host "[Alert] Suspicious E-Mail Forwarding Rule(s) detected: ForwardingSmtpAddress ($Count)" -ForegroundColor Red
    }
}

# Set-MailboxJunkEmailConfiguration - Configure a Junk E-Mail rule for a specific mailbox
$Import = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object { $_.Operations -eq "Set-MailboxJunkEmailConfiguration" } | Sort-Object { $_.CreationDate -as [datetime] } -Descending
$Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
if ($Count -gt 0)
{
    Write-Host "[Alert] Suspicious Operation(s) detected: Set-MailboxJunkEmailConfiguration ($Count)" -ForegroundColor Red
    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV" -ItemType Directory -Force | Out-Null
    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\XLSX" -ItemType Directory -Force | Out-Null

    # CSV
    $Import | Select-Object @{Name="CreationDate";Expression={([DateTime]::ParseExact($_.CreationDate, "$TimestampFormat", [cultureinfo]::InvariantCulture).ToString("yyyy-MM-dd HH:mm:ss"))}},UserIds,RecordType,Operations,AuditData,ResultIndex,ResultCount,Identity,IsValid,ObjectState | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Set-MailboxJunkEmailConfiguration.csv" -NoTypeInformation -Encoding UTF8
    
    # XLSX
    if (Get-Module -ListAvailable -Name ImportExcel)
    {
        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Set-MailboxJunkEmailConfiguration.csv")
        {
            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Set-MailboxJunkEmailConfiguration.csv") -gt 0)
            {
                $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Set-MailboxJunkEmailConfiguration.csv" -Delimiter ","
                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\XLSX\Set-MailboxJunkEmailConfiguration.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Junk E-Mail Rules" -CellStyleSB {
                param($WorkSheet)
                # BackgroundColor and FontColor for specific cells of TopRow
                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                Set-Format -Address $WorkSheet.Cells["A1:J1"] -BackgroundColor $BackgroundColor -FontColor White
                # HorizontalAlignment "Center" of columns A-D and F-J
                $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"
                $WorkSheet.Cells["F:J"].Style.HorizontalAlignment="Center"
                }
            }
        }
    }

    # AuditData
    
    # CSV
    $Results = @()
    ForEach($Record in $Import)
    {
        $AuditData = $Record.AuditData | ConvertFrom-Json
        $AppAccessContext = $AuditData.AppAccessContext
        $Parameters = $AuditData.Parameters

        $Line = [PSCustomObject]@{
        "CreationDate"                = $Record.CreationDate
        "IssuedAtTime"                = $AppAccessContext.IssuedAtTime
        "RecordType"                  = $Record.RecordType
        "Operation"                   = $Record.Operations
        "ResultStatus"                = $AuditData.ResultStatus
        "UserKey"                     = $AuditData.UserKey
        "UserType"                    = $AuditData.UserType
        "Version"                     = $AuditData.Version
        "Workload"                    = $AuditData.Workload
        "ClientIP"                    = $AuditData.ClientIP | & $IPinfo grepip -o # Remove Port Number
        "ObjectId"                    = $AuditData.ObjectId
        "UserId"                      = $AuditData.UserId
        "AppId"                       = $AuditData.AppId
        "AppPoolName"                 = $AuditData.AppPoolName
        "ClientAppId"                 = $AuditData.ClientAppId
        "ExternalAccess"              = $AuditData.ExternalAccess
        "OrganizationName"            = $AuditData.OrganizationName
        "OriginatingServer"           = $AuditData.OriginatingServer
        "Identity"                    = $Parameters | Where-Object { $_.Name -eq "Identity" } | Select-Object -ExpandProperty Value
        "BlockedSendersAndDomains"    = $Parameters | Where-Object { $_.Name -eq "BlockedSendersAndDomains" } | Select-Object -ExpandProperty Value
        "TrustedSendersAndDomains"    = $Parameters | Where-Object { $_.Name -eq "TrustedSendersAndDomains" } | Select-Object -ExpandProperty Value
        "TrustedRecipientsAndDomains" = $Parameters | Where-Object { $_.Name -eq "TrustedRecipientsAndDomains" } | Select-Object -ExpandProperty Value
        "Enabled"                     = $Parameters | Where-Object { $_.Name -eq "Enabled" } | Select-Object -ExpandProperty Value
        "TrustedListsOnly"            = $Parameters | Where-Object { $_.Name -eq "TrustedListsOnly" } | Select-Object -ExpandProperty Value
        "ContactsTrusted"             = $Parameters | Where-Object { $_.Name -eq "ContactsTrusted" } | Select-Object -ExpandProperty Value
        "RequestId"                   = $AuditData.RequestId
        "SessionId"                   = $AuditData.SessionId
        }

        $Results += $Line
    }

    $Results | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Set-MailboxJunkEmailConfiguration_AuditData.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Get-Module -ListAvailable -Name ImportExcel)
    {
        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Set-MailboxJunkEmailConfiguration_AuditData.csv")
        {
            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Set-MailboxJunkEmailConfiguration_AuditData.csv") -gt 0)
            {
                $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Set-MailboxJunkEmailConfiguration_AuditData.csv" -Delimiter ","
                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\XLSX\Set-MailboxJunkEmailConfiguration_AuditData.xlsx" -NoNumberConversion * -FreezePane 2,5 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Junk E-Mail Rules" -CellStyleSB {
                param($WorkSheet)
                # BackgroundColor and FontColor for specific cells of TopRow
                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                Set-Format -Address $WorkSheet.Cells["A1:AA1"] -BackgroundColor $BackgroundColor -FontColor White
                # HorizontalAlignment "Center" of columns A-S and W-AA
                $WorkSheet.Cells["A:S"].Style.HorizontalAlignment="Center"
                $WorkSheet.Cells["W:AA"].Style.HorizontalAlignment="Center"
                # ConditionalFormatting - Set-MailboxJunkEmailConfiguration
                Add-ConditionalFormatting -Address $WorkSheet.Cells["C:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Set-MailboxJunkEmailConfiguration",$D1)))' -BackgroundColor Red
                }
            }
        }
    }
}

# Add-MailboxPermission - Change permissions for a mailbox (Mailbox Delegation)
$Import = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object { $_.Operations -eq "Add-MailboxPermission" } | Sort-Object { $_.CreationDate -as [datetime] } -Descending
$Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
if ($Count -gt 0)
{
    Write-Host "[Alert] Suspicious Operation(s) detected: Add-MailboxPermission ($Count)" -ForegroundColor Red
}

# AccessRights
# - FullAccess
# - ChangePermission
# - ChangeOwner

# Add-MailboxFolderPermission - Add permissions on a mailbox folder
$Import = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object { $_.Operations -eq "Add-MailboxFolderPermission" } | Sort-Object { $_.CreationDate -as [datetime] } -Descending
$Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
if ($Count -gt 0)
{
    Write-Host "[Alert] Suspicious Operation(s) detected: Add-MailboxFolderPermission ($Count)" -ForegroundColor Red
}

# Set-MailboxFolderPermission - Set permissions on a mailbox folder
$Import = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object { $_.Operations -eq "Set-MailboxFolderPermission" } | Sort-Object { $_.CreationDate -as [datetime] } -Descending
$Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
if ($Count -gt 0)
{
    Write-Host "[Alert] Suspicious Operation(s) detected: Set-MailboxFolderPermission ($Count)" -ForegroundColor Red
}

# New-InboundConnector - Setup a new email inbound connector
$Import = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object { $_.Operations -eq "New-InboundConnector" } | Sort-Object { $_.CreationDate -as [datetime] } -Descending
$Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
if ($Count -gt 0)
{
    Write-Host "[Alert] Suspicious Operation(s) detected: New-InboundConnector ($Count)" -ForegroundColor Red
    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV" -ItemType Directory -Force | Out-Null
    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\XLSX" -ItemType Directory -Force | Out-Null

    # CSV
    $Import | Select-Object @{Name="CreationDate";Expression={([DateTime]::ParseExact($_.CreationDate, "$TimestampFormat", [cultureinfo]::InvariantCulture).ToString("yyyy-MM-dd HH:mm:ss"))}},UserIds,RecordType,Operations,AuditData,ResultIndex,ResultCount,Identity,IsValid,ObjectState | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\New-InboundConnector.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Get-Module -ListAvailable -Name ImportExcel)
    {
        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\New-InboundConnector.csv")
        {
            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\New-InboundConnector.csv") -gt 0)
            {
                $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\New-InboundConnector.csv" -Delimiter ","
                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\XLSX\New-InboundConnector.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "New-InboundConnector" -CellStyleSB {
                param($WorkSheet)
                # BackgroundColor and FontColor for specific cells of TopRow
                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                Set-Format -Address $WorkSheet.Cells["A1:J1"] -BackgroundColor $BackgroundColor -FontColor White
                # HorizontalAlignment "Center" of columns A-D and F-J
                $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"
                $WorkSheet.Cells["F:J"].Style.HorizontalAlignment="Center"
                }
            }
        }
    }

    # AuditData

    # CSV
    $Import | Select-Object -ExpandProperty AuditData | ConvertFrom-Json | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\New-InboundConnector_AuditData.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    # TODO
}

# OAuth Applications / Permission Grants

# Suspicious Operation(s) detected: Add service principal
# RecordType: AzureActiveDirectory --> Azure Active Directory events.
# Operation: Add service principal. --> An application was registered in Azure AD. An application is represented by a service principal in the directory.
# Identifies when a new service principal is added in Azure AD. The following analytic detects addition of new service principal accounts added to O365 tenants. Service principals are essentially non-human accounts used by applications, services, or scripts to access resources and interact with APIs on behalf of the organization.
$Import = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object { $_.RecordType -eq "AzureActiveDirectory" } | Where-Object { $_.Operations -eq "Add service principal." } | Sort-Object { $_.CreationDate -as [datetime] } -Descending
$Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
if ($Count -gt 0)
{
    Write-Host "[Alert] Suspicious Operation(s) detected: Add service principal ($Count)" -ForegroundColor Red
    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV" -ItemType Directory -Force | Out-Null
    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\XLSX" -ItemType Directory -Force | Out-Null

    # CSV
    $Import | Select-Object @{Name="CreationDate";Expression={([DateTime]::ParseExact($_.CreationDate, "$TimestampFormat", [cultureinfo]::InvariantCulture).ToString("yyyy-MM-dd HH:mm:ss"))}},UserIds,RecordType,Operations,AuditData,ResultIndex,ResultCount,Identity,IsValid,ObjectState | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Add-service-principal.csv" -NoTypeInformation -Encoding UTF8
    
    # XLSX
    if (Get-Module -ListAvailable -Name ImportExcel)
    {
        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Add-service-principal.csv")
        {
            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Add-service-principal.csv") -gt 0)
            {
                $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Add-service-principal.csv" -Delimiter ","
                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\XLSX\Add-service-principal.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Add service principal" -CellStyleSB {
                param($WorkSheet)
                # BackgroundColor and FontColor for specific cells of TopRow
                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                Set-Format -Address $WorkSheet.Cells["A1:J1"] -BackgroundColor $BackgroundColor -FontColor White
                # HorizontalAlignment "Center" of columns A-D and F-J
                $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"
                $WorkSheet.Cells["F:J"].Style.HorizontalAlignment="Center"
                # ConditionalFormatting
                Add-ConditionalFormatting -Address $WorkSheet.Cells["D:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Add service principal.",$D1)))' -BackgroundColor Red
                }
            }
        }
    }

    # AuditData

    # CSV
    $Results = @()
    ForEach($Record in $Import)
    {
        $AuditData = $Record.AuditData | ConvertFrom-Json
        $ExtendedProperties = $AuditData.ExtendedProperties

        $Line = [PSCustomObject]@{
        "CreationDate"                  = $Record.CreationDate
        "Id"                            = $AuditData.Id
        "RecordType"                    = $Record.RecordType
        "Operation"                     = $AuditData.Operation
        "OrganizationId"                = $AuditData.OrganizationId
        "RecordType_AuditData"          = $AuditData.RecordType
        "ResultStatus"                  = $AuditData.ResultStatus
        "UserKey"                       = $AuditData.UserKey
        "UserType"                      = $AuditData.UserType
        "Version"                       = $AuditData.Version
        "Workload"                      = $AuditData.Workload
        "ObjectId"                      = $AuditData.ObjectId
        "UserId"                        = $AuditData.UserId
        "AzureActiveDirectoryEventType" = $AuditData.AzureActiveDirectoryEventType
        "User-Agent"                    = $ExtendedProperties | Where-Object { $_.Name -eq "additionalDetails" } | Select-Object -ExpandProperty Value | ForEach-Object{($_ -split ",")[0]} | ForEach-Object{($_ -split ":")[1]} | ForEach-Object {$_ -replace '"',''}
        "AppId"                         = $ExtendedProperties | Where-Object { $_.Name -eq "additionalDetails" } | Select-Object -ExpandProperty Value | ForEach-Object{($_ -split ",")[1]} | ForEach-Object{($_ -split ":")[1]} | ForEach-Object {$_ -replace '"',''} | ForEach-Object {$_ -replace '}',''}
        }

        $Results += $Line
    }

    $Results | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Add-service-principal_AuditData.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Get-Module -ListAvailable -Name ImportExcel)
    {
        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Add-service-principal_AuditData.csv")
        {
            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Add-service-principal_AuditData.csv") -gt 0)
            {
                $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Add-service-principal_AuditData.csv" -Delimiter ","
                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\XLSX\Add-service-principal_AuditData.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Add service principal" -CellStyleSB {
                param($WorkSheet)
                # BackgroundColor and FontColor for specific cells of TopRow
                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                Set-Format -Address $WorkSheet.Cells["A1:P1"] -BackgroundColor $BackgroundColor -FontColor White
                # HorizontalAlignment "Center" of columns A-P
                $WorkSheet.Cells["A:P"].Style.HorizontalAlignment="Center"
                # ConditionalFormatting - Add service principal.
                Add-ConditionalFormatting -Address $WorkSheet.Cells["C:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Add service principal.",$D1)))' -BackgroundColor Red
                # ConditionalFormatting - AppId
                Add-ConditionalFormatting -Address $WorkSheet.Cells["P:P"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("e9a7fea1-1cc0-4cd9-a31b-9137ca5deedd",$P1)))' -BackgroundColor Red
                }
            }
        }
    }
}

# Suspicious Operation(s) detected: Add delegated permission grant
# RecordType: AzureActiveDirectory --> Azure Active Directory events.
# Operation: Add delegated permissions grant. --> API permissions have been delegated to an application. "Add delegated permissions grant." can be seen when a user tries to access an app from myapp portal and get a consent page.
$Import = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object { $_.RecordType -eq "AzureActiveDirectory" } | Where-Object { $_.Operations -eq "Add delegated permission grant." } | Sort-Object { $_.CreationDate -as [datetime] } -Descending
$Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
if ($Count -gt 0)
{
    Write-Host "[Alert] Suspicious Operation(s) detected: Add delegated permissions grant ($Count)" -ForegroundColor Red
    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV" -ItemType Directory -Force | Out-Null
    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\XLSX" -ItemType Directory -Force | Out-Null

    # CSV
    $Import | Select-Object @{Name="CreationDate";Expression={([DateTime]::ParseExact($_.CreationDate, "$TimestampFormat", [cultureinfo]::InvariantCulture).ToString("yyyy-MM-dd HH:mm:ss"))}},UserIds,RecordType,Operations,AuditData,ResultIndex,ResultCount,Identity,IsValid,ObjectState | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Add-delegated-permissions-grant.csv" -NoTypeInformation -Encoding UTF8
    
    # XLSX
    if (Get-Module -ListAvailable -Name ImportExcel)
    {
        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Add-delegated-permissions-grant.csv")
        {
            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Add-delegated-permissions-grant.csv") -gt 0)
            {
                $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Add-delegated-permissions-grant.csv" -Delimiter ","
                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\XLSX\Add-delegated-permissions-grant.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Add delegated permissions grant" -CellStyleSB {
                param($WorkSheet)
                # BackgroundColor and FontColor for specific cells of TopRow
                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                Set-Format -Address $WorkSheet.Cells["A1:J1"] -BackgroundColor $BackgroundColor -FontColor White
                # HorizontalAlignment "Center" of columns A-D and F-J
                $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"
                $WorkSheet.Cells["F:J"].Style.HorizontalAlignment="Center"
                # ConditionalFormatting
                Add-ConditionalFormatting -Address $WorkSheet.Cells["D:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Add delegated permission grant.",$D1)))' -BackgroundColor Red
                }
            }
        }
    }

    # AuditData

    # CSV
    $Results = @()
    ForEach($Record in $Import)
    {
        $AuditData = $Record.AuditData | ConvertFrom-Json
        $ExtendedProperties = $AuditData.ExtendedProperties
        $ModifiedProperties = $AuditData.ModifiedProperties
        $Target = $AuditData.Target

        $Line = [PSCustomObject]@{
        "CreationDate"                  = $Record.CreationDate
        "Id"                            = $AuditData.Id
        "RecordType"                    = $Record.RecordType
        "Operation"                     = $AuditData.Operation
        "OrganizationId"                = $AuditData.OrganizationId
        "ResultStatus"                  = $AuditData.ResultStatus
        "UserKey"                       = $AuditData.UserKey
        "UserType"                      = $AuditData.UserType
        "Version"                       = $AuditData.Version
        "Workload"                      = $AuditData.Workload
        "UserId"                        = $AuditData.UserId
        "AzureActiveDirectoryEventType" = $AuditData.AzureActiveDirectoryEventType
        "User-Agent"                    = $ExtendedProperties | Where-Object { $_.Name -eq "additionalDetails" } | Select-Object -ExpandProperty Value | ForEach-Object{($_ -split ",")[0]} | ForEach-Object{($_ -split ":")[1]} | ForEach-Object {$_ -replace '"',''}
        "AppId"                         = $ExtendedProperties | Where-Object { $_.Name -eq "additionalDetails" } | Select-Object -ExpandProperty Value | ForEach-Object{($_ -split ",")[1]} | ForEach-Object{($_ -split ":")[1]} | ForEach-Object {$_ -replace '"',''} | ForEach-Object {$_ -replace '}',''}
        "ExtendedAuditEventCategory"    = $ExtendedProperties | Where-Object { $_.Name -eq "extendedAuditEventCategory" } | Select-Object -ExpandProperty Value
        "Scope"                         = ($ModifiedProperties | Where-Object { $_.Name -eq "DelegatedPermissionGrant.Scope" } | Select-Object -ExpandProperty NewValue).Trim()
        "ConsentType"                   = $ModifiedProperties | Where-Object { $_.Name -eq "DelegatedPermissionGrant.ConsentType" } | Select-Object -ExpandProperty NewValue
        "ObjectID"                      = $ModifiedProperties | Where-Object { $_.Name -eq "ServicePrincipal.ObjectID" } | Select-Object -ExpandProperty NewValue
        "ActorContextId"                = $AuditData.ActorContextId
        "InterSystemsId"                = $AuditData.InterSystemsId
        "IntraSystemId"                 = $AuditData.IntraSystemId
        "SupportTicketId"               = $AuditData.SupportTicketId
        "Target"                        = $Target | Where-Object { $_.ID -eq "Microsoft Graph" } | Select-Object -ExpandProperty ID
        "TargetContextId"               = $AuditData.TargetContextId
        }

        $Results += $Line
    }

    $Results | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Add-delegated-permissions-grant_AuditData.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Get-Module -ListAvailable -Name ImportExcel)
    {
        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Add-delegated-permissions-grant_AuditData.csv")
        {
            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Add-delegated-permissions-grant_AuditData.csv") -gt 0)
            {
                $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Add-delegated-permissions-grant_AuditData.csv" -Delimiter ","
                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\XLSX\Add-delegated-permissions-grant_AuditData.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Add delegated permission grant" -CellStyleSB {
                param($WorkSheet)
                # BackgroundColor and FontColor for specific cells of TopRow
                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                Set-Format -Address $WorkSheet.Cells["A1:X1"] -BackgroundColor $BackgroundColor -FontColor White
                # HorizontalAlignment "Center" of columns A-X
                $WorkSheet.Cells["A:X"].Style.HorizontalAlignment="Center"
                # ConditionalFormatting - Add delegated permission grant.
                Add-ConditionalFormatting -Address $WorkSheet.Cells["C:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Add delegated permission grant.",$D1)))' -BackgroundColor Red
                # ConditionalFormatting - Scope
                Add-ConditionalFormatting -Address $WorkSheet.Cells["P:P"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("IMAP.AccessAsUser.All",$P1)))' -BackgroundColor Red
                }
            }
        }
    }

}

# Suspicious Operation(s) detected: Add app role assignment grant to user
# RecordType: AzureActiveDirectory --> Azure Active Directory events.
# Operation: Add app role assignment grant to user. --> "Add app role assignment grant to user." is generated when an app is assigned to a user from the Enterprise app blade. User can access these assigned apps from myapp portal.
$Import = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object { $_.RecordType -eq "AzureActiveDirectory" } | Where-Object { $_.Operations -eq "Add app role assignment grant to user." } | Sort-Object { $_.CreationDate -as [datetime] } -Descending
$Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
if ($Count -gt 0)
{
    Write-Host "[Alert] Suspicious Operation(s) detected: Add app role assignment grant to user ($Count)" -ForegroundColor Red
    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV" -ItemType Directory -Force | Out-Null
    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\XLSX" -ItemType Directory -Force | Out-Null

    # CSV
    $Import | Select-Object @{Name="CreationDate";Expression={([DateTime]::ParseExact($_.CreationDate, "$TimestampFormat", [cultureinfo]::InvariantCulture).ToString("yyyy-MM-dd HH:mm:ss"))}},UserIds,RecordType,Operations,AuditData,ResultIndex,ResultCount,Identity,IsValid,ObjectState | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Add-app-role-assignment-grant-to-user.csv" -NoTypeInformation -Encoding UTF8
    
    # XLSX
    if (Get-Module -ListAvailable -Name ImportExcel)
    {
        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Add-app-role-assignment-grant-to-user.csv")
        {
            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Add-app-role-assignment-grant-to-user.csv") -gt 0)
            {
                $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Add-app-role-assignment-grant-to-user.csv" -Delimiter ","
                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\XLSX\Add-app-role-assignment-grant-to-user.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "App Role Assignment" -CellStyleSB {
                param($WorkSheet)
                # BackgroundColor and FontColor for specific cells of TopRow
                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                Set-Format -Address $WorkSheet.Cells["A1:J1"] -BackgroundColor $BackgroundColor -FontColor White
                # HorizontalAlignment "Center" of columns A-D and F-J
                $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"
                $WorkSheet.Cells["F:J"].Style.HorizontalAlignment="Center"
                # ConditionalFormatting
                Add-ConditionalFormatting -Address $WorkSheet.Cells["D:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Add app role assignment grant to user.",$D1)))' -BackgroundColor Red
                }
            }
        }
    }

    # AuditData

    # CSV
    $Results = @()
    ForEach($Record in $Import)
    {
        $AuditData = $Record.AuditData | ConvertFrom-Json
        $ExtendedProperties = $AuditData.ExtendedProperties
        $ModifiedProperties = $AuditData.ModifiedProperties
        $Target = $AuditData.Target

        $Line = [PSCustomObject]@{
        "CreationDate"                  = $Record.CreationDate
        "Id"                            = $AuditData.Id
        "RecordType"                    = $Record.RecordType
        "Operation"                     = $AuditData.Operation
        "OrganizationId"                = $AuditData.OrganizationId
        "ResultStatus"                  = $AuditData.ResultStatus
        "UserKey"                       = $AuditData.UserKey
        "UserType"                      = $AuditData.UserType
        "Version"                       = $AuditData.Version
        "Workload"                      = $AuditData.Workload
        "ObjectId"                      = $AuditData.ObjectId
        "UserId"                        = $AuditData.UserId
        "AzureActiveDirectoryEventType" = $AuditData.AzureActiveDirectoryEventType
        "User-Agent"                    = $ExtendedProperties | Where-Object { $_.Name -eq "additionalDetails" } | Select-Object -ExpandProperty Value | ForEach-Object{($_ -split ",")[0]} | ForEach-Object{($_ -split ":")[1]} | ForEach-Object {$_ -replace '"',''}
        "AppId"                         = $ExtendedProperties | Where-Object { $_.Name -eq "additionalDetails" } | Select-Object -ExpandProperty Value | ForEach-Object{($_ -split ",")[1]} | ForEach-Object{($_ -split ":")[1]} | ForEach-Object {$_ -replace '"',''} | ForEach-Object {$_ -replace '}',''}
        "ExtendedAuditEventCategory"    = $ExtendedProperties | Where-Object { $_.Name -eq "extendedAuditEventCategory" } | Select-Object -ExpandProperty Value
        "LastModifiedDateTime"          = ($ModifiedProperties | Where-Object { $_.Name -eq "AppRoleAssignment.LastModifiedDateTime" } | Select-Object @{Name="LastModifiedDateTime";Expression={([DateTime]::ParseExact($_.NewValue, "$TimestampFormat", [cultureinfo]::InvariantCulture).ToString("yyyy-MM-dd HH:mm:ss"))}}).LastModifiedDateTime
        "TargetId"                      = $ModifiedProperties | Where-Object { $_.Name -eq "TargetId.ServicePrincipalNames" } | Select-Object -ExpandProperty NewValue
        "ActorContextId"                = $AuditData.ActorContextId
        "InterSystemsId"                = $AuditData.InterSystemsId
        "IntraSystemId"                 = $AuditData.IntraSystemId
        "SupportTicketId"               = $AuditData.SupportTicketId
        "Target"                        = $Target | Where-Object { $_.Type -eq "1" } | Select-Object -ExpandProperty ID
        "TargetContextId"               = $AuditData.TargetContextId
        }

        $Results += $Line
    }

    $Results | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Add-app-role-assignment-grant-to-user_AuditData.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Get-Module -ListAvailable -Name ImportExcel)
    {
        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Add-app-role-assignment-grant-to-user_AuditData.csv")
        {
            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Add-app-role-assignment-grant-to-user_AuditData.csv") -gt 0)
            {
                $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Add-app-role-assignment-grant-to-user_AuditData.csv" -Delimiter ","
                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\XLSX\Add-app-role-assignment-grant-to-user_AuditData.xlsx" -FreezePane 2,5 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Add app role assignment grant" -CellStyleSB {
                param($WorkSheet)
                # BackgroundColor and FontColor for specific cells of TopRow
                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                Set-Format -Address $WorkSheet.Cells["A1:X1"] -BackgroundColor $BackgroundColor -FontColor White
                # HorizontalAlignment "Center" of columns A-X
                $WorkSheet.Cells["A:X"].Style.HorizontalAlignment="Center"
                # ConditionalFormatting - Add app role assignment grant to user
                Add-ConditionalFormatting -Address $WorkSheet.Cells["C:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Add app role assignment grant to user.",$D1)))' -BackgroundColor Red
                # ConditionalFormatting - AppId
                Add-ConditionalFormatting -Address $WorkSheet.Cells["O:O"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("e9a7fea1-1cc0-4cd9-a31b-9137ca5deedd",$O1)))' -BackgroundColor Red # eM Client
                # ConditionalFormatting - Target
                Add-ConditionalFormatting -Address $WorkSheet.Cells["W:W"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("eM Client",$W1)))' -BackgroundColor Red
                }
            }
        }
    }
}

# Suspicious Operation(s) detected: Consent to application
# RecordType: AzureActiveDirectory --> Azure Active Directory events.
# Operation: Consent to application. --> Consent is the process of a user granting authorization to an application to access protected resources on their behalf. Detects when a user grants permissions to an Azure-registered application or when an administrator grants tenant-wide permissions to an application. An adversary may create an Azure-registered application that requests access to data such as contact information, email, or documents.
# https://www.elastic.co/guide/en/security/current/possible-consent-grant-attack-via-azure-registered-application.html
$Import = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object { $_.RecordType -eq "AzureActiveDirectory" } | Where-Object { $_.Operations -eq "Consent to application." } | Sort-Object { $_.CreationDate -as [datetime] } -Descending
$Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
if ($Count -gt 0)
{
    Write-Host "[Alert] Suspicious Operation(s) detected: Consent to application ($Count)" -ForegroundColor Red
    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV" -ItemType Directory -Force | Out-Null
    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\XLSX" -ItemType Directory -Force | Out-Null

    # CSV
    $Import | Select-Object @{Name="CreationDate";Expression={([DateTime]::ParseExact($_.CreationDate, "$TimestampFormat", [cultureinfo]::InvariantCulture).ToString("yyyy-MM-dd HH:mm:ss"))}},UserIds,RecordType,Operations,AuditData,ResultIndex,ResultCount,Identity,IsValid,ObjectState | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Consent-to-application.csv" -NoTypeInformation -Encoding UTF8
    
    # XLSX
    if (Get-Module -ListAvailable -Name ImportExcel)
    {
        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Consent-to-application.csv")
        {
            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Consent-to-application.csv") -gt 0)
            {
                $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Consent-to-application.csv" -Delimiter ","
                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\XLSX\Consent-to-application.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Consent to application" -CellStyleSB {
                param($WorkSheet)
                # BackgroundColor and FontColor for specific cells of TopRow
                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                Set-Format -Address $WorkSheet.Cells["A1:J1"] -BackgroundColor $BackgroundColor -FontColor White
                # HorizontalAlignment "Center" of columns A-D and F-J
                $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"
                $WorkSheet.Cells["F:J"].Style.HorizontalAlignment="Center"
                # ConditionalFormatting
                Add-ConditionalFormatting -Address $WorkSheet.Cells["D:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Consent to application.",$D1)))' -BackgroundColor Red
                }
            }
        }
    }

    # AuditData

    # CSV
    $Results = @()
    ForEach($Record in $Import)
    {
        $AuditData = $Record.AuditData | ConvertFrom-Json
        $ExtendedProperties = $AuditData.ExtendedProperties
        $ModifiedProperties = $AuditData.ModifiedProperties
        $Target = $AuditData.Target

        $Line = [PSCustomObject]@{
        "CreationDate"                  = $Record.CreationDate
        "Id"                            = $AuditData.Id
        "RecordType"                    = $Record.RecordType
        "Operation"                     = $AuditData.Operation
        "OrganizationId"                = $AuditData.OrganizationId
        "ResultStatus"                  = $AuditData.ResultStatus
        "UserKey"                       = $AuditData.UserKey
        "UserType"                      = $AuditData.UserType
        "Version"                       = $AuditData.Version
        "Workload"                      = $AuditData.Workload
        "ObjectId"                      = $AuditData.ObjectId
        "UserId"                        = $AuditData.UserId
        "AzureActiveDirectoryEventType" = $AuditData.AzureActiveDirectoryEventType
        "User-Agent"                    = $ExtendedProperties | Where-Object { $_.Name -eq "additionalDetails" } | Select-Object -ExpandProperty Value | ForEach-Object{($_ -split ",")[0]} | ForEach-Object{($_ -split ":")[1]} | ForEach-Object {$_ -replace '"',''}
        "AppId"                         = $ExtendedProperties | Where-Object { $_.Name -eq "additionalDetails" } | Select-Object -ExpandProperty Value | ForEach-Object{($_ -split ",")[1]} | ForEach-Object{($_ -split ":")[1]} | ForEach-Object {$_ -replace '"',''} | ForEach-Object {$_ -replace '}',''}
        "ExtendedAuditEventCategory"    = $ExtendedProperties | Where-Object { $_.Name -eq "extendedAuditEventCategory" } | Select-Object -ExpandProperty Value
        "IsAdminConsent"                = $ModifiedProperties | Where-Object { $_.Name -eq "ConsentContext.IsAdminConsent" } | Select-Object -ExpandProperty NewValue
        "IsAppOnly"                     = $ModifiedProperties | Where-Object { $_.Name -eq "ConsentContext.IsAppOnly" } | Select-Object -ExpandProperty NewValue
        "OnBehalfOfAll"                 = $ModifiedProperties | Where-Object { $_.Name -eq "ConsentContext.ConsentContext.OnBehalfOfAll" } | Select-Object -ExpandProperty NewValue
        "Tags"                          = $ModifiedProperties | Where-Object { $_.Name -eq "ConsentContext.Tags" } | Select-Object -ExpandProperty NewValue
        "Permissions"                   = ($ModifiedProperties | Where-Object { $_.Name -eq "ConsentAction.Permissions" } | Select-Object -ExpandProperty NewValue | ForEach-Object{($_ -split "Scope: ")[1]} | ForEach-Object{($_ -split "CreatedDateTime: ")[0]}).Trim() | ForEach-Object {$_ -replace ',$',''}
        "TargetId"                      = $ModifiedProperties | Where-Object { $_.Name -eq "TargetId.ServicePrincipalNames" } | Select-Object -ExpandProperty NewValue
        "ActorContextId"                = $AuditData.ActorContextId
        "InterSystemsId"                = $AuditData.InterSystemsId
        "IntraSystemId"                 = $AuditData.IntraSystemId
        "SupportTicketId"               = $AuditData.SupportTicketId
        "Target"                        = $Target | Where-Object { $_.Type -eq "1" } | Select-Object -ExpandProperty ID
        "TargetContextId"               = $AuditData.TargetContextId
        }

        $Results += $Line
    }

    $Results | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Consent-to-application_AuditData.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Get-Module -ListAvailable -Name ImportExcel)
    {
        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Consent-to-application_AuditData.csv")
        {
            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Consent-to-application_AuditData.csv") -gt 0)
            {
                $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Consent-to-application_AuditData.csv" -Delimiter ","
                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\XLSX\Consent-to-application_AuditData.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Consent to application." -CellStyleSB {
                param($WorkSheet)
                # BackgroundColor and FontColor for specific cells of TopRow
                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                Set-Format -Address $WorkSheet.Cells["A1:AB1"] -BackgroundColor $BackgroundColor -FontColor White
                # HorizontalAlignment "Center" of columns A-AB
                $WorkSheet.Cells["A:AB"].Style.HorizontalAlignment="Center"
                # ConditionalFormatting - Consent to application.
                Add-ConditionalFormatting -Address $WorkSheet.Cells["C:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Consent to application.",$D1)))' -BackgroundColor Red
                # ConditionalFormatting - AppId
                Add-ConditionalFormatting -Address $WorkSheet.Cells["O:O"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("e9a7fea1-1cc0-4cd9-a31b-9137ca5deedd",$O1)))' -BackgroundColor Red # eM Client
                # ConditionalFormatting - Permissions
                Add-ConditionalFormatting -Address $WorkSheet.Cells["U:U"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("IMAP.AccessAsUser.All",$U1)))' -BackgroundColor Red
                # ConditionalFormatting - Target
                Add-ConditionalFormatting -Address $WorkSheet.Cells["AA:AA"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("eM Client",$AA1)))' -BackgroundColor Red
                }
            }
        }
    }
}

# Anti-Forensics Techniques

# Operation: New-UnifiedAuditLogRetentionPolicy
$Import = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object { $_.Operations -eq "New-UnifiedAuditLogRetentionPolicy" } | Sort-Object { $_.CreationDate -as [datetime] } -Descending
$Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
if ($Count -gt 0)
{
    Write-Host "[Alert] Anti-Forensics Technique detected: New-UnifiedAuditLogRetentionPolicy ($Count)" -ForegroundColor Red
}

# Operation: Set-UnifiedAuditLogRetentionPolicy
$Import = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object { $_.Operations -eq "Set-UnifiedAuditLogRetentionPolicy" } | Sort-Object { $_.CreationDate -as [datetime] } -Descending
$Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
if ($Count -gt 0)
{
    Write-Host "[Alert] Anti-Forensics Technique detected: Set-UnifiedAuditLogRetentionPolicy ($Count)" -ForegroundColor Red
}

# Operation: Remove-UnifiedAuditLogRetentionPolicy
$Import = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object { $_.Operations -eq "Remove-UnifiedAuditLogRetentionPolicy" } | Sort-Object { $_.CreationDate -as [datetime] } -Descending
$Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
if ($Count -gt 0)
{
    Write-Host "[Alert] Anti-Forensics Technique detected: Remove-UnifiedAuditLogRetentionPolicy ($Count)" -ForegroundColor Red
}

# Operation: Set-AdminAuditLogConfig + UnifiedAuditIngestionEnabled-False --> Disable Unified Audit Logging
# https://docs.datadoghq.com/security/default_rules/m365-admin-audit-log-disabled/
$AuditData = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object { $_.RecordType -eq "ExchangeAdmin" } | Where-Object { $_.Operations -eq "Set-AdminAuditLogConfig" } | Sort-Object { $_.CreationDate -as [datetime] } -Descending | Select-Object -ExpandProperty AuditData
$Import = $AuditData | ConvertFrom-Json | Select-Object -ExpandProperty Parameters | Where-Object { $_.Name -eq "UnifiedAuditLogIngestionEnabled" } | Where-Object { $_.Value -eq "False" }
$Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
if ($Count -gt 0)
{
    Write-Host "[Alert] Anti-Forensics Technique detected: Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled `$false ($Count)" -ForegroundColor Red
}

# $Import | Select-Object -ExpandProperty AuditData | ConvertFrom-Json | Select-Object -ExpandProperty Parameters | Where-Object { $_.Name -eq "UnifiedAuditLogIngestionEnabled" } | Select-Object -ExpandProperty Value
# True

# Set-AdminAuditLogConfig -UnifiedAuditLogIngestionEnabled $false
# https://docs.datadoghq.com/security/default_rules/?search=microsoft+365

# AdminAuditLogAgeLimit (dd.hh:mm:ss) --> The default value is 90 days.
# Get-AdminAuditLogConfig | Format-List AdminAuditLogAgeLimit
# AdminAuditLogAgeLimit : 90.00:00:00
#
# Get-AdminAuditLogConfig | Select-Object AdminAuditLogAgeLimit
# AdminAuditLogAgeLimit
# ---------------------
# 90.00:00:00

# Check if UAL is enabled
# Get-AdminAuditLogConfig | Select-Object -ExpandProperty UnifiedAuditLogIngestionEnabled --> True|False

# Check for UAL Policy
# https://learn.microsoft.com/en-us/powershell/module/exchange/get-unifiedauditlogretentionpolicy?view=exchange-ps
# Get-UnifiedAuditLogRetentionPolicy --> This cmdlet is available only in Security & Compliance PowerShell.
# Connect-IPPSSession -UserPrincipalName <upn> --> Connecting to Security and Compliance Center (SCC)
# https://learn.microsoft.com/en-us/powershell/module/exchange/connect-ippssession?view=exchange-ps
# Get-UnifiedAuditLogRetentionPolicy

$EndTime_Processing = (Get-Date)
$Time_Processing = ($EndTime_Processing-$StartTime_Processing)
('UnifiedAuditLog Processing duration:      {0} h {1} min {2} sec' -f $Time_Processing.Hours, $Time_Processing.Minutes, $Time_Processing.Seconds) >> "$OUTPUT_FOLDER\Stats.txt"

}

Start-Processing

#############################################################################################################################################################################################

Function Get-IPLocation {

$StartTime_DataEnrichment = (Get-Date)

# Count IP addresses
Write-Output "[Info]  Parsing AuditData (JSON) for ClientIP and ClientIPAddress Properties ..."
New-Item "$OUTPUT_FOLDER\ClientIP" -ItemType Directory -Force | Out-Null
$ClientIP = Import-Csv -Path "$LogFile" -Delimiter "," | Select-Object -ExpandProperty AuditData | ConvertFrom-Json | Select-Object -ExpandProperty ClientIP -ErrorAction SilentlyContinue | Where-Object { $_.Trim() -ne "" }
$ClientIPAddress = Import-Csv -Path "$LogFile" -Delimiter "," | Select-Object -ExpandProperty AuditData | ConvertFrom-Json | Select-Object -ExpandProperty ClientIPAddress -ErrorAction SilentlyContinue | Where-Object { $_.Trim() -ne "" }
$Data = $ClientIP + $ClientIPAddress

$Unique = $Data | Sort-Object -Unique
$Unique | Out-File "$OUTPUT_FOLDER\ClientIP\IP-All.txt"

[int]$Count = ($Unique | Measure-Object).Count
$UniqueIP = '{0:N0}' -f $Count
[int]$Total = ($Data | Measure-Object).Count
$TotalIP = '{0:N0}' -f $Total
Write-Output "[Info]  $UniqueIP IP addresses found ($TotalIP)"

# IPv4
# https://ipinfo.io/bogon
$IPv4 = "(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
$Private = "^(192\.168|10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.)"
$Special = "^(0\.0\.0\.0|127\.0\.0\.1|169\.254\.|224\.0\.0)"
Get-Content "$OUTPUT_FOLDER\ClientIP\IP-All.txt" | Select-String -Pattern $IPv4 -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique -Property { [System.Version]$_ } | Out-File "$OUTPUT_FOLDER\ClientIP\IPv4-All.txt"
Get-Content "$OUTPUT_FOLDER\ClientIP\IP-All.txt" | Select-String -Pattern $IPv4 -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique -Property { [System.Version]$_ } | Where-Object {$_ -notmatch $Private} | Where-Object {$_ -notmatch $Special} | Out-File "$OUTPUT_FOLDER\ClientIP\IPv4.txt"

# Count
$Total = (Get-Content "$OUTPUT_FOLDER\ClientIP\IPv4-All.txt" | Measure-Object).Count # Public (Unique) + Private (Unique) --> Note: Extracts IPv4 addresses of IPv4-compatible IPv6 addresses.
$Public = (Get-Content "$OUTPUT_FOLDER\ClientIP\IPv4.txt" | Measure-Object).Count # Public (Unique)
Write-Output "[Info]  $Public Public IPv4 addresses found ($Total)"

# IPv6
# https://ipinfo.io/bogon
$IPv6 = ":(?::[a-f\d]{1,4}){0,5}(?:(?::[a-f\d]{1,4}){1,2}|:(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})))|[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}|:)|(?::(?:[a-f\d]{1,4})?|(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))))|:(?:(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|[a-f\d]{1,4}(?::[a-f\d]{1,4})?|))|(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|:[a-f\d]{1,4}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){0,2})|:))|(?:(?::[a-f\d]{1,4}){0,2}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:))|(?:(?::[a-f\d]{1,4}){0,3}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:))|(?:(?::[a-f\d]{1,4}){0,4}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:))"
$Bogon = "^(::1|::ffff:|100::|2001:10::|2001:db8::|fc00::|fe80::|fec0::|ff00::)"
Get-Content "$OUTPUT_FOLDER\ClientIP\IP-All.txt" | Select-String -Pattern $IPv6 -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique | Out-File "$OUTPUT_FOLDER\ClientIP\IPv6-All.txt"
Get-Content "$OUTPUT_FOLDER\ClientIP\IP-All.txt" | Select-String -Pattern $IPv6 -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique | Where-Object {$_ -notmatch $Bogon} | Out-File "$OUTPUT_FOLDER\ClientIP\IPv6.txt"

# Count
$Total = (Get-Content "$OUTPUT_FOLDER\ClientIP\IPv6-All.txt" | Measure-Object).Count # including Bogus IPv6 addresses (e.g. IPv4-compatible IPv6 addresses)
$Public = (Get-Content "$OUTPUT_FOLDER\ClientIP\IPv6.txt" | Measure-Object).Count
Write-Output "[Info]  $Public Public IPv6 addresses found ($Total)"

# IP.txt
Write-Output "IPAddress" | Out-File "$OUTPUT_FOLDER\ClientIP\IP.txt" # Header

# IPv4.txt
if (Test-Path "$OUTPUT_FOLDER\ClientIP\IPv4.txt")
{
    if ((Get-Item "$OUTPUT_FOLDER\ClientIP\IPv4.txt").Length -gt 0kb)
    {
        Get-Content -Path "$OUTPUT_FOLDER\ClientIP\IPv4.txt" | Out-File "$OUTPUT_FOLDER\ClientIP\IP.txt" -Append
    }
}

# IPv6.txt
if (Test-Path "$OUTPUT_FOLDER\ClientIP\IPv6.txt")
{
    if ((Get-Item "$OUTPUT_FOLDER\ClientIP\IPv6.txt").Length -gt 0kb)
    {
        Get-Content -Path "$OUTPUT_FOLDER\ClientIP\IPv6.txt" | Out-File "$OUTPUT_FOLDER\ClientIP\IP.txt" -Append
    }
}

# Authenticated-Operations.txt
Write-Output "IPAddress" | Out-File "$OUTPUT_FOLDER\ClientIP\Authenticated-Operations.txt" # Header
$ClientIP = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Custom.csv" -Delimiter "," | Where-Object { $_.Operation -ne 'UserLoginFailed' } | Where-Object { $_.ClientIP -ne '' } | Select-Object -ExpandProperty ClientIP -Unique 
$ClientIPAddress = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Custom.csv" -Delimiter "," | Where-Object { $_.Operation -ne 'UserLoginFailed' } | Where-Object { $_.ClientIPAddress -ne '' } | Select-Object -ExpandProperty ClientIPAddress -Unique 
$Authenticated = $ClientIP + $ClientIPAddress | Sort-Object -Unique | Sort-Object {$_ -as [Version]}
$Authenticated | Out-File "$OUTPUT_FOLDER\ClientIP\Authenticated-Operations.txt" -Encoding UTF8 -Append

# IPinfo CLI (50k lookups per month, Geolocation data only)
if (Test-Path "$($IPinfo)")
{
    if (Test-Path "$OUTPUT_FOLDER\ClientIP\IP.txt")
    {
        if ((Get-Item "$OUTPUT_FOLDER\ClientIP\IP.txt").Length -gt 0kb)
        {
            # Internet Connectivity Check (Vista+)
            $NetworkListManager = [Activator]::CreateInstance([Type]::GetTypeFromCLSID([Guid]‘{DCB00C01-570F-4A9B-8D69-199FDBA5723B}’)).IsConnectedToInternet

            if (!($NetworkListManager -eq "True"))
            {
                Write-Host "[Error] Your computer is NOT connected to the Internet. IP addresses cannot be checked via IPinfo API." -ForegroundColor Red
            }
            else
            {
                # Check if IPinfo.io is reachable
                if (!(Test-NetConnection -ComputerName ipinfo.io -Port 443).TcpTestSucceeded)
                {
                    Write-Host "[Error] ipinfo.io is NOT reachable. IP addresses cannot be checked via IPinfo API." -ForegroundColor Red
                }
                else
                {
                    # Map IPs
                    # https://ipinfo.io/map
                    New-Item "$OUTPUT_FOLDER\ClientIP\IPinfo" -ItemType Directory -Force | Out-Null
                    Get-Content "$OUTPUT_FOLDER\ClientIP\IP.txt" | & $IPinfo map | Out-File "$OUTPUT_FOLDER\ClientIP\IPinfo\Map_All-Operations.txt"
                    Get-Content "$OUTPUT_FOLDER\ClientIP\Authenticated-Operations.txt" | & $IPinfo map | Out-File "$OUTPUT_FOLDER\ClientIP\IPinfo\Map_Authenticated-Operations.txt"

                    # Access Token
                    # https://ipinfo.io/signup?ref=cli
                    if (!("$Token" -eq "access_token"))
                    {
                        # Summarize IPs
                        # https://ipinfo.io/summarize-ips

                        # TXT (lists VPNs)
                        Get-Content "$OUTPUT_FOLDER\ClientIP\IP.txt" | & $IPinfo summarize -t $Token | Out-File "$OUTPUT_FOLDER\ClientIP\IPinfo\Summary.txt"

                        # CSV --> No Privacy Detection --> Standard ($249/month w/ 250k lookups)
                        Get-Content "$OUTPUT_FOLDER\ClientIP\IP.txt" | & $IPinfo --csv -t $Token | Out-File "$OUTPUT_FOLDER\ClientIP\IPinfo\IPinfo.csv" -Encoding UTF8

                        # Custom CSV (Free)
                        if (Test-Path "$OUTPUT_FOLDER\ClientIP\IPinfo\IPinfo.csv")
                        {
                            if([int](& $xsv count "$OUTPUT_FOLDER\ClientIP\IPinfo\IPinfo.csv") -gt 0)
                            {
                                $IPinfoRecords = Import-Csv "$OUTPUT_FOLDER\ClientIP\IPinfo\IPinfo.csv" -Delimiter "," -Encoding UTF8
                                
                                $CustomCsv = @()

                                ForEach($IPinfoRecord in $IPinfoRecords)
                                {
                                    $Line = [PSCustomObject]@{
                                        "IP"           = $IPinfoRecord.ip
                                        "City"         = $IPinfoRecord.city
                                        "Region"       = $IPinfoRecord.region
                                        "Country"      = $IPinfoRecord.country
                                        "Country Name" = $IPinfoRecord.country_name
                                        "EU"           = $IPinfoRecord.isEU
                                        "Location"     = $IPinfoRecord.loc
                                        "ASN"          = $IPinfoRecord | Select-Object -ExpandProperty org | ForEach-Object{($_ -split "\s+")[0]}
                                        "OrgName"      = $IPinfoRecord | Select-Object -ExpandProperty org | ForEach-Object {$_ -replace "^AS[0-9]+ "}
                                        "Postal Code"  = $IPinfoRecord.postal
                                        "Timezone"     = $IPinfoRecord.timezone
                                    }

                                    $CustomCsv += $Line
                                }

                                $CustomCsv | Sort-Object {$_.IP -as [Version]} | Export-Csv -Path "$OUTPUT_FOLDER\ClientIP\IPinfo\IPinfo-Custom.csv" -NoTypeInformation -Encoding UTF8
                            }
                        }

                        # Custom XLSX (Free)
                        if (Get-Module -ListAvailable -Name ImportExcel)
                        {
                            if (Test-Path "$OUTPUT_FOLDER\ClientIP\IPinfo\IPinfo-Custom.csv")
                            {
                                if([int](& $xsv count "$OUTPUT_FOLDER\ClientIP\IPinfo\IPinfo-Custom.csv") -gt 0)
                                {
                                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\ClientIP\IPinfo\IPinfo-Custom.csv" -Delimiter "," | Sort-Object {$_.IP -as [Version]}
                                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\ClientIP\IPinfo\IPinfo-Custom.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -IncludePivotTable -PivotTableName "PivotTable" -PivotRows "Country Name" -PivotData @{"IP"="Count"} -WorkSheetname "IPinfo (Free)" -CellStyleSB {
                                    param($WorkSheet)
                                    # BackgroundColor and FontColor for specific cells of TopRow
                                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                    Set-Format -Address $WorkSheet.Cells["A1:K1"] -BackgroundColor $BackgroundColor -FontColor White
                                    # HorizontalAlignment "Center" of columns A-K
                                    $WorkSheet.Cells["A:K"].Style.HorizontalAlignment="Center"
                                    }
                                }
                            }
                        }

                        # Count
                        if (Test-Path "$OUTPUT_FOLDER\ClientIP\IPinfo\IPinfo-Custom.csv")
                        {
                            if([int](& $xsv count "$OUTPUT_FOLDER\ClientIP\IPinfo\IPinfo-Custom.csv") -gt 0)
                            {
                                # Suspicious ASN (Autonomous System Number)
                                $Data = Import-Csv -Path "$OUTPUT_FOLDER\ClientIP\IPinfo\IPinfo-Custom.csv" -Delimiter ","
                                $Total = ($Data | Select-Object ASN | Measure-Object).Count
                                $Count = ($Data | Select-Object ASN -Unique | Measure-Object).Count
                                $ASN = $AsnBlacklist_HashTable.Count
                                Write-Output "[Info]  $Count ASN found ($Total)"
                                Write-Output "[Info]  Initializing ASN Blacklist ($ASN) ..."

                                # Iterating over the HashTable
                                foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
                                {
                                    $Import = $Data | Where-Object { $_.ASN -eq "AS$ASN" }
                                    $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
                                    if ($Count -gt 0)
                                    {
                                        $OrgName = $AsnBlacklist_HashTable["$ASN"][0]
                                        Write-Host "[Alert] Suspicious ASN detected: AS$ASN - $OrgName ($Count)" -ForegroundColor Red
                                    }
                                }

                                # Suspicious Countries
                                $Data = Import-Csv -Path "$OUTPUT_FOLDER\ClientIP\IPinfo\IPinfo-Custom.csv" -Delimiter ","
                                $Total = ($Data | Select-Object Country | Measure-Object).Count
                                $Count = ($Data | Select-Object Country -Unique | Measure-Object).Count
                                $Countries = $CountryBlacklist_HashTable.Count
                                Write-Output "[Info]  $Count Countries found ($Total)"
                                Write-Output "[Info]  Initializing Country Blacklist ($Countries) ..."

                                # Iterating over the HashTable
                                foreach ($CountryName in $CountryBlacklist_HashTable.Keys) 
                                {
                                    $Import = $Data | Where-Object { $_."Country Name" -eq "$CountryName" }
                                    $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
                                    if ($Count -gt 0)
                                    {
                                        Write-Host "[Alert] Suspicious Country detected: $CountryName ($Count)" -ForegroundColor Red
                                    }
                                }
                            }
                        }

                        # XLSX (Free)
                        if (Get-Module -ListAvailable -Name ImportExcel)
                        {
                            if (Test-Path "$OUTPUT_FOLDER\ClientIP\IPinfo\IPinfo.csv")
                            {
                                if([int](& $xsv count "$OUTPUT_FOLDER\ClientIP\IPinfo\IPinfo.csv") -gt 0)
                                {
                                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\ClientIP\IPinfo\IPinfo.csv" -Delimiter "," | Select-Object ip,city,region,country,country_name,isEU,loc,org,postal,timezone | Sort-Object {$_.ip -as [Version]}
                                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\ClientIP\IPinfo\IPinfo.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "IPinfo (Free)" -CellStyleSB {
                                    param($WorkSheet)
                                    # BackgroundColor and FontColor for specific cells of TopRow
                                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                    Set-Format -Address $WorkSheet.Cells["A1:J1"] -BackgroundColor $BackgroundColor -FontColor White
                                    # HorizontalAlignment "Center" of columns A-J
                                    $WorkSheet.Cells["A:J"].Style.HorizontalAlignment="Center"
                                    }
                                }
                            }
                        }

                        # Create HashTable and import 'IPinfo-Custom.csv'
                        $HashTable = @{}
                        if (Test-Path "$OUTPUT_FOLDER\ClientIP\IPinfo\IPinfo-Custom.csv")
                        {
                            if([int](& $xsv count "$OUTPUT_FOLDER\ClientIP\IPinfo\IPinfo-Custom.csv") -gt 0)
                            {
                                Import-Csv "$OUTPUT_FOLDER\ClientIP\IPinfo\IPinfo-Custom.csv" -Delimiter "," -Encoding UTF8 | ForEach-Object { $HashTable[$_.IP] = $_.City,$_.Region,$_.Country,$_."Country Name",$_.EU,$_.Location,$_.ASN,$_.OrgName,$_."Postal Code",$_.Timezone }

                                # Count Ingested Properties
                                $Count = $HashTable.Count
                                Write-Output "[Info]  Initializing 'IPinfo-Custom.csv' Lookup Table ($Count) ..."
                            }
                        }

                        # Hunt
                        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Custom.csv")
                        {
                            if([int](& $xsv count "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Custom.csv") -gt 0)
                            {
                                $Records = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Custom.csv" -Delimiter "," -Encoding UTF8

                                # CSV
                                $Results = @()
                                ForEach($Record in $Records)
                                {
                                    # ClientIP or ClientIPAddress
                                    $IP = $Record.ClientIP | ForEach-Object {$_ -replace "^::ffff:"} # Remove Prefix of IPv4-mapped IPv6 address

                                    if ($IP -eq "")
                                    {
                                        $IP = $Record.ClientIPAddress
                                    }

                                    # Check if HashTable contains IP
                                    if($HashTable.ContainsKey("$IP"))
                                    {
                                        $City        = $HashTable["$IP"][0]
                                        $Region      = $HashTable["$IP"][1]
                                        $Country     = $HashTable["$IP"][2]
                                        $CountryName = $HashTable["$IP"][3]
                                        $EU          = $HashTable["$IP"][4]
                                        $Location    = $HashTable["$IP"][5]
                                        $ASN         = $HashTable["$IP"][6]
                                        $OrgName     = $HashTable["$IP"][7]
                                        $PostalCode  = $HashTable["$IP"][8]
                                        $Timezone    = $HashTable["$IP"][9]
                                    }
                                    else
                                    {
                                        $City        = ""
                                        $Region      = ""
                                        $Country     = ""
                                        $CountryName = ""
                                        $EU          = ""
                                        $Location    = ""
                                        $ASN         = ""
                                        $OrgName     = ""
                                        $PostalCode  = ""
                                        $Timezone    = ""
                                    }

                                    $Line = [PSCustomObject]@{
                                        "CreationDate"          = $Record.CreationDate # UTC
                                        "UserId"                = $Record.UserId
                                        "RecordType"            = $Record.RecordType
                                        "Operation"             = $Record.Operation
                                        "ObjectId"              = $Record.ObjectId
                                        "ClientIP"              = $Record.ClientIP
                                        "ClientIPAddress"       = $Record.ClientIPAddress
                                        "UserAgent"             = $Record.UserAgent
                                        "ClientInfoString"      = $Record.ClientInfoString
                                        "City"                  = $City
                                        "Region"                = $Region
                                        "Country"               = $Country
                                        "Country Name"          = $CountryName
                                        "EU"                    = $EU
                                        "Location"              = $Location
                                        "ASN"                   = $ASN
                                        "OrgName"               = $OrgName
                                        "Postal Code"           = $PostalCode
                                        "Timezone"              = $Timezone
                                        "SessionId"             = $Record.SessionId
                                        "InterSystemsId"        = $Record.InterSystemsId
                                        "OS"                    = $Record.OS
                                        "BrowserType"           = $Record.BrowserType
                                        "IsCompliantAndManaged" = $Record.IsCompliantAndManaged
                                        "Workload"              = $Record.Workload
                                    }

                                    $Results += $Line
                                }

                                $Results | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -NoTypeInformation -Encoding UTF8
                            }
                        }

                        # XLSX
                        if (Get-Module -ListAvailable -Name ImportExcel)
                        {
                            if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv")
                            {
                                if([int](& $xsv count "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv") -gt 0)
                                {
                                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter ","
                                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\XLSX\Hunt.xlsx" -NoHyperLinkConversion * -NoNumberConversion * -FreezePane 2,5 -BoldTopRow -AutoSize -AutoFilter -IncludePivotTable -PivotTableName "PivotTable" -WorkSheetname "Hunt" -CellStyleSB {
                                    param($WorkSheet)
                                    # BackgroundColor and FontColor for specific cells of TopRow
                                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                    Set-Format -Address $WorkSheet.Cells["A1:Y1"] -BackgroundColor $BackgroundColor -FontColor White
                                    # HorizontalAlignment "Center" of columns A-D and F-Y
                                    $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"
                                    $WorkSheet.Cells["F:Y"].Style.HorizontalAlignment="Center"

                                    # Iterating over the ASN-Blacklist HashTable
                                    foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
                                    {
                                        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$P1)))' -f $ASN
                                        Add-ConditionalFormatting -Address $WorkSheet.Cells["P:P"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
                                    }

                                    # Iterating over the Country-Blacklist HashTable
                                    foreach ($Country in $CountryBlacklist_HashTable.Keys) 
                                    {
                                        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$M1)))' -f $Country
                                        Add-ConditionalFormatting -Address $WorkSheet.Cells["M:M"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
                                    }

                                    # ConditionalFormatting - ObjectId
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["E:E"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("e9a7fea1-1cc0-4cd9-a31b-9137ca5deedd",$E1)))' -BackgroundColor Red # eM Client
                                    # ConditionalFormatting - Suspicious Operations
                                    $Cells = "D:D"
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Add app role assignment grant to user",$D1)))' -BackgroundColor Red # BEC
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Add delegated permission grant",$D1)))' -BackgroundColor Red # BEC
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Add service principal",$D1)))' -BackgroundColor Red # BEC
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Add-MailboxPermission",$D1)))' -BackgroundColor Red # BEC
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Consent to application",$D1)))' -BackgroundColor Red # BEC
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Disable-InboxRule",$D1)))' -BackgroundColor Red # BEC
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Enable-InboxRule",$D1)))' -BackgroundColor Red # BEC
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("New-InboundConnector",$D1)))' -BackgroundColor Red # BEC
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("New-InboxRule",$D1)))' -BackgroundColor Red # BEC
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Remove-InboundConnector",$D1)))' -BackgroundColor Red # BEC
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Remove-InboxRule",$D1)))' -BackgroundColor Red # BEC
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Set-InboundConnector",$D1)))' -BackgroundColor Red # BEC
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Set-InboxRule",$D1)))' -BackgroundColor Red # BEC
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '$D1="Set-Mailbox"' -BackgroundColor Red # BEC
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '$D1="UpdateInboxRules"' -BackgroundColor Red # BEC
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Set-MailboxJunkEmailConfiguration",$D1)))' -BackgroundColor Red # BEC
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("SearchStarted",$D1)))' -BackgroundColor Red # Content Search Abuse
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("SearchExportDownloaded",$D1)))' -BackgroundColor Red # Content Search Abuse
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("ViewedSearchExported",$D1)))' -BackgroundColor Red # Content Search Abuse
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("New-UnifiedAuditLogRetentionPolicy",$D1)))' -BackgroundColor Red # Anti-Forensics
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Set-UnifiedAuditLogRetentionPolicy",$D1)))' -BackgroundColor Red # Anti-Forensics
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Remove-UnifiedAuditLogRetentionPolicy",$D1)))' -BackgroundColor Red # Anti-Forensics
                                    # ConditionalFormatting - Suspicious ClientInfoString
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["I:I"] -WorkSheet $WorkSheet -RuleType 'Expression' '=AND($I1="Client=OWA;Action=ViaProxy",$P1<>"AS53813",$P1<>"AS62044")' -BackgroundColor Red # AiTM Proxy Server
                                    }
                                }
                            }
                        }

                        # ASN 
                        
                        # CSV (Stats)
                        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv")
                        {
                            if([int](& $xsv count "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv") -gt 0)
                            {
                                $Total = (Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," | Select-Object ASN | Where-Object {$_.ASN -ne '' } | Measure-Object).Count
                                Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," | Select-Object ASN,OrgName | Where-Object {$_.ASN -ne '' } | Where-Object {$null -ne ($_.PSObject.Properties | ForEach-Object {$_.Value})} | Group-Object ASN,OrgName | Select-Object Count,@{Name='ASN'; Expression={ $_.Values[0] }},@{Name='OrgName'; Expression={ $_.Values[1] }},@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Stats\CSV\ASN.csv" -NoTypeInformation -Encoding UTF8
                            }
                        }

                        # XLSX (Stats)
                        if (Get-Module -ListAvailable -Name ImportExcel)
                        {
                            if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Stats\CSV\ASN.csv")
                            {
                                if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Stats\CSV\ASN.csv") -gt 0)
                                {
                                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Stats\CSV\ASN.csv" -Delimiter ","
                                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Stats\XLSX\ASN.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ASN" -CellStyleSB {
                                    param($WorkSheet)
                                    # BackgroundColor and FontColor for specific cells of TopRow
                                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                    Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor White
                                    # HorizontalAlignment "Center" of columns A-D
                                    $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"

                                    # Iterating over the ASN-Blacklist HashTable
                                    foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
                                    {
                                        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$B1)))' -f $ASN
                                        Add-ConditionalFormatting -Address $WorkSheet.Cells["A:D"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
                                    }

                                    }
                                }
                            }
                        }

                        # ClientIP / Country Name
                        
                        # CSV (Stats)
                        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv")
                        {
                            if([int](& $xsv count "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv") -gt 0)
                            {
                                $Total = (Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," | Select-Object ClientIP | Where-Object {$_.ClientIP -ne '' } | Measure-Object).Count
                                Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," -Encoding UTF8 | Select-Object ClientIP,Country,"Country Name",ASN,OrgName | Where-Object {$_.ClientIP -ne '' } | Where-Object {$_."Country Name" -ne '' } | Where-Object {$null -ne ($_.PSObject.Properties | ForEach-Object {$_.Value})} | Group-Object ClientIP,Country,"Country Name",ASN,OrgName | Select-Object Count,@{Name='ClientIP'; Expression={ $_.Values[0] }},@{Name='Country'; Expression={ $_.Values[1] }},@{Name='Country Name'; Expression={ $_.Values[2] }},@{Name='ASN'; Expression={ $_.Values[3] }},@{Name='OrgName'; Expression={ $_.Values[4] }},@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Stats\CSV\ClientIP.csv" -NoTypeInformation -Encoding UTF8
                            }
                        }

                        # XLSX (Stats)
                        if (Get-Module -ListAvailable -Name ImportExcel)
                        {
                            if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Stats\CSV\ClientIP.csv")
                            {
                                if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Stats\CSV\ClientIP.csv") -gt 0)
                                {
                                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Stats\CSV\ClientIP.csv" -Delimiter ","
                                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Stats\XLSX\ClientIP.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ClientIP" -CellStyleSB {
                                    param($WorkSheet)
                                    # BackgroundColor and FontColor for specific cells of TopRow
                                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                    Set-Format -Address $WorkSheet.Cells["A1:G1"] -BackgroundColor $BackgroundColor -FontColor White
                                    # HorizontalAlignment "Center" of columns A-G
                                    $WorkSheet.Cells["A:G"].Style.HorizontalAlignment="Center"

                                    # Iterating over the ASN-Blacklist HashTable
                                    foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
                                    {
                                        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$E1)))' -f $ASN
                                        Add-ConditionalFormatting -Address $WorkSheet.Cells["E:F"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
                                    }

                                    # Iterating over the Country-Blacklist HashTable
                                    foreach ($Country in $CountryBlacklist_HashTable.Keys) 
                                    {
                                        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$D1)))' -f $Country
                                        Add-ConditionalFormatting -Address $WorkSheet.Cells["C:D"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
                                    }
                                    
                                    }
                                }
                            }
                        }

                        # Country / Country Name

                        # CSV (Stats)
                        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv")
                        {
                            if([int](& $xsv count "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv") -gt 0)
                            {
                                $Total = (Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," | Select-Object Country | Where-Object {$_.Country -ne '' } | Measure-Object).Count
                                Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," | Select-Object Country,"Country Name" | Where-Object {$_.Country -ne '' } | Where-Object {$null -ne ($_.PSObject.Properties | ForEach-Object {$_.Value})} | Group-Object Country,"Country Name" | Select-Object Count,@{Name='Country'; Expression={ $_.Values[0] }},@{Name='Country Name'; Expression={ $_.Values[1] }},@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Stats\CSV\Country.csv" -NoTypeInformation -Encoding UTF8
                                
                                # Countries
                                $Countries = (Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," | Select-Object Country -Unique | Where-Object { $_.Country -ne '' } | Measure-Object).Count

                                # Cities
                                $Cities = (Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," | Select-Object City -Unique | Where-Object { $_.City -ne '' } | Measure-Object).Count

                                Write-Output "[Info]  $Countries Countries and $Cities Cities found"
                            }
                        }

                        # XLSX (Stats)
                        if (Get-Module -ListAvailable -Name ImportExcel)
                        {
                            if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Stats\CSV\Country.csv")
                            {
                                if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Stats\CSV\Country.csv") -gt 0)
                                {
                                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Stats\CSV\Country.csv" -Delimiter ","
                                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Stats\XLSX\Country.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Countries" -CellStyleSB {
                                    param($WorkSheet)
                                    # BackgroundColor and FontColor for specific cells of TopRow
                                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                    Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor White
                                    # HorizontalAlignment "Center" of columns A-D
                                    $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"

                                    # Iterating over the Country-Blacklist HashTable
                                    foreach ($Country in $CountryBlacklist_HashTable.Keys) 
                                    {
                                        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$C1)))' -f $Country
                                        Add-ConditionalFormatting -Address $WorkSheet.Cells["A:D"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
                                    }

                                    }
                                }
                            }
                        }

                        # OAuth Applications

                        # Create HashTable and import 'Application-Blacklist.csv'
                        $ApplicationBlacklist_HashTable = @{}
                        if (Test-Path "$SCRIPT_DIR\Blacklists\Application-Blacklist.csv")
                        {
                            if([int](& $xsv count "$SCRIPT_DIR\Blacklists\Application-Blacklist.csv") -gt 0)
                            {
                                Import-Csv "$SCRIPT_DIR\Blacklists\Application-Blacklist.csv" -Delimiter "," | ForEach-Object { $ApplicationBlacklist_HashTable[$_.AppId] = $_.AppDisplayName,$_.Severity }

                                # Count Ingested Properties
                                $Count = $ApplicationBlacklist_HashTable.Count
                                Write-Output "[Info]  Initializing 'Application-Blacklist.csv' Lookup Table ($Count) ..."

                                $Data = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter ","

                                # Iterating over the HashTable
                                foreach ($AppId in $ApplicationBlacklist_HashTable.Keys) 
                                {
                                    $Import = $Data | Where-Object { $_.ObjectId -eq "$AppId" }
                                    $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
                                    if ($Count -gt 0)
                                    {
                                    	$AppDisplayName = $ApplicationBlacklist_HashTable["$AppId"][0]
                                        $Severity = $ApplicationBlacklist_HashTable["$AppId"][1]
                                        Write-Host "[Alert] Suspicious OAuth Application detected: $AppDisplayName ($Count)" -ForegroundColor $Severity
                                    }
                                }
                            }
                        }

                        # Workload

                        # CSV (Stats)
                        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv")
                        {
                            if([int](& $xsv count "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv") -gt 0)
                            {
                                $Total = (Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," | Select-Object Workload | Measure-Object).Count
                                Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," -Encoding UTF8 | Group-Object Workload | Select-Object @{Name='Workload'; Expression={$_.Name}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Stats\CSV\Workload.csv" -NoTypeInformation -Encoding UTF8
                            }
                        }

                        # XLSX (Stats)
                        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Stats\CSV\Workload.csv")
                        {
                            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Stats\CSV\Workload.csv") -gt 0)
                            {
                                $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Stats\CSV\Workload.csv" -Delimiter ","
                                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Stats\XLSX\Workload.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Workload" -CellStyleSB {
                                param($WorkSheet)
                                # BackgroundColor and FontColor for specific cells of TopRow
                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
                                # HorizontalAlignment "Center" of column B-C
                                $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
                                }
                            }
                        }

                        # Line Charts
                        New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Stats\XLSX\LineCharts" -ItemType Directory -Force | Out-Null

                        # Operations
                        $Import = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Select-Object @{Name="CreationDate";Expression={([DateTime]::Parse($_.CreationDate).ToString("yyyy-MM-dd"))}},Operation | Group-Object{($_.CreationDate)} | Select-Object Count,@{Name='CreationDate'; Expression={ $_.Values[0] }} | Sort-Object { $_.CreationDate -as [datetime] }
                        $ChartDefinition = New-ExcelChartDefinition -XRange CreationDate -YRange Count -Title "Operations" -ChartType Line -NoLegend -Width 1200
                        $Import | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Stats\XLSX\LineCharts\Operations.xlsx" -Append -WorksheetName "Line Chart" -AutoNameRange -ExcelChartDefinition $ChartDefinition

                        # UserLoggedIn
                        $Import = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," -Encoding UTF8 | Where-Object { $_.RecordType -eq "AzureActiveDirectoryStsLogon" } | Where-Object { $_.Operation -eq "UserLoggedIn" } | Select-Object CreationDate,Operation | Group-Object{($_.CreationDate -split "\s+")[0]} | Select-Object Count,@{Name='CreationDate'; Expression={ $_.Values[0] }} | Sort-Object { $_.CreationDate -as [datetime] }
                        $ChartDefinition = New-ExcelChartDefinition -XRange CreationDate -YRange Count -Title "UserLoggedIn" -ChartType Line -NoLegend -Width 1200
                        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Stats\XLSX\LineCharts\UserLoggedIn.xlsx" -Append -WorksheetName "Line Chart" -AutoNameRange -ExcelChartDefinition $ChartDefinition
                        
                        # UserLoginFailed
                        $Import = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," -Encoding UTF8 | Where-Object { $_.RecordType -eq "AzureActiveDirectoryStsLogon" } | Where-Object { $_.Operation -eq "UserLoginFailed" } | Select-Object CreationDate,Operation | Group-Object{($_.CreationDate -split "\s+")[0]} | Select-Object Count,@{Name='CreationDate'; Expression={ $_.Values[0] }} | Sort-Object { $_.CreationDate -as [datetime] }
                        $ChartDefinition = New-ExcelChartDefinition -XRange CreationDate -YRange Count -Title "UserLoginFailed" -ChartType Line -NoLegend -Width 1200
                        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Stats\XLSX\LineCharts\UserLoginFailed.xlsx" -Append -WorksheetName "Line Chart" -AutoNameRange -ExcelChartDefinition $ChartDefinition

                        # Suspicious Operations
                        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv")
                        {
                            if([int](& $xsv count "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv") -gt 0)
                            {
                                # UserLoginFailed
                                # RecordType: AzureActiveDirectoryStsLogon --> Secure Token Service (STS) logon events in Azure Active Directory.
                                # Operation: UserLoginFailed --> This property contains the Azure Active Directory STS (AADSTS) error code.
                                $Import = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," -Encoding UTF8 | Where-Object { $_.RecordType -eq "AzureActiveDirectoryStsLogon" } | Where-Object { $_.Operation -eq "UserLoginFailed" }
                                $Count = ($Import | Group-Object{($_.CreationDate -split "\s+")[0]} | Where-Object Count -ge 10 | Measure-Object).Count

                                if ($Count -ge 1)
                                {
                                    Write-Host "[Alert] Suspicious Operation(s) detected: 10+ UserLoginFailed operations per user on a single day ($Count)" -ForegroundColor Yellow
                                    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV" -ItemType Directory -Force | Out-Null
                                    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\XLSX" -ItemType Directory -Force | Out-Null

                                    # CSV
                                    $Import | Group-Object{($_.CreationDate -split "\s+")[0]} | Where-Object Count -ge 10 | Select-Object Name,Count | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\AzureActiveDirectoryStsLogon-UserLoginFailed-Overview.csv" -NoTypeInformation -Encoding UTF8
                                    $Import | Group-Object{($_.CreationDate -split "\s+")[0]} | Where-Object Count -ge 10 | Select-Object -Expand Group | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\AzureActiveDirectoryStsLogon-UserLoginFailed.csv" -NoTypeInformation -Encoding UTF8

                                    # AzureActiveDirectoryStsLogon-UserLoginFailed-Overview.xlsx
                                    if (Get-Module -ListAvailable -Name ImportExcel)
                                    {
                                        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\AzureActiveDirectoryStsLogon-UserLoginFailed-Overview.csv")
                                        {
                                            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\AzureActiveDirectoryStsLogon-UserLoginFailed-Overview.csv") -gt 0)
                                            {
                                                $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\AzureActiveDirectoryStsLogon-UserLoginFailed-Overview.csv" -Delimiter ","
                                                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\XLSX\AzureActiveDirectoryStsLogon-UserLoginFailed-Overview.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "UserLoginFailed" -CellStyleSB {
                                                param($WorkSheet)
                                                # BackgroundColor and FontColor for specific cells of TopRow
                                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                                Set-Format -Address $WorkSheet.Cells["A1:B1"] -BackgroundColor $BackgroundColor -FontColor White
                                                # HorizontalAlignment "Center" of columns A-B
                                                $WorkSheet.Cells["A:B"].Style.HorizontalAlignment="Center"
                                                }
                                            }
                                        }
                                    }

                                    # AzureActiveDirectoryStsLogon-UserLoginFailed.xlsx
                                    if (Get-Module -ListAvailable -Name ImportExcel)
                                    {
                                        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\AzureActiveDirectoryStsLogon-UserLoginFailed.csv")
                                        {
                                            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\AzureActiveDirectoryStsLogon-UserLoginFailed.csv") -gt 0)
                                            {
                                                $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\AzureActiveDirectoryStsLogon-UserLoginFailed.csv" -Delimiter "," | Select-Object CreationDate,UserId,RecordType,Operation,ObjectId,ClientIP,UserAgent,City,Region,Country,"Country Name",EU,Location,ASN,OrgName,"Postal Code",Timezone,Workload
                                                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\XLSX\AzureActiveDirectoryStsLogon-UserLoginFailed.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "UserLoginFailed" -CellStyleSB {
                                                param($WorkSheet)
                                                # BackgroundColor and FontColor for specific cells of TopRow
                                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                                Set-Format -Address $WorkSheet.Cells["A1:R1"] -BackgroundColor $BackgroundColor -FontColor White
                                                # HorizontalAlignment "Center" of columns A-R
                                                $WorkSheet.Cells["A:R"].Style.HorizontalAlignment="Center"
                                                # ConditionalFormatting
                                                Add-ConditionalFormatting -Address $WorkSheet.Cells["C:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("AzureActiveDirectoryStsLogon",$C1)))' -BackgroundColor Red
                                                Add-ConditionalFormatting -Address $WorkSheet.Cells["D:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("UserLoginFailed",$D1)))' -BackgroundColor Red
                                                }
                                            }
                                        }
                                    }

                                }
                            }
                        }

                        # Mailbox Auditing
                        # https://learn.microsoft.com/en-us/purview/audit-mailboxes
                        # https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema
                        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv")
                        {
                            if([int](& $xsv count "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv") -gt 0)
                            {
                                # Suspicious Mailbox Action(s) detected: Multiple email messages were deleted and moved to the 'Deleted Items' folder
                                # RecordType: ExchangeItemGroup --> Events from an Exchange mailbox audit log for actions that can be performed on multiple items, such as moving or deleted one or more email messages.
                                # Operation: MoveToDeletedItems --> A message was deleted and moved to the Deleted Items folder.
                                $Import = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," -Encoding UTF8 | Where-Object { $_.RecordType -eq "ExchangeItemGroup" } | Where-Object { $_.OrgName -ne "Zscaler Switzerland GmbH" } | Where-Object { $_.Operation -eq "MoveToDeletedItems" }
                                $Count = ($Import | Group-Object{($_.CreationDate -split "\s+")[0]} | Where-Object Count -ge 50 | Measure-Object).Count

                                if ($Count -ge 1)
                                {
                                    Write-Host "[Alert] Suspicious Mailbox Action(s) detected: 50+ email messages were deleted and moved to the 'Deleted Items' folder on a single day ($Count)" -ForegroundColor Red
                                    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV" -ItemType Directory -Force | Out-Null
                                    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\XLSX" -ItemType Directory -Force | Out-Null

                                    # CSV
                                    $Import | Group-Object{($_.CreationDate -split "\s+")[0]} | Where-Object Count -ge 50 | Select-Object Name,Count | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItemGroup-MoveToDeletedItems-Overview.csv" -NoTypeInformation -Encoding UTF8
                                    $Import | Group-Object{($_.CreationDate -split "\s+")[0]} | Where-Object Count -ge 50 | Select-Object -Expand Group | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItemGroup-MoveToDeletedItems.csv" -NoTypeInformation -Encoding UTF8

                                    # ExchangeItemGroup-MoveToDeletedItems-Overview.xlsx
                                    if (Get-Module -ListAvailable -Name ImportExcel)
                                    {
                                        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItemGroup-MoveToDeletedItems-Overview.csv")
                                        {
                                            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItemGroup-MoveToDeletedItems-Overview.csv") -gt 0)
                                            {
                                                $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItemGroup-MoveToDeletedItems-Overview.csv" -Delimiter ","
                                                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\XLSX\ExchangeItemGroup-MoveToDeletedItems-Overview.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "MoveToDeletedItems" -CellStyleSB {
                                                param($WorkSheet)
                                                # BackgroundColor and FontColor for specific cells of TopRow
                                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                                Set-Format -Address $WorkSheet.Cells["A1:B1"] -BackgroundColor $BackgroundColor -FontColor White
                                                # HorizontalAlignment "Center" of columns A-B
                                                $WorkSheet.Cells["A:B"].Style.HorizontalAlignment="Center"
                                                }
                                            }
                                        }
                                    }

                                    # ExchangeItemGroup-MoveToDeletedItems.xlsx
                                    if (Get-Module -ListAvailable -Name ImportExcel)
                                    {
                                        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItemGroup-MoveToDeletedItems.csv")
                                        {
                                            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItemGroup-MoveToDeletedItems.csv") -gt 0)
                                            {
                                                $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItemGroup-MoveToDeletedItems.csv" -Delimiter "," | Select-Object CreationDate,UserId,RecordType,Operation,ObjectId,ClientIP,UserAgent,City,Region,Country,"Country Name",EU,Location,ASN,OrgName,"Postal Code",Timezone,Workload
                                                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\XLSX\ExchangeItemGroup-MoveToDeletedItems.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "MoveToDeletedItems" -CellStyleSB {
                                                param($WorkSheet)
                                                # BackgroundColor and FontColor for specific cells of TopRow
                                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                                Set-Format -Address $WorkSheet.Cells["A1:R1"] -BackgroundColor $BackgroundColor -FontColor White
                                                # HorizontalAlignment "Center" of columns A-R
                                                $WorkSheet.Cells["A:R"].Style.HorizontalAlignment="Center"
                                                # ConditionalFormatting
                                                Add-ConditionalFormatting -Address $WorkSheet.Cells["C:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("ExchangeItemGroup",$C1)))' -BackgroundColor Red
                                                Add-ConditionalFormatting -Address $WorkSheet.Cells["D:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("MoveToDeletedItems",$D1)))' -BackgroundColor Red
                                                }
                                            }
                                        }
                                    }
                                }

                                # Suspicious Mailbox Action(s) detected: Multiple email messages were deleted from the 'Deleted Items' folder
                                # RecordType: ExchangeItemGroup --> Events from an Exchange mailbox audit log for actions that can be performed on multiple items, such as moving or deleted one or more email messages.
                                # Operation: SoftDelete --> A message was permanently deleted or deleted from the Deleted Items folder. Soft-deleted items are moved to the Recoverable Items folder.
                                $Import = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," -Encoding UTF8 | Where-Object { $_.RecordType -eq "ExchangeItemGroup" } | Where-Object { $_.OrgName -ne "Zscaler Switzerland GmbH" } | Where-Object { $_.Operation -eq "SoftDelete" }
                                $Count = ($Import | Group-Object{($_.CreationDate -split "\s+")[0]} | Where-Object Count -ge 50 | Measure-Object).Count
                                
                                if ($Count -ge 1)
                                {
                                    Write-Host "[Alert] Suspicious Mailbox Action(s) detected: 50+ email messages were permanently deleted from the 'Deleted Items' folder on a single day ($Count)" -ForegroundColor Red
                                    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV" -ItemType Directory -Force | Out-Null
                                    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\XLSX" -ItemType Directory -Force | Out-Null

                                    # CSV
                                    $Import | Group-Object{($_.CreationDate -split "\s+")[0]} | Where-Object Count -ge 50 | Select-Object Name,Count | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItemGroup-SoftDelete-Overview.csv" -NoTypeInformation -Encoding UTF8
                                    $Import | Group-Object{($_.CreationDate -split "\s+")[0]} | Where-Object Count -ge 50 | Select-Object -Expand Group | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItemGroup-SoftDelete.csv" -NoTypeInformation -Encoding UTF8

                                    # ExchangeItemGroup-SoftDelete-Overview.xlsx
                                    if (Get-Module -ListAvailable -Name ImportExcel)
                                    {
                                        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItemGroup-SoftDelete-Overview.csv")
                                        {
                                            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItemGroup-SoftDelete-Overview.csv") -gt 0)
                                            {
                                                $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItemGroup-SoftDelete-Overview.csv" -Delimiter ","
                                                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\XLSX\ExchangeItemGroup-SoftDelete-Overview.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "SoftDelete" -CellStyleSB {
                                                param($WorkSheet)
                                                # BackgroundColor and FontColor for specific cells of TopRow
                                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                                Set-Format -Address $WorkSheet.Cells["A1:B1"] -BackgroundColor $BackgroundColor -FontColor White
                                                # HorizontalAlignment "Center" of columns A-B
                                                $WorkSheet.Cells["A:B"].Style.HorizontalAlignment="Center"
                                                }
                                            }
                                        }
                                    }

                                    # ExchangeItemGroup-SoftDelete.xlsx
                                    if (Get-Module -ListAvailable -Name ImportExcel)
                                    {
                                        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItemGroup-SoftDelete.csv")
                                        {
                                            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItemGroup-SoftDelete.csv") -gt 0)
                                            {
                                                $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItemGroup-SoftDelete.csv" -Delimiter "," | Select-Object CreationDate,UserId,RecordType,Operation,ObjectId,ClientIP,UserAgent,City,Region,Country,"Country Name",EU,Location,ASN,OrgName,"Postal Code",Timezone,Workload
                                                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\XLSX\ExchangeItemGroup-SoftDelete.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "SoftDelete" -CellStyleSB {
                                                param($WorkSheet)
                                                # BackgroundColor and FontColor for specific cells of TopRow
                                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                                Set-Format -Address $WorkSheet.Cells["A1:R1"] -BackgroundColor $BackgroundColor -FontColor White
                                                # HorizontalAlignment "Center" of columns A-R
                                                $WorkSheet.Cells["A:R"].Style.HorizontalAlignment="Center"
                                                # ConditionalFormatting
                                                Add-ConditionalFormatting -Address $WorkSheet.Cells["C:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("ExchangeItemGroup",$C1)))' -BackgroundColor Red
                                                Add-ConditionalFormatting -Address $WorkSheet.Cells["D:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("SoftDelete",$D1)))' -BackgroundColor Red
                                                }
                                            }
                                        }
                                    }
                                }

                                # Suspicious Mailbox Action(s) detected: Multiple email messages were purged from the 'Recoverable Items' folder
                                # RecordType: ExchangeItemGroup --> Events from an Exchange mailbox audit log for actions that can be performed on multiple items, such as moving or deleted one or more email messages.
                                # Operation: HardDelete --> A message was purged from the Recoverable Items folder.
                                $Import = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," -Encoding UTF8 | Where-Object { $_.RecordType -eq "ExchangeItemGroup" } | Where-Object { $_.OrgName -ne "Zscaler Switzerland GmbH" } | Where-Object { $_.Operation -eq "HardDelete" }
                                $Count = ($Import | Group-Object{($_.CreationDate -split "\s+")[0]} | Where-Object Count -ge 50 | Measure-Object).Count

                                if ($Count -ge 1)
                                {
                                    Write-Host "[Alert] Suspicious Mailbox Action(s) detected: 50+ email messages were purged from the 'Recoverable Items' folder on a single day ($Count)" -ForegroundColor Red
                                    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV" -ItemType Directory -Force | Out-Null
                                    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\XLSX" -ItemType Directory -Force | Out-Null

                                    # CSV
                                    $Import | Group-Object{($_.CreationDate -split "\s+")[0]} | Where-Object Count -ge 50 | Select-Object Name,Count | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItemGroup-HardDelete-Overview.csv" -NoTypeInformation -Encoding UTF8
                                    $Import | Group-Object{($_.CreationDate -split "\s+")[0]} | Where-Object Count -ge 50 | Select-Object -Expand Group | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItemGroup-HardDelete.csv" -NoTypeInformation -Encoding UTF8

                                    # ExchangeItemGroup-HardDelete-Overview.xlsx
                                    if (Get-Module -ListAvailable -Name ImportExcel)
                                    {
                                        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItemGroup-HardDelete-Overview.csv")
                                        {
                                            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItemGroup-HardDelete-Overview.csv") -gt 0)
                                            {
                                                $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItemGroup-HardDelete-Overview.csv" -Delimiter ","
                                                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\XLSX\ExchangeItemGroup-HardDelete-Overview.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "HardDelete" -CellStyleSB {
                                                param($WorkSheet)
                                                # BackgroundColor and FontColor for specific cells of TopRow
                                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                                Set-Format -Address $WorkSheet.Cells["A1:B1"] -BackgroundColor $BackgroundColor -FontColor White
                                                # HorizontalAlignment "Center" of columns A-B
                                                $WorkSheet.Cells["A:B"].Style.HorizontalAlignment="Center"
                                                }
                                            }
                                        }
                                    }

                                    # ExchangeItemGroup-HardDelete.xlsx
                                    if (Get-Module -ListAvailable -Name ImportExcel)
                                    {
                                        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItemGroup-HardDelete.csv")
                                        {
                                            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItemGroup-HardDelete.csv") -gt 0)
                                            {
                                                $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItemGroup-HardDelete.csv" -Delimiter "," | Select-Object CreationDate,UserId,RecordType,Operation,ObjectId,ClientIP,UserAgent,City,Region,Country,"Country Name",EU,Location,ASN,OrgName,"Postal Code",Timezone,Workload
                                                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\XLSX\ExchangeItemGroup-HardDelete.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "HardDelete" -CellStyleSB {
                                                param($WorkSheet)
                                                # BackgroundColor and FontColor for specific cells of TopRow
                                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                                Set-Format -Address $WorkSheet.Cells["A1:R1"] -BackgroundColor $BackgroundColor -FontColor White
                                                # HorizontalAlignment "Center" of columns A-R
                                                $WorkSheet.Cells["A:R"].Style.HorizontalAlignment="Center"
                                                # ConditionalFormatting
                                                Add-ConditionalFormatting -Address $WorkSheet.Cells["C:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("ExchangeItemGroup",$C1)))' -BackgroundColor Red
                                                Add-ConditionalFormatting -Address $WorkSheet.Cells["D:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("HardDelete",$D1)))' -BackgroundColor Red
                                                }
                                            }
                                        }
                                    }

                                    # Suspicious Mailbox Action(s) detected: Single email messages were purged from the 'Recoverable Items' folder
                                    # RecordType: ExchangeItem --> Events from an Exchange mailbox audit log for actions that are performed on a single item, such as creating or receiving an email message.
                                    # Operation: HardDelete --> A message was purged from the Recoverable Items folder.
                                    $Import = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," -Encoding UTF8 | Where-Object { $_.RecordType -eq "ExchangeItem" } | Where-Object { $_.OrgName -ne "Zscaler Switzerland GmbH" } | Where-Object { $_.Operation -eq "HardDelete" }
                                    $Count = ($Import | Group-Object{($_.CreationDate -split "\s+")[0]} | Where-Object Count -ge 50 | Measure-Object).Count

                                    if ($Count -ge 1)
                                    {
                                        Write-Host "[Alert] Suspicious Mailbox Action(s) detected: 50+ single email messages were purged from the 'Recoverable Items' folder on a single day ($Count)" -ForegroundColor Red
                                        New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV" -ItemType Directory -Force | Out-Null
                                        New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\XLSX" -ItemType Directory -Force | Out-Null

                                        # CSV
                                        $Import | Group-Object{($_.CreationDate -split "\s+")[0]} | Where-Object Count -ge 50 | Select-Object Name,Count | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItem-HardDelete-Overview.csv" -NoTypeInformation -Encoding UTF8
                                        $Import | Group-Object{($_.CreationDate -split "\s+")[0]} | Where-Object Count -ge 50 | Select-Object -Expand Group | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItem-HardDelete.csv" -NoTypeInformation -Encoding UTF8

                                        # ExchangeItem-HardDelete-Overview.xlsx
                                        if (Get-Module -ListAvailable -Name ImportExcel)
                                        {
                                            if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItem-HardDelete-Overview.csv")
                                            {
                                                if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItem-HardDelete-Overview.csv") -gt 0)
                                                {
                                                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItem-HardDelete-Overview.csv" -Delimiter ","
                                                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\XLSX\ExchangeItem-HardDelete-Overview.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "HardDelete" -CellStyleSB {
                                                    param($WorkSheet)
                                                    # BackgroundColor and FontColor for specific cells of TopRow
                                                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                                    Set-Format -Address $WorkSheet.Cells["A1:B1"] -BackgroundColor $BackgroundColor -FontColor White
                                                    # HorizontalAlignment "Center" of columns A-B
                                                    $WorkSheet.Cells["A:B"].Style.HorizontalAlignment="Center"
                                                    }
                                                }
                                            }
                                        }

                                        # ExchangeItem-HardDelete.xlsx
                                        if (Get-Module -ListAvailable -Name ImportExcel)
                                        {
                                            if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItem-HardDelete.csv")
                                            {
                                                if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItem-HardDelete.csv") -gt 0)
                                                {
                                                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItem-HardDelete.csv" -Delimiter "," | Select-Object CreationDate,UserId,RecordType,Operation,ObjectId,ClientIP,UserAgent,City,Region,Country,"Country Name",EU,Location,ASN,OrgName,"Postal Code",Timezone,Workload
                                                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\XLSX\ExchangeItem-HardDelete.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "HardDelete" -CellStyleSB {
                                                    param($WorkSheet)
                                                    # BackgroundColor and FontColor for specific cells of TopRow
                                                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                                    Set-Format -Address $WorkSheet.Cells["A1:R1"] -BackgroundColor $BackgroundColor -FontColor White
                                                    # HorizontalAlignment "Center" of columns A-R
                                                    $WorkSheet.Cells["A:R"].Style.HorizontalAlignment="Center"
                                                    # ConditionalFormatting
                                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["C:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("ExchangeItem",$C1)))' -BackgroundColor Red
                                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["D:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("HardDelete",$D1)))' -BackgroundColor Red
                                                    }
                                                }
                                            }
                                        }
                                    }

                                    # Suspicious Mailbox Action(s) detected: Possible outgoing spam from shared mailbox
                                    # RecordType: ExchangeItem --> 	Events from an Exchange mailbox audit log for actions that are performed on a single item, such as creating or receiving an email message.
                                    # Operation: SendAs --> A message was sent using the SendAs permission. This permission allows another user to send the message as though it came from the mailbox owner.
                                    $Import = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," -Encoding UTF8 | Where-Object { $_.RecordType -eq "ExchangeItem" } | Where-Object { $_.OrgName -ne "Zscaler Switzerland GmbH" } | Where-Object { $_.Operation -eq "SendAs" }
                                    $Count = ($Import | Group-Object{($_.CreationDate -split "\s+")[0]} | Where-Object Count -ge 10 | Measure-Object).Count

                                    if ($Count -ge 1)
                                    {
                                        Write-Host "[Alert] Suspicious Mailbox Action(s) detected: 10+ email messages were sent using the 'SendAs' permission on a single day. Possible outgoing spam from shared mailbox. ($Count)" -ForegroundColor Red
                                        New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV" -ItemType Directory -Force | Out-Null
                                        New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\XLSX" -ItemType Directory -Force | Out-Null

                                        # CSV
                                        $Import | Group-Object{($_.CreationDate -split "\s+")[0]} | Where-Object Count -ge 10 | Select-Object Name,Count | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItem-SendAs-Overview.csv" -NoTypeInformation -Encoding UTF8
                                        $Import | Group-Object{($_.CreationDate -split "\s+")[0]} | Where-Object Count -ge 10 | Select-Object -Expand Group | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItem-SendAs.csv" -NoTypeInformation -Encoding UTF8
                                        
                                        # ExchangeItem-SendAs-Overview.xlsx
                                        if (Get-Module -ListAvailable -Name ImportExcel)
                                        {
                                            if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItem-SendAs-Overview.csv")
                                            {
                                                if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItem-SendAs-Overview.csv") -gt 0)
                                                {
                                                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItem-SendAs-Overview.csv" -Delimiter ","
                                                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\XLSX\ExchangeItem-SendAs-Overview.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "SendAs" -CellStyleSB {
                                                    param($WorkSheet)
                                                    # BackgroundColor and FontColor for specific cells of TopRow
                                                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                                    Set-Format -Address $WorkSheet.Cells["A1:B1"] -BackgroundColor $BackgroundColor -FontColor White
                                                    # HorizontalAlignment "Center" of columns A-B
                                                    $WorkSheet.Cells["A:B"].Style.HorizontalAlignment="Center"
                                                    }
                                                }
                                            }
                                        }

                                        # ExchangeItem-SendAs.xlsx
                                        if (Get-Module -ListAvailable -Name ImportExcel)
                                        {
                                            if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItem-SendAs.csv")
                                            {
                                                if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItem-SendAs.csv") -gt 0)
                                                {
                                                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItem-SendAs.csv" -Delimiter "," | Select-Object CreationDate,UserId,RecordType,Operation,ObjectId,ClientIP,UserAgent,City,Region,Country,"Country Name",EU,Location,ASN,OrgName,"Postal Code",Timezone,Workload
                                                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\XLSX\ExchangeItem-SendAs.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "SendAs" -CellStyleSB {
                                                    param($WorkSheet)
                                                    # BackgroundColor and FontColor for specific cells of TopRow
                                                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                                    Set-Format -Address $WorkSheet.Cells["A1:R1"] -BackgroundColor $BackgroundColor -FontColor White
                                                    # HorizontalAlignment "Center" of columns A-R
                                                    $WorkSheet.Cells["A:R"].Style.HorizontalAlignment="Center"
                                                    # ConditionalFormatting
                                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["C:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("ExchangeItem",$C1)))' -BackgroundColor Red
                                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["D:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("SendAs",$D1)))' -BackgroundColor Red
                                                    }
                                                }
                                            }
                                        }

                                        # Suspicious Mailbox Action(s) detected: Possible outgoing spam
                                        # RecordType: ExchangeItem --> 	Events from an Exchange mailbox audit log for actions that are performed on a single item, such as creating or receiving an email message.
                                        # Operation: Update --> A message or any of its properties was changed.
                                        $Import = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," -Encoding UTF8 | Where-Object { $_.RecordType -eq "ExchangeItem" } | Where-Object { $_.OrgName -ne "Zscaler Switzerland GmbH" } | Where-Object { $_.Operation -eq "Update" }
                                        $Count = ($Import | Group-Object{($_.CreationDate -split "\s+")[0]} | Where-Object Count -ge 20 | Measure-Object).Count

                                        if ($Count -ge 1)
                                        {
                                            Write-Host "[Alert] Suspicious Mailbox Action(s) detected: 20+ email messages or any of its properties were changed on a single day. Possible outgoing spam from shared mailbox. ($Count)" -ForegroundColor Red
                                            New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV" -ItemType Directory -Force | Out-Null
                                            New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\XLSX" -ItemType Directory -Force | Out-Null

                                            # CSV
                                            $Import | Group-Object{($_.CreationDate -split "\s+")[0]} | Where-Object Count -ge 20 | Select-Object Name,Count | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItem-Update-Overview.csv" -NoTypeInformation -Encoding UTF8
                                            $Import | Group-Object{($_.CreationDate -split "\s+")[0]} | Where-Object Count -ge 20 | Select-Object -Expand Group | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItem-Update.csv" -NoTypeInformation -Encoding UTF8
                                            
                                            # ExchangeItem-Update-Overview.xlsx
                                            if (Get-Module -ListAvailable -Name ImportExcel)
                                            {
                                                if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItem-Update-Overview.csv")
                                                {
                                                    if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItem-Update-Overview.csv") -gt 0)
                                                    {
                                                        $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItem-Update-Overview.csv" -Delimiter ","
                                                        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\XLSX\ExchangeItem-Update-Overview.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Update" -CellStyleSB {
                                                        param($WorkSheet)
                                                        # BackgroundColor and FontColor for specific cells of TopRow
                                                        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                                        Set-Format -Address $WorkSheet.Cells["A1:B1"] -BackgroundColor $BackgroundColor -FontColor White
                                                        # HorizontalAlignment "Center" of columns A-B
                                                        $WorkSheet.Cells["A:B"].Style.HorizontalAlignment="Center"
                                                        }
                                                    }
                                                }
                                            }

                                            # ExchangeItem-Update.xlsx
                                            if (Get-Module -ListAvailable -Name ImportExcel)
                                            {
                                                if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItem-Update.csv")
                                                {
                                                    if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItem-Update.csv") -gt 0)
                                                    {
                                                        $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItem-Update.csv" -Delimiter "," | Select-Object CreationDate,UserId,RecordType,Operation,ObjectId,ClientIP,UserAgent,City,Region,Country,"Country Name",EU,Location,ASN,OrgName,"Postal Code",Timezone,Workload
                                                        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\XLSX\ExchangeItem-Update.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Update" -CellStyleSB {
                                                        param($WorkSheet)
                                                        # BackgroundColor and FontColor for specific cells of TopRow
                                                        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                                        Set-Format -Address $WorkSheet.Cells["A1:R1"] -BackgroundColor $BackgroundColor -FontColor White
                                                        # HorizontalAlignment "Center" of columns A-R
                                                        $WorkSheet.Cells["A:R"].Style.HorizontalAlignment="Center"
                                                        # ConditionalFormatting
                                                        Add-ConditionalFormatting -Address $WorkSheet.Cells["C:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("ExchangeItem",$C1)))' -BackgroundColor Yellow
                                                        Add-ConditionalFormatting -Address $WorkSheet.Cells["D:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Update",$D1)))' -BackgroundColor Yellow
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        # SharePoint Auditing
                        # https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema
                        # https://learn.microsoft.com/en-us/purview/audit-log-sharing
                        # https://learn.microsoft.com/en-us/purview/audit-log-activities
                        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv")
                        {
                            if([int](& $xsv count "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv") -gt 0)
                            {
                                # Suspicious SharePointSharingOperations

                                # Suspicious SharePoint Action(s) detected: A user in your organization tried to share 10+ resources (likely a site) with an external user on a single day.
                                # RecordType: SharePointSharingOperation --> SharePoint sharing events.
                                # Operation: SharingInvitationCreated --> A user in your organization tried to share a resource (likely a site) with an external user. This results in an external sharing invitation sent to the target user. No access to the resource is granted at this point.
                                $Import = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," -Encoding UTF8 | Where-Object { $_.RecordType -eq "SharePointSharingOperation" } | Where-Object { $_.Operation -eq "SharingInvitationCreated" }
                                $Count = ($Import | Group-Object{($_.CreationDate -split "\s+")[0]} | Where-Object Count -ge 10 | Measure-Object).Count

                                if ($Count -ge 1)
                                {
                                    Write-Host "[Alert] Suspicious SharePoint Action(s) detected: A user in your organization tried to share 10+ resources (likely a site) with an external user on a single day. ($Count)" -ForegroundColor Red
                                    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV" -ItemType Directory -Force | Out-Null
                                    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\XLSX" -ItemType Directory -Force | Out-Null

                                    # CSV
                                    $Import | Group-Object{($_.CreationDate -split "\s+")[0]} | Where-Object Count -ge 10 | Select-Object Name,Count | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointSharingOperation-SharingInvitationCreated-Overview.csv" -NoTypeInformation -Encoding UTF8
                                    $Import | Group-Object{($_.CreationDate -split "\s+")[0]} | Where-Object Count -ge 10 | Select-Object -Expand Group | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointSharingOperation-SharingInvitationCreated.csv" -NoTypeInformation -Encoding UTF8
                                            
                                    # SharePointSharingOperation-SharingInvitationCreated-Overview.xlsx
                                    if (Get-Module -ListAvailable -Name ImportExcel)
                                    {
                                        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointSharingOperation-SharingInvitationCreated-Overview.csv")
                                        {
                                            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointSharingOperation-SharingInvitationCreated-Overview.csv") -gt 0)
                                            {
                                                $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointSharingOperation-SharingInvitationCreated-Overview.csv" -Delimiter ","
                                                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\XLSX\SharePointSharingOperation-SharingInvitationCreated-Overview.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "SharingInvitationCreated" -CellStyleSB {
                                                param($WorkSheet)
                                                # BackgroundColor and FontColor for specific cells of TopRow
                                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                                Set-Format -Address $WorkSheet.Cells["A1:B1"] -BackgroundColor $BackgroundColor -FontColor White
                                                # HorizontalAlignment "Center" of columns A-B
                                                $WorkSheet.Cells["A:B"].Style.HorizontalAlignment="Center"
                                                }
                                            }
                                        }
                                    }

                                    # SharePointSharingOperation-SharingInvitationCreated.xlsx
                                    if (Get-Module -ListAvailable -Name ImportExcel)
                                    {
                                        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointSharingOperation-SharingInvitationCreated.csv")
                                        {
                                            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointSharingOperation-SharingInvitationCreated.csv") -gt 0)
                                            {
                                                $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointSharingOperation-SharingInvitationCreated.csv" -Delimiter "," | Select-Object CreationDate,UserId,RecordType,Operation,ObjectId,ClientIP,UserAgent,City,Region,Country,"Country Name",EU,Location,ASN,OrgName,"Postal Code",Timezone,Workload
                                                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\XLSX\SharePointSharingOperation-SharingInvitationCreated.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "SharingInvitationCreated" -CellStyleSB {
                                                param($WorkSheet)
                                                # BackgroundColor and FontColor for specific cells of TopRow
                                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                                Set-Format -Address $WorkSheet.Cells["A1:R1"] -BackgroundColor $BackgroundColor -FontColor White
                                                # HorizontalAlignment "Center" of columns A-R
                                                $WorkSheet.Cells["A:R"].Style.HorizontalAlignment="Center"
                                                # ConditionalFormatting
                                                Add-ConditionalFormatting -Address $WorkSheet.Cells["C:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("SharePointSharingOperation",$C1)))' -BackgroundColor Yellow
                                                Add-ConditionalFormatting -Address $WorkSheet.Cells["D:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("SharingInvitationCreated",$D1)))' -BackgroundColor Yellow
                                                }
                                            }
                                        }
                                    }
                                }

                                # Suspicious SharePoint Action(s) detected: 50+ users were added to a specific people link on a single day
                                # RecordType: SharePointSharingOperation --> SharePoint sharing events.
                                # Operation: AddedToSecureLink -->  A user was added to a specific people link. Use the TargetUserOrGroupName field in this event to identify the user added to the corresponding specific people link. This target user may be someone who is external to your organization.
                                $Import = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," -Encoding UTF8 | Where-Object { $_.RecordType -eq "SharePointSharingOperation" } | Where-Object { $_.Operation -eq "AddedToSecureLink" } | Sort-Object { $_.CreationDate -as [datetime] } -Descending
                                $Count = ($Import | Group-Object{($_.CreationDate -split "\s+")[0]} | Where-Object Count -ge 50 | Measure-Object).Count

                                if ($Count -ge 1)
                                {
                                    Write-Host "[Alert] Suspicious SharePoint Action(s) detected: 50+ users were added to a specific people link on a single day. ($Count)" -ForegroundColor Red
                                    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV" -ItemType Directory -Force | Out-Null
                                    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\XLSX" -ItemType Directory -Force | Out-Null

                                    # CSV
                                    $Import | Group-Object{($_.CreationDate -split "\s+")[0]} | Where-Object Count -ge 50 | Select-Object Name,Count | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointSharingOperation-AddedToSecureLink-Overview.csv" -NoTypeInformation -Encoding UTF8
                                    $Import | Group-Object{($_.CreationDate -split "\s+")[0]} | Where-Object Count -ge 50 | Select-Object -Expand Group | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointSharingOperation-AddedToSecureLink.csv" -NoTypeInformation -Encoding UTF8
                                      
                                    # SharePointSharingOperation-AddedToSecureLink-Overview.xlsx
                                    if (Get-Module -ListAvailable -Name ImportExcel)
                                    {
                                        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointSharingOperation-AddedToSecureLink-Overview.csv")
                                        {
                                            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointSharingOperation-AddedToSecureLink-Overview.csv") -gt 0)
                                            {
                                                $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointSharingOperation-AddedToSecureLink-Overview.csv" -Delimiter ","
                                                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\XLSX\SharePointSharingOperation-AddedToSecureLink-Overview.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "AddedToSecureLink" -CellStyleSB {
                                                param($WorkSheet)
                                                # BackgroundColor and FontColor for specific cells of TopRow
                                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                                Set-Format -Address $WorkSheet.Cells["A1:B1"] -BackgroundColor $BackgroundColor -FontColor White
                                                # HorizontalAlignment "Center" of columns A-B
                                                $WorkSheet.Cells["A:B"].Style.HorizontalAlignment="Center"
                                                }
                                            }
                                        }
                                    }

                                    # SharePointSharingOperation-AddedToSecureLink.xlsx
                                    if (Get-Module -ListAvailable -Name ImportExcel)
                                    {
                                        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointSharingOperation-AddedToSecureLink.csv")
                                        {
                                            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointSharingOperation-AddedToSecureLink.csv") -gt 0)
                                            {
                                                $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointSharingOperation-AddedToSecureLink.csv" -Delimiter "," | Select-Object CreationDate,UserId,RecordType,Operation,ObjectId,ClientIP,UserAgent,City,Region,Country,"Country Name",EU,Location,ASN,OrgName,"Postal Code",Timezone,Workload
                                                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\XLSX\SharePointSharingOperation-AddedToSecureLink.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "AddedToSecureLink" -CellStyleSB {
                                                param($WorkSheet)
                                                # BackgroundColor and FontColor for specific cells of TopRow
                                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                                Set-Format -Address $WorkSheet.Cells["A1:R1"] -BackgroundColor $BackgroundColor -FontColor White
                                                # HorizontalAlignment "Center" of columns A-R
                                                $WorkSheet.Cells["A:R"].Style.HorizontalAlignment="Center"
                                                # ConditionalFormatting
                                                Add-ConditionalFormatting -Address $WorkSheet.Cells["C:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("SharePointSharingOperation",$C1)))' -BackgroundColor Yellow
                                                Add-ConditionalFormatting -Address $WorkSheet.Cells["D:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("AddedToSecureLink",$D1)))' -BackgroundColor Yellow
                                                }
                                            }
                                        }
                                    }
                                }

                                # Suspicious SharePoint Action(s) detected: A user has created a 'specific people link' to share a resource with a specific person. This target user may be someone who is external to your organization.
                                # RecordType: SharePointSharingOperation --> SharePoint sharing events.
                                # Operation: SecureLinkCreated --> A user has created a 'specific people link' to share a resource with a specific person. This target user may be someone who is external to your organization. The person that the resource is shared with is identified in the audit record for the AddedToSecureLink event. The time stamps for these two events are nearly identical.
                                $Import = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," -Encoding UTF8 | Where-Object { $_.RecordType -eq "SharePointSharingOperation" } | Where-Object { $_.Operation -eq "SecureLinkCreated" } | Sort-Object { $_.CreationDate -as [datetime] } -Descending
                                $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

                                if ($Count -gt 0)
                                {
                                    Write-Host "[Alert] Suspicious SharePoint Action(s) detected: A user has created a 'specific people link' to share a resource with a specific person. This target user may be someone who is external to your organization. ($Count)" -ForegroundColor Red
                                    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV" -ItemType Directory -Force | Out-Null
                                    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\XLSX" -ItemType Directory -Force | Out-Null

                                    # CSV
                                    $Import | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointSharingOperation-SecureLinkCreated.csv" -NoTypeInformation -Encoding UTF8

                                    # XLSX
                                    if (Get-Module -ListAvailable -Name ImportExcel)
                                    {
                                        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointSharingOperation-SecureLinkCreated.csv")
                                        {
                                            if([int](& $xsv count "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointSharingOperation-SecureLinkCreated.csv") -gt 0)
                                            {
                                                $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointSharingOperation-SecureLinkCreated.csv" -Delimiter "," | Select-Object CreationDate,UserId,RecordType,Operation,ObjectId,ClientIP,UserAgent,City,Region,Country,"Country Name",EU,Location,ASN,OrgName,"Postal Code",Timezone,Workload
                                                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\XLSX\SharePointSharingOperation-SecureLinkCreated.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "SecureLinkCreated" -CellStyleSB {
                                                param($WorkSheet)
                                                # BackgroundColor and FontColor for specific cells of TopRow
                                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                                Set-Format -Address $WorkSheet.Cells["A1:R1"] -BackgroundColor $BackgroundColor -FontColor White
                                                # HorizontalAlignment "Center" of columns A-D and F-R
                                                $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"
                                                $WorkSheet.Cells["F:R"].Style.HorizontalAlignment="Center"
                                                # ConditionalFormatting
                                                Add-ConditionalFormatting -Address $WorkSheet.Cells["C:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("SharePointSharingOperation",$C1)))' -BackgroundColor Red
                                                Add-ConditionalFormatting -Address $WorkSheet.Cells["D:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("SecureLinkCreated",$D1)))' -BackgroundColor Red
                                                }
                                            }
                                        }
                                    }
                                }

                                # Suspicious SharePoint Action(s) detected: A user has 5+ updated a 'specific people link' to share a resource with a specific person. This target user may be someone who is external to your organization.
                                # RecordType: SharePointSharingOperation --> SharePoint sharing events.
                                # Operation: SecureLinkUpdated --> For a SharePoint Item.
                                $Import = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," -Encoding UTF8 | Where-Object { $_.RecordType -eq "SharePointSharingOperation" } | Where-Object { $_.Operation -eq "SecureLinkUpdated" } | Sort-Object { $_.CreationDate -as [datetime] } -Descending
                                $Count = ($Import | Group-Object{($_.CreationDate -split "\s+")[0]} | Where-Object Count -ge 5 | Measure-Object).Count

                                if ($Count -ge 1)
                                {
                                    Write-Host "[Alert] Suspicious SharePoint Action(s) detected: A user has 5+ updated a 'specific people link' to share a resource with a specific person. This target user may be someone who is external to your organization. ($Count)" -ForegroundColor Red
                                    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV" -ItemType Directory -Force | Out-Null
                                    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\XLSX" -ItemType Directory -Force | Out-Null

                                    # CSV
                                    $Import | Group-Object{($_.CreationDate -split "\s+")[0]} | Where-Object Count -ge 5 | Select-Object Name,Count | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointSharingOperation-SecureLinkUpdated-Overview.csv" -NoTypeInformation -Encoding UTF8
                                    $Import | Group-Object{($_.CreationDate -split "\s+")[0]} | Where-Object Count -ge 5 | Select-Object -Expand Group | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointSharingOperation-SecureLinkUpdated.csv" -NoTypeInformation -Encoding UTF8
                                    
                                    # SharePointSharingOperation-SecureLinkUpdated-Overview.xlsx
                                    if (Get-Module -ListAvailable -Name ImportExcel)
                                    {
                                        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointSharingOperation-SecureLinkUpdated-Overview.csv")
                                        {
                                            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointSharingOperation-SecureLinkUpdated-Overview.csv") -gt 0)
                                            {
                                                $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointSharingOperation-SecureLinkUpdated-Overview.csv" -Delimiter ","
                                                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\XLSX\SharePointSharingOperation-SecureLinkUpdated-Overview.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "SecureLinkUpdated" -CellStyleSB {
                                                param($WorkSheet)
                                                # BackgroundColor and FontColor for specific cells of TopRow
                                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                                Set-Format -Address $WorkSheet.Cells["A1:B1"] -BackgroundColor $BackgroundColor -FontColor White
                                                # HorizontalAlignment "Center" of columns A-B
                                                $WorkSheet.Cells["A:B"].Style.HorizontalAlignment="Center"
                                                }
                                            }
                                        }
                                    }

                                    # SharePointSharingOperation-SecureLinkUpdated.xlsx
                                    if (Get-Module -ListAvailable -Name ImportExcel)
                                    {
                                        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointSharingOperation-SecureLinkUpdated.csv")
                                        {
                                            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointSharingOperation-SecureLinkUpdated.csv") -gt 0)
                                            {
                                                $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointSharingOperation-SecureLinkUpdated.csv" -Delimiter "," | Select-Object CreationDate,UserId,RecordType,Operation,ObjectId,ClientIP,UserAgent,City,Region,Country,"Country Name",EU,Location,ASN,OrgName,"Postal Code",Timezone,Workload
                                                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\XLSX\SharePointSharingOperation-SecureLinkUpdated.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "SecureLinkUpdated" -CellStyleSB {
                                                param($WorkSheet)
                                                # BackgroundColor and FontColor for specific cells of TopRow
                                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                                Set-Format -Address $WorkSheet.Cells["A1:R1"] -BackgroundColor $BackgroundColor -FontColor White
                                                # HorizontalAlignment "Center" of columns A-R
                                                $WorkSheet.Cells["A:R"].Style.HorizontalAlignment="Center"
                                                # ConditionalFormatting
                                                Add-ConditionalFormatting -Address $WorkSheet.Cells["C:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("SharePointSharingOperation",$C1)))' -BackgroundColor Yellow
                                                Add-ConditionalFormatting -Address $WorkSheet.Cells["D:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("SecureLinkUpdated",$D1)))' -BackgroundColor Yellow
                                                }
                                            }
                                        }
                                    }
                                }

                                # Suspicious SharePoint Action(s) detected: A user shared 10+ a file, folder, or site in SharePoint for Business with a user in your organization's directory
                                # RecordType: SharePointSharingOperation --> SharePoint sharing events.
                                # Operation: SharingSet --> User (member or guest) shared a file, folder, or site in SharePoint or OneDrive for Business with a user in your organization's directory. The value in the Detail column for this activity identifies the name of the user the resource was shared with and whether this user is a member or a guest. This activity is often accompanied by a second event that describes how the user was granted access to the resource. For example, adding the user to a group that has access to the resource.
                                $Import = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," -Encoding UTF8 | Where-Object { $_.RecordType -eq "SharePointSharingOperation" } | Where-Object { $_.Operation -eq "SharingSet" } | Sort-Object { $_.CreationDate -as [datetime] } -Descending
                                $Count = ($Import | Group-Object{($_.CreationDate -split "\s+")[0]} | Where-Object Count -ge 10 | Measure-Object).Count

                                if ($Count -ge 1)
                                {
                                    Write-Host "[Alert] Suspicious SharePoint Action(s) detected: A user shared 10+ a file, folder, or site in SharePoint for Business with a user in your organization's directory ($Count)" -ForegroundColor Red
                                    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV" -ItemType Directory -Force | Out-Null
                                    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\XLSX" -ItemType Directory -Force | Out-Null

                                    # CSV
                                    $Import | Group-Object{($_.CreationDate -split "\s+")[0]} | Where-Object Count -ge 5 | Select-Object Name,Count | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointSharingOperation-SharingSet-Overview.csv" -NoTypeInformation -Encoding UTF8
                                    $Import | Group-Object{($_.CreationDate -split "\s+")[0]} | Where-Object Count -ge 5 | Select-Object -Expand Group | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointSharingOperation-SharingSet.csv" -NoTypeInformation -Encoding UTF8
                                    
                                    # SharePointSharingOperation-SharingSet-Overview.xlsx
                                    if (Get-Module -ListAvailable -Name ImportExcel)
                                    {
                                        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointSharingOperation-SharingSet-Overview.csv")
                                        {
                                            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointSharingOperation-SharingSet-Overview.csv") -gt 0)
                                            {
                                                $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointSharingOperation-SharingSet-Overview.csv" -Delimiter ","
                                                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\XLSX\SharePointSharingOperation-SharingSet-Overview.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "SharingSet" -CellStyleSB {
                                                param($WorkSheet)
                                                # BackgroundColor and FontColor for specific cells of TopRow
                                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                                Set-Format -Address $WorkSheet.Cells["A1:B1"] -BackgroundColor $BackgroundColor -FontColor White
                                                # HorizontalAlignment "Center" of columns A-B
                                                $WorkSheet.Cells["A:B"].Style.HorizontalAlignment="Center"
                                                }
                                            }
                                        }
                                    }

                                    # SharePointSharingOperation-SharingSet.xlsx
                                    if (Get-Module -ListAvailable -Name ImportExcel)
                                    {
                                        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointSharingOperation-SharingSet.csv")
                                        {
                                            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointSharingOperation-SharingSet.csv") -gt 0)
                                            {
                                                $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointSharingOperation-SharingSet.csv" -Delimiter "," | Select-Object CreationDate,UserId,RecordType,Operation,ObjectId,ClientIP,UserAgent,City,Region,Country,"Country Name",EU,Location,ASN,OrgName,"Postal Code",Timezone,Workload
                                                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\XLSX\SharePointSharingOperation-SharingSet.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "SharingSet" -CellStyleSB {
                                                param($WorkSheet)
                                                # BackgroundColor and FontColor for specific cells of TopRow
                                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                                Set-Format -Address $WorkSheet.Cells["A1:R1"] -BackgroundColor $BackgroundColor -FontColor White
                                                # HorizontalAlignment "Center" of columns A-R
                                                $WorkSheet.Cells["A:R"].Style.HorizontalAlignment="Center"
                                                # ConditionalFormatting
                                                Add-ConditionalFormatting -Address $WorkSheet.Cells["C:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("SharePointSharingOperation",$C1)))' -BackgroundColor Yellow
                                                Add-ConditionalFormatting -Address $WorkSheet.Cells["D:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("SharingSet",$D1)))' -BackgroundColor Yellow
                                                }
                                            }
                                        }
                                    }
                                }

                                # Suspicious SharePointFileOperations

                                # Suspicious SharePoint Action(s) detected: A user in your organization possibly uploaded a suspicious document on a site
                                # RecordType: SharePointFileOperation --> SharePoint file operation events.
                                # Operation: FileUploaded --> User uploads a document to a folder on a SharePoint or OneDrive for Business site.
                                $Import = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," -Encoding UTF8 | Where-Object { $_.RecordType -eq "SharePointFileOperation" } | Where-Object { $_.Operation -eq "FileUploaded" } | Sort-Object { $_.CreationDate -as [datetime] } -Descending
                                $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

                                if ($Count -gt 0)
                                {
                                    Write-Host "[Alert] Suspicious SharePoint Action(s) detected: A user in your organization possibly uploaded a suspicious document on a site ($Count)" -ForegroundColor Yellow
                                    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV" -ItemType Directory -Force | Out-Null
                                    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\XLSX" -ItemType Directory -Force | Out-Null

                                    # CSV
                                    $Import | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointFileOperation-FileUploaded.csv" -NoTypeInformation -Encoding UTF8

                                    # XLSX
                                    if (Get-Module -ListAvailable -Name ImportExcel)
                                    {
                                        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointFileOperation-FileUploaded.csv")
                                        {
                                            if([int](& $xsv count "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointFileOperation-FileUploaded.csv") -gt 0)
                                            {
                                                $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointFileOperation-FileUploaded.csv" -Delimiter "," | Select-Object CreationDate,UserId,RecordType,Operation,ObjectId,ClientIP,UserAgent,City,Region,Country,"Country Name",EU,Location,ASN,OrgName,"Postal Code",Timezone,Workload
                                                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\XLSX\SharePointFileOperation-FileUploaded.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "FileUploaded" -CellStyleSB {
                                                param($WorkSheet)
                                                # BackgroundColor and FontColor for specific cells of TopRow
                                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                                Set-Format -Address $WorkSheet.Cells["A1:R1"] -BackgroundColor $BackgroundColor -FontColor White
                                                # HorizontalAlignment "Center" of columns A-D and F-R
                                                $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"
                                                $WorkSheet.Cells["F:R"].Style.HorizontalAlignment="Center"
                                                # ConditionalFormatting
                                                Add-ConditionalFormatting -Address $WorkSheet.Cells["C:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("SharePointFileOperation",$C1)))' -BackgroundColor Yellow
                                                Add-ConditionalFormatting -Address $WorkSheet.Cells["D:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("FileUploaded",$D1)))' -BackgroundColor Yellow
                                                }
                                            }
                                        }
                                    }
                                }

                                # Suspicious SharePoint Action(s) detected: 50+ files were downloaded from a SharePoint or OneDrive for Business site on a single day. Possible Data Exfiltration.
                                # RecordType: SharePointFileOperation --> SharePoint file operation events.
                                # Operation: FileDownloaded --> User downloads a document from a SharePoint or OneDrive for Business site
                                $Import = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," -Encoding UTF8 | Where-Object { $_.RecordType -eq "SharePointFileOperation" } | Where-Object { $_.Operation -eq "FileDownloaded" } | Sort-Object { $_.CreationDate -as [datetime] } -Descending
                                $Count = ($Import | Group-Object{($_.CreationDate -split "\s+")[0]} | Where-Object Count -ge 50 | Measure-Object).Count

                                if ($Count -ge 1)
                                {
                                    Write-Host "[Alert] Suspicious SharePoint Action(s) detected: 50+ files were downloaded from a SharePoint or OneDrive for Business site on a single day. Possible Data Exfiltration. ($Count)" -ForegroundColor Red
                                    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV" -ItemType Directory -Force | Out-Null
                                    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\XLSX" -ItemType Directory -Force | Out-Null

                                    # CSV
                                    $Import | Group-Object{($_.CreationDate -split "\s+")[0]} | Where-Object Count -ge 50 | Select-Object Name,Count | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointFileOperation-FileDownloaded-Overview.csv" -NoTypeInformation -Encoding UTF8
                                    $Import | Group-Object{($_.CreationDate -split "\s+")[0]} | Where-Object Count -ge 50 | Select-Object -Expand Group | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointFileOperation-FileDownloaded.csv" -NoTypeInformation -Encoding UTF8
                                    
                                    # SharePointFileOperation-FileDownloaded-Overview.xlsx
                                    if (Get-Module -ListAvailable -Name ImportExcel)
                                    {
                                        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointFileOperation-FileDownloaded-Overview.csv")
                                        {
                                            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointFileOperation-FileDownloaded-Overview.csv") -gt 0)
                                            {
                                                $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointFileOperation-FileDownloaded-Overview.csv" -Delimiter ","
                                                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\XLSX\SharePointFileOperation-FileDownloaded-Overview.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "FileDownloaded" -CellStyleSB {
                                                param($WorkSheet)
                                                # BackgroundColor and FontColor for specific cells of TopRow
                                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                                Set-Format -Address $WorkSheet.Cells["A1:B1"] -BackgroundColor $BackgroundColor -FontColor White
                                                # HorizontalAlignment "Center" of columns A-B
                                                $WorkSheet.Cells["A:B"].Style.HorizontalAlignment="Center"
                                                }
                                            }
                                        }
                                    }

                                    # SharePointFileOperation-FileDownloaded.xlsx
                                    if (Get-Module -ListAvailable -Name ImportExcel)
                                    {
                                        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointFileOperation-FileDownloaded.csv")
                                        {
                                            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointFileOperation-FileDownloaded.csv") -gt 0)
                                            {
                                                $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointFileOperation-FileDownloaded.csv" -Delimiter "," | Select-Object CreationDate,UserId,RecordType,Operation,ObjectId,ClientIP,UserAgent,City,Region,Country,"Country Name",EU,Location,ASN,OrgName,"Postal Code",Timezone,Workload
                                                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\XLSX\SharePointFileOperation-FileDownloaded.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "FileDownloaded" -CellStyleSB {
                                                param($WorkSheet)
                                                # BackgroundColor and FontColor for specific cells of TopRow
                                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                                Set-Format -Address $WorkSheet.Cells["A1:R1"] -BackgroundColor $BackgroundColor -FontColor White
                                                # HorizontalAlignment "Center" of columns A-R
                                                $WorkSheet.Cells["A:R"].Style.HorizontalAlignment="Center"
                                                # ConditionalFormatting
                                                Add-ConditionalFormatting -Address $WorkSheet.Cells["C:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("SharePointFileOperation",$C1)))' -BackgroundColor Yellow
                                                Add-ConditionalFormatting -Address $WorkSheet.Cells["D:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("FileDownloaded",$D1)))' -BackgroundColor Yellow
                                                }
                                            }
                                        }
                                    }
                                }

                                # Suspicious SharePoint Action(s) detected: A user in your organization continually accesses a file for an extended period (up to 3 hours)
                                # RecordType: SharePointFileOperation --> SharePoint file operation events.
                                # Operation: FileAccessedExtended --> This is related to the 'Accessed file' (FileAccessed) activity. A FileAccessedExtended event is logged when the same person continually accesses a file for an extended period (up to 3 hours).
                                $Import = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," -Encoding UTF8 | Where-Object { $_.RecordType -eq "SharePointFileOperation" } | Where-Object { $_.Operation -eq "FileAccessedExtended" } | Sort-Object { $_.CreationDate -as [datetime] } -Descending
                                $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

                                if ($Count -gt 0)
                                {
                                    Write-Host "[Alert] Suspicious SharePoint Action(s) detected: A user in your organization continually accesses a file for an extended period (up to 3 hours) ($Count)" -ForegroundColor Yellow
                                    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV" -ItemType Directory -Force | Out-Null
                                    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\XLSX" -ItemType Directory -Force | Out-Null

                                    # CSV
                                    $Import | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointFileOperation-FileAccessedExtended.csv" -NoTypeInformation -Encoding UTF8

                                    # XLSX
                                    if (Get-Module -ListAvailable -Name ImportExcel)
                                    {
                                        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointFileOperation-FileAccessedExtended.csv")
                                        {
                                            if([int](& $xsv count "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointFileOperation-FileAccessedExtended.csv") -gt 0)
                                            {
                                                $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointFileOperation-FileAccessedExtended.csv" -Delimiter "," | Select-Object CreationDate,UserId,RecordType,Operation,ObjectId,ClientIP,UserAgent,City,Region,Country,"Country Name",EU,Location,ASN,OrgName,"Postal Code",Timezone,Workload
                                                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\XLSX\SharePointFileOperation-FileAccessedExtended.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "FileAccessedExtended" -CellStyleSB {
                                                param($WorkSheet)
                                                # BackgroundColor and FontColor for specific cells of TopRow
                                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                                Set-Format -Address $WorkSheet.Cells["A1:R1"] -BackgroundColor $BackgroundColor -FontColor White
                                                # HorizontalAlignment "Center" of columns A-D and F-R
                                                $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"
                                                $WorkSheet.Cells["F:R"].Style.HorizontalAlignment="Center"
                                                # ConditionalFormatting
                                                Add-ConditionalFormatting -Address $WorkSheet.Cells["C:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("SharePointFileOperation",$C1)))' -BackgroundColor Yellow
                                                Add-ConditionalFormatting -Address $WorkSheet.Cells["D:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("FileAccessedExtended",$D1)))' -BackgroundColor Yellow
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    else
                    {
                        Write-Output "[Info]  IPinfo Access Token NOT found. Please sign up for free."
                    }
                }
            }
        }
    }
}
else
{
    Write-Output "[Info]  ipinfo.exe NOT found."
}

$EndTime_DataEnrichment = (Get-Date)
$Time_DataEnrichment = ($EndTime_DataEnrichment-$StartTime_DataEnrichment)
('UnifiedAuditLog Data Enrichment duration: {0} h {1} min {2} sec' -f $Time_DataEnrichment.Hours, $Time_DataEnrichment.Minutes, $Time_DataEnrichment.Seconds) >> "$OUTPUT_FOLDER\Stats.txt"

}

Get-IPLocation

#############################################################################################################################################################################################

Function Get-Analytics {

$StartTime_Analytics = (Get-Date)

# AiTM Proxy Server
if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv")
{
    if([int](& $xsv count "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv") -gt 0)
    {
        $Import = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," | Where-Object { $_.ClientInfoString -eq "Client=OWA;Action=ViaProxy" } | Where-Object { $_.ASN -notmatch ($Whitelist) } | Sort-Object { $_.CreationTime -as [datetime] } -Descending
        $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

        if ($Count -gt 0)
        {
            Write-Host "[Alert] Suspicious ClientInfoString indicates AiTM Proxy Server: Client=OWA;Action=ViaProxy ($Count)" -ForegroundColor Red
        }
    }
}

# Hunting for Suspicious SessionIds
if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv")
{
    if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv") -gt 0)
    {
        Write-output "[Info]  Hunting for Suspicious SessionIds ..."

        $SessionIds = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," | Where-Object { $_.Operation -eq "UserLoggedIn" } | Where-Object { $_.SessionId -ne "" } | Select-Object -ExpandProperty SessionId -Unique

        $Total = ($SessionIds | Measure-Object).Count

        $Results = @()
        ForEach($SessionId in $SessionIds)
        {
            $Line = [PSCustomObject]@{
            "SessionId"      = $SessionId
            "ClientIP"       = (Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," | Where-Object { $_.SessionId -eq "$SessionId" } | Select-Object ClientIP -Unique | Measure-Object).Count
            "Country"        = (Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," | Where-Object { $_.SessionId -eq "$SessionId" } | Select-Object Country -Unique | Measure-Object).Count
            "ASN"            = (Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," | Where-Object { $_.SessionId -eq "$SessionId" } | Select-Object ASN -Unique | Measure-Object).Count
            "OS"             = (Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," | Where-Object { $_.SessionId -eq "$SessionId" } | Select-Object OS -Unique | Measure-Object).Count
            "BrowserType"    = (Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," | Where-Object { $_.SessionId -eq "$SessionId" } | Select-Object BrowserType -Unique | Measure-Object).Count
            "InterSystemsId" = (Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," | Where-Object { $_.SessionId -eq "$SessionId" } | Select-Object InterSystemsId -Unique | Measure-Object).Count
            }

            $Results += $Line
        }

        $Results | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Suspicious-SessionIds.csv" -NoTypeInformation
    }
}

# XLSX
if (Get-Module -ListAvailable -Name ImportExcel)
{
    if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Suspicious-SessionIds.csv")
    {
        if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Suspicious-SessionIds.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Suspicious-SessionIds.csv" -Delimiter "," | Sort-Object @{Expression={ $_."ClientIP" -as [Int] }} -Descending
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\XLSX\Suspicious-SessionIds.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Suspicious SessionIds" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:G1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of column A-G
            $WorkSheet.Cells["A:G"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting - Different IP addresses (and User-Agents) indicate Session Cookie Theft
            $LastRow = $WorkSheet.Dimension.End.Row
            Add-ConditionalFormatting -Address $WorkSheet.Cells["B2:B$LastRow"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '=$B2>=2' -BackgroundColor Red # ClientIP
            Add-ConditionalFormatting -Address $WorkSheet.Cells["C2:C$LastRow"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '=$C2>=2' -BackgroundColor Red # Country
            Add-ConditionalFormatting -Address $WorkSheet.Cells["D2:D$LastRow"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '=$D2>=2' -BackgroundColor Red # ASN
            Add-ConditionalFormatting -Address $WorkSheet.Cells["E2:E$LastRow"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '=$E2>=2' -BackgroundColor Red # OS
            Add-ConditionalFormatting -Address $WorkSheet.Cells["F2:F$LastRow"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '=$F2>=2' -BackgroundColor Red # BrowserType
            Add-ConditionalFormatting -Address $WorkSheet.Cells["A2:A$LastRow"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '=AND($B2>=2,$D2>=2)' -BackgroundColor Red # ClientIP + ASN = Suspicious SessionId
            }
        }
    }
}

# Suspicious SessionIds
$SuspiciousSessionIds = ($IMPORT | Where-Object { $_.ClientIP -ge "2" } | Where-Object { $_.ASN -ge "2" } | Measure-Object).Count
if ($SuspiciousSessionIds -gt 0)
{
    Write-Host "[Info]  $SuspiciousSessionIds Suspicious SessionIds found ($Total)" -ForegroundColor Red
}
else
{
    Write-Host "[Info]  $Total SessionIds found"
}

# Sessions (Duration)
if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv")
{
    if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv") -gt 0)
    {
        $SessionIds = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," | Where-Object { $_.Operation -eq "UserLoggedIn" } | Where-Object { $_.SessionId -ne "" } | Select-Object -ExpandProperty SessionId -Unique

        $Results = @()
        ForEach($SessionId in $SessionIds)
        {
            $StartDate  = (Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," | Where-Object { $_.SessionId -eq "$SessionId" } | Select-Object CreationDate | Sort-Object { $_.CreationDate -as [datetime] } -Descending | Select-Object -Last 1).CreationDate
            $EndDate    = (Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," | Where-Object { $_.SessionId -eq "$SessionId" } | Select-Object CreationDate | Sort-Object { $_.CreationDate -as [datetime] } -Descending | Select-Object -First 1).CreationDate
            $Difference = New-TimeSpan -Start $StartDate -End $EndDate

            $Line = [PSCustomObject]@{
            "SessionId"    = $SessionId
            "StartDate"    = $StartDate
            "EndDate"      = $EndDate
            "TotalSeconds" = $Difference.TotalSeconds
            "Duration"     = '{0} days {1} h {2} min {3} sec' -f $Difference.Days, $Difference.Hours,$Difference.Minutes,$Difference.Seconds
            }

            $Results += $Line
        }

        $Results | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\SessionIds-Duration.csv" -NoTypeInformation
    }
}

# XLSX
if (Get-Module -ListAvailable -Name ImportExcel)
{
    if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\SessionIds-Duration.csv")
    {
        if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\SessionIds-Duration.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\SessionIds-Duration.csv" -Delimiter "," | Sort-Object { $_.StartDate -as [datetime] } -Descending
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\XLSX\SessionIds-Duration.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Sessions" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:E1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of column A-E
            $WorkSheet.Cells["A:E"].Style.HorizontalAlignment="Center"
            }
        }
    }
}

$EndTime_Analytics = (Get-Date)
$Time_Analytics = ($EndTime_Analytics-$StartTime_Analytics)
('Analytics Processing duration:            {0} h {1} min {2} sec' -f $Time_Analytics.Hours, $Time_Analytics.Minutes, $Time_Analytics.Seconds) >> "$OUTPUT_FOLDER\Stats.txt"

}

Get-Analytics

#############################################################################################################################################################################################

Function Get-MailItemsAccessed {

# MailboxItemsAccessed (MIA)

$StartTime_MailItemsAccessed = (Get-Date)

# RecordType: ExchangeItemAggregated --> Events related to the MailItemsAccessed mailbox auditing action.
# Operation: MailItemsAccessed --> An operation in the UAL that indicates when a mail item or folder has been accessed or viewed by a user or application.
$MailboxItemRecords = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object { $_.RecordType -eq "ExchangeItemAggregated" } | Where-Object { $_.Operations -eq "MailItemsAccessed" } | Sort-Object { $_.CreationDate -as [datetime] } -Descending
$Count = [string]::Format('{0:N0}',($MailboxItemRecords | Measure-Object).Count)
if ($Count -gt 0)
{
    Write-Output "[Info]  Mailbox Auditing: MailItemsAccessed ($Count)"
    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV" -ItemType Directory -Force | Out-Null
    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\XLSX" -ItemType Directory -Force | Out-Null

    # Untouched
    $MailboxItemRecords | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\Untouched.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Get-Module -ListAvailable -Name ImportExcel)
    {
        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\Untouched.csv")
        {
            if([int](& $xsv count "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\Untouched.csv") -gt 0)
            {
                $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\Untouched.csv" -Delimiter "," -Encoding UTF8
                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\XLSX\Untouched.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "MailItemsAccessed" -CellStyleSB {
                param($WorkSheet)
                # BackgroundColor and FontColor for specific cells of TopRow
                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                Set-Format -Address $WorkSheet.Cells["A1:J1"] -BackgroundColor $BackgroundColor -FontColor White
                # HorizontalAlignment "Center" of columns A-D and F-J
                $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"
                $WorkSheet.Cells["F:J"].Style.HorizontalAlignment="Center"
                }
            }
        }
    }

    # AuditData
    $MailboxItemRecords | Select-Object -ExpandProperty AuditData | ConvertFrom-Json | Sort-Object { $_.CreationDate -as [datetime] } -Descending | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\AuditData.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Get-Module -ListAvailable -Name ImportExcel)
    {
        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\AuditData.csv")
        {
            if([int](& $xsv count "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\AuditData.csv") -gt 0)
            {
                $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\AuditData.csv" -Delimiter "," -Encoding UTF8
                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\XLSX\AuditData.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "AuditData" -CellStyleSB {
                param($WorkSheet)
                # BackgroundColor and FontColor for specific cells of TopRow
                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                Set-Format -Address $WorkSheet.Cells["A1:AA1"] -BackgroundColor $BackgroundColor -FontColor White
                # HorizontalAlignment "Center" of columns A-N and P-AA
                $WorkSheet.Cells["A:N"].Style.HorizontalAlignment="Center"
                $WorkSheet.Cells["P:AA"].Style.HorizontalAlignment="Center"
                }
            }
        }
    }

    # Custom CSV
    $Results = @()
    ForEach($Record in $MailboxItemRecords)
    {

        $AuditData = ConvertFrom-Json $Record.AuditData

        $Line = [PSCustomObject]@{
            CreationTime      = ($AuditData | Select-Object @{Name="CreationTime";Expression={([DateTime]::Parse($_.CreationTime).ToString("yyyy-MM-dd HH:mm:ss"))}}).CreationTime
            Id                = $AuditData.Id
            Operation         = $AuditData.Operation
            OrganizationId    = $AuditData.OrganizationId
            RecordType        = $AuditData.RecordType
            ResultStatus      = $AuditData.ResultStatus
            UserKey           = $AuditData.UserKey
            UserType          = $AuditData.UserType
            Version           = $AuditData.Version
            Workload          = $AuditData.Workload
            UserId            = $AuditData.UserId
            AppId             = $AuditData.AppId
            ClientAppId       = $AuditData.ClientAppId
            ClientIPAddress   = $AuditData.ClientIPAddress
            ClientInfoString  = $AuditData.ClientInfoString
            ExternalAccess    = $AuditData.ExternalAccess
            InternalLogonType = $AuditData.InternalLogonType
            LogonType         = $AuditData.LogonType
            LogonUserSid      = $AuditData.LogonUserSid
            MailboxGuid       = $AuditData.MailboxGuid
            MailboxOwnerSid   = $AuditData.MailboxOwnerSid
            MailboxOwnerUPN   = $AuditData.MailboxOwnerUPN

            # OperationProperties
            MailAccessType    = ($AuditData | Select-Object -ExpandProperty OperationProperties -ErrorAction SilentlyContinue | Where-Object {$_.Name -eq 'MailAccessType'}).Value
            IsThrottled       = ($AuditData | Select-Object -ExpandProperty OperationProperties -ErrorAction SilentlyContinue | Where-Object {$_.Name -eq 'IsThrottled'}).Value

            OrganizationName  = $AuditData.OrganizationName
            OriginatingServer = $AuditData.OriginatingServer

            # Folders --> FolderItems
            ClientRequestId   = ($AuditData | Select-Object -ExpandProperty Folders -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FolderItems -ErrorAction SilentlyContinue | Select-Object ClientRequestId -Unique).ClientRequestId -join "`r`n"
            InternetMessageId = ($AuditData | Select-Object -ExpandProperty Folders -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FolderItems -ErrorAction SilentlyContinue | Select-Object InternetMessageId).InternetMessageId -join "`r`n"
            SizeInBytes       = ($AuditData | Select-Object -ExpandProperty Folders -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FolderItems -ErrorAction SilentlyContinue | Select-Object SizeInBytes).SizeInBytes -join "`r`n"
            
            # Folders
            FolderId          = ($AuditData | Select-Object -ExpandProperty Folders -ErrorAction SilentlyContinue | Select-Object Id).Id -join "`r`n"
            Folder            = ($AuditData | Select-Object -ExpandProperty Folders -ErrorAction SilentlyContinue | Select-Object Path).Path -join "`r`n" # Folder & Mailbox

            OperationCount    = $AuditData.OperationCount # Aggregated Events
        }

        $Results += $Line
    }

    $Results | Sort-Object { $_.CreationTime -as [datetime] } -Descending | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\MailboxItemsAccessed.csv" -NoTypeInformation -Encoding UTF8

    # MailboxItemsAccessed.xlsx
    if (Get-Module -ListAvailable -Name ImportExcel)
    {
        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\MailboxItemsAccessed.csv")
        {
            if([int](& $xsv count "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\MailboxItemsAccessed.csv") -gt 0)
            {
                $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\MailboxItemsAccessed.csv" -Delimiter "," -Encoding UTF8
                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\XLSX\MailboxItemsAccessed.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "MailboxItemsAccessed" -CellStyleSB {
                param($WorkSheet)
                # BackgroundColor and FontColor for specific cells of TopRow
                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                Set-Format -Address $WorkSheet.Cells["A1:AF1"] -BackgroundColor $BackgroundColor -FontColor White
                # HorizontalAlignment "Center" of columns A-Z and AD-AF
                $WorkSheet.Cells["A:Z"].Style.HorizontalAlignment="Center"
                $WorkSheet.Cells["AD:AF"].Style.HorizontalAlignment="Center"
                }
            }
        }
    }

    # Stats
    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\CSV" -ItemType Directory -Force | Out-Null
    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\XLSX" -ItemType Directory -Force | Out-Null

    # AppId (Stats)
    $Total = (Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\MailboxItemsAccessed.csv" -Delimiter "," | Where-Object { $_.AppId -ne '' } | Select-Object AppId | Measure-Object).Count
    Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\MailboxItemsAccessed.csv" -Delimiter "," -Encoding UTF8 | Where-Object { $_.AppId -ne '' } | Group-Object AppId | Select-Object @{Name='AppId'; Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\CSV\AppId.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\CSV\AppId.csv")
    {
        if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\CSV\AppId.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\CSV\AppId.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\XLSX\AppId.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "AppId" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-C
            $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
            }
        }
    }

    # DisplayName (Stats)
    $AppIdRecords = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\CSV\AppId.csv" -Delimiter "," -Encoding UTF8

    # Sources

    # Microsoft First-Party Applications
    # https://github.com/MicrosoftDocs/SupportArticles-docs/blob/main/support/azure/active-directory/verify-first-party-apps-sign-in.md

    # DEV-Tenant
    # Connect-Azure
    # Get-AzureADServicePrincipal | Select-Object AppId,DisplayName | Sort-Object DisplayName | Export-Csv -Path "C:\Users\evild3ad\Desktop\Microsoft_First_Party_Applications.csv" -NoTypeInformation -Encoding UTF8

    # Azure Portal
    # Enterprise Applications --> List of Microsoft Apps in Entra ID (Entra Apps)

    # GitHub
    # https://github.com/merill/microsoft-info/blob/main/customdata/OtherMicrosoftApps.csv

    # Create HashTable and import 'Microsoft_Applications.csv'
    $HashTable = @{}
    if (Test-Path "$SCRIPT_DIR\Config\Microsoft_Applications.csv")
    {
        if([int](& $xsv count "$SCRIPT_DIR\Config\Microsoft_Applications.csv") -gt 0)
        {
            Import-Csv "$SCRIPT_DIR\Config\Microsoft_Applications.csv" -Delimiter "," | ForEach-Object { $HashTable[$_.AppId] = $_.DisplayName }

            # Count Ingested Properties
            $Count = $HashTable.Count
            Write-Output "[Info]  Initializing 'Microsoft_Applications.csv' Lookup Table ($Count) ..."
        }
    }

    # Custom CSV
    $Results = @()
    ForEach($Record in $AppIdRecords)
    {
        # AppId
        $AppId = $Record.AppId

        # Check if HashTable contains AppId
        if($HashTable.ContainsKey("$AppId"))
        {
            $DisplayName = $HashTable["$AppId"]
        }
        else
        {
            $DisplayName = ""
        }

        $Line = [PSCustomObject]@{
            "AppId"       = $Record.AppId
            "DisplayName" = $DisplayName
            "Count"       = $Record.Count
            "PercentUse"  = $Record.PercentUse
        }

        $Results += $Line
    }

    $Results | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\CSV\DisplayName.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Get-Module -ListAvailable -Name ImportExcel)
    {
        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\CSV\DisplayName.csv")
        {
            if([int](& $xsv count "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\CSV\DisplayName.csv") -gt 0)
            {
                $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\CSV\DisplayName.csv" -Delimiter ","
                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\XLSX\DisplayName.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "DisplayName" -CellStyleSB {
                param($WorkSheet)
                # BackgroundColor and FontColor for specific cells of TopRow
                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor White
                # HorizontalAlignment "Center" of columns A-D
                $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"
                }
            }
        }
    }

    # ClientAppId (Stats)
    $Total = (Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\MailboxItemsAccessed.csv" -Delimiter "," | Select-Object ClientAppId | Measure-Object).Count
    Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\MailboxItemsAccessed.csv" -Delimiter "," -Encoding UTF8 | Group-Object ClientAppId | Select-Object @{Name='ClientAppId'; Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\CSV\ClientAppId.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\CSV\ClientAppId.csv")
    {
        if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\CSV\ClientAppId.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\CSV\ClientAppId.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\XLSX\ClientAppId.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ClientAppId" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns B-C
            $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
            }
        }
    }

    # ClientInfoString (Stats)
    $Total = (Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\MailboxItemsAccessed.csv" -Delimiter "," | Select-Object ClientInfoString | Measure-Object).Count
    Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\MailboxItemsAccessed.csv" -Delimiter "," -Encoding UTF8 | Group-Object ClientInfoString | Select-Object @{Name='ClientInfoString'; Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\CSV\ClientInfoString.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\CSV\ClientInfoString.csv")
    {
        if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\CSV\ClientInfoString.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\CSV\ClientInfoString.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\XLSX\ClientInfoString.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ClientInfoString" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns B-C
            $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting
            Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Client=OWA;Action=ViaProxy",$A1)))' -BackgroundColor Red # AiTM Server
            }
        }
    }

    # AggregatedFolders (Stats)
    $Total = (Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\MailboxItemsAccessed.csv" -Delimiter "," | Select-Object Folder | Measure-Object).Count
    Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\MailboxItemsAccessed.csv" -Delimiter "," -Encoding UTF8 | Group-Object Folder | Select-Object @{Name='Folder'; Expression={$_.Name}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\CSV\AggregatedFolders.csv" -NoTypeInformation -Encoding UTF8
    
    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\CSV\AggregatedFolders.csv")
    {
        if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\CSV\AggregatedFolders.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\CSV\AggregatedFolders.csv" -Delimiter "," -Encoding UTF8
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\XLSX\AggregatedFolders.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "AggregatedFolders" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns B-C
            $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
            }
        }
    }

    # Folder (Stats)
    $Total = (Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\MailboxItemsAccessed.csv" -Delimiter "," | ForEach-Object {($_.Folder -split "`r`n")} | Measure-Object).Count
    Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\MailboxItemsAccessed.csv" -Delimiter "," -Encoding UTF8 | Select-Object Folder | ForEach-Object {($_.Folder -split "`r`n")} | Group-Object | Select-Object @{Name='Folder'; Expression={$_.Name}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\CSV\Folders.csv" -NoTypeInformation -Encoding UTF8
    
    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\CSV\Folders.csv")
    {
        if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\CSV\Folders.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\CSV\Folders.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\XLSX\Folders.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Folders" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns B-C
            $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
            }
        }
    }

    # MailAccessType (Stats) ---> MailItemsAccessed events are triggered by two event types: Sync and Bind operations.
    # Auditing sync access --> Sync access is recorded when a mailbox is accessed by a desktop version of the Outlook client for Windows or Mac.
    # Auditing bind access --> Bind access is recorded when an individual message is accessed.
    $Total = (Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\MailboxItemsAccessed.csv" -Delimiter "," | Select-Object MailAccessType | Measure-Object).Count
    Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\MailboxItemsAccessed.csv" -Delimiter "," -Encoding UTF8 | Group-Object MailAccessType | Select-Object @{Name='MailAccessType'; Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\CSV\MailAccessType.csv" -NoTypeInformation -Encoding UTF8

    # Count
    [int]$Bind = (Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\MailboxItemsAccessed.csv" -Delimiter "," | Where-Object { $_.MailAccessType -eq "Bind" } | Measure-Object).Count
    [int]$Sync = (Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\MailboxItemsAccessed.csv" -Delimiter "," | Where-Object { $_.MailAccessType -eq "Sync" } | Measure-Object).Count
    $BindAccess = '{0:N0}' -f $Bind
    $SyncAccess = '{0:N0}' -f $Sync
    Write-Output "[Info]  $BindAccess Bind Access Operation(s) and $SyncAccess Sync Access Operation(s) found"

    # OperationCount
    # Note: The MailItemsAccess operation writes an aggregated 2-minute window of activity into a single audit record.
    [int]$Sum = (Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\MailboxItemsAccessed.csv" -Delimiter "," | Select-Object OperationCount | Measure-Object -Property OperationCount -Sum).Sum
    $OperationCount = '{0:N0}' -f $Sum
    Write-Output "[Info]  Total number of accessed mailbox items: $OperationCount"

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\CSV\MailAccessType.csv")
    {
        if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\CSV\MailAccessType.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\CSV\MailAccessType.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\XLSX\MailAccessType.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "MailAccessType" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-C
            $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
            }
        }
    }

    # Line Charts
    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\XLSX\LineCharts" -ItemType Directory -Force | Out-Null

    # Accessed Mailbox Items per day
    $Import = Import-Csv -Path "$LogFile" -Delimiter "," | Where-Object { $_.RecordType -eq "ExchangeItemAggregated" } | Where-Object { $_.Operations -eq "MailItemsAccessed" } | Select-Object @{Name="CreationDate";Expression={([DateTime]::Parse($_.CreationDate).ToString("yyyy-MM-dd"))}} | Group-Object{($_.CreationDate -split "\s+")[0]} | Select-Object Count,@{Name='CreationDate'; Expression={ $_.Values[0] }} | Sort-Object { $_.CreationDate -as [datetime] }
    $ChartDefinition = New-ExcelChartDefinition -XRange CreationDate -YRange Count -Title "MailItemsAccessed" -ChartType Line -NoLegend -Width 1200
    $Import | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\XLSX\LineCharts\MailItemsAccessed.xlsx" -Append -WorksheetName "Line Chart" -AutoNameRange -ExcelChartDefinition $ChartDefinition

    # Count IP addresses
    Write-Output "[Info]  Parsing AuditData (JSON) for ClientIPAddress Property ..."
    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\ClientIPAddress" -ItemType Directory -Force | Out-Null
    $Data = Import-Csv -Path "$LogFile" -Delimiter "," | Where-Object { $_.RecordType -eq "ExchangeItemAggregated" } | Where-Object { $_.Operations -eq "MailItemsAccessed" } | Select-Object -ExpandProperty AuditData | ConvertFrom-Json | Select-Object -ExpandProperty ClientIPAddress -ErrorAction SilentlyContinue | Where-Object { $_.Trim() -ne "" }
    $Unique = $Data | Sort-Object -Unique
    $Unique | Out-File "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\ClientIPAddress\IP-All.txt"
    $Count = ($Unique | Measure-Object).Count
    $Total = ($Data | Measure-Object).Count
    Write-Output "[Info]  $Count IP addresses found ($Total)"

    # IPv4
    # https://ipinfo.io/bogon
    $IPv4 = "(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
    $Private = "^(192\.168|10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.)"
    $Special = "^(0\.0\.0\.0|127\.0\.0\.1|169\.254\.|224\.0\.0)"
    Get-Content "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\ClientIPAddress\IP-All.txt" | Select-String -Pattern $IPv4 -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique -Property { [System.Version]$_ } | Out-File "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\ClientIPAddress\IPv4-All.txt"
    Get-Content "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\ClientIPAddress\IP-All.txt" | Select-String -Pattern $IPv4 -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique -Property { [System.Version]$_ } | Where-Object {$_ -notmatch $Private} | Where-Object {$_ -notmatch $Special} | Out-File "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\ClientIPAddress\IPv4.txt"

    # Count
    $Total = (Get-Content "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\ClientIPAddress\IPv4-All.txt" | Measure-Object).Count # Public (Unique) + Private (Unique) --> Note: Extracts IPv4 addresses of IPv4-compatible IPv6 addresses.
    $Public = (Get-Content "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\ClientIPAddress\IPv4.txt" | Measure-Object).Count # Public (Unique)
    Write-Output "[Info]  $Public Public IPv4 addresses found ($Total)"
    
    # IPv6
    # https://ipinfo.io/bogon
    $IPv6 = ":(?::[a-f\d]{1,4}){0,5}(?:(?::[a-f\d]{1,4}){1,2}|:(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})))|[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}|:)|(?::(?:[a-f\d]{1,4})?|(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))))|:(?:(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|[a-f\d]{1,4}(?::[a-f\d]{1,4})?|))|(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|:[a-f\d]{1,4}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){0,2})|:))|(?:(?::[a-f\d]{1,4}){0,2}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:))|(?:(?::[a-f\d]{1,4}){0,3}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:))|(?:(?::[a-f\d]{1,4}){0,4}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:))"
    $Bogon = "^(::1|::ffff:|100::|2001:10::|2001:db8::|fc00::|fe80::|fec0::|ff00::)"
    Get-Content "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\ClientIPAddress\IP-All.txt" | Select-String -Pattern $IPv6 -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique | Out-File "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\ClientIPAddress\IPv6-All.txt"
    Get-Content "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\ClientIPAddress\IP-All.txt" | Select-String -Pattern $IPv6 -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique | Where-Object {$_ -notmatch $Bogon} | Out-File "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\ClientIPAddress\IPv6.txt"

    # Count
    $Total = (Get-Content "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\ClientIPAddress\IPv6-All.txt" | Measure-Object).Count # including Bogus IPv6 addresses (e.g. IPv4-compatible IPv6 addresses)
    $Public = (Get-Content "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\ClientIPAddress\IPv6.txt" | Measure-Object).Count
    Write-Output "[Info]  $Public Public IPv6 addresses found ($Total)"

    # IP.txt
    Write-Output "IPAddress" | Out-File "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\ClientIPAddress\IP.txt" -Encoding UTF8 # Header

    # IPv4.txt
    if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\ClientIPAddress\IPv4.txt")
    {
        if ((Get-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\ClientIPAddress\IPv4.txt").Length -gt 0kb)
        {
            Get-Content -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\ClientIPAddress\IPv4.txt" | Out-File "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\ClientIPAddress\IP.txt" -Encoding UTF8 -Append
        }
    }

    # IPv6.txt
    if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\ClientIPAddress\IPv6.txt")
    {
        if ((Get-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\ClientIPAddress\IPv6.txt").Length -gt 0kb)
        {
            Get-Content -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\ClientIPAddress\IPv6.txt" | Out-File "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\ClientIPAddress\IP.txt" -Append
        }
    }

    # IPinfo CLI (50k lookups per month, Geolocation data only)
    if (Test-Path "$($IPinfo)")
    {
        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\ClientIPAddress\IP.txt")
        {
            if ((Get-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\ClientIPAddress\IP.txt").Length -gt 0kb)
            {
                # Internet Connectivity Check (Vista+)
                $NetworkListManager = [Activator]::CreateInstance([Type]::GetTypeFromCLSID([Guid]‘{DCB00C01-570F-4A9B-8D69-199FDBA5723B}’)).IsConnectedToInternet

                if (!($NetworkListManager -eq "True"))
                {
                    Write-Host "[Error] Your computer is NOT connected to the Internet. IP addresses cannot be checked via IPinfo API." -ForegroundColor Red
                }
                else
                {
                    # Check if IPinfo.io is reachable
                    if (!(Test-NetConnection -ComputerName ipinfo.io -Port 443).TcpTestSucceeded)
                    {
                        Write-Host "[Error] ipinfo.io is NOT reachable. IP addresses cannot be checked via IPinfo API." -ForegroundColor Red
                    }
                    else
                    {
                        # Map IPs
                        # https://ipinfo.io/map
                        New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\ClientIPAddress\IPinfo" -ItemType Directory -Force | Out-Null
                        Get-Content "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\ClientIPAddress\IP.txt" | & $IPinfo map | Out-File "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\ClientIPAddress\IPinfo\Map.txt"

                        # Access Token
                        if (!("$Token" -eq "access_token"))
                        {
                            # Summarize IPs
                            # https://ipinfo.io/summarize-ips

                            # TXT (lists VPNs)
                            Get-Content "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\ClientIPAddress\IP.txt" | & $IPinfo summarize -t $Token | Out-File "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\ClientIPAddress\IPinfo\Summary.txt"
                        }
                    }
                }
            }
        }
    }

    # Create HashTable and import 'IPinfo-Custom.csv'
    $HashTable = @{}
    if (Test-Path "$OUTPUT_FOLDER\ClientIP\IPinfo\IPinfo-Custom.csv")
    {
        if([int](& $xsv count "$OUTPUT_FOLDER\ClientIP\IPinfo\IPinfo-Custom.csv") -gt 0)
        {
            Import-Csv "$OUTPUT_FOLDER\ClientIP\IPinfo\IPinfo-Custom.csv" -Delimiter "," -Encoding UTF8 | ForEach-Object { $HashTable[$_.IP] = $_.City,$_.Region,$_.Country,$_."Country Name",$_.ASN,$_.OrgName }

            # Count Ingested Properties
            $Count = $HashTable.Count
            Write-Output "[Info]  Initializing 'IPinfo-Custom.csv' Lookup Table ($Count) ..."
        }
    }

    # Hunt
    if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\MailboxItemsAccessed.csv")
    {
        if([int](& $xsv count "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\MailboxItemsAccessed.csv") -gt 0)
        {
            $Records = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\MailboxItemsAccessed.csv" -Delimiter "," -Encoding UTF8

            # CSV
            $Results = @()
            ForEach($Record in $Records)
            {
                # ClientIPAddress
                $ClientIPAddress = $Record.ClientIPAddress

                # Check if HashTable contains ClientIPAddress
                if($HashTable.ContainsKey("$ClientIPAddress"))
                {
                    $City        = $HashTable["$ClientIPAddress"][0]
                    $Region      = $HashTable["$ClientIPAddress"][1]
                    $Country     = $HashTable["$ClientIPAddress"][2]
                    $CountryName = $HashTable["$ClientIPAddress"][3]
                    $ASN         = $HashTable["$ClientIPAddress"][4]
                    $OrgName     = $HashTable["$ClientIPAddress"][5]
                }
                else
                {
                    $City        = ""
                    $Region      = ""
                    $Country     = ""
                    $CountryName = ""
                    $ASN         = ""
                    $OrgName     = ""
                }

                $Line = [PSCustomObject]@{
                    "CreationTime"      = $Record.CreationTime
                    "Id"                = $Record.Id
                    "Workload"          = $Record.Workload
                    "Operation"         = $Record.Operation
                    "MailAccessType"    = $Record.MailAccessType
                    "IsThrottled"       = $Record.IsThrottled
                    "UserId"            = $Record.UserId
                    "AppId"             = $Record.AppId
                    "ClientAppId"       = $Record.ClientAppId
                    "ClientIPAddress"   = $Record.ClientIPAddress
                    "City"              = $City
                    "Region"            = $Region
                    "Country"           = $Country
                    "Country Name"      = $CountryName
                    "ASN"               = $ASN
                    "OrgName"           = $OrgName
                    "ClientInfoString"  = $Record.ClientInfoString
                    "InternetMessageId" = $Record.InternetMessageId
                    "Folder"            = $Record.Folder
                    "OperationCount"    = $Record.OperationCount
                }

                $Results += $Line
            }

            $Results | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\Hunt.csv" -Delimiter "," -NoTypeInformation -Encoding UTF8

            # XLSX
            if (Get-Module -ListAvailable -Name ImportExcel)
            {
                if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\Hunt.csv")
                {
                    if([int](& $xsv count "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\Hunt.csv") -gt 0)
                    {
                        $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\Hunt.csv" -Delimiter ","
                        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\XLSX\Hunt.xlsx" -NoNumberConversion * -FreezePane 2,2 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Hunt" -CellStyleSB {
                        param($WorkSheet)
                        # BackgroundColor and FontColor for specific cells of TopRow
                        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                        Set-Format -Address $WorkSheet.Cells["A1:T1"] -BackgroundColor $BackgroundColor -FontColor White
                        # HorizontalAlignment "Center" of columns A-Q and S-T
                        $WorkSheet.Cells["A:Q"].Style.HorizontalAlignment="Center"
                        $WorkSheet.Cells["S:T"].Style.HorizontalAlignment="Center"
                        # ConditionalFormatting
                        Add-ConditionalFormatting -Address $WorkSheet.Cells["Q:Q"] -WorkSheet $WorkSheet -RuleType 'Expression' '=AND($Q1="Client=OWA;Action=ViaProxy",$O1<>"AS53813",$O1<>"AS62044")' -BackgroundColor Red # AiTM Proxy Server
                        }
                    }
                }
            }
         
            # ASN 
            
            # CSV (Stats)
            if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\Hunt.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\Hunt.csv") -gt 0)
                {
                    $Total = (Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\Hunt.csv" -Delimiter "," | Select-Object ASN | Where-Object {$_.ASN -ne '' } | Measure-Object).Count
                    Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\Hunt.csv" -Delimiter "," | Select-Object ASN,OrgName | Where-Object {$_.ASN -ne '' } | Where-Object {$null -ne ($_.PSObject.Properties | ForEach-Object {$_.Value})} | Group-Object ASN,OrgName | Select-Object Count,@{Name='ASN'; Expression={ $_.Values[0] }},@{Name='OrgName'; Expression={ $_.Values[1] }},@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\CSV\ASN.csv" -NoTypeInformation -Encoding UTF8
                }
            }

            # XLSX (Stats)
            if (Get-Module -ListAvailable -Name ImportExcel)
            {
                if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\CSV\ASN.csv")
                {
                    if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\CSV\ASN.csv") -gt 0)
                    {
                        $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\CSV\ASN.csv" -Delimiter ","
                        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\XLSX\ASN.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ASN" -CellStyleSB {
                        param($WorkSheet)
                        # BackgroundColor and FontColor for specific cells of TopRow
                        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                        Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor White
                        # HorizontalAlignment "Center" of columns A-D
                        $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"
                        }
                    }
                }
            }

            # ClientIPAddress / Country Name
                        
            # CSV (Stats)
            if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\Hunt.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\Hunt.csv") -gt 0)
                {
                    $Total = (Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\Hunt.csv" -Delimiter "," | Select-Object ClientIPAddress | Where-Object {$_.ClientIPAddress -ne '' } | Measure-Object).Count
                    Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\Hunt.csv" -Delimiter "," -Encoding UTF8| Select-Object ClientIPAddress,Country,"Country Name",ASN,OrgName | Where-Object {$_.ClientIPAddress -ne '' } | Where-Object {$_."Country Name" -ne '' } | Where-Object {$null -ne ($_.PSObject.Properties | ForEach-Object {$_.Value})} | Group-Object ClientIPAddress,Country,"Country Name",ASN,OrgName | Select-Object Count,@{Name='ClientIPAddress'; Expression={ $_.Values[0] }},@{Name='Country'; Expression={ $_.Values[1] }},@{Name='Country Name'; Expression={ $_.Values[2] }},@{Name='ASN'; Expression={ $_.Values[3] }},@{Name='OrgName'; Expression={ $_.Values[4] }},@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\CSV\ClientIPAddress.csv" -NoTypeInformation -Encoding UTF8
                }
            }

            # XLSX (Stats)
            if (Get-Module -ListAvailable -Name ImportExcel)
            {
                if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\CSV\ClientIPAddress.csv")
                {
                    if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\CSV\ClientIPAddress.csv") -gt 0)
                    {
                        $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\CSV\ClientIPAddress.csv" -Delimiter ","
                        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\XLSX\ClientIPAddress.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ClientIPAddress" -CellStyleSB {
                        param($WorkSheet)
                        # BackgroundColor and FontColor for specific cells of TopRow
                        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                        Set-Format -Address $WorkSheet.Cells["A1:G1"] -BackgroundColor $BackgroundColor -FontColor White
                        # HorizontalAlignment "Center" of columns A-G
                        $WorkSheet.Cells["A:G"].Style.HorizontalAlignment="Center"
                        }
                    }
                }
            }

            # Country / Country Name

            # CSV (Stats)
            if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\Hunt.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\Hunt.csv") -gt 0)
                {
                    $Total = (Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\Hunt.csv" -Delimiter "," | Select-Object Country | Where-Object {$_.Country -ne '' } | Measure-Object).Count
                    Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\Hunt.csv" -Delimiter "," | Select-Object Country,"Country Name" | Where-Object {$_.Country -ne '' } | Where-Object {$null -ne ($_.PSObject.Properties | ForEach-Object {$_.Value})} | Group-Object Country,"Country Name" | Select-Object Count,@{Name='Country'; Expression={ $_.Values[0] }},@{Name='Country Name'; Expression={ $_.Values[1] }},@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\CSV\Country.csv" -NoTypeInformation -Encoding UTF8
                                
                    # Countries
                    $Countries = (Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\Hunt.csv" -Delimiter "," | Select-Object Country -Unique | Where-Object { $_.Country -ne '' } | Measure-Object).Count

                    # Cities
                    $Cities = (Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\Hunt.csv" -Delimiter "," | Select-Object City -Unique | Where-Object { $_.City -ne '' } | Measure-Object).Count

                    Write-Output "[Info]  $Countries Countries and $Cities Cities found"
                }
            }

            # XLSX (Stats)
            if (Get-Module -ListAvailable -Name ImportExcel)
            {
                if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\CSV\Country.csv")
                {
                    if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\CSV\Country.csv") -gt 0)
                    {
                        $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\CSV\Country.csv" -Delimiter ","
                        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\XLSX\Country.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Countries" -CellStyleSB {
                        param($WorkSheet)
                        # BackgroundColor and FontColor for specific cells of TopRow
                        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                        Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor White
                        # HorizontalAlignment "Center" of columns A-D
                        $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"
                        }
                    }
                }
            }

            # Throttling of MailItemsAccessed Audit Records
            # If more than 1000 MailItemsAccessed audit records are generated in less than 24 hours, Exchange Online will stop generating auditing records for MailItemsAccessed activity. 
            # When a mailbox is throttled, MailItemsAccessed activity won't be logged for 24 hours after the mailbox was throttled. 
            # If the mailbox was throttled, there's a potential that mailbox could have been compromised during this period. 
            # The recording of MailItemsAccessed activity will be resumed following a 24-hour period.

            # - Less than 1% of all mailboxes in Exchange Online are throttled
            # - When a mailbox is throttling, only audit records for MailItemsAccessed activity aren't audited. Other mailbox auditing actions aren't affected.
            # - Mailboxes are throttled only for Bind operations. Audit records for sync operations aren't throttled.
            # - If a mailbox is throttled, you can probably assume there was MailItemsAccessed activity that wasn't recorded in the audit logs.

            # IsThrottled --> Exfiltration
            if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\Hunt.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\Hunt.csv") -gt 0)
                {
                    $Import = Import-Csv -Path "$LogFile" -Delimiter "," | Where-Object { $_.IsThrottled -eq "True" } | Sort-Object { $_.CreationTime -as [datetime] } -Descending
                    $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

                    if ($Count -gt 0)
                    {
                        Write-Host "[Alert] MailItemsAccessed Throttling: More than 1000 MailItemsAccessed Audit Records were generated in less than 24 hours ($Count)" -ForegroundColor Red
                    }
                }
            }
        }
    }
}

$EndTime_MailItemsAccessed = (Get-Date)
$Time_MailItemsAccessed = ($EndTime_MailItemsAccessed-$StartTime_MailItemsAccessed)
('MailItemsAccessed Processing duration:    {0} h {1} min {2} sec' -f $Time_MailItemsAccessed.Hours, $Time_MailItemsAccessed.Minutes, $Time_MailItemsAccessed.Seconds) >> "$OUTPUT_FOLDER\Stats.txt"

}

Get-MailItemsAccessed

# Notes
# - MailItemsAccessed applies to all logon types (Owner, Admin and Delegate)
# - Covers all email protocols, including POP, IMAP, MAPI, EWS, Exchange ActiveSync, and REST.
# - Monitors both sync and bind methods of accessing emails. Sync access is recorded when a mailbox is accessed by a desktop version of the Outlook client for Windows or Mac. Bind event is recorded when an individual message is accessed.
# - The InternetMessageId is a unique identifier assigned to each email message. With the InternetMessageId in hand, you can leverage the message trace log to retrieve the metadata of the exposed metadata.
# - The OperationCount indicates the number of messages that were accessed in a bind operation.

# Step #1 - Authenticate w/ Certificate

# Step #2 - Identify the email belonging to a particular InternetMessageId and retrieve its content
# Get-MgUserMessage -Filter "InternetMessageId eq '<InternetMessageId>'" -UserId <userid> | Format-List *

# Step #3 - Get email message as MSG
# $Message = Get-MgUserMessage -Filter "InternetMessageId eq '<InternetMessageId>'" -UserId <userid> | Format-List *
# Get-MgUserMessageContent -MessageId $Message.Id -UserId <userid> -OutFile "$env:USERPROFILE\export_suspicious_email.msg"

# Links
# https://www.aon.com/cyber-solutions/aon_cyber_labs/microsoft-365-identifying-mailbox-access/
# https://github.com/PwC-IR/MIA-MailItemsAccessed-
# https://learn.microsoft.com/en-us/purview/audit-log-investigate-accounts

#############################################################################################################################################################################################

Function Get-DeviceCodeAuthentication {

$StartTime_DeviceCodeAuthentication = (Get-Date)

# UserLoggedIn
$UserLoggedInRecords = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object { $_.RecordType -eq "AzureActiveDirectoryStsLogon" } | Where-Object { $_.Operations -eq "UserLoggedIn" }

# AuditData
$AuditData = $UserLoggedInRecords | Select-Object -ExpandProperty AuditData | ConvertFrom-Json | Sort-Object { $_.CreationDate -as [datetime] } -Descending

New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Device-Code-Authentication\CSV" -ItemType Directory -Force | Out-Null
New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Device-Code-Authentication\XLSX" -ItemType Directory -Force | Out-Null

# Custom CSV
$Results = @()
ForEach($Record in $UserLoggedInRecords)
{

    $AuditData = ConvertFrom-Json $Record.AuditData

    $Line = [PSCustomObject]@{
        CreationTime       = ($AuditData | Select-Object @{Name="CreationTime";Expression={([DateTime]::Parse($_.CreationTime).ToString("yyyy-MM-dd HH:mm:ss"))}}).CreationTime
        Id                 = $AuditData.Id
        Operation          = $AuditData.Operation
        OrganizationId     = $AuditData.OrganizationId
        RecordType         = $AuditData.RecordType
        ResultStatus       = $AuditData.ResultStatus
        UserKey            = $AuditData.UserKey
        UserType           = $AuditData.UserType
        Version            = $AuditData.Version
        Workload           = $AuditData.Workload
        ClientIP           = $AuditData.ClientIP
        ObjectId           = $AuditData.ObjectId
        UserId             = $AuditData.UserId
        AzureActiveDirectoryEventType = $AuditData.AzureActiveDirectoryEventType

        # ExtendedProperties
        ResultStatusDetail = ($AuditData | Select-Object -ExpandProperty ExtendedProperties | Where-Object {$_.Name -eq 'ResultStatusDetail'}).Value
        UserAgent          = ($AuditData | Select-Object -ExpandProperty ExtendedProperties | Where-Object {$_.Name -eq 'UserAgent'}).Value
        RequestType        = ($AuditData | Select-Object -ExpandProperty ExtendedProperties | Where-Object {$_.Name -eq 'RequestType'}).Value

        # ModifiedProperties
        ModifiedProperties = $AuditData | Select-Object -ExpandProperty ModifiedProperties

        # Actor
        ActorId            = ($AuditData | Select-Object -ExpandProperty Actor | Select-Object ID).ID -join "`r`n"
        ActorType          = ($AuditData | Select-Object -ExpandProperty Actor | Select-Object Type).Type -join "`r`n"

        ActorContextId     = $AuditData.ActorContextId
        ActorIpAddress     = $AuditData.ActorIpAddress
        InterSystemsId     = $AuditData.InterSystemsId
        IntraSystemId      = $AuditData.IntraSystemId
        SupportTicketId    = $AuditData.SupportTicketId

        # Target
        TargetId           = ($AuditData | Select-Object -ExpandProperty Target | Select-Object ID).ID -join "`r`n"
        TargetType         = ($AuditData | Select-Object -ExpandProperty Target | Select-Object Type).Type -join "`r`n"

        TargetContextId    = $AuditData.TargetContextId
        ApplicationId      = $AuditData.ApplicationId

        # DeviceProperties
        OS                 = ($AuditData | Select-Object -ExpandProperty DeviceProperties | Where-Object {$_.Name -eq 'OS'}).Value
        BrowserType        = ($AuditData | Select-Object -ExpandProperty DeviceProperties | Where-Object {$_.Name -eq 'BrowserType'}).Value
        IsCompliantAndManaged = ($AuditData | Select-Object -ExpandProperty DeviceProperties | Where-Object {$_.Name -eq 'IsCompliantAndManaged'}).Value
        SessionId          = ($AuditData | Select-Object -ExpandProperty DeviceProperties | Where-Object {$_.Name -eq 'SessionId'}).Value

        ErrorNumber        = $AuditData.ErrorNumber
    }

    $Results += $Line
}

$Results | Sort-Object { $_.CreationTime -as [datetime] } -Descending | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Device-Code-Authentication\CSV\UserLoggedIn.csv" -NoTypeInformation -Encoding UTF8

# UserLoggedIn.xlsx
if (Get-Module -ListAvailable -Name ImportExcel)
{
    if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Device-Code-Authentication\CSV\UserLoggedIn.csv")
    {
        if([int](& $xsv count "$OUTPUT_FOLDER\UnifiedAuditLogs\Device-Code-Authentication\CSV\UserLoggedIn.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Device-Code-Authentication\CSV\UserLoggedIn.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Device-Code-Authentication\XLSX\UserLoggedIn.xlsx" -NoNumberConversion * -NoHyperLinkConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "UserLoggedIn" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:AH1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-AH
            $WorkSheet.Cells["A:AH"].Style.HorizontalAlignment="Center"
            }
        }
    }
}

# M365 Device Code Phishing Attacks (OAuth2)
# Device Code Phishing exploits the device authorization grant flow in the Microsoft identity platform to allow an attacker's device or application access to the target user's account or system.
# Note: The device code is valid for only 15 minutes, giving the user a limited time window to view the phishing email and enter the device code for authentication on "https://microsoft.com/devicelogin”.

# https://microsoft.com/devicelogin --> https://login.microsoftonline.com/common/oauth2/deviceauth

# RecordType: AzureActiveDirectoryStsLogon --> Secure Token Service (STS) logon events in Azure Active Directory.
# Operation: UserLoggedIn --> A user signed in to their Microsoft 365 user account.
# RequestType: Cmsi:Cmsi --> ???
$DeviceCodeAuthenticationRecords = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Device-Code-Authentication\CSV\UserLoggedIn.csv" -Delimiter "," -Encoding UTF8 | Where-Object { $_.RecordType -eq "AzureActiveDirectoryStsLogon" } | Where-Object { $_.Operations -eq "UserLoggedIn" } | Where-Object { $_.RequestType -eq "Cmsi:Cmsi" } | Sort-Object { $_.CreationDate -as [datetime] } -Descending
$Count = [string]::Format('{0:N0}',($DeviceCodeAuthenticationRecords | Measure-Object).Count)
if ($Count -gt 0)
{
    Write-Host "[Alert] Potential Device Code Phishing Attack(s) detected ($Count)" -ForegroundColor Red
}

# Stats
New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Device-Code-Authentication\Stats\CSV" -ItemType Directory -Force | Out-Null
New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Device-Code-Authentication\Stats\XLSX" -ItemType Directory -Force | Out-Null

# RequestType (Stats)
if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Device-Code-Authentication\CSV\UserLoggedIn.csv")
{
    if([int](& $xsv count "$OUTPUT_FOLDER\UnifiedAuditLogs\Device-Code-Authentication\CSV\UserLoggedIn.csv") -gt 0)
    {
        $Total = (Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Device-Code-Authentication\CSV\UserLoggedIn.csv" -Delimiter "," | Select-Object RequestType | Measure-Object).Count
        Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Device-Code-Authentication\CSV\UserLoggedIn.csv" -Delimiter "," | Group-Object RequestType | Select-Object @{Name='RequestType'; Expression={$_.Name}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}}| Sort-Object Count -Descending | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Device-Code-Authentication\Stats\CSV\RequestType.csv" -NoTypeInformation -Encoding UTF8
    }
}

# XLSX
if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Device-Code-Authentication\Stats\CSV\RequestType.csv")
{
    if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Device-Code-Authentication\Stats\CSV\RequestType.csv") -gt 0)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Device-Code-Authentication\Stats\CSV\RequestType.csv" -Delimiter ","
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Device-Code-Authentication\Stats\XLSX\RequestType.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "RequestType" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
        Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
        # HorizontalAlignment "Center" of column A-C
        $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
        }
    }
}

$EndTime_DeviceCodeAuthentication = (Get-Date)
$Time_DeviceCodeAuthentication = ($EndTime_DeviceCodeAuthentication-$StartTime_DeviceCodeAuthentication)
('DeviceCodeAuthentication duration:        {0} h {1} min {2} sec' -f $Time_DeviceCodeAuthentication.Hours, $Time_DeviceCodeAuthentication.Minutes, $Time_DeviceCodeAuthentication.Seconds) >> "$OUTPUT_FOLDER\Stats.txt"

}

Get-DeviceCodeAuthentication

# RequestTypes --> Description??? Undocumented???
# Cmsi:Cmsi --> Device Code Authentication
# Kmsi:kmsi --> Keep Me Signed In feature???
# SAS:ProcessAuth
# OAuth2:Authorize
# Login:reprocess
# OAuth2:Token

#############################################################################################################################################################################################

Function Get-MicrosoftTeams {

# Microsoft Teams

# https://learn.microsoft.com/en-us/purview/audit-log-activities#microsoft-teams-shifts-activities
# https://learn.microsoft.com/en-us/purview/audit-teams-audit-log-events
# https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema#microsoft-teams-schema
# https://learn.microsoft.com/en-us/purview/ediscovery-document-metadata-fields

$StartTime_MicrosoftTeams = (Get-Date)

# MicrosoftTeams
$MicrosoftTeamsRecords = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object { $_.RecordType -eq "MicrosoftTeams" }

# Check if Microsoft Teams Records exist
$Count = [string]::Format('{0:N0}',($MicrosoftTeamsRecords | Measure-Object).Count)
if ($Count -eq 0)
{
    Return
}

New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\CSV" -ItemType Directory -Force | Out-Null
New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\XLSX" -ItemType Directory -Force | Out-Null

# Custom CSV
$Results = @()
ForEach($Record in $MicrosoftTeamsRecords)
{

    $AuditData = ConvertFrom-Json $Record.AuditData

    $Line = [PSCustomObject]@{
        CreationTime            = ($AuditData | Select-Object @{Name="CreationTime";Expression={([DateTime]::Parse($_.CreationTime).ToString("yyyy-MM-dd HH:mm:ss"))}}).CreationTime
        Id                      = $AuditData.Id
        Operation               = $AuditData.Operation
        OrganizationId          = $AuditData.OrganizationId
        RecordType              = $AuditData.RecordType
        UserKey                 = $AuditData.UserKey
        UserType                = $AuditData.UserType
        Version                 = $AuditData.Version
        Workload                = $AuditData.Workload
        ClientIP                = $AuditData.ClientIP
        ObjectId                = $AuditData.ObjectId
        UserId                  = $AuditData.UserId
        ChatThreadId            = $AuditData.ChatThreadId
        CommunicationType       = $AuditData.CommunicationType

        # ExtraProperties
        TimeZone                = ($AuditData | Select-Object -ExpandProperty ExtraProperties -ErrorAction SilentlyContinue | Where-Object {$_.Key -eq 'TimeZone'}).Value
        OsName                  = ($AuditData | Select-Object -ExpandProperty ExtraProperties -ErrorAction SilentlyContinue | Where-Object {$_.Key -eq 'OsName'}).Value
        OsVersion               = ($AuditData | Select-Object -ExpandProperty ExtraProperties -ErrorAction SilentlyContinue | Where-Object {$_.Key -eq 'OsVersion'}).Value
        Country                 = ($AuditData | Select-Object -ExpandProperty ExtraProperties -ErrorAction SilentlyContinue | Where-Object {$_.Key -eq 'Country'}).Value
        ClientName              = ($AuditData | Select-Object -ExpandProperty ExtraProperties -ErrorAction SilentlyContinue | Where-Object {$_.Key -eq 'ClientName'}).Value
        ClientVersion           = ($AuditData | Select-Object -ExpandProperty ExtraProperties -ErrorAction SilentlyContinue | Where-Object {$_.Key -eq 'ClientVersion'}).Value
        ClientUtcOffsetSeconds  = ($AuditData | Select-Object -ExpandProperty ExtraProperties -ErrorAction SilentlyContinue | Where-Object {$_.Key -eq 'ClientUtcOffsetSeconds'}).Value

        MessageId               = $AuditData.MessageId
        MessageReactionType     = $AuditData.MessageReactionType
        MessageVersion          = $AuditData.MessageVersion

        # ParticipantInfo
        HasForeignTenantUsers   = ($AuditData | Select-Object -ExpandProperty ParticipantInfo -ErrorAction SilentlyContinue | Select-Object HasForeignTenantUsers).HasForeignTenantUsers
        HasGuestUsers           = ($AuditData | Select-Object -ExpandProperty ParticipantInfo -ErrorAction SilentlyContinue | Select-Object HasGuestUsers).HasGuestUsers
        HasOtherGuestUsers      = ($AuditData | Select-Object -ExpandProperty ParticipantInfo -ErrorAction SilentlyContinue | Select-Object HasOtherGuestUsers).HasOtherGuestUsers
        HasUnauthenticatedUsers = ($AuditData | Select-Object -ExpandProperty ParticipantInfo -ErrorAction SilentlyContinue | Select-Object HasUnauthenticatedUsers).HasUnauthenticatedUsers
        ParticipatingTenantIds  = ($AuditData | Select-Object -ExpandProperty ParticipantInfo -ErrorAction SilentlyContinue | Select-Object ParticipatingTenantIds).ParticipatingTenantIds -join "`r`n"
        ParticipantDomains      = ($AuditData | Select-Object -ExpandProperty ParticipantInfo -ErrorAction SilentlyContinue | Select-Object ParticipantDomains).ParticipantDomains -join "`r`n"

        ChatName                = $AuditData.ChatName
        ItemName                = $AuditData.ItemName
    }

    $Results += $Line
}

$Results | Sort-Object { $_.CreationTime -as [datetime] } -Descending | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\CSV\MicrosoftTeams.csv" -NoTypeInformation -Encoding UTF8

# MicrosoftTeams.xlsx
if (Get-Module -ListAvailable -Name ImportExcel)
{
    if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\CSV\MicrosoftTeams.csv")
    {
        if([int](& $xsv count "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\CSV\MicrosoftTeams.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\CSV\MicrosoftTeams.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\XLSX\MicrosoftTeams.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "MicrosoftTeams" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:AC1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-AC
            $WorkSheet.Cells["A:AC"].Style.HorizontalAlignment="Center"
            }
        }
    }
}

# Stats
New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\Stats\CSV" -ItemType Directory -Force | Out-Null
New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\Stats\XLSX" -ItemType Directory -Force | Out-Null

# Operation (Stats)
if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\CSV\MicrosoftTeams.csv")
{
    if([int](& $xsv count "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\CSV\MicrosoftTeams.csv") -gt 0)
    {
        $Total = (Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\CSV\MicrosoftTeams.csv" -Delimiter "," | Select-Object Operation | Measure-Object).Count
        Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\CSV\MicrosoftTeams.csv" -Delimiter "," | Group-Object Operation | Select-Object @{Name='Operation'; Expression={$_.Name}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}}| Sort-Object Count -Descending | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\Stats\CSV\Operation.csv" -NoTypeInformation -Encoding UTF8
    }
}

# XLSX
if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\Stats\CSV\Operation.csv")
{
    if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\Stats\CSV\Operation.csv") -gt 0)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\Stats\CSV\Operation.csv" -Delimiter ","
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\Stats\XLSX\Operation.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Operation" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
        Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
        # HorizontalAlignment "Center" of column A-C
        $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
        }
    }
}

# Operations
# ChatCreated         - A Teams chat was created.
# MessageSent         - A new message was posted to a chat or channel.
# ReactedToMessage    - User reacted to a message.
# TeamsSessionStarted - A user signs in to a Microsoft Teams client. This event doesn't capture token refresh activities.

# CommunicationType (Stats)
if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\CSV\MicrosoftTeams.csv")
{
    if([int](& $xsv count "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\CSV\MicrosoftTeams.csv") -gt 0)
    {
        $Total = (Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\CSV\MicrosoftTeams.csv" -Delimiter "," | Select-Object CommunicationType | Measure-Object).Count
        Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\CSV\MicrosoftTeams.csv" -Delimiter "," | Group-Object CommunicationType | Select-Object @{Name='CommunicationType'; Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}}| Sort-Object Count -Descending | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\Stats\CSV\CommunicationType.csv" -NoTypeInformation -Encoding UTF8
    }
}

# ParticipantDomains (Stats)
# TODO

# XLSX
if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\Stats\CSV\CommunicationType.csv")
{
    if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\Stats\CSV\CommunicationType.csv") -gt 0)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\Stats\CSV\CommunicationType.csv" -Delimiter ","
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\Stats\XLSX\CommunicationType.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "CommunicationType" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
        Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
        # HorizontalAlignment "Center" of column A-C
        $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
        }
    }
}

# Line Charts
New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\Stats\XLSX\LineCharts" -ItemType Directory -Force | Out-Null

# MicrosoftTeams - Operations per day (Line Chart)
$Import = Import-Csv -Path "$LogFile" -Delimiter "," | Where-Object { $_.RecordType -eq "MicrosoftTeams" } | Select-Object @{Name="CreationDate";Expression={([DateTime]::Parse($_.CreationDate).ToString("yyyy-MM-dd"))}} | Group-Object{($_.CreationDate -split "\s+")[0]} | Select-Object Count,@{Name='CreationDate'; Expression={ $_.Values[0] }} | Sort-Object { $_.CreationDate -as [datetime] }
$Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
if ($Count -gt 0)
{
    $ChartDefinition = New-ExcelChartDefinition -XRange CreationDate -YRange Count -Title "Microsoft Teams" -ChartType Line -NoLegend -Width 1200
    $Import | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\Stats\XLSX\LineCharts\MicrosoftTeams.xlsx" -Append -WorksheetName "Line Chart" -AutoNameRange -ExcelChartDefinition $ChartDefinition
}

# Microsoft Teams Phishing --> Malicious payload placed on SharePoint Online

# - The threat actor has the capability to register a completely new tenant and generate a user account that mimics the identity of a particular individual, such as the CEO.
# - They leverage this account to send messages through Microsoft Teams.
# - By default, Microsoft Teams allows external messages from external organizations.
# - The attackers also use security terms or product-specific names into these subdomain names to lend credibility to the technical support-themed messages used as bait.
# - The victim will see that someone is trying to chat with them. It's possible to bypass this warning.
# - An audit record to this event is only logged when the operation is performed by calling a Microsoft Graph API.

# Microsoft Teams as phishing vector (Initial Access)
# RecordType: MicrosoftTeams --> Events from Microsoft Teams.
# Operations: ChatCreated --> A Teams chat was created.
$ChatCreated = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\CSV\MicrosoftTeams.csv" -Delimiter "," -Encoding UTF8 | Where-Object { $_.Operations -eq "ChatCreated" } | Sort-Object { $_.CreationDate -as [datetime] } -Descending
$Count = [string]::Format('{0:N0}',($ChatCreated | Measure-Object).Count)
if ($Count -gt 0)
{
    Write-Host "[Alert] Potential Microsoft Teams Phishing Attack(s) detected: ChatCreated ($Count)" -ForegroundColor Red
}

# Microsoft Teams as phishing vector (Initial Access)

# RecordType: MicrosoftTeams --> Events from Microsoft Teams.
# Operation: MessageSent --> A new message was posted to a chat or channel.
$MessageSentRecords = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object { $_.RecordType -eq "MicrosoftTeams" } | Where-Object { $_.Operations -eq "MessageSent" } 

# MessageSent.csv
$Results = @()
ForEach($Record in $MessageSentRecords)
{

    $AuditData = ConvertFrom-Json $Record.AuditData

    $Line = [PSCustomObject]@{
        CreationTime            = ($AuditData | Select-Object @{Name="CreationTime";Expression={([DateTime]::Parse($_.CreationTime).ToString("yyyy-MM-dd HH:mm:ss"))}}).CreationTime
        Id                      = $AuditData.Id
        Operation               = $AuditData.Operation
        OrganizationId          = $AuditData.OrganizationId
        RecordType              = $AuditData.RecordType
        UserKey                 = $AuditData.UserKey
        UserType                = $AuditData.UserType
        Version                 = $AuditData.Version
        Workload                = $AuditData.Workload
        ClientIP                = $AuditData.ClientIP
        UserId                  = $AuditData.UserId
        ChatThreadId            = $AuditData.ChatThreadId
        CommunicationType       = $AuditData.CommunicationType

        # ExtraProperties
        TimeZone                = ($AuditData | Select-Object -ExpandProperty ExtraProperties -ErrorAction SilentlyContinue | Where-Object {$_.Key -eq 'TimeZone'}).Value
        OsName                  = ($AuditData | Select-Object -ExpandProperty ExtraProperties -ErrorAction SilentlyContinue | Where-Object {$_.Key -eq 'OsName'}).Value
        OsVersion               = ($AuditData | Select-Object -ExpandProperty ExtraProperties -ErrorAction SilentlyContinue | Where-Object {$_.Key -eq 'OsVersion'}).Value
        Country                 = ($AuditData | Select-Object -ExpandProperty ExtraProperties -ErrorAction SilentlyContinue | Where-Object {$_.Key -eq 'Country'}).Value
        ClientName              = ($AuditData | Select-Object -ExpandProperty ExtraProperties -ErrorAction SilentlyContinue | Where-Object {$_.Key -eq 'ClientName'}).Value
        ClientVersion           = ($AuditData | Select-Object -ExpandProperty ExtraProperties -ErrorAction SilentlyContinue | Where-Object {$_.Key -eq 'ClientVersion'}).Value
        ClientUtcOffsetSeconds  = ($AuditData | Select-Object -ExpandProperty ExtraProperties -ErrorAction SilentlyContinue | Where-Object {$_.Key -eq 'ClientUtcOffsetSeconds'}).Value

        MessageId               = $AuditData.MessageId
        MessageVersion          = $AuditData.MessageVersion

        # ParticipantInfo
        HasForeignTenantUsers   = ($AuditData | Select-Object -ExpandProperty ParticipantInfo -ErrorAction SilentlyContinue | Select-Object HasForeignTenantUsers).HasForeignTenantUsers
        HasGuestUsers           = ($AuditData | Select-Object -ExpandProperty ParticipantInfo -ErrorAction SilentlyContinue | Select-Object HasGuestUsers).HasGuestUsers
        HasOtherGuestUsers      = ($AuditData | Select-Object -ExpandProperty ParticipantInfo -ErrorAction SilentlyContinue | Select-Object HasOtherGuestUsers).HasOtherGuestUsers
        HasUnauthenticatedUsers = ($AuditData | Select-Object -ExpandProperty ParticipantInfo -ErrorAction SilentlyContinue | Select-Object HasUnauthenticatedUsers).HasUnauthenticatedUsers
        ParticipatingTenantIds  = ($AuditData | Select-Object -ExpandProperty ParticipantInfo -ErrorAction SilentlyContinue | Select-Object ParticipatingTenantIds).ParticipatingTenantIds -join "`r`n"

        ChatName                = $AuditData.ChatName
        ItemName                = $AuditData.ItemName
    }

    $Results += $Line
}

$Results | Sort-Object { $_.CreationTime -as [datetime] } -Descending | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\CSV\MessageSent.csv" -NoTypeInformation -Encoding UTF8

# MessageSent.xlsx
if (Get-Module -ListAvailable -Name ImportExcel)
{
    if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\CSV\MessageSent.csv")
    {
        if([int](& $xsv count "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\CSV\MessageSent.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\CSV\MessageSent.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\XLSX\MessageSent.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "MessageSent" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:AC1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-AC
            $WorkSheet.Cells["A:AC"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting
            Add-ConditionalFormatting -Address $WorkSheet.Cells["U:U"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("True",$U1)))' -BackgroundColor Red # HasForeignTenantUsers
            Add-ConditionalFormatting -Address $WorkSheet.Cells["V:V"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("True",$V1)))' -BackgroundColor Red # HasGuestUsers
            Add-ConditionalFormatting -Address $WorkSheet.Cells["W:W"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("True",$W1)))' -BackgroundColor Red # HasOtherGuestUsers
            }
        }
    }
}

# Investigating Malicious Links shared in Microsoft Teams --> Get Messages with URLs in

# RecordType: MicrosoftTeams --> Events from Microsoft Teams.
# Operation: MessageCreatedHasLink --> A user sends a message containing a URL link in Teams.
$MessageCreatedHasLinkRecords = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object { $_.RecordType -eq "MicrosoftTeams" } | Where-Object { $_.Operations -eq "MessageCreatedHasLink" } 

# MessageCreatedHasLink.csv
$Results = @()
ForEach($Record in $MessageCreatedHasLinkRecords)
{

    $AuditData = ConvertFrom-Json $Record.AuditData

    $Line = [PSCustomObject]@{
        CreationTime            = ($AuditData | Select-Object @{Name="CreationTime";Expression={([DateTime]::Parse($_.CreationTime).ToString("yyyy-MM-dd HH:mm:ss"))}}).CreationTime
        Id                      = $AuditData.Id
        Operation               = $AuditData.Operation
        OrganizationId          = $AuditData.OrganizationId
        RecordType              = $AuditData.RecordType
        UserKey                 = $AuditData.UserKey
        UserType                = $AuditData.UserType
        Version                 = $AuditData.Version
        Workload                = $AuditData.Workload
        ClientIP                = $AuditData.ClientIP
        UserId                  = $AuditData.UserId
        ChatThreadId            = $AuditData.ChatThreadId
        CommunicationType       = $AuditData.CommunicationType

        # ExtraProperties
        TimeZone                = ($AuditData | Select-Object -ExpandProperty ExtraProperties -ErrorAction SilentlyContinue | Where-Object {$_.Key -eq 'TimeZone'}).Value
        OsName                  = ($AuditData | Select-Object -ExpandProperty ExtraProperties -ErrorAction SilentlyContinue | Where-Object {$_.Key -eq 'OsName'}).Value
        OsVersion               = ($AuditData | Select-Object -ExpandProperty ExtraProperties -ErrorAction SilentlyContinue | Where-Object {$_.Key -eq 'OsVersion'}).Value
        Country                 = ($AuditData | Select-Object -ExpandProperty ExtraProperties -ErrorAction SilentlyContinue | Where-Object {$_.Key -eq 'Country'}).Value
        ClientName              = ($AuditData | Select-Object -ExpandProperty ExtraProperties -ErrorAction SilentlyContinue | Where-Object {$_.Key -eq 'ClientName'}).Value
        ClientVersion           = ($AuditData | Select-Object -ExpandProperty ExtraProperties -ErrorAction SilentlyContinue | Where-Object {$_.Key -eq 'ClientVersion'}).Value
        ClientUtcOffsetSeconds  = ($AuditData | Select-Object -ExpandProperty ExtraProperties -ErrorAction SilentlyContinue | Where-Object {$_.Key -eq 'ClientUtcOffsetSeconds'}).Value

        MessageId               = $AuditData.MessageId
        MessageVersion          = $AuditData.MessageVersion

        # ParticipantInfo
        HasForeignTenantUsers   = ($AuditData | Select-Object -ExpandProperty ParticipantInfo -ErrorAction SilentlyContinue | Select-Object HasForeignTenantUsers).HasForeignTenantUsers
        HasGuestUsers           = ($AuditData | Select-Object -ExpandProperty ParticipantInfo -ErrorAction SilentlyContinue | Select-Object HasGuestUsers).HasGuestUsers
        HasOtherGuestUsers      = ($AuditData | Select-Object -ExpandProperty ParticipantInfo -ErrorAction SilentlyContinue | Select-Object HasOtherGuestUsers).HasOtherGuestUsers
        HasUnauthenticatedUsers = ($AuditData | Select-Object -ExpandProperty ParticipantInfo -ErrorAction SilentlyContinue | Select-Object HasUnauthenticatedUsers).HasUnauthenticatedUsers
        ParticipatingDomains    = $AuditData | Select-Object -ExpandProperty ParticipantInfo -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ParticipatingDomains -ErrorAction SilentlyContinue
        ParticipatingSIPDomains = $AuditData | Select-Object -ExpandProperty ParticipantInfo -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ParticipatingSIPDomains -ErrorAction SilentlyContinue
        ParticipatingTenantIds  = ($AuditData | Select-Object -ExpandProperty ParticipantInfo -ErrorAction SilentlyContinue | Select-Object ParticipatingTenantIds).ParticipatingTenantIds -join "`r`n"

        ResourceTenantId        = $AuditData.ResourceTenantId
        ItemName                = $AuditData.ItemName
        MessageURLs             = ($AuditData | Select-Object MessageURLs).MessageURLs -join "`r`n"
        URLs                    = ($AuditData| Select-Object -ExpandProperty MessageURLs).Count
    }

    $Results += $Line
}

$Results | Sort-Object { $_.CreationTime -as [datetime] } -Descending | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\CSV\MessageCreatedHasLink.csv" -NoTypeInformation -Encoding UTF8

# MessageCreatedHasLink.xlsx
if (Get-Module -ListAvailable -Name ImportExcel)
{
    if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\CSV\MessageCreatedHasLink.csv")
    {
        if([int](& $xsv count "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\CSV\MessageCreatedHasLink.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\CSV\MessageCreatedHasLink.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\XLSX\MessageCreatedHasLink.xlsx" -NoNumberConversion * -NoHyperLinkConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "MessageCreatedHasLink" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:AG1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-AG
            $WorkSheet.Cells["A:AG"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting
            Add-ConditionalFormatting -Address $WorkSheet.Cells["W:W"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("True",$W1)))' -BackgroundColor Red # HasForeignTenantUsers
            Add-ConditionalFormatting -Address $WorkSheet.Cells["X:X"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("True",$X1)))' -BackgroundColor Red # HasGuestUsers
            Add-ConditionalFormatting -Address $WorkSheet.Cells["Y:Y"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("True",$Y1)))' -BackgroundColor Red # HasOtherGuestUsers
            Add-ConditionalFormatting -Address $WorkSheet.Cells["AF:AF"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("http",$AF1)))' -BackgroundColor Red # MessageURLs
            }
        }
    }
}


# RecordType: MicrosoftTeams --> Events from Microsoft Teams.
# Operation: MessageUpdatedHasLink --> xxx
# TODO

# RecordType: MicrosoftTeams --> Events from Microsoft Teams.
# Operation: ChatCreated --> A Teams chat was created.
# TODO

$EndTime_MicrosoftTeams = (Get-Date)
$Time_MicrosoftTeams = ($EndTime_MicrosoftTeams-$StartTime_MicrosoftTeams)
('MicrosoftTeams Processing duration:       {0} h {1} min {2} sec' -f $Time_MicrosoftTeams.Hours, $Time_MicrosoftTeams.Minutes, $Time_MicrosoftTeams.Seconds) >> "$OUTPUT_FOLDER\Stats.txt"

}

Get-MicrosoftTeams

#endregion Analysis

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Footer

# Get End Time
$endTime = (Get-Date)

# Echo Time elapsed
Write-Output ""
Write-Output "FINISHED!"

$Time = ($endTime-$startTime)
$ElapsedTime = ('Overall analysis duration: {0} h {1} min {2} sec' -f $Time.Hours, $Time.Minutes, $Time.Seconds)
Write-Output "$ElapsedTime"

# Stop logging
Write-Host ""
Stop-Transcript
Start-Sleep 2

# MessageBox UI
$MessageBody = "Status: Unified Audit Log Analysis completed."
$MessageTitle = "UAL-Analyzer.ps1 (https://lethal-forensics.com/)"
$ButtonType = "OK"
$MessageIcon = "Information"
$Result = [System.Windows.Forms.MessageBox]::Show($MessageBody, $MessageTitle, $ButtonType, $MessageIcon)

if ($Result -eq "OK" ) 
{
    # Reset Progress Preference
    $Global:ProgressPreference = $OriginalProgressPreference

    # Reset Windows Title
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

#endregion Footer

#############################################################################################################################################################################################
#############################################################################################################################################################################################
