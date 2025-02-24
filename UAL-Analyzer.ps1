# UAL-Analyzer
#
# @author:    Martin Willing
# @copyright: Copyright (c) 2025 Martin Willing. All rights reserved. Licensed under the MIT license.
# @contact:   Any feedback or suggestions are always welcome and much appreciated - mwilling@lethal-forensics.com
# @url:       https://lethal-forensics.com/
# @date:      2025-02-24
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
# ImportExcel v7.8.10 (2024-10-21)
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
# Tested on Windows 10 Pro (x64) Version 22H2 (10.0.19045.5487) and PowerShell 5.1 (5.1.19041.5486)
# Tested on Windows 10 Pro (x64) Version 22H2 (10.0.19045.5487) and PowerShell 7.5.0
#
#
#############################################################################################################################################################################################
#############################################################################################################################################################################################

<#
.SYNOPSIS
  UAL-Analyzer - Automated Processing of M365 Unified Audit Logs for DFIR

.DESCRIPTION
  UAL-Analyzer.ps1 is a PowerShell script utilized to simplify the analysis of M365 Unified Audit Logs extracted via "Microsoft Extractor Suite" by Invictus Incident Response.

  https://github.com/invictus-ir/Microsoft-Extractor-Suite (Microsoft-Extractor-Suite v3.0.2)

  https://microsoft-365-extractor-suite.readthedocs.io/en/latest/functionality/M365/UnifiedAuditLog.html

  Single User Audit

.PARAMETER OutputDir
  Specifies the output directory. Default is "$env:USERPROFILE\Desktop\UAL-Analyzer".

  Note: The subdirectory 'UAL-Analyzer' is automatically created.

.PARAMETER Path
  Specifies the path to the CSV-based input file (UAL-Combined.csv).

.EXAMPLE
  PS> .\UAL-Analyzer.ps1

.EXAMPLE
  PS> .\UAL-Analyzer.ps1 -Path "$env:USERPROFILE\Desktop\UAL-Combined.csv"

.EXAMPLE
  PS> .\UAL-Analyzer.ps1 -Path "H:\Microsoft-Extractor-Suite\UAL-Combined.csv" -OutputDir "H:\Microsoft-Analyzer-Suite"

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
    [String]$Path,
    [String]$OutputDir
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

# Colors
Add-Type -AssemblyName System.Drawing
$script:Green  = [System.Drawing.Color]::FromArgb(0,176,80) # Green
$script:Orange = [System.Drawing.Color]::FromArgb(255,192,0) # Orange

# Output Directory
if (!($OutputDir))
{
    $script:OUTPUT_FOLDER = "$env:USERPROFILE\Desktop\UAL-Analyzer" # Default
}
else
{
    if ($OutputDir -cnotmatch '.+(?=\\)') 
    {
        Write-Host "[Error] You must provide a valid directory path." -ForegroundColor Red
        Exit
    }
    else
    {
        $script:OUTPUT_FOLDER = "$OutputDir\UAL-Analyzer" # Custom
    }
}

# Tools

# IPinfo CLI
$script:IPinfo = "$SCRIPT_DIR\Tools\IPinfo\ipinfo.exe"

# xsv
$script:xsv = "$SCRIPT_DIR\Tools\xsv\xsv.exe"

# ASN Whitelist
$script:Whitelist = (Import-Csv "$SCRIPT_DIR\Whitelists\ASN-Whitelist.csv" -Delimiter "," | Select-Object -ExpandProperty ASN) -join "|"

# Configuration File
if(!(Test-Path "$PSScriptRoot\Config.ps1"))
{
    Write-Host "[Error] Config.ps1 NOT found." -ForegroundColor Red
}
else
{
    . "$PSScriptRoot\Config.ps1"
}

#endregion Declarations

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Header

# Check if the PowerShell script is being run with admin rights
if (!([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
    Write-Host "[Error] This PowerShell script must be run with admin rights." -ForegroundColor Red
    Exit
}

# Check if PowerShell module 'ImportExcel' is installed
if (!(Get-Module -ListAvailable -Name ImportExcel))
{
    Write-Host "[Error] Please install 'ImportExcel' PowerShell module." -ForegroundColor Red
    Write-Host "[Info]  Check out: https://github.com/evild3ad/Microsoft-Analyzer-Suite/wiki#setup"
    Exit
}

# Windows Title
$DefaultWindowsTitle = $Host.UI.RawUI.WindowTitle
$Host.UI.RawUI.WindowTitle = "UAL-Analyzer - Automated Processing of M365 Unified Audit Logs for DFIR"

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
Write-Output "UAL-Analyzer - Automated Processing of M365 Unified Audit Logs for DFIR"
Write-Output "(c) 2025 Martin Willing at Lethal-Forensics (https://lethal-forensics.com/)"
Write-Output ""

# Analysis date (ISO 8601)
$script:AnalysisDate = [datetime]::Now.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
Write-Output "Analysis date: $AnalysisDate UTC"
Write-Output ""

# Blacklists

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

# Create HashTable and import 'MoveToFolder-Blacklist.csv'
$script:MoveToFolderBlacklist_HashTable = [ordered]@{}
if (Test-Path "$SCRIPT_DIR\Blacklists\MoveToFolder-Blacklist.csv")
{
    if([int](& $xsv count "$SCRIPT_DIR\Blacklists\MoveToFolder-Blacklist.csv") -gt 0)
    {
        Import-Csv "$SCRIPT_DIR\Blacklists\MoveToFolder-Blacklist.csv" -Delimiter "," | ForEach-Object { $MoveToFolderBlacklist_HashTable[$_.Name] = $_.Language }

        # Count Ingested Properties
        $Count = $MoveToFolderBlacklist_HashTable.Count
        Write-Output "[Info]  Initializing 'MoveToFolder-Blacklist.csv' Lookup Table ($Count) ..."
    }
}

# Create HashTable and import 'UserAgent-Blacklist.csv'
$script:UserAgentBlacklist_HashTable = [ordered]@{}
if (Test-Path "$SCRIPT_DIR\Blacklists\UserAgent-Blacklist.csv")
{
    if([int](& $xsv count "$SCRIPT_DIR\Blacklists\UserAgent-Blacklist.csv") -gt 0)
    {
        Import-Csv "$SCRIPT_DIR\Blacklists\UserAgent-Blacklist.csv" -Delimiter "," | ForEach-Object { $UserAgentBlacklist_HashTable[$_.UserAgent] = $_.Category,$_.Severity }

        # Count Ingested Properties
        $Count = $UserAgentBlacklist_HashTable.Count
        Write-Output "[Info]  Initializing 'UserAgent-Blacklist.csv' Lookup Table ($Count) ..."
    }
}

# Configurations

# Create HashTable and import 'LogonType.csv'
$script:LogonType_HashTable = @{}
if(Test-Path "$SCRIPT_DIR\Config\LogonType.csv")
{
    if([int](& $xsv count "$SCRIPT_DIR\Config\LogonType.csv") -gt 0)
    {
        Import-Csv "$SCRIPT_DIR\Config\LogonType.csv" -Delimiter "," -Encoding UTF8 | ForEach-Object { $LogonType_HashTable[$_.Value] = $_.LogonType }
    }
}

# Create HashTable and import 'MicrosoftApps.csv'
$script:MicrosoftApps_HashTable = @{}
if(Test-Path "$SCRIPT_DIR\Config\MicrosoftApps.csv")
{
    if([int](& $xsv count "$SCRIPT_DIR\Config\MicrosoftApps.csv") -gt 0)
    {
        Import-Csv "$SCRIPT_DIR\Config\MicrosoftApps.csv" -Delimiter "," -Encoding UTF8 | ForEach-Object { $MicrosoftApps_HashTable[$_.AppId] = $_.AppDisplayName }
    }
}

# Create HashTable and import 'Status.csv'
$script:ErrorNumber_HashTable = @{}
if(Test-Path "$SCRIPT_DIR\Config\Status.csv")
{
    if([int](& $xsv count "$SCRIPT_DIR\Config\Status.csv") -gt 0)
    {
        Import-Csv "$SCRIPT_DIR\Config\Status.csv" -Delimiter "," -Encoding UTF8 | ForEach-Object { $ErrorNumber_HashTable[$_.ErrorCode] = $_.Status, $_.Message }
    }
}

# Create HashTable and import 'TrustType.csv'
$script:TrustType_HashTable = @{}
if(Test-Path "$SCRIPT_DIR\Config\TrustType.csv")
{
    if([int](& $xsv count "$SCRIPT_DIR\Config\TrustType.csv") -gt 0)
    {
        Import-Csv "$SCRIPT_DIR\Config\TrustType.csv" -Delimiter "," -Encoding UTF8 | ForEach-Object { $TrustType_HashTable[$_.Value] = $_.Description }
    }
}

# Create HashTable and import 'UserType.csv'
$script:UserType_HashTable = @{}
if(Test-Path "$SCRIPT_DIR\Config\UserType.csv")
{
    if([int](& $xsv count "$SCRIPT_DIR\Config\UserType.csv") -gt 0)
    {
        Import-Csv "$SCRIPT_DIR\Config\UserType.csv" -Delimiter "," -Encoding UTF8 | ForEach-Object { $UserType_HashTable[$_.Value] = $_.Member, $_.Description }
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
if (!(Test-Path "$LogFile" -PathType Leaf))
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
    Write-Host "[Error] No IPinfo CLI Access Token provided. Please add your personal access token to 'Config.ps1'" -ForegroundColor Red
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

# Time Frame
$CreationTime = Import-Csv -Path "$LogFile" -Delimiter "," | Select-Object -ExpandProperty AuditData | ConvertFrom-Json | Select-Object CreationTime | Sort-Object { $_.CreationTime -as [datetime] }
$StartTime = $CreationTime | Select-Object -First 1 | Select-Object -ExpandProperty CreationTime | ForEach-Object {$_ -replace 'T',' '}
$EndTime = $CreationTime | Select-Object -Last 1 | Select-Object -ExpandProperty CreationTime | ForEach-Object {$_ -replace 'T',' '}
Write-Output "[Info]  Log data from $StartTime UTC until $EndTime UTC"

# Estimated Analysis Time
('[Info]  Estimated Analysis Time: {0} h {1} min {2} sec' -f $TimeSpan.Hours, $TimeSpan.Minutes, $TimeSpan.Seconds)

# XLSX

# Untouched
if (Test-Path "$LogFile")
{
    if([int](& $xsv count -d "," "$LogFile") -gt 0)
    {
        $IMPORT = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Sort-Object { $_.CreationDate -as [datetime] } -Descending
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\XLSX\Untouched.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Untouched" -CellStyleSB {
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

# File Size (XLSX)
if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\XLSX\1-Untouched.xlsx")
{
    $Size = Get-FileSize((Get-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\XLSX\1-Untouched.xlsx").Length)
    Write-Output "[Info]  File Size (XLSX) : $Size"
}

# Custom CSV (incl. removing duplicates)
$Data = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Sort-Object Identity -Unique | Sort-Object { $_.CreationDate -as [datetime] } -Descending

$Results = [Collections.Generic.List[PSObject]]::new()
ForEach($Record in $Data)
{
    $AuditData = $Record.AuditData | ConvertFrom-Json
    $ClientIP = $AuditData.ClientIP | & $IPinfo grepip -o # Remove Port Number from IPv4 (if existing)
    $AppAccessContext = $AuditData.AppAccessContext

    $UserLoggedIn = $AuditData | Where-Object { $_.Operation -eq "UserLoggedIn" }

    if ($null -ne $UserLoggedIn)
    {
        $SessionId = ($AuditData | Where-Object { $_.Operation -eq "UserLoggedIn" } | Select-Object -ExpandProperty DeviceProperties | Where-Object {$_.Name -eq 'SessionId'}).Value
        $UserAgent = ($AuditData | Where-Object { $_.Operation -eq "UserLoggedIn" } | Select-Object -ExpandProperty ExtendedProperties | Where-Object {$_.Name -eq 'UserAgent'}).Value
    }
    else
    {
        $SessionId = ($AuditData | Select-Object SessionId).SessionId
        $UserAgent = $AuditData.UserAgent
    }

    $Line = [PSCustomObject]@{
    "CreationTime"          = $AuditData | Select-Object -ExpandProperty CreationTime | ForEach-Object {$_ -replace 'T',' '}
    "UserId"                = $Record.UserIds
    "Id"                    = $AuditData.RecordType
    "RecordType"            = $Record.RecordType
    "Operation"             = $Record.Operations
    "ObjectId"              = $AuditData.ObjectId
    "ClientIP"              = $ClientIP
    "ClientIPAddress"       = $AuditData.ClientIPAddress
    "UserAgent"             = $UserAgent
    "ClientInfoString"      = $AuditData.ClientInfoString
    "RequestType"           = ($AuditData | Where-Object { $_.Operation -eq "UserLoggedIn" } | Select-Object -ExpandProperty ExtendedProperties | Where-Object {$_.Name -eq 'RequestType'}).Value
    "SessionId"             = $SessionId
    "InterSystemsId"        = $AuditData.InterSystemsId # The GUID that track the actions across components within the Office 365 service
    "DeviceName"            = ($AuditData | Where-Object { $_.Operation -eq "UserLoggedIn" } | Select-Object -ExpandProperty DeviceProperties | Where-Object {$_.Name -eq 'DisplayName'}).Value
    "DeviceId"              = ($AuditData | Where-Object { $_.Operation -eq "UserLoggedIn" } | Select-Object -ExpandProperty DeviceProperties | Where-Object {$_.Name -eq 'Id'}).Value
    "OS"                    = ($AuditData | Where-Object { $_.Operation -eq "UserLoggedIn" } | Select-Object -ExpandProperty DeviceProperties | Where-Object {$_.Name -eq 'OS'}).Value
    "BrowserType"           = ($AuditData | Where-Object { $_.Operation -eq "UserLoggedIn" } | Select-Object -ExpandProperty DeviceProperties | Where-Object {$_.Name -eq 'BrowserType'}).Value
    "IsCompliant"           = ($AuditData | Where-Object { $_.Operation -eq "UserLoggedIn" } | Select-Object -ExpandProperty DeviceProperties | Where-Object {$_.Name -eq 'IsCompliant'}).Value
    "IsCompliantAndManaged" = ($AuditData | Where-Object { $_.Operation -eq "UserLoggedIn" } | Select-Object -ExpandProperty DeviceProperties | Where-Object {$_.Name -eq 'IsCompliantAndManaged'}).Value
    "Workload"              = $AuditData.Workload
    "IssuedAtTime"          = $AppAccessContext.IssuedAtTime
    "UniqueTokenId"         = $AppAccessContext.UniqueTokenId
    }

    $Results.Add($Line)
}

$Results | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Custom.csv" -NoTypeInformation -Encoding UTF8

# Custom XLSX
if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Custom.csv")
{
    if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Custom.csv") -gt 0)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Custom.csv" -Delimiter ","
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\XLSX\Custom.xlsx" -NoHyperLinkConversion * -NoNumberConversion * -FreezePane 2,6 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Custom View" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
        Set-Format -Address $WorkSheet.Cells["A1:V1"] -BackgroundColor $BackgroundColor -FontColor White
        # HorizontalAlignment "Center" of columns A-E and G-V
        $WorkSheet.Cells["A:E"].Style.HorizontalAlignment="Center"
        $WorkSheet.Cells["G:V"].Style.HorizontalAlignment="Center"
        }
    }
}

# XLSX
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

# Stats
New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Stats" -ItemType Directory -Force | Out-Null

# ClientInfoString (Stats)
$Total = (Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Custom.csv" -Delimiter "," | Select-Object ClientInfoString | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Custom.csv" -Delimiter "," -Encoding UTF8 | Group-Object ClientInfoString | Select-Object @{Name='ClientInfoString'; Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Stats\ClientInfoString.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ClientInfoString" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns B-C
    $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
    # ConditionalFormatting
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Client=OWA;Action=ViaProxy",$A1)))' -BackgroundColor Red # AiTM Server
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Client=WebServices;eM Client",$A1)))' -BackgroundColor Red # eM Client
    }
}

# DeviceProperties (Stats)
$Data = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Custom.csv" -Delimiter "," | Select-Object DeviceId
$Devices = ($Data | Where-Object {$_.DeviceId -ne '' } | Select-Object DeviceId -Unique | Measure-Object).Count
$Total = ($Data | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Custom.csv" -Delimiter "," -Encoding UTF8 | Select-Object DeviceName,DeviceId | Group-Object DeviceName,DeviceId | Select-Object @{Name='DeviceName'; Expression={if($_.Values[0]){$_.Values[0]}else{'N/A'}}},@{Name='DeviceId'; Expression={if($_.Values[1]){$_.Values[0]}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Stats\DeviceProperties.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "DeviceProperties" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of column B-D
    $WorkSheet.Cells["B:D"].Style.HorizontalAlignment="Center"
    }

    Write-Output "[Info]  $Devices Device Identities found ($Total)"
}

# Operations (Stats)
# https://learn.microsoft.com/en-us/purview/audit-log-activities
# https://learn.microsoft.com/en-us/purview/ediscovery-search-for-activities-in-the-audit-log
# https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities
$Operations = (Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Select-Object Operations | Sort-Object Operations -Unique | Measure-Object).Count
$Total = (Import-Csv -Path "$LogFile" -Delimiter "," | Select-Object Operations | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Group-Object Operations | Select-Object @{Name='Operation'; Expression={$_.Name}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Stats\Operation.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Operations" -CellStyleSB {
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
    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(SEARCH("Set-InboxRule",$A1)))' -BackgroundColor Red # PowerShell/API or M365 Portal
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
    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("HygieneTenantEvents",$A1)))' -BackgroundColor Red # Hygiene events are related to outbound spam protection. These events are related to users who are restricted from sending email.
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

# RecordType (Stats)
$RecordTypes = (Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Select-Object RecordType | Sort-Object RecordType -Unique | Measure-Object).Count
$Total = (Import-Csv -Path "$LogFile" -Delimiter "," | Select-Object "File Path" | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Group-Object RecordType | Select-Object @{Name='RecordType'; Expression={$_.Name}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Stats\RecordType.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "RecordType" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of column B-C
    $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
    }

    Write-Output "[Info]  $RecordTypes RecordTypes and $Operations Operations found"
}

# RecordType / Id (Stats)
$Total = (Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Custom.csv" -Delimiter "," | Select-Object RecordType | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Custom.csv" -Delimiter "," -Encoding UTF8 | Group-Object Id,RecordType | Select-Object @{Name='Id'; Expression={ $_.Values[0] }},@{Name='RecordType'; Expression={ $_.Values[1] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Stats\RecordType-Id.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "RecordType" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of column A and C-D
    $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
    $WorkSheet.Cells["C:D"].Style.HorizontalAlignment="Center"
    }
}

# RecordType / Id / Workload
$Total = (Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Custom.csv" -Delimiter "," | Select-Object RecordType | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Custom.csv" -Delimiter "," -Encoding UTF8 | Group-Object Id,RecordType,Workload | Select-Object @{Name='Id'; Expression={ $_.Values[0] }},@{Name='RecordType'; Expression={ $_.Values[1] }},@{Name='Workload'; Expression={ $_.Values[2] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Stats\RecordType-Id-Workload.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "RecordType" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:E1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of column A and C-E
    $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
    $WorkSheet.Cells["C:E"].Style.HorizontalAlignment="Center"
    }
}

# RequestType (Stats)
$Total = (Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Custom.csv" -Delimiter "," | Select-Object RequestType | Where-Object {$_.RequestType -ne '' } | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Custom.csv" -Delimiter "," | Select-Object RequestType | Where-Object {$_.RequestType -ne '' } | Where-Object {$null -ne ($_.PSObject.Properties | ForEach-Object {$_.Value})} | Group-Object RequestType | Select-Object @{Name='RequestType'; Expression={$_.Name}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Stats\RequestType.xlsx" -NoHyperLinkConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "RequestType" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of column B-C
    $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
    # ConditionalFormatting - RequestType
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Consent:Set",$A1)))' -BackgroundColor Yellow # User Application Consent (Consent Permissions Grant)
    }
}

# RequestTypes --> Type of Authentication (Microsoft Entra Authentication)
# Cmsi:Cmsi              Check My Sign In (CMSI). For security reasons, user confirmation is required for this request. Indicates use of device code auth. 
# Consent:Set            Permissions requested and confirmed by user.
# Kmsi:kmsi              Keep Me Signed In (KMSI) prompt --> Stay signed in?
# Login:login            ???
# Login:reprocess        This likely indicates that the user's session has expired. When the user attempts to access the application or service again, he is prompted to reauthenticate.
# Login:resume           ???
# OAuth2:Authorize       ???
# OAuth2:Login*          This usually happens when a user is trying to sign into an application that uses Office 365 resources, and the application is requesting to authenticate the user by redirecting them to the OAuth 2.0 login process.
# OAuth2:Token           This likely indicates a token request action in the OAuth 2.0 authorization framework. This token is then used to access protected resources on behalf of the user. When an application has successfully authenticated with the user's credentials, it will make a token request to receive an access token that allows it to access the user's resources in Office 365.
# OrgIdWsTrust2:process  ???
# PermitSso:PermitSso    ???
# Saml2:processrequest   ???
# SAS:BeginAuth          ???
# SAS:EndAuth            ???
# SAS:ProcessAuth        ???
# SSPR:end               ???
# WindowsAuthenticationControllerusernamemixed       ???
# WindowsAuthewnticationControllerwindowstransport   ???
# WsFederation:wsfederation   ???

# EndpointCall (AADSignInEventsBeta --> Microsoft Entra interactive and non-interactive sign-ins)
# Note: You need to have a Microsoft Entra ID P2 license to collect and view activities for this table.
# Information about the AAD endpoint that the request was sent to and the type of request sent during sign in.
# https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-aadsignineventsbeta-table
# https://www.reliaquest.com/blog/business-email-compromise-detection/

# UserAgent (Stats)
$Total = (Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Custom.csv" -Delimiter "," | Select-Object UserAgent | Where-Object {$_.UserAgent -ne '' } | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Custom.csv" -Delimiter "," | Select-Object UserAgent | Where-Object {$_.UserAgent -ne '' } | Where-Object {$null -ne ($_.PSObject.Properties | ForEach-Object {$_.Value})} | Group-Object UserAgent | Select-Object @{Name='UserAgent'; Expression={$_.Name}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Stats\UserAgent.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "UserAgent" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of column B-C
    $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"

    # Iterating over the UserAgent-Blacklist HashTable
    foreach ($UserAgent in $UserAgentBlacklist_HashTable.Keys) 
    {
        $Severity = $UserAgentBlacklist_HashTable["$UserAgent"][1]
        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$A1)))' -f $UserAgent
        Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
    }

    }
}

# Suspicious Operations

# Inbox Rules
# Inbox Rules let users automate actions on incoming emails when they match specific criteria, such as containing certain words in the subject line or coming from a particular sender. 
# These actions can include moving messages to designated folders, marking them as read, or forwarding them to external addresses. 

# New-InboxRule --> Create a new Inbox Rule in a mailbox
# https://learn.microsoft.com/en-us/powershell/module/exchange/new-inboxrule?view=exchange-ps
# Hide Artifacts: Email Hiding Rules [T1564.008] --> https://attack.mitre.org/techniques/T1564/008/
$Import = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object { $_.RecordType -eq "ExchangeAdmin" } | Where-Object { $_.Operations -eq "New-InboxRule" } | Sort-Object Identity -Unique | Sort-Object { $_.CreationDate -as [datetime] } -Descending
$Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
if ($Count -gt 0)
{
    Write-Host "[Alert] Suspicious Operation(s) detected: New-InboxRule ($Count)" -ForegroundColor Red
    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV" -ItemType Directory -Force | Out-Null
    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\XLSX" -ItemType Directory -Force | Out-Null

    # CSV
    $Import | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\New-InboxRule.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\New-InboxRule.csv")
    {
        if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\New-InboxRule.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\New-InboxRule.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\XLSX\New-InboxRule.xlsx" -FreezePane 2,5 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "New-InboxRule" -CellStyleSB {
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

    # AuditData

    # CSV
    $Results = [Collections.Generic.List[PSObject]]::new()
    ForEach($Record in $Import)
    {
        $AuditData = $Record.AuditData | ConvertFrom-Json
        $Parameters = $AuditData.Parameters
        $AppAccessContext = $AuditData.AppAccessContext

        # Parameters
        New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\TXT" -ItemType Directory -Force | Out-Null
        $Parameters | Out-File "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\TXT\New-InboxRule_Parameters.txt" -Append

        # Check if 'MicrosoftApps.csv' contains AppId
        [string]$GUID = $AuditData.AppId

        if($MicrosoftApps_HashTable.ContainsKey("$GUID"))
        {
            $AppDisplayName = $MicrosoftApps_HashTable["$GUID"]
        }
        else
        {
            $AppDisplayName = "Third-Party Application"
        }

        # UserType
        [int]$UserTypeValue = $AuditData.UserType

        # Check if HashTable contains Value
        if($UserType_HashTable.ContainsKey("$UserTypeValue"))
        {
            $UserType = $UserType_HashTable["$UserTypeValue"][0]
        }

        $Line = [PSCustomObject]@{
        "CreationTime"                 = $AuditData | Select-Object -ExpandProperty CreationTime | ForEach-Object {$_ -replace 'T',' '}
        "UserId"                       = $AuditData.UserId
        "RecordType"                   = $Record.RecordType
        "Operation"                    = $AuditData.Operation
        "ResultStatus"                 = $AuditData.ResultStatus
        "UserType"                     = $UserType
        "ObjectId"                     = $AuditData.ObjectId
        "AppId"                        = $AuditData.AppId
        "AppDisplayName"               = $AppDisplayName
        "ExternalAccess"               = $AuditData.ExternalAccess
        "ClientIP"                     = $AuditData.ClientIP | & $IPinfo grepip -o

        # Parameters
        
        # Hiding Artifacts / Mailbox Monitoring
        "Name"                         = $Parameters | Where-Object { $_.Name -eq "Name" } | Select-Object -ExpandProperty Value
        "From"                         = $Parameters | Where-Object { $_.Name -eq "From" } | Select-Object -ExpandProperty Value
        "MarkAsRead"                   = $Parameters | Where-Object { $_.Name -eq "MarkAsRead" } | Select-Object -ExpandProperty Value # Hiding
        "DeleteMessage"                = $Parameters | Where-Object { $_.Name -eq "DeleteMessage" } | Select-Object -ExpandProperty Value # Hiding
        "MoveToFolder"                 = $Parameters | Where-Object { $_.Name -eq "MoveToFolder" } | Select-Object -ExpandProperty Value # Hiding
        "Force"                        = $Parameters | Where-Object { $_.Name -eq "Force" } | Select-Object -ExpandProperty Value
        "AlwaysDeleteOutlookRulesBlob" = $Parameters | Where-Object { $_.Name -eq "AlwaysDeleteOutlookRulesBlob" } | Select-Object -ExpandProperty Value
        "StopProcessingRules"          = $Parameters | Where-Object { $_.Name -eq "StopProcessingRules" } | Select-Object -ExpandProperty Value
        "FromAddressContainsWords"     = $Parameters | Where-Object { $_.Name -eq "FromAddressContainsWords" } | Select-Object -ExpandProperty Value # Monitoring
        "SubjectContainsWords"         = $Parameters | Where-Object { $_.Name -eq "SubjectContainsWords" } | Select-Object -ExpandProperty Value # Monitoring
        "BodyContainsWords"            = $Parameters | Where-Object { $_.Name -eq "BodyContainsWords" } | Select-Object -ExpandProperty Value # Monitoring
        "MyNameInToOrCcBox"            = $Parameters | Where-Object { $_.Name -eq "MyNameInToOrCcBox" } | Select-Object -ExpandProperty Value # Monitoring

        # Email Forwarding / Email Collection
        "ForwardAsAttachmentTo"        = $Parameters | Where-Object { $_.Name -eq "ForwardAsAttachmentTo" } | Select-Object -ExpandProperty Value # Email Forwarding / Email Collection
        "ForwardTo"                    = $Parameters | Where-Object { $_.Name -eq "ForwardTo" } | Select-Object -ExpandProperty Value # Email Forwarding / Email Collection
        "RedirectTo"                   = $Parameters | Where-Object { $_.Name -eq "RedirectTo" } | Select-Object -ExpandProperty Value # Email Forwarding / Email Collection    
        
        "IssuedAtTime"                 = $AppAccessContext.IssuedAtTime
        "UniqueTokenId"                = $AppAccessContext.UniqueTokenId
        "SessionId"                    = ($AuditData | Select-Object SessionId).SessionId
        "Id"                           = $AuditData.Id
        "Workload"                     = $AuditData.Workload
        "OrganizationName"             = $AuditData.OrganizationName
        "OrganizationId"               = $AuditData.OrganizationId
        "OriginatingServer"            = $AuditData.OriginatingServer
        }

        $Results.Add($Line)
    }

    $Results | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\New-InboxRule_AuditData.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\New-InboxRule_AuditData.csv")
    {
        if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\New-InboxRule_AuditData.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\New-InboxRule_AuditData.csv" -Delimiter ","
            
            # Inbox Rule 'Name' with only non-alphanumeric characters
            [array]$RegEx01 = $IMPORT | Where-Object { $_.Name -match "^[^a-zA-Z\d\s:]$" } | Select-Object -ExpandProperty Name
            $Count = $RegEx01.Count
            if ($Count -gt 0)
            {
                Write-Host "[Alert] Suspicious Operation(s) detected: New-InboxRule + Inbox Rule Name w/ only non-alphanumeric characters ($Count)" -ForegroundColor Red
            }

            # Inbox Rule with a short 'Name' (5 or less characters)
            [array]$RegEx02 = $IMPORT | Where-Object { $_.Name -match "^[a-zA-Z0-9]{1,5}$" } | Select-Object -ExpandProperty Name
            $Count = $RegEx02.Count
            if ($Count -gt 0)
            {
                Write-Host "[Alert] Suspicious Operation(s) detected: New-InboxRule + Inbox Rule Name w/ 5 or less alphanumeric characters ($Count)" -ForegroundColor Red
            }

            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\XLSX\New-InboxRule_AuditData.xlsx" -NoNumberConversion * -FreezePane 2,5 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "New-InboxRule" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:AH1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-AH
            $WorkSheet.Cells["A:AH"].Style.HorizontalAlignment="Center"
            
            # ConditionalFormatting - New-InboxRule
            Add-ConditionalFormatting -Address $WorkSheet.Cells["C:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("New-InboxRule",$D1)))' -BackgroundColor Red

            # ConditionalFormatting - Name

            # Inbox Rule 'Name' with only non-alphanumeric characters
            foreach ($Name in $RegEx01) 
            {
                $ConditionValue = 'EXACT("{0}",$L1)' -f $Name
                Add-ConditionalFormatting -Address $WorkSheet.Cells["L:L"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
            }

            # Inbox Rule with a short 'Name' (5 or less characters)
            foreach ($Name in $RegEx02) 
            {
                $ConditionValue = 'EXACT("{0}",$L1)' -f $Name
                Add-ConditionalFormatting -Address $WorkSheet.Cells["L:L"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
            }

            # ConditionalFormatting - MarkAsRead
            Add-ConditionalFormatting -Address $WorkSheet.Cells["N:N"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("True",$N1)))' -BackgroundColor Red

            # ConditionalFormatting - DeleteMessage
            Add-ConditionalFormatting -Address $WorkSheet.Cells["O:O"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("True",$O1)))' -BackgroundColor Red
            
            # Iterating over the MoveToFolder-Blacklist HashTable
            foreach ($MoveToFolder in $MoveToFolderBlacklist_HashTable.Keys) 
            {
                $ConditionValue = 'NOT(ISERROR(FIND("{0}",$P1)))' -f $MoveToFolder
                Add-ConditionalFormatting -Address $WorkSheet.Cells["P:P"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
            }

            # ConditionalFormatting - StopProcessingRules
            Add-ConditionalFormatting -Address $WorkSheet.Cells["S:S"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("True",$S1)))' -BackgroundColor Red

            # ConditionalFormatting - ForwardAsAttachmentTo
            $LastRow = $WorkSheet.Dimension.End.Row
            Add-ConditionalFormatting -Address $WorkSheet.Cells["X2:X$LastRow"] -WorkSheet $WorkSheet -RuleType ContainsText -BackgroundColor Red

            # ConditionalFormatting - ForwardTo
            $LastRow = $WorkSheet.Dimension.End.Row
            Add-ConditionalFormatting -Address $WorkSheet.Cells["Y2:Y$LastRow"] -WorkSheet $WorkSheet -RuleType ContainsText -BackgroundColor Red

            # ConditionalFormatting - RedirectTo
            $LastRow = $WorkSheet.Dimension.End.Row
            Add-ConditionalFormatting -Address $WorkSheet.Cells["Z2:Z$LastRow"] -WorkSheet $WorkSheet -RuleType ContainsText -BackgroundColor Red
            }
        }
    }
}

# Set-InboxRule --> Change an existing Inbox Rule, often used for setting up Email Forwarding Rules
# https://learn.microsoft.com/en-us/powershell/module/exchange/set-inboxrule?view=exchange-ps
$Import = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object { $_.RecordType -eq "ExchangeAdmin" } | Where-Object { $_.Operations -eq "Set-InboxRule" } | Sort-Object Identity -Unique | Sort-Object { $_.CreationDate -as [datetime] } -Descending
$Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
if ($Count -gt 0)
{
    Write-Host "[Alert] Suspicious Operation(s) detected: Set-InboxRule ($Count)" -ForegroundColor Red
    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV" -ItemType Directory -Force | Out-Null
    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\XLSX" -ItemType Directory -Force | Out-Null

    # CSV
    $Import | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Set-InboxRule.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Set-InboxRule.csv")
    {
        if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Set-InboxRule.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Set-InboxRule.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\XLSX\Set-InboxRule.xlsx" -FreezePane 2,5 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Set-InboxRule" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:J1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-D and F-J
            $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["F:J"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting
            Add-ConditionalFormatting -Address $WorkSheet.Cells["C:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(SEARCH("Set-InboxRule",$D1)))' -BackgroundColor Red
            }
        }
    }

    # AuditData

    # CSV
    $Results = [Collections.Generic.List[PSObject]]::new()
    ForEach($Record in $Import)
    {
        $AuditData = $Record.AuditData | ConvertFrom-Json
        $Parameters = $AuditData.Parameters
        $AppAccessContext = $AuditData.AppAccessContext

        # Parameters
        New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\TXT" -ItemType Directory -Force | Out-Null
        $Parameters | Out-File "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\TXT\Set-InboxRule_Parameters.txt" -Append

        # Check if 'MicrosoftApps.csv' contains AppId
        [string]$GUID = $AuditData.AppId

        if($MicrosoftApps_HashTable.ContainsKey("$GUID"))
        {
            $AppDisplayName = $MicrosoftApps_HashTable["$GUID"]
        }
        else
        {
            $AppDisplayName = "Third-Party Application"
        }

        # UserType
        [int]$UserTypeValue = $AuditData.UserType

        # Check if HashTable contains Value
        if($UserType_HashTable.ContainsKey("$UserTypeValue"))
        {
            $UserType = $UserType_HashTable["$UserTypeValue"][0]
        }

        $Line = [PSCustomObject]@{
        "CreationTime"                 = $AuditData | Select-Object -ExpandProperty CreationTime | ForEach-Object {$_ -replace 'T',' '}
        "UserId"                       = $AuditData.UserId
        "RecordType"                   = $Record.RecordType
        "Operation"                    = $AuditData.Operation
        "ResultStatus"                 = $AuditData.ResultStatus
        "UserType"                     = $UserType
        "ObjectId"                     = $AuditData.ObjectId
        "AppId"                        = $AuditData.AppId
        "AppDisplayName"               = $AppDisplayName
        "ExternalAccess"               = $AuditData.ExternalAccess
        "ClientIP"                     = $AuditData.ClientIP | & $IPinfo grepip -o
        
        # Parameters

        # Hiding Artifacts / Mailbox Monitoring
        "Name"                         = $Parameters | Where-Object { $_.Name -eq "Name" } | Select-Object -ExpandProperty Value # Specifies a name for the Inbox rule
        "Identity"                     = $Parameters | Where-Object { $_.Name -eq "Identity" } | Select-Object -ExpandProperty Value # Specifies the Inbox rule  
        "From"                         = $Parameters | Where-Object { $_.Name -eq "From" } | Select-Object -ExpandProperty Value # Monitoring
        "MarkAsRead"                   = $Parameters | Where-Object { $_.Name -eq "MarkAsRead" } | Select-Object -ExpandProperty Value # Hiding
        "DeleteMessage"                = $Parameters | Where-Object { $_.Name -eq "DeleteMessage" } | Select-Object -ExpandProperty Value # Hiding
        "MoveToFolder"                 = $Parameters | Where-Object { $_.Name -eq "MoveToFolder" } | Select-Object -ExpandProperty Value # Hiding
        "Force"                        = $Parameters | Where-Object { $_.Name -eq "Force" } | Select-Object -ExpandProperty Value
        "AlwaysDeleteOutlookRulesBlob" = $Parameters | Where-Object { $_.Name -eq "AlwaysDeleteOutlookRulesBlob" } | Select-Object -ExpandProperty Value
        "StopProcessingRules"          = $Parameters | Where-Object { $_.Name -eq "StopProcessingRules" } | Select-Object -ExpandProperty Value
        "FromAddressContainsWords"     = $Parameters | Where-Object { $_.Name -eq "FromAddressContainsWords" } | Select-Object -ExpandProperty Value # Monitoring
        "SubjectContainsWords"         = $Parameters | Where-Object { $_.Name -eq "SubjectContainsWords" } | Select-Object -ExpandProperty Value # Monitoring
        "BodyContainsWords"            = $Parameters | Where-Object { $_.Name -eq "BodyContainsWords" } | Select-Object -ExpandProperty Value # Monitoring
        "MyNameInToOrCcBox"            = $Parameters | Where-Object { $_.Name -eq "MyNameInToOrCcBox" } | Select-Object -ExpandProperty Value # Monitoring

        # Email Forwarding / Email Collection
        "ForwardAsAttachmentTo"        = $Parameters | Where-Object { $_.Name -eq "ForwardAsAttachmentTo" } | Select-Object -ExpandProperty Value # Email Forwarding / Email Collection
        "ForwardTo"                    = $Parameters | Where-Object { $_.Name -eq "ForwardTo" } | Select-Object -ExpandProperty Value # Email Forwarding / Email Collection
        "RedirectTo"                   = $Parameters | Where-Object { $_.Name -eq "RedirectTo" } | Select-Object -ExpandProperty Value # Email Forwarding / Email Collection
        
        "IssuedAtTime"                 = $AppAccessContext.IssuedAtTime
        "UniqueTokenId"                = $AppAccessContext.UniqueTokenId
        "SessionId"                    = ($AuditData | Select-Object SessionId).SessionId
        "Id"                           = $AuditData.Id
        "Workload"                     = $AuditData.Workload
        "OrganizationName"             = $AuditData.OrganizationName
        "OrganizationId"               = $AuditData.OrganizationId
        "OriginatingServer"            = $AuditData.OriginatingServer
        }

        $Results.Add($Line)
    }

    $Results | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Set-InboxRule_AuditData.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Set-InboxRule_AuditData.csv")
    {
        if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Set-InboxRule_AuditData.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Set-InboxRule_AuditData.csv" -Delimiter "," -Encoding UTF8

            # Inbox Rule 'Name' with only non-alphanumeric characters
            [array]$RegEx01 = $IMPORT | Where-Object { $_.Name -match "^[^a-zA-Z\d\s:]$" } | Select-Object -ExpandProperty Name
            $Count = $RegEx01.Count
            if ($Count -gt 0)
            {
                Write-Host "[Alert] Suspicious Operation(s) detected: Set-InboxRule + Inbox Rule Name w/ only non-alphanumeric characters ($Count)" -ForegroundColor Red
            }

            # Inbox Rule with a short 'Name' (5 or less characters)
            [array]$RegEx02 = $IMPORT | Where-Object { $_.Name -match "^[a-zA-Z0-9]{1,5}$" } | Select-Object -ExpandProperty Name
            $Count = $RegEx02.Count
            if ($Count -gt 0)
            {
                Write-Host "[Alert] Suspicious Operation(s) detected: Set-InboxRule + Inbox Rule Name w/ 5 or less alphanumeric characters ($Count)" -ForegroundColor Red
            }

            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\XLSX\Set-InboxRule_AuditData.xlsx" -NoNumberConversion * -FreezePane 2,5 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Set-InboxRule" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:AI1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-AI
            $WorkSheet.Cells["A:AI"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting - Set-InboxRule
            Add-ConditionalFormatting -Address $WorkSheet.Cells["C:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(SEARCH("Set-InboxRule",$D1)))' -BackgroundColor Red
            
            # ConditionalFormatting - Name

            # Inbox Rule 'Name' with only non-alphanumeric characters
            foreach ($Name in $RegEx01) 
            {
                $ConditionValue = 'EXACT("{0}",$L1)' -f $Name
                Add-ConditionalFormatting -Address $WorkSheet.Cells["L:L"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
            }

            # Inbox Rule with a short 'Name' (5 or less characters)
            foreach ($Name in $RegEx02) 
            {
                $ConditionValue = 'EXACT("{0}",$L1)' -f $Name
                Add-ConditionalFormatting -Address $WorkSheet.Cells["L:L"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
            }

            # ConditionalFormatting - MarkAsRead
            Add-ConditionalFormatting -Address $WorkSheet.Cells["O:O"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("True",$O1)))' -BackgroundColor Red
            
            # ConditionalFormatting - DeleteMessage
            Add-ConditionalFormatting -Address $WorkSheet.Cells["P:P"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("True",$P1)))' -BackgroundColor Red
            
            # Iterating over the MoveToFolder-Blacklist HashTable
            foreach ($MoveToFolder in $MoveToFolderBlacklist_HashTable.Keys) 
            {
                $ConditionValue = 'NOT(ISERROR(FIND("{0}",$Q1)))' -f $MoveToFolder
                Add-ConditionalFormatting -Address $WorkSheet.Cells["Q:Q"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
            }

            # ConditionalFormatting - StopProcessingRules
            Add-ConditionalFormatting -Address $WorkSheet.Cells["T:T"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("True",$T1)))' -BackgroundColor Red

            # ConditionalFormatting - ForwardAsAttachmentTo
            $LastRow = $WorkSheet.Dimension.End.Row
            Add-ConditionalFormatting -Address $WorkSheet.Cells["Y2:Y$LastRow"] -WorkSheet $WorkSheet -RuleType ContainsText -BackgroundColor Red

            # ConditionalFormatting - ForwardTo
            $LastRow = $WorkSheet.Dimension.End.Row
            Add-ConditionalFormatting -Address $WorkSheet.Cells["Z2:Z$LastRow"] -WorkSheet $WorkSheet -RuleType ContainsText -BackgroundColor Red

            # ConditionalFormatting - RedirectTo
            $LastRow = $WorkSheet.Dimension.End.Row
            Add-ConditionalFormatting -Address $WorkSheet.Cells["AA2:AA$LastRow"] -WorkSheet $WorkSheet -RuleType ContainsText -BackgroundColor Red

            }
        }
    }
}

# Remove-InboxRule --> Remove an existing Inbox Rule in a mailbox
# https://learn.microsoft.com/en-us/powershell/module/exchange/remove-inboxrule?view=exchange-ps
$Import = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object { $_.RecordType -eq "ExchangeAdmin" } | Where-Object { $_.Operations -eq "Remove-InboxRule" } | Sort-Object Identity -Unique | Sort-Object { $_.CreationDate -as [datetime] } -Descending
$Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
if ($Count -gt 0)
{
    Write-Host "[Alert] Suspicious Operation(s) detected: Remove-InboxRule ($Count)" -ForegroundColor Red
    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV" -ItemType Directory -Force | Out-Null
    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\XLSX" -ItemType Directory -Force | Out-Null

    # CSV
    $Import | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Remove-InboxRule.csv" -NoTypeInformation -Encoding UTF8
    
    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Remove-InboxRule.csv")
    {
        if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Remove-InboxRule.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Remove-InboxRule.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\XLSX\Remove-InboxRule.xlsx" -FreezePane 2,5 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Remove-InboxRule" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:J1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-D and F-J
            $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["F:J"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting
            Add-ConditionalFormatting -Address $WorkSheet.Cells["C:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Remove-InboxRule",$D1)))' -BackgroundColor Red
            }
        }
    }

    # AuditData

    # CSV
    $Results = [Collections.Generic.List[PSObject]]::new()
    ForEach($Record in $Import)
    {
        $AuditData = $Record.AuditData | ConvertFrom-Json
        $Parameters = $AuditData.Parameters
        $AppAccessContext = $AuditData.AppAccessContext # Contains the 'IssuedAtTime' and the 'UniqueTokenId' for the application context for the user or service principal that performed the action.

        # Check if 'MicrosoftApps.csv' contains AppId
        [string]$GUID = $AuditData.AppId

        if($MicrosoftApps_HashTable.ContainsKey("$GUID"))
        {
            $AppDisplayName = $MicrosoftApps_HashTable["$GUID"]
        }
        else
        {
            $AppDisplayName = "Third-Party Application"
        }

        # UserType
        [int]$UserTypeValue = $AuditData.UserType

        # Check if HashTable contains Value
        if($UserType_HashTable.ContainsKey("$UserTypeValue"))
        {
            $UserType = $UserType_HashTable["$UserTypeValue"][0]
        }

        $Line = [PSCustomObject]@{
        "CreationTime"                 = $AuditData | Select-Object -ExpandProperty CreationTime | ForEach-Object {$_ -replace 'T',' '}
        "UserId"                       = $AuditData.UserId
        "RecordType"                   = $Record.RecordType
        "Operation"                    = $AuditData.Operation
        "ResultStatus"                 = $AuditData.ResultStatus # Indicates whether the action was successful or not. For Exchange admin activity, the value is either True or False.
        "UserType"                     = $UserType
        "ObjectId"                     = $AuditData.ObjectId
        "AppId"                        = $AuditData.AppId
        "AppDisplayName"               = $AppDisplayName
        "ExternalAccess"               = $AuditData.ExternalAccess # This is true if the logon user's domain is different from the mailbox owner's domain.
        "ClientIP"                     = $AuditData.ClientIP | & $IPinfo grepip -o # Remove Port Number
        "Mailbox"                      = $Parameters | Where-Object { $_.Name -eq "Mailbox" } | Select-Object -ExpandProperty Value # Specifies the mailbox that contains the Inbox rule
        "Identity"                     = $Parameters | Where-Object { $_.Name -eq "Identity" } | Select-Object -ExpandProperty Value # Specifies the Inbox rule
        "Confirm"                      = $Parameters | Where-Object { $_.Name -eq "Confirm" } | Select-Object -ExpandProperty Value # Show or hide the confirmation prompt
        "Force"                        = $Parameters | Where-Object { $_.Name -eq "Force" } | Select-Object -ExpandProperty Value # Hides warning or confirmation messages
        "AlwaysDeleteOutlookRulesBlob" = $Parameters | Where-Object { $_.Name -eq "AlwaysDeleteOutlookRulesBlob" } | Select-Object -ExpandProperty Value # Hides warning message
        "IssuedAtTime"                 = $AppAccessContext.IssuedAtTime # Indicates when the authentication for this Microsoft Entra token occurred.
        "UniqueTokenId"                = $AppAccessContext.UniqueTokenId # Contains the unique identifier for the token passed during sign-in. This identifier can be used to correlate the token request with the sign-in.
        "SessionId"                    = ($AuditData | Select-Object SessionId).SessionId
        "Id"                           = $AuditData.Id
        "RequestId"                    = ($AuditData | Select-Object RequestId).RequestId
        "Workload"                     = $AuditData.Workload
        "OrganizationName"             = $AuditData.OrganizationName # The name of the tenant.
        "OrganizationId"               = $AuditData.OrganizationId # The GUID of the tenant.
        "OriginatingServer"            = $AuditData.OriginatingServer # This is from where the operation originated.
        }

        $Results.Add($Line)
    }

    $Results | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Remove-InboxRule_AuditData.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Remove-InboxRule_AuditData.csv")
    {
        if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Remove-InboxRule_AuditData.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Remove-InboxRule_AuditData.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\XLSX\Remove-InboxRule_AuditData.xlsx" -NoNumberConversion * -FreezePane 2,5 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Remove-InboxRule" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:Y1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-Y
            $WorkSheet.Cells["A:Y"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting - Set-InboxRule
            Add-ConditionalFormatting -Address $WorkSheet.Cells["C:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Remove-InboxRule",$D1)))' -BackgroundColor Red
            }
        }
    }
}

# https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema
# https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema#exchange-mailbox-schema

# Enable-InboxRule --> Enable an existing Inbox Rule in a mailbox
# https://learn.microsoft.com/en-us/powershell/module/exchange/enable-inboxrule?view=exchange-ps
$Import = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object { $_.RecordType -eq "ExchangeAdmin" } | Where-Object { $_.Operations -eq "Enable-InboxRule" } | Sort-Object Identity -Unique | Sort-Object { $_.CreationDate -as [datetime] } -Descending
$Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
if ($Count -gt 0)
{
    Write-Host "[Alert] Suspicious Operation(s) detected: Enable-InboxRule ($Count)" -ForegroundColor Red
    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV" -ItemType Directory -Force | Out-Null
    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\XLSX" -ItemType Directory -Force | Out-Null

    # CSV
    $Import | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Enable-InboxRule.csv" -NoTypeInformation -Encoding UTF8
    
    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Enable-InboxRule.csv")
    {
        if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Enable-InboxRule.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Enable-InboxRule.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\XLSX\Enable-InboxRule.xlsx" -FreezePane 2,5 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Enable-InboxRule" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:J1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-D and F-J
            $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["F:J"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting
            Add-ConditionalFormatting -Address $WorkSheet.Cells["C:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Enable-InboxRule",$D1)))' -BackgroundColor Red
            }
        }
    }

    # AuditData

    # CSV
    $Results = [Collections.Generic.List[PSObject]]::new()
    ForEach($Record in $Import)
    {
        $AuditData = $Record.AuditData | ConvertFrom-Json
        $Parameters = $AuditData.Parameters
        $AppAccessContext = $AuditData.AppAccessContext

        # Check if 'MicrosoftApps.csv' contains AppId
        [string]$GUID = $AuditData.AppId

        if($MicrosoftApps_HashTable.ContainsKey("$GUID"))
        {
            $AppDisplayName = $MicrosoftApps_HashTable["$GUID"]
        }
        else
        {
            $AppDisplayName = "Third-Party Application"
        }

        # UserType
        [int]$UserTypeValue = $AuditData.UserType

        # Check if HashTable contains Value
        if($UserType_HashTable.ContainsKey("$UserTypeValue"))
        {
            $UserType = $UserType_HashTable["$UserTypeValue"][0]
        }

        $Line = [PSCustomObject]@{
        "CreationTime"                 = $AuditData | Select-Object -ExpandProperty CreationTime | ForEach-Object {$_ -replace 'T',' '}
        "UserId"                       = $AuditData.UserId
        "RecordType"                   = $Record.RecordType
        "Operation"                    = $AuditData.Operation
        "ResultStatus"                 = $AuditData.ResultStatus
        "UserType"                     = $UserType
        "ObjectId"                     = $AuditData.ObjectId
        "AppId"                        = $AuditData.AppId
        "AppDisplayName"               = $AppDisplayName
        "ExternalAccess"               = $AuditData.ExternalAccess
        "ClientIP"                     = $AuditData.ClientIP | & $IPinfo grepip -o
        "Mailbox"                      = $Parameters | Where-Object { $_.Name -eq "Mailbox" } | Select-Object -ExpandProperty Value
        "Identity"                     = $Parameters | Where-Object { $_.Name -eq "Identity" } | Select-Object -ExpandProperty Value
        "Confirm"                      = $Parameters | Where-Object { $_.Name -eq "Confirm" } | Select-Object -ExpandProperty Value
        "Force"                        = $Parameters | Where-Object { $_.Name -eq "Force" } | Select-Object -ExpandProperty Value
        "AlwaysDeleteOutlookRulesBlob" = $Parameters | Where-Object { $_.Name -eq "AlwaysDeleteOutlookRulesBlob" } | Select-Object -ExpandProperty Value
        "IssuedAtTime"                 = $AppAccessContext.IssuedAtTime
        "UniqueTokenId"                = $AppAccessContext.UniqueTokenId
        "SessionId"                    = ($AuditData | Select-Object SessionId).SessionId
        "Id"                           = $AuditData.Id
        "RequestId"                    = ($AuditData | Select-Object RequestId).RequestId
        "Workload"                     = $AuditData.Workload
        "OrganizationName"             = $AuditData.OrganizationName
        "OrganizationId"               = $AuditData.OrganizationId
        "OriginatingServer"            = $AuditData.OriginatingServer
        }

        $Results.Add($Line)
    }

    $Results | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Enable-InboxRule_AuditData.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Enable-InboxRule_AuditData.csv")
    {
        if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Enable-InboxRule_AuditData.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Enable-InboxRule_AuditData.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\XLSX\Enable-InboxRule_AuditData.xlsx" -NoNumberConversion * -FreezePane 2,5 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Enable-InboxRule" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:Y1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-Y
            $WorkSheet.Cells["A:Y"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting - Set-InboxRule
            Add-ConditionalFormatting -Address $WorkSheet.Cells["C:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Enable-InboxRule",$D1)))' -BackgroundColor Red
            }
        }
    }
}

# Disable-InboxRule --> Disable an existing Inbox Rule in a mailbox
# https://learn.microsoft.com/en-us/powershell/module/exchange/disable-inboxrule?view=exchange-ps
$Import = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object { $_.RecordType -eq "ExchangeAdmin" } | Where-Object { $_.Operations -eq "Disable-InboxRule" } | Sort-Object Identity -Unique | Sort-Object { $_.CreationDate -as [datetime] } -Descending
$Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
if ($Count -gt 0)
{
    Write-Host "[Alert] Suspicious Operation(s) detected: Disable-InboxRule ($Count)" -ForegroundColor Red
    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV" -ItemType Directory -Force | Out-Null
    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\XLSX" -ItemType Directory -Force | Out-Null

    # CSV
    $Import | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Disable-InboxRule.csv" -NoTypeInformation -Encoding UTF8
    
    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Disable-InboxRule.csv")
    {
        if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Disable-InboxRule.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Disable-InboxRule.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\XLSX\Disable-InboxRule.xlsx" -FreezePane 2,5 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Disable-InboxRule" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:J1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-D and F-J
            $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["F:J"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting
            Add-ConditionalFormatting -Address $WorkSheet.Cells["C:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Disable-InboxRule",$D1)))' -BackgroundColor Red
            }
        }
    }

    # AuditData

    # CSV
    $Results = [Collections.Generic.List[PSObject]]::new()
    ForEach($Record in $Import)
    {
        $AuditData = $Record.AuditData | ConvertFrom-Json
        $Parameters = $AuditData.Parameters
        $AppAccessContext = $AuditData.AppAccessContext

        # Check if 'MicrosoftApps.csv' contains AppId
        [string]$GUID = $AuditData.AppId

        if($MicrosoftApps_HashTable.ContainsKey("$GUID"))
        {
            $AppDisplayName = $MicrosoftApps_HashTable["$GUID"]
        }
        else
        {
            $AppDisplayName = "Third-Party Application"
        }

        # UserType
        [int]$UserTypeValue = $AuditData.UserType

        # Check if HashTable contains Value
        if($UserType_HashTable.ContainsKey("$UserTypeValue"))
        {
            $UserType = $UserType_HashTable["$UserTypeValue"][0]
        }

        $Line = [PSCustomObject]@{
        "CreationTime"                 = $AuditData | Select-Object -ExpandProperty CreationTime | ForEach-Object {$_ -replace 'T',' '}
        "UserId"                       = $AuditData.UserId
        "RecordType"                   = $Record.RecordType
        "Operation"                    = $AuditData.Operation
        "ResultStatus"                 = $AuditData.ResultStatus
        "UserType"                     = $UserType
        "ObjectId"                     = $AuditData.ObjectId
        "AppId"                        = $AuditData.AppId
        "AppDisplayName"               = $AppDisplayName
        "ExternalAccess"               = $AuditData.ExternalAccess
        "ClientIP"                     = $AuditData.ClientIP | & $IPinfo grepip -o
        "Mailbox"                      = $Parameters | Where-Object { $_.Name -eq "Mailbox" } | Select-Object -ExpandProperty Value
        "Identity"                     = $Parameters | Where-Object { $_.Name -eq "Identity" } | Select-Object -ExpandProperty Value
        "Confirm"                      = $Parameters | Where-Object { $_.Name -eq "Confirm" } | Select-Object -ExpandProperty Value
        "Force"                        = $Parameters | Where-Object { $_.Name -eq "Force" } | Select-Object -ExpandProperty Value
        "AlwaysDeleteOutlookRulesBlob" = $Parameters | Where-Object { $_.Name -eq "AlwaysDeleteOutlookRulesBlob" } | Select-Object -ExpandProperty Value
        "IssuedAtTime"                 = $AppAccessContext.IssuedAtTime
        "UniqueTokenId"                = $AppAccessContext.UniqueTokenId
        "SessionId"                    = ($AuditData | Select-Object SessionId).SessionId
        "Id"                           = $AuditData.Id
        "RequestId"                    = ($AuditData | Select-Object RequestId).RequestId
        "Workload"                     = $AuditData.Workload
        "OrganizationName"             = $AuditData.OrganizationName
        "OrganizationId"               = $AuditData.OrganizationId
        "OriginatingServer"            = $AuditData.OriginatingServer
        }

        $Results.Add($Line)
    }

    $Results | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Disable-InboxRule_AuditData.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Disable-InboxRule_AuditData.csv")
    {
        if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Disable-InboxRule_AuditData.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Disable-InboxRule_AuditData.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\XLSX\Disable-InboxRule_AuditData.xlsx" -NoNumberConversion * -FreezePane 2,5 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Disable-InboxRule" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:Y1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-Y
            $WorkSheet.Cells["A:Y"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting - Set-InboxRule
            Add-ConditionalFormatting -Address $WorkSheet.Cells["C:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Disable-InboxRule",$D1)))' -BackgroundColor Red
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
    $Records | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\UpdateInboxRules.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\UpdateInboxRules.csv")
    {
        if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\UpdateInboxRules.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\UpdateInboxRules.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\XLSX\UpdateInboxRules.xlsx" -FreezePane 2,5 -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "UpdateInboxRules" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:J1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-D and F-J
            $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["F:J"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting
            Add-ConditionalFormatting -Address $WorkSheet.Cells["C:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("UpdateInboxRules",$D1)))' -BackgroundColor Red
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
        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\UpdateInboxRules-RedirectToRecipientsAction.csv")
        {
            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\UpdateInboxRules-RedirectToRecipientsAction.csv") -gt 0)
            {
                $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\UpdateInboxRules-RedirectToRecipientsAction.csv" -Delimiter "," | Sort-Object Identity -Unique | Sort-Object { $_.CreationDate -as [datetime] } -Descending
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

        # Custom CSV
        $Data = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\UpdateInboxRules-RedirectToRecipientsAction.csv" -Delimiter "," | Sort-Object { $_.CreationDate -as [datetime] } -Descending

        $Results = [Collections.Generic.List[PSObject]]::new()
        ForEach($Record in $Data)
        {
            $AuditData = $Record.AuditData | ConvertFrom-Json
            $OperationProperties = $AuditData.OperationProperties
            $ServerRule = ($OperationProperties | Where-Object {$_.Name -eq 'ServerRule'}).Value | ConvertFrom-Json

            $Line = [PSCustomObject]@{
            "CreationTime"          = $AuditData | Select-Object -ExpandProperty CreationTime | ForEach-Object {$_ -replace 'T',' '}
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

            $Results.Add($Line)
        }

        $Results | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\UpdateInboxRules-RedirectToRecipientsAction_Custom.csv" -NoTypeInformation
    }

    # Custom XLSX
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
    $Import | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Set-Mailbox.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
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

    # AuditData

    # CSV
    $Results = [Collections.Generic.List[PSObject]]::new()
    ForEach($Record in $Import)
    {
        $AuditData = $Record.AuditData | ConvertFrom-Json
        $AppAccessContext = $AuditData.AppAccessContext
        $Parameters = $AuditData.Parameters

        $Line = [PSCustomObject]@{
        "CreationTime"               = $AuditData | Select-Object -ExpandProperty CreationTime | ForEach-Object {$_ -replace 'T',' '}
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

        $Results.Add($Line)
    }

    $Results | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Set-Mailbox_AuditData.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
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
    $Import | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Set-MailboxJunkEmailConfiguration.csv" -NoTypeInformation -Encoding UTF8
    
    # XLSX
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

    # AuditData
    
    # CSV
    $Results = [Collections.Generic.List[PSObject]]::new()
    ForEach($Record in $Import)
    {
        $AuditData = $Record.AuditData | ConvertFrom-Json
        $AppAccessContext = $AuditData.AppAccessContext
        $Parameters = $AuditData.Parameters

        $Line = [PSCustomObject]@{
        "CreationTime"                = $AuditData | Select-Object -ExpandProperty CreationTime | ForEach-Object {$_ -replace 'T',' '}
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

        $Results.Add($Line)
    }

    $Results | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Set-MailboxJunkEmailConfiguration_AuditData.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
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

# Mailbox Permission Changes

# Add-MailboxPermission - Added delegate mailbox permissions --> T1098.002 - Account Manipulation: Additional Email Delegate Permissions
# Description: An administrator assigned the FullAccess mailbox permission to a user (known as a delegate) to another person's mailbox. The FullAccess permission allows the delegate to open the other person's mailbox, and read and manage the contents of the mailbox.
# https://learn.microsoft.com/en-us/powershell/module/exchange/add-mailboxpermission?view=exchange-ps
$Import = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object { $_.RecordType -eq "ExchangeAdmin" } | Where-Object { $_.Operations -eq "Add-MailboxPermission" } | Sort-Object { $_.CreationDate -as [datetime] } -Descending
$Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
if ($Count -gt 0)
{
    Write-Host "[Alert] Suspicious Operation(s) detected: Add-MailboxPermission ($Count)" -ForegroundColor Red
    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV" -ItemType Directory -Force | Out-Null
    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\XLSX" -ItemType Directory -Force | Out-Null

    # AuditData
    
    # CSV
    $Results = [Collections.Generic.List[PSObject]]::new()
    ForEach($Record in $Import)
    {
        $AuditData = $Record.AuditData | ConvertFrom-Json
        $AppAccessContext = $AuditData.AppAccessContext
        $Parameters = $AuditData.Parameters

        # UserType (Value --> Member Name)
        [int]$UserTypeValue = $AuditData.UserType

        # Check if HashTable contains Value
        if($UserType_HashTable.ContainsKey("$UserTypeValue"))
        {
            $UserType = $UserType_HashTable["$UserTypeValue"][0]
        }

        $Line = [PSCustomObject]@{
        "CreationTime"                = $AuditData | Select-Object -ExpandProperty CreationTime | ForEach-Object {$_ -replace 'T',' '}
        "Id"                          = $AuditData.Id
        "Workload"                    = $AuditData.Workload
        "RecordType"                  = $Record.RecordType
        "Operation"                   = $Record.Operations
        "ResultStatus"                = $AuditData.ResultStatus
        "UserId"                      = $AuditData.UserId
        "UserKey"                     = $AuditData.UserKey
        "UserType"                    = $UserType
        "Version"                     = $AuditData.Version
        "ClientIP"                    = $AuditData.ClientIP | & $IPinfo grepip -o # Remove Port Number
        "ObjectId"                    = $AuditData.ObjectId
        "AppId"                       = $AuditData.AppId
        "AppPoolName"                 = $AuditData.AppPoolName
        "CorrelationID"               = $AuditData.CorrelationID # Empty
        "ExternalAccess"              = $AuditData.ExternalAccess
        "OrganizationName"            = $AuditData.OrganizationName
        "OriginatingServer"           = $AuditData.OriginatingServer
        "Identity"                    = $Parameters | Where-Object { $_.Name -eq "Identity" } | Select-Object -ExpandProperty Value
        "User"                        = $Parameters | Where-Object { $_.Name -eq "User" } | Select-Object -ExpandProperty Value
        "AccessRights"                = $Parameters | Where-Object { $_.Name -eq "AccessRights" } | Select-Object -ExpandProperty Value # FullAccess, ChangePermission, ChangeOwner
        "RequestId"                   = $AuditData.RequestId
        "SessionId"                   = $AuditData.SessionId
        }

        $Results.Add($Line)
    }

    $Results | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Add-MailboxPermission.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Add-MailboxPermission.csv")
    {
        if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Add-MailboxPermission.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Add-MailboxPermission.csv" -Delimiter "," -Encoding UTF8
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\XLSX\Add-MailboxPermission.xlsx" -NoNumberConversion * -FreezePane 2,6 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Add-MailboxPermission" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:W1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-W
            $WorkSheet.Cells["A:W"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting
            Add-ConditionalFormatting -Address $WorkSheet.Cells["D:E"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Add-MailboxPermission",$E1)))' -BackgroundColor Red
            Add-ConditionalFormatting -Address $WorkSheet.Cells["I:I"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Admin",$I1)))' -BackgroundColor Red
            Add-ConditionalFormatting -Address $WorkSheet.Cells["U:U"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("FullAccess",$U1)))' -BackgroundColor Red
            }
        }
    }
}

# Add-RecipientPermission - Add SendAs permission to users mailbox (in a cloud-based organization)
# Note: SendAs permission allows a user or group members to send messages that appear to come from the specified mailbox, mail contact, mail user, or group.
# https://learn.microsoft.com/en-us/powershell/module/exchange/add-recipientpermission?view=exchange-ps
$Import = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object { $_.RecordType -eq "ExchangeAdmin" } | Where-Object { $_.Operations -eq "Add-RecipientPermission" } | Sort-Object { $_.CreationDate -as [datetime] } -Descending
$Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
if ($Count -gt 0)
{
    Write-Host "[Alert] Suspicious Operation(s) detected: Add-RecipientPermission ($Count)" -ForegroundColor Red
    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV" -ItemType Directory -Force | Out-Null
    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\XLSX" -ItemType Directory -Force | Out-Null

    # AuditData
    
    # CSV
    $Results = [Collections.Generic.List[PSObject]]::new()
    ForEach($Record in $Import)
    {
        $AuditData = $Record.AuditData | ConvertFrom-Json
        $AppAccessContext = $AuditData.AppAccessContext
        $Parameters = $AuditData.Parameters

        $Line = [PSCustomObject]@{
        "CreationTime"                = $AuditData | Select-Object -ExpandProperty CreationTime | ForEach-Object {$_ -replace 'T',' '}
        "Id"                          = $AuditData.Id
        "Workload"                    = $AuditData.Workload
        "RecordType"                  = $Record.RecordType
        "Operation"                   = $Record.Operations
        "ResultStatus"                = $AuditData.ResultStatus
        "UserId"                      = $AuditData.UserId
        "UserKey"                     = $AuditData.UserKey
        "UserType"                    = $UserType
        "Version"                     = $AuditData.Version
        "ClientIP"                    = $AuditData.ClientIP | & $IPinfo grepip -o # Remove Port Number
        "ObjectId"                    = $AuditData.ObjectId
        "AppId"                       = $AuditData.AppId
        "AppPoolName"                 = $AuditData.AppPoolName
        "ClientAppId"                 = $AuditData.ClientAppId
        "CorrelationID"               = $AuditData.CorrelationID # Empty
        "ExternalAccess"              = $AuditData.ExternalAccess
        "OrganizationName"            = $AuditData.OrganizationName
        "OriginatingServer"           = $AuditData.OriginatingServer
        "Identity"                    = $Parameters | Where-Object { $_.Name -eq "Identity" } | Select-Object -ExpandProperty Value
        "Trustee"                     = $Parameters | Where-Object { $_.Name -eq "Trustee" } | Select-Object -ExpandProperty Value
        "AccessRights"                = $Parameters | Where-Object { $_.Name -eq "AccessRights" } | Select-Object -ExpandProperty Value # SendAs
        "RequestId"                   = $AuditData.RequestId
        "SessionId"                   = $AuditData.SessionId
        }

        $Results.Add($Line)
    }

    $Results | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Add-RecipientPermission.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Add-RecipientPermission.csv")
    {
        if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Add-RecipientPermission.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Add-RecipientPermission.csv" -Delimiter "," -Encoding UTF8
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\XLSX\Add-RecipientPermission.xlsx" -NoNumberConversion * -FreezePane 2,6 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Add-RecipientPermission" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:X1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-X
            $WorkSheet.Cells["A:X"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting
            Add-ConditionalFormatting -Address $WorkSheet.Cells["D:E"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Add-RecipientPermission",$E1)))' -BackgroundColor Red
            Add-ConditionalFormatting -Address $WorkSheet.Cells["I:I"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Admin",$I1)))' -BackgroundColor Red
            Add-ConditionalFormatting -Address $WorkSheet.Cells["V:V"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("SendAs",$V1)))' -BackgroundColor Red
            }
        }
    }
}

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
    $Import | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\New-InboundConnector.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
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
    $Import | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Add-service-principal.csv" -NoTypeInformation -Encoding UTF8
    
    # XLSX
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

    # AuditData

    # CSV
    $Results = [Collections.Generic.List[PSObject]]::new()
    ForEach($Record in $Import)
    {
        $AuditData = $Record.AuditData | ConvertFrom-Json
        $ExtendedProperties = $AuditData.ExtendedProperties

        $Line = [PSCustomObject]@{
        "CreationTime"                  = $AuditData | Select-Object -ExpandProperty CreationTime | ForEach-Object {$_ -replace 'T',' '}
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

        $Results.Add($Line)
    }

    $Results | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Add-service-principal_AuditData.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
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
    $Import | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Add-delegated-permissions-grant.csv" -NoTypeInformation -Encoding UTF8
    
    # XLSX
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

    # AuditData

    # CSV
    $Results = [Collections.Generic.List[PSObject]]::new()
    ForEach($Record in $Import)
    {
        $AuditData = $Record.AuditData | ConvertFrom-Json
        $ExtendedProperties = $AuditData.ExtendedProperties
        $ModifiedProperties = $AuditData.ModifiedProperties
        $Target = $AuditData.Target

        $Line = [PSCustomObject]@{
        "CreationTime"                  = $AuditData | Select-Object -ExpandProperty CreationTime | ForEach-Object {$_ -replace 'T',' '}
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

        $Results.Add($Line)
    }

    $Results | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Add-delegated-permissions-grant_AuditData.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
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
    $Import | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Add-app-role-assignment-grant-to-user.csv" -NoTypeInformation -Encoding UTF8
    
    # XLSX
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

    # AuditData

    # CSV
    $Results = [Collections.Generic.List[PSObject]]::new()
    ForEach($Record in $Import)
    {
        $AuditData = $Record.AuditData | ConvertFrom-Json
        $ExtendedProperties = $AuditData.ExtendedProperties
        $ModifiedProperties = $AuditData.ModifiedProperties
        $Target = $AuditData.Target

        $Line = [PSCustomObject]@{
        "CreationTime"                  = $AuditData | Select-Object -ExpandProperty CreationTime | ForEach-Object {$_ -replace 'T',' '}
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
        "LastModifiedDateTime"          = ($ModifiedProperties | Where-Object { $_.Name -eq "AppRoleAssignment.LastModifiedDateTime" }).LastModifiedDateTime
        "TargetId"                      = $ModifiedProperties | Where-Object { $_.Name -eq "TargetId.ServicePrincipalNames" } | Select-Object -ExpandProperty NewValue
        "ActorContextId"                = $AuditData.ActorContextId
        "InterSystemsId"                = $AuditData.InterSystemsId
        "IntraSystemId"                 = $AuditData.IntraSystemId
        "SupportTicketId"               = $AuditData.SupportTicketId
        "Target"                        = $Target | Where-Object { $_.Type -eq "1" } | Select-Object -ExpandProperty ID
        "TargetContextId"               = $AuditData.TargetContextId
        }

        $Results.Add($Line)
    }

    $Results | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Add-app-role-assignment-grant-to-user_AuditData.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
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
    $Import | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Consent-to-application.csv" -NoTypeInformation -Encoding UTF8
    
    # XLSX
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

    # AuditData

    # CSV
    $Results = [Collections.Generic.List[PSObject]]::new()
    ForEach($Record in $Import)
    {
        $AuditData = $Record.AuditData | ConvertFrom-Json
        $ExtendedProperties = $AuditData.ExtendedProperties
        $ModifiedProperties = $AuditData.ModifiedProperties
        $Target = $AuditData.Target

        $Line = [PSCustomObject]@{
        "CreationTime"                  = $AuditData | Select-Object -ExpandProperty CreationTime | ForEach-Object {$_ -replace 'T',' '}
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

        $Results.Add($Line)
    }

    $Results | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\Consent-to-application_AuditData.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
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

# Suspicious Operation(s) detected: HygieneTenantEvents
# Note: Related to Exchange Online Protection and Microsoft Defender for Office 365. Hygiene events are related to outbound spam protection. These events are related to users who are restricted from sending email.
$Import = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object { $_.RecordType -eq "HygieneEvent" } | Where-Object { $_.Operations -eq "HygieneTenantEvents" } | Sort-Object Id -Unique | Sort-Object { $_.CreationDate -as [datetime] } -Descending
$Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
if ($Count -gt 0)
{
    Write-Host "[Alert] Suspicious Operation(s) detected: HygieneTenantEvents - Outbound Spam Protection ($Count)" -ForegroundColor Red
    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV" -ItemType Directory -Force | Out-Null
    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\XLSX" -ItemType Directory -Force | Out-Null

    # CSV
    $Import | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\HygieneTenantEvents.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\HygieneTenantEvents.csv")
    {
        if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\HygieneTenantEvents.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\HygieneTenantEvents.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\XLSX\HygieneTenantEvents.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "HygieneTenantEvents" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:J1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-D and F-J
            $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["F:J"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting
            Add-ConditionalFormatting -Address $WorkSheet.Cells["D:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("HygieneTenantEvents",$D1)))' -BackgroundColor Red
            }
        }
    }

    # AuditData

    # CSV
    $Results = [Collections.Generic.List[PSObject]]::new()
    ForEach($Record in $Import)
    {
        $AuditData = $Record.AuditData | ConvertFrom-Json

        $Line = [PSCustomObject]@{
        "CreationTime"                       = $AuditData | Select-Object -ExpandProperty CreationTime | ForEach-Object {$_ -replace 'T',' '}
        "Id"                                 = $AuditData.Id
        "RecordType"                         = $Record.RecordType
        "Operation"                          = $AuditData.Operation
        "OrganizationId"                     = $AuditData.OrganizationId
        "ResultStatus"                       = $AuditData.ResultStatus
        "UserKey"                            = $AuditData.UserKey
        "UserType"                           = $AuditData.UserType
        "Version"                            = $AuditData.Version
        "Workload"                           = $AuditData.Workload
        "UserId"                             = $AuditData.UserId
        "Audit"                              = $AuditData.Audit
        "Event"                              = $AuditData.Event
        "EventId"                            = $AuditData.EventId
        "EventValue"                         = $AuditData.EventValue
        "Reason"                             = $AuditData.Reason # Untouched
        "OutboundSpamLast24Hours"            = $AuditData.Reason | ForEach-Object{($_ -split ";")} | Select-String -Pattern "^OutboundSpamLast24Hours=" | ForEach-Object{($_ -split "=")[1]}
        "OutboundMailLast24Hours"            = $AuditData.Reason | ForEach-Object{($_ -split ";")} | Select-String -Pattern "^OutboundMailLast24Hours=" | ForEach-Object{($_ -split "=")[1]}
        "OutboundSpamPercent"                = $AuditData.Reason | ForEach-Object{($_ -split ";")} | Select-String -Pattern "^OutboundSpamPercent=" | ForEach-Object{($_ -split "=")[1]}
        "Last Spam Message - MessagetraceId" = $AuditData.Reason | ForEach-Object{($_ -split ";")} | Select-String -Pattern "^Last Spam Message MessagetraceId:" | ForEach-Object{($_ -split ":")[1]}
        "ClientIP"                           = $AuditData.Reason | ForEach-Object{($_ -split ";")} | Select-String -Pattern "^CIP=" | ForEach-Object{($_ -split "=")[1]}
        "ASN"                                = $AuditData.Reason | ForEach-Object{($_ -split ";")} | Select-String -Pattern "^AS:" | ForEach-Object{($_ -split ":")[1]}
        "Message"                            = ($AuditData.Reason | ForEach-Object{($_ -split ";")} | Select-String -Pattern ":" -NotMatch | Select-String -Pattern "=" -NotMatch | Out-String).Trim()
        }

        $Results.Add($Line)
    }

    $Results | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\HygieneTenantEvents_AuditData.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\HygieneTenantEvents_AuditData.csv")
    {
        if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\HygieneTenantEvents_AuditData.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\HygieneTenantEvents_AuditData.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\XLSX\HygieneTenantEvents_AuditData.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "HygieneTenantEvents" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:W1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-V
            $WorkSheet.Cells["A:V"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting - Consent to application.
            Add-ConditionalFormatting -Address $WorkSheet.Cells["C:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("HygieneTenantEvents",$D1)))' -BackgroundColor Red
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

# Check IPinfo Subscription Plan (https://ipinfo.io/pricing)
if (Test-Path "$($IPinfo)")
{
    $Quota = & $IPinfo quota
    if ($Quota -eq "err: please login first to check quota")
    {
        # Login
        & $IPinfo init "$Token" > $null
        $Quota = & $IPinfo quota
    }

    Write-Output "[Info]  Checking IPinfo Subscription Plan ..."
    [int]$TotalRequests = $Quota | Select-String -Pattern "Total Requests" | ForEach-Object{($_ -split "\s+")[-1]}
    [int]$RemainingRequests = $Quota | Select-String -Pattern "Remaining Requests" | ForEach-Object{($_ -split "\s+")[-1]}
    $TotalMonth = '{0:N0}' -f $TotalRequests | ForEach-Object {$_ -replace ' ','.'}
    $RemainingMonth = '{0:N0}' -f $RemainingRequests | ForEach-Object {$_ -replace ' ','.'}

    if (& $IPinfo myip --token "$Token" | Select-String -Pattern "Privacy" -Quiet)
    {
        $script:PrivacyDetection = "True"
        Write-output "[Info]  IPinfo Subscription Plan w/ Privacy Detection found"
        Write-Output "[Info]  $RemainingMonth Requests left this month"
    }
    else
    {
        $script:PrivacyDetection = "False"
        Write-output "[Info]  IPinfo Subscription: Free ($TotalMonth Requests/Month)"
        Write-Output "[Info]  $RemainingMonth Requests left this month"
    }
}

# IPinfo CLI
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

                        # TXT --> Top Privacy Services
                        Get-Content "$OUTPUT_FOLDER\ClientIP\IP.txt" | & $IPinfo summarize --token "$Token" | Out-File "$OUTPUT_FOLDER\ClientIP\IPinfo\Summary.txt"

                        # CSV
                        Get-Content "$OUTPUT_FOLDER\ClientIP\IP.txt" | & $IPinfo --csv --token "$Token" | Out-File "$OUTPUT_FOLDER\ClientIP\IPinfo\IPinfo.csv" -Encoding UTF8

                        # Custom CSV (Free)
                        if ($PrivacyDetection -eq "False")
                        {
                            if (Test-Path "$OUTPUT_FOLDER\ClientIP\IPinfo\IPinfo.csv")
                            {
                                if([int](& $xsv count "$OUTPUT_FOLDER\ClientIP\IPinfo\IPinfo.csv") -gt 0)
                                {
                                    $IPinfoRecords = Import-Csv "$OUTPUT_FOLDER\ClientIP\IPinfo\IPinfo.csv" -Delimiter "," -Encoding UTF8

                                    $Results = [Collections.Generic.List[PSObject]]::new()
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

                                        $Results.Add($Line)
                                    }

                                    $Results | Sort-Object {$_.IP -as [Version]} | Export-Csv -Path "$OUTPUT_FOLDER\ClientIP\IPinfo\IPinfo-Custom.csv" -NoTypeInformation -Encoding UTF8
                                }
                            }

                            # Custom XLSX (Free)
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

                        # Custom CSV (Privacy Detection)
                        if ($PrivacyDetection -eq "True")
                        {
                            if (Test-Path "$OUTPUT_FOLDER\ClientIP\IPinfo\IPinfo.csv")
                            {
                                if([int](& $xsv count "$OUTPUT_FOLDER\ClientIP\IPinfo\IPinfo.csv") -gt 0)
                                {
                                    $IPinfoRecords = Import-Csv "$OUTPUT_FOLDER\ClientIP\IPinfo\IPinfo.csv" -Delimiter "," -Encoding UTF8
                                
                                    $Results = [Collections.Generic.List[PSObject]]::new()
                                    ForEach($IPinfoRecord in $IPinfoRecords)
                                    {
                                        $Line = [PSCustomObject]@{
                                            "IP"           = $IPinfoRecord.ip
                                            "City"         = $IPinfoRecord.city
                                            "Region"       = $IPinfoRecord.region
                                            "Country"      = $IPinfoRecord.country
                                            "Country Name" = $IPinfoRecord.country_name
                                            "Location"     = $IPinfoRecord.loc
                                            "ASN"          = $IPinfoRecord.asn_id
                                            "OrgName"      = $IPinfoRecord.asn_asn
                                            "Postal Code"  = $IPinfoRecord.postal
                                            "Timezone"     = $IPinfoRecord.timezone
                                            "VPN"          = $IPinfoRecord.privacy_vpn
                                            "Proxy"        = $IPinfoRecord.privacy_proxy
                                            "Tor"          = $IPinfoRecord.privacy_tor
                                            "Relay"        = $IPinfoRecord.privacy_relay
                                            "Hosting"      = $IPinfoRecord.privacy_hosting
                                            "Service"      = $IPinfoRecord.privacy_service
                                        }

                                        $Results.Add($Line)
                                    }

                                    $Results | Sort-Object {$_.IP -as [Version]} | Export-Csv -Path "$OUTPUT_FOLDER\ClientIP\IPinfo\IPinfo-Custom.csv" -NoTypeInformation -Encoding UTF8
                                }
                            }

                            # Custom XLSX (Privacy Detection)
                            if (Test-Path "$OUTPUT_FOLDER\ClientIP\IPinfo\IPinfo-Custom.csv")
                            {
                                if([int](& $xsv count "$OUTPUT_FOLDER\ClientIP\IPinfo\IPinfo-Custom.csv") -gt 0)
                                {
                                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\ClientIP\IPinfo\IPinfo-Custom.csv" -Delimiter "," | Sort-Object {$_.ip -as [Version]}
                                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\ClientIP\IPinfo\IPinfo-Custom.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -IncludePivotTable -PivotTableName "PivotTable" -PivotRows "Country Name" -PivotData @{"IP"="Count"} -WorkSheetname "IPinfo (Standard)" -CellStyleSB {
                                    param($WorkSheet)
                                    # BackgroundColor and FontColor for specific cells of TopRow
                                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                    Set-Format -Address $WorkSheet.Cells["A1:P1"] -BackgroundColor $BackgroundColor -FontColor White
                                    # HorizontalAlignment "Center" of columns A-P
                                    $WorkSheet.Cells["A:P"].Style.HorizontalAlignment="Center"
                                    # ConditionalFormatting - VPN
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["K:K"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("true",$K1)))' -BackgroundColor Red
                                    # ConditionalFormatting - Proxy
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["L:L"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("true",$L1)))' -BackgroundColor Red
                                    # ConditionalFormatting - Tor
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["M:M"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("true",$M1)))' -BackgroundColor Red
                                    # ConditionalFormatting - Relay
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["N:N"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("true",$N1)))' -BackgroundColor Red
                                    # ConditionalFormatting - Service
                                    $LastRow = $WorkSheet.Dimension.End.Row
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["P2:P$LastRow"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '=$P2<>""' -BackgroundColor Red
                                    
                                    # ConditionalFormatting - ASN
                                    foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
                                    {
                                        $ConditionValue = 'NOT(ISERROR(FIND("AS{0}",$G1)))' -f $ASN
                                        Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
                                    }

                                    # ConditionalFormatting - Country
                                    foreach ($Country in $CountryBlacklist_HashTable.Keys) 
                                    {
                                        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$E1)))' -f $Country
                                        Add-ConditionalFormatting -Address $WorkSheet.Cells["E:E"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
                                    }
                                    
                                    }
                                }
                            }
                        }

                        # Create HashTable and import 'IPinfo-Custom.csv'
                        $script:IPinfo_HashTable = @{}
                        if (Test-Path "$OUTPUT_FOLDER\ClientIP\IPinfo\IPinfo-Custom.csv")
                        {
                            if([int](& $xsv count "$OUTPUT_FOLDER\ClientIP\IPinfo\IPinfo-Custom.csv") -gt 0)
                            {
                                # Free
                                if ($PrivacyDetection -eq "False")
                                {
                                    Import-Csv -Path "$OUTPUT_FOLDER\ClientIP\IPinfo\IPinfo-Custom.csv" -Delimiter "," -Encoding UTF8 | ForEach-Object { $IPinfo_HashTable[$_.IP] = $_.City,$_.Region,$_.Country,$_."Country Name",$_.Location,$_.ASN,$_.OrgName,$_."Postal Code",$_.Timezone }
                                }

                                # Privacy Detection
                                if ($PrivacyDetection -eq "True")
                                {
                                    Import-Csv -Path "$OUTPUT_FOLDER\ClientIP\IPinfo\IPinfo-Custom.csv" -Delimiter "," -Encoding UTF8 | ForEach-Object { $IPinfo_HashTable[$_.IP] = $_.City,$_.Region,$_.Country,$_."Country Name",$_.Location,$_.ASN,$_.OrgName,$_."Postal Code",$_.Timezone,$_.VPN,$_.Proxy,$_.Tor,$_.Relay,$_.Hosting,$_.Service }
                                }

                                # Count Ingested Properties
                                $Count = $IPinfo_HashTable.Count
                                Write-Output "[Info]  Initializing 'IPinfo-Custom.csv' Lookup Table ($Count) ..."
                            }
                        }

                        # Hunt

                        # IPinfo Subscription: Free
                        if ($PrivacyDetection -eq "False")
                        {
                            if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Custom.csv")
                            {
                                if([int](& $xsv count "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Custom.csv") -gt 0)
                                {
                                    $Records = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Custom.csv" -Delimiter "," -Encoding UTF8

                                    # CSV
                                    $Results = [Collections.Generic.List[PSObject]]::new()
                                    ForEach($Record in $Records)
                                    {
                                        # ClientIP or ClientIPAddress
                                        $IP = $Record.ClientIP | ForEach-Object {$_ -replace "^::ffff:"} # Remove Prefix of IPv4-mapped IPv6 address

                                        if ($IP -eq "")
                                        {
                                            $IP = $Record.ClientIPAddress
                                        }

                                        # Check if HashTable contains IP
                                        if($IPinfo_HashTable.ContainsKey("$IP"))
                                        {
                                            $City        = $IPinfo_HashTable["$IP"][0]
                                            $Region      = $IPinfo_HashTable["$IP"][1]
                                            $Country     = $IPinfo_HashTable["$IP"][2]
                                            $CountryName = $IPinfo_HashTable["$IP"][3]
                                            $Location    = $IPinfo_HashTable["$IP"][4]
                                            $ASN         = $IPinfo_HashTable["$IP"][5] | ForEach-Object {$_ -replace "^AS"}
                                            $OrgName     = $IPinfo_HashTable["$IP"][6]
                                            $PostalCode  = $IPinfo_HashTable["$IP"][7]
                                            $Timezone    = $IPinfo_HashTable["$IP"][8]
                                        }
                                        else
                                        {
                                            $City        = ""
                                            $Region      = ""
                                            $Country     = ""
                                            $CountryName = ""
                                            $Location    = ""
                                            $ASN         = ""
                                            $OrgName     = ""
                                            $PostalCode  = ""
                                            $Timezone    = ""
                                        }

                                        $Line = [PSCustomObject]@{
                                            "CreationTime"          = $Record.CreationTime # UTC
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
                                            "Location"              = $Location
                                            "ASN"                   = $ASN
                                            "OrgName"               = $OrgName
                                            "Timezone"              = $Timezone
                                            "SessionId"             = $Record.SessionId
                                            "InterSystemsId"        = $Record.InterSystemsId
                                            "RequestType"           = $Record.RequestType
                                            "DeviceName"            = $Record.DeviceName
                                            "DeviceId"              = $Record.DeviceId
                                            "OS"                    = $Record.OS
                                            "BrowserType"           = $Record.BrowserType
                                            "IsCompliant"           = $Record.IsCompliant
                                            "IsCompliantAndManaged" = $Record.IsCompliantAndManaged
                                            "Workload"              = $Record.Workload
                                            "IssuedAtTime"          = $Record.IssuedAtTime
                                            "UniqueTokenId"         = $Record.UniqueTokenId
                                        }

                                        $Results.Add($Line)
                                    }

                                    $Results | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -NoTypeInformation -Encoding UTF8
                                }
                            }
                        
                            # XLSX
                            if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv")
                            {
                                if([int](& $xsv count "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv") -gt 0)
                                {
                                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," | Sort-Object { $_.CreationTime -as [datetime] } -Descending
                                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\XLSX\Hunt.xlsx" -NoHyperLinkConversion * -NoNumberConversion * -FreezePane 2,5 -BoldTopRow -AutoSize -AutoFilter -IncludePivotTable -PivotTableName "PivotTable" -WorkSheetname "Hunt" -CellStyleSB {
                                    param($WorkSheet)
                                    # BackgroundColor and FontColor for specific cells of TopRow
                                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                    Set-Format -Address $WorkSheet.Cells["A1:AC1"] -BackgroundColor $BackgroundColor -FontColor White
                                    # HorizontalAlignment "Center" of columns A-D and F-AC
                                    $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"
                                    $WorkSheet.Cells["F:AC"].Style.HorizontalAlignment="Center"

                                    # Iterating over the Application-Blacklist HashTable
                                    foreach ($AppId in $ApplicationBlacklist_HashTable.Keys) 
                                    {
                                        $Severity = $ApplicationBlacklist_HashTable["$AppId"][1]
                                        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$E1)))' -f $AppId
                                        Add-ConditionalFormatting -Address $WorkSheet.Cells["E:E"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
                                    }

                                    # Iterating over the ASN-Blacklist HashTable
                                    foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
                                    {
                                        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$O1)))' -f $ASN
                                        Add-ConditionalFormatting -Address $WorkSheet.Cells["O:O"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red

                                        $ConditionValue = '=AND(NOT(ISERROR(FIND("{0}",$O1))),$R1<>"")' -f $ASN
                                        Add-ConditionalFormatting -Address $WorkSheet.Cells["R:R"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red # Colorize also the corresponding SessionId
                                    }

                                    # Iterating over the Country-Blacklist HashTable
                                    foreach ($Country in $CountryBlacklist_HashTable.Keys) 
                                    {
                                        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$M1)))' -f $Country
                                        Add-ConditionalFormatting -Address $WorkSheet.Cells["M:M"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
                                    }

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
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("HygieneTenantEvents",$D1)))' -BackgroundColor Red # Outbound Spam
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("SearchStarted",$D1)))' -BackgroundColor Red # Content Search Abuse
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("SearchExportDownloaded",$D1)))' -BackgroundColor Red # Content Search Abuse
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("ViewedSearchExported",$D1)))' -BackgroundColor Red # Content Search Abuse
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("New-UnifiedAuditLogRetentionPolicy",$D1)))' -BackgroundColor Red # Anti-Forensics
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Set-UnifiedAuditLogRetentionPolicy",$D1)))' -BackgroundColor Red # Anti-Forensics
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Remove-UnifiedAuditLogRetentionPolicy",$D1)))' -BackgroundColor Red # Anti-Forensics

                                    # ConditionalFormatting - Operations
                                    $Cells = "D:D"
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Change user password.",$D1)))' -BackgroundColor Yellow # Changed user password
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Reset user password.",$D1)))' -BackgroundColor $Green # Administrator resets the password for a user.
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Update StsRefreshTokenValidFrom Timestamp.",$D1)))' -BackgroundColor $Green # Revoke Sessions --> Check 'ObjectId' for UPN

                                    # ConditionalFormatting - Suspicious ClientInfoString
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["I:I"] -WorkSheet $WorkSheet -RuleType 'Expression' '=AND($I1="Client=OWA;Action=ViaProxy",$P1<>"AS53813",$P1<>"AS62044")' -BackgroundColor Red # AiTM Proxy Server

                                    # Iterating over the UserAgent-Blacklist HashTable
                                    foreach ($UserAgent in $UserAgentBlacklist_HashTable.Keys) 
                                    {
                                        $Severity = $UserAgentBlacklist_HashTable["$UserAgent"][1]
                                        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$H1)))' -f $UserAgent
                                        Add-ConditionalFormatting -Address $WorkSheet.Cells["H:H"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
                                    }

                                    # ConditionalFormatting - BrowserType
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["X:X"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Other",$X1)))' -BackgroundColor Red

                                    }
                                }
                            }
                        }

                        # IPinfo Subscription Plan w/ Privacy Detection
                        if ($PrivacyDetection -eq "True")
                        {
                            if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Custom.csv")
                            {
                                if([int](& $xsv count "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Custom.csv") -gt 0)
                                {
                                    $Records = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Custom.csv" -Delimiter "," -Encoding UTF8

                                    # CSV
                                    $Results = [Collections.Generic.List[PSObject]]::new()
                                    ForEach($Record in $Records)
                                    {
                                        # ClientIP or ClientIPAddress
                                        $IP = $Record.ClientIP | ForEach-Object {$_ -replace "^::ffff:"} # Remove Prefix of IPv4-mapped IPv6 address

                                        if ($IP -eq "")
                                        {
                                            $IP = $Record.ClientIPAddress
                                        }

                                        # Check if HashTable contains IP
                                        if($IPinfo_HashTable.ContainsKey("$IP"))
                                        {
                                            $City        = $IPinfo_HashTable["$IP"][0]
                                            $Region      = $IPinfo_HashTable["$IP"][1]
                                            $Country     = $IPinfo_HashTable["$IP"][2]
                                            $CountryName = $IPinfo_HashTable["$IP"][3]
                                            $Location    = $IPinfo_HashTable["$IP"][4]
                                            $ASN         = $IPinfo_HashTable["$IP"][5] | ForEach-Object {$_ -replace "^AS"}
                                            $OrgName     = $IPinfo_HashTable["$IP"][6]
                                            $PostalCode  = $IPinfo_HashTable["$IP"][7]
                                            $Timezone    = $IPinfo_HashTable["$IP"][8]
                                            $VPN         = $IPinfo_HashTable["$IP"][9]
                                            $Proxy       = $IPinfo_HashTable["$IP"][10]
                                            $Tor         = $IPinfo_HashTable["$IP"][11]
                                            $Relay       = $IPinfo_HashTable["$IP"][12]
                                            $Hosting     = $IPinfo_HashTable["$IP"][13]
                                            $Service     = $IPinfo_HashTable["$IP"][14]
                                        }
                                        else
                                        {
                                            $City        = ""
                                            $Region      = ""
                                            $Country     = ""
                                            $CountryName = ""
                                            $Location    = ""
                                            $ASN         = ""
                                            $OrgName     = ""
                                            $PostalCode  = ""
                                            $Timezone    = ""
                                            $VPN         = ""
                                            $Proxy       = ""
                                            $Tor         = ""
                                            $Relay       = ""
                                            $Hosting     = ""
                                            $Service     = ""
                                        }

                                        $Line = [PSCustomObject]@{
                                            "CreationTime"          = $Record.CreationTime # UTC
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
                                            "Location"              = $Location
                                            "ASN"                   = $ASN
                                            "OrgName"               = $OrgName
                                            "Postal Code"           = $PostalCode
                                            "Timezone"              = $Timezone
                                            "VPN"                   = $VPN
                                            "Proxy"                 = $Proxy
                                            "Tor"                   = $Tor
                                            "Relay"                 = $Relay
                                            "Hosting"               = $Hosting
                                            "Service"               = $Service
                                            "SessionId"             = $Record.SessionId
                                            "InterSystemsId"        = $Record.InterSystemsId
                                            "RequestType"           = $Record.RequestType
                                            "DeviceName"            = $Record.DeviceName
                                            "DeviceId"              = $Record.DeviceId
                                            "OS"                    = $Record.OS
                                            "BrowserType"           = $Record.BrowserType
                                            "IsCompliant"           = $Record.IsCompliant
                                            "IsCompliantAndManaged" = $Record.IsCompliantAndManaged
                                            "Workload"              = $Record.Workload
                                            "IssuedAtTime"          = $Record.IssuedAtTime
                                            "UniqueTokenId"         = $Record.UniqueTokenId
                                        }

                                        $Results.Add($Line)
                                    }

                                    $Results | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -NoTypeInformation -Encoding UTF8
                                }
                            }
                        
                            # XLSX
                            if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv")
                            {
                                if([int](& $xsv count "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv") -gt 0)
                                {
                                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," | Sort-Object { $_.CreationTime -as [datetime] } -Descending
                                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\XLSX\Hunt.xlsx" -NoHyperLinkConversion * -NoNumberConversion * -FreezePane 2,5 -BoldTopRow -AutoSize -AutoFilter -IncludePivotTable -PivotTableName "PivotTable" -WorkSheetname "Hunt" -CellStyleSB {
                                    param($WorkSheet)
                                    # BackgroundColor and FontColor for specific cells of TopRow
                                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                    Set-Format -Address $WorkSheet.Cells["A1:AJ1"] -BackgroundColor $BackgroundColor -FontColor White
                                    # HorizontalAlignment "Center" of columns A-D and F-AJ
                                    $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"
                                    $WorkSheet.Cells["F:AJ"].Style.HorizontalAlignment="Center"

                                    # Iterating over the Application-Blacklist HashTable
                                    foreach ($AppId in $ApplicationBlacklist_HashTable.Keys) 
                                    {
                                        $Severity = $ApplicationBlacklist_HashTable["$AppId"][1]
                                        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$E1)))' -f $AppId
                                        Add-ConditionalFormatting -Address $WorkSheet.Cells["E:E"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
                                    }

                                    # Iterating over the ASN-Blacklist HashTable
                                    foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
                                    {
                                        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$O1)))' -f $ASN
                                        Add-ConditionalFormatting -Address $WorkSheet.Cells["O:O"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red

                                        $ConditionValue = '=AND(NOT(ISERROR(FIND("{0}",$O1))),$R1<>"")' -f $ASN
                                        Add-ConditionalFormatting -Address $WorkSheet.Cells["R:R"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red # Colorize also the corresponding SessionId
                                    }

                                    # Iterating over the Country-Blacklist HashTable
                                    foreach ($Country in $CountryBlacklist_HashTable.Keys) 
                                    {
                                        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$M1)))' -f $Country
                                        Add-ConditionalFormatting -Address $WorkSheet.Cells["M:M"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
                                    }

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
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("HygieneTenantEvents",$D1)))' -BackgroundColor Red # Outbound Spam
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("SearchStarted",$D1)))' -BackgroundColor Red # Content Search Abuse
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("SearchExportDownloaded",$D1)))' -BackgroundColor Red # Content Search Abuse
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("ViewedSearchExported",$D1)))' -BackgroundColor Red # Content Search Abuse
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("New-UnifiedAuditLogRetentionPolicy",$D1)))' -BackgroundColor Red # Anti-Forensics
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Set-UnifiedAuditLogRetentionPolicy",$D1)))' -BackgroundColor Red # Anti-Forensics
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Remove-UnifiedAuditLogRetentionPolicy",$D1)))' -BackgroundColor Red # Anti-Forensics

                                    # ConditionalFormatting - Operations
                                    $Cells = "D:D"
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Change user password.",$D1)))' -BackgroundColor Yellow # Changed user password
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Reset user password.",$D1)))' -BackgroundColor $Green # Administrator resets the password for a user.
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Update StsRefreshTokenValidFrom Timestamp.",$D1)))' -BackgroundColor $Green # Revoke Sessions --> Check 'ObjectId' for UPN

                                    # ConditionalFormatting - Suspicious ClientInfoString
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["I:I"] -WorkSheet $WorkSheet -RuleType 'Expression' '=AND($I1="Client=OWA;Action=ViaProxy",$P1<>"AS53813",$P1<>"AS62044")' -BackgroundColor Red # AiTM Proxy Server

                                    # Iterating over the UserAgent-Blacklist HashTable
                                    foreach ($UserAgent in $UserAgentBlacklist_HashTable.Keys) 
                                    {
                                        $Severity = $UserAgentBlacklist_HashTable["$UserAgent"][1]
                                        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$H1)))' -f $UserAgent
                                        Add-ConditionalFormatting -Address $WorkSheet.Cells["H:H"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
                                    }

                                    # ConditionalFormatting - BrowserType
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["X:X"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Other",$X1)))' -BackgroundColor Red

                                    }
                                }
                            }
                        }

                        # ASN (Stats)
                        $Total = (Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," | Select-Object ASN | Where-Object {$_.ASN -ne '' } | Measure-Object).Count
                        if ($Total -ge "1")
                        {
                            $Stats = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," | Select-Object ASN,OrgName | Where-Object {$_.ASN -ne '' } | Where-Object {$null -ne ($_.PSObject.Properties | ForEach-Object {$_.Value})} | Group-Object ASN,OrgName | Select-Object @{Name='ASN'; Expression={ $_.Values[0] }},@{Name='OrgName'; Expression={ $_.Values[1] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
                            $Stats | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Stats\ASN.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ASN" -CellStyleSB {
                            param($WorkSheet)
                            # BackgroundColor and FontColor for specific cells of TopRow
                            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                            Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor White
                            # HorizontalAlignment "Center" of columns A-D
                            $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"

                            # Iterating over the ASN-Blacklist HashTable
                            foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
                            {
                                $ConditionValue = 'NOT(ISERROR(FIND("{0}",$A1)))' -f $ASN
                                Add-ConditionalFormatting -Address $WorkSheet.Cells["A:D"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
                            }

                            }
                        }

                        # ClientIP / Country Name (Stats)
                        $Total = (Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," | Select-Object ClientIP | Where-Object {$_.ClientIP -ne '' } | Measure-Object).Count
                        if ($Total -ge "1")
                        {
                            $Stats = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," -Encoding UTF8 | Select-Object ClientIP,Country,"Country Name",ASN,OrgName | Where-Object {$_.ClientIP -ne '' } | Where-Object {$_."Country Name" -ne '' } | Where-Object {$null -ne ($_.PSObject.Properties | ForEach-Object {$_.Value})} | Group-Object ClientIP,Country,"Country Name",ASN,OrgName | Select-Object @{Name='ClientIP'; Expression={ $_.Values[0] }},@{Name='Country'; Expression={ $_.Values[1] }},@{Name='Country Name'; Expression={ $_.Values[2] }},@{Name='ASN'; Expression={ $_.Values[3] }},@{Name='OrgName'; Expression={ $_.Values[4] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
                            $Stats | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Stats\ClientIP.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ClientIP" -CellStyleSB {
                            param($WorkSheet)
                            # BackgroundColor and FontColor for specific cells of TopRow
                            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                            Set-Format -Address $WorkSheet.Cells["A1:G1"] -BackgroundColor $BackgroundColor -FontColor White
                            # HorizontalAlignment "Center" of columns A-G
                            $WorkSheet.Cells["A:G"].Style.HorizontalAlignment="Center"

                            # Iterating over the ASN-Blacklist HashTable
                            foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
                            {
                                $ConditionValue = 'NOT(ISERROR(FIND("{0}",$D1)))' -f $ASN
                                Add-ConditionalFormatting -Address $WorkSheet.Cells["D:E"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
                            }

                            # Iterating over the Country-Blacklist HashTable
                            foreach ($Country in $CountryBlacklist_HashTable.Keys) 
                            {
                                $ConditionValue = 'NOT(ISERROR(FIND("{0}",$C1)))' -f $Country
                                Add-ConditionalFormatting -Address $WorkSheet.Cells["B:C"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
                            }
                                    
                            }
                        }

                        # Country / Country Name (Stats)
                        $Total = (Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," | Select-Object Country | Where-Object {$_.Country -ne '' } | Measure-Object).Count
                        if ($Total -ge "1")
                        {
                            $Stats = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," | Select-Object Country,"Country Name" | Where-Object {$_.Country -ne '' } | Where-Object {$null -ne ($_.PSObject.Properties | ForEach-Object {$_.Value})} | Group-Object Country,"Country Name" | Select-Object @{Name='Country'; Expression={ $_.Values[0] }},@{Name='Country Name'; Expression={ $_.Values[1] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
                            $Stats | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Stats\Country.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Countries" -CellStyleSB {
                            param($WorkSheet)
                            # BackgroundColor and FontColor for specific cells of TopRow
                            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                            Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor White
                            # HorizontalAlignment "Center" of columns A-D
                            $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"

                            # Iterating over the Country-Blacklist HashTable
                            foreach ($Country in $CountryBlacklist_HashTable.Keys) 
                            {
                                $ConditionValue = 'NOT(ISERROR(FIND("{0}",$B1)))' -f $Country
                                Add-ConditionalFormatting -Address $WorkSheet.Cells["A:D"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
                            }

                            }
                            
                            $Countries = (Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," | Select-Object Country -Unique | Where-Object { $_.Country -ne '' } | Measure-Object).Count
                            $Cities = (Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," | Select-Object City -Unique | Where-Object { $_.City -ne '' } | Measure-Object).Count
                            Write-Output "[Info]  $Countries Countries and $Cities Cities found"
                        }

                        # OAuth Applications

                        # Create HashTable and import 'Application-Blacklist.csv'
                        $ApplicationBlacklist_HashTable = @{}
                        if (Test-Path "$SCRIPT_DIR\Blacklists\Application-Blacklist.csv")
                        {
                            if([int](& $xsv count "$SCRIPT_DIR\Blacklists\Application-Blacklist.csv") -gt 0)
                            {
                                Import-Csv "$SCRIPT_DIR\Blacklists\Application-Blacklist.csv" -Delimiter "," | ForEach-Object { $ApplicationBlacklist_HashTable[$_.AppId] = $_.AppDisplayName,$_.Severity }

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
                        $Total = (Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," | Select-Object Workload | Measure-Object).Count
                        if ($Total -ge "1")
                        {        
                            $Stats = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," -Encoding UTF8 | Group-Object Workload | Select-Object @{Name='Workload'; Expression={$_.Name}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
                            $Stats | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Stats\Workload.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Workload" -CellStyleSB {
                            param($WorkSheet)
                            # BackgroundColor and FontColor for specific cells of TopRow
                            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                            Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
                            # HorizontalAlignment "Center" of column B-C
                            $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
                            }
                        }

                        # Line Charts
                        New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Stats\LineCharts" -ItemType Directory -Force | Out-Null
                        $Data = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Select-Object -ExpandProperty AuditData | ConvertFrom-Json | Select-Object @{Name="CreationTime";Expression={($_.CreationTime | ForEach-Object{($_ -split "T")[0]})}},Operation | Sort-Object { $_.CreationTime -as [datetime] }

                        # Operations
                        $Import = $Data | Group-Object{($_.CreationTime)} | Select-Object @{Name='CreationTime'; Expression={ $_.Values[0] }},Count | Sort-Object { $_.CreationTime -as [datetime] }
                        $ChartDefinition = New-ExcelChartDefinition -XRange CreationTime -YRange Count -Title "Operations" -ChartType Line -NoLegend -Width 1200
                        $Import | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Stats\LineCharts\Operations.xlsx" -Append -WorksheetName "Line Chart" -AutoNameRange -ExcelChartDefinition $ChartDefinition

                        # UserLoggedIn
                        $Import = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," -Encoding UTF8 | Where-Object { $_.RecordType -eq "AzureActiveDirectoryStsLogon" } | Where-Object { $_.Operation -eq "UserLoggedIn" } | Select-Object CreationTime,Operation | Group-Object{($_.CreationTime -split "\s+")[0]} | Select-Object @{Name='CreationTime'; Expression={ $_.Values[0] }},Count | Sort-Object { $_.CreationTime -as [datetime] }
                        $ChartDefinition = New-ExcelChartDefinition -XRange CreationTime -YRange Count -Title "UserLoggedIn" -ChartType Line -NoLegend -Width 1200
                        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Stats\LineCharts\UserLoggedIn.xlsx" -Append -WorksheetName "Line Chart" -AutoNameRange -ExcelChartDefinition $ChartDefinition
                        
                        # UserLoginFailed
                        $Import = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," -Encoding UTF8 | Where-Object { $_.RecordType -eq "AzureActiveDirectoryStsLogon" } | Where-Object { $_.Operation -eq "UserLoginFailed" } | Select-Object CreationTime,Operation | Group-Object{($_.CreationTime -split "\s+")[0]} | Select-Object @{Name='CreationTime'; Expression={ $_.Values[0] }},Count | Sort-Object { $_.CreationTime -as [datetime] }
                        $ChartDefinition = New-ExcelChartDefinition -XRange CreationTime -YRange Count -Title "UserLoginFailed" -ChartType Line -NoLegend -Width 1200
                        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Stats\LineCharts\UserLoginFailed.xlsx" -Append -WorksheetName "Line Chart" -AutoNameRange -ExcelChartDefinition $ChartDefinition

                        # Suspicious Operations
                        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv")
                        {
                            if([int](& $xsv count "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv") -gt 0)
                            {
                                # UserLoginFailed
                                # RecordType: AzureActiveDirectoryStsLogon --> Secure Token Service (STS) logon events in Azure Active Directory.
                                # Operation: UserLoginFailed --> This property contains the Azure Active Directory STS (AADSTS) error code.
                                $Import = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," -Encoding UTF8 | Where-Object { $_.RecordType -eq "AzureActiveDirectoryStsLogon" } | Where-Object { $_.Operation -eq "UserLoginFailed" }
                                $Count = ($Import | Group-Object{($_.CreationTime -split "\s+")[0]} | Where-Object Count -ge 10 | Measure-Object).Count

                                if ($Count -ge 1)
                                {
                                    Write-Host "[Alert] Suspicious Operation(s) detected: 10+ UserLoginFailed operations per user on a single day ($Count)" -ForegroundColor Yellow
                                    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV" -ItemType Directory -Force | Out-Null
                                    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\XLSX" -ItemType Directory -Force | Out-Null

                                    # CSV
                                    $Import | Group-Object{($_.CreationTime -split "\s+")[0]} | Where-Object Count -ge 10 | Select-Object Name,Count | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\AzureActiveDirectoryStsLogon-UserLoginFailed-Overview.csv" -NoTypeInformation -Encoding UTF8
                                    $Import | Group-Object{($_.CreationTime -split "\s+")[0]} | Where-Object Count -ge 10 | Select-Object -Expand Group | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\AzureActiveDirectoryStsLogon-UserLoginFailed.csv" -NoTypeInformation -Encoding UTF8

                                    # AzureActiveDirectoryStsLogon-UserLoginFailed-Overview.xlsx
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

                                    # AzureActiveDirectoryStsLogon-UserLoginFailed.xlsx
                                    if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\AzureActiveDirectoryStsLogon-UserLoginFailed.csv")
                                    {
                                        if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\AzureActiveDirectoryStsLogon-UserLoginFailed.csv") -gt 0)
                                        {
                                            $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\CSV\AzureActiveDirectoryStsLogon-UserLoginFailed.csv" -Delimiter "," | Select-Object CreationTime,UserId,RecordType,Operation,ObjectId,ClientIP,UserAgent,City,Region,Country,"Country Name",ASN,OrgName,Timezone,Workload
                                            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Operations\XLSX\AzureActiveDirectoryStsLogon-UserLoginFailed.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "UserLoginFailed" -CellStyleSB {
                                            param($WorkSheet)
                                            # BackgroundColor and FontColor for specific cells of TopRow
                                            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                            Set-Format -Address $WorkSheet.Cells["A1:O1"] -BackgroundColor $BackgroundColor -FontColor White
                                            # HorizontalAlignment "Center" of columns A-O
                                            $WorkSheet.Cells["A:O"].Style.HorizontalAlignment="Center"
                                            # ConditionalFormatting
                                            Add-ConditionalFormatting -Address $WorkSheet.Cells["C:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("AzureActiveDirectoryStsLogon",$C1)))' -BackgroundColor Red
                                            Add-ConditionalFormatting -Address $WorkSheet.Cells["D:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("UserLoginFailed",$D1)))' -BackgroundColor Red
                                            
                                            # Iterating over the ASN-Blacklist HashTable
                                            foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
                                            {
                                                $ConditionValue = 'NOT(ISERROR(FIND("{0}",$L1)))' -f $ASN
                                                Add-ConditionalFormatting -Address $WorkSheet.Cells["L:L"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
                                            }
                                            
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        # Exchange Mailbox Activities
                        Write-Host "[Info]  Analyzing Exchange Mailbox Activities ..."

                        # Function Get-MoveToDeletedItems
                        Function Get-MoveToDeletedItems {

                        # MoveToDeletedItems - Moved messages to 'Deleted Items' folder
                        # Description: A message was deleted and moved to the Deleted Items folder.
                        $Records = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object { $_.RecordType -eq "ExchangeItemGroup" } | Where-Object { $_.Operations -eq "MoveToDeletedItems" } | Sort-Object { $_.CreationTime -as [datetime] } -Descending
                        $Count = ($Records | Select-Object CreationTime).Count
                        $MoveToDeletedItems = '{0:N0}' -f $Count

                        if ($Count -gt 0)
                        {
                            Write-Host "[Info]  $MoveToDeletedItems messages were moved to Deleted Items folder: MoveToDeletedItems"
                            New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV" -ItemType Directory -Force | Out-Null
                            New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\XLSX" -ItemType Directory -Force | Out-Null

                            # CSV
                            $Results = [Collections.Generic.List[PSObject]]::new()
                            ForEach($Record in $Records)
                            {
                                $AuditData     = $Record.AuditData | ConvertFrom-Json
                                $AffectedItems = $AuditData.AffectedItems
                                $ClientRequestId = $AuditData | Select-Object -ExpandProperty ClientRequestId -ErrorAction SilentlyContinue | ForEach-Object {$_ -replace '{'} | ForEach-Object {$_ -replace '}'}
                                $DestFolder    = $AuditData.DestFolder
                                $Folder        = $AuditData.Folder

                                # UserType
                                [int]$UserTypeValue = $AuditData.UserType

                                # Check if HashTable contains Value
                                if($UserType_HashTable.ContainsKey("$UserTypeValue"))
                                {
                                    $UserType = $UserType_HashTable["$UserTypeValue"][0]
                                }
                                        
                                $Line = [PSCustomObject]@{
                                "CreationTime"          = $AuditData | Select-Object -ExpandProperty CreationTime | ForEach-Object {$_ -replace 'T',' '}
                                "Id"                    = $AuditData.Id
                                "Workload"              = $AuditData.Workload
                                "RecordType"            = $Record.RecordType
                                "Operation"             = $AuditData.Operation
                                "ResultStatus"          = $AuditData.ResultStatus # Succeeded, PartiallySucceeded, Failed
                                "UserId"                = $AuditData.UserId
                                "UserKey"               = $AuditData.UserKey
                                "UserType"              = $UserType
                                "ClientIP"              = $AuditData.ClientIP
                                "ClientIPAddress"       = $AuditData.ClientIPAddress # Client computer IP address.
                                "AppId"                 = $AuditData.AppId
                                "ClientInfoString"      = $AuditData.ClientInfoString # Details that identify which client or Exchange component performed the operation.
                                "ClientProcessName"     = $AuditData.ClientProcessName # Name of the client application process.
                                "ClientRequestId"       = $ClientRequestId
                                "ClientVersion"         = $AuditData.ClientVersion # Client application version.
                                "ExternalAccess"        = $AuditData.ExternalAccess
                                "InternalLogonType"     = $AuditData.InternalLogonType
                                "LogonType"             = $AuditData.LogonType # Owner, Delegate, Admin
                                "LogonUserSid"          = $AuditData.LogonUserSid
                                "MailboxGuid"           = $AuditData.MailboxGuid # Mailbox GUID.
                                "MailboxOwnerSid"       = $AuditData.MailboxOwnerSid # Mailbox owner security identifier (SID).
                                "MailboxOwnerUPN"       = $AuditData.MailboxOwnerUPN # Mailbox owner user principal name (UPN).
                                "OrganizationId"        = $AuditData.OrganizationId
                                "OrganizationName"      = $AuditData.OrganizationName
                                "OriginatingServer"     = $AuditData.OriginatingServer
                                "SessionId"             = $AuditData.SessionId
                                "AffectedItemsId"       = $AffectedItems.Id
                                "InternetMessageId"     = $AffectedItems.InternetMessageId
                                "ParentFolder"          = $AffectedItems.ParentFolder
                                "CrossMailboxOperation" = $AuditData.CrossMailboxOperation # Information about whether the operation logged is a cross-mailbox operation (for example, copying or moving messages among mailboxes).
                                "FolderId"              = $Folder.Id # Folder GUID.
                                "FolderPath"            = $Folder.Path # Folder path.
                                "DestFolderId"          = $DestFolder.Id # Destination folder GUID for move operations.
                                "DestFolderPath"        = $DestFolder.Path # Destination folder path for move operations.
                                "Subject"               = $AffectedItems.Subject
                                "Attachments"           = $AffectedItems.Attachments
                                }

                                $Results.Add($Line)
                            }

                            $Results | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\MoveToDeletedItems.csv" -NoTypeInformation -Encoding UTF8
                        }

                        # XLSX
                        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\MoveToDeletedItems.csv")
                        {
                            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\MoveToDeletedItems.csv") -gt 0)
                            {
                                $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\MoveToDeletedItems.csv" -Delimiter "," -Encoding UTF8 | Sort-Object { $_.CreationTime -as [datetime] } -Descending
                                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\XLSX\MoveToDeletedItems.xlsx" -NoNumberConversion * -FreezePane 2,6 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "MoveToDeletedItems" -CellStyleSB {
                                param($WorkSheet)
                                # BackgroundColor and FontColor for specific cells of TopRow
                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                Set-Format -Address $WorkSheet.Cells["A1:AK1"] -BackgroundColor $BackgroundColor -FontColor White
                                # HorizontalAlignment "Center" of columns A-AI
                                $WorkSheet.Cells["A:AI"].Style.HorizontalAlignment="Center"
                                # ConditionalFormatting
                                Add-ConditionalFormatting -Address $WorkSheet.Cells["D:E"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("MoveToDeletedItems",$E1)))' -BackgroundColor Red
                                }
                            }
                        }

                        # Line Charts
                        New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\XLSX\LineCharts" -ItemType Directory -Force | Out-Null

                        # Messages moved to Deleted Items folder per day (MoveToDeletedItems)
                        $AuditData = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Select-Object -ExpandProperty AuditData | ConvertFrom-Json
                        $Import = $AuditData | Where-Object { $_.Operation -eq "MoveToDeletedItems" } | Select-Object @{Name="CreationTime";Expression={($_.CreationTime | ForEach-Object{($_ -split "T")[0]})}} | Group-Object{($_.CreationTime)} | Select-Object @{Name='CreationTime'; Expression={ $_.Values[0] }},Count | Sort-Object { $_.CreationTime -as [datetime] }
                        $Count = ($Import | Measure-Object).Count
                        if ($Count -gt 0)
                        {
                            $ChartDefinition = New-ExcelChartDefinition -XRange CreationTime -YRange Count -Title "MoveToDeletedItems" -ChartType Line -NoLegend -Width 1200
                            $Import | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\XLSX\LineCharts\MoveToDeletedItems.xlsx" -Append -WorksheetName "Line Chart" -AutoNameRange -ExcelChartDefinition $ChartDefinition
                        }

                        }

                        Get-MoveToDeletedItems

                        # Function Get-SoftDelete
                        Function Get-SoftDelete {

                        # SoftDelete - Deleted messages from 'Deleted Items' folder
                        # Description: A message was permanently deleted or deleted from the Deleted Items folder. These items are moved to the 'Recoverable Items' folder.
                        # Note: Messages are also moved to the 'Recoverable Items' folder when a user selects it and presses Shift+Delete.
                        $Records = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object { $_.RecordType -eq "ExchangeItemGroup" } | Where-Object { $_.Operations -eq "SoftDelete" } | Sort-Object { $_.CreationTime -as [datetime] } -Descending
                        $Count = ($Records | Select-Object CreationTime).Count
                        $SoftDelete = '{0:N0}' -f $Count

                        if ($Count -gt 0)
                        {
                            Write-Host "[Info]  $SoftDelete messages were deleted from Deleted Items folder: SoftDelete (AggregatedItems)"
                            New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV" -ItemType Directory -Force | Out-Null
                            New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\XLSX" -ItemType Directory -Force | Out-Null

                            # CSV
                            $Results = [Collections.Generic.List[PSObject]]::new()
                            ForEach($Record in $Records)
                            {
                                $AuditData       = $Record.AuditData | ConvertFrom-Json
                                $AffectedItems   = $AuditData.AffectedItems
                                $ClientRequestId = $AuditData | Select-Object -ExpandProperty ClientRequestId -ErrorAction SilentlyContinue | ForEach-Object {$_ -replace '{'} | ForEach-Object {$_ -replace '}'}
                                $Folder          = $AuditData.Folder
                                $AggregatedItems = ($AffectedItems.InternetMessageId).Count

                                # UserType (Value --> Member Name)
                                [int]$UserTypeValue = $AuditData.UserType

                                # Check if HashTable contains Value
                                if($UserType_HashTable.ContainsKey("$UserTypeValue"))
                                {
                                    $UserType = $UserType_HashTable["$UserTypeValue"][0]
                                }
                                        
                                $Line = [PSCustomObject]@{
                                "CreationTime"          = $AuditData | Select-Object -ExpandProperty CreationTime | ForEach-Object {$_ -replace 'T',' '}
                                "Id"                    = $AuditData.Id
                                "Workload"              = $AuditData.Workload
                                "RecordType"            = $Record.RecordType
                                "Operation"             = $AuditData.Operation
                                "OperationCount"        = $AggregatedItems # Aggregated Events
                                "ResultStatus"          = $AuditData.ResultStatus # Succeeded, PartiallySucceeded, Failed
                                "UserId"                = $AuditData.UserId
                                "UserKey"               = $AuditData.UserKey
                                "UserType"              = $UserType
                                "ClientIP"              = $AuditData.ClientIP
                                "ClientIPAddress"       = $AuditData.ClientIPAddress
                                "AppId"                 = $AuditData.AppId
                                "ClientInfoString"      = $AuditData.ClientInfoString
                                "ClientProcessName"     = $AuditData.ClientProcessName
                                "ClientRequestId"       = $ClientRequestId
                                "ClientVersion"         = $AuditData.ClientVersion
                                "ExternalAccess"        = $AuditData.ExternalAccess
                                "InternalLogonType"     = $AuditData.InternalLogonType
                                "LogonType"             = $AuditData.LogonType # Owner, Delegate, Admin
                                "LogonUserSid"          = $AuditData.LogonUserSid
                                "MailboxGuid"           = $AuditData.MailboxGuid
                                "MailboxOwnerSid"       = $AuditData.MailboxOwnerSid
                                "MailboxOwnerUPN"       = $AuditData.MailboxOwnerUPN
                                "OrganizationId"        = $AuditData.OrganizationId
                                "OrganizationName"      = $AuditData.OrganizationName
                                "OriginatingServer"     = $AuditData.OriginatingServer
                                "SessionId"             = $AuditData.SessionId
                                "AffectedItemsId"       = ($AffectedItems.Id) -join "`r`n"
                                "InternetMessageId"     = ($AffectedItems.InternetMessageId) -join "`r`n"
                                "ParentFolder"          = ($AffectedItems.ParentFolder) -join "`r`n"
                                "CrossMailboxOperation" = $AuditData.CrossMailboxOperation
                                "FolderId"              = $Folder.Id
                                "FolderPath"            = $Folder.Path
                                "Subject"               = ($AffectedItems.Subject) -join "`r`n"
                                "Attachments"           = ($AffectedItems.Attachments) -join "`r`n"
                                }

                                $Results.Add($Line)
                            }

                            $Results | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\SoftDelete.csv" -NoTypeInformation -Encoding UTF8
                        }

                        # XLSX
                        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\SoftDelete.csv")
                        {
                            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\SoftDelete.csv") -gt 0)
                            {
                                $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\SoftDelete.csv" -Delimiter "," -Encoding UTF8 | Sort-Object { $_.CreationTime -as [datetime] } -Descending
                                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\XLSX\SoftDelete.xlsx" -NoNumberConversion * -NoHyperLinkConversion * -FreezePane 2,7 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "SoftDelete" -CellStyleSB {
                                param($WorkSheet)
                                # BackgroundColor and FontColor for specific cells of TopRow
                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                Set-Format -Address $WorkSheet.Cells["A1:AJ1"] -BackgroundColor $BackgroundColor -FontColor White
                                # HorizontalAlignment "Center" of columns A-AH
                                $WorkSheet.Cells["A:AH"].Style.HorizontalAlignment="Center"
                                # ConditionalFormatting
                                Add-ConditionalFormatting -Address $WorkSheet.Cells["D:E"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("SoftDelete",$E1)))' -BackgroundColor Red
                                }
                            }
                        }

                        # OperationCount
                        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\SoftDelete.csv")
                        {
                            $Import = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\SoftDelete.csv" -Delimiter "," -Encoding UTF8 | Select-Object -ExpandProperty OperationCount | Measure-Object -Sum
                            $Total = ($Import).Sum
                            $Count = ($Import).Count
                            $TotalItems = '{0:N0}' -f $Total
                            Write-Host "[Info]  $TotalItems messages were deleted from Deleted Items folder: SoftDelete ($Count)"
                        }

                        # Line Charts
                        New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\XLSX\LineCharts" -ItemType Directory -Force | Out-Null

                        # Deleted messages from Deleted Items folder per day (SoftDelete --> AggregatedItems)
                        $AuditData = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Select-Object -ExpandProperty AuditData | ConvertFrom-Json
                        $Import = $AuditData | Where-Object { $_.Operation -eq "SoftDelete" } | Select-Object @{Name="CreationTime";Expression={($_.CreationTime | ForEach-Object{($_ -split "T")[0]})}} | Group-Object{($_.CreationTime)} | Select-Object @{Name='CreationTime'; Expression={ $_.Values[0] }},Count | Sort-Object { $_.CreationTime -as [datetime] }
                        $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
                        if ($Count -gt 0)
                        {
                            $ChartDefinition = New-ExcelChartDefinition -XRange CreationTime -YRange Count -Title "SoftDelete (AggregatedItems)" -ChartType Line -NoLegend -Width 1200
                            $Import | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\XLSX\LineCharts\SoftDelete-AggregatedItems.xlsx" -Append -WorksheetName "Line Chart" -AutoNameRange -ExcelChartDefinition $ChartDefinition
                        }

                        # Deleted messages from Deleted Items folder per day (SoftDelete --> OperationCount)
                        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\SoftDelete.csv")
                        {
                            $Import = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\SoftDelete.csv" -Delimiter "," | Select-Object CreationTime,OperationCount | Group-Object CreationTime | Select-Object @{Name="CreationTime";Expression={$_.Name}}, @{Name="OperationCount";Expression={($_.Group | Measure-Object OperationCount -Sum).Sum}} | Sort-Object { $_.CreationTime -as [datetime] }
                            $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
                            if ($Count -gt 0)
                            {
                                $ChartDefinition = New-ExcelChartDefinition -XRange CreationTime -YRange OperationCount -Title "SoftDelete" -ChartType Line -NoLegend -Width 1200
                                $Import | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\XLSX\LineCharts\SoftDelete-OperationCount.xlsx" -Append -WorksheetName "Line Chart" -AutoNameRange -ExcelChartDefinition $ChartDefinition
                            }
                        }

                        }

                        Get-SoftDelete

                        # Function Get-HardDelete
                        Function Get-HardDelete {

                        # HardDelete - Purged items from the mailbox (messages and calendar items)
                        # Description: An item was purged from the 'Recoverable Items' folder (permanently deleted from the mailbox).
                        $Records = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object { $_.RecordType -eq "ExchangeItemGroup" } | Where-Object { $_.Operations -eq "HardDelete" } | Sort-Object { $_.CreationTime -as [datetime] } -Descending
                        $Count = ($Records | Select-Object CreationTime).Count
                        $HardDelete = '{0:N0}' -f $Count

                        if ($Count -gt 0)
                        {
                            Write-Host "[Info]  $HardDelete items were purged from the mailbox: HardDelete"
                            New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV" -ItemType Directory -Force | Out-Null
                            New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\XLSX" -ItemType Directory -Force | Out-Null

                            # CSV
                            $Results = [Collections.Generic.List[PSObject]]::new()
                            ForEach($Record in $Records)
                            {
                                $AuditData       = $Record.AuditData | ConvertFrom-Json
                                $AffectedItems   = $AuditData.AffectedItems
                                $ClientRequestId = $AuditData | Select-Object -ExpandProperty ClientRequestId -ErrorAction SilentlyContinue | ForEach-Object {$_ -replace '{'} | ForEach-Object {$_ -replace '}'}
                                $Folder          = $AuditData.Folder

                                # UserType (Value --> Member Name)
                                [int]$UserTypeValue = $AuditData.UserType

                                # Check if HashTable contains Value
                                if($UserType_HashTable.ContainsKey("$UserTypeValue"))
                                {
                                    $UserType = $UserType_HashTable["$UserTypeValue"][0]
                                }
                                        
                                $Line = [PSCustomObject]@{
                                "CreationTime"          = $AuditData | Select-Object -ExpandProperty CreationTime | ForEach-Object {$_ -replace 'T',' '}
                                "Id"                    = $AuditData.Id
                                "Workload"              = $AuditData.Workload
                                "RecordType"            = $Record.RecordType
                                "Operation"             = $AuditData.Operation
                                "ResultStatus"          = $AuditData.ResultStatus # Succeeded, PartiallySucceeded, Failed
                                "UserId"                = $AuditData.UserId
                                "UserKey"               = $AuditData.UserKey
                                "UserType"              = $UserType
                                "ClientIP"              = $AuditData.ClientIP
                                "ClientIPAddress"       = $AuditData.ClientIPAddress
                                "AppId"                 = $AuditData.AppId
                                "ClientInfoString"      = $AuditData.ClientInfoString
                                "ClientRequestId"       = $ClientRequestId
                                "ExternalAccess"        = $AuditData.ExternalAccess
                                "InternalLogonType"     = $AuditData.InternalLogonType
                                "LogonType"             = $AuditData.LogonType # Owner, Delegate, Admin
                                "LogonUserSid"          = $AuditData.LogonUserSid
                                "MailboxOwnerMasterAccountSid" = $AuditData.MailboxOwnerMasterAccountSid
                                "MailboxGuid"           = $AuditData.MailboxGuid
                                "MailboxOwnerSid"       = $AuditData.MailboxOwnerSid
                                "MailboxOwnerUPN"       = $AuditData.MailboxOwnerUPN
                                "OrganizationId"        = $AuditData.OrganizationId
                                "OrganizationName"      = $AuditData.OrganizationName
                                "OriginatingServer"     = $AuditData.OriginatingServer
                                "SessionId"             = $AuditData.SessionId
                                "AffectedItemsId"       = ($AffectedItems.Id) -join "`r`n"
                                "InternetMessageId"     = ($AffectedItems.InternetMessageId) -join "`r`n"
                                "ParentFolder"          = ($AffectedItems.ParentFolder) -join "`r`n"
                                "CrossMailboxOperation" = $AuditData.CrossMailboxOperation
                                "FolderId"              = $Folder.Id
                                "FolderPath"            = $Folder.Path
                                "Subject"               = ($AffectedItems.Subject) -join "`r`n"
                                "Attachments"           = ($AffectedItems.Attachments) -join "`r`n"
                                }

                                $Results.Add($Line)
                            }

                            $Results | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\HardDelete.csv" -NoTypeInformation -Encoding UTF8
                        }

                        # XLSX
                        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\HardDelete.csv")
                        {
                            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\HardDelete.csv") -gt 0)
                            {
                                $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\HardDelete.csv" -Delimiter "," -Encoding UTF8 | Sort-Object { $_.CreationTime -as [datetime] } -Descending
                                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\XLSX\HardDelete.xlsx" -NoHyperLinkConversion * -NoNumberConversion * -FreezePane 2,6 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "HardDelete" -CellStyleSB {
                                param($WorkSheet)
                                # BackgroundColor and FontColor for specific cells of TopRow
                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                Set-Format -Address $WorkSheet.Cells["A1:AH1"] -BackgroundColor $BackgroundColor -FontColor White
                                # HorizontalAlignment "Center" of columns A-AG
                                $WorkSheet.Cells["A:AG"].Style.HorizontalAlignment="Center"
                                # ConditionalFormatting
                                Add-ConditionalFormatting -Address $WorkSheet.Cells["D:E"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("HardDelete",$E1)))' -BackgroundColor Red
                                }
                            }
                        }

                        # Line Charts
                        New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\XLSX\LineCharts" -ItemType Directory -Force | Out-Null

                        # Purged items from the mailbox (messages and calendar items) per day (HardDelete)
                        $AuditData = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Select-Object -ExpandProperty AuditData | ConvertFrom-Json
                        $Import = $AuditData | Where-Object { $_.Operation -eq "HardDelete" } | Select-Object @{Name="CreationTime";Expression={($_.CreationTime | ForEach-Object{($_ -split "T")[0]})}} | Group-Object{($_.CreationTime)} | Select-Object @{Name='CreationTime'; Expression={ $_.Values[0] }},Count | Sort-Object { $_.CreationTime -as [datetime] }
                        
                        $Count = ($Import | Measure-Object).Count
                        if ($Count -gt 0)
                        {
                            $ChartDefinition = New-ExcelChartDefinition -XRange CreationTime -YRange Count -Title "HardDelete" -ChartType Line -NoLegend -Width 1200
                            $Import | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\XLSX\LineCharts\HardDelete.xlsx" -Append -WorksheetName "Line Chart" -AutoNameRange -ExcelChartDefinition $ChartDefinition
                        }

                        }

                        Get-HardDelete

                        # Function Get-Send
                        Function Get-Send {

                        # Send - Sent message
                        # Description: A message was sent, replied to or forwarded.
                        $Records = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object { $_.RecordType -eq "ExchangeItem" } | Where-Object { $_.Operations -eq "Send" } | Sort-Object { $_.CreationTime -as [datetime] } -Descending
                        $Count = ($Records | Select-Object CreationTime).Count
                        $Send = '{0:N0}' -f $Count

                        if ($Count -gt 0)
                        {
                            Write-Host "[Info]  $Send messages were sent, replied to or forwarded: Send"
                            New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV" -ItemType Directory -Force | Out-Null
                            New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\XLSX" -ItemType Directory -Force | Out-Null

                            # CSV
                            $Results = [Collections.Generic.List[PSObject]]::new()
                            ForEach($Record in $Records)
                            {
                                $AuditData    = $Record.AuditData | ConvertFrom-Json
                                $Item         = $AuditData.Item
                                $ParentFolder = $Item.ParentFolder

                                # UserType (Value --> Member Name)
                                [int]$UserTypeValue = $AuditData.UserType

                                # Check if HashTable contains Value
                                if($UserType_HashTable.ContainsKey("$UserTypeValue"))
                                {
                                    $UserType = $UserType_HashTable["$UserTypeValue"][0]
                                }

                                # LogonType (Value --> Type)
                                [int]$LogonTypeValue = $AuditData.LogonType

                                # Check if HashTable contains Value
                                if($LogonType_HashTable.ContainsKey("$LogonTypeValue"))
                                {
                                    $LogonType = $LogonType_HashTable["$LogonTypeValue"]
                                }
                                        
                                $Line = [PSCustomObject]@{
                                "CreationTime"          = $AuditData | Select-Object -ExpandProperty CreationTime | ForEach-Object {$_ -replace 'T',' '}
                                "Id"                    = $AuditData.Id
                                "Workload"              = $AuditData.Workload
                                "RecordType"            = $Record.RecordType
                                "Operation"             = $AuditData.Operation
                                "ResultStatus"          = $AuditData.ResultStatus # Succeeded, PartiallySucceeded, Failed
                                "UserId"                = $AuditData.UserId
                                "UserKey"               = $AuditData.UserKey
                                "UserType"              = $UserType
                                "ClientIP"              = $AuditData.ClientIP
                                "ClientIPAddress"       = $AuditData.ClientIPAddress
                                "AppId"                 = $AuditData.AppId
                                "ClientInfoString"      = $AuditData.ClientInfoString
                                "ClientRequestId"       = $AuditData.ClientRequestId
                                "ExternalAccess"        = $AuditData.ExternalAccess
                                "InternalLogonType"     = $AuditData.InternalLogonType
                                "LogonType"             = $LogonType
                                "LogonUserSid"          = $AuditData.LogonUserSid
                                "MailboxGuid"           = $AuditData.MailboxGuid
                                "MailboxOwnerSid"       = $AuditData.MailboxOwnerSid
                                "MailboxOwnerUPN"       = $AuditData.MailboxOwnerUPN
                                "OrganizationId"        = $AuditData.OrganizationId
                                "OrganizationName"      = $AuditData.OrganizationName
                                "OriginatingServer"     = $AuditData.OriginatingServer
                                "SessionId"             = $AuditData.SessionId
                                "Attachments"           = ($Item.Attachments) -join "`r`n"
                                "MessageId"             = $Item.Id
                                "InternetMessageId"     = $Item.InternetMessageId
                                "Path"                  = $ParentFolder.Path
                                "SizeInBytes"           = $Item.SizeInBytes
                                "Subject"               = $Item.Subject
                                "SaveToSentItems"       = $AuditData.SaveToSentItems

                                }

                                $Results.Add($Line)
                            }

                            $Results | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\Send.csv" -NoTypeInformation -Encoding UTF8
                        }

                        # XLSX
                        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\Send.csv")
                        {
                            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\Send.csv") -gt 0)
                            {
                                $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\Send.csv" -Delimiter "," -Encoding UTF8 | Sort-Object { $_.CreationTime -as [datetime] } -Descending
                                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\XLSX\Send.xlsx" -NoHyperLinkConversion * -NoNumberConversion * -FreezePane 2,6 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Send" -CellStyleSB {
                                param($WorkSheet)
                                # BackgroundColor and FontColor for specific cells of TopRow
                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                Set-Format -Address $WorkSheet.Cells["A1:AF1"] -BackgroundColor $BackgroundColor -FontColor White
                                # HorizontalAlignment "Center" of columns A-AF
                                $WorkSheet.Cells["A:AF"].Style.HorizontalAlignment="Center"
                                # ConditionalFormatting
                                Add-ConditionalFormatting -Address $WorkSheet.Cells["D:E"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Send",$E1)))' -BackgroundColor Red
                                }
                            }
                        }

                        }

                        Get-Send

                        # Function Get-SendAs
                        Function Get-SendAs {

                        # SendAs - Sent message using Send As permissions
                        # Description: A message was sent using the SendAs permission. This means that another user sent the message as though it came from the mailbox owner.
                        $Records = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object { $_.RecordType -eq "ExchangeItem" } | Where-Object { $_.Operations -eq "SendAs" } | Sort-Object { $_.CreationTime -as [datetime] } -Descending
                        $Count = ($Records | Select-Object CreationTime).Count
                        $SendAs = '{0:N0}' -f $Count

                        if ($Count -gt 0)
                        {
                            Write-Host "[Info]  $SendAs messages were sent using SendAs permisisons: SendAs"
                            New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV" -ItemType Directory -Force | Out-Null
                            New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\XLSX" -ItemType Directory -Force | Out-Null

                            # CSV
                            $Results = [Collections.Generic.List[PSObject]]::new()
                            ForEach($Record in $Records)
                            {
                                $AuditData    = $Record.AuditData | ConvertFrom-Json
                                $Item         = $AuditData.Item
                                $ParentFolder = $Item.ParentFolder

                                # UserType (Value --> Member Name)
                                [int]$UserTypeValue = $AuditData.UserType

                                # Check if HashTable contains Value
                                if($UserType_HashTable.ContainsKey("$UserTypeValue"))
                                {
                                    $UserType = $UserType_HashTable["$UserTypeValue"][0]
                                }

                                # LogonType (Value --> Type)
                                [int]$LogonTypeValue = $AuditData.LogonType

                                # Check if HashTable contains Value
                                if($LogonType_HashTable.ContainsKey("$LogonTypeValue"))
                                {
                                    $LogonType = $LogonType_HashTable["$LogonTypeValue"]
                                }
                                        
                                $Line = [PSCustomObject]@{
                                "CreationTime"          = $AuditData | Select-Object -ExpandProperty CreationTime | ForEach-Object {$_ -replace 'T',' '}
                                "Id"                    = $AuditData.Id
                                "Workload"              = $AuditData.Workload
                                "RecordType"            = $Record.RecordType
                                "Operation"             = $AuditData.Operation
                                "ResultStatus"          = $AuditData.ResultStatus # Succeeded, PartiallySucceeded, Failed
                                "UserId"                = $AuditData.UserId
                                "UserKey"               = $AuditData.UserKey
                                "UserType"              = $UserType
                                "ClientIP"              = $AuditData.ClientIP
                                "ClientIPAddress"       = $AuditData.ClientIPAddress
                                "AppId"                 = $AuditData.AppId
                                "ClientAppId"           = $AuditData.ClientAppId
                                "ClientInfoString"      = $AuditData.ClientInfoString
                                "ExternalAccess"        = $AuditData.ExternalAccess
                                "InternalLogonType"     = $AuditData.InternalLogonType
                                "LogonType"             = $LogonType
                                "LogonUserSid"          = $AuditData.LogonUserSid
                                "MailboxGuid"           = $AuditData.MailboxGuid
                                "MailboxOwnerSid"       = $AuditData.MailboxOwnerSid
                                "MailboxOwnerUPN"       = $AuditData.MailboxOwnerUPN
                                "OrganizationId"        = $AuditData.OrganizationId
                                "OrganizationName"      = $AuditData.OrganizationName
                                "OriginatingServer"     = $AuditData.OriginatingServer
                                "SessionId"             = $AuditData.SessionId
                                "Attachments"           = ($Item.Attachments) -join "`r`n"
                                "MessageId"             = $Item.Id
                                "InternetMessageId"     = $Item.InternetMessageId
                                "Path"                  = $ParentFolder.Path
                                "SizeInBytes"           = $Item.SizeInBytes
                                "Subject"               = $Item.Subject
                                "SaveToSentItems"       = $AuditData.SaveToSentItems
                                "SendAsUserMailboxGuid" = $AuditData.SendAsUserMailboxGuid
                                "SendAsUserSmtp"        = $AuditData.SendAsUserSmtp
                                }

                                $Results.Add($Line)
                            }

                            $Results | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\SendAs.csv" -NoTypeInformation -Encoding UTF8
                        }

                        # XLSX
                        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\SendAs.csv")
                        {
                            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\SendAs.csv") -gt 0)
                            {
                                $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\SendAs.csv" -Delimiter "," -Encoding UTF8 | Sort-Object { $_.CreationTime -as [datetime] } -Descending
                                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\XLSX\SendAs.xlsx" -NoHyperLinkConversion * -NoNumberConversion * -FreezePane 2,6 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "SendAs" -CellStyleSB {
                                param($WorkSheet)
                                # BackgroundColor and FontColor for specific cells of TopRow
                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                Set-Format -Address $WorkSheet.Cells["A1:AH1"] -BackgroundColor $BackgroundColor -FontColor White
                                # HorizontalAlignment "Center" of columns A-Y, AA-AD and AF-AH
                                $WorkSheet.Cells["A:Y"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["AA:AD"].Style.HorizontalAlignment="Center"
                                $WorkSheet.Cells["AF:AH"].Style.HorizontalAlignment="Center"
                                # ConditionalFormatting
                                Add-ConditionalFormatting -Address $WorkSheet.Cells["D:E"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("SendAs",$E1)))' -BackgroundColor Red
                                }
                            }
                        }

                        }

                        Get-SendAs

                        # Function Get-SendOnBehalf
                        Function Get-SendOnBehalf {

                        # SendOnBehalf - Sent message using Send On Behalf permissions
                        # Description: A message was sent using the SendOnBehalf permission. This means that another user sent the message on behalf of the mailbox owner. The message indicates to the recipient whom the message was sent on behalf of and who actually sent the message.
                        $Records = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object { $_.RecordType -eq "ExchangeItem" } | Where-Object { $_.Operations -eq "SendOnBehalf" } | Sort-Object { $_.CreationTime -as [datetime] } -Descending
                        $Count = ($Records | Select-Object CreationTime).Count
                        $SendOnBehalf = '{0:N0}' -f $Count

                        if ($Count -gt 0)
                        {
                            Write-Host "[Info]  $SendOnBehalf messages were sent using SendOnBehalf permisisons: SendOnBehalf"
                            New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV" -ItemType Directory -Force | Out-Null
                            New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\XLSX" -ItemType Directory -Force | Out-Null

                            # CSV
                            $Results = [Collections.Generic.List[PSObject]]::new()
                            ForEach($Record in $Records)
                            {
                                $AuditData    = $Record.AuditData | ConvertFrom-Json
                                $Item         = $AuditData.Item
                                $ParentFolder = $Item.ParentFolder

                                # UserType (Value --> Member Name)
                                [int]$UserTypeValue = $AuditData.UserType

                                # Check if HashTable contains Value
                                if($UserType_HashTable.ContainsKey("$UserTypeValue"))
                                {
                                    $UserType = $UserType_HashTable["$UserTypeValue"][0]
                                }

                                # LogonType (Value --> Type)
                                [int]$LogonTypeValue = $AuditData.LogonType

                                # Check if HashTable contains Value
                                if($LogonType_HashTable.ContainsKey("$LogonTypeValue"))
                                {
                                    $LogonType = $LogonType_HashTable["$LogonTypeValue"]
                                }

                                $Line = [PSCustomObject]@{
                                "CreationTime"          = $AuditData | Select-Object -ExpandProperty CreationTime | ForEach-Object {$_ -replace 'T',' '}
                                "Id"                            = $AuditData.Id
                                "Workload"                      = $AuditData.Workload
                                "RecordType"                    = $Record.RecordType
                                "Operation"                     = $AuditData.Operation
                                "ResultStatus"                  = $AuditData.ResultStatus # Succeeded, PartiallySucceeded, Failed
                                "UserId"                        = $AuditData.UserId
                                "UserKey"                       = $AuditData.UserKey
                                "UserType"                      = $UserType
                                "Version"                       = $AuditData.Version
                                "ClientIP"                      = $AuditData.ClientIP
                                "ClientIPAddress"               = $AuditData.ClientIPAddress
                                "AppId"                         = $AuditData.AppId
                                "ClientAppId"                   = $AuditData.ClientAppId
                                "ClientInfoString"              = $AuditData.ClientInfoString
                                "ClientRequestId"               = $AuditData.ClientRequestId
                                "ExternalAccess"                = $AuditData.ExternalAccess
                                "InternalLogonType"             = $AuditData.InternalLogonType
                                "LogonType"                     = $LogonType
                                "LogonUserSid"                  = $AuditData.LogonUserSid
                                "MailboxGuid"                   = $AuditData.MailboxGuid
                                "MailboxOwnerSid"               = $AuditData.MailboxOwnerSid
                                "MailboxOwnerUPN"               = $AuditData.MailboxOwnerUPN
                                "OrganizationId"                = $AuditData.OrganizationId
                                "OrganizationName"              = $AuditData.OrganizationName
                                "OriginatingServer"             = $AuditData.OriginatingServer
                                "SessionId"                     = $AuditData.SessionId
                                "MessageId"                     = $Item.Id
                                "InternetMessageId"             = $Item.InternetMessageId
                                "Path"                          = $ParentFolder.Path
                                "SizeInBytes"                   = $Item.SizeInBytes
                                "Subject"                       = $Item.Subject
                                "SaveToSentItems"               = $AuditData.SaveToSentItems
                                "SendOnBehalfOfUserMailboxGuid" = $AuditData.SendOnBehalfOfUserMailboxGuid
                                "SendOnBehalfOfUserSmtp"        = $AuditData.SendOnBehalfOfUserSmtp
                                }

                                $Results.Add($Line)
                            }

                            $Results | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\SendOnBehalf.csv" -NoTypeInformation -Encoding UTF8
                        }

                        # XLSX
                        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\SendOnBehalf.csv")
                        {
                            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\SendOnBehalf.csv") -gt 0)
                            {
                                $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\SendOnBehalf.csv" -Delimiter "," -Encoding UTF8 | Sort-Object { $_.CreationTime -as [datetime] } -Descending
                                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\XLSX\SendOnBehalf.xlsx" -NoHyperLinkConversion * -NoNumberConversion * -FreezePane 2,6 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "SendOnBehalf" -CellStyleSB {
                                param($WorkSheet)
                                # BackgroundColor and FontColor for specific cells of TopRow
                                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                Set-Format -Address $WorkSheet.Cells["A1:AI1"] -BackgroundColor $BackgroundColor -FontColor White
                                # HorizontalAlignment "Center" of columns A-AI
                                $WorkSheet.Cells["A:AI"].Style.HorizontalAlignment="Center"
                                # ConditionalFormatting
                                Add-ConditionalFormatting -Address $WorkSheet.Cells["D:E"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("SendOnBehalf",$E1)))' -BackgroundColor Red
                                }
                            }
                        }

                        }

                        Get-SendOnBehalf

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
                                $Count = ($Import | Group-Object{($_.CreationTime -split "\s+")[0]} | Where-Object Count -ge 50 | Measure-Object).Count

                                if ($Count -ge 1)
                                {
                                    Write-Host "[Alert] Suspicious Mailbox Action(s) detected: 50+ email messages were deleted and moved to the 'Deleted Items' folder on a single day ($Count)" -ForegroundColor Red
                                    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV" -ItemType Directory -Force | Out-Null
                                    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\XLSX" -ItemType Directory -Force | Out-Null

                                    # CSV
                                    $Import | Group-Object{($_.CreationTime -split "\s+")[0]} | Where-Object Count -ge 50 | Select-Object Name,Count | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItemGroup-MoveToDeletedItems-Overview.csv" -NoTypeInformation -Encoding UTF8
                                    $Import | Group-Object{($_.CreationTime -split "\s+")[0]} | Where-Object Count -ge 50 | Select-Object -Expand Group | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItemGroup-MoveToDeletedItems.csv" -NoTypeInformation -Encoding UTF8

                                    # ExchangeItemGroup-MoveToDeletedItems-Overview.xlsx
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

                                    # ExchangeItemGroup-MoveToDeletedItems.xlsx
                                    if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItemGroup-MoveToDeletedItems.csv")
                                    {
                                        if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItemGroup-MoveToDeletedItems.csv") -gt 0)
                                        {
                                            $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItemGroup-MoveToDeletedItems.csv" -Delimiter "," | Select-Object CreationTime,UserId,RecordType,Operation,ObjectId,ClientIP,UserAgent,City,Region,Country,"Country Name",ASN,OrgName,Timezone,Workload
                                            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\XLSX\ExchangeItemGroup-MoveToDeletedItems.xlsx" -NoNumberConversion * -NoHyperLinkConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "MoveToDeletedItems" -CellStyleSB {
                                            param($WorkSheet)
                                            # BackgroundColor and FontColor for specific cells of TopRow
                                            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                            Set-Format -Address $WorkSheet.Cells["A1:O1"] -BackgroundColor $BackgroundColor -FontColor White
                                            # HorizontalAlignment "Center" of columns A-O
                                            $WorkSheet.Cells["A:O"].Style.HorizontalAlignment="Center"
                                            # ConditionalFormatting
                                            Add-ConditionalFormatting -Address $WorkSheet.Cells["C:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("ExchangeItemGroup",$C1)))' -BackgroundColor Red
                                            Add-ConditionalFormatting -Address $WorkSheet.Cells["D:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("MoveToDeletedItems",$D1)))' -BackgroundColor Red
                                            }
                                        }
                                    }
                                }

                                # Suspicious Mailbox Action(s) detected: Multiple email messages were deleted from the 'Deleted Items' folder
                                # RecordType: ExchangeItemGroup --> Events from an Exchange mailbox audit log for actions that can be performed on multiple items, such as moving or deleted one or more email messages.
                                # Operation: SoftDelete --> A message was permanently deleted or deleted from the Deleted Items folder. Soft-deleted items are moved to the Recoverable Items folder.
                                $Import = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," -Encoding UTF8 | Where-Object { $_.RecordType -eq "ExchangeItemGroup" } | Where-Object { $_.OrgName -ne "Zscaler Switzerland GmbH" } | Where-Object { $_.Operation -eq "SoftDelete" }
                                $Count = ($Import | Group-Object{($_.CreationTime -split "\s+")[0]} | Where-Object Count -ge 50 | Measure-Object).Count
                                
                                if ($Count -ge 1)
                                {
                                    Write-Host "[Alert] Suspicious Mailbox Action(s) detected: 50+ email messages were permanently deleted from the 'Deleted Items' folder on a single day ($Count)" -ForegroundColor Red
                                    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV" -ItemType Directory -Force | Out-Null
                                    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\XLSX" -ItemType Directory -Force | Out-Null

                                    # CSV
                                    $Import | Group-Object{($_.CreationTime -split "\s+")[0]} | Where-Object Count -ge 50 | Select-Object Name,Count | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItemGroup-SoftDelete-Overview.csv" -NoTypeInformation -Encoding UTF8
                                    $Import | Group-Object{($_.CreationTime -split "\s+")[0]} | Where-Object Count -ge 50 | Select-Object -Expand Group | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItemGroup-SoftDelete.csv" -NoTypeInformation -Encoding UTF8

                                    # ExchangeItemGroup-SoftDelete-Overview.xlsx
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

                                    # ExchangeItemGroup-SoftDelete.xlsx
                                    if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItemGroup-SoftDelete.csv")
                                    {
                                        if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItemGroup-SoftDelete.csv") -gt 0)
                                        {
                                            $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItemGroup-SoftDelete.csv" -Delimiter "," | Select-Object CreationTime,UserId,RecordType,Operation,ObjectId,ClientIP,UserAgent,City,Region,Country,"Country Name",ASN,OrgName,Timezone,Workload
                                            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\XLSX\ExchangeItemGroup-SoftDelete.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "SoftDelete" -CellStyleSB {
                                            param($WorkSheet)
                                            # BackgroundColor and FontColor for specific cells of TopRow
                                            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                            Set-Format -Address $WorkSheet.Cells["A1:O1"] -BackgroundColor $BackgroundColor -FontColor White
                                            # HorizontalAlignment "Center" of columns A-O
                                            $WorkSheet.Cells["A:O"].Style.HorizontalAlignment="Center"
                                            # ConditionalFormatting
                                            Add-ConditionalFormatting -Address $WorkSheet.Cells["C:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("ExchangeItemGroup",$C1)))' -BackgroundColor Red
                                            Add-ConditionalFormatting -Address $WorkSheet.Cells["D:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("SoftDelete",$D1)))' -BackgroundColor Red
                                            }
                                        }
                                    }
                                }

                                # Suspicious Mailbox Action(s) detected: Multiple email messages were purged from the 'Recoverable Items' folder
                                # RecordType: ExchangeItemGroup --> Events from an Exchange mailbox audit log for actions that can be performed on multiple items, such as moving or deleted one or more email messages.
                                # Operation: HardDelete --> A message was purged from the Recoverable Items folder.
                                $Import = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," -Encoding UTF8 | Where-Object { $_.RecordType -eq "ExchangeItemGroup" } | Where-Object { $_.OrgName -ne "Zscaler Switzerland GmbH" } | Where-Object { $_.Operation -eq "HardDelete" }
                                $Count = ($Import | Group-Object{($_.CreationTime -split "\s+")[0]} | Where-Object Count -ge 50 | Measure-Object).Count

                                if ($Count -ge 1)
                                {
                                    Write-Host "[Alert] Suspicious Mailbox Action(s) detected: 50+ email messages were purged from the 'Recoverable Items' folder on a single day ($Count)" -ForegroundColor Red
                                    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV" -ItemType Directory -Force | Out-Null
                                    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\XLSX" -ItemType Directory -Force | Out-Null

                                    # CSV
                                    $Import | Group-Object{($_.CreationTime -split "\s+")[0]} | Where-Object Count -ge 50 | Select-Object Name,Count | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItemGroup-HardDelete-Overview.csv" -NoTypeInformation -Encoding UTF8
                                    $Import | Group-Object{($_.CreationTime -split "\s+")[0]} | Where-Object Count -ge 50 | Select-Object -Expand Group | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItemGroup-HardDelete.csv" -NoTypeInformation -Encoding UTF8

                                    # ExchangeItemGroup-HardDelete-Overview.xlsx
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

                                    # ExchangeItemGroup-HardDelete.xlsx
                                    if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItemGroup-HardDelete.csv")
                                    {
                                        if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItemGroup-HardDelete.csv") -gt 0)
                                        {
                                            $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItemGroup-HardDelete.csv" -Delimiter "," | Select-Object CreationTime,UserId,RecordType,Operation,ObjectId,ClientIP,UserAgent,City,Region,Country,"Country Name",ASN,OrgName,Timezone,Workload
                                            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\XLSX\ExchangeItemGroup-HardDelete.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "HardDelete" -CellStyleSB {
                                            param($WorkSheet)
                                            # BackgroundColor and FontColor for specific cells of TopRow
                                            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                            Set-Format -Address $WorkSheet.Cells["A1:O1"] -BackgroundColor $BackgroundColor -FontColor White
                                            # HorizontalAlignment "Center" of columns A-O
                                            $WorkSheet.Cells["A:O"].Style.HorizontalAlignment="Center"
                                            # ConditionalFormatting
                                            Add-ConditionalFormatting -Address $WorkSheet.Cells["C:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("ExchangeItemGroup",$C1)))' -BackgroundColor Red
                                            Add-ConditionalFormatting -Address $WorkSheet.Cells["D:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("HardDelete",$D1)))' -BackgroundColor Red
                                            
                                            # Iterating over the ASN-Blacklist HashTable
                                            foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
                                            {
                                                $ConditionValue = 'NOT(ISERROR(FIND("{0}",$L1)))' -f $ASN
                                                Add-ConditionalFormatting -Address $WorkSheet.Cells["L:L"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
                                            }

                                            }
                                        }
                                    }

                                    # Suspicious Mailbox Action(s) detected: Single email messages were purged from the 'Recoverable Items' folder
                                    # RecordType: ExchangeItem --> Events from an Exchange mailbox audit log for actions that are performed on a single item, such as creating or receiving an email message.
                                    # Operation: HardDelete --> A message was purged from the Recoverable Items folder.
                                    $Import = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," -Encoding UTF8 | Where-Object { $_.RecordType -eq "ExchangeItem" } | Where-Object { $_.OrgName -ne "Zscaler Switzerland GmbH" } | Where-Object { $_.Operation -eq "HardDelete" }
                                    $Count = ($Import | Group-Object{($_.CreationTime -split "\s+")[0]} | Where-Object Count -ge 50 | Measure-Object).Count

                                    if ($Count -ge 1)
                                    {
                                        Write-Host "[Alert] Suspicious Mailbox Action(s) detected: 50+ single email messages were purged from the 'Recoverable Items' folder on a single day ($Count)" -ForegroundColor Red
                                        New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV" -ItemType Directory -Force | Out-Null
                                        New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\XLSX" -ItemType Directory -Force | Out-Null

                                        # CSV
                                        $Import | Group-Object{($_.CreationTime -split "\s+")[0]} | Where-Object Count -ge 50 | Select-Object Name,Count | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItem-HardDelete-Overview.csv" -NoTypeInformation -Encoding UTF8
                                        $Import | Group-Object{($_.CreationTime -split "\s+")[0]} | Where-Object Count -ge 50 | Select-Object -Expand Group | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItem-HardDelete.csv" -NoTypeInformation -Encoding UTF8

                                        # ExchangeItem-HardDelete-Overview.xlsx
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

                                        # ExchangeItem-HardDelete.xlsx
                                        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItem-HardDelete.csv")
                                        {
                                            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItem-HardDelete.csv") -gt 0)
                                            {
                                                $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItem-HardDelete.csv" -Delimiter "," | Select-Object CreationTime,UserId,RecordType,Operation,ObjectId,ClientIP,UserAgent,City,Region,Country,"Country Name",EU,Location,ASN,OrgName,"Postal Code",Timezone,Workload
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

                                    # Suspicious Mailbox Action(s) detected: Possible outgoing spam from shared mailbox
                                    # RecordType: ExchangeItem --> 	Events from an Exchange mailbox audit log for actions that are performed on a single item, such as creating or receiving an email message.
                                    # Operation: SendAs --> A message was sent using the SendAs permission. This permission allows another user to send the message as though it came from the mailbox owner.
                                    $Import = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," -Encoding UTF8 | Where-Object { $_.RecordType -eq "ExchangeItem" } | Where-Object { $_.OrgName -ne "Zscaler Switzerland GmbH" } | Where-Object { $_.Operation -eq "SendAs" }
                                    $Count = ($Import | Group-Object{($_.CreationTime -split "\s+")[0]} | Where-Object Count -ge 10 | Measure-Object).Count

                                    if ($Count -ge 1)
                                    {
                                        Write-Host "[Alert] Suspicious Mailbox Action(s) detected: 10+ email messages were sent using the 'SendAs' permission on a single day. Possible outgoing spam from shared mailbox. ($Count)" -ForegroundColor Red
                                        New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV" -ItemType Directory -Force | Out-Null
                                        New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\XLSX" -ItemType Directory -Force | Out-Null

                                        # CSV
                                        $Import | Group-Object{($_.CreationTime -split "\s+")[0]} | Where-Object Count -ge 10 | Select-Object Name,Count | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItem-SendAs-Overview.csv" -NoTypeInformation -Encoding UTF8
                                        $Import | Group-Object{($_.CreationTime -split "\s+")[0]} | Where-Object Count -ge 10 | Select-Object -Expand Group | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItem-SendAs.csv" -NoTypeInformation -Encoding UTF8
                                        
                                        # ExchangeItem-SendAs-Overview.xlsx
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

                                        # ExchangeItem-SendAs.xlsx
                                        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItem-SendAs.csv")
                                        {
                                            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItem-SendAs.csv") -gt 0)
                                            {
                                                $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItem-SendAs.csv" -Delimiter "," | Select-Object CreationTime,UserId,RecordType,Operation,ObjectId,ClientIP,UserAgent,City,Region,Country,"Country Name",EU,Location,ASN,OrgName,"Postal Code",Timezone,Workload
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

                                        # Suspicious Mailbox Action(s) detected: Possible outgoing spam
                                        # RecordType: ExchangeItem --> 	Events from an Exchange mailbox audit log for actions that are performed on a single item, such as creating or receiving an email message.
                                        # Operation: Update --> A message or any of its properties was changed.
                                        $Import = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," -Encoding UTF8 | Where-Object { $_.RecordType -eq "ExchangeItem" } | Where-Object { $_.OrgName -ne "Zscaler Switzerland GmbH" } | Where-Object { $_.Operation -eq "Update" }
                                        $Count = ($Import | Group-Object{($_.CreationTime -split "\s+")[0]} | Where-Object Count -ge 20 | Measure-Object).Count

                                        if ($Count -ge 1)
                                        {
                                            Write-Host "[Alert] Suspicious Mailbox Action(s) detected: 20+ email messages or any of its properties were changed on a single day. Possible outgoing spam from shared mailbox. ($Count)" -ForegroundColor Red
                                            New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV" -ItemType Directory -Force | Out-Null
                                            New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\XLSX" -ItemType Directory -Force | Out-Null

                                            # CSV
                                            $Import | Group-Object{($_.CreationTime -split "\s+")[0]} | Where-Object Count -ge 20 | Select-Object Name,Count | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItem-Update-Overview.csv" -NoTypeInformation -Encoding UTF8
                                            $Import | Group-Object{($_.CreationTime -split "\s+")[0]} | Where-Object Count -ge 20 | Select-Object -Expand Group | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItem-Update.csv" -NoTypeInformation -Encoding UTF8
                                            
                                            # ExchangeItem-Update-Overview.xlsx
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

                                            # ExchangeItem-Update.xlsx
                                            if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItem-Update.csv")
                                            {
                                                if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItem-Update.csv") -gt 0)
                                                {
                                                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-Mailbox-Actions\CSV\ExchangeItem-Update.csv" -Delimiter "," | Select-Object CreationTime,UserId,RecordType,Operation,ObjectId,ClientIP,UserAgent,City,Region,Country,"Country Name",EU,Location,ASN,OrgName,"Postal Code",Timezone,Workload
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
                                $Count = ($Import | Group-Object{($_.CreationTime -split "\s+")[0]} | Where-Object Count -ge 10 | Measure-Object).Count

                                if ($Count -ge 1)
                                {
                                    Write-Host "[Alert] Suspicious SharePoint Action(s) detected: A user in your organization tried to share 10+ resources (likely a site) with an external user on a single day. ($Count)" -ForegroundColor Red
                                    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV" -ItemType Directory -Force | Out-Null
                                    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\XLSX" -ItemType Directory -Force | Out-Null

                                    # CSV
                                    $Import | Group-Object{($_.CreationTime -split "\s+")[0]} | Where-Object Count -ge 10 | Select-Object Name,Count | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointSharingOperation-SharingInvitationCreated-Overview.csv" -NoTypeInformation -Encoding UTF8
                                    $Import | Group-Object{($_.CreationTime -split "\s+")[0]} | Where-Object Count -ge 10 | Select-Object -Expand Group | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointSharingOperation-SharingInvitationCreated.csv" -NoTypeInformation -Encoding UTF8
                                            
                                    # SharePointSharingOperation-SharingInvitationCreated-Overview.xlsx
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

                                    # SharePointSharingOperation-SharingInvitationCreated.xlsx
                                    if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointSharingOperation-SharingInvitationCreated.csv")
                                    {
                                        if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointSharingOperation-SharingInvitationCreated.csv") -gt 0)
                                        {
                                            $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointSharingOperation-SharingInvitationCreated.csv" -Delimiter "," | Select-Object CreationTime,UserId,RecordType,Operation,ObjectId,ClientIP,UserAgent,City,Region,Country,"Country Name",EU,Location,ASN,OrgName,"Postal Code",Timezone,Workload
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
                                            
                                            # Iterating over the ASN-Blacklist HashTable
                                            foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
                                            {
                                                $ConditionValue = 'NOT(ISERROR(FIND("{0}",$L1)))' -f $ASN
                                                Add-ConditionalFormatting -Address $WorkSheet.Cells["L:L"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
                                            }
                                            
                                            }
                                        }
                                    }
                                }

                                # Suspicious SharePoint Action(s) detected: 50+ users were added to a specific people link on a single day
                                # RecordType: SharePointSharingOperation --> SharePoint sharing events.
                                # Operation: AddedToSecureLink -->  A user was added to a specific people link. Use the TargetUserOrGroupName field in this event to identify the user added to the corresponding specific people link. This target user may be someone who is external to your organization.
                                $Import = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," -Encoding UTF8 | Where-Object { $_.RecordType -eq "SharePointSharingOperation" } | Where-Object { $_.Operation -eq "AddedToSecureLink" } | Sort-Object { $_.CreationTime -as [datetime] } -Descending
                                $Count = ($Import | Group-Object{($_.CreationTime -split "\s+")[0]} | Where-Object Count -ge 50 | Measure-Object).Count

                                if ($Count -ge 1)
                                {
                                    Write-Host "[Alert] Suspicious SharePoint Action(s) detected: 50+ users were added to a specific people link on a single day. ($Count)" -ForegroundColor Red
                                    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV" -ItemType Directory -Force | Out-Null
                                    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\XLSX" -ItemType Directory -Force | Out-Null

                                    # CSV
                                    $Import | Group-Object{($_.CreationTime -split "\s+")[0]} | Where-Object Count -ge 50 | Select-Object Name,Count | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointSharingOperation-AddedToSecureLink-Overview.csv" -NoTypeInformation -Encoding UTF8
                                    $Import | Group-Object{($_.CreationTime -split "\s+")[0]} | Where-Object Count -ge 50 | Select-Object -Expand Group | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointSharingOperation-AddedToSecureLink.csv" -NoTypeInformation -Encoding UTF8
                                      
                                    # SharePointSharingOperation-AddedToSecureLink-Overview.xlsx
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

                                    # SharePointSharingOperation-AddedToSecureLink.xlsx
                                    if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointSharingOperation-AddedToSecureLink.csv")
                                    {
                                        if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointSharingOperation-AddedToSecureLink.csv") -gt 0)
                                        {
                                            $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointSharingOperation-AddedToSecureLink.csv" -Delimiter "," | Select-Object CreationTime,UserId,RecordType,Operation,ObjectId,ClientIP,UserAgent,City,Region,Country,"Country Name",ASN,OrgName,Timezone,Workload,UniqueTokenId
                                            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\XLSX\SharePointSharingOperation-AddedToSecureLink.xlsx" -NoNumberConversion * -NoHyperLinkConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "AddedToSecureLink" -CellStyleSB {
                                            param($WorkSheet)
                                            # BackgroundColor and FontColor for specific cells of TopRow
                                            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                            Set-Format -Address $WorkSheet.Cells["A1:P1"] -BackgroundColor $BackgroundColor -FontColor White
                                            # HorizontalAlignment "Center" of columns A-P
                                            $WorkSheet.Cells["A:P"].Style.HorizontalAlignment="Center"
                                            # ConditionalFormatting
                                            Add-ConditionalFormatting -Address $WorkSheet.Cells["C:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("SharePointSharingOperation",$C1)))' -BackgroundColor Yellow
                                            Add-ConditionalFormatting -Address $WorkSheet.Cells["D:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("AddedToSecureLink",$D1)))' -BackgroundColor Yellow
                                            
                                            # Iterating over the ASN-Blacklist HashTable
                                            foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
                                            {
                                                $ConditionValue = 'NOT(ISERROR(FIND("{0}",$L1)))' -f $ASN
                                                Add-ConditionalFormatting -Address $WorkSheet.Cells["L:L"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
                                            }

                                            }
                                        }
                                    }
                                }

                                # Suspicious SharePoint Action(s) detected: A user has created a 'specific people link' to share a resource with a specific person. This target user may be someone who is external to your organization.
                                # RecordType: SharePointSharingOperation --> SharePoint sharing events.
                                # Operation: SecureLinkCreated --> A user has created a 'specific people link' to share a resource with a specific person. This target user may be someone who is external to your organization. The person that the resource is shared with is identified in the audit record for the AddedToSecureLink event. The time stamps for these two events are nearly identical.
                                $Import = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," -Encoding UTF8 | Where-Object { $_.RecordType -eq "SharePointSharingOperation" } | Where-Object { $_.Operation -eq "SecureLinkCreated" } | Sort-Object { $_.CreationTime -as [datetime] } -Descending
                                $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

                                if ($Count -gt 0)
                                {
                                    Write-Host "[Alert] Suspicious SharePoint Action(s) detected: A user has created a 'specific people link' to share a resource with a specific person. This target user may be someone who is external to your organization. ($Count)" -ForegroundColor Red
                                    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV" -ItemType Directory -Force | Out-Null
                                    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\XLSX" -ItemType Directory -Force | Out-Null

                                    # CSV
                                    $Import | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointSharingOperation-SecureLinkCreated.csv" -NoTypeInformation -Encoding UTF8

                                    # XLSX
                                    if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointSharingOperation-SecureLinkCreated.csv")
                                    {
                                        if([int](& $xsv count "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointSharingOperation-SecureLinkCreated.csv") -gt 0)
                                        {
                                            $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointSharingOperation-SecureLinkCreated.csv" -Delimiter "," | Select-Object CreationTime,UserId,RecordType,Operation,ObjectId,ClientIP,UserAgent,City,Region,Country,"Country Name",ASN,OrgName,Timezone,Workload,UniqueTokenId
                                            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\XLSX\SharePointSharingOperation-SecureLinkCreated.xlsx" -NoNumberConversion * -NoHyperLinkConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "SecureLinkCreated" -CellStyleSB {
                                            param($WorkSheet)
                                            # BackgroundColor and FontColor for specific cells of TopRow
                                            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                            Set-Format -Address $WorkSheet.Cells["A1:P1"] -BackgroundColor $BackgroundColor -FontColor White
                                            # HorizontalAlignment "Center" of columns A-D and F-P
                                            $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"
                                            $WorkSheet.Cells["F:P"].Style.HorizontalAlignment="Center"
                                            # ConditionalFormatting
                                            Add-ConditionalFormatting -Address $WorkSheet.Cells["C:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("SharePointSharingOperation",$C1)))' -BackgroundColor Red
                                            Add-ConditionalFormatting -Address $WorkSheet.Cells["D:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("SecureLinkCreated",$D1)))' -BackgroundColor Red
                                            
                                            # Iterating over the ASN-Blacklist HashTable
                                            foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
                                            {
                                                $ConditionValue = 'NOT(ISERROR(FIND("{0}",$L1)))' -f $ASN
                                                Add-ConditionalFormatting -Address $WorkSheet.Cells["L:L"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
                                            }

                                            }
                                        }
                                    }
                                }

                                # Suspicious SharePoint Action(s) detected: A user has 5+ updated a 'specific people link' to share a resource with a specific person. This target user may be someone who is external to your organization.
                                # RecordType: SharePointSharingOperation --> SharePoint sharing events.
                                # Operation: SecureLinkUpdated --> For a SharePoint Item.
                                $Import = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," -Encoding UTF8 | Where-Object { $_.RecordType -eq "SharePointSharingOperation" } | Where-Object { $_.Operation -eq "SecureLinkUpdated" } | Sort-Object { $_.CreationTime -as [datetime] } -Descending
                                $Count = ($Import | Group-Object{($_.CreationTime -split "\s+")[0]} | Where-Object Count -ge 5 | Measure-Object).Count

                                if ($Count -ge 1)
                                {
                                    Write-Host "[Alert] Suspicious SharePoint Action(s) detected: A user has 5+ updated a 'specific people link' to share a resource with a specific person. This target user may be someone who is external to your organization. ($Count)" -ForegroundColor Red
                                    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV" -ItemType Directory -Force | Out-Null
                                    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\XLSX" -ItemType Directory -Force | Out-Null

                                    # CSV
                                    $Import | Group-Object{($_.CreationTime -split "\s+")[0]} | Where-Object Count -ge 5 | Select-Object Name,Count | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointSharingOperation-SecureLinkUpdated-Overview.csv" -NoTypeInformation -Encoding UTF8
                                    $Import | Group-Object{($_.CreationTime -split "\s+")[0]} | Where-Object Count -ge 5 | Select-Object -Expand Group | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointSharingOperation-SecureLinkUpdated.csv" -NoTypeInformation -Encoding UTF8
                                    
                                    # SharePointSharingOperation-SecureLinkUpdated-Overview.xlsx
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

                                    # SharePointSharingOperation-SecureLinkUpdated.xlsx
                                    if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointSharingOperation-SecureLinkUpdated.csv")
                                    {
                                        if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointSharingOperation-SecureLinkUpdated.csv") -gt 0)
                                        {
                                            $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointSharingOperation-SecureLinkUpdated.csv" -Delimiter "," | Select-Object CreationTime,UserId,RecordType,Operation,ObjectId,ClientIP,UserAgent,City,Region,Country,"Country Name",ASN,OrgName,Timezone,Workload,UniqueTokenId
                                            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\XLSX\SharePointSharingOperation-SecureLinkUpdated.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "SecureLinkUpdated" -CellStyleSB {
                                            param($WorkSheet)
                                            # BackgroundColor and FontColor for specific cells of TopRow
                                            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                            Set-Format -Address $WorkSheet.Cells["A1:P1"] -BackgroundColor $BackgroundColor -FontColor White
                                            # HorizontalAlignment "Center" of columns A-P
                                            $WorkSheet.Cells["A:P"].Style.HorizontalAlignment="Center"
                                            # ConditionalFormatting
                                            Add-ConditionalFormatting -Address $WorkSheet.Cells["C:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("SharePointSharingOperation",$C1)))' -BackgroundColor Yellow
                                            Add-ConditionalFormatting -Address $WorkSheet.Cells["D:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("SecureLinkUpdated",$D1)))' -BackgroundColor Yellow
                                            
                                            # Iterating over the ASN-Blacklist HashTable
                                            foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
                                            {
                                                $ConditionValue = 'NOT(ISERROR(FIND("{0}",$L1)))' -f $ASN
                                                Add-ConditionalFormatting -Address $WorkSheet.Cells["L:L"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
                                            }
                                            
                                            }
                                        }
                                    }
                                }

                                # Suspicious SharePoint Action(s) detected: A user shared 10+ a file, folder, or site in SharePoint for Business with a user in your organization's directory
                                # RecordType: SharePointSharingOperation --> SharePoint sharing events.
                                # Operation: SharingSet --> User (member or guest) shared a file, folder, or site in SharePoint or OneDrive for Business with a user in your organization's directory. The value in the Detail column for this activity identifies the name of the user the resource was shared with and whether this user is a member or a guest. This activity is often accompanied by a second event that describes how the user was granted access to the resource. For example, adding the user to a group that has access to the resource.
                                $Import = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," -Encoding UTF8 | Where-Object { $_.RecordType -eq "SharePointSharingOperation" } | Where-Object { $_.Operation -eq "SharingSet" } | Sort-Object { $_.CreationTime -as [datetime] } -Descending
                                $Count = ($Import | Group-Object{($_.CreationTime -split "\s+")[0]} | Where-Object Count -ge 10 | Measure-Object).Count

                                if ($Count -ge 1)
                                {
                                    Write-Host "[Alert] Suspicious SharePoint Action(s) detected: A user shared 10+ a file, folder, or site in SharePoint for Business with a user in your organization's directory ($Count)" -ForegroundColor Red
                                    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV" -ItemType Directory -Force | Out-Null
                                    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\XLSX" -ItemType Directory -Force | Out-Null

                                    # CSV
                                    $Import | Group-Object{($_.CreationTime -split "\s+")[0]} | Where-Object Count -ge 5 | Select-Object Name,Count | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointSharingOperation-SharingSet-Overview.csv" -NoTypeInformation -Encoding UTF8
                                    $Import | Group-Object{($_.CreationTime -split "\s+")[0]} | Where-Object Count -ge 5 | Select-Object -Expand Group | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointSharingOperation-SharingSet.csv" -NoTypeInformation -Encoding UTF8
                                    
                                    # SharePointSharingOperation-SharingSet-Overview.xlsx
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

                                    # SharePointSharingOperation-SharingSet.xlsx
                                    if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointSharingOperation-SharingSet.csv")
                                    {
                                        if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointSharingOperation-SharingSet.csv") -gt 0)
                                        {
                                            $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointSharingOperation-SharingSet.csv" -Delimiter "," | Select-Object CreationTime,UserId,RecordType,Operation,ObjectId,ClientIP,UserAgent,City,Region,Country,"Country Name",ASN,OrgName,Timezone,Workload,UniqueTokenId
                                            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\XLSX\SharePointSharingOperation-SharingSet.xlsx" -NoNumberConversion * -NoHyperLinkConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "SharingSet" -CellStyleSB {
                                            param($WorkSheet)
                                            # BackgroundColor and FontColor for specific cells of TopRow
                                            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                            Set-Format -Address $WorkSheet.Cells["A1:P1"] -BackgroundColor $BackgroundColor -FontColor White
                                            # HorizontalAlignment "Center" of columns A-P
                                            $WorkSheet.Cells["A:P"].Style.HorizontalAlignment="Center"
                                            # ConditionalFormatting
                                            Add-ConditionalFormatting -Address $WorkSheet.Cells["C:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("SharePointSharingOperation",$C1)))' -BackgroundColor Yellow
                                            Add-ConditionalFormatting -Address $WorkSheet.Cells["D:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("SharingSet",$D1)))' -BackgroundColor Yellow
                                            
                                            # Iterating over the ASN-Blacklist HashTable
                                            foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
                                            {
                                                $ConditionValue = 'NOT(ISERROR(FIND("{0}",$L1)))' -f $ASN
                                                Add-ConditionalFormatting -Address $WorkSheet.Cells["L:L"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
                                            }

                                            }
                                        }
                                    }
                                }

                                # Suspicious SharePointFileOperations

                                # Suspicious SharePoint Action(s) detected: A user in your organization possibly uploaded a suspicious document on a site
                                # RecordType: SharePointFileOperation --> SharePoint file operation events.
                                # Operation: FileUploaded --> User uploads a document to a folder on a SharePoint or OneDrive for Business site.
                                $Import = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," -Encoding UTF8 | Where-Object { $_.RecordType -eq "SharePointFileOperation" } | Where-Object { $_.Operation -eq "FileUploaded" } | Sort-Object { $_.CreationTime -as [datetime] } -Descending
                                $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

                                if ($Count -gt 0)
                                {
                                    Write-Host "[Alert] Suspicious SharePoint Action(s) detected: A user in your organization possibly uploaded a suspicious document on a site ($Count)" -ForegroundColor Yellow
                                    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV" -ItemType Directory -Force | Out-Null
                                    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\XLSX" -ItemType Directory -Force | Out-Null

                                    # CSV
                                    $Import | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointFileOperation-FileUploaded.csv" -NoTypeInformation -Encoding UTF8

                                    # XLSX
                                    if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointFileOperation-FileUploaded.csv")
                                    {
                                        if([int](& $xsv count "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointFileOperation-FileUploaded.csv") -gt 0)
                                        {
                                            $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointFileOperation-FileUploaded.csv" -Delimiter "," | Select-Object CreationTime,UserId,RecordType,Operation,ObjectId,ClientIP,UserAgent,City,Region,Country,"Country Name",ASN,OrgName,Timezone,Workload,UniqueTokenId
                                            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\XLSX\SharePointFileOperation-FileUploaded.xlsx" -NoNumberConversion * -NoHyperLinkConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "FileUploaded" -CellStyleSB {
                                            param($WorkSheet)
                                            # BackgroundColor and FontColor for specific cells of TopRow
                                            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                            Set-Format -Address $WorkSheet.Cells["A1:P1"] -BackgroundColor $BackgroundColor -FontColor White
                                            # HorizontalAlignment "Center" of columns A-D and F-P
                                            $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"
                                            $WorkSheet.Cells["F:P"].Style.HorizontalAlignment="Center"
                                            # ConditionalFormatting
                                            Add-ConditionalFormatting -Address $WorkSheet.Cells["C:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("SharePointFileOperation",$C1)))' -BackgroundColor Yellow
                                            Add-ConditionalFormatting -Address $WorkSheet.Cells["D:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("FileUploaded",$D1)))' -BackgroundColor Yellow
                                            
                                            # Iterating over the ASN-Blacklist HashTable
                                            foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
                                            {
                                                $ConditionValue = 'NOT(ISERROR(FIND("{0}",$L1)))' -f $ASN
                                                Add-ConditionalFormatting -Address $WorkSheet.Cells["L:L"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
                                            }

                                            }
                                        }
                                    }
                                }

                                # Suspicious SharePoint Action(s) detected: 50+ files were downloaded from a SharePoint or OneDrive for Business site on a single day. Possible Data Exfiltration.
                                # RecordType: SharePointFileOperation --> SharePoint file operation events.
                                # Operation: FileDownloaded --> User downloads a document from a SharePoint or OneDrive for Business site
                                $Import = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," -Encoding UTF8 | Where-Object { $_.RecordType -eq "SharePointFileOperation" } | Where-Object { $_.Operation -eq "FileDownloaded" } | Sort-Object { $_.CreationTime -as [datetime] } -Descending
                                $Count = ($Import | Group-Object{($_.CreationTime -split "\s+")[0]} | Where-Object Count -ge 50 | Measure-Object).Count

                                if ($Count -ge 1)
                                {
                                    Write-Host "[Alert] Suspicious SharePoint Action(s) detected: 50+ files were downloaded from a SharePoint or OneDrive for Business site on a single day. Possible Data Exfiltration. ($Count)" -ForegroundColor Red
                                    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV" -ItemType Directory -Force | Out-Null
                                    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\XLSX" -ItemType Directory -Force | Out-Null

                                    # CSV
                                    $Import | Group-Object{($_.CreationTime -split "\s+")[0]} | Where-Object Count -ge 50 | Select-Object Name,Count | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointFileOperation-FileDownloaded-Overview.csv" -NoTypeInformation -Encoding UTF8
                                    $Import | Group-Object{($_.CreationTime -split "\s+")[0]} | Where-Object Count -ge 50 | Select-Object -Expand Group | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointFileOperation-FileDownloaded.csv" -NoTypeInformation -Encoding UTF8
                                    
                                    # SharePointFileOperation-FileDownloaded-Overview.xlsx
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

                                    # SharePointFileOperation-FileDownloaded.xlsx
                                    if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointFileOperation-FileDownloaded.csv")
                                    {
                                        if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointFileOperation-FileDownloaded.csv") -gt 0)
                                        {
                                            $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointFileOperation-FileDownloaded.csv" -Delimiter "," | Select-Object CreationTime,UserId,RecordType,Operation,ObjectId,ClientIP,UserAgent,City,Region,Country,"Country Name",EU,Location,ASN,OrgName,"Postal Code",Timezone,Workload
                                            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\XLSX\SharePointFileOperation-FileDownloaded.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "FileDownloaded" -CellStyleSB {
                                            param($WorkSheet)
                                            # BackgroundColor and FontColor for specific cells of TopRow
                                            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                            Set-Format -Address $WorkSheet.Cells["A1:R1"] -BackgroundColor $BackgroundColor -FontColor White
                                            # HorizontalAlignment "Center" of columns A-R
                                            $WorkSheet.Cells["A:R"].Style.HorizontalAlignment="Center"
                                            # ConditionalFormatting - RecordType
                                            Add-ConditionalFormatting -Address $WorkSheet.Cells["C:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("SharePointFileOperation",$C1)))' -BackgroundColor Yellow
                                            # ConditionalFormatting - Operation
                                            Add-ConditionalFormatting -Address $WorkSheet.Cells["D:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("FileDownloaded",$D1)))' -BackgroundColor Yellow
                                            # ConditionalFormatting - UserAgent
                                            Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("OneDriveMpc-Transform_Zip",$G1)))' -BackgroundColor Red # Downloading a folder (as ZIP file) --> Data Exfiltration
                                            
                                            # Iterating over the ASN-Blacklist HashTable
                                            foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
                                            {
                                                $ConditionValue = 'NOT(ISERROR(FIND("{0}",$L1)))' -f $ASN
                                                Add-ConditionalFormatting -Address $WorkSheet.Cells["L:L"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
                                            }
                                            
                                            }
                                        }
                                    }
                                }

                                # Suspicious SharePoint Action(s) detected: A user in your organization continually accesses a file for an extended period (up to 3 hours)
                                # RecordType: SharePointFileOperation --> SharePoint file operation events.
                                # Operation: FileAccessedExtended --> This is related to the 'Accessed file' (FileAccessed) activity. A FileAccessedExtended event is logged when the same person continually accesses a file for an extended period (up to 3 hours).
                                $Import = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," -Encoding UTF8 | Where-Object { $_.RecordType -eq "SharePointFileOperation" } | Where-Object { $_.Operation -eq "FileAccessedExtended" } | Sort-Object { $_.CreationTime -as [datetime] } -Descending
                                $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

                                if ($Count -gt 0)
                                {
                                    Write-Host "[Alert] Suspicious SharePoint Action(s) detected: A user in your organization continually accesses a file for an extended period (up to 3 hours) ($Count)" -ForegroundColor Yellow
                                    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV" -ItemType Directory -Force | Out-Null
                                    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\XLSX" -ItemType Directory -Force | Out-Null

                                    # CSV
                                    $Import | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointFileOperation-FileAccessedExtended.csv" -NoTypeInformation -Encoding UTF8

                                    # XLSX
                                    if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointFileOperation-FileAccessedExtended.csv")
                                    {
                                        if([int](& $xsv count "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointFileOperation-FileAccessedExtended.csv") -gt 0)
                                        {
                                            $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\CSV\SharePointFileOperation-FileAccessedExtended.csv" -Delimiter "," | Select-Object CreationTime,UserId,RecordType,Operation,ObjectId,ClientIP,UserAgent,City,Region,Country,"Country Name",ASN,OrgName,Timezone,Workload,UniqueTokenId
                                            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\XLSX\SharePointFileOperation-FileAccessedExtended.xlsx" -NoNumberConversion * -NoHyperLinkConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "FileAccessedExtended" -CellStyleSB {
                                            param($WorkSheet)
                                            # BackgroundColor and FontColor for specific cells of TopRow
                                            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                            Set-Format -Address $WorkSheet.Cells["A1:P1"] -BackgroundColor $BackgroundColor -FontColor White
                                            # HorizontalAlignment "Center" of columns A-D and F-P
                                            $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"
                                            $WorkSheet.Cells["F:P"].Style.HorizontalAlignment="Center"
                                            # ConditionalFormatting
                                            Add-ConditionalFormatting -Address $WorkSheet.Cells["C:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("SharePointFileOperation",$C1)))' -BackgroundColor Yellow
                                            Add-ConditionalFormatting -Address $WorkSheet.Cells["D:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("FileAccessedExtended",$D1)))' -BackgroundColor Yellow
                                            
                                            # Iterating over the ASN-Blacklist HashTable
                                            foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
                                            {
                                                $ConditionValue = 'NOT(ISERROR(FIND("{0}",$L1)))' -f $ASN
                                                Add-ConditionalFormatting -Address $WorkSheet.Cells["L:L"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
                                            }

                                            }
                                        }
                                    }
                                }

                                # Line Charts

                                # Import Data
                                $AuditData = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Sort-Object Identity -Unique | Select-Object -ExpandProperty AuditData | ConvertFrom-Json

                                # SharePoint (Workload)
                                $Import = $AuditData | Where-Object { $_.Workload -eq "SharePoint" } | Select-Object @{Name="CreationTime";Expression={($_.CreationTime | ForEach-Object{($_ -split "T")[0]})}} | Group-Object{($_.CreationTime)} | Select-Object @{Name='CreationTime'; Expression={ $_.Values[0] }},Count | Sort-Object { $_.CreationTime -as [datetime] }
                                $Count = ($Import | Measure-Object).Count
                                if ($Count -gt 0)
                                {
                                    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\XLSX\LineCharts" -ItemType Directory -Force | Out-Null 
                                    $ChartDefinition = New-ExcelChartDefinition -XRange CreationTime -YRange Count -Title "SharePoint" -ChartType Line -NoLegend -Width 1200
                                    $Import | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\XLSX\LineCharts\SharePoint.xlsx" -Append -WorksheetName "Line Chart" -AutoNameRange -ExcelChartDefinition $ChartDefinition
                                }

                                # OneDrive (Workload)
                                $Import = $AuditData | Where-Object { $_.Workload -eq "OneDrive" } | Select-Object @{Name="CreationTime";Expression={($_.CreationTime | ForEach-Object{($_ -split "T")[0]})}} | Group-Object{($_.CreationTime)} | Select-Object @{Name='CreationTime'; Expression={ $_.Values[0] }},Count | Sort-Object { $_.CreationTime -as [datetime] }
                                $Count = ($Import | Measure-Object).Count
                                if ($Count -gt 0)
                                {
                                    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\XLSX\LineCharts" -ItemType Directory -Force | Out-Null 
                                    $ChartDefinition = New-ExcelChartDefinition -XRange CreationTime -YRange Count -Title "OneDrive" -ChartType Line -NoLegend -Width 1200
                                    $Import | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\XLSX\LineCharts\OneDrive.xlsx" -Append -WorksheetName "Line Chart" -AutoNameRange -ExcelChartDefinition $ChartDefinition
                                }

                                # FileDownloaded (SharePoint and OneDrive)
                                $Import = $AuditData | Where-Object { $_.Workload -eq "SharePoint" -or $_.Workload -eq "OneDrive" } | Where-Object { $_.Operation -eq "FileDownloaded" } | Select-Object @{Name="CreationTime";Expression={($_.CreationTime | ForEach-Object{($_ -split "T")[0]})}} | Group-Object{($_.CreationTime)} | Select-Object @{Name='CreationTime'; Expression={ $_.Values[0] }},Count | Sort-Object { $_.CreationTime -as [datetime] }
                                $Count = ($Import | Measure-Object).Count
                                if ($Count -gt 0)
                                {
                                    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\XLSX\LineCharts" -ItemType Directory -Force | Out-Null 
                                    $ChartDefinition = New-ExcelChartDefinition -XRange CreationTime -YRange Count -Title "FileDownloaded" -ChartType Line -NoLegend -Width 1200
                                    $Import | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Suspicious-SharePoint-Actions\XLSX\LineCharts\FileDownloaded.xlsx" -Append -WorksheetName "Line Chart" -AutoNameRange -ExcelChartDefinition $ChartDefinition
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

# UserLoggedIn
# https://learn.microsoft.com/en-us/purview/audit-log-detailed-properties
# https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema#enum-authenticationmethod---type-edmint32
$UserLoggedInRecords = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object { $_.RecordType -eq "AzureActiveDirectoryStsLogon" } | Where-Object { $_.Operations -eq "UserLoggedIn" }

# AuditData
$AuditData = $UserLoggedInRecords | Select-Object -ExpandProperty AuditData | ConvertFrom-Json | Sort-Object { $_.CreationTime -as [datetime] } -Descending

New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV" -ItemType Directory -Force | Out-Null
New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\XLSX" -ItemType Directory -Force | Out-Null

# IPinfo Subscription: Free
if ($PrivacyDetection -eq "False")
{
    # Custom CSV
    $Results = [Collections.Generic.List[PSObject]]::new()
    ForEach($Record in $UserLoggedInRecords)
    {
        $AuditData = ConvertFrom-Json $Record.AuditData
        $AppAccessContext = $AuditData.AppAccessContext

        # ErrorNumber
        [int]$ErrorNumber = $AuditData.ErrorNumber

        # Check if HashTable contains ErrorNumber
        if($ErrorNumber_HashTable.ContainsKey("$ErrorNumber"))
        {
            $Message   = $ErrorNumber_HashTable["$ErrorNumber"][1]
        }

        # Check if 'MicrosoftApps.csv' contains AppId
        # https://github.com/merill/microsoft-info
        [string]$GUID = $AuditData.ApplicationId

        if($MicrosoftApps_HashTable.ContainsKey("$GUID"))
        {
            $AppDisplayName = $MicrosoftApps_HashTable["$GUID"]
        }
        else
        {
            $AppDisplayName = "Third-Party Application"
        }

        # Check if 'Application-Blacklist.csv' contains AppId
        if($ApplicationBlacklist_HashTable.Contains("$GUID"))
        {
            $AppDisplayName = $ApplicationBlacklist_HashTable["$GUID"][0]
        }

        # TrustType (Value --> Description)
        [int]$TrustTypeValue = ($AuditData | Select-Object -ExpandProperty DeviceProperties | Where-Object {$_.Name -eq 'TrustType'}).Value

        # Check if HashTable contains Value
        if($TrustType_HashTable.ContainsKey("$TrustTypeValue"))
        {
            $TrustType = $TrustType_HashTable["$TrustTypeValue"]
        }
        else
        {
            $TrustType = ""
        }

        # UserType (Value --> Member Name)
        [int]$UserTypeValue = $AuditData.UserType

        # Check if HashTable contains Value
        if($UserType_HashTable.ContainsKey("$UserTypeValue"))
        {
            $UserType = $UserType_HashTable["$UserTypeValue"][0]
        }

        # ClientIP
        $ClientIP = $AuditData.ClientIP

        # Check if HashTable contains ClientIP
        if($IPinfo_HashTable.ContainsKey("$ClientIP"))
        {
            $City        = $IPinfo_HashTable["$ClientIP"][0]
            $Region      = $IPinfo_HashTable["$ClientIP"][1]
            $Country     = $IPinfo_HashTable["$ClientIP"][2]
            $CountryName = $IPinfo_HashTable["$ClientIP"][3]
            $ASN         = $IPinfo_HashTable["$ClientIP"][5] | ForEach-Object {$_ -replace "^AS"}
            $OrgName     = $IPinfo_HashTable["$ClientIP"][6]
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

        # IsCompliant
        $IsCompliantValue = ($AuditData | Select-Object -ExpandProperty DeviceProperties | Where-Object {$_.Name -eq 'IsCompliant'}).Value
        if($IsCompliantValue -ne "True")
        {
            $IsCompliant = "False"
        }
        else
        {
            $IsCompliant = "True"
        }

        # IsCompliantAndManaged
        $IsCompliantAndManagedValue = ($AuditData | Select-Object -ExpandProperty DeviceProperties | Where-Object {$_.Name -eq 'IsCompliantAndManaged'}).Value
        if($IsCompliantAndManagedValue -ne "True")
        {
            $IsCompliantAndManaged = "False"
        }
        else
        {
            $IsCompliantAndManaged = "True"
        }

        $Line = [PSCustomObject]@{
            CreationTime       = $AuditData | Select-Object -ExpandProperty CreationTime | ForEach-Object {$_ -replace 'T',' '} # The date and time in Coordinated Universal Time (UTC) when the audit log record was generated.
            Id                 = $AuditData.Id # Unique identifier of an audit record.
            UserId             = $AuditData.UserId # The UPN (User Principal Name) of the user who performed the action (specified in the Operation property) that resulted in the record being logged.
            UserType           = $UserType # The type of user that performed the operation.
            RecordType         = "AzureActiveDirectoryStsLogon" # The type of operation indicated by the record.
            Operation          = $AuditData.Operation # The name of the user or admin activity. For a description of the most common operations/activities.
            ObjectId           = $AuditData.ObjectId # For SharePoint and OneDrive for Business activity, the full path name of the file or folder accessed by the user. For Exchange admin audit logging, the name of the object that was modified by the cmdlet.
            #OrganizationId     = $AuditData.OrganizationId # The GUID for the organization's tenant.
            #RecordType         = $AuditData.RecordType # The type of operation indicated by the record.
            #ResultStatus       = $AuditData.ResultStatus # Indicates whether the action (specified in the Operation property) was successful or not. Possible values are Succeeded, PartiallySucceeded, or Failed. For Exchange admin activity, the value is either True or False.
            #UserKey            = $AuditData.UserKey # An alternative ID for the user identified in the UserId property. This property is populated with the passport unique ID (PUID) for events performed by users in SharePoint, OneDrive for Business, and Exchange.
            #Version            = $AuditData.Version # Indicates the version number of the activity (identified by the Operation property) that's logged.
            #Workload           = $AuditData.Workload # The Office 365 service where the activity occurred.
            ClientIP           = $ClientIP # The IP address of the device that was used when the activity was logged. The IP address is displayed in either an IPv4 or IPv6 address format.
            #AzureActiveDirectoryEventType = $AuditData.AzureActiveDirectoryEventType

            # ExtendedProperties --> The extended properties of the Microsoft Entra event.
            UserAgent          = ($AuditData | Select-Object -ExpandProperty ExtendedProperties | Where-Object {$_.Name -eq 'UserAgent'}).Value # Information about the user's browser. This information is provided by the browser.
            RequestType        = ($AuditData | Select-Object -ExpandProperty ExtendedProperties | Where-Object {$_.Name -eq 'RequestType'}).Value
            ResultStatusDetail = ($AuditData | Select-Object -ExpandProperty ExtendedProperties | Where-Object {$_.Name -eq 'ResultStatusDetail'}).Value

            # IP Data Enrichment
            "City"                  = $City
            "Region"                = $Region
            "Country"               = $Country
            "Country Name"          = $CountryName
            "ASN"                   = $ASN
            "OrgName"               = $OrgName

            # ModifiedProperties --> This property is included for admin events. The property includes the name of the property that was modified, the new value of the modified property, and the previous value of the modified property.
            #ModifiedProperties = $AuditData | Select-Object -ExpandProperty ModifiedProperties

            # Actor --> The user or service principal that performed the action.
            #ActorId            = ($AuditData | Select-Object -ExpandProperty Actor | Select-Object ID).ID -join "`r`n"
            #ActorType          = ($AuditData | Select-Object -ExpandProperty Actor | Select-Object Type).Type -join "`r`n"

            #ActorContextId     = $AuditData.ActorContextId # The GUID of the organization that the actor belongs to.
            #ActorIpAddress     = $AuditData.ActorIpAddress # The actor's IP address in IPV4 or IPV6 address format.
            #IntraSystemId      = $AuditData.IntraSystemId # The GUID that's generated by Azure Active Directory to track the action.
            #SupportTicketId    = $AuditData.SupportTicketId # The customer support ticket ID for the action in "act-on-behalf-of" situations.

            # Target --> The user that the action (identified by the Operation property) was performed on.
            #TargetId           = ($AuditData | Select-Object -ExpandProperty Target | Select-Object ID).ID -join "`r`n"
            #TargetType         = ($AuditData | Select-Object -ExpandProperty Target | Select-Object Type).Type -join "`r`n"

            #TargetContextId    = $AuditData.TargetContextId # The GUID of the organization that the targeted user belongs to.
            ApplicationId      = $AuditData.ApplicationId # The ID of the application performing the operation.
            AppDisplayName     = $AppDisplayName

            # DeviceProperties --> 	This property includes various device details, including Id, Display name, OS, Browser, IsCompliant, IsCompliantAndManaged, SessionId, and DeviceTrustType.
            DeviceName         = ($AuditData | Select-Object -ExpandProperty DeviceProperties | Where-Object {$_.Name -eq 'DisplayName'}).Value
            DeviceId           = ($AuditData | Select-Object -ExpandProperty DeviceProperties | Where-Object {$_.Name -eq 'Id'}).Value
            OS                 = ($AuditData | Select-Object -ExpandProperty DeviceProperties | Where-Object {$_.Name -eq 'OS'}).Value
            BrowserType        = ($AuditData | Select-Object -ExpandProperty DeviceProperties | Where-Object {$_.Name -eq 'BrowserType'}).Value
            TrustType          = $TrustType
            IsCompliant        = $IsCompliant
            IsCompliantAndManaged = $IsCompliantAndManaged
            SessionId          = ($AuditData | Select-Object -ExpandProperty DeviceProperties | Where-Object {$_.Name -eq 'SessionId'}).Value

            InterSystemsId     = $AuditData.InterSystemsId # The GUID that track the actions across components within the Office 365 service.
            ErrorNumber        = $ErrorNumber # Microsoft Entra authentication and authorization error code
            Message            = $Message # Error Code Message

            # AppAccessContext
            IssuedAtTime       = $AppAccessContext.IssuedAtTime # Indicates when the authentication for this Microsoft Entra token occurred.
            UniqueTokenId      = $AppAccessContext.UniqueTokenId # Contains the unique identifier for the token passed during sign-in. This identifier can be used to correlate the token request with the sign-in.
        }

        $Results.Add($Line)
    }

    $Results | Sort-Object { $_.CreationTime -as [datetime] } -Descending | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\UserLoggedIn.csv" -NoTypeInformation -Encoding UTF8

    # UserLoggedIn.xlsx
    if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\UserLoggedIn.csv")
    {
        if([int](& $xsv count "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\UserLoggedIn.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\UserLoggedIn.csv" -Delimiter "," -Encoding UTF8
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\XLSX\UserLoggedIn.xlsx" -NoHyperLinkConversion * -NoNumberConversion * -FreezePane 2,4 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "UserLoggedIn" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:AF1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-AF
            $WorkSheet.Cells["A:AF"].Style.HorizontalAlignment="Center"

            # Iterating over the Application-Blacklist HashTable - ObjectId
            foreach ($AppId in $ApplicationBlacklist_HashTable.Keys) 
            {
                $Severity = $ApplicationBlacklist_HashTable["$AppId"][1]
                $ConditionValue = 'NOT(ISERROR(FIND("{0}",$G1)))' -f $AppId
                Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
            }

            # Iterating over the Application-Blacklist HashTable - ApplicationId
            foreach ($AppId in $ApplicationBlacklist_HashTable.Keys) 
            {
                $Severity = $ApplicationBlacklist_HashTable["$AppId"][1]
                $ConditionValue = 'NOT(ISERROR(FIND("{0}",$R1)))' -f $AppId
                Add-ConditionalFormatting -Address $WorkSheet.Cells["R:R"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
            }

            # Iterating over the ASN-Blacklist HashTable
            foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
            {
                $ConditionValue = 'NOT(ISERROR(FIND("{0}",$P1)))' -f $ASN
                Add-ConditionalFormatting -Address $WorkSheet.Cells["P:P"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red

                $ConditionValue = '=AND(NOT(ISERROR(FIND("{0}",$P1))),$AA1<>"")' -f $ASN
                Add-ConditionalFormatting -Address $WorkSheet.Cells["AA:AA"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red # Colorize also the corresponding SessionId
            }

            # Iterating over the Country-Blacklist HashTable
            foreach ($Country in $CountryBlacklist_HashTable.Keys) 
            {
                $ConditionValue = 'NOT(ISERROR(FIND("{0}",$O1)))' -f $Country
                Add-ConditionalFormatting -Address $WorkSheet.Cells["O:O"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
            }

            # ConditionalFormatting - ObjectId
            $Cells = "G:G"
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("4765445b-32c6-49b0-83e6-1d93765276ca",$G1)))' -BackgroundColor Yellow # OfficeHome (AiTM)
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("00000002-0000-0ff1-ce00-000000000000",$G1)))' -BackgroundColor Yellow # Office 365 Exchange Online (AiTM)
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("72782ba9-4490-4f03-8d82-562370ea3566",$G1)))' -BackgroundColor Yellow # Office 365 (AiTM)
            # ObjectId = Unknown

            # Iterating over the UserAgent-Blacklist HashTable
            foreach ($UserAgent in $UserAgentBlacklist_HashTable.Keys) 
            {
                $Severity = $UserAgentBlacklist_HashTable["$UserAgent"][1]
                $ConditionValue = 'NOT(ISERROR(FIND("{0}",$I1)))' -f $UserAgent
                Add-ConditionalFormatting -Address $WorkSheet.Cells["I:I"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
            }

            # ConditionalFormatting - BrowserType
            Add-ConditionalFormatting -Address $WorkSheet.Cells["V:V"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Other",$V1)))' -BackgroundColor Red
            }
        }
    }
}

# IPinfo Subscription Plan w/ Privacy Detection
if ($PrivacyDetection -eq "True")
{
    # Custom CSV
    $Results = [Collections.Generic.List[PSObject]]::new()
    ForEach($Record in $UserLoggedInRecords)
    {

        $AuditData = ConvertFrom-Json $Record.AuditData
        $AppAccessContext = $AuditData.AppAccessContext

        # ErrorNumber
        [int]$ErrorNumber = $AuditData.ErrorNumber

        # Check if HashTable contains ErrorNumber
        if($ErrorNumber_HashTable.ContainsKey("$ErrorNumber"))
        {
            $Message   = $ErrorNumber_HashTable["$ErrorNumber"][1]
        }

        # Check if 'MicrosoftApps.csv' contains AppId
        # https://github.com/merill/microsoft-info
        [string]$GUID = $AuditData.ApplicationId

        if($MicrosoftApps_HashTable.ContainsKey("$GUID"))
        {
            $AppDisplayName = $MicrosoftApps_HashTable["$GUID"]
        }
        else
        {
            $AppDisplayName = "Third-Party Application"
        }

        # Check if 'Application-Blacklist.csv' contains AppId
        if($ApplicationBlacklist_HashTable.Contains("$GUID"))
        {
            $AppDisplayName = $ApplicationBlacklist_HashTable["$GUID"][0]
        }

        # TrustType (Value --> Description)
        [int]$TrustTypeValue = ($AuditData | Select-Object -ExpandProperty DeviceProperties | Where-Object {$_.Name -eq 'TrustType'}).Value

        # Check if HashTable contains Value
        if($TrustType_HashTable.ContainsKey("$TrustTypeValue"))
        {
            $TrustType = $TrustType_HashTable["$TrustTypeValue"]
        }
        else
        {
            $TrustType = ""
        }

        # UserType (Value --> Member Name)
        [int]$UserTypeValue = $AuditData.UserType

        # Check if HashTable contains Value
        if($UserType_HashTable.ContainsKey("$UserTypeValue"))
        {
            $UserType = $UserType_HashTable["$UserTypeValue"][0]
        }

        # ClientIP
        $ClientIP = $AuditData.ClientIP

        # Check if HashTable contains ClientIP
        if($IPinfo_HashTable.ContainsKey("$ClientIP"))
        {
            $City        = $IPinfo_HashTable["$ClientIP"][0]
            $Region      = $IPinfo_HashTable["$ClientIP"][1]
            $Country     = $IPinfo_HashTable["$ClientIP"][2]
            $CountryName = $IPinfo_HashTable["$ClientIP"][3]
            $Location    = $IPinfo_HashTable["$ClientIP"][4]
            $ASN         = $IPinfo_HashTable["$ClientIP"][5] | ForEach-Object {$_ -replace "^AS"}
            $OrgName     = $IPinfo_HashTable["$ClientIP"][6]
            $PostalCode  = $IPinfo_HashTable["$ClientIP"][7]
            $Timezone    = $IPinfo_HashTable["$ClientIP"][8]
            $VPN         = $IPinfo_HashTable["$ClientIP"][9]
            $Proxy       = $IPinfo_HashTable["$ClientIP"][10]
            $Tor         = $IPinfo_HashTable["$ClientIP"][11]
            $Relay       = $IPinfo_HashTable["$ClientIP"][12]
            $Hosting     = $IPinfo_HashTable["$ClientIP"][13]
            $Service     = $IPinfo_HashTable["$ClientIP"][14]
        }
        else
        {
            $City        = ""
            $Region      = ""
            $Country     = ""
            $CountryName = ""
            $Location    = ""
            $ASN         = ""
            $OrgName     = ""
            $PostalCode  = ""
            $Timezone    = ""
            $VPN         = ""
            $Proxy       = ""
            $Tor         = ""
            $Relay       = ""
            $Hosting     = ""
            $Service     = ""
        }

        # IsCompliant
        $IsCompliantValue = ($AuditData | Select-Object -ExpandProperty DeviceProperties | Where-Object {$_.Name -eq 'IsCompliant'}).Value
        if($IsCompliantValue -ne "True")
        {
            $IsCompliant = "False"
        }
        else
        {
            $IsCompliant = "True"
        }

        # IsCompliantAndManaged
        $IsCompliantAndManagedValue = ($AuditData | Select-Object -ExpandProperty DeviceProperties | Where-Object {$_.Name -eq 'IsCompliantAndManaged'}).Value
        if($IsCompliantAndManagedValue -ne "True")
        {
            $IsCompliantAndManaged = "False"
        }
        else
        {
            $IsCompliantAndManaged = "True"
        }

        $Line = [PSCustomObject]@{
            CreationTime       = $AuditData | Select-Object -ExpandProperty CreationTime | ForEach-Object {$_ -replace 'T',' '} # The date and time in Coordinated Universal Time (UTC) when the audit log record was generated.
            Id                 = $AuditData.Id # Unique identifier of an audit record.
            UserId             = $AuditData.UserId # The UPN (User Principal Name) of the user who performed the action (specified in the Operation property) that resulted in the record being logged.
            UserType           = $UserType # The type of user that performed the operation.
            RecordType         = "AzureActiveDirectoryStsLogon" # The type of operation indicated by the record.
            Operation          = $AuditData.Operation # The name of the user or admin activity. For a description of the most common operations/activities.
            ObjectId           = $AuditData.ObjectId # For SharePoint and OneDrive for Business activity, the full path name of the file or folder accessed by the user. For Exchange admin audit logging, the name of the object that was modified by the cmdlet.
            #OrganizationId     = $AuditData.OrganizationId # The GUID for the organization's tenant.
            #RecordType         = $AuditData.RecordType # The type of operation indicated by the record.
            #ResultStatus       = $AuditData.ResultStatus # Indicates whether the action (specified in the Operation property) was successful or not. Possible values are Succeeded, PartiallySucceeded, or Failed. For Exchange admin activity, the value is either True or False.
            #UserKey            = $AuditData.UserKey # An alternative ID for the user identified in the UserId property. This property is populated with the passport unique ID (PUID) for events performed by users in SharePoint, OneDrive for Business, and Exchange.
            #Version            = $AuditData.Version # Indicates the version number of the activity (identified by the Operation property) that's logged.
            #Workload           = $AuditData.Workload # The Office 365 service where the activity occurred.
            ClientIP           = $ClientIP # The IP address of the device that was used when the activity was logged. The IP address is displayed in either an IPv4 or IPv6 address format.
            #AzureActiveDirectoryEventType = $AuditData.AzureActiveDirectoryEventType

            # ExtendedProperties --> The extended properties of the Microsoft Entra event.
            UserAgent          = ($AuditData | Select-Object -ExpandProperty ExtendedProperties | Where-Object {$_.Name -eq 'UserAgent'}).Value # Information about the user's browser. This information is provided by the browser.
            RequestType        = ($AuditData | Select-Object -ExpandProperty ExtendedProperties | Where-Object {$_.Name -eq 'RequestType'}).Value
            ResultStatusDetail = ($AuditData | Select-Object -ExpandProperty ExtendedProperties | Where-Object {$_.Name -eq 'ResultStatusDetail'}).Value

            # IP Data Enrichment
            "City"        = $City
            "Region"      = $Region
            "Country"     = $Country
            "CountryName" = $CountryName
            "Location"    = $Location
            "ASN"         = $ASN
            "OrgName"     = $OrgName
            "PostalCode"  = $PostalCode
            "Timezone"    = $Timezone
            "VPN"         = $VPN
            "Proxy"       = $Proxy
            "Tor"         = $Tor
            "Relay"       = $Relay
            "Hosting"     = $Hosting
            "Service"     = $Service

            # ModifiedProperties --> This property is included for admin events. The property includes the name of the property that was modified, the new value of the modified property, and the previous value of the modified property.
            #ModifiedProperties = $AuditData | Select-Object -ExpandProperty ModifiedProperties

            # Actor --> The user or service principal that performed the action.
            #ActorId            = ($AuditData | Select-Object -ExpandProperty Actor | Select-Object ID).ID -join "`r`n"
            #ActorType          = ($AuditData | Select-Object -ExpandProperty Actor | Select-Object Type).Type -join "`r`n"

            #ActorContextId     = $AuditData.ActorContextId # The GUID of the organization that the actor belongs to.
            #ActorIpAddress     = $AuditData.ActorIpAddress # The actor's IP address in IPV4 or IPV6 address format.
            #IntraSystemId      = $AuditData.IntraSystemId # The GUID that's generated by Azure Active Directory to track the action.
            #SupportTicketId    = $AuditData.SupportTicketId # The customer support ticket ID for the action in "act-on-behalf-of" situations.

            # Target --> The user that the action (identified by the Operation property) was performed on.
            #TargetId           = ($AuditData | Select-Object -ExpandProperty Target | Select-Object ID).ID -join "`r`n"
            #TargetType         = ($AuditData | Select-Object -ExpandProperty Target | Select-Object Type).Type -join "`r`n"

            #TargetContextId    = $AuditData.TargetContextId # The GUID of the organization that the targeted user belongs to.
            ApplicationId      = $AuditData.ApplicationId # The ID of the application performing the operation.
            AppDisplayName     = $AppDisplayName

            # DeviceProperties --> 	This property includes various device details, including Id, Display name, OS, Browser, IsCompliant, IsCompliantAndManaged, SessionId, and DeviceTrustType.
            DeviceName         = ($AuditData | Select-Object -ExpandProperty DeviceProperties | Where-Object {$_.Name -eq 'DisplayName'}).Value
            DeviceId           = ($AuditData | Select-Object -ExpandProperty DeviceProperties | Where-Object {$_.Name -eq 'Id'}).Value
            OS                 = ($AuditData | Select-Object -ExpandProperty DeviceProperties | Where-Object {$_.Name -eq 'OS'}).Value
            BrowserType        = ($AuditData | Select-Object -ExpandProperty DeviceProperties | Where-Object {$_.Name -eq 'BrowserType'}).Value
            TrustType          = $TrustType
            IsCompliant        = $IsCompliant
            IsCompliantAndManaged = $IsCompliantAndManaged
            SessionId          = ($AuditData | Select-Object -ExpandProperty DeviceProperties | Where-Object {$_.Name -eq 'SessionId'}).Value

            InterSystemsId     = $AuditData.InterSystemsId # The GUID that track the actions across components within the Office 365 service.
            ErrorNumber        = $ErrorNumber # Microsoft Entra authentication and authorization error code
            Message            = $Message # Error Code Message

            # AppAccessContext
            IssuedAtTime       = $AppAccessContext.IssuedAtTime # Indicates when the authentication for this Microsoft Entra token occurred.
            UniqueTokenId      = $AppAccessContext.UniqueTokenId # Contains the unique identifier for the token passed during sign-in. This identifier can be used to correlate the token request with the sign-in.
        }

        $Results.Add($Line)
    }

    $Results | Sort-Object { $_.CreationTime -as [datetime] } -Descending | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\UserLoggedIn.csv" -NoTypeInformation -Encoding UTF8

    # UserLoggedIn.xlsx
    if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\UserLoggedIn.csv")
    {
        if([int](& $xsv count "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\UserLoggedIn.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\UserLoggedIn.csv" -Delimiter "," -Encoding UTF8
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\XLSX\UserLoggedIn.xlsx" -NoHyperLinkConversion * -NoNumberConversion * -FreezePane 2,4 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "UserLoggedIn" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:AM1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-AM
            $WorkSheet.Cells["A:AM"].Style.HorizontalAlignment="Center"

            # Iterating over the Application-Blacklist HashTable - ObjectId
            foreach ($AppId in $ApplicationBlacklist_HashTable.Keys) 
            {
                $Severity = $ApplicationBlacklist_HashTable["$AppId"][1]
                $ConditionValue = 'NOT(ISERROR(FIND("{0}",$G1)))' -f $AppId
                Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
            }

            # Iterating over the Application-Blacklist HashTable - ApplicationId
            foreach ($AppId in $ApplicationBlacklist_HashTable.Keys) 
            {
                $Severity = $ApplicationBlacklist_HashTable["$AppId"][1]
                $ConditionValue = 'NOT(ISERROR(FIND("{0}",$AA1)))' -f $AppId
                Add-ConditionalFormatting -Address $WorkSheet.Cells["AA:AB"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
            }

            # Iterating over the ASN-Blacklist HashTable
            foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
            {
                $ConditionValue = 'NOT(ISERROR(FIND("{0}",$Q1)))' -f $ASN
                Add-ConditionalFormatting -Address $WorkSheet.Cells["Q:Q"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red

                $ConditionValue = '=AND(NOT(ISERROR(FIND("{0}",$Q1))),$AJ1<>"")' -f $ASN
                Add-ConditionalFormatting -Address $WorkSheet.Cells["AJ:AJ"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red # Colorize also the corresponding SessionId
            }

            # Iterating over the Country-Blacklist HashTable
            foreach ($Country in $CountryBlacklist_HashTable.Keys) 
            {
                $ConditionValue = 'NOT(ISERROR(FIND("{0}",$O1)))' -f $Country
                Add-ConditionalFormatting -Address $WorkSheet.Cells["O:O"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
            }

            # ConditionalFormatting - ObjectId
            $Cells = "G:G"
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("4765445b-32c6-49b0-83e6-1d93765276ca",$G1)))' -BackgroundColor Yellow # OfficeHome (AiTM)
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("00000002-0000-0ff1-ce00-000000000000",$G1)))' -BackgroundColor Yellow # Office 365 Exchange Online (AiTM)
            Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("72782ba9-4490-4f03-8d82-562370ea3566",$G1)))' -BackgroundColor Yellow # Office 365 (AiTM)
            # ObjectId = Unknown

            # Iterating over the UserAgent-Blacklist HashTable
            foreach ($UserAgent in $UserAgentBlacklist_HashTable.Keys) 
            {
                $Severity = $UserAgentBlacklist_HashTable["$UserAgent"][1]
                $ConditionValue = 'NOT(ISERROR(FIND("{0}",$I1)))' -f $UserAgent
                Add-ConditionalFormatting -Address $WorkSheet.Cells["I:I"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
            }

            # ConditionalFormatting - RequestType
            Add-ConditionalFormatting -Address $WorkSheet.Cells["J:J"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Consent:Set",$J1)))' -BackgroundColor Yellow # User Application Consent (Consent Permissions Grant)

            # ConditionalFormatting - BrowserType
            Add-ConditionalFormatting -Address $WorkSheet.Cells["AF:AF"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Other",$AF1)))' -BackgroundColor Red
            }
        }
    }
}

# UserLoginFailed
# https://learn.microsoft.com/en-us/purview/audit-log-detailed-properties
# https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema#enum-authenticationmethod---type-edmint32
$UserLoginFailedRecords = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object { $_.RecordType -eq "AzureActiveDirectoryStsLogon" } | Where-Object { $_.Operations -eq "UserLoginFailed" }

# AuditData
$AuditData = $UserLoginFailedRecords | Select-Object -ExpandProperty AuditData | ConvertFrom-Json | Sort-Object { $_.CreationTime -as [datetime] } -Descending

New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV" -ItemType Directory -Force | Out-Null
New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\XLSX" -ItemType Directory -Force | Out-Null

# IPinfo Subscription: Free
if ($PrivacyDetection -eq "False")
{
    # Custom CSV
    $Results = [Collections.Generic.List[PSObject]]::new()
    ForEach($Record in $UserLoginFailedRecords)
    {

        $AuditData = ConvertFrom-Json $Record.AuditData

        # ErrorNumber
        [int]$ErrorNumber = $AuditData.ErrorNumber

        # Check if HashTable contains ErrorNumber
        if($ErrorNumber_HashTable.ContainsKey("$ErrorNumber"))
        {
            $Message   = $ErrorNumber_HashTable["$ErrorNumber"][1]
        }

        # Check if 'MicrosoftApps.csv' contains AppId
        # https://github.com/merill/microsoft-info
        [string]$GUID = $AuditData.ApplicationId

        if($MicrosoftApps_HashTable.ContainsKey("$GUID"))
        {
            $AppDisplayName = $MicrosoftApps_HashTable["$GUID"]
        }
        else
        {
            $AppDisplayName = "Third-Party Application"
        }

        # Check if 'Application-Blacklist.csv' contains AppId
        if($ApplicationBlacklist_HashTable.Contains("$GUID"))
        {
            $AppDisplayName = $ApplicationBlacklist_HashTable["$GUID"][0]
        }

        # TrustType (Value --> Description)
        [int]$TrustTypeValue = ($AuditData | Select-Object -ExpandProperty DeviceProperties | Where-Object {$_.Name -eq 'TrustType'}).Value

        # Check if HashTable contains Value
        if($TrustType_HashTable.ContainsKey("$TrustTypeValue"))
        {
            $TrustType = $TrustType_HashTable["$TrustTypeValue"]
        }
        else
        {
            $TrustType = ""
        }

        # UserType (Value --> Member Name)
        [int]$UserTypeValue = $AuditData.UserType

        # Check if HashTable contains Value
        if($UserType_HashTable.ContainsKey("$UserTypeValue"))
        {
            $UserType = $UserType_HashTable["$UserTypeValue"][0]
        }

        # ClientIP
        $ClientIP = $AuditData.ClientIP

        # Check if HashTable contains ClientIP
        if($IPinfo_HashTable.ContainsKey("$ClientIP"))
        {
            $City        = $IPinfo_HashTable["$ClientIP"][0]
            $Region      = $IPinfo_HashTable["$ClientIP"][1]
            $Country     = $IPinfo_HashTable["$ClientIP"][2]
            $CountryName = $IPinfo_HashTable["$ClientIP"][3]
            $ASN         = $IPinfo_HashTable["$ClientIP"][6]
            $OrgName     = $IPinfo_HashTable["$ClientIP"][7]
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

        # IsCompliant
        $IsCompliantValue = ($AuditData | Select-Object -ExpandProperty DeviceProperties | Where-Object {$_.Name -eq 'IsCompliant'}).Value
        if($IsCompliantValue -ne "True")
        {
            $IsCompliant = "False"
        }
        else
        {
            $IsCompliant = "True"
        }

        # IsCompliantAndManaged
        $IsCompliantAndManagedValue = ($AuditData | Select-Object -ExpandProperty DeviceProperties | Where-Object {$_.Name -eq 'IsCompliantAndManaged'}).Value
        if($IsCompliantAndManagedValue -ne "True")
        {
            $IsCompliantAndManaged = "False"
        }
        else
        {
            $IsCompliantAndManaged = "True"
        }

        $Line = [PSCustomObject]@{
            CreationTime       = $AuditData | Select-Object -ExpandProperty CreationTime | ForEach-Object {$_ -replace 'T',' '} # The date and time in Coordinated Universal Time (UTC) when the audit log record was generated.
            Id                 = $AuditData.Id # Unique identifier of an audit record.
            UserId             = $AuditData.UserId # The UPN (User Principal Name) of the user who performed the action (specified in the Operation property) that resulted in the record being logged.
            UserType           = $UserType # The type of user that performed the operation.
            RecordType         = "AzureActiveDirectoryStsLogon" # The type of operation indicated by the record.
            Operation          = $AuditData.Operation # The name of the user or admin activity. For a description of the most common operations/activities.
            ObjectId           = $AuditData.ObjectId # For SharePoint and OneDrive for Business activity, the full path name of the file or folder accessed by the user. For Exchange admin audit logging, the name of the object that was modified by the cmdlet.
            #OrganizationId     = $AuditData.OrganizationId # The GUID for the organization's tenant.
            #RecordType         = $AuditData.RecordType # The type of operation indicated by the record.
            #ResultStatus       = $AuditData.ResultStatus # Indicates whether the action (specified in the Operation property) was successful or not. Possible values are Succeeded, PartiallySucceeded, or Failed. For Exchange admin activity, the value is either True or False.
            #UserKey            = $AuditData.UserKey # An alternative ID for the user identified in the UserId property. This property is populated with the passport unique ID (PUID) for events performed by users in SharePoint, OneDrive for Business, and Exchange.
            #Version            = $AuditData.Version # Indicates the version number of the activity (identified by the Operation property) that's logged.
            #Workload           = $AuditData.Workload # The Office 365 service where the activity occurred.
            ClientIP           = $ClientIP # The IP address of the device that was used when the activity was logged. The IP address is displayed in either an IPv4 or IPv6 address format.
            #AzureActiveDirectoryEventType = $AuditData.AzureActiveDirectoryEventType

            # ExtendedProperties --> The extended properties of the Microsoft Entra event.
            UserAgent          = ($AuditData | Select-Object -ExpandProperty ExtendedProperties | Where-Object {$_.Name -eq 'UserAgent'}).Value # Information about the user's browser. This information is provided by the browser.
            RequestType        = ($AuditData | Select-Object -ExpandProperty ExtendedProperties | Where-Object {$_.Name -eq 'RequestType'}).Value
            ResultStatusDetail = ($AuditData | Select-Object -ExpandProperty ExtendedProperties | Where-Object {$_.Name -eq 'ResultStatusDetail'}).Value

            # IP Data Enrichment
            "City"                  = $City
            "Region"                = $Region
            "Country"               = $Country
            "Country Name"          = $CountryName
            "ASN"                   = $ASN
            "OrgName"               = $OrgName

            # ModifiedProperties --> This property is included for admin events. The property includes the name of the property that was modified, the new value of the modified property, and the previous value of the modified property.
            #ModifiedProperties = $AuditData | Select-Object -ExpandProperty ModifiedProperties

            # Actor --> The user or service principal that performed the action.
            #ActorId            = ($AuditData | Select-Object -ExpandProperty Actor | Select-Object ID).ID -join "`r`n"
            #ActorType          = ($AuditData | Select-Object -ExpandProperty Actor | Select-Object Type).Type -join "`r`n"

            #ActorContextId     = $AuditData.ActorContextId # The GUID of the organization that the actor belongs to.
            #ActorIpAddress     = $AuditData.ActorIpAddress # The actor's IP address in IPV4 or IPV6 address format.
            #IntraSystemId      = $AuditData.IntraSystemId # The GUID that's generated by Azure Active Directory to track the action.
            #SupportTicketId    = $AuditData.SupportTicketId # The customer support ticket ID for the action in "act-on-behalf-of" situations.

            # Target --> The user that the action (identified by the Operation property) was performed on.
            #TargetId           = ($AuditData | Select-Object -ExpandProperty Target | Select-Object ID).ID -join "`r`n"
            #TargetType         = ($AuditData | Select-Object -ExpandProperty Target | Select-Object Type).Type -join "`r`n"

            #TargetContextId    = $AuditData.TargetContextId # The GUID of the organization that the targeted user belongs to.
            ApplicationId      = $AuditData.ApplicationId # The ID of the application performing the operation.
            AppDisplayName     = $AppDisplayName

            # DeviceProperties --> 	This property includes various device details, including Id, Display name, OS, Browser, IsCompliant, IsCompliantAndManaged, SessionId, and DeviceTrustType.
            DeviceName         = ($AuditData | Select-Object -ExpandProperty DeviceProperties | Where-Object {$_.Name -eq 'DisplayName'}).Value
            DeviceId           = ($AuditData | Select-Object -ExpandProperty DeviceProperties | Where-Object {$_.Name -eq 'Id'}).Value
            OS                 = ($AuditData | Select-Object -ExpandProperty DeviceProperties | Where-Object {$_.Name -eq 'OS'}).Value
            BrowserType        = ($AuditData | Select-Object -ExpandProperty DeviceProperties | Where-Object {$_.Name -eq 'BrowserType'}).Value
            TrustType          = $TrustType
            IsCompliant        = $IsCompliant
            IsCompliantAndManaged = $IsCompliantAndManaged
            SessionId          = ($AuditData | Select-Object -ExpandProperty DeviceProperties | Where-Object {$_.Name -eq 'SessionId'}).Value

            InterSystemsId     = $AuditData.InterSystemsId # The GUID that track the actions across components within the Office 365 service.
            ErrorNumber        = $ErrorNumber # Microsoft Entra authentication and authorization error code
            Message            = $Message # Error Code Message
            LogonError         = $AuditData.LogonError # For failed logins, this property contains a user-readable description of the reason for the failed login.
        }

        $Results.Add($Line)
    }

    $Results | Sort-Object { $_.CreationTime -as [datetime] } -Descending | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\UserLoginFailed.csv" -NoTypeInformation -Encoding UTF8

    # UserLoginFailed.xlsx
    if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\UserLoginFailed.csv")
    {
        if([int](& $xsv count "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\UserLoginFailed.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\UserLoginFailed.csv" -Delimiter "," -Encoding UTF8
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\XLSX\UserLoginFailed.xlsx" -NoHyperLinkConversion * -NoNumberConversion * -FreezePane 2,4 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "UserLoginFailed" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:AE1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-AE
            $WorkSheet.Cells["A:AE"].Style.HorizontalAlignment="Center"

            # Iterating over the Application-Blacklist HashTable - ObjectId
            foreach ($AppId in $ApplicationBlacklist_HashTable.Keys) 
            {
                $Severity = $ApplicationBlacklist_HashTable["$AppId"][1]
                $ConditionValue = 'NOT(ISERROR(FIND("{0}",$G1)))' -f $AppId
                Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
            }

            # Iterating over the Application-Blacklist HashTable - ApplicationId
            foreach ($AppId in $ApplicationBlacklist_HashTable.Keys) 
            {
                $Severity = $ApplicationBlacklist_HashTable["$AppId"][1]
                $ConditionValue = 'NOT(ISERROR(FIND("{0}",$R1)))' -f $AppId
                Add-ConditionalFormatting -Address $WorkSheet.Cells["R:R"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
            }

            # Iterating over the ASN-Blacklist HashTable
            foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
            {
                $ConditionValue = 'NOT(ISERROR(FIND("{0}",$P1)))' -f $ASN
                Add-ConditionalFormatting -Address $WorkSheet.Cells["P:P"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red

                $ConditionValue = '=AND(NOT(ISERROR(FIND("{0}",$P1))),$Z1<>"")' -f $ASN
                Add-ConditionalFormatting -Address $WorkSheet.Cells["Z:Z"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red # Colorize also the corresponding SessionId
            }

            # Iterating over the Country-Blacklist HashTable
            foreach ($Country in $CountryBlacklist_HashTable.Keys) 
            {
                $ConditionValue = 'NOT(ISERROR(FIND("{0}",$O1)))' -f $Country
                Add-ConditionalFormatting -Address $WorkSheet.Cells["O:O"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
            }

            # Iterating over the UserAgent-Blacklist HashTable
            foreach ($UserAgent in $UserAgentBlacklist_HashTable.Keys) 
            {
                $Severity = $UserAgentBlacklist_HashTable["$UserAgent"][1]
                $ConditionValue = 'NOT(ISERROR(FIND("{0}",$I1)))' -f $UserAgent
                Add-ConditionalFormatting -Address $WorkSheet.Cells["I:I"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
            }

            # ConditionalFormatting - RequestType
            Add-ConditionalFormatting -Address $WorkSheet.Cells["J:J"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Consent:Set",$J1)))' -BackgroundColor Yellow # User Application Consent (Consent Permissions Grant)

            # ConditionalFormatting - LogonError
            Add-ConditionalFormatting -Address $WorkSheet.Cells["AD:AD"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("CmsiInterrupt",$AD1)))' -BackgroundColor Red # Device Code Authentication
            }
        }
    }
}

# IPinfo Subscription Plan w/ Privacy Detection
if ($PrivacyDetection -eq "True")
{
    # Custom CSV
    $Results = [Collections.Generic.List[PSObject]]::new()
    ForEach($Record in $UserLoginFailedRecords)
    {

        $AuditData = ConvertFrom-Json $Record.AuditData

        # ErrorNumber
        [int]$ErrorNumber = $AuditData.ErrorNumber

        # Check if HashTable contains ErrorNumber
        if($ErrorNumber_HashTable.ContainsKey("$ErrorNumber"))
        {
            $Message   = $ErrorNumber_HashTable["$ErrorNumber"][1]
        }

        # Check if 'MicrosoftApps.csv' contains AppId
        # https://github.com/merill/microsoft-info
        [string]$GUID = $AuditData.ApplicationId

        if($MicrosoftApps_HashTable.ContainsKey("$GUID"))
        {
            $AppDisplayName = $MicrosoftApps_HashTable["$GUID"]
        }
        else
        {
            $AppDisplayName = "Third-Party Application"
        }

        # Check if 'Application-Blacklist.csv' contains AppId
        if($ApplicationBlacklist_HashTable.Contains("$GUID"))
        {
            $AppDisplayName = $ApplicationBlacklist_HashTable["$GUID"][0]
        }

        # TrustType (Value --> Description)
        [int]$TrustTypeValue = ($AuditData | Select-Object -ExpandProperty DeviceProperties | Where-Object {$_.Name -eq 'TrustType'}).Value

        # Check if HashTable contains Value
        if($TrustType_HashTable.ContainsKey("$TrustTypeValue"))
        {
            $TrustType = $TrustType_HashTable["$TrustTypeValue"]
        }
        else
        {
            $TrustType = ""
        }

        # UserType (Value --> Member Name)
        [int]$UserTypeValue = $AuditData.UserType

        # Check if HashTable contains Value
        if($UserType_HashTable.ContainsKey("$UserTypeValue"))
        {
            $UserType = $UserType_HashTable["$UserTypeValue"][0]
        }

        # ClientIP
        $ClientIP = $AuditData.ClientIP

        # Check if HashTable contains ClientIP
        if($IPinfo_HashTable.ContainsKey("$ClientIP"))
        {
            $City        = $IPinfo_HashTable["$ClientIP"][0]
            $Region      = $IPinfo_HashTable["$ClientIP"][1]
            $Country     = $IPinfo_HashTable["$ClientIP"][2]
            $CountryName = $IPinfo_HashTable["$ClientIP"][3]
            $Location    = $IPinfo_HashTable["$ClientIP"][4]
            $ASN         = $IPinfo_HashTable["$ClientIP"][5] | ForEach-Object {$_ -replace "^AS"}
            $OrgName     = $IPinfo_HashTable["$ClientIP"][6]
            $PostalCode  = $IPinfo_HashTable["$ClientIP"][7]
            $Timezone    = $IPinfo_HashTable["$ClientIP"][8]
            $VPN         = $IPinfo_HashTable["$ClientIP"][9]
            $Proxy       = $IPinfo_HashTable["$ClientIP"][10]
            $Tor         = $IPinfo_HashTable["$ClientIP"][11]
            $Relay       = $IPinfo_HashTable["$ClientIP"][12]
            $Hosting     = $IPinfo_HashTable["$ClientIP"][13]
            $Service     = $IPinfo_HashTable["$ClientIP"][14]
        }
        else
        {
            $City        = ""
            $Region      = ""
            $Country     = ""
            $CountryName = ""
            $Location    = ""
            $ASN         = ""
            $OrgName     = ""
            $PostalCode  = ""
            $Timezone    = ""
            $VPN         = ""
            $Proxy       = ""
            $Tor         = ""
            $Relay       = ""
            $Hosting     = ""
            $Service     = ""
        }

        # IsCompliant
        $IsCompliantValue = ($AuditData | Select-Object -ExpandProperty DeviceProperties | Where-Object {$_.Name -eq 'IsCompliant'}).Value
        if($IsCompliantValue -ne "True")
        {
            $IsCompliant = "False"
        }
        else
        {
            $IsCompliant = "True"
        }

        # IsCompliantAndManaged
        $IsCompliantAndManagedValue = ($AuditData | Select-Object -ExpandProperty DeviceProperties | Where-Object {$_.Name -eq 'IsCompliantAndManaged'}).Value
        if($IsCompliantAndManagedValue -ne "True")
        {
            $IsCompliantAndManaged = "False"
        }
        else
        {
            $IsCompliantAndManaged = "True"
        }

        $Line = [PSCustomObject]@{
            CreationTime       = $AuditData | Select-Object -ExpandProperty CreationTime | ForEach-Object {$_ -replace 'T',' '} # The date and time in Coordinated Universal Time (UTC) when the audit log record was generated.
            Id                 = $AuditData.Id # Unique identifier of an audit record.
            UserId             = $AuditData.UserId # The UPN (User Principal Name) of the user who performed the action (specified in the Operation property) that resulted in the record being logged.
            UserType           = $UserType # The type of user that performed the operation.
            RecordType         = "AzureActiveDirectoryStsLogon" # The type of operation indicated by the record.
            Operation          = $AuditData.Operation # The name of the user or admin activity. For a description of the most common operations/activities.
            ObjectId           = $AuditData.ObjectId # For SharePoint and OneDrive for Business activity, the full path name of the file or folder accessed by the user. For Exchange admin audit logging, the name of the object that was modified by the cmdlet.
            #OrganizationId     = $AuditData.OrganizationId # The GUID for the organization's tenant.
            #RecordType         = $AuditData.RecordType # The type of operation indicated by the record.
            #ResultStatus       = $AuditData.ResultStatus # Indicates whether the action (specified in the Operation property) was successful or not. Possible values are Succeeded, PartiallySucceeded, or Failed. For Exchange admin activity, the value is either True or False.
            #UserKey            = $AuditData.UserKey # An alternative ID for the user identified in the UserId property. This property is populated with the passport unique ID (PUID) for events performed by users in SharePoint, OneDrive for Business, and Exchange.
            #Version            = $AuditData.Version # Indicates the version number of the activity (identified by the Operation property) that's logged.
            #Workload           = $AuditData.Workload # The Office 365 service where the activity occurred.
            ClientIP           = $ClientIP # The IP address of the device that was used when the activity was logged. The IP address is displayed in either an IPv4 or IPv6 address format.
            #AzureActiveDirectoryEventType = $AuditData.AzureActiveDirectoryEventType

            # ExtendedProperties --> The extended properties of the Microsoft Entra event.
            UserAgent          = ($AuditData | Select-Object -ExpandProperty ExtendedProperties | Where-Object {$_.Name -eq 'UserAgent'}).Value # Information about the user's browser. This information is provided by the browser.
            RequestType        = ($AuditData | Select-Object -ExpandProperty ExtendedProperties | Where-Object {$_.Name -eq 'RequestType'}).Value
            ResultStatusDetail = ($AuditData | Select-Object -ExpandProperty ExtendedProperties | Where-Object {$_.Name -eq 'ResultStatusDetail'}).Value

            # IP Data Enrichment
            "City"        = $City
            "Region"      = $Region
            "Country"     = $Country
            "CountryName" = $CountryName
            "Location"    = $Location
            "ASN"         = $ASN
            "OrgName"     = $OrgName
            "PostalCode"  = $PostalCode
            "Timezone"    = $Timezone
            "VPN"         = $VPN
            "Proxy"       = $Proxy
            "Tor"         = $Tor
            "Relay"       = $Relay
            "Hosting"     = $Hosting
            "Service"     = $Service

            # ModifiedProperties --> This property is included for admin events. The property includes the name of the property that was modified, the new value of the modified property, and the previous value of the modified property.
            #ModifiedProperties = $AuditData | Select-Object -ExpandProperty ModifiedProperties

            # Actor --> The user or service principal that performed the action.
            #ActorId            = ($AuditData | Select-Object -ExpandProperty Actor | Select-Object ID).ID -join "`r`n"
            #ActorType          = ($AuditData | Select-Object -ExpandProperty Actor | Select-Object Type).Type -join "`r`n"

            #ActorContextId     = $AuditData.ActorContextId # The GUID of the organization that the actor belongs to.
            #ActorIpAddress     = $AuditData.ActorIpAddress # The actor's IP address in IPV4 or IPV6 address format.
            #IntraSystemId      = $AuditData.IntraSystemId # The GUID that's generated by Azure Active Directory to track the action.
            #SupportTicketId    = $AuditData.SupportTicketId # The customer support ticket ID for the action in "act-on-behalf-of" situations.

            # Target --> The user that the action (identified by the Operation property) was performed on.
            #TargetId           = ($AuditData | Select-Object -ExpandProperty Target | Select-Object ID).ID -join "`r`n"
            #TargetType         = ($AuditData | Select-Object -ExpandProperty Target | Select-Object Type).Type -join "`r`n"

            #TargetContextId    = $AuditData.TargetContextId # The GUID of the organization that the targeted user belongs to.
            ApplicationId      = $AuditData.ApplicationId # The ID of the application performing the operation.
            AppDisplayName     = $AppDisplayName

            # DeviceProperties --> 	This property includes various device details, including Id, Display name, OS, Browser, IsCompliant, IsCompliantAndManaged, SessionId, and DeviceTrustType.
            DeviceName         = ($AuditData | Select-Object -ExpandProperty DeviceProperties | Where-Object {$_.Name -eq 'DisplayName'}).Value
            DeviceId           = ($AuditData | Select-Object -ExpandProperty DeviceProperties | Where-Object {$_.Name -eq 'Id'}).Value
            OS                 = ($AuditData | Select-Object -ExpandProperty DeviceProperties | Where-Object {$_.Name -eq 'OS'}).Value
            BrowserType        = ($AuditData | Select-Object -ExpandProperty DeviceProperties | Where-Object {$_.Name -eq 'BrowserType'}).Value
            TrustType          = $TrustType
            IsCompliant        = $IsCompliant
            IsCompliantAndManaged = $IsCompliantAndManaged
            SessionId          = ($AuditData | Select-Object -ExpandProperty DeviceProperties | Where-Object {$_.Name -eq 'SessionId'}).Value

            InterSystemsId     = $AuditData.InterSystemsId # The GUID that track the actions across components within the Office 365 service.
            ErrorNumber        = $ErrorNumber # Microsoft Entra authentication and authorization error code
            Message            = $Message # Error Code Message
            LogonError         = $AuditData.LogonError # For failed logins, this property contains a user-readable description of the reason for the failed login.
        }

        $Results.Add($Line)
    }

    $Results | Sort-Object { $_.CreationTime -as [datetime] } -Descending | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\UserLoginFailed.csv" -NoTypeInformation -Encoding UTF8

    # UserLoginFailed.xlsx
    if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\UserLoginFailed.csv")
    {
        if([int](& $xsv count "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\UserLoginFailed.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\UserLoginFailed.csv" -Delimiter "," -Encoding UTF8
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\XLSX\UserLoginFailed.xlsx" -NoHyperLinkConversion * -NoNumberConversion * -FreezePane 2,4 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "UserLoginFailed" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:AN1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-AN
            $WorkSheet.Cells["A:AN"].Style.HorizontalAlignment="Center"

            # Iterating over the Application-Blacklist HashTable - ObjectId
            foreach ($AppId in $ApplicationBlacklist_HashTable.Keys) 
            {
                $Severity = $ApplicationBlacklist_HashTable["$AppId"][1]
                $ConditionValue = 'NOT(ISERROR(FIND("{0}",$G1)))' -f $AppId
                Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
            }

            # Iterating over the Application-Blacklist HashTable - ApplicationId
            foreach ($AppId in $ApplicationBlacklist_HashTable.Keys) 
            {
                $Severity = $ApplicationBlacklist_HashTable["$AppId"][1]
                $ConditionValue = 'NOT(ISERROR(FIND("{0}",$AA1)))' -f $AppId
                Add-ConditionalFormatting -Address $WorkSheet.Cells["AA:AB"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
            }

            # Iterating over the ASN-Blacklist HashTable
            foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
            {
                $ConditionValue = 'NOT(ISERROR(FIND("{0}",$Q1)))' -f $ASN
                Add-ConditionalFormatting -Address $WorkSheet.Cells["Q:Q"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red

                $ConditionValue = '=AND(NOT(ISERROR(FIND("{0}",$Q1))),$AJ1<>"")' -f $ASN
                Add-ConditionalFormatting -Address $WorkSheet.Cells["AJ:AJ"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red # Colorize also the corresponding SessionId
            }

            # Iterating over the Country-Blacklist HashTable
            foreach ($Country in $CountryBlacklist_HashTable.Keys) 
            {
                $ConditionValue = 'NOT(ISERROR(FIND("{0}",$O1)))' -f $Country
                Add-ConditionalFormatting -Address $WorkSheet.Cells["O:O"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
            }

            # Iterating over the UserAgent-Blacklist HashTable
            foreach ($UserAgent in $UserAgentBlacklist_HashTable.Keys) 
            {
                $Severity = $UserAgentBlacklist_HashTable["$UserAgent"][1]
                $ConditionValue = 'NOT(ISERROR(FIND("{0}",$I1)))' -f $UserAgent
                Add-ConditionalFormatting -Address $WorkSheet.Cells["I:I"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
            }

            # ConditionalFormatting - RequestType
            Add-ConditionalFormatting -Address $WorkSheet.Cells["J:J"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Consent:Set",$J1)))' -BackgroundColor Yellow # User Application Consent (Consent Permissions Grant)

            # ConditionalFormatting - LogonError
            Add-ConditionalFormatting -Address $WorkSheet.Cells["AN:AN"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("CmsiInterrupt",$AN1)))' -BackgroundColor Red # Device Code Authentication
            }
        }
    }
}

# Device Code Authentication failed
# CmsiInterrupt - For security reasons, user confirmation is required for this request.
if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\UserLoginFailed.csv")
{
    if([int](& $xsv count "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\UserLoginFailed.csv") -gt 0)
    {
        $Import = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\UserLoginFailed.csv" -Delimiter "," | Where-Object { $_.LogonError -eq "CmsiInterrupt" } | Where-Object { $_.ErrorNumber -eq "50199" } | Sort-Object { $_.CreationTime -as [datetime] } -Descending
        $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

        if ($Count -gt 0)
        {
            Write-Host "[Alert] Failed Device Code Authentication detected: User Confirmation Prompt ($Count)" -ForegroundColor Red
            New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\DeviceCode\CSV" -ItemType Directory -Force | Out-Null
            New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\DeviceCode\XLSX" -ItemType Directory -Force | Out-Null

            # CSV
            $Import | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\DeviceCode\CSV\Failed-DeviceCode-Authentication.csv" -NoTypeInformation -Encoding UTF8

            # XLSX
            if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\DeviceCode\CSV\Failed-DeviceCode-Authentication.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\UnifiedAuditLogs\DeviceCode\CSV\Failed-DeviceCode-Authentication.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\DeviceCode\CSV\Failed-DeviceCode-Authentication.csv" -Delimiter "," -Encoding UTF8
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\DeviceCode\XLSX\Failed-DeviceCode-Authentication.xlsx" -NoHyperLinkConversion * -NoNumberConversion * -FreezePane 2,4 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Failed DeviceCode Auth" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:AD1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-AD
                    $WorkSheet.Cells["A:AD"].Style.HorizontalAlignment="Center"
                    # ConditionalFormatting - LogonError
                    Add-ConditionalFormatting -Address $WorkSheet.Cells["AD:AD"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("CmsiInterrupt",$AD1)))' -BackgroundColor Red # Device Code Authentication
                    # ConditionalFormatting - ErrorNumber
                    Add-ConditionalFormatting -Address $WorkSheet.Cells["AB:AB"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("50199",$AB1)))' -BackgroundColor Red # For security reasons, user confirmation is required for this request.
                    }
                }
            }
        }
    }
}

# ClientInfoString

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

# eM Client
if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv")
{
    if([int](& $xsv count "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv") -gt 0)
    {
        $Import = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," -Encoding UTF8 | Where-Object { $_.ClientInfoString -match "Client=WebServices;eM Client" } | Sort-Object { $_.CreationTime -as [datetime] } -Descending
        $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

        if ($Count -gt 0)
        {
            Write-Host "[Alert] Suspicious ClientInfoString indicates Mailbox Synchronisation: Client=WebServices;eM Client ($Count)" -ForegroundColor Red
        }
    }
}

# Session Cookie Theft

# Hunting for Session Cookie Theft --> Initial Access [TA0001]
if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\UserLoggedIn.csv")
{
    if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\UserLoggedIn.csv") -gt 0)
    {
        Write-Output "[Info]  Hunting for Session Cookie Theft ..."

        $Hunt = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," -Encoding UTF8
        $UserLoggedIn = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\UserLoggedIn.csv" -Delimiter "," -Encoding UTF8
        $SessionIds = $UserLoggedIn | Select-Object -ExpandProperty SessionId -Unique
        
        $Total = ($SessionIds | Measure-Object).Count
        $OfficeHome = ($UserLoggedIn | Where-Object { $_.ObjectId -eq "4765445b-32c6-49b0-83e6-1d93765276ca" } | Select-Object -ExpandProperty SessionId -Unique | Measure-Object).Count
        $Office365 = ($UserLoggedIn | Where-Object { $_.ObjectId -eq "72782ba9-4490-4f03-8d82-562370ea3566" } | Select-Object -ExpandProperty SessionId -Unique | Measure-Object).Count
        $Office365ExchangeOnline = ($UserLoggedIn | Where-Object { $_.ObjectId -eq "00000002-0000-0ff1-ce00-000000000000" } | Select-Object -ExpandProperty SessionId -Unique | Measure-Object).Count

        $Results = [Collections.Generic.List[PSObject]]::new()
        ForEach($SessionId in $SessionIds)
        {
            # Filter
            $Data = $UserLoggedIn | Where-Object { $_.SessionId -eq "$SessionId" } | Where-Object { ($_.ObjectId -eq "4765445b-32c6-49b0-83e6-1d93765276ca") -or ($_.ObjectId -eq "72782ba9-4490-4f03-8d82-562370ea3566") -or ($_.ObjectId -eq "00000002-0000-0ff1-ce00-000000000000") } 
            # 4765445b-32c6-49b0-83e6-1d93765276ca # OfficeHome (Evilginx, Tycoon, Caffeine)
            # 72782ba9-4490-4f03-8d82-562370ea3566 # Office 365 (EvilProxy)
            # 00000002-0000-0ff1-ce00-000000000000 # Office 365 Exchange Online (Naked Pages, SakaiPages)

            # DeviceProperties
            $Count = ($Data | Where-Object { $_.SessionId -eq "$SessionId" } | Where-Object { $_.DeviceId -ne "" } | Select-Object DeviceId -Unique | Measure-Object).Count
            if ($Count)
            {
                [int]$DeviceProperties = $Count
            }
            else
            {
                [string]$DeviceProperties = "No"
            }

            $Line = [PSCustomObject]@{
            "SessionId"        = $SessionId
            "ClientIP"         = ($Data | Select-Object ClientIP -Unique | Measure-Object).Count # Unique Count per SessionId (Location) --> Filtered on known bad ObjectIds
            "Country"          = ($Data | Select-Object Country -Unique | Measure-Object).Count # Unique Count per SessionId (Location) --> Filtered on known bad ObjectIds
            "City"             = ($Data | Select-Object City -Unique | Measure-Object).Count # Unique Count per SessionId (Location) --> Filtered on known bad ObjectIds
            "ASN"              = ($Data | Select-Object ASN -Unique | Measure-Object).Count # Unique Count per SessionId (Location) --> Filtered on known bad ObjectIds
            "OS"               = ($Data | Select-Object OS -Unique | Measure-Object).Count # Unique Count per SessionId (Device Properties) --> Filtered on known bad ObjectIds
            "BrowserType"      = ($Data | Where-Object { $_.BrowserType -ne "" } | Select-Object BrowserType -Unique | Measure-Object).Count # Unique Count per SessionId (Device Properties) --> Filtered on known bad ObjectIds
            "UserAgent"        = ($Data | Where-Object { $_.UserAgent -ne "" } | Select-Object UserAgent -Unique | Measure-Object).Count # Unique Count per SessionId (Device Properties) --> Filtered on known bad ObjectIds
            "DeviceProperties" = $DeviceProperties # Unique Count of 'DeviceProperties' per SessionId (Device Properties) --> Filtered on known bad ObjectIds
            "UserLoggedIn"     = ($Data | Where-Object { $_.Operation -eq "UserLoggedIn" } | Measure-Object).Count # Count of 'UserLoggedIn' operations per SessionId --> Filtered on known bad ObjectIds
            "UniqueTokenId"    = ($Hunt | Where-Object { $_.SessionId -eq "$SessionId" } | Where-Object { $_.UniqueTokenId -ne "" } | Select-Object UniqueTokenId -Unique | Measure-Object).Count # Unique Count of 'UniqueTokenId' per SessionId (AppAccessContext)
            }

            $Results.Add($Line)
        }

        $Results | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Suspicious-SessionIds.csv" -NoTypeInformation -Encoding UTF8
    }
}

# XLSX
if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Suspicious-SessionIds.csv")
{
    if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Suspicious-SessionIds.csv") -gt 0)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Suspicious-SessionIds.csv" -Delimiter "," | Sort-Object @{Expression={ $_."ClientIP" -as [Int] }} -Descending
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\XLSX\Suspicious-SessionIds.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Suspicious SessionIds" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
        Set-Format -Address $WorkSheet.Cells["A1:K1"] -BackgroundColor $BackgroundColor -FontColor White
        # HorizontalAlignment "Center" of column A-K
        $WorkSheet.Cells["A:K"].Style.HorizontalAlignment="Center"
        # ConditionalFormatting - Different IP addresses (and User-Agents) or missing Device Properties indicate Session Cookie Theft
        $LastRow = $WorkSheet.Dimension.End.Row
        Add-ConditionalFormatting -Address $WorkSheet.Cells["B2:B$LastRow"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '=$B2>=2' -BackgroundColor Red # ClientIP
        Add-ConditionalFormatting -Address $WorkSheet.Cells["C2:C$LastRow"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '=$C2>=2' -BackgroundColor Red # Country
        Add-ConditionalFormatting -Address $WorkSheet.Cells["D2:D$LastRow"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '=$D2>=2' -BackgroundColor Red # City
        Add-ConditionalFormatting -Address $WorkSheet.Cells["E2:E$LastRow"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '=$E2>=2' -BackgroundColor Red # ASN
        Add-ConditionalFormatting -Address $WorkSheet.Cells["F2:F$LastRow"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '=$F2>=2' -BackgroundColor Red # OS
        Add-ConditionalFormatting -Address $WorkSheet.Cells["G2:G$LastRow"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '=$G2>=2' -BackgroundColor Red # BrowserType
        Add-ConditionalFormatting -Address $WorkSheet.Cells["I:I"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("No",$I1)))' -BackgroundColor Red # DeviceProperties  
        Add-ConditionalFormatting -Address $WorkSheet.Cells["A2:A$LastRow"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '=AND($B2>=2,$E2>=2)' -BackgroundColor Red # ClientIP + ASN = Suspicious SessionId
        }
    }
}

# Potential Adversary-in-The-Middle [T1557]
$SuspiciousSessionIds = ($IMPORT | Where-Object { [int]$_.ClientIP -ge "2" } | Where-Object { [int]$_.ASN -ge "2" } | Measure-Object).Count
if ($SuspiciousSessionIds -gt 0)
{
    Write-Host "[Info]  $SuspiciousSessionIds Potential Adversary-in-The-Middle found (Total: $Total / OfficeHome: $OfficeHome / Office 365: $Office365 / Office 365 Exchange Online: $Office365ExchangeOnline)" -ForegroundColor Red
}
else
{
    Write-Host "[Info]  $Total SessionIds found (OfficeHome: $OfficeHome / Office 365: $Office365 / Office 365 Exchange Online: $Office365ExchangeOnline)"
}

# Sessions (Duration)
if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv")
{
    if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv") -gt 0)
    {
        $SessionIds = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," | Where-Object { $_.Operation -eq "UserLoggedIn" } | Where-Object { $_.SessionId -ne "" } | Select-Object -ExpandProperty SessionId -Unique

        $Results = [Collections.Generic.List[PSObject]]::new()
        ForEach($SessionId in $SessionIds)
        {
            $Session = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Hunt.csv" -Delimiter "," | Where-Object { $_.SessionId -eq "$SessionId" } | Select-Object CreationTime | Sort-Object { $_.CreationTime -as [datetime] } -Descending

            $StartDate  = ($Session | Select-Object -Last 1).CreationTime
            $EndDate    = ($Session | Select-Object -First 1).CreationTime
            $Difference = New-TimeSpan -Start $StartDate -End $EndDate

            $Line = [PSCustomObject]@{
            "SessionId"    = $SessionId
            "StartDate"    = $StartDate
            "EndDate"      = $EndDate
            "TotalSeconds" = $Difference.TotalSeconds
            "Duration"     = '{0} days {1} h {2} min {3} sec' -f $Difference.Days, $Difference.Hours,$Difference.Minutes,$Difference.Seconds
            }

            $Results.Add($Line)
        }

        $Results | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\SessionIds-Duration.csv" -NoTypeInformation
    }
}

# XLSX
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

# Adversary-in-The-Middle (AiTM) Phishing Attack

# Step 1: User enters credentials on the phishing page.
# Step 2: AiTM server relays credentials to the Microsoft server and authenticates.
# Step 3: User is redirected to the Microsoft portal or a fake landing page.

# In the Unified Audit Logs (UAL), steps 2 and 3 are recorded as consecutive logins from different IPs which occur within about 30 seconds of each other—and often within only a couple of seconds. 
# The first login will be the AiTM server (step 2), with the second login being from the user’s legitimate IP address (step 3).

# Note: Based on my own research it takes sometimes a little bit more time for the adversary to copy the session token from the AiTM server to a different machine.

# Function Find-AiTMSuspiciousUserLogin by @Flittermelint
Function Find-AiTMSuspiciousUserLogin
{
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline)][object[]]$InputObject,

                                      [string[]]$ByProperty        = @('ClientIP', 'ASN'),

        [Alias('Within')]             [timespan]$TimeSpan          = [timespan]'00:00:30',

                                      [string]  $GroupBy           = 'UserId',

                                      [string]  $TimestampProperty = 'CreationTime',

                                      [string]  $TimestampFormat   = 'yyyy-MM-dd HH:mm:ss'
    )

    Begin {

        $previousEvent = $null

        $SuspicionProperty = '#Suspicious'
        $CalcTSpanProperty = '#TimeStamp'

        $EnhanceObject = @{

            Property = @(

                @{ Name = $SuspicionProperty; Expression = { "" } }
                @{ Name = $CalcTSpanProperty; Expression = { [datetime]::ParseExact($_.$TimestampProperty, $TimestampFormat, [CultureInfo]::InvariantCulture) } }

                '*'
            )
        }

        Function Test-AiTMSuspiciousTimespan($Object1, $Object2, $ByProperty, $TimeSpan)
        {
            [math]::Abs(($Object1.$ByProperty - $Object2.$ByProperty).Ticks) -le $TimeSpan.Ticks
        }

        Function Get-AiTMSuspiciousProperty($Object1, $Object2, $ByProperty)
        {
            foreach($p in $ByProperty)
            {
                if($Object1.$p -ne $Object2.$p) { $p }
            }
        }

        Function Out-AiTMEvent($AiTMEvent)
        {
            if($AiTMEvent)
            {
                $AiTMEvent.$SuspicionProperty = ("$($AiTMEvent.$SuspicionProperty)".Split(' ', [System.StringSplitOptions]::RemoveEmptyEntries) | Select-Object -Unique | Sort-Object -Descending) -join ', '

                $AiTMEvent | Select-Object -Property * -ExcludeProperty $CalcTSpanProperty
            }
        }
    }

    Process {

        foreach($AiTMEvent in $InputObject)
        {
            $currentEvent = $AiTMEvent | Select-Object @EnhanceObject

            if($previousEvent)
            {
                if($previousEvent.$GroupingProperty -eq $currentEvent.$GroupingProperty)
                {
                    if(Test-AiTMSuspiciousTimespan $previousEvent $currentEvent $CalcTSpanProperty $TimeSpan)
                    {
                        $SuspiciousProperties = Get-AiTMSuspiciousProperty $previousEvent $currentEvent $ByProperty

                        if($SuspiciousProperties)
                        {
                            $previousEvent.$SuspicionProperty = "$($previousEvent.$SuspicionProperty) $(@($SuspiciousProperties) -join ' ')"
                             $currentEvent.$SuspicionProperty = "$( $currentEvent.$SuspicionProperty) $(@($SuspiciousProperties) -join ' ')"
                        }
                    }
                }
            }

            Out-AiTMEvent $previousEvent

            $previousEvent = $currentEvent
        }
    }

    End {

        Out-AiTMEvent $currentEvent
    }
}

# Find-AiTMSuspiciousUserLogin
if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\UserLoggedIn.csv")
{
    if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\UserLoggedIn.csv") -gt 0)
    {
        $Analyzed = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\UserLoggedIn.csv" -Delimiter "," -Encoding UTF8 | Sort-Object -Descending CreationTime| Find-AiTMSuspiciousUserLogin       
        $Suspicious = $Analyzed | Where-Object -Property "#Suspicious" | Select-Object @{Name="Suspicious"; Expression={$_."#Suspicious"}},CreationTime,Id,UserId,UserType,RecordType,Operation,ObjectId,ClientIP,UserAgent,RequestType,ResultStatusDetail,City,Region,Country,"Country Name",ASN,OrgName,ApplicationId,DeviceName,DeviceId,OS,BrowserType,TrustType,IsCompliant,IsCompliantAndManaged,SessionId,InterSystemsId,ErrorNumber,Message

        # CSV
        if ($Suspicious)
        {
            $Suspicious | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Find-AiTMSuspiciousUserLogin.csv" -NoTypeInformation -Encoding UTF8
        }

        # XLSX
        if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Find-AiTMSuspiciousUserLogin.csv")
        {
            if([int](& $xsv count -d "," "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Find-AiTMSuspiciousUserLogin.csv") -gt 0)
            {
                $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\Find-AiTMSuspiciousUserLogin.csv" -Delimiter "," -Encoding UTF8 | Sort-Object { $_.CreationTime -as [datetime] } -Descending
                $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\XLSX\Find-AiTMSuspiciousUserLogin.xlsx" -NoNumberConversion * -NoHyperLinkConversion * -FreezePane 2,3 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "AiTMSuspiciousUserLogin" -CellStyleSB {
                param($WorkSheet)
                # BackgroundColor and FontColor for specific cells of TopRow
                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                Set-Format -Address $WorkSheet.Cells["A1:AD1"] -BackgroundColor $BackgroundColor -FontColor White
                # HorizontalAlignment "Center" of columns A-AD
                $WorkSheet.Cells["A:AD"].Style.HorizontalAlignment="Center"

                # Iterating over the Application-Blacklist HashTable - ObjectId
                foreach ($AppId in $ApplicationBlacklist_HashTable.Keys) 
                {
                    $Severity = $ApplicationBlacklist_HashTable["$AppId"][1]
                    $ConditionValue = 'NOT(ISERROR(FIND("{0}",$H1)))' -f $AppId
                    Add-ConditionalFormatting -Address $WorkSheet.Cells["H:H"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
                }

                # Iterating over the Application-Blacklist HashTable - ApplicationId
                foreach ($AppId in $ApplicationBlacklist_HashTable.Keys) 
                {
                    $Severity = $ApplicationBlacklist_HashTable["$AppId"][1]
                    $ConditionValue = 'NOT(ISERROR(FIND("{0}",$S1)))' -f $AppId
                    Add-ConditionalFormatting -Address $WorkSheet.Cells["S:S"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
                }

                # Iterating over the ASN-Blacklist HashTable
                foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
                {
                    $ConditionValue = 'NOT(ISERROR(FIND("{0}",$Q1)))' -f $ASN
                    Add-ConditionalFormatting -Address $WorkSheet.Cells["Q:Q"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red

                    $ConditionValue = '=AND(NOT(ISERROR(FIND("{0}",$Q1))),$AA1<>"")' -f $ASN
                    Add-ConditionalFormatting -Address $WorkSheet.Cells["AA:AA"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red # Colorize also the corresponding SessionId
                }

                # Iterating over the Country-Blacklist HashTable
                foreach ($Country in $CountryBlacklist_HashTable.Keys) 
                {
                    $ConditionValue = 'NOT(ISERROR(FIND("{0}",$P1)))' -f $Country
                    Add-ConditionalFormatting -Address $WorkSheet.Cells["P:P"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
                }

                # ConditionalFormatting - ObjectId
                $Cells = "H:H"
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("4765445b-32c6-49b0-83e6-1d93765276ca",$H1)))' -BackgroundColor Yellow # OfficeHome (AiTM)
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("00000002-0000-0ff1-ce00-000000000000",$H1)))' -BackgroundColor Yellow # Office 365 Exchange Online (AiTM)
                Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("72782ba9-4490-4f03-8d82-562370ea3566",$H1)))' -BackgroundColor Yellow # Office 365 (AiTM)
                
                # Iterating over the UserAgent-Blacklist HashTable
                foreach ($UserAgent in $UserAgentBlacklist_HashTable.Keys) 
                {
                    $Severity = $UserAgentBlacklist_HashTable["$UserAgent"][1]
                    $ConditionValue = 'NOT(ISERROR(FIND("{0}",$J1)))' -f $UserAgent
                    Add-ConditionalFormatting -Address $WorkSheet.Cells["J:J"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
                }

                # ConditionalFormatting - BrowserType
                Add-ConditionalFormatting -Address $WorkSheet.Cells["W:W"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Other",$W1)))' -BackgroundColor Red

                }
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

# MailItemsAccessed (MIA)
# https://learn.microsoft.com/en-us/purview/audit-log-investigate-accounts

$StartTime_MailItemsAccessed = (Get-Date)

# RecordType: ExchangeItem (RecordType: 2) --> Events from an Exchange mailbox audit log for actions that are performed on a single item, such as creating or receiving an email message.
# RecordType: ExchangeItemAggregated (RecordType: 50) --> Events related to the MailItemsAccessed mailbox auditing action.
# Operation: MailItemsAccessed --> An operation in the UAL that indicates when a mail item or folder has been accessed or viewed by a user or application.
$MailboxItemRecords = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Sort-Object Identifier -Unique | Where-Object { $_.Operations -eq "MailItemsAccessed" } | Sort-Object { $_.CreationDate -as [datetime] } -Descending
$Count = [string]::Format('{0:N0}',($MailboxItemRecords | Measure-Object).Count)
if ($Count -gt 0)
{
    Write-Output "[Info]  Analyzing the 'MailItemsAccessed' Mailbox-Auditing Action ($Count) ..."
    Write-Output "[Info]  The MailItemsAccessed operation writes an aggregated 2-minute window of activity into a single audit record."
    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV" -ItemType Directory -Force | Out-Null
    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\XLSX" -ItemType Directory -Force | Out-Null

    # Untouched
    $MailboxItemRecords | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\Untouched.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\Untouched.csv")
    {
        if([int](& $xsv count "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\Untouched.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\Untouched.csv" -Delimiter "," -Encoding UTF8 | Select-Object CreationDate,UserIds,RecordType,Operations,AuditData,ResultIndex,ResultCount,Identity,IsValid,ObjectState
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

    # Custom CSV
    $Results = [Collections.Generic.List[PSObject]]::new()
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
            SessionId         = $AuditData.SessionId

            # Folders --> FolderItems
            ClientRequestId   = ($AuditData | Select-Object -ExpandProperty Folders -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FolderItems -ErrorAction SilentlyContinue | Select-Object ClientRequestId -Unique).ClientRequestId -join "`r`n"
            InternetMessageId = ($AuditData | Select-Object -ExpandProperty Folders -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FolderItems -ErrorAction SilentlyContinue | Select-Object InternetMessageId).InternetMessageId -join "`r`n"
            SizeInBytes       = ($AuditData | Select-Object -ExpandProperty Folders -ErrorAction SilentlyContinue | Select-Object -ExpandProperty FolderItems -ErrorAction SilentlyContinue | Select-Object SizeInBytes).SizeInBytes -join "`r`n"
            
            # Folders
            FolderId          = ($AuditData | Select-Object -ExpandProperty Folders -ErrorAction SilentlyContinue | Select-Object Id).Id -join "`r`n"
            Folder            = ($AuditData | Select-Object -ExpandProperty Folders -ErrorAction SilentlyContinue | Select-Object Path).Path -join "`r`n" # Folder & Mailbox

            OperationCount    = $AuditData.OperationCount # Aggregated Events
        }

        $Results.Add($Line)
    }

    $Results | Sort-Object { $_.CreationTime -as [datetime] } -Descending | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\MailItemsAccessed.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\MailItemsAccessed.csv")
    {
        if([int](& $xsv count "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\MailItemsAccessed.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\MailItemsAccessed.csv" -Delimiter "," -Encoding UTF8
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\XLSX\MailItemsAccessed.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "MailItemsAccessed" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:AG1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-AB and AE-AG
            $WorkSheet.Cells["A:AB"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["AE:AG"].Style.HorizontalAlignment="Center"
            # HorizontalAlignment "Right" of column AD
            $WorkSheet.Cells["AD:AD"].Style.HorizontalAlignment="Right"
            # HorizontalAlignment "Center" of header of column AD
            $WorkSheet.Cells["AD1:AD1"].Style.HorizontalAlignment="Center"
            }
        }
    }

    # Stats
    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats" -ItemType Directory -Force | Out-Null

    # Importing 'MailItemsAccessed.csv'
    $MailItemsAccessed = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\MailItemsAccessed.csv" -Delimiter "," -Encoding UTF8

    # AppId (Stats)
    $Total = ($MailItemsAccessed | Select-Object AppId | Measure-Object).Count
    if ($Total -ge "1")
    {
        $Stats = $MailItemsAccessed | Group-Object AppId | Select-Object @{Name='AppId'; Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
        $Stats | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\AppId.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "AppId" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
        Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
        # HorizontalAlignment "Center" of columns A-C
        $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"

        # Iterating over the Application-Blacklist HashTable
        foreach ($AppId in $ApplicationBlacklist_HashTable.Keys)
        {
            $Severity = $ApplicationBlacklist_HashTable["$AppId"][1]
            $ConditionValue = 'NOT(ISERROR(FIND("{0}",$A1)))' -f $AppId
            Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity   
        }

        }
    }

    # ClientAppId (Stats)
    $Total = ($MailItemsAccessed | Select-Object ClientAppId | Measure-Object).Count
    if ($Total -ge "1")
    {
        $Stats = $MailItemsAccessed | Group-Object ClientAppId | Select-Object @{Name='ClientAppId'; Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
        $Stats | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\ClientAppId.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ClientAppId" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
        Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
        # HorizontalAlignment "Center" of columns A-C
        $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"

        # Iterating over the Application-Blacklist HashTable
        foreach ($AppId in $ApplicationBlacklist_HashTable.Keys)
        {
            $Severity = $ApplicationBlacklist_HashTable["$AppId"][1]
            $ConditionValue = 'NOT(ISERROR(FIND("{0}",$A1)))' -f $AppId
            Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity   
        }

        }
    }

    # ClientInfoString (Stats)
    $Total = ($MailItemsAccessed | Select-Object ClientInfoString | Measure-Object).Count
    if ($Total -ge "1")
    {
        $Stats = $MailItemsAccessed | Group-Object ClientInfoString | Select-Object @{Name='ClientInfoString'; Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
        $Stats | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\ClientInfoString.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ClientInfoString" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
        Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
        # HorizontalAlignment "Center" of columns B-C
        $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
        # ConditionalFormatting
        Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Client=OWA;Action=ViaProxy",$A1)))' -BackgroundColor Red # AiTM Server
        Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Client=WebServices;eM Client",$A1)))' -BackgroundColor Red # eM Client
        }
    }

    # AggregatedFolders (Stats)
    $Total = ($MailItemsAccessed | Select-Object Folder | Measure-Object).Count
    if ($Total -ge "1")
    {
        $Stats = $MailItemsAccessed | Group-Object Folder | Select-Object @{Name='Folder'; Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
        $Stats | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\AggregatedFolders.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "AggregatedFolders" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
        Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
        # HorizontalAlignment "Center" of columns B-C
        $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
        }
    }

    # Folder (Stats)
    $Total = ($MailItemsAccessed | ForEach-Object {($_.Folder -split "`r`n")} | Measure-Object).Count
    if ($Total -ge "1")
    {
        $Stats = $MailItemsAccessed| Select-Object Folder | ForEach-Object {($_.Folder -split "`r`n")} | Group-Object | Select-Object @{Name='Folder'; Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
        $Stats | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\Folders.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Folders" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
        Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
        # HorizontalAlignment "Center" of columns B-C
        $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
        }
    }

    # MailAccessType (Stats) ---> MailItemsAccessed events are triggered by two event types: Sync and Bind operations.
    # Auditing Sync Access --> Sync access is recorded when a mailbox is accessed by a desktop version of the Outlook client for Windows or Mac.
    # Auditing Bind Access --> Bind access is recorded when an individual message is accessed.
    $Total = ($MailItemsAccessed | Select-Object MailAccessType | Measure-Object).Count
    if ($Total -ge "1")
    {
        $Stats = $MailItemsAccessed | Group-Object MailAccessType | Select-Object @{Name='MailAccessType'; Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
        $Stats | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\MailAccessType.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "MailAccessType" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
        Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
        # HorizontalAlignment "Center" of columns A-C
        $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
        }
    }

    # OperationCount
    # Note: The MailItemsAccess operation writes an aggregated 2-minute window of activity into a single audit record.
    [int]$Sum = ($MailItemsAccessed | Select-Object OperationCount | Measure-Object -Property OperationCount -Sum).Sum
    $OperationCount = '{0:N0}' -f $Sum
    Write-Output "[Info]  Total Number of Accessed Mailbox Items: $OperationCount"

    # Count
    [int]$Bind = ($MailItemsAccessed | Where-Object { $_.MailAccessType -eq "Bind" } | Measure-Object).Count
    [int]$Sync = ($MailItemsAccessed | Where-Object { $_.MailAccessType -eq "Sync" } | Measure-Object).Count
    $BindAccess = '{0:N0}' -f $Bind
    $SyncAccess = '{0:N0}' -f $Sync
    Write-Output "[Info]  $SyncAccess Sync Access Operation(s) found"
    Write-Output "[Info]  $BindAccess Bind Access Operation(s) found"

    # Line Charts
    New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\LineCharts" -ItemType Directory -Force | Out-Null

    # Accessed Mailbox Items (per day)
    $AuditData = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Select-Object -ExpandProperty AuditData | ConvertFrom-Json
    $Import = $AuditData | Where-Object { $_.Operation -eq "MailItemsAccessed" } | Select-Object @{Name="CreationTime";Expression={($_.CreationTime | ForEach-Object{($_ -split "T")[0]})}} | Group-Object{($_.CreationTime -split "\s+")[0]} | Select-Object @{Name='CreationTime'; Expression={ $_.Values[0] }},Count | Sort-Object { $_.CreationTime -as [datetime] }
    $ChartDefinition = New-ExcelChartDefinition -XRange CreationTime -YRange Count -Title "MailItemsAccessed" -ChartType Line -NoLegend -Width 1200
    $Import | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\LineCharts\MailItemsAccessed.xlsx" -Append -WorksheetName "Line Chart" -AutoNameRange -ExcelChartDefinition $ChartDefinition

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

    # IPinfo CLI
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

                            # TXT --> Top Privacy Services
                            Get-Content "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\ClientIPAddress\IP.txt" | & $IPinfo summarize --token "$Token" | Out-File "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\ClientIPAddress\IPinfo\Summary.txt"
                        
                            # CSV
                            Get-Content "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\ClientIPAddress\IPv4.txt" | & $IPinfo --csv --token "$Token" | Out-File "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\ClientIPAddress\IPinfo\IPinfo.csv" -Encoding UTF8
                            
                            # Custom CSV (Free)
                            if ($PrivacyDetection -eq "False")
                            {
                                if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\ClientIPAddress\IPinfo\IPinfo.csv")
                                {
                                    if([int](& $xsv count "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\ClientIPAddress\IPinfo\IPinfo.csv") -gt 0)
                                    {
                                        $IPinfoRecords = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\ClientIPAddress\IPinfo\IPinfo.csv" -Delimiter "," -Encoding UTF8

                                        $Results = [Collections.Generic.List[PSObject]]::new()
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

                                            $Results.Add($Line)
                                        }

                                        $Results | Sort-Object {$_.IP -as [Version]} | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\ClientIPAddress\IPinfo\IPinfo-Custom.csv" -NoTypeInformation -Encoding UTF8
                                    }
                                }

                                # Custom XLSX (Free)
                                if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\ClientIPAddress\IPinfo\IPinfo-Custom.csv")
                                {
                                    if([int](& $xsv count "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\ClientIPAddress\IPinfo\IPinfo-Custom.csv") -gt 0)
                                    {
                                        $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\ClientIPAddress\IPinfo\IPinfo-Custom.csv" -Delimiter "," | Sort-Object {$_.IP -as [Version]}
                                        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\ClientIPAddress\IPinfo\IPinfo-Custom.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -IncludePivotTable -PivotTableName "PivotTable" -PivotRows "Country Name" -PivotData @{"IP"="Count"} -WorkSheetname "IPinfo (Free)" -CellStyleSB {
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

                            # Custom CSV (Privacy Detection)
                            if ($PrivacyDetection -eq "True")
                            {
                                if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\ClientIPAddress\IPinfo\IPinfo.csv")
                                {
                                    if([int](& $xsv count "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\ClientIPAddress\IPinfo\IPinfo.csv") -gt 0)
                                    {
                                        $IPinfoRecords = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\ClientIPAddress\IPinfo\IPinfo.csv" -Delimiter "," -Encoding UTF8
                                
                                        $Results = [Collections.Generic.List[PSObject]]::new()
                                        ForEach($IPinfoRecord in $IPinfoRecords)
                                        {
                                            $Line = [PSCustomObject]@{
                                                "IP"           = $IPinfoRecord.ip
                                                "City"         = $IPinfoRecord.city
                                                "Region"       = $IPinfoRecord.region
                                                "Country"      = $IPinfoRecord.country
                                                "Country Name" = $IPinfoRecord.country_name
                                                "Location"     = $IPinfoRecord.loc
                                                "ASN"          = $IPinfoRecord.asn_id
                                                "OrgName"      = $IPinfoRecord.asn_asn
                                                "Postal Code"  = $IPinfoRecord.postal
                                                "Timezone"     = $IPinfoRecord.timezone
                                                "VPN"          = $IPinfoRecord.privacy_vpn
                                                "Proxy"        = $IPinfoRecord.privacy_proxy
                                                "Tor"          = $IPinfoRecord.privacy_tor
                                                "Relay"        = $IPinfoRecord.privacy_relay
                                                "Hosting"      = $IPinfoRecord.privacy_hosting
                                                "Service"      = $IPinfoRecord.privacy_service
                                            }

                                            $Results.Add($Line)
                                        }

                                        $Results | Sort-Object {$_.IP -as [Version]} | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\ClientIPAddress\IPinfo\IPinfo-Custom.csv" -NoTypeInformation -Encoding UTF8
                                    }
                                }

                                # Custom XLSX (Privacy Detection)
                                if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\ClientIPAddress\IPinfo\IPinfo-Custom.csv")
                                {
                                    if([int](& $xsv count "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\ClientIPAddress\IPinfo\IPinfo-Custom.csv") -gt 0)
                                    {
                                        $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\ClientIPAddress\IPinfo\IPinfo-Custom.csv" -Delimiter "," | Sort-Object {$_.ip -as [Version]}
                                        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\ClientIPAddress\IPinfo\IPinfo-Custom.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -IncludePivotTable -PivotTableName "PivotTable" -PivotRows "Country Name" -PivotData @{"IP"="Count"} -WorkSheetname "IPinfo (Standard)" -CellStyleSB {
                                        param($WorkSheet)
                                        # BackgroundColor and FontColor for specific cells of TopRow
                                        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                        Set-Format -Address $WorkSheet.Cells["A1:P1"] -BackgroundColor $BackgroundColor -FontColor White
                                        # HorizontalAlignment "Center" of columns A-P
                                        $WorkSheet.Cells["A:P"].Style.HorizontalAlignment="Center"
                                        # ConditionalFormatting - VPN
                                        Add-ConditionalFormatting -Address $WorkSheet.Cells["K:K"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("true",$K1)))' -BackgroundColor Red
                                        # ConditionalFormatting - Proxy
                                        Add-ConditionalFormatting -Address $WorkSheet.Cells["L:L"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("true",$L1)))' -BackgroundColor Red
                                        # ConditionalFormatting - Tor
                                        Add-ConditionalFormatting -Address $WorkSheet.Cells["M:M"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("true",$M1)))' -BackgroundColor Red
                                        # ConditionalFormatting - Relay
                                        Add-ConditionalFormatting -Address $WorkSheet.Cells["N:N"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("true",$N1)))' -BackgroundColor Red
                                        # ConditionalFormatting - Service
                                        $LastRow = $WorkSheet.Dimension.End.Row
                                        Add-ConditionalFormatting -Address $WorkSheet.Cells["P2:P$LastRow"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '=$P2<>""' -BackgroundColor Red
                                    
                                        # ConditionalFormatting - ASN
                                        foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
                                        {
                                            $ConditionValue = 'NOT(ISERROR(FIND("AS{0}",$G1)))' -f $ASN
                                            Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
                                        }

                                        # ConditionalFormatting - Country
                                        foreach ($Country in $CountryBlacklist_HashTable.Keys) 
                                        {
                                            $ConditionValue = 'NOT(ISERROR(FIND("{0}",$E1)))' -f $Country
                                            Add-ConditionalFormatting -Address $WorkSheet.Cells["E:E"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
                                        }
                                    
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    # Create HashTable and import 'IPinfo-Custom.csv'
    $IPinfo_HashTable = @{}
    if (Test-Path "$OUTPUT_FOLDER\ClientIP\IPinfo\IPinfo-Custom.csv")
    {
        if([int](& $xsv count "$OUTPUT_FOLDER\ClientIP\IPinfo\IPinfo-Custom.csv") -gt 0)
        {
            # Free
            if ($PrivacyDetection -eq "False")
            {
                Import-Csv -Path "$OUTPUT_FOLDER\ClientIP\IPinfo\IPinfo-Custom.csv" -Delimiter "," -Encoding UTF8 | ForEach-Object { $IPinfo_HashTable[$_.IP] = $_.City,$_.Region,$_.Country,$_."Country Name",$_.Location,$_.ASN,$_.OrgName,$_."Postal Code",$_.Timezone }
            }

            # Privacy Detection
            if ($PrivacyDetection -eq "True")
            {
                Import-Csv -Path "$OUTPUT_FOLDER\ClientIP\IPinfo\IPinfo-Custom.csv" -Delimiter "," -Encoding UTF8 | ForEach-Object { $IPinfo_HashTable[$_.IP] = $_.City,$_.Region,$_.Country,$_."Country Name",$_.Location,$_.ASN,$_.OrgName,$_."Postal Code",$_.Timezone,$_.VPN,$_.Proxy,$_.Tor,$_.Relay,$_.Hosting,$_.Service }
            }

            # Count Ingested Properties
            $Count = $IPinfo_HashTable.Count
            Write-Output "[Info]  Initializing 'IPinfo-Custom.csv' Lookup Table ($Count) ..."
        }
    }

    # Hunt
    if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\MailItemsAccessed.csv")
    {
        if([int](& $xsv count "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\MailItemsAccessed.csv") -gt 0)
        {
            $Records = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\MailItemsAccessed.csv" -Delimiter "," -Encoding UTF8

            # CSV
            $Results = [Collections.Generic.List[PSObject]]::new()
            ForEach($Record in $Records)
            {
                # ClientIPAddress
                $ClientIPAddress = $Record.ClientIPAddress

                # Check if HashTable contains ClientIPAddress
                if($IPinfo_HashTable.ContainsKey("$ClientIPAddress"))
                {
                    $City        = $IPinfo_HashTable["$ClientIPAddress"][0]
                    $Region      = $IPinfo_HashTable["$ClientIPAddress"][1]
                    $Country     = $IPinfo_HashTable["$ClientIPAddress"][2]
                    $CountryName = $IPinfo_HashTable["$ClientIPAddress"][3]
                    $ASN         = $IPinfo_HashTable["$ClientIPAddress"][4]
                    $OrgName     = $IPinfo_HashTable["$ClientIPAddress"][5]
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

                # Check if 'MicrosoftApps.csv' contains AppId
                # https://github.com/merill/microsoft-info
                [string]$GUID = $Record.AppId

                if($MicrosoftApps_HashTable.ContainsKey("$GUID"))
                {
                    $AppDisplayName = $MicrosoftApps_HashTable["$GUID"]
                }
                else
                {
                    $AppDisplayName = "Third-Party Application"
                }

                # Check if 'Application-Blacklist.csv' contains AppId
                if($ApplicationBlacklist_HashTable.Contains("$GUID"))
                {
                    $AppDisplayName = $ApplicationBlacklist_HashTable["$GUID"][0]
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
                    "AppDisplayName"    = $AppDisplayName
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
                    SessionId           = $Record.SessionId
                }

                $Results.Add($Line)
            }

            $Results | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\Hunt.csv" -Delimiter "," -NoTypeInformation -Encoding UTF8

            # XLSX
            if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\Hunt.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\Hunt.csv") -gt 0)
                {
                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\Hunt.csv" -Delimiter ","
                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\XLSX\Hunt.xlsx" -NoNumberConversion * -FreezePane 2,2 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Hunt" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:V1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of columns A-R and T-V
                    $WorkSheet.Cells["A:R"].Style.HorizontalAlignment="Center"
                    $WorkSheet.Cells["T:V"].Style.HorizontalAlignment="Center"
                    
                    # ConditionalFormatting - AppDisplayName
                    Add-ConditionalFormatting -Address $WorkSheet.Cells["I:I"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Third-Party Application",$I1)))' -BackgroundColor Yellow
                    
                    # ConditionalFormatting - ClientInfoString
                    Add-ConditionalFormatting -Address $WorkSheet.Cells["R:R"] -WorkSheet $WorkSheet -RuleType 'Expression' '=AND($R1="Client=OWA;Action=ViaProxy",$R1<>"AS53813",$R1<>"AS62044")' -BackgroundColor Red # AiTM Proxy Server
                    Add-ConditionalFormatting -Address $WorkSheet.Cells["R:R"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Client=WebServices;eM Client",$R1)))' -BackgroundColor Red # eM Client

                    # Iterating over the Application-Blacklist HashTable
                    foreach ($AppId in $ApplicationBlacklist_HashTable.Keys)
                    {
                        $Severity = $ApplicationBlacklist_HashTable["$AppId"][1]
                        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$H1)))' -f $AppId
                        Add-ConditionalFormatting -Address $WorkSheet.Cells["H:I"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity   
                    }

                    # Iterating over the ASN-Blacklist HashTable
                    foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
                    {
                        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$P1)))' -f $ASN
                        Add-ConditionalFormatting -Address $WorkSheet.Cells["P:P"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red

                        $ConditionValue = '=AND(NOT(ISERROR(FIND("{0}",$P1))),$V1<>"")' -f $ASN
                        Add-ConditionalFormatting -Address $WorkSheet.Cells["V:V"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red # Colorize also the corresponding SessionId
                    }

                    # Iterating over the Country-Blacklist HashTable
                    foreach ($Country in $CountryBlacklist_HashTable.Keys) 
                    {
                        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$O1)))' -f $Country
                        Add-ConditionalFormatting -Address $WorkSheet.Cells["O:O"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
                    }

                    }

                    $Countries = (Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\Hunt.csv" -Delimiter "," | Select-Object Country -Unique | Where-Object { $_.Country -ne '' } | Measure-Object).Count
                    $Cities = (Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\Hunt.csv" -Delimiter "," | Select-Object City -Unique | Where-Object { $_.City -ne '' } | Measure-Object).Count
                    Write-Output "[Info]  $Countries Countries and $Cities Cities found"
                }
            }

            # AppId / AppDisplayName (Stats)
            if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\Hunt.csv")
            {
                if([int](& $xsv count "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\Hunt.csv") -gt 0)
                {
                    $Import = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\Hunt.csv" -Delimiter "," -Encoding UTF8 | Where-Object { $_.AppId -ne '' }
                    $Total = ($Import | Select-Object -ExpandProperty OperationCount | Measure-Object -Sum).Sum
                    $AppIds = $Import | Select-Object -ExpandProperty AppId -Unique | Sort-Object AppId
                    
                    $Results = [Collections.Generic.List[PSObject]]::new()
                    ForEach($AppId in $AppIds)
                    {
                        $AppDisplayName = $Import | Where-Object {$_.AppId -eq "$AppId"} | Select-Object -ExpandProperty AppDisplayName -Unique
                        $Count = ($Import | Where-Object {$_.AppId -eq "$AppId"} | Select-Object -ExpandProperty OperationCount | Measure-Object -Sum).Sum

                        $Line = [PSCustomObject]@{
                            AppId          = $AppId
                            AppDisplayName = $AppDisplayName
                            Count          = $Count
                            PercentUsage   = "{0:p2}" -f ($Count / $Total)
                        }

                        $Results.Add($Line)
                    }

                    $Stats = $Results | Sort-Object Count -Descending

                    # XLSX
                    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\AppId-AppDisplayName.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "AppId" -CellStyleSB {
                    param($WorkSheet)
                    # BackgroundColor and FontColor for specific cells of TopRow
                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                    Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor White
                    # HorizontalAlignment "Center" of column A-D
                    $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"

                    # Iterating over the Application-Blacklist HashTable
                    foreach ($AppId in $ApplicationBlacklist_HashTable.Keys)
                    {
                        $Severity = $ApplicationBlacklist_HashTable["$AppId"][1]
                        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$A1)))' -f $AppId
                        Add-ConditionalFormatting -Address $WorkSheet.Cells["A:D"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity   
                    }

                    # ConditionalFormatting - AppDisplayName
                    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Third-Party Application",$B1)))' -BackgroundColor Yellow

                    }
                }
            }

            # Third-Party Applications / Unknown Applications
            if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\AppId-AppDisplayName.xlsx")
            {
                # Iterating over the Application-Blacklist HashTable
                foreach ($AppId in $ApplicationBlacklist_HashTable.Keys) 
                {
                    $Import = Import-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\AppId-AppDisplayName.xlsx" | Where-Object { $_.AppId -eq "$AppId" }
                    $Count = ($Import | Measure-Object).Count
                    if ($Count -gt 0)
                    {
                        $InternetMessageIds = ($Import | Select-Object -ExpandProperty Count | Measure-Object -Sum).Sum
                        $AppDisplayName = $ApplicationBlacklist_HashTable["$AppId"][0]
                        $Severity = $ApplicationBlacklist_HashTable["$AppId"][1]
                        Write-Host "[Alert] Suspicious Application detected: $AppDisplayName (Accessed Mailbox Items: $InternetMessageIds)" -ForegroundColor $Severity
                    }
                }

                $Import = Import-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\AppId-AppDisplayName.xlsx" | Where-Object {$_.AppDisplayName -eq "Third-Party Application"}
                $Count = ($Import | Select-Object -ExpandProperty AppId | Measure-Object).Count
                if ($Count -gt 0)
                {
                    $InternetMessageIds = ($Import | Select-Object -ExpandProperty Count | Measure-Object -Sum).Sum
                    Write-Host "[Alert] $Count Third-Party Application(s) detected (Accessed Mailbox Items: $InternetMessageIds)" -ForegroundColor Yellow
                }

                # 464e0e4d-676a-4c3b-9f81-2ed9b2a9acd2 - ???
                # 9fd38622-d9b4-4401-b1b9-1ce14c5e435a - ???
            }

            # ASN (Stats)
            $Total = (Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\Hunt.csv" -Delimiter "," | Select-Object ASN | Where-Object { $_.ASN -ne '' } | Measure-Object).Count
            if ($Total -ge "1")
            {
                $Stats = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\Hunt.csv" -Delimiter "," | Select-Object ASN,OrgName | Where-Object { $_.ASN -ne '' } | Where-Object {$null -ne ($_.PSObject.Properties | ForEach-Object {$_.Value})} | Group-Object ASN,OrgName | Select-Object @{Name='ASN'; Expression={ $_.Values[0] }},@{Name='OrgName'; Expression={ $_.Values[1] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
                $Stats | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\ASN.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ASN" -CellStyleSB {
                param($WorkSheet)
                # BackgroundColor and FontColor for specific cells of TopRow
                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor White
                # HorizontalAlignment "Center" of columns A-D
                $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"

                # Iterating over the ASN-Blacklist HashTable
                foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
                {
                    $ConditionValue = 'NOT(ISERROR(FIND("{0}",$A1)))' -f $ASN
                    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
                }

                }
            }

            # ClientIPAddress / Country Name (Stats)
            $Total = (Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\Hunt.csv" -Delimiter "," | Select-Object ClientIPAddress | Where-Object {$_.ClientIPAddress -ne '' } | Measure-Object).Count
            if ($Total -ge "1")
            {
                $Stats = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\Hunt.csv" -Delimiter "," -Encoding UTF8| Select-Object ClientIPAddress,Country,"Country Name",ASN,OrgName | Where-Object {$_.ClientIPAddress -ne '' } | Where-Object {$_."Country Name" -ne '' } | Where-Object {$null -ne ($_.PSObject.Properties | ForEach-Object {$_.Value})} | Group-Object ClientIPAddress,Country,"Country Name",ASN,OrgName | Select-Object @{Name='ClientIPAddress'; Expression={ $_.Values[0] }},@{Name='Country'; Expression={ $_.Values[1] }},@{Name='Country Name'; Expression={ $_.Values[2] }},@{Name='ASN'; Expression={ $_.Values[3] }},@{Name='OrgName'; Expression={ $_.Values[4] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
                $Stats | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\ClientIPAddress.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ClientIPAddress" -CellStyleSB {
                param($WorkSheet)
                # BackgroundColor and FontColor for specific cells of TopRow
                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                Set-Format -Address $WorkSheet.Cells["A1:G1"] -BackgroundColor $BackgroundColor -FontColor White
                # HorizontalAlignment "Center" of columns A-G
                $WorkSheet.Cells["A:G"].Style.HorizontalAlignment="Center"

                # Iterating over the ASN-Blacklist HashTable
                foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
                {
                    $ConditionValue = 'NOT(ISERROR(FIND("{0}",$D1)))' -f $ASN
                    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:G"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
                }

                # Iterating over the Country-Blacklist HashTable
                foreach ($Country in $CountryBlacklist_HashTable.Keys) 
                {
                    $ConditionValue = 'NOT(ISERROR(FIND("{0}",$C1)))' -f $Country
                    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:G"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
                }

                }
            }

            # Country / Country Name (Stats)
            $Total = (Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\Hunt.csv" -Delimiter "," | Select-Object Country | Where-Object {$_.Country -ne '' } | Measure-Object).Count
            if ($Total -ge "1")
            {
                $Stats = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\CSV\Hunt.csv" -Delimiter "," | Select-Object Country,"Country Name" | Where-Object {$_.Country -ne '' } | Where-Object {$null -ne ($_.PSObject.Properties | ForEach-Object {$_.Value})} | Group-Object Country,"Country Name" | Select-Object @{Name='Country'; Expression={ $_.Values[0] }},@{Name='Country Name'; Expression={ $_.Values[1] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
                $Stats | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\Accessed-Mailbox-Items\Stats\Country.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Countries" -CellStyleSB {
                param($WorkSheet)
                # BackgroundColor and FontColor for specific cells of TopRow
                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor White
                # HorizontalAlignment "Center" of columns A-D
                $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"

                # Iterating over the Country-Blacklist HashTable
                foreach ($Country in $CountryBlacklist_HashTable.Keys) 
                {
                    $ConditionValue = 'NOT(ISERROR(FIND("{0}",$B1)))' -f $Country
                    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:D"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
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

            # IsThrottled --> Mailbox Synchronisation for Offline Usage / Exfiltration
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
# https://www.triskelelabs.com/business-email-compromise-mailbox-synchronisation-malicious-oauth-applications

#############################################################################################################################################################################################

Function Get-DeviceCodeAuthentication {

$StartTime_DeviceCodeAuthentication = (Get-Date)

# M365 Device Code Phishing Attacks (OAuth2)
# Device Code Phishing exploits the device authorization grant flow in the Microsoft identity platform to allow an attacker's device or application access to the target user's account or system.
# Note: The device code is valid for only 15 minutes, giving the user a limited time window to view the phishing email and enter the device code for authentication on "https://microsoft.com/devicelogin”.

# https://microsoft.com/devicelogin --> https://login.microsoftonline.com/common/oauth2/deviceauth

# RecordType: AzureActiveDirectoryStsLogon --> Secure Token Service (STS) logon events in Azure Active Directory.
# Operation: UserLoggedIn --> A user signed in to their Microsoft 365 user account.
# RequestType: Cmsi:Cmsi --> Check My Sign In
$DeviceCodeAuthenticationRecords = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\CSV\UserLoggedIn.csv" -Delimiter "," -Encoding UTF8 | Where-Object { $_.RecordType -eq "AzureActiveDirectoryStsLogon" } | Where-Object { $_.Operations -eq "UserLoggedIn" } | Where-Object { $_.RequestType -eq "Cmsi:Cmsi" } | Sort-Object { $_.CreationTime -as [datetime] } -Descending
$Count = [string]::Format('{0:N0}',($DeviceCodeAuthenticationRecords | Measure-Object).Count)
if ($Count -gt 0)
{
    Write-Host "[Alert] Potential Device Code Phishing Attack(s) detected ($Count)" -ForegroundColor Red
}

$EndTime_DeviceCodeAuthentication = (Get-Date)
$Time_DeviceCodeAuthentication = ($EndTime_DeviceCodeAuthentication-$StartTime_DeviceCodeAuthentication)
('DeviceCodeAuthentication duration:        {0} h {1} min {2} sec' -f $Time_DeviceCodeAuthentication.Hours, $Time_DeviceCodeAuthentication.Minutes, $Time_DeviceCodeAuthentication.Seconds) >> "$OUTPUT_FOLDER\Stats.txt"

}

Get-DeviceCodeAuthentication

#############################################################################################################################################################################################

Function Get-MicrosoftTeams {

# Microsoft Teams

# https://learn.microsoft.com/en-us/purview/audit-log-activities#microsoft-teams-activities
# https://learn.microsoft.com/en-us/purview/audit-teams-audit-log-events
# https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema#microsoft-teams-schema
# https://learn.microsoft.com/en-us/purview/ediscovery-document-metadata-fields

$StartTime_MicrosoftTeams = (Get-Date)

# MicrosoftTeams
$MicrosoftTeamsRecords = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Sort-Object Identifier -Unique | Where-Object { $_.RecordType -eq "MicrosoftTeams" }

# Check if Microsoft Teams Records exist
$Count = [string]::Format('{0:N0}',($MicrosoftTeamsRecords).Count)
if ($Count -eq 0)
{
    Return
}

New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\CSV" -ItemType Directory -Force | Out-Null
New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\XLSX" -ItemType Directory -Force | Out-Null

# Custom CSV
$Results = [Collections.Generic.List[PSObject]]::new()
ForEach($Record in $MicrosoftTeamsRecords)
{
    $AuditData = ConvertFrom-Json $Record.AuditData

    $Line = [PSCustomObject]@{
        CreationTime            = ($AuditData | Select-Object @{Name="CreationTime";Expression={([DateTime]::Parse($_.CreationTime).ToString("yyyy-MM-dd HH:mm:ss"))}}).CreationTime
        Id                      = $AuditData.Id
        Operation               = $AuditData.Operation
        RecordType              = $AuditData.RecordType
        UserId                  = $AuditData.UserId
        UserKey                 = $AuditData.UserKey
        UserType                = $AuditData.UserType
        Version                 = $AuditData.Version
        Workload                = $AuditData.Workload
        ClientIP                = $AuditData.ClientIP
        ObjectId                = $AuditData.ObjectId
        OrganizationId          = $AuditData.OrganizationId
        
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

    $Results.Add($Line)
}

$Results | Sort-Object { $_.CreationTime -as [datetime] } -Descending | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\CSV\MicrosoftTeams.csv" -NoTypeInformation -Encoding UTF8

# MicrosoftTeams.xlsx
if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\CSV\MicrosoftTeams.csv")
{
    if([int](& $xsv count "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\CSV\MicrosoftTeams.csv") -gt 0)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\CSV\MicrosoftTeams.csv" -Delimiter ","
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\XLSX\MicrosoftTeams.xlsx" -NoNumberConversion * -FreezePane 2,4 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "MicrosoftTeams" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
        Set-Format -Address $WorkSheet.Cells["A1:AF1"] -BackgroundColor $BackgroundColor -FontColor White
        # HorizontalAlignment "Center" of columns A-AF
        $WorkSheet.Cells["A:AF"].Style.HorizontalAlignment="Center"
        }
    }
}

# Stats
New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\Stats" -ItemType Directory -Force | Out-Null

# Operation (Stats)
$Total = (Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\CSV\MicrosoftTeams.csv" -Delimiter "," | Select-Object Operation | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\CSV\MicrosoftTeams.csv" -Delimiter "," | Group-Object Operation | Select-Object @{Name='Operation'; Expression={$_.Name}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}}| Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\Stats\Operation.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Operation" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of column A-C
    $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
    }
}

# Operations
# ChatCreated          - A Teams chat was created.
# ChannelDeleted       - A user deletes a channel from a team.
# MessageDeleted       - A message in a chat or channel was deleted.
# MessageEditedHasLink - A user edits a message and adds a URL link to it in Teams.
# MessageSent          - A new message was posted to a chat or channel.
# ReactedToMessage     - User reacted to a message.
# TeamsSessionStarted  - A user signs in to a Microsoft Teams client. This event doesn't capture token refresh activities.

# CommunicationType (Stats)
$Total = (Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\CSV\MicrosoftTeams.csv" -Delimiter "," | Select-Object CommunicationType | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\CSV\MicrosoftTeams.csv" -Delimiter "," | Group-Object CommunicationType | Select-Object @{Name='CommunicationType'; Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}}| Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\Stats\CommunicationType.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "CommunicationType" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of column A-C
    $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
    }
}

# Microsoft Teams External Domain Activity
# https://learn.microsoft.com/en-us/microsoftteams/teams-analytics-and-reports/external-domain-activity-report
# https://www.cisa.gov/sites/default/files/2025-01/microsoft-expanded-cloud-logs-implementation-playbook-508c.pdf

# ParticipantDomains (Stats)
# List of all domains of participants of a message.
# TODO

# ParticipatingDomains (Stats)
# MessageCreatedHasLink, MessageRead
# TODO

# ParticipatingDomains
# ParticipantDomains

# Line Charts
New-Item "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\Stats\LineCharts" -ItemType Directory -Force | Out-Null

# MicrosoftTeams - Operations per day (Line Chart)
$AuditData = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Select-Object -ExpandProperty AuditData | ConvertFrom-Json
$Import = $AuditData | Where-Object { $_.RecordType -eq "25" } | Select-Object @{Name="CreationTime";Expression={($_.CreationTime | ForEach-Object{($_ -split "T")[0]})}} | Group-Object{($_.CreationTime)} | Select-Object @{Name='CreationTime'; Expression={ $_.Values[0] }},Count | Sort-Object { $_.CreationTime -as [datetime] }
$Count = ($Import | Measure-Object).Count
if ($Count -gt 0)
{
    $ChartDefinition = New-ExcelChartDefinition -XRange CreationTime -YRange Count -Title "Microsoft Teams" -ChartType Line -NoLegend -Width 1200
    $Import | Export-Excel -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\Stats\LineCharts\MicrosoftTeams.xlsx" -Append -WorksheetName "Line Chart" -AutoNameRange -ExcelChartDefinition $ChartDefinition
}

# RecordType: 25 - MicrosoftTeams
# RecordType: 57 - MicrosoftTeamsAdmin
# RecordType: 59 - MicrosoftTeamsDevice
# RecordType: 60 - MicrosoftTeamsAnalytics
# RecordType: 73 - MicrosoftTeamsShifts

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
$ChatCreated = Import-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\CSV\MicrosoftTeams.csv" -Delimiter "," -Encoding UTF8 | Where-Object { $_.Operations -eq "ChatCreated" } | Sort-Object { $_.CreationTime -as [datetime] } -Descending
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
$Results = [Collections.Generic.List[PSObject]]::new()
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

    $Results.Add($Line)
}

$Results | Sort-Object { $_.CreationTime -as [datetime] } -Descending | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\CSV\MessageSent.csv" -NoTypeInformation -Encoding UTF8

# MessageSent.xlsx
if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\CSV\MessageSent.csv")
{
    if([int](& $xsv count "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\CSV\MessageSent.csv") -gt 0)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\CSV\MessageSent.csv" -Delimiter "," -Encoding UTF8
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

# Investigating Malicious Links shared in Microsoft Teams --> Get Messages with URLs in

# RecordType: MicrosoftTeams --> Events from Microsoft Teams.
# Operation: MessageCreatedHasLink --> A user sends a message containing a URL link in Teams.
$MessageCreatedHasLinkRecords = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object { $_.RecordType -eq "MicrosoftTeams" } | Where-Object { $_.Operations -eq "MessageCreatedHasLink" } 

# MessageCreatedHasLink.csv
$Results = [Collections.Generic.List[PSObject]]::new()
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
        ParticipatingDomains    = ($AuditData | Select-Object -ExpandProperty ParticipantInfo -ErrorAction SilentlyContinue | Select-Object ParticipatingDomains).ParticipatingDomains -join "`r`n"
        ParticipatingSIPDomains = ($AuditData | Select-Object -ExpandProperty ParticipantInfo -ErrorAction SilentlyContinue | Select-Object ParticipatingSIPDomains).ParticipatingSIPDomains -join "`r`n"
        ParticipatingTenantIds  = ($AuditData | Select-Object -ExpandProperty ParticipantInfo -ErrorAction SilentlyContinue | Select-Object ParticipatingTenantIds).ParticipatingTenantIds -join "`r`n"

        ResourceTenantId        = $AuditData.ResourceTenantId
        ItemName                = $AuditData.ItemName
        MessageURLs             = ($AuditData | Select-Object MessageURLs).MessageURLs -join "`r`n"
        URLs                    = ($AuditData| Select-Object -ExpandProperty MessageURLs).Count
    }

    $Results.Add($Line)
}

$Results | Sort-Object { $_.CreationTime -as [datetime] } -Descending | Export-Csv -Path "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\CSV\MessageCreatedHasLink.csv" -NoTypeInformation -Encoding UTF8

# MessageCreatedHasLink.xlsx
if (Test-Path "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\CSV\MessageCreatedHasLink.csv")
{
    if([int](& $xsv count "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\CSV\MessageCreatedHasLink.csv") -gt 0)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\UnifiedAuditLogs\MicrosoftTeams\CSV\MessageCreatedHasLink.csv" -Delimiter "," -Encoding UTF8
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
Start-Sleep 0.5

# IPinfo Logout
& $IPinfo logout > $null

# IPinfo Clear Cache (Optional)
#& $IPinfo cache clear > $null

# Cleaning up
Clear-Variable Token

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

# SIG # Begin signature block
# MIIrxQYJKoZIhvcNAQcCoIIrtjCCK7ICAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUHWkHa6lYtT1rrhfHvYiBBGP0
# 1a+ggiT/MIIFbzCCBFegAwIBAgIQSPyTtGBVlI02p8mKidaUFjANBgkqhkiG9w0B
# AQwFADB7MQswCQYDVQQGEwJHQjEbMBkGA1UECAwSR3JlYXRlciBNYW5jaGVzdGVy
# MRAwDgYDVQQHDAdTYWxmb3JkMRowGAYDVQQKDBFDb21vZG8gQ0EgTGltaXRlZDEh
# MB8GA1UEAwwYQUFBIENlcnRpZmljYXRlIFNlcnZpY2VzMB4XDTIxMDUyNTAwMDAw
# MFoXDTI4MTIzMTIzNTk1OVowVjELMAkGA1UEBhMCR0IxGDAWBgNVBAoTD1NlY3Rp
# Z28gTGltaXRlZDEtMCsGA1UEAxMkU2VjdGlnbyBQdWJsaWMgQ29kZSBTaWduaW5n
# IFJvb3QgUjQ2MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAjeeUEiIE
# JHQu/xYjApKKtq42haxH1CORKz7cfeIxoFFvrISR41KKteKW3tCHYySJiv/vEpM7
# fbu2ir29BX8nm2tl06UMabG8STma8W1uquSggyfamg0rUOlLW7O4ZDakfko9qXGr
# YbNzszwLDO/bM1flvjQ345cbXf0fEj2CA3bm+z9m0pQxafptszSswXp43JJQ8mTH
# qi0Eq8Nq6uAvp6fcbtfo/9ohq0C/ue4NnsbZnpnvxt4fqQx2sycgoda6/YDnAdLv
# 64IplXCN/7sVz/7RDzaiLk8ykHRGa0c1E3cFM09jLrgt4b9lpwRrGNhx+swI8m2J
# mRCxrds+LOSqGLDGBwF1Z95t6WNjHjZ/aYm+qkU+blpfj6Fby50whjDoA7NAxg0P
# OM1nqFOI+rgwZfpvx+cdsYN0aT6sxGg7seZnM5q2COCABUhA7vaCZEao9XOwBpXy
# bGWfv1VbHJxXGsd4RnxwqpQbghesh+m2yQ6BHEDWFhcp/FycGCvqRfXvvdVnTyhe
# Be6QTHrnxvTQ/PrNPjJGEyA2igTqt6oHRpwNkzoJZplYXCmjuQymMDg80EY2NXyc
# uu7D1fkKdvp+BRtAypI16dV60bV/AK6pkKrFfwGcELEW/MxuGNxvYv6mUKe4e7id
# FT/+IAx1yCJaE5UZkADpGtXChvHjjuxf9OUCAwEAAaOCARIwggEOMB8GA1UdIwQY
# MBaAFKARCiM+lvEH7OKvKe+CpX/QMKS0MB0GA1UdDgQWBBQy65Ka/zWWSC8oQEJw
# IDaRXBeF5jAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zATBgNVHSUE
# DDAKBggrBgEFBQcDAzAbBgNVHSAEFDASMAYGBFUdIAAwCAYGZ4EMAQQBMEMGA1Ud
# HwQ8MDowOKA2oDSGMmh0dHA6Ly9jcmwuY29tb2RvY2EuY29tL0FBQUNlcnRpZmlj
# YXRlU2VydmljZXMuY3JsMDQGCCsGAQUFBwEBBCgwJjAkBggrBgEFBQcwAYYYaHR0
# cDovL29jc3AuY29tb2RvY2EuY29tMA0GCSqGSIb3DQEBDAUAA4IBAQASv6Hvi3Sa
# mES4aUa1qyQKDKSKZ7g6gb9Fin1SB6iNH04hhTmja14tIIa/ELiueTtTzbT72ES+
# BtlcY2fUQBaHRIZyKtYyFfUSg8L54V0RQGf2QidyxSPiAjgaTCDi2wH3zUZPJqJ8
# ZsBRNraJAlTH/Fj7bADu/pimLpWhDFMpH2/YGaZPnvesCepdgsaLr4CnvYFIUoQx
# 2jLsFeSmTD1sOXPUC4U5IOCFGmjhp0g4qdE2JXfBjRkWxYhMZn0vY86Y6GnfrDyo
# XZ3JHFuu2PMvdM+4fvbXg50RlmKarkUT2n/cR/vfw1Kf5gZV6Z2M8jpiUbzsJA8p
# 1FiAhORFe1rYMIIGFDCCA/ygAwIBAgIQeiOu2lNplg+RyD5c9MfjPzANBgkqhkiG
# 9w0BAQwFADBXMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVk
# MS4wLAYDVQQDEyVTZWN0aWdvIFB1YmxpYyBUaW1lIFN0YW1waW5nIFJvb3QgUjQ2
# MB4XDTIxMDMyMjAwMDAwMFoXDTM2MDMyMTIzNTk1OVowVTELMAkGA1UEBhMCR0Ix
# GDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDEsMCoGA1UEAxMjU2VjdGlnbyBQdWJs
# aWMgVGltZSBTdGFtcGluZyBDQSBSMzYwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAw
# ggGKAoIBgQDNmNhDQatugivs9jN+JjTkiYzT7yISgFQ+7yavjA6Bg+OiIjPm/N/t
# 3nC7wYUrUlY3mFyI32t2o6Ft3EtxJXCc5MmZQZ8AxCbh5c6WzeJDB9qkQVa46xiY
# Epc81KnBkAWgsaXnLURoYZzksHIzzCNxtIXnb9njZholGw9djnjkTdAA83abEOHQ
# 4ujOGIaBhPXG2NdV8TNgFWZ9BojlAvflxNMCOwkCnzlH4oCw5+4v1nssWeN1y4+R
# laOywwRMUi54fr2vFsU5QPrgb6tSjvEUh1EC4M29YGy/SIYM8ZpHadmVjbi3Pl8h
# JiTWw9jiCKv31pcAaeijS9fc6R7DgyyLIGflmdQMwrNRxCulVq8ZpysiSYNi79tw
# 5RHWZUEhnRfs/hsp/fwkXsynu1jcsUX+HuG8FLa2BNheUPtOcgw+vHJcJ8HnJCrc
# UWhdFczf8O+pDiyGhVYX+bDDP3GhGS7TmKmGnbZ9N+MpEhWmbiAVPbgkqykSkzyY
# Vr15OApZYK8CAwEAAaOCAVwwggFYMB8GA1UdIwQYMBaAFPZ3at0//QET/xahbIIC
# L9AKPRQlMB0GA1UdDgQWBBRfWO1MMXqiYUKNUoC6s2GXGaIymzAOBgNVHQ8BAf8E
# BAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBADATBgNVHSUEDDAKBggrBgEFBQcDCDAR
# BgNVHSAECjAIMAYGBFUdIAAwTAYDVR0fBEUwQzBBoD+gPYY7aHR0cDovL2NybC5z
# ZWN0aWdvLmNvbS9TZWN0aWdvUHVibGljVGltZVN0YW1waW5nUm9vdFI0Ni5jcmww
# fAYIKwYBBQUHAQEEcDBuMEcGCCsGAQUFBzAChjtodHRwOi8vY3J0LnNlY3RpZ28u
# Y29tL1NlY3RpZ29QdWJsaWNUaW1lU3RhbXBpbmdSb290UjQ2LnA3YzAjBggrBgEF
# BQcwAYYXaHR0cDovL29jc3Auc2VjdGlnby5jb20wDQYJKoZIhvcNAQEMBQADggIB
# ABLXeyCtDjVYDJ6BHSVY/UwtZ3Svx2ImIfZVVGnGoUaGdltoX4hDskBMZx5NY5L6
# SCcwDMZhHOmbyMhyOVJDwm1yrKYqGDHWzpwVkFJ+996jKKAXyIIaUf5JVKjccev3
# w16mNIUlNTkpJEor7edVJZiRJVCAmWAaHcw9zP0hY3gj+fWp8MbOocI9Zn78xvm9
# XKGBp6rEs9sEiq/pwzvg2/KjXE2yWUQIkms6+yslCRqNXPjEnBnxuUB1fm6bPAV+
# Tsr/Qrd+mOCJemo06ldon4pJFbQd0TQVIMLv5koklInHvyaf6vATJP4DfPtKzSBP
# kKlOtyaFTAjD2Nu+di5hErEVVaMqSVbfPzd6kNXOhYm23EWm6N2s2ZHCHVhlUgHa
# C4ACMRCgXjYfQEDtYEK54dUwPJXV7icz0rgCzs9VI29DwsjVZFpO4ZIVR33LwXyP
# DbYFkLqYmgHjR3tKVkhh9qKV2WCmBuC27pIOx6TYvyqiYbntinmpOqh/QPAnhDge
# xKG9GX/n1PggkGi9HCapZp8fRwg8RftwS21Ln61euBG0yONM6noD2XQPrFwpm3Gc
# uqJMf0o8LLrFkSLRQNwxPDDkWXhW+gZswbaiie5fd/W2ygcto78XCSPfFWveUOSZ
# 5SqK95tBO8aTHmEa4lpJVD7HrTEn9jb1EGvxOb1cnn0CMIIGGjCCBAKgAwIBAgIQ
# Yh1tDFIBnjuQeRUgiSEcCjANBgkqhkiG9w0BAQwFADBWMQswCQYDVQQGEwJHQjEY
# MBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMS0wKwYDVQQDEyRTZWN0aWdvIFB1Ymxp
# YyBDb2RlIFNpZ25pbmcgUm9vdCBSNDYwHhcNMjEwMzIyMDAwMDAwWhcNMzYwMzIx
# MjM1OTU5WjBUMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVk
# MSswKQYDVQQDEyJTZWN0aWdvIFB1YmxpYyBDb2RlIFNpZ25pbmcgQ0EgUjM2MIIB
# ojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAmyudU/o1P45gBkNqwM/1f/bI
# U1MYyM7TbH78WAeVF3llMwsRHgBGRmxDeEDIArCS2VCoVk4Y/8j6stIkmYV5Gej4
# NgNjVQ4BYoDjGMwdjioXan1hlaGFt4Wk9vT0k2oWJMJjL9G//N523hAm4jF4UjrW
# 2pvv9+hdPX8tbbAfI3v0VdJiJPFy/7XwiunD7mBxNtecM6ytIdUlh08T2z7mJEXZ
# D9OWcJkZk5wDuf2q52PN43jc4T9OkoXZ0arWZVeffvMr/iiIROSCzKoDmWABDRzV
# /UiQ5vqsaeFaqQdzFf4ed8peNWh1OaZXnYvZQgWx/SXiJDRSAolRzZEZquE6cbcH
# 747FHncs/Kzcn0Ccv2jrOW+LPmnOyB+tAfiWu01TPhCr9VrkxsHC5qFNxaThTG5j
# 4/Kc+ODD2dX/fmBECELcvzUHf9shoFvrn35XGf2RPaNTO2uSZ6n9otv7jElspkfK
# 9qEATHZcodp+R4q2OIypxR//YEb3fkDn3UayWW9bAgMBAAGjggFkMIIBYDAfBgNV
# HSMEGDAWgBQy65Ka/zWWSC8oQEJwIDaRXBeF5jAdBgNVHQ4EFgQUDyrLIIcouOxv
# SK4rVKYpqhekzQwwDgYDVR0PAQH/BAQDAgGGMBIGA1UdEwEB/wQIMAYBAf8CAQAw
# EwYDVR0lBAwwCgYIKwYBBQUHAwMwGwYDVR0gBBQwEjAGBgRVHSAAMAgGBmeBDAEE
# ATBLBgNVHR8ERDBCMECgPqA8hjpodHRwOi8vY3JsLnNlY3RpZ28uY29tL1NlY3Rp
# Z29QdWJsaWNDb2RlU2lnbmluZ1Jvb3RSNDYuY3JsMHsGCCsGAQUFBwEBBG8wbTBG
# BggrBgEFBQcwAoY6aHR0cDovL2NydC5zZWN0aWdvLmNvbS9TZWN0aWdvUHVibGlj
# Q29kZVNpZ25pbmdSb290UjQ2LnA3YzAjBggrBgEFBQcwAYYXaHR0cDovL29jc3Au
# c2VjdGlnby5jb20wDQYJKoZIhvcNAQEMBQADggIBAAb/guF3YzZue6EVIJsT/wT+
# mHVEYcNWlXHRkT+FoetAQLHI1uBy/YXKZDk8+Y1LoNqHrp22AKMGxQtgCivnDHFy
# AQ9GXTmlk7MjcgQbDCx6mn7yIawsppWkvfPkKaAQsiqaT9DnMWBHVNIabGqgQSGT
# rQWo43MOfsPynhbz2Hyxf5XWKZpRvr3dMapandPfYgoZ8iDL2OR3sYztgJrbG6VZ
# 9DoTXFm1g0Rf97Aaen1l4c+w3DC+IkwFkvjFV3jS49ZSc4lShKK6BrPTJYs4NG1D
# GzmpToTnwoqZ8fAmi2XlZnuchC4NPSZaPATHvNIzt+z1PHo35D/f7j2pO1S8BCys
# QDHCbM5Mnomnq5aYcKCsdbh0czchOm8bkinLrYrKpii+Tk7pwL7TjRKLXkomm5D1
# Umds++pip8wH2cQpf93at3VDcOK4N7EwoIJB0kak6pSzEu4I64U6gZs7tS/dGNSl
# jf2OSSnRr7KWzq03zl8l75jy+hOds9TWSenLbjBQUGR96cFr6lEUfAIEHVC1L68Y
# 1GGxx4/eRI82ut83axHMViw1+sVpbPxg51Tbnio1lB93079WPFnYaOvfGAA0e0zc
# fF/M9gXr+korwQTh2Prqooq2bYNMvUoUKD85gnJ+t0smrWrb8dee2CvYZXD5laGt
# aAxOfy/VKNmwuWuAh9kcMIIGXTCCBMWgAwIBAgIQOlJqLITOVeYdZfzMEtjpiTAN
# BgkqhkiG9w0BAQwFADBVMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBM
# aW1pdGVkMSwwKgYDVQQDEyNTZWN0aWdvIFB1YmxpYyBUaW1lIFN0YW1waW5nIENB
# IFIzNjAeFw0yNDAxMTUwMDAwMDBaFw0zNTA0MTQyMzU5NTlaMG4xCzAJBgNVBAYT
# AkdCMRMwEQYDVQQIEwpNYW5jaGVzdGVyMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0
# ZWQxMDAuBgNVBAMTJ1NlY3RpZ28gUHVibGljIFRpbWUgU3RhbXBpbmcgU2lnbmVy
# IFIzNTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAI3RZ/TBSJu9/ThJ
# Ok1hgZvD2NxFpWEENo0GnuOYloD11BlbmKCGtcY0xiMrsN7LlEgcyoshtP3P2J/v
# neZhuiMmspY7hk/Q3l0FPZPBllo9vwT6GpoNnxXLZz7HU2ITBsTNOs9fhbdAWr/M
# m8MNtYov32osvjYYlDNfefnBajrQqSV8Wf5ZvbaY5lZhKqQJUaXxpi4TXZKohLgx
# U7g9RrFd477j7jxilCU2ptz+d1OCzNFAsXgyPEM+NEMPUz2q+ktNlxMZXPF9WLIh
# OhE3E8/oNSJkNTqhcBGsbDI/1qCU9fBhuSojZ0u5/1+IjMG6AINyI6XLxM8OAGQm
# aMB8gs2IZxUTOD7jTFR2HE1xoL7qvSO4+JHtvNceHu//dGeVm5Pdkay3Et+YTt9E
# wAXBsd0PPmC0cuqNJNcOI0XnwjE+2+Zk8bauVz5ir7YHz7mlj5Bmf7W8SJ8jQwO2
# IDoHHFC46ePg+eoNors0QrC0PWnOgDeMkW6gmLBtq3CEOSDU8iNicwNsNb7ABz0W
# 1E3qlSw7jTmNoGCKCgVkLD2FaMs2qAVVOjuUxvmtWMn1pIFVUvZ1yrPIVbYt1aTl
# d2nrmh544Auh3tgggy/WluoLXlHtAJgvFwrVsKXj8ekFt0TmaPL0lHvQEe5jHbuf
# hc05lvCtdwbfBl/2ARSTuy1s8CgFAgMBAAGjggGOMIIBijAfBgNVHSMEGDAWgBRf
# WO1MMXqiYUKNUoC6s2GXGaIymzAdBgNVHQ4EFgQUaO+kMklptlI4HepDOSz0FGqe
# DIUwDgYDVR0PAQH/BAQDAgbAMAwGA1UdEwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYI
# KwYBBQUHAwgwSgYDVR0gBEMwQTA1BgwrBgEEAbIxAQIBAwgwJTAjBggrBgEFBQcC
# ARYXaHR0cHM6Ly9zZWN0aWdvLmNvbS9DUFMwCAYGZ4EMAQQCMEoGA1UdHwRDMEEw
# P6A9oDuGOWh0dHA6Ly9jcmwuc2VjdGlnby5jb20vU2VjdGlnb1B1YmxpY1RpbWVT
# dGFtcGluZ0NBUjM2LmNybDB6BggrBgEFBQcBAQRuMGwwRQYIKwYBBQUHMAKGOWh0
# dHA6Ly9jcnQuc2VjdGlnby5jb20vU2VjdGlnb1B1YmxpY1RpbWVTdGFtcGluZ0NB
# UjM2LmNydDAjBggrBgEFBQcwAYYXaHR0cDovL29jc3Auc2VjdGlnby5jb20wDQYJ
# KoZIhvcNAQEMBQADggGBALDcLsn6TzZMii/2yU/V7xhPH58Oxr/+EnrZjpIyvYTz
# 2u/zbL+fzB7lbrPml8ERajOVbudan6x08J1RMXD9hByq+yEfpv1G+z2pmnln5Xuc
# fA9MfzLMrCArNNMbUjVcRcsAr18eeZeloN5V4jwrovDeLOdZl0tB7fOX5F6N2rmX
# aNTuJR8yS2F+EWaL5VVg+RH8FelXtRvVDLJZ5uqSNIckdGa/eUFhtDKTTz9LtOUh
# 46v2JD5Q3nt8mDhAjTKp2fo/KJ6FLWdKAvApGzjpPwDqFeJKf+kJdoBKd2zQuwzk
# 5Wgph9uA46VYK8p/BTJJahKCuGdyKFIFfEfakC4NXa+vwY4IRp49lzQPLo7Wticq
# Maaqb8hE2QmCFIyLOvWIg4837bd+60FcCGbHwmL/g1ObIf0rRS9ceK4DY9rfBnHF
# H2v1d4hRVvZXyCVlrL7ZQuVzjjkLMK9VJlXTVkHpuC8K5S4HHTv2AJx6mOdkMJwS
# 4gLlJ7gXrIVpnxG+aIniGDCCBmswggTToAMCAQICEQCMQZ6TvyvOrIgGKDt2Gb08
# MA0GCSqGSIb3DQEBDAUAMFQxCzAJBgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0aWdv
# IExpbWl0ZWQxKzApBgNVBAMTIlNlY3RpZ28gUHVibGljIENvZGUgU2lnbmluZyBD
# QSBSMzYwHhcNMjQxMTE0MDAwMDAwWhcNMjcxMTE0MjM1OTU5WjBXMQswCQYDVQQG
# EwJERTEWMBQGA1UECAwNTmllZGVyc2FjaHNlbjEXMBUGA1UECgwOTWFydGluIFdp
# bGxpbmcxFzAVBgNVBAMMDk1hcnRpbiBXaWxsaW5nMIICIjANBgkqhkiG9w0BAQEF
# AAOCAg8AMIICCgKCAgEA0Z9u5pyMwenbCRSzHsUEDUXfGjL+9w05WuvBukPLvldk
# 2NSUP2eI9qAiPQE1tytz+zQD3ZRNEJrXYwtBf++I7H4pf4vC8Mbsk9N+MGm1YmSl
# HKHZirBBYTPWpvFuZFIC7guRSCuMDTquU382HR08ibtXkdl7kg6DKdMIOOZjrhTQ
# W2AfA1QbR8aG71quHgrN5VMV9O8Ed0K9lLW/dsPHlNryq9krPcSIf2LzOFMYAaTt
# SOjvltrQAeZpspyIKAn1+5ruog9wPgIaUPRr9tPRvN8vBT6xSSFlO+003oRK2z42
# dO+MV8K5RJIZxlApNcPiojbWR2kp9F/r54aie6LQcUGUABEpYVl6Qygrp551Z1YM
# L1VrXHAIcWTveXon+lbLP1IQmgWdurM5Z3hrRXkwpSOPpN5qn1rqHbV4x3PKIQHJ
# Vqe11csJYsIQhRLAHBZKZAsor3stLKhH68IjJ0ctXpR9Ut+13EGmr+fm7eCsbSF7
# jlRMd7zPTB3Za2ltMtaJ+RPIuLWoHSOOUx9C1NPNLm3NjCqqumV7aZU7tcHRdgoM
# t4X0ki5CbHEVgKb6bzjulbXOI0xvwDuoqjeTOksHfoONF7bMQQ/4EpPZDKpICdaQ
# 9RqeYJB5z9b3rrfmICfcVnEQySO73IrParF8LVcm3jgoeeq00Lwv03+gSbYonhEC
# AwEAAaOCAbMwggGvMB8GA1UdIwQYMBaAFA8qyyCHKLjsb0iuK1SmKaoXpM0MMB0G
# A1UdDgQWBBSMcmQJhB5e7gHxMGweJ8yPDAgi2zAOBgNVHQ8BAf8EBAMCB4AwDAYD
# VR0TAQH/BAIwADATBgNVHSUEDDAKBggrBgEFBQcDAzBKBgNVHSAEQzBBMDUGDCsG
# AQQBsjEBAgEDAjAlMCMGCCsGAQUFBwIBFhdodHRwczovL3NlY3RpZ28uY29tL0NQ
# UzAIBgZngQwBBAEwSQYDVR0fBEIwQDA+oDygOoY4aHR0cDovL2NybC5zZWN0aWdv
# LmNvbS9TZWN0aWdvUHVibGljQ29kZVNpZ25pbmdDQVIzNi5jcmwweQYIKwYBBQUH
# AQEEbTBrMEQGCCsGAQUFBzAChjhodHRwOi8vY3J0LnNlY3RpZ28uY29tL1NlY3Rp
# Z29QdWJsaWNDb2RlU2lnbmluZ0NBUjM2LmNydDAjBggrBgEFBQcwAYYXaHR0cDov
# L29jc3Auc2VjdGlnby5jb20wKAYDVR0RBCEwH4EdbXdpbGxpbmdAbGV0aGFsLWZv
# cmVuc2ljcy5jb20wDQYJKoZIhvcNAQEMBQADggGBAGdHQTDMJblhm/jA9axlmj7W
# l6zWZ5WajmcYG3azCwSgEK9EBnCCwlSGeEmWGnr0+cjEeoxRkgI4GhbZ5PGaW7Rs
# IoP3nfwvw9TXvEmcn33bQC57P+Qh8TJ1PJLO7re3bEesxQ+P25pY7qFKIueVuv11
# P9aa/rakWmRib40iiUAjfTIRQL10qTz6kbI9u83tfimCARdfy9AVtB0tHfWYRklK
# BMKjAy6UH9nqiRcsss1rdtVVYSxepoGdXRObQi2WOxEc8ev4eTexdMN+taIoIszG
# wjHUk9vVznOZgfKugsnuzphHzNowckVmvnHeEcnLDdqdsB0bpKauPIl/rT1Sph8D
# Sn/rqbijw0AHleCe4FArXryLDraMogtvmpoprvNaONuA5fjbAMgi89El7zQIVb7V
# O9x+tYLaD2v0lqLnptkvm86e6Brxj6Kf/ZoeAl5Iui1Xgx94QzPIWbCYPxE6CFog
# 6M03NslqsFeDs8neMeSMfJXJFzIFrslnMZiytUZiqTCCBoIwggRqoAMCAQICEDbC
# sL18Gzrno7PdNsvJdWgwDQYJKoZIhvcNAQEMBQAwgYgxCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpOZXcgSmVyc2V5MRQwEgYDVQQHEwtKZXJzZXkgQ2l0eTEeMBwGA1UE
# ChMVVGhlIFVTRVJUUlVTVCBOZXR3b3JrMS4wLAYDVQQDEyVVU0VSVHJ1c3QgUlNB
# IENlcnRpZmljYXRpb24gQXV0aG9yaXR5MB4XDTIxMDMyMjAwMDAwMFoXDTM4MDEx
# ODIzNTk1OVowVzELMAkGA1UEBhMCR0IxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRl
# ZDEuMCwGA1UEAxMlU2VjdGlnbyBQdWJsaWMgVGltZSBTdGFtcGluZyBSb290IFI0
# NjCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAIid2LlFZ50d3ei5JoGa
# VFTAfEkFm8xaFQ/ZlBBEtEFAgXcUmanU5HYsyAhTXiDQkiUvpVdYqZ1uYoZEMgtH
# ES1l1Cc6HaqZzEbOOp6YiTx63ywTon434aXVydmhx7Dx4IBrAou7hNGsKioIBPy5
# GMN7KmgYmuu4f92sKKjbxqohUSfjk1mJlAjthgF7Hjx4vvyVDQGsd5KarLW5d73E
# 3ThobSkob2SL48LpUR/O627pDchxll+bTSv1gASn/hp6IuHJorEu6EopoB1CNFp/
# +HpTXeNARXUmdRMKbnXWflq+/g36NJXB35ZvxQw6zid61qmrlD/IbKJA6COw/8lF
# SPQwBP1ityZdwuCysCKZ9ZjczMqbUcLFyq6KdOpuzVDR3ZUwxDKL1wCAxgL2Mpz7
# eZbrb/JWXiOcNzDpQsmwGQ6Stw8tTCqPumhLRPb7YkzM8/6NnWH3T9ClmcGSF22L
# EyJYNWCHrQqYubNeKolzqUbCqhSqmr/UdUeb49zYHr7ALL8bAJyPDmubNqMtuaob
# KASBqP84uhqcRY/pjnYd+V5/dcu9ieERjiRKKsxCG1t6tG9oj7liwPddXEcYGOUi
# WLm742st50jGwTzxbMpepmOP1mLnJskvZaN5e45NuzAHteORlsSuDt5t4BBRCJL+
# 5EZnnw0ezntk9R8QJyAkL6/bAgMBAAGjggEWMIIBEjAfBgNVHSMEGDAWgBRTeb9a
# qitKz1SA4dibwJ3ysgNmyzAdBgNVHQ4EFgQU9ndq3T/9ARP/FqFsggIv0Ao9FCUw
# DgYDVR0PAQH/BAQDAgGGMA8GA1UdEwEB/wQFMAMBAf8wEwYDVR0lBAwwCgYIKwYB
# BQUHAwgwEQYDVR0gBAowCDAGBgRVHSAAMFAGA1UdHwRJMEcwRaBDoEGGP2h0dHA6
# Ly9jcmwudXNlcnRydXN0LmNvbS9VU0VSVHJ1c3RSU0FDZXJ0aWZpY2F0aW9uQXV0
# aG9yaXR5LmNybDA1BggrBgEFBQcBAQQpMCcwJQYIKwYBBQUHMAGGGWh0dHA6Ly9v
# Y3NwLnVzZXJ0cnVzdC5jb20wDQYJKoZIhvcNAQEMBQADggIBAA6+ZUHtaES45aHF
# 1BGH5Lc7JYzrftrIF5Ht2PFDxKKFOct/awAEWgHQMVHol9ZLSyd/pYMbaC0IZ+XB
# W9xhdkkmUV/KbUOiL7g98M/yzRyqUOZ1/IY7Ay0YbMniIibJrPcgFp73WDnRDKtV
# utShPSZQZAdtFwXnuiWl8eFARK3PmLqEm9UsVX+55DbVIz33Mbhba0HUTEYv3yJ1
# fwKGxPBsP/MgTECimh7eXomvMm0/GPxX2uhwCcs/YLxDnBdVVlxvDjHjO1cuwbOp
# kiJGHmLXXVNbsdXUC2xBrq9fLrfe8IBsA4hopwsCj8hTuwKXJlSTrZcPRVSccP5i
# 9U28gZ7OMzoJGlxZ5384OKm0r568Mo9TYrqzKeKZgFo0fj2/0iHbj55hc20jfxvK
# 3mQi+H7xpbzxZOFGm/yVQkpo+ffv5gdhp+hv1GDsvJOtJinJmgGbBFZIThbqI+MH
# vAmMmkfb3fTxmSkop2mSJL1Y2x/955S29Gu0gSJIkc3z30vU/iXrMpWx2tS7UVfV
# P+5tKuzGtgkP7d/doqDrLF1u6Ci3TpjAZdeLLlRQZm867eVeXED58LXd1Dk6UvaA
# hvmWYXoiLz4JA5gPBcz7J311uahxCweNxE+xxxR3kT0WKzASo5G/PyDez6NHdIUK
# BeE3jDPs2ACc6CkJ1Sji4PKWVT0/MYIGMDCCBiwCAQEwaTBUMQswCQYDVQQGEwJH
# QjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMSswKQYDVQQDEyJTZWN0aWdvIFB1
# YmxpYyBDb2RlIFNpZ25pbmcgQ0EgUjM2AhEAjEGek78rzqyIBig7dhm9PDAJBgUr
# DgMCGgUAoHgwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMx
# DAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkq
# hkiG9w0BCQQxFgQUVpLfAelRuFrhDwCYIqsevVTbB8UwDQYJKoZIhvcNAQEBBQAE
# ggIAHUETFerdoY7jfaL2VFOrUQQufY8CTEL9uga1Xe24bTWzNlh+CwdBCL9WuqsR
# d5fI1kgAH4vgN2IG688VOm7w6FNJPcynpN+TOtPKCEXncBURpzJNWmk8QogHm7Tl
# Qvguae44wWuU8wybw0irSoxyQK4x1aJWzU2PokZBqTPbskRYQZX5fwQi3GmE4uWh
# Y3CW3JJ+hkr4DU5cZpxM3Mog0X9nZnbdnN4iqPX05qjb51r34xb3CfQus+iHoD6z
# eH0FK/m327mljZSxZ0PZY5GlFFraTjPIYyszKNIVaFjDCvA5pVSWexHk+5Uo/EcH
# G0dEiaJr9I/uPo6RRri9y/2DwoRt/ux3peVEdIDtWgApIm17DRg0gvcqE5K97ZKO
# M+RkKLRmbrVtc0+zvFQ/pcnmgPITzNwCi4DQ39Q3eYmCE+dl3reOMfcg7FYGCzxV
# O4TD4p5NaJbkQyiYuvG32plQve2PPFrMqmmzcHAmLlOFTK3n1hOC24gmyQoIcKg5
# tDC/ZDwgZhAumi/Ujxq3gG02tNKrLFwBoaXlymM9uor3cU9l9vHB2m2/Sa+GEqvM
# YgkTCnDiJHEC9mviaVwRG4KYkZEzxwYbQKbljzLSqPsX5tTnnLlyx2dSC5v5fLl1
# D7EsW0d+bsx8MF+H4rGXDImFCIxP7aiJjbpdKD8s5OdKLe6hggMiMIIDHgYJKoZI
# hvcNAQkGMYIDDzCCAwsCAQEwaTBVMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2Vj
# dGlnbyBMaW1pdGVkMSwwKgYDVQQDEyNTZWN0aWdvIFB1YmxpYyBUaW1lIFN0YW1w
# aW5nIENBIFIzNgIQOlJqLITOVeYdZfzMEtjpiTANBglghkgBZQMEAgIFAKB5MBgG
# CSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI1MDIyNDA2
# MDExMVowPwYJKoZIhvcNAQkEMTIEMAl9FkhvmHY+V4FA74x6Zi5kFngrY/OwnbW/
# bt0wnypMDwmYomchdz1ryRG0RE8lTTANBgkqhkiG9w0BAQEFAASCAgBy2ITGjeoX
# 45MSk89FossfpND6b74wi6fsdAbFHqDo9MGprs7SN8KX1b0t1FWHnrmXGfDo2muZ
# 1geTu0cBvr+2albYFnVBwtaiO/JBq/RXvsasplhFHitPctztG1OGvJON0ISPuR/l
# dVMb2NjL15BqhtVTAy/lZVahyex63hSYeupSwL8BxE+PbF9Lp/2twrxWA6n1DA9H
# yTg0H1JbGqRzLucRn9+J6L+vYkUK6UFsLb/P3YRKrc3aPVEwpH67W4XgtwhYtlEo
# BWuIxZ81JCZiImtwGY5Pbc9qG6htfE0rF2CeC5h+wZ3gHYObl9iCro2V5y/2Tb5l
# 7WCrw31h0pVaBfQA41WOvFq/YuZh/OVNcLLG/t8Hv0tAv8Ti2wn8VOhOgMD9zEO6
# GbI9xM8sabKGb30tW+ao5sCH1fR6vecj5pEEpLRA7BZDX7smO7D8nDv/aK58tbL8
# nbvIOQdCiXVS06qhHxZcVKGNkyIUjj1iUqenGf1UIsiHE+w+vIxgYXc55chP9rHc
# /i9X11hbDXdMpqvZ6enVncxgIg2R+FbE731Sjwa93I0N6f86o3f31gseR3hheHC0
# t0cxIr8irYxqmr7KvWhf1aqd0m2xSHrwGtdNfCJrD4mU88lzW6TTlbBFmbpHKENh
# CgFlIq8Yh5baUAORfWlptPRSWvtBxPYRHQ==
# SIG # End signature block
