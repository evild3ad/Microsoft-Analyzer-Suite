# MTL-Analyzer v0.1
#
# @author:    Martin Willing
# @copyright: Copyright (c) 2024 Martin Willing. All rights reserved.
# @contact:   Any feedback or suggestions are always welcome and much appreciated - mwilling@lethal-forensics.com
# @url:       https://lethal-forensics.com/
# @date:      2024-08-20
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
# ImportExcel v7.8.9 (2024-06-21)
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
# Release Date: 2024-08-20
# Initial Release
#
#
# Tested on Windows 10 Pro (x64) Version 22H2 (10.0.19045.4780) and PowerShell 5.1 (5.1.19041.4780)
# Tested on Windows 10 Pro (x64) Version 22H2 (10.0.19045.4780) and PowerShell 7.4.4
#
#
#############################################################################################################################################################################################
#############################################################################################################################################################################################

<#
.SYNOPSIS
  MTL-Analyzer v0.1 - Automated Processing of M365 Message Trace Logs for DFIR

.DESCRIPTION
  MTL-Analyzer.ps1 is a PowerShell script utilized to simplify the analysis of M365 Message Trace Logs extracted via "Microsoft Extractor Suite" by Invictus Incident Response.

  https://microsoft-365-extractor-suite.readthedocs.io/en/latest/functionality/MessageTraceLog.html

  Single User Audit

.PARAMETER OutputDir
  Specifies the output directory. Default is "$env:USERPROFILE\Desktop\MTL-Analyzer".

.PARAMETER Path
  Specifies the path to the CSV-based input file (<UPN>-MTL.csv).

.EXAMPLE
  PS> .\MTL-Analyzer.ps1

.EXAMPLE
  PS> .\MTL-Analyzer.ps1 -Path "$env:USERPROFILE\Desktop\<UPN>-MTL.csv"

.EXAMPLE
  PS> .\MTL-Analyzer.ps1 -Path "H:\Microsoft-Extractor-Suite\<UPN>-MTL.csv" -OutputDir "H:\Microsoft-Analyzer-Suite\MTL-Analyzer"

.NOTES
  Author - Martin Willing

.LINK
  https://lethal-forensics.com/
#>

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
    $script:OUTPUT_FOLDER = "$env:USERPROFILE\Desktop\MTL-Analyzer" # Default
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
        $script:OUTPUT_FOLDER = $OutputDir
    }
}

# Tools

# IPinfo CLI
$script:IPinfo = "$SCRIPT_DIR\Tools\IPinfo\ipinfo.exe"

# IPinfo CLI - Access Token
$script:Token = "access_token" # Please insert your Access Token here (Default: access_token)

# xsv
$script:xsv = "$SCRIPT_DIR\Tools\xsv\xsv.exe"

#endregion Declarations

#############################################################################################################################################################################################

#region Header

# Windows Title
$DefaultWindowsTitle = $Host.UI.RawUI.WindowTitle
$Host.UI.RawUI.WindowTitle = "MTL-Analyzer v0.1 - Automated Processing of M365 Message Trace Logs for DFIR"

# Check if the PowerShell script is being run with admin rights
if (!([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
    Write-Host "[Error] This PowerShell script must be run with admin rights." -ForegroundColor Red
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
Function Get-FileSize() {
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
        $OpenFileDialog.Filter = "Message Trace Log Files (*-MTL.csv)|*-MTL.csv|All Files (*.*)|*.*"
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
Write-Output "MTL-Analyzer v0.1 - Automated Processing of M365 Message Trace Logs for DFIR"
Write-Output "(c) 2024 Martin Willing at Lethal-Forensics (https://lethal-forensics.com/)"
Write-Output ""

# Analysis date (ISO 8601)
$script:AnalysisDate = [datetime]::Now.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
Write-Output "Analysis date: $AnalysisDate UTC"
Write-Output ""

# Create HashTable and import 'ASN-Whitelist.csv'
$script:AsnWhitelist_HashTable = [ordered]@{}
if (Test-Path "$SCRIPT_DIR\Whitelists\ASN-Whitelist.csv")
{
    if([int](& $xsv count "$SCRIPT_DIR\Whitelists\ASN-Whitelist.csv") -gt 0)
    {
        Import-Csv "$SCRIPT_DIR\Whitelists\ASN-Whitelist.csv" -Delimiter "," | ForEach-Object { $AsnWhitelist_HashTable[$_.ASN] = $_.OrgName,$_.Info }
    }
}

# Create HashTable and import 'ASN-Blacklist.csv'
$script:AsnBlacklist_HashTable = [ordered]@{}
if (Test-Path "$SCRIPT_DIR\Blacklists\ASN-Blacklist.csv")
{
    if([int](& $xsv count "$SCRIPT_DIR\Blacklists\ASN-Blacklist.csv") -gt 0)
    {
        Import-Csv "$SCRIPT_DIR\Blacklists\ASN-Blacklist.csv" -Delimiter "," | ForEach-Object { $AsnBlacklist_HashTable[$_.ASN] = $_.OrgName,$_.Info }
    }
}

# Create HashTable and import 'Country-Blacklist.csv'
$script:CountryBlacklist_HashTable = [ordered]@{}
if (Test-Path "$SCRIPT_DIR\Blacklists\Country-Blacklist.csv")
{
    if([int](& $xsv count "$SCRIPT_DIR\Blacklists\Country-Blacklist.csv") -gt 0)
    {
        Import-Csv "$SCRIPT_DIR\Blacklists\Country-Blacklist.csv" -Delimiter "," | ForEach-Object { $CountryBlacklist_HashTable[$_."Country Name"] = $_.Country }
    }
}

#endregion Header

#############################################################################################################################################################################################

#region Analysis

# Message Trace Logs

Function Start-Processing {

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
    Stop-Transcript
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

# Check IPinfo CLI Access Token 
if ("$Token" -eq "access_token")
{
    Write-Host "[Error] No IPinfo CLI Access Token provided. Please add your personal access token in Line 149." -ForegroundColor Red
    Write-Host ""
    Stop-Transcript
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

# UserId
$script:UserId = Import-Csv -Path "$LogFile" -Delimiter "," | Group-Object SenderAddress | Sort-Object Count -Descending | Select-Object Name,Count -First 1 | Select-Object -ExpandProperty Name

# Domain
$Domain = $UserId | ForEach-Object{($_ -split ".*@")[1]}

# Input Size
$InputSize = Get-FileSize((Get-Item "$LogFile").Length)
Write-Output "[Info]  Total Input Size: $InputSize"

# Count rows of CSV (w/ thousands separators)
[int]$Count = & $xsv count "$LogFile"
$Rows = '{0:N0}' -f $Count
Write-Output "[Info]  Total Lines: $Rows"

# Processing M365 Unified Audit Logs
Write-Output "[Info]  Processing M365 Message Trace Logs ($UserId) ..."
New-Item "$OUTPUT_FOLDER\MessageTraceLogs\CSV" -ItemType Directory -Force | Out-Null
New-Item "$OUTPUT_FOLDER\MessageTraceLogs\XLSX" -ItemType Directory -Force | Out-Null

# Check Timestamp Format
$Timestamp = (Import-Csv -Path "$LogFile" -Delimiter "," | Select-Object Received -First 1).Received

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
$StartDate = (Import-Csv -Path "$LogFile" -Delimiter "," | Select-Object @{Name="Received";Expression={([DateTime]::ParseExact($_.Received, "$TimestampFormat", [cultureinfo]::InvariantCulture).ToString("yyyy-MM-dd HH:mm:ss"))}} | Sort-Object { $_.Received -as [datetime] } -Descending | Select-Object -Last 1).Received
$EndDate = (Import-Csv -Path "$LogFile" -Delimiter "," | Select-Object @{Name="Received";Expression={([DateTime]::ParseExact($_.Received, "$TimestampFormat", [cultureinfo]::InvariantCulture).ToString("yyyy-MM-dd HH:mm:ss"))}} | Sort-Object { $_.Received -as [datetime] } -Descending | Select-Object -First 1).Received
Write-Output "[Info]  Log data from $StartDate UTC until $EndDate UTC"

# XLSX

# Untouched
if (Get-Module -ListAvailable -Name ImportExcel)
{
    if (Test-Path "$LogFile")
    {
        if([int](& $xsv count -d "," "$LogFile") -gt 0)
        {
            $IMPORT = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\MessageTraceLogs\XLSX\Untouched.xlsx" -NoHyperLinkConversion * -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "MTL-Untouched" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:N1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A, C-E and G-N 
            $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["C:E"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["G:N"].Style.HorizontalAlignment="Center"
            }
        }
    }
}

# File Size (XLSX)
if (Test-Path "$OUTPUT_FOLDER\MessageTraceLogs\XLSX\Untouched.xlsx")
{
    $Size = Get-FileSize((Get-Item "$OUTPUT_FOLDER\MessageTraceLogs\XLSX\Untouched.xlsx").Length)
    Write-Output "[Info]  File Size (XLSX) : $Size"
}

# Stats
New-Item "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Inbound" -ItemType Directory -Force | Out-Null
New-Item "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Outbound" -ItemType Directory -Force | Out-Null
New-Item "$OUTPUT_FOLDER\MessageTraceLogs\Stats\XLSX\Inbound" -ItemType Directory -Force | Out-Null
New-Item "$OUTPUT_FOLDER\MessageTraceLogs\Stats\XLSX\Outbound" -ItemType Directory -Force | Out-Null

# Total Messages
[int]$TotalMessages = (Import-Csv -Path "$LogFile" -Delimiter "," | Measure-Object).Count
$TotalMessagesCount = '{0:N0}' -f $TotalMessages
Write-Output "[Info]  Total Messages: $TotalMessagesCount"

# Incoming Messages (RecipientAddress)
[int]$IncomingMessages = (Import-Csv -Path "$LogFile" -Delimiter "," | Where-Object {$_.RecipientAddress -eq "$UserId" } | Measure-Object).Count
$IncomingMessagesCount = '{0:N0}' -f $IncomingMessages

# Incoming Messages (RecipientAddress) --> Internal
[int]$IncomingMessagesFromInternal = (Import-Csv -Path "$LogFile" -Delimiter "," | Where-Object {$_.RecipientAddress -eq "$UserId"} | Where-Object {$_.SenderAddress -like "*$Domain"} | Measure-Object).Count
$IncomingMessagesFromInternalCount = '{0:N0}' -f $IncomingMessagesFromInternal

# Incoming Messages (RecipientAddress) --> External
[int]$IncomingMessagesFromExternal = (Import-Csv -Path "$LogFile" -Delimiter "," | Where-Object {$_.RecipientAddress -eq "$UserId"} | Where-Object {$_.SenderAddress -notlike "*$Domain"} | Measure-Object).Count
$IncomingMessagesFromExternalCount = '{0:N0}' -f $IncomingMessagesFromExternal

Write-Output "[Info]  Incoming Messages: $IncomingMessagesCount (Internal: $IncomingMessagesFromInternalCount, External: $IncomingMessagesFromExternalCount)"

# Outgoing Messages (SenderAddress)
[int]$OutgoingMessages = (Import-Csv -Path "$LogFile" -Delimiter "," | Where-Object {$_.SenderAddress -eq "$UserId" } | Measure-Object).Count
$OutgoingMessagesCount = '{0:N0}' -f $OutgoingMessages

# Outgoing Messages (SenderAddress) --> Internal
[int]$OutgoingMessagesToInternal = (Import-Csv -Path "$LogFile" -Delimiter "," | Where-Object {$_.SenderAddress -eq "$UserId" } | Where-Object {$_.RecipientAddress -like "*$Domain" } | Measure-Object).Count
$OutgoingMessagesToInternalCount = '{0:N0}' -f $OutgoingMessagesToInternal

# Outgoing Messages (SenderAddress) --> External
[int]$OutgoingMessagesToExternal = (Import-Csv -Path "$LogFile" -Delimiter "," | Where-Object {$_.SenderAddress -eq "$UserId" } | Where-Object {$_.RecipientAddress -notlike "*$Domain" } | Measure-Object).Count
$OutgoingMessagesToExternalCount = '{0:N0}' -f $OutgoingMessagesToExternal

Write-Output "[Info]  Outgoing Messages: $OutgoingMessagesCount (Internal: $OutgoingMessagesToInternalCount, External: $OutgoingMessagesToExternalCount)"

# Subject (Inbound)

# CSV (Stats)
$Total = (Import-Csv -Path "$LogFile" -Delimiter "," | Where-Object {$_.RecipientAddress -eq "$UserId" } | Select-Object Subject | Measure-Object).Count
Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object {$_.RecipientAddress -eq "$UserId" } | Group-Object Subject | Sort-Object Count -Descending | Select-Object @{Name='Subject'; Expression={$_.Name}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Export-Csv -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Inbound\Subjects.csv" -NoTypeInformation -Encoding UTF8

$SubjectCount = (Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object {$_.RecipientAddress -eq "$UserId" } | Select-Object Subject | Sort-Object Subject -Unique | Measure-Object).Count
Write-Output "[Info]  Subjects (Inbound): $SubjectCount"

# XLSX (Stats)
if (Get-Module -ListAvailable -Name ImportExcel)
{
    if (Test-Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Inbound\Subjects.csv")
    {
        if([int](& $xsv count -d "," "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Inbound\Subjects.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Inbound\Subjects.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\XLSX\Inbound\Subjects.xlsx" -NoHyperLinkConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Subject (Inbound)" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns B-C
            $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
            }
        }
    }
}

# Subject (Outbound)

# CSV (Stats)
$Total = (Import-Csv -Path "$LogFile" -Delimiter "," | Where-Object {$_.SenderAddress -eq "$UserId" } | Select-Object Subject | Measure-Object).Count
Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object {$_.SenderAddress -eq "$UserId" } | Group-Object Subject | Sort-Object Count -Descending | Select-Object @{Name='Subject'; Expression={$_.Name}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Export-Csv -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Outbound\Subjects.csv" -NoTypeInformation -Encoding UTF8

$SubjectCount = (Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object {$_.SenderAddress -eq "$UserId" } | Select-Object Subject | Sort-Object Subject -Unique | Measure-Object).Count
Write-Output "[Info]  Subjects (Outbound): $SubjectCount"

# XLSX (Stats)
if (Get-Module -ListAvailable -Name ImportExcel)
{
    if (Test-Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Outbound\Subjects.csv")
    {
        if([int](& $xsv count -d "," "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Outbound\Subjects.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Outbound\Subjects.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\XLSX\Outbound\Subjects.xlsx" -NoHyperLinkConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Subject (Outbound)" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns B-C
            $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
            }
        }
    }
}

# MessageId (Inbound)
$Total = (Import-Csv -Path "$LogFile" -Delimiter "," | Where-Object {$_.RecipientAddress -eq "$UserId" } | Select-Object MessageId | Measure-Object).Count
Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object {$_.RecipientAddress -eq "$UserId" } | Group-Object MessageId | Sort-Object Count -Descending | Select-Object @{Name='MessageId'; Expression={$_.Name}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Export-Csv -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Inbound\MessageIds.csv" -NoTypeInformation -Encoding UTF8

$MessageIdCount = (Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object {$_.RecipientAddress -eq "$UserId" } | Select-Object MessageId | Sort-Object MessageId -Unique | Measure-Object).Count
Write-Output "[Info]  MessageIds (Inbound): $MessageIdCount"

# XLSX (Stats)
if (Get-Module -ListAvailable -Name ImportExcel)
{
    if (Test-Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Inbound\MessageIds.csv")
    {
        if([int](& $xsv count -d "," "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Inbound\MessageIds.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Inbound\MessageIds.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\XLSX\Inbound\MessageIds.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "MessageId (Outbound)" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-C
            $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
            }
        }
    }
}

# MessageId (Outbound)
$Total = (Import-Csv -Path "$LogFile" -Delimiter "," | Where-Object {$_.SenderAddress -eq "$UserId" } | Select-Object MessageId | Measure-Object).Count
Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object {$_.SenderAddress -eq "$UserId" } | Group-Object MessageId | Sort-Object Count -Descending | Select-Object @{Name='MessageId'; Expression={$_.Name}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Export-Csv -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Outbound\MessageIds.csv" -NoTypeInformation -Encoding UTF8

$MessageIdCount = (Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object {$_.SenderAddress -eq "$UserId" } | Select-Object MessageId | Sort-Object MessageId -Unique | Measure-Object).Count
Write-Output "[Info]  MessageIds (Outbound): $MessageIdCount"

# XLSX (Stats)
if (Get-Module -ListAvailable -Name ImportExcel)
{
    if (Test-Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Outbound\MessageIds.csv")
    {
        if([int](& $xsv count -d "," "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Outbound\MessageIds.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Outbound\MessageIds.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\XLSX\Outbound\MessageIds.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "MessageId (Outbound)" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-C
            $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
            }
        }
    }
}

# MessageTraceId (Inbound)

# CSV (Stats)
$Total = (Import-Csv -Path "$LogFile" -Delimiter "," | Where-Object {$_.RecipientAddress -eq "$UserId" } | Select-Object MessageTraceId | Measure-Object).Count
Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object {$_.RecipientAddress -eq "$UserId" } | Group-Object MessageTraceId | Sort-Object Count -Descending | Select-Object @{Name='MessageTraceId'; Expression={$_.Name}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Export-Csv -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Inbound\MessageTraceIds.csv" -NoTypeInformation -Encoding UTF8

$MessageTraceIdCount = (Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object {$_.RecipientAddress -eq "$UserId" } | Select-Object MessageTraceId | Sort-Object MessageTraceId -Unique | Measure-Object).Count
Write-Output "[Info]  MessageTraceIds (Inbound): $MessageTraceIdCount"

# XLSX (Stats)
if (Get-Module -ListAvailable -Name ImportExcel)
{
    if (Test-Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Inbound\MessageTraceIds.csv")
    {
        if([int](& $xsv count -d "," "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Inbound\MessageTraceIds.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Inbound\MessageTraceIds.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\XLSX\Inbound\MessageTraceIds.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "MessageTraceId (Inbound)" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-C
            $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
            }
        }
    }
}

# MessageTraceId (Outbound)

# CSV (Stats)
$Total = (Import-Csv -Path "$LogFile" -Delimiter "," | Where-Object {$_.SenderAddress -eq "$UserId" } | Select-Object MessageTraceId | Measure-Object).Count
Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object {$_.SenderAddress -eq "$UserId" } | Group-Object MessageTraceId | Sort-Object Count -Descending | Select-Object @{Name='MessageTraceId'; Expression={$_.Name}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Export-Csv -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Outbound\MessageTraceIds.csv" -NoTypeInformation -Encoding UTF8

$MessageTraceIdCount = (Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object {$_.SenderAddress -eq "$UserId" } | Select-Object MessageTraceId | Sort-Object MessageTraceId -Unique | Measure-Object).Count
Write-Output "[Info]  MessageTraceIds (Outbound): $MessageTraceIdCount"

# XLSX (Stats)
if (Get-Module -ListAvailable -Name ImportExcel)
{
    if (Test-Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Outbound\MessageTraceIds.csv")
    {
        if([int](& $xsv count -d "," "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Outbound\MessageTraceIds.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Outbound\MessageTraceIds.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\XLSX\Outbound\MessageTraceIds.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "MessageTraceId (Outbound)" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-C
            $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
            }
        }
    }
}

# Status (Inbound)
Write-Output "[Info]  Tracking the Delivery Status of all Inbound Messages ..."

# CSV (Stats)
$Total = (Import-Csv -Path "$LogFile" -Delimiter "," | Where-Object {$_.RecipientAddress -eq "$UserId" } | Select-Object Status | Measure-Object).Count
Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object {$_.RecipientAddress -eq "$UserId" } | Group-Object Status | Sort-Object Count -Descending | Select-Object @{Name='Status'; Expression={$_.Name}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Export-Csv -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Inbound\Status.csv" -NoTypeInformation -Encoding UTF8
[int]$Failed = (Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object {$_.RecipientAddress -eq "$UserId" } | Where-Object {$_.Status -eq 'Failed' } | Measure-Object).Count
[int]$Delivered = (Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object {$_.RecipientAddress -eq "$UserId" } | Where-Object {$_.Status -eq 'Delivered' } | Measure-Object).Count
[int]$FilteredAsSpam = (Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object {$_.RecipientAddress -eq "$UserId" } | Where-Object {$_.Status -eq 'FilteredAsSpam' } | Measure-Object).Count
[int]$Quarantined = (Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object {$_.RecipientAddress -eq "$UserId" } | Where-Object {$_.Status -eq 'Quarantined' } | Measure-Object).Count
$FailedCount = '{0:N0}' -f $Failed
$DeliveredCount = '{0:N0}' -f $Delivered
$FilteredAsSpamCount = '{0:N0}' -f $FilteredAsSpam
$QuarantinedCount = '{0:N0}' -f $Quarantined
Write-Output "[Info]  Delivered (Inbound): $DeliveredCount"
Write-Output "[Info]  Failed (Inbound): $FailedCount"
Write-Output "[Info]  FilteredAsSpam (Inbound): $FilteredAsSpamCount"
Write-Output "[Info]  Quarantined (Inbound): $QuarantinedCount"

# XLSX (Stats)
if (Get-Module -ListAvailable -Name ImportExcel)
{
    if (Test-Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Inbound\Status.csv")
    {
        if([int](& $xsv count -d "," "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Inbound\Status.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Inbound\Status.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\XLSX\Inbound\Status.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Status (Inbound)" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-C
            $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
            }
        }
    }
}

# Add Worksheet w/ Pie Chart (Inbound)
$ExcelChart = New-ExcelChartDefinition -XRange Status -YRange Count -ChartType Pie -ShowPercent -Title "Delivery Status (Inbound)" -LegendPosition Bottom
$IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\XLSX\Inbound\Status.xlsx" -Append -WorksheetName "Pie Chart" -ExcelChartDefinition $ExcelChart -AutoNameRange

# Status (Outbound)
Write-Output "[Info]  Tracking the Delivery Status of all Outbound Messages ..."

# CSV (Stats)
$Total = (Import-Csv -Path "$LogFile" -Delimiter "," | Where-Object {$_.SenderAddress -eq "$UserId" } | Select-Object Status | Measure-Object).Count
Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object {$_.SenderAddress -eq "$UserId" } | Group-Object Status | Sort-Object Count -Descending | Select-Object @{Name='Status'; Expression={$_.Name}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Export-Csv -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Outbound\Status.csv" -NoTypeInformation -Encoding UTF8
[int]$Failed = (Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object {$_.SenderAddress -eq "$UserId" } | Where-Object {$_.Status -eq 'Failed' } | Measure-Object).Count
[int]$Delivered = (Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object {$_.SenderAddress -eq "$UserId" } | Where-Object {$_.Status -eq 'Delivered' } | Measure-Object).Count
[int]$FilteredAsSpam = (Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object {$_.SenderAddress -eq "$UserId" } | Where-Object {$_.Status -eq 'FilteredAsSpam' } | Measure-Object).Count
[int]$Quarantined = (Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object {$_.SenderAddress -eq "$UserId" } | Where-Object {$_.Status -eq 'Quarantined' } | Measure-Object).Count
$FailedCount = '{0:N0}' -f $Failed
$DeliveredCount = '{0:N0}' -f $Delivered
$FilteredAsSpamCount = '{0:N0}' -f $FilteredAsSpam
$QuarantinedCount = '{0:N0}' -f $Quarantined
Write-Output "[Info]  Delivered (Outbound): $DeliveredCount"
Write-Output "[Info]  Failed (Outbound): $FailedCount"
Write-Output "[Info]  FilteredAsSpam (Outbound): $FilteredAsSpamCount"
Write-Output "[Info]  Quarantined (Outbound): $QuarantinedCount"

# XLSX (Stats)
if (Get-Module -ListAvailable -Name ImportExcel)
{
    if (Test-Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Outbound\Status.csv")
    {
        if([int](& $xsv count -d "," "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Outbound\Status.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Outbound\Status.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\XLSX\Outbound\Status.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Status (Outbound)" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-C
            $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
            }
        }
    }
}

# Add Worksheet w/ Pie Chart (Outbound)
$ExcelChart = New-ExcelChartDefinition -XRange Status -YRange Count -ChartType Pie -ShowPercent -Title "Delivery Status (Outbound)" -LegendPosition Bottom
$IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\XLSX\Outbound\Status.xlsx" -Append -WorksheetName "Pie Chart" -ExcelChartDefinition $ExcelChart -AutoNameRange

# Delivery Status
#
# https://learn.microsoft.com/en-us/exchange/monitoring/trace-an-email-message/message-trace-modern-eac#delivery-status
#
# Delivered      - The message was successfully delivered to the intended destination.
# Expanded       - A distribution group recipient was expanded before delivery to the individual members of the group.
# Failed         - The message wasn't delivered.
# FilteredAsSpam - The message was identified as spam, and was rejected or blocked (not quarantined).
# Pending        - Delivery of the message is being attempted or reattempted.
# Quarantined    - The message was quarantined (as spam, bulk mail, or phishing).
# Resolved       - The message was redirected to a new recipient address based on an Active Directory look up. When this event happens, the original recipient address is listed in a separate row in the message trace along with the final delivery status for the message.

}

Start-Processing

#############################################################################################################################################################################################

Function Get-IPLocation {

# Count IP addresses
Write-Output "[Info]  Parsing Message Trace Logs for FromIP Property ..."
New-Item "$OUTPUT_FOLDER\FromIP" -ItemType Directory -Force | Out-Null
$Data = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Select-Object -ExpandProperty FromIP | Where-Object { $_.Trim() -ne "" }

$Unique = $Data | Sort-Object -Unique
$Unique | Out-File "$OUTPUT_FOLDER\FromIP\IP-All.txt"

$Count = ($Unique | Measure-Object).Count
$Total = ($Data | Measure-Object).Count
Write-Output "[Info]  $Count IP addresses found ($Total)"

# IPv4
# https://ipinfo.io/bogon
$IPv4 = "(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
$Private = "^(192\.168|10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.)"
$Special = "^(0\.0\.0\.0|127\.0\.0\.1|169\.254\.|224\.0\.0)"
Get-Content "$OUTPUT_FOLDER\FromIP\IP-All.txt" | Select-String -Pattern $IPv4 -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique -Property { [System.Version]$_ } | Out-File "$OUTPUT_FOLDER\FromIP\IPv4-All.txt"
Get-Content "$OUTPUT_FOLDER\FromIP\IP-All.txt" | Select-String -Pattern $IPv4 -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique -Property { [System.Version]$_ } | Where-Object {$_ -notmatch $Private} | Where-Object {$_ -notmatch $Special} | Out-File "$OUTPUT_FOLDER\FromIP\IPv4.txt"

# Count
$Total = (Get-Content "$OUTPUT_FOLDER\FromIP\IPv4-All.txt" | Measure-Object).Count # Public (Unique) + Private (Unique) --> Note: Extracts IPv4 addresses of IPv4-compatible IPv6 addresses.
$Public = (Get-Content "$OUTPUT_FOLDER\FromIP\IPv4.txt" | Measure-Object).Count # Public (Unique)
Write-Output "[Info]  $Public Public IPv4 addresses found ($Total)"

# IPv6
# https://ipinfo.io/bogon
$IPv6 = ":(?::[a-f\d]{1,4}){0,5}(?:(?::[a-f\d]{1,4}){1,2}|:(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})))|[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}|:)|(?::(?:[a-f\d]{1,4})?|(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))))|:(?:(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|[a-f\d]{1,4}(?::[a-f\d]{1,4})?|))|(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|:[a-f\d]{1,4}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){0,2})|:))|(?:(?::[a-f\d]{1,4}){0,2}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:))|(?:(?::[a-f\d]{1,4}){0,3}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:))|(?:(?::[a-f\d]{1,4}){0,4}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:))"
$Bogon = "^(::1|::ffff:|100::|2001:10::|2001:db8::|fc00::|fe80::|fec0::|ff00::)"
Get-Content "$OUTPUT_FOLDER\FromIP\IP-All.txt" | Select-String -Pattern $IPv6 -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique | Out-File "$OUTPUT_FOLDER\FromIP\IPv6-All.txt"
Get-Content "$OUTPUT_FOLDER\FromIP\IP-All.txt" | ForEach-Object{($_ -split "\s+")[5]} | Select-String -Pattern $IPv6 -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique | Where-Object {$_ -notmatch $Bogon} | Out-File "$OUTPUT_FOLDER\FromIP\IPv6.txt"

# Count
$Total = (Get-Content "$OUTPUT_FOLDER\FromIP\IPv6-All.txt" | Measure-Object).Count # including Bogus IPv6 addresses (e.g. IPv4-compatible IPv6 addresses)
$Public = (Get-Content "$OUTPUT_FOLDER\FromIP\IPv6.txt" | Measure-Object).Count
Write-Output "[Info]  $Public Public IPv6 addresses found ($Total)"

# IP.txt
Write-Output "IPAddress" | Out-File "$OUTPUT_FOLDER\FromIP\IP.txt" # Header

# IPv4.txt
if (Test-Path "$OUTPUT_FOLDER\FromIP\IPv4.txt")
{
    if ((Get-Item "$OUTPUT_FOLDER\FromIP\IPv4.txt").Length -gt 0kb)
    {
        Get-Content -Path "$OUTPUT_FOLDER\FromIP\IPv4.txt" | Out-File "$OUTPUT_FOLDER\FromIP\IP.txt" -Append
    }
}

# IPv6.txt
if (Test-Path "$OUTPUT_FOLDER\FromIP\IPv6.txt")
{
    if ((Get-Item "$OUTPUT_FOLDER\FromIP\IPv6.txt").Length -gt 0kb)
    {
        Get-Content -Path "$OUTPUT_FOLDER\FromIP\IPv6.txt" | Out-File "$OUTPUT_FOLDER\FromIP\IP.txt" -Append
    }
}

# IP (Inbound)
New-Item "$OUTPUT_FOLDER\FromIP\Inbound" -ItemType Directory -Force | Out-Null
$Data = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object {$_.RecipientAddress -eq "$UserId" }  | Select-Object -ExpandProperty FromIP | Where-Object { $_.Trim() -ne "" }
$Unique = $Data | Sort-Object -Unique
$Unique | Out-File "$OUTPUT_FOLDER\FromIP\Inbound\IP-All.txt"

# IPv4 (Inbound)
Get-Content "$OUTPUT_FOLDER\FromIP\Inbound\IP-All.txt" | Select-String -Pattern $IPv4 -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique -Property { [System.Version]$_ } | Out-File "$OUTPUT_FOLDER\FromIP\Inbound\IPv4-All.txt"
Get-Content "$OUTPUT_FOLDER\FromIP\Inbound\IP-All.txt" | Select-String -Pattern $IPv4 -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique -Property { [System.Version]$_ } | Where-Object {$_ -notmatch $Private} | Where-Object {$_ -notmatch $Special} | Out-File "$OUTPUT_FOLDER\FromIP\Inbound\IPv4.txt"

# IPv6 (Inbound)
Get-Content "$OUTPUT_FOLDER\FromIP\Inbound\IP-All.txt" | Select-String -Pattern $IPv6 -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique | Out-File "$OUTPUT_FOLDER\FromIP\Inbound\IPv6-All.txt"
Get-Content "$OUTPUT_FOLDER\FromIP\Inbound\IP-All.txt" | ForEach-Object{($_ -split "\s+")[5]} | Select-String -Pattern $IPv6 -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique | Where-Object {$_ -notmatch $Bogon} | Out-File "$OUTPUT_FOLDER\FromIP\Inbound\IPv6.txt"

# IP-Inbound.txt
Write-Output "IPAddress" | Out-File "$OUTPUT_FOLDER\FromIP\Inbound\IP.txt" # Header

# IPv4.txt
if (Test-Path "$OUTPUT_FOLDER\FromIP\Inbound\IPv4.txt")
{
    if ((Get-Item "$OUTPUT_FOLDER\FromIP\Inbound\IPv4.txt").Length -gt 0kb)
    {
        Get-Content -Path "$OUTPUT_FOLDER\FromIP\Inbound\IPv4.txt" | Out-File "$OUTPUT_FOLDER\FromIP\Inbound\IP.txt" -Append
    }
}

# IPv6.txt
if (Test-Path "$OUTPUT_FOLDER\FromIP\Inbound\IPv6.txt")
{
    if ((Get-Item "$OUTPUT_FOLDER\FromIP\Inbound\IPv6.txt").Length -gt 0kb)
    {
        Get-Content -Path "$OUTPUT_FOLDER\FromIP\Inbound\IPv6.txt" | Out-File "$OUTPUT_FOLDER\FromIP\Inbound\IP.txt" -Append
    }
}

# IP (Outbound)
New-Item "$OUTPUT_FOLDER\FromIP\Outbound" -ItemType Directory -Force | Out-Null
$Data = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object {$_.SenderAddress -eq "$UserId" }  | Select-Object -ExpandProperty FromIP | Where-Object { $_.Trim() -ne "" }
$Unique = $Data | Sort-Object -Unique
$Unique | Out-File "$OUTPUT_FOLDER\FromIP\Outbound\IP-All.txt"

# IPv4 (Outbound)
Get-Content "$OUTPUT_FOLDER\FromIP\Outbound\IP-All.txt" | Select-String -Pattern $IPv4 -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique -Property { [System.Version]$_ } | Out-File "$OUTPUT_FOLDER\FromIP\Outbound\IPv4-All.txt"
Get-Content "$OUTPUT_FOLDER\FromIP\Outbound\IP-All.txt" | Select-String -Pattern $IPv4 -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique -Property { [System.Version]$_ } | Where-Object {$_ -notmatch $Private} | Where-Object {$_ -notmatch $Special} | Out-File "$OUTPUT_FOLDER\FromIP\Outbound\IPv4.txt"


# IPv6 (Outbound)
Get-Content "$OUTPUT_FOLDER\FromIP\Outbound\IP-All.txt" | Select-String -Pattern $IPv6 -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique | Out-File "$OUTPUT_FOLDER\FromIP\Outbound\IPv6-All.txt"
Get-Content "$OUTPUT_FOLDER\FromIP\Outbound\IP-All.txt" | ForEach-Object{($_ -split "\s+")[5]} | Select-String -Pattern $IPv6 -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique | Where-Object {$_ -notmatch $Bogon} | Out-File "$OUTPUT_FOLDER\FromIP\Outbound\IPv6.txt"

# IP-Outbound.txt
Write-Output "IPAddress" | Out-File "$OUTPUT_FOLDER\FromIP\Outbound\IP.txt" # Header

# IPv4.txt
if (Test-Path "$OUTPUT_FOLDER\FromIP\Outbound\IPv4.txt")
{
    if ((Get-Item "$OUTPUT_FOLDER\FromIP\Outbound\IPv4.txt").Length -gt 0kb)
    {
        Get-Content -Path "$OUTPUT_FOLDER\FromIP\Outbound\IPv4.txt" | Out-File "$OUTPUT_FOLDER\FromIP\Outbound\IP.txt" -Append
    }
}

# IPv6.txt
if (Test-Path "$OUTPUT_FOLDER\FromIP\Outbound\IPv6.txt")
{
    if ((Get-Item "$OUTPUT_FOLDER\FromIP\Outbound\IPv6.txt").Length -gt 0kb)
    {
        Get-Content -Path "$OUTPUT_FOLDER\FromIP\Outbound\IPv6.txt" | Out-File "$OUTPUT_FOLDER\FromIP\Outbound\IP.txt" -Append
    }
}

# IPinfo CLI (50k lookups per month, Geolocation data only)
if (Test-Path "$($IPinfo)")
{
    if (Test-Path "$OUTPUT_FOLDER\FromIP\IP.txt")
    {
        if ((Get-Item "$OUTPUT_FOLDER\FromIP\IP.txt").Length -gt 0kb)
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
                    New-Item "$OUTPUT_FOLDER\FromIP\IPinfo" -ItemType Directory -Force | Out-Null

                    # All
                    Get-Content "$OUTPUT_FOLDER\FromIP\IP.txt" | & $IPinfo map | Out-File "$OUTPUT_FOLDER\FromIP\IPinfo\Map-All.txt"

                    # Inbound
                    Get-Content "$OUTPUT_FOLDER\FromIP\Inbound\IP.txt" | & $IPinfo map | Out-File "$OUTPUT_FOLDER\FromIP\IPinfo\Map-Inbound.txt"

                    # Outbound
                    Get-Content "$OUTPUT_FOLDER\FromIP\Outbound\IP.txt" | & $IPinfo map | Out-File "$OUTPUT_FOLDER\FromIP\IPinfo\Map-Outbound.txt"

                    # Access Token
                    # https://ipinfo.io/signup?ref=cli
                    if (!("$Token" -eq "access_token"))
                    {
                        # Summarize IPs
                        # https://ipinfo.io/summarize-ips

                        # TXT (lists VPNs)
                        Get-Content -Path "$OUTPUT_FOLDER\FromIP\IP.txt" | & $IPinfo summarize -t $Token | Out-File "$OUTPUT_FOLDER\FromIP\IPinfo\Summary.txt"

                        # CSV --> No Privacy Detection --> Standard ($249/month w/ 250k lookups)
                        Get-Content -Path "$OUTPUT_FOLDER\FromIP\IP.txt" | & $IPinfo --csv -t $Token | Out-File "$OUTPUT_FOLDER\FromIP\IPinfo\IPinfo.csv"

                        # Custom CSV (Free)
                        if (Test-Path "$OUTPUT_FOLDER\FromIP\IPinfo\IPinfo.csv")
                        {
                            if([int](& $xsv count "$OUTPUT_FOLDER\FromIP\IPinfo\IPinfo.csv") -gt 0)
                            {
                                $Import = Import-Csv "$OUTPUT_FOLDER\FromIP\IPinfo\IPinfo.csv" -Delimiter ","

                                $Import | Foreach-Object {

                                    New-Object -TypeName PSObject -Property @{
                                        "IP"           = $_ | Select-Object -ExpandProperty ip
                                        "City"         = $_ | Select-Object -ExpandProperty city
                                        "Region"       = $_ | Select-Object -ExpandProperty region
                                        "Country"      = $_ | Select-Object -ExpandProperty country
                                        "Country Name" = $_ | Select-Object -ExpandProperty country_name
                                        "EU"           = $_ | Select-Object -ExpandProperty isEU
                                        "Location"     = $_ | Select-Object -ExpandProperty loc
                                        "ASN"          = $_ | Select-Object -ExpandProperty org | ForEach-Object{($_ -split "\s+")[0]}
                                        "OrgName"      = $_ | Select-Object -ExpandProperty org | ForEach-Object { $_ -replace "^AS[0-9]+ " } # OrgName
                                        "Postal Code"  = $_ | Select-Object -ExpandProperty postal
                                        "Timezone"     = $_ | Select-Object -ExpandProperty timezone
                                        }
                                } | Select-Object "IP","City","Region","Country","Country Name","EU","Location","ASN","OrgName","Postal Code","Timezone" | Sort-Object {$_.ip -as [Version]} | ConvertTo-Csv -NoTypeInformation -Delimiter "," | Out-File "$OUTPUT_FOLDER\FromIP\IPinfo\IPinfo-Custom.csv"
                            }
                        }

                        # Custom XLSX (Free)
                        if (Get-Module -ListAvailable -Name ImportExcel)
                        {
                            if (Test-Path "$OUTPUT_FOLDER\FromIP\IPinfo\IPinfo-Custom.csv")
                            {
                                if([int](& $xsv count "$OUTPUT_FOLDER\FromIP\IPinfo\IPinfo-Custom.csv") -gt 0)
                                {
                                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\FromIP\IPinfo\IPinfo-Custom.csv" -Delimiter "," | Sort-Object {$_.ip -as [Version]}
                                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\FromIP\IPinfo\IPinfo-Custom.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -IncludePivotTable -PivotTableName "PivotTable" -PivotRows "Country Name" -PivotData @{"IP"="Count"} -WorkSheetname "IPinfo (Free)" -CellStyleSB {
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
                        if (Test-Path "$OUTPUT_FOLDER\FromIP\IPinfo\IPinfo-Custom.csv")
                        {
                            if([int](& $xsv count "$OUTPUT_FOLDER\FromIP\IPinfo\IPinfo-Custom.csv") -gt 0)
                            {
                                # Suspicious ASN (Autonomous System Number)
                                $Data = Import-Csv -Path "$OUTPUT_FOLDER\FromIP\IPinfo\IPinfo-Custom.csv" -Delimiter ","
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
                                $Data = Import-Csv -Path "$OUTPUT_FOLDER\FromIP\IPinfo\IPinfo-Custom.csv" -Delimiter ","
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
                            if (Test-Path "$OUTPUT_FOLDER\FromIP\IPinfo\IPinfo.csv")
                            {
                                if([int](& $xsv count "$OUTPUT_FOLDER\FromIP\IPinfo\IPinfo.csv") -gt 0)
                                {
                                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\FromIP\IPinfo\IPinfo.csv" -Delimiter "," | Select-Object ip,city,region,country,country_name,isEU,loc,org,postal,timezone | Sort-Object {$_.ip -as [Version]}
                                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\FromIP\IPinfo\IPinfo.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "IPinfo (Free)" -CellStyleSB {
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
                        $script:HashTable = @{}
                        if (Test-Path "$OUTPUT_FOLDER\FromIP\IPinfo\IPinfo-Custom.csv")
                        {
                            if([int](& $xsv count "$OUTPUT_FOLDER\FromIP\IPinfo\IPinfo-Custom.csv") -gt 0)
                            {
                                Import-Csv "$OUTPUT_FOLDER\FromIP\IPinfo\IPinfo-Custom.csv" -Delimiter "," -Encoding UTF8 | ForEach-Object { $HashTable[$_.IP] = $_.City,$_.Country,$_."Country Name",$_.ASN,$_.OrgName }

                                # Count Ingested Properties
                                $Count = $HashTable.Count
                                Write-Output "[Info]  Initializing 'IPinfo-Custom.csv' Lookup Table ($Count) ..."
                            }
                        }

                        # Hunt
                        Write-Output "[Info]  Creating Enhanced Message Trace Report (Hunt View) ..."
                        $Records = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8

                        # CSV
                        $Results = @()
                        ForEach($Record in $Records)
                        {
                            # FromIP
                            $IP = $Record.FromIP | ForEach-Object {$_ -replace "^::ffff:"} # Remove Prefix of IPv4-mapped IPv6 address

                            # Check if HashTable contains IP
                            if($HashTable.ContainsKey("$IP"))
                            {
                                $City        = $HashTable["$IP"][0]
                                $Country     = $HashTable["$IP"][1]
                                $CountryName = $HashTable["$IP"][2]
                                $ASN         = $HashTable["$IP"][3]
                                $OrgName     = $HashTable["$IP"][4]
                            }
                            else
                            {
                                $City        = ""
                                $Country     = ""
                                $CountryName = ""
                                $ASN         = ""
                                $OrgName     = ""
                            }

                            # Direction
                            if($Record.RecipientAddress -eq "$UserId")
                            {
                                $Direction = "Inbound" # Messages sent to recipients in your organization.
                            }
                            else
                            {
                                $Direction = "Outbound" # Messages sent from users in your organization.
                            }

                            $Line = [PSCustomObject]@{
                                "Received"         = ($Record | Select-Object @{Name="Received";Expression={([DateTime]::ParseExact($_.Received, "$TimestampFormat", [cultureinfo]::InvariantCulture).ToString("yyyy-MM-dd HH:mm:ss"))}}).Received
                                "SenderAddress"    = $Record.SenderAddress
                                "RecipientAddress" = $Record.RecipientAddress
                                "Subject"          = $Record.Subject
                                "Direction"        = $Direction
                                "Status"           = $Record.Status
                                "MessageId"        = $Record.MessageId
                                "MessageTraceId"   = $Record.MessageTraceId
                                "Size"             = $Record.Size
                                "ToIP"             = $Record.ToIP
                                "FromIP"           = $IP
                                "City"             = $City
                                "Country"          = $Country
                                "Country Name"     = $CountryName
                                "ASN"              = $ASN
                                "OrgName"          = $OrgName
                            }

                            $Results += $Line
                        }

                        $Results | Export-Csv -Path "$OUTPUT_FOLDER\MessageTraceLogs\CSV\Hunt.csv" -NoTypeInformation -Encoding UTF8

                        # XLSX
                        if (Get-Module -ListAvailable -Name ImportExcel)
                        {
                            if (Test-Path "$OUTPUT_FOLDER\MessageTraceLogs\CSV\Hunt.csv")
                            {
                                if([int](& $xsv count "$OUTPUT_FOLDER\MessageTraceLogs\CSV\Hunt.csv") -gt 0)
                                {
                                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\MessageTraceLogs\CSV\Hunt.csv" -Delimiter ","
                                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\MessageTraceLogs\XLSX\Hunt.xlsx" -NoHyperLinkConversion * -NoNumberConversion * -FreezePane 2,7 -BoldTopRow -AutoSize -AutoFilter -IncludePivotTable -PivotTableName "PivotTable" -WorkSheetname "Hunt" -CellStyleSB {
                                    param($WorkSheet)
                                    # BackgroundColor and FontColor for specific cells of TopRow
                                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                    Set-Format -Address $WorkSheet.Cells["A1:P1"] -BackgroundColor $BackgroundColor -FontColor White
                                    # HorizontalAlignment "Center" of columns A-P
                                    $WorkSheet.Cells["A:P"].Style.HorizontalAlignment="Center"

                                    # Iterating over the ASN-Whitelist HashTable
                                    foreach ($ASN in $AsnWhitelist_HashTable.Keys) 
                                    {
                                        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$O1)))' -f $ASN
                                        Add-ConditionalFormatting -Address $WorkSheet.Cells["O:O"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Green
                                    }
                                    
                                    # Iterating over the ASN-Blacklist HashTable
                                    foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
                                    {
                                        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$O1)))' -f $ASN
                                        Add-ConditionalFormatting -Address $WorkSheet.Cells["O:O"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
                                    }

                                    # Iterating over the Country-Blacklist HashTable
                                    foreach ($Country in $CountryBlacklist_HashTable.Keys) 
                                    {
                                        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$N1)))' -f $Country
                                        Add-ConditionalFormatting -Address $WorkSheet.Cells["N:N"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
                                    }

                                    # ConditionalFormatting - Status
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["F:F"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Quarantined",$F1)))' -BackgroundColor Red
                                                        
                                    }
                                }
                            }
                        }

                        # ASN 
                        
                        # CSV (Stats)
                        if (Test-Path "$OUTPUT_FOLDER\MessageTraceLogs\CSV\Hunt.csv")
                        {
                            if([int](& $xsv count "$OUTPUT_FOLDER\MessageTraceLogs\CSV\Hunt.csv") -gt 0)
                            {
                                $Total = (Import-Csv -Path "$OUTPUT_FOLDER\MessageTraceLogs\CSV\Hunt.csv" -Delimiter "," | Select-Object ASN | Where-Object {$_.ASN -ne '' } | Measure-Object).Count
                                Import-Csv -Path "$OUTPUT_FOLDER\MessageTraceLogs\CSV\Hunt.csv" -Delimiter "," | Select-Object ASN,OrgName | Where-Object {$_.ASN -ne '' } | Where-Object {$null -ne ($_.PSObject.Properties | ForEach-Object {$_.Value})} | Group-Object ASN,OrgName | Select-Object Count,@{Name='ASN'; Expression={ $_.Values[0] }},@{Name='OrgName'; Expression={ $_.Values[1] }},@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending | Export-Csv -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\ASN.csv" -NoTypeInformation -Encoding UTF8
                            }
                        }

                        # XLSX (Stats)
                        if (Get-Module -ListAvailable -Name ImportExcel)
                        {
                            if (Test-Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\ASN.csv")
                            {
                                if([int](& $xsv count -d "," "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\ASN.csv") -gt 0)
                                {
                                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\ASN.csv" -Delimiter ","
                                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\XLSX\ASN.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ASN" -CellStyleSB {
                                    param($WorkSheet)
                                    # BackgroundColor and FontColor for specific cells of TopRow
                                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                    Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor White
                                    # HorizontalAlignment "Center" of columns A-D
                                    $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"

                                    # Iterating over the ASN-Whitelist HashTable
                                    foreach ($ASN in $AsnWhitelist_HashTable.Keys) 
                                    {
                                        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$B1)))' -f $ASN
                                        Add-ConditionalFormatting -Address $WorkSheet.Cells["A:D"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Green
                                    }

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

                        # Country / Country Name

                        # CSV (Stats)
                        if (Test-Path "$OUTPUT_FOLDER\MessageTraceLogs\CSV\Hunt.csv")
                        {
                            if([int](& $xsv count "$OUTPUT_FOLDER\MessageTraceLogs\CSV\Hunt.csv") -gt 0)
                            {
                                $Total = (Import-Csv -Path "$OUTPUT_FOLDER\MessageTraceLogs\CSV\Hunt.csv" -Delimiter "," | Select-Object Country | Where-Object {$_.Country -ne '' } | Measure-Object).Count
                                Import-Csv -Path "$OUTPUT_FOLDER\MessageTraceLogs\CSV\Hunt.csv" -Delimiter "," | Select-Object Country,"Country Name" | Where-Object {$_.Country -ne '' } | Where-Object {$null -ne ($_.PSObject.Properties | ForEach-Object {$_.Value})} | Group-Object Country,"Country Name" | Select-Object Count,@{Name='Country'; Expression={ $_.Values[0] }},@{Name='Country Name'; Expression={ $_.Values[1] }},@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending | Export-Csv -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Country.csv" -NoTypeInformation -Encoding UTF8

                                # Countries
                                $Countries = (Import-Csv -Path "$OUTPUT_FOLDER\MessageTraceLogs\CSV\Hunt.csv" -Delimiter "," | Select-Object Country -Unique | Where-Object { $_.Country -ne '' } | Measure-Object).Count

                                # Cities
                                $Cities = (Import-Csv -Path "$OUTPUT_FOLDER\MessageTraceLogs\CSV\Hunt.csv" -Delimiter "," | Select-Object City -Unique | Where-Object { $_.City -ne '' } | Measure-Object).Count

                                Write-Output "[Info]  $Countries Countries and $Cities Cities found"
                            }
                        }

                        # XLSX (Stats)
                        if (Get-Module -ListAvailable -Name ImportExcel)
                        {
                            if (Test-Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Country.csv")
                            {
                                if([int](& $xsv count -d "," "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Country.csv") -gt 0)
                                {
                                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\Country.csv" -Delimiter ","
                                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\XLSX\Country.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Countries" -CellStyleSB {
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

                        # FromIP / Country Name

                        # CSV (Stats)
                        if (Test-Path "$OUTPUT_FOLDER\MessageTraceLogs\CSV\Hunt.csv")
                        {
                            if([int](& $xsv count "$OUTPUT_FOLDER\MessageTraceLogs\CSV\Hunt.csv") -gt 0)
                            {
                                $Total = (Import-Csv -Path "$OUTPUT_FOLDER\MessageTraceLogs\CSV\Hunt.csv" -Delimiter "," | Select-Object FromIP | Where-Object {$_.FromIP -ne '' } | Measure-Object).Count
                                Import-Csv -Path "$OUTPUT_FOLDER\MessageTraceLogs\CSV\Hunt.csv" -Delimiter "," -Encoding UTF8 | Select-Object FromIP,Country,"Country Name",ASN,OrgName | Where-Object {$_.FromIP -ne '' } | Where-Object {$_."Country Name" -ne '' } | Where-Object {$null -ne ($_.PSObject.Properties | ForEach-Object {$_.Value})} | Group-Object FromIP,Country,"Country Name",ASN,OrgName | Select-Object Count,@{Name='FromIP'; Expression={ $_.Values[0] }},@{Name='Country'; Expression={ $_.Values[1] }},@{Name='Country Name'; Expression={ $_.Values[2] }},@{Name='ASN'; Expression={ $_.Values[3] }},@{Name='OrgName'; Expression={ $_.Values[4] }},@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending | Export-Csv -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\FromIP.csv" -NoTypeInformation -Encoding UTF8
                            }
                        }

                        # XLSX (Stats)
                        if (Get-Module -ListAvailable -Name ImportExcel)
                        {
                            if (Test-Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\FromIP.csv")
                            {
                                if([int](& $xsv count -d "," "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\FromIP.csv") -gt 0)
                                {
                                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\MessageTraceLogs\Stats\CSV\FromIP.csv" -Delimiter ","
                                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\XLSX\FromIP.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "FromIP" -CellStyleSB {
                                    param($WorkSheet)
                                    # BackgroundColor and FontColor for specific cells of TopRow
                                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                    Set-Format -Address $WorkSheet.Cells["A1:G1"] -BackgroundColor $BackgroundColor -FontColor White
                                    # HorizontalAlignment "Center" of columns A-G
                                    $WorkSheet.Cells["A:G"].Style.HorizontalAlignment="Center"

                                    # Iterating over the ASN-Whitelist HashTable
                                    foreach ($ASN in $AsnWhitelist_HashTable.Keys) 
                                    {
                                        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$E1)))' -f $ASN
                                        Add-ConditionalFormatting -Address $WorkSheet.Cells["E:F"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Green
                                    }

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

                        # Line Charts
                        New-Item "$OUTPUT_FOLDER\MessageTraceLogs\Stats\XLSX\LineCharts" -ItemType Directory -Force | Out-Null

                        # Inbound
                        $Import = Import-Csv "$OUTPUT_FOLDER\MessageTraceLogs\CSV\Hunt.csv" -Delimiter "," -Encoding UTF8 | Where-Object { $_.Direction -eq "Inbound" } | Select-Object Received,Direction | Group-Object{($_.Received -split "\s+")[0]} | Select-Object Count,@{Name='Received'; Expression={ $_.Values[0] }} | Sort-Object { $_.Received -as [datetime] }
                        $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
                        if ($Count -gt 0)
                        {
                            $ChartDefinition = New-ExcelChartDefinition -XRange Received -YRange Count -Title "Inbound Messages" -ChartType Line -NoLegend -Width 1200
                            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\XLSX\LineCharts\Inbound.xlsx" -Append -WorksheetName "Line Chart" -AutoNameRange -ExcelChartDefinition $ChartDefinition
                        }

                        # Outbound
                        $Import = Import-Csv "$OUTPUT_FOLDER\MessageTraceLogs\CSV\Hunt.csv" -Delimiter "," -Encoding UTF8 | Where-Object { $_.Direction -eq "Outbound" } | Select-Object Received,Direction | Group-Object{($_.Received -split "\s+")[0]} | Select-Object Count,@{Name='Received'; Expression={ $_.Values[0] }} | Sort-Object { $_.Received -as [datetime] }
                        $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
                        if ($Count -gt 0)
                        {
                            $ChartDefinition = New-ExcelChartDefinition -XRange Received -YRange Count -Title "Outbound Messages" -ChartType Line -NoLegend -Width 1200
                            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\MessageTraceLogs\Stats\XLSX\LineCharts\Outbound.xlsx" -Append -WorksheetName "Line Chart" -AutoNameRange -ExcelChartDefinition $ChartDefinition
                        }
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

}

Get-IPLocation

#endregion Analysis

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
Start-Sleep 1

# MessageBox UI
$MessageBody = "Status: Message Trace Log Analysis completed."
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
