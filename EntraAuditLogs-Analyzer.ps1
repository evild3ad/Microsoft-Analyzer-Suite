# EntraAuditLogs-Analyzer
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
  EntraAuditLogs-Analyzer - Automated Processing of Microsoft Entra ID Audit Logs for DFIR

.DESCRIPTION
  EntraAuditLogs-Analyzer.ps1 is a PowerShell script utilized to simplify the analysis of Microsoft Entra ID Audit Logs extracted via "Microsoft Extractor Suite" by Invictus-IR.

  https://github.com/invictus-ir/Microsoft-Extractor-Suite (Microsoft-Extractor-Suite v3.0.2)

  https://microsoft-365-extractor-suite.readthedocs.io/en/latest/functionality/Azure/AzureActiveDirectoryAuditLog.html

.PARAMETER OutputDir
  Specifies the output directory. Default is "$env:USERPROFILE\Desktop\EntraAuditLogs-Analyzer".

  Note: The subdirectory 'EntraAuditLogs-Analyzer' is automatically created.

.PARAMETER Path
  Specifies the path to the JSON-based input file (AuditLogs-Combined.json).

.EXAMPLE
  PS> .\EntraAuditLogs-Analyzer.ps1

.EXAMPLE
  PS> .\EntraAuditLogs-Analyzer.ps1 -Path "$env:USERPROFILE\Desktop\AuditLogs-Combined.json"

.EXAMPLE
  PS> .\EntraAuditLogs-Analyzer.ps1 -Path "H:\Microsoft-Extractor-Suite\AuditLogs-Combined.json" -OutputDir "H:\Microsoft-Analyzer-Suite"

.NOTES
  Author - Martin Willing

.LINK
  https://lethal-forensics.com/
#>

#############################################################################################################################################################################################
#############################################################################################################################################################################################

# How long does Microsoft Entra ID store the Audit logs data?

# Microsoft Entra ID Free      7 days
# Microsoft Entra ID P1       30 days
# Microsoft Entra ID P2       30 days

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

# Custom Colors
Add-Type -AssemblyName System.Drawing
$script:Green  = [System.Drawing.Color]::FromArgb(0,176,80) # Green
$script:Orange = [System.Drawing.Color]::FromArgb(255,192,0) # Orange

# Output Directory
if (!($OutputDir))
{
    $script:OUTPUT_FOLDER = "$env:USERPROFILE\Desktop\EntraAuditLogs-Analyzer" # Default
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
        $script:OUTPUT_FOLDER = "$OutputDir\EntraAuditLogs-Analyzer" # Custom
    }
}

# Tools

# IPinfo CLI
$script:IPinfo = "$SCRIPT_DIR\Tools\IPinfo\ipinfo.exe"

# xsv
$script:xsv = "$SCRIPT_DIR\Tools\xsv\xsv.exe"

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
$Host.UI.RawUI.WindowTitle = "EntraAuditLogs-Analyzer - Automated Processing of Microsoft Entra ID Audit Logs for DFIR"

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
        $OpenFileDialog.Filter = "Entra ID Audit Logs|AuditLogs-Combined.json|All Files (*.*)|*.*"
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
Write-Output "EntraAuditLogs-Analyzer - Automated Processing of Microsoft Entra ID Audit Logs for DFIR"
Write-Output "(c) 2025 Martin Willing at Lethal-Forensics (https://lethal-forensics.com/)"
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

#endregion Header

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Analysis

# Microsoft Entra ID Audit Logs (Last 7 days / Last 30 days)

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
if (!($Extension -eq ".json" ))
{
    Write-Host "[Error] No JSON File provided." -ForegroundColor Red
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

# Import JSON
Write-Output "[Info]  Importing JSON data ..." 
$Data = (Get-Content -Path "$LogFile" -Raw) -join "`n`r" | ConvertFrom-Json | Sort-Object { $_.activityDateTime -as [datetime] } -Descending # UTF-8 with BOM

# UserId
$UserIds = ($Data | Select-Object -ExpandProperty InitiatedBy | Select-Object -ExpandProperty User | Select-Object -ExpandProperty Id | Sort-Object -Unique).Count
if ($Count -eq 1)
{
    $UserId = ($UserIds).UserIds
    $Message = "[Info]  Processing Microsoft Entra ID Audit Logs ($UserId) ..."
}
else
{
    $Message = "[Info]  Processing Microsoft Entra ID Audit Logs [time-consuming task] ..."
}

# Input Size
$InputSize = Get-FileSize((Get-Item "$LogFile").Length)
Write-Output "[Info]  Total Input Size: $InputSize"

# Count rows of JSON (w/ thousands separators)
$Count = 0
switch -File "$LogFile" { default { ++$Count } }
$Rows = '{0:N0}' -f $Count
Write-Output "[Info]  Total Lines: $Rows"

# Time Frame
$Last  = ($Data | Sort-Object { $_.activityDateTime -as [datetime] } -Descending | Select-Object -Last 1).activityDateTime
$First = ($Data | Sort-Object { $_.activityDateTime -as [datetime] } -Descending | Select-Object -First 1).activityDateTime
$StartDate = (Get-Date $Last).ToString("yyyy-MM-dd HH:mm:ss")
$EndDate = (Get-Date $First).ToString("yyyy-MM-dd HH:mm:ss")
Write-Output "[Info]  Log data from $StartDate UTC until $EndDate UTC"

# Processing Microsoft Entra ID Audit Log
Write-Output "$Message"
New-Item "$OUTPUT_FOLDER\EntraAuditLogs\CSV" -ItemType Directory -Force | Out-Null
New-Item "$OUTPUT_FOLDER\EntraAuditLogs\XLSX" -ItemType Directory -Force | Out-Null

# Untouched
# https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.reports/get-mgauditlogdirectoryaudit?view=graph-powershell-1.0
# https://learn.microsoft.com/en-us/graph/api/resources/directoryaudit?view=graph-rest-1.0
# https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities

# CSV
$Results = [Collections.Generic.List[PSObject]]::new()
ForEach($Record in $Data)
{
    $ActorObjectId = $Record | Select-Object -ExpandProperty initiatedBy | Select-Object -ExpandProperty user | Select-Object -ExpandProperty id

    if ($null -eq $ActorObjectId)
    {
        $ActorType     = "App"
    }
    else
    {
        $ActorType     = "User"
    }

    $ActivityDateTime = $Record | Select-Object -ExpandProperty activityDateTime

    $Line = [PSCustomObject]@{
    "ActivityDateTime"          = (Get-Date $ActivityDateTime).ToString("yyyy-MM-dd HH:mm:ss.fff") # Indicates the date and time the activity was performed. The Timestamp type is always in UTC time.
    "InitiatedBy (UPN)"         = ($Record | Select-Object -ExpandProperty initiatedBy | Select-Object -ExpandProperty $ActorType | Select-Object userPrincipalName).userPrincipalName # The userPrincipalName attribute of the user.
    "TargetResources (UPN)"     = ($Record | Select-Object -ExpandProperty targetResources | Select-Object userPrincipalName | Select-Object -Index 0).userPrincipalName # When type is set to User, this includes the user name that initiated the action; null for other types.
    "UserId"                    = ($Record | Select-Object -ExpandProperty initiatedBy | Select-Object -ExpandProperty $ActorType | Select-Object id).id # Unique identifier for the identity.
    "AppDisplayName"            = ($Record | Select-Object -ExpandProperty initiatedBy | Select-Object -ExpandProperty $ActorType | Select-Object displayName).displayName # Refers to the application name displayed in the Microsoft Entra admin center.
    "AppId"                     = ($Record | Select-Object -ExpandProperty initiatedBy | Select-Object -ExpandProperty $ActorType | Select-Object appId).appId # Refers to the unique ID representing application in Microsoft Entra ID.
    "ServicePrincipalId"        = ($Record | Select-Object -ExpandProperty initiatedBy | Select-Object -ExpandProperty $ActorType | Select-Object servicePrincipalId).servicePrincipalId # Refers to the unique ID for the service principal in Microsoft Entra ID.
    "LoggedByService"           = $Record.loggedByService # Indicates information on which service initiated the activity.
    "Category"                  = $Record.category # Indicates which resource category that's targeted by the activity.
    "ActivityDisplayName"       = $Record.activityDisplayName # Indicates the activity name or the operation name.
    "OperationType"             = $Record.operationType # Indicates the type of operation that was performed.
    "Result"                    = $Record.result # Indicates the result of the activity.
    "ResultReason"              = $Record.resultReason # Indicates the reason for failure if the result is failure or timeout.
    "IPAddress"                 = ($Record | Select-Object -ExpandProperty initiatedBy | Select-Object -ExpandProperty $ActorType | Select-Object iPAddress).iPAddress # Indicates the client IP address used by user performing the activity.

    # InitiatedBy - Indicates information about the user or app initiated the activity.
    # https://learn.microsoft.com/en-us/graph/api/resources/useridentity?view=graph-rest-1.0
    # https://learn.microsoft.com/en-us/graph/api/resources/appidentity?view=graph-rest-1.0
    "UserDisplayName"           = ($Record | Select-Object -ExpandProperty initiatedBy | Select-Object -ExpandProperty $ActorType | Select-Object displayName).displayName # The identity's display name. This may not always be available or up-to-date.
    "ServicePrincipalName"      = ($Record | Select-Object -ExpandProperty initiatedBy | Select-Object -ExpandProperty $ActorType | Select-Object servicePrincipalName).servicePrincipalName # Refers to the Service Principal Name is the Application name in the tenant.

    # TargetResources
    # https://learn.microsoft.com/en-us/graph/api/resources/targetresource?view=graph-rest-1.0
    # https://learn.microsoft.com/en-us/graph/api/resources/modifiedproperty?view=graph-rest-1.0
    "Target1DisplayName"               = ($Record | Select-Object -ExpandProperty targetResources | Select-Object displayName | Select-Object -Index 0).displayName # Indicates the visible name defined for the resource.
    "Target1GroupType"                 = ($Record | Select-Object -ExpandProperty targetResources | Select-Object groupType | Select-Object -Index 0).groupType # When type is set to Group, this indicates the group type.
    "Target1Id"                        = ($Record | Select-Object -ExpandProperty targetResources | Select-Object id | Select-Object -Index 0).id # Indicates the unique ID of the resource.
    "Target1Type"                      = ($Record | Select-Object -ExpandProperty targetResources | Select-Object type | Select-Object -Index 0).type # Describes the resource type.
    "Target1ModifiedProperty1Name"     = ($Record | Select-Object -ExpandProperty targetResources | Select-Object -ExpandProperty modifiedProperties | Select-Object displayName | Select-Object -Index 0).displayName # Indicates the property name of the target attribute that was changed.
    "Target1ModifiedProperty1OldValue" = ($Record | Select-Object -ExpandProperty targetResources | Select-Object -ExpandProperty modifiedProperties | Select-Object oldValue | Select-Object -Index 0).oldValue | ForEach-Object {$_ -replace '"',''} | ForEach-Object {$_ -replace '[[\]]',''} # Indicates the previous value (before the update) for the property.
    "Target1ModifiedProperty1NewValue" = ($Record | Select-Object -ExpandProperty targetResources | Select-Object -ExpandProperty modifiedProperties | Select-Object newValue | Select-Object -Index 0).newValue | ForEach-Object {$_ -replace '"',''} | ForEach-Object {$_ -replace '[[\]]',''} # Indicates the updated value for the propery.
    "Target1ModifiedProperty2Name"     = ($Record | Select-Object -ExpandProperty targetResources | Select-Object -ExpandProperty modifiedProperties | Select-Object displayName | Select-Object -Index 1).displayName # Indicates the property name of the target attribute that was changed.
    "Target1ModifiedProperty2OldValue" = ($Record | Select-Object -ExpandProperty targetResources | Select-Object -ExpandProperty modifiedProperties | Select-Object oldValue | Select-Object -Index 1).oldValue | ForEach-Object {$_ -replace '"',''} | ForEach-Object {$_ -replace '[[\]]',''} # Indicates the previous value (before the update) for the property.
    "Target1ModifiedProperty2NewValue" = ($Record | Select-Object -ExpandProperty targetResources | Select-Object -ExpandProperty modifiedProperties | Select-Object newValue | Select-Object -Index 1).newValue | ForEach-Object {$_ -replace '"',''} | ForEach-Object {$_ -replace '[[\]]',''} # Indicates the updated value for the propery.
    "Target1ModifiedProperty3Name"     = ($Record | Select-Object -ExpandProperty targetResources | Select-Object -ExpandProperty modifiedProperties | Select-Object displayName | Select-Object -Index 2).displayName # Indicates the property name of the target attribute that was changed.
    "Target1ModifiedProperty3OldValue" = ($Record | Select-Object -ExpandProperty targetResources | Select-Object -ExpandProperty modifiedProperties | Select-Object oldValue | Select-Object -Index 2).oldValue | ForEach-Object {$_ -replace '"',''} | ForEach-Object {$_ -replace '[[\]]',''} # Indicates the previous value (before the update) for the property.
    "Target1ModifiedProperty3NewValue" = ($Record | Select-Object -ExpandProperty targetResources | Select-Object -ExpandProperty modifiedProperties | Select-Object newValue | Select-Object -Index 2).newValue | ForEach-Object {$_ -replace '"',''} | ForEach-Object {$_ -replace '[[\]]',''} # Indicates the updated value for the propery.
    "Target1ModifiedProperty4Name"     = ($Record | Select-Object -ExpandProperty targetResources | Select-Object -ExpandProperty modifiedProperties | Select-Object displayName | Select-Object -Index 3).displayName # Indicates the property name of the target attribute that was changed.
    "Target1ModifiedProperty4OldValue" = ($Record | Select-Object -ExpandProperty targetResources | Select-Object -ExpandProperty modifiedProperties | Select-Object oldValue | Select-Object -Index 3).oldValue | ForEach-Object {$_ -replace '"',''} | ForEach-Object {$_ -replace '[[\]]',''} # Indicates the previous value (before the update) for the property.
    "Target1ModifiedProperty4NewValue" = ($Record | Select-Object -ExpandProperty targetResources | Select-Object -ExpandProperty modifiedProperties | Select-Object newValue | Select-Object -Index 3).newValue | ForEach-Object {$_ -replace '"',''} | ForEach-Object {$_ -replace '[[\]]',''} # Indicates the updated value for the propery.
    "Target1ModifiedProperty5Name"     = ($Record | Select-Object -ExpandProperty targetResources | Select-Object -ExpandProperty modifiedProperties | Select-Object displayName | Select-Object -Index 4).displayName # Indicates the property name of the target attribute that was changed.
    "Target1ModifiedProperty5OldValue" = ($Record | Select-Object -ExpandProperty targetResources | Select-Object -ExpandProperty modifiedProperties | Select-Object oldValue | Select-Object -Index 4).oldValue | ForEach-Object {$_ -replace '"',''} | ForEach-Object {$_ -replace '[[\]]',''} # Indicates the previous value (before the update) for the property.
    "Target1ModifiedProperty5NewValue" = ($Record | Select-Object -ExpandProperty targetResources | Select-Object -ExpandProperty modifiedProperties | Select-Object newValue | Select-Object -Index 4).newValue | ForEach-Object {$_ -replace '"',''} | ForEach-Object {$_ -replace '[[\]]',''} # Indicates the updated value for the propery.
    "Target1UserPrincipalName"         = ($Record | Select-Object -ExpandProperty targetResources | Select-Object userPrincipalName | Select-Object -Index 0).userPrincipalName # When type is set to User, this includes the user name that initiated the action; null for other types.

    "Target2DisplayName"               = ($Record | Select-Object -ExpandProperty targetResources | Select-Object displayName | Select-Object -Index 1).displayName
    "Target2GroupType"                 = ($Record | Select-Object -ExpandProperty targetResources | Select-Object groupType | Select-Object -Index 1).groupType
    "Target2Id"                        = ($Record | Select-Object -ExpandProperty targetResources | Select-Object id | Select-Object -Index 1).id
    "Target2Type"                      = ($Record | Select-Object -ExpandProperty targetResources | Select-Object type | Select-Object -Index 1).type
    "Target2UserPrincipalName"         = ($Record | Select-Object -ExpandProperty targetResources | Select-Object userPrincipalName | Select-Object -Index 1).userPrincipalName

    "Target3DisplayName"               = ($Record | Select-Object -ExpandProperty targetResources | Select-Object displayName | Select-Object -Index 2).displayName
    "Target3GroupType"                 = ($Record | Select-Object -ExpandProperty targetResources | Select-Object groupType | Select-Object -Index 2).groupType
    "Target3Id"                        = ($Record | Select-Object -ExpandProperty targetResources | Select-Object id | Select-Object -Index 2).id
    "Target3Type"                      = ($Record | Select-Object -ExpandProperty targetResources | Select-Object type | Select-Object -Index 2).type
    "Target3UserPrincipalName"         = ($Record | Select-Object -ExpandProperty targetResources | Select-Object userPrincipalName | Select-Object -Index 2).userPrincipalName

    # AdditionalDetails
    "GroupType"                 = ($Record | Select-Object -ExpandProperty additionalDetails | Where-Object {$_.Key -eq 'GroupType'}).Value # Unified
    "UserType"                  = ($Record | Select-Object -ExpandProperty additionalDetails | Where-Object {$_.Key -eq 'UserType'}).Value # Guest, Member
    "UserAgent"                 = ($Record | Select-Object -ExpandProperty additionalDetails | Where-Object {$_.Key -eq 'User-Agent'}).Value
    "DeviceId"                  = ($Record | Select-Object -ExpandProperty additionalDetails | Where-Object {$_.Key -eq 'DeviceId'}).Value
    "DeviceOSType"              = ($Record | Select-Object -ExpandProperty additionalDetails | Where-Object {$_.Key -eq 'DeviceOSType'}).Value
    "DeviceTrustType"           = ($Record | Select-Object -ExpandProperty additionalDetails | Where-Object {$_.Key -eq 'DeviceTrustType'}).Value

    "CorrelationId"             = $Record.correlationId # Indicates a unique ID that helps correlate activities that span across various services. Can be used to trace logs across services.
    "Id"                        = $Record.id # Indicates the unique ID for the activity.
    }

    $Results.Add($Line)
}

$Results | Export-Csv -Path "$OUTPUT_FOLDER\EntraAuditLogs\CSV\Untouched.csv" -NoTypeInformation -Encoding UTF8

# XLSX
if (Test-Path "$OUTPUT_FOLDER\EntraAuditLogs\CSV\Untouched.csv")
{
    if([int](& $xsv count -d "," "$OUTPUT_FOLDER\EntraAuditLogs\CSV\Untouched.csv") -gt 0)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\EntraAuditLogs\CSV\Untouched.csv" -Delimiter "," -Encoding UTF8
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\EntraAuditLogs\XLSX\Untouched.xlsx" -NoNumberConversion * -NoHyperLinkConversion * -FreezePane 2,4 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "EntraAuditLogs" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
        Set-Format -Address $WorkSheet.Cells["A1:BB1"] -BackgroundColor $BackgroundColor -FontColor White
        # HorizontalAlignment "Center" of columns A-L, N-U and X-BB
        $WorkSheet.Cells["A:L"].Style.HorizontalAlignment="Center"
        $WorkSheet.Cells["N:U"].Style.HorizontalAlignment="Center"
        $WorkSheet.Cells["X:BB"].Style.HorizontalAlignment="Center"
        }
    }
}

# File Size (Untouched.xlsx)
if (Test-Path "$OUTPUT_FOLDER\EntraAuditLogs\XLSX\Untouched.xlsx")
{
    $Size = Get-FileSize((Get-Item "$OUTPUT_FOLDER\EntraAuditLogs\XLSX\Untouched.xlsx").Length)
    Write-Output "[Info]  File Size (Untouched.xlsx): $Size"
}

$EndTime_Processing = (Get-Date)
$Time_Processing = ($EndTime_Processing-$StartTime_Processing)
('EntraAuditLogs Processing duration:   {0} h {1} min {2} sec' -f $Time_Processing.Hours, $Time_Processing.Minutes, $Time_Processing.Seconds) >> "$OUTPUT_FOLDER\Stats.txt"

}

Start-Processing

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Stats

Function Get-Stats {

$StartTime_Stats = (Get-Date)

# Stats
Write-Output "[Info]  Creating Statistics ..."
New-Item "$OUTPUT_FOLDER\EntraAuditLogs\Stats" -ItemType Directory -Force | Out-Null

# ActivityDisplayName --> Activity (Stats)
$Total = (Import-Csv -Path "$OUTPUT_FOLDER\EntraAuditLogs\CSV\Untouched.csv" -Delimiter "," | Select-Object ActivityDisplayName | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = Import-Csv -Path "$OUTPUT_FOLDER\EntraAuditLogs\CSV\Untouched.csv" -Delimiter "," -Encoding UTF8 | Group-Object ActivityDisplayName | Select-Object @{Name='Activity'; Expression={$_.Name}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\EntraAuditLogs\Stats\ActivityDisplayName.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Activity" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns B-C
    $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
    # ConditionalFormatting - Activity
    $Cells = "A:C"
    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Add application",$A1)))' -BackgroundColor Red # Application Creation (Privilege Escalation)
    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Add delegated permission grant",$A1)))' -BackgroundColor Red # OAuth Application Permission Grant
    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Add eligible member to role in PIM completed (permanent)",$A1)))' -BackgroundColor Red # AZT401 - Privileged Identity Management Role (Privilege Escalation)
    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Add eligible member to role in PIM requested (permanent)",$A1)))' -BackgroundColor Red # AZT401 - Privileged Identity Management Role (Privilege Escalation)
    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Add member to role completed (PIM activation)",$A1)))' -BackgroundColor Red # AZT401 - Privileged Identity Management Role (Privilege Escalation)
    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Add member to role requested (PIM activation)",$A1)))' -BackgroundColor Red # AZT401 - Privileged Identity Management Role (Privilege Escalation)
    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Change user password",$A1)))' -BackgroundColor Yellow # A user changes their password. Self-service password reset has to be enabled (for all or selected users) in your organization to allow users to reset their password.
    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Consent to application",$A1)))' -BackgroundColor Red # OAuth Application Permission Grant
    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Disable account",$A1)))' -BackgroundColor Yellow # Disable a user in Microsoft Entra ID
    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Reset user password",$A1)))' -BackgroundColor Red # Administrator resets the password for a user. ATO?
    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Set domain authentication",$A1)))' -BackgroundColor Red # Modification of Trusted Domain
    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Set federation settings on domain",$A1)))' -BackgroundColor Red # Modification of Trusted Domain
    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Update application",$A1)))' -BackgroundColor Red # Modifying Permissions / Adding Permissions (Privilege Escalation)
    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Update application - Certificates and secrets management",$A1)))' -BackgroundColor Red # A user added a secret or certificate to an Entra ID Application (Privilege Escalation)
    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Update StsRefreshTokenValidFrom Timestamp",$A1)))' -BackgroundColor Yellow # A Refresh Token becomes valid. Entra ID will force users to perform re-authentication whenever this attribute is updated (e.g. after Session Revoke).  
    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("User registered all required security info",$A1)))' -BackgroundColor Red # MFA registered
    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("User registered security info",$A1)))' -BackgroundColor Red # MFA registered
    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("User reported unusual sign-in event as not legitimate",$A1)))' -BackgroundColor Red # ATO
    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("User started security info registration",$A1)))' -BackgroundColor Red # MFA registered
    }
}

# Category (Stats)
$Total = (Import-Csv -Path "$OUTPUT_FOLDER\EntraAuditLogs\CSV\Untouched.csv" -Delimiter "," | Select-Object Category | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = Import-Csv -Path "$OUTPUT_FOLDER\EntraAuditLogs\CSV\Untouched.csv" -Delimiter "," -Encoding UTF8 | Group-Object Category | Select-Object @{Name='Category'; Expression={$_.Name}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\EntraAuditLogs\Stats\Category.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Category" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns B-C
    $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
    }
}

# LoggedByService --> Service (Stats)
$Total = (Import-Csv -Path "$OUTPUT_FOLDER\EntraAuditLogs\CSV\Untouched.csv" -Delimiter "," | Select-Object LoggedByService | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = Import-Csv -Path "$OUTPUT_FOLDER\EntraAuditLogs\CSV\Untouched.csv" -Delimiter "," -Encoding UTF8 | Group-Object LoggedByService | Select-Object @{Name='Service'; Expression={$_.Name}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\EntraAuditLogs\Stats\LoggedByService.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Service" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns B-C
    $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
    }
}

# OperationType (Stats)
$Total = (Import-Csv -Path "$OUTPUT_FOLDER\EntraAuditLogs\CSV\Untouched.csv" -Delimiter "," | Select-Object OperationType | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = Import-Csv -Path "$OUTPUT_FOLDER\EntraAuditLogs\CSV\Untouched.csv" -Delimiter "," -Encoding UTF8 | Group-Object OperationType | Select-Object @{Name='OperationType';Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\EntraAuditLogs\Stats\OperationType.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "OperationType" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns B-C
    $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
    }
}

# PrimaryTarget (Stats)
$Total = (Import-Csv -Path "$OUTPUT_FOLDER\EntraAuditLogs\CSV\Untouched.csv" -Delimiter "," | Select-Object Target1DisplayName | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = Import-Csv -Path "$OUTPUT_FOLDER\EntraAuditLogs\CSV\Untouched.csv" -Delimiter "," -Encoding UTF8 | Group-Object Target1DisplayName | Select-Object @{Name='PrimaryTarget';Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\EntraAuditLogs\Stats\PrimaryTarget.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "PrimaryTarget" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns B-C
    $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
    }
}

# Status (Stats)
$Total = (Import-Csv -Path "$OUTPUT_FOLDER\EntraAuditLogs\CSV\Untouched.csv" -Delimiter "," | Select-Object Result | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = Import-Csv -Path "$OUTPUT_FOLDER\EntraAuditLogs\CSV\Untouched.csv" -Delimiter "," -Encoding UTF8 | Group-Object Result | Select-Object @{Name='Status'; Expression={$_.Name}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\EntraAuditLogs\Stats\Status.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Status" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns A-C
    $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
    }
}

# StatusReason (Stats)
$Total = (Import-Csv -Path "$OUTPUT_FOLDER\EntraAuditLogs\CSV\Untouched.csv" -Delimiter "," | Select-Object ResultReason | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = Import-Csv -Path "$OUTPUT_FOLDER\EntraAuditLogs\CSV\Untouched.csv" -Delimiter "," -Encoding UTF8 | Group-Object ResultReason | Select-Object @{Name='StatusReason';Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\EntraAuditLogs\Stats\StatusReason.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "StatusReason" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns B-C
    $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
    # ConditionalFormatting - StatusReason
    $Cells = "A:C"
    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Access denied. Insufficient privileges to proceed.",$A1)))' -BackgroundColor Red # Denied Access Request
    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("User failed to register Authenticator App with Code",$A1)))' -BackgroundColor Red # Persistence Attempt
    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("User registered all required security info.",$A1)))' -BackgroundColor Red # Persistence
    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("User registered Authenticator App with Code",$A1)))' -BackgroundColor Red # Persistence
    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("User registered Authenticator App with Notification",$A1)))' -BackgroundColor Red # Persistence
    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("User registered Authenticator App with Notification and Code",$A1)))' -BackgroundColor Red # Persistence
    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("User started the registration for Authenticator App with Code",$A1)))' -BackgroundColor Red # Persistence
    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("User started the registration for Authenticator App with Notification and Code",$A1)))' -BackgroundColor Red # Persistence
    }
}

# Status / StatusReason (Stats)
$Total = (Import-Csv -Path "$OUTPUT_FOLDER\EntraAuditLogs\CSV\Untouched.csv" -Delimiter "," | Select-Object Result | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = Import-Csv -Path "$OUTPUT_FOLDER\EntraAuditLogs\CSV\Untouched.csv" -Delimiter "," -Encoding UTF8 | Select-Object @{Name='Status'; Expression={$_.Result}},@{Name='StatusReason';Expression={if($_.ResultReason){$_.ResultReason}else{'N/A'}}} | Group-Object Status,StatusReason | Select-Object @{Name='Status'; Expression={ $_.Values[0] }},@{Name='StatusReason'; Expression={ $_.Values[1] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\EntraAuditLogs\Stats\Status-StatusReason.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Status-StatusReason" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns A and C-D
    $WorkSheet.Cells["A:A"].Style.HorizontalAlignment="Center"
    $WorkSheet.Cells["C:D"].Style.HorizontalAlignment="Center"
    # ConditionalFormatting - StatusReason
    $Cells = "A:D"
    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Access denied. Insufficient privileges to proceed.",$B1)))' -BackgroundColor Red # Denied Access Request
    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("User failed to register Authenticator App with Code",$B1)))' -BackgroundColor Red # Persistence Attempt
    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("User registered all required security info.",$B1)))' -BackgroundColor Red # Persistence
    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("User registered Authenticator App with Code",$B1)))' -BackgroundColor Red # Persistence
    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("User registered Authenticator App with Notification",$B1)))' -BackgroundColor Red # Persistence
    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("User registered Authenticator App with Notification and Code",$B1)))' -BackgroundColor Red # Persistence
    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("User started the registration for Authenticator App with Code",$B1)))' -BackgroundColor Red # Persistence
    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("User started the registration for Authenticator App with Notification and Code",$B1)))' -BackgroundColor Red # Persistence 
    }
}

# TargetType (Stats)
$Total = (Import-Csv -Path "$OUTPUT_FOLDER\EntraAuditLogs\CSV\Untouched.csv" -Delimiter "," | Select-Object Target1Type | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = Import-Csv -Path "$OUTPUT_FOLDER\EntraAuditLogs\CSV\Untouched.csv" -Delimiter "," -Encoding UTF8 | Group-Object Target1Type | Select-Object @{Name='TargetType';Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\EntraAuditLogs\Stats\TargetType.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "TargetType" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns A-C
    $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
    }
}

# UserAgent (Stats)
$Total = (Import-Csv -Path "$OUTPUT_FOLDER\EntraAuditLogs\CSV\Untouched.csv" -Delimiter "," | Where-Object {$_.UserAgent -ne '' } | Select-Object UserAgent | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = Import-Csv -Path "$OUTPUT_FOLDER\EntraAuditLogs\CSV\Untouched.csv" -Delimiter "," -Encoding UTF8 | Where-Object {$_.UserAgent -ne '' } | Group-Object UserAgent | Select-Object @{Name='UserAgent';Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\EntraAuditLogs\Stats\UserAgent.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "UserAgent" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns B-C
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

# UserDisplayName (Stats)
$Total = (Import-Csv -Path "$OUTPUT_FOLDER\EntraAuditLogs\CSV\Untouched.csv" -Delimiter "," | Where-Object {$_.UserDisplayName -ne '' } | Select-Object UserDisplayName | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = Import-Csv -Path "$OUTPUT_FOLDER\EntraAuditLogs\CSV\Untouched.csv" -Delimiter "," -Encoding UTF8 | Where-Object {$_.UserDisplayName -ne '' } | Group-Object UserDisplayName | Select-Object @{Name='UserDisplayName'; Expression={$_.Name}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\EntraAuditLogs\Stats\UserDisplayName.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "UserDisplayName" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns B-C
    $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
    }
}

# Line Charts
New-Item "$OUTPUT_FOLDER\EntraAuditLogs\Stats\LineCharts" -ItemType Directory -Force | Out-Null

# ActivityDisplayName --> Activity
$Import = Import-Csv -Path "$OUTPUT_FOLDER\EntraAuditLogs\CSV\Untouched.csv" -Delimiter "," -Encoding UTF8 | Select-Object @{Name="ActivityDateTime";Expression={((Get-Date $_.ActivityDateTime).ToString("yyyy-MM-dd"))}},ActivityDisplayName | Group-Object{($_.ActivityDateTime)} | Select-Object Count,@{Name='ActivityDateTime'; Expression={ $_.Values[0] }} | Sort-Object { $_.ActivityDateTime -as [datetime] }
$ChartDefinition = New-ExcelChartDefinition -XRange ActivityDateTime -YRange Count -Title "Activity" -ChartType Line -NoLegend -Width 1200
$Import | Export-Excel -Path "$OUTPUT_FOLDER\EntraAuditLogs\Stats\LineCharts\Activity.xlsx" -Append -WorksheetName "Line Chart" -AutoNameRange -ExcelChartDefinition $ChartDefinition

$EndTime_Stats = (Get-Date)
$Time_Stats = ($EndTime_Stats-$StartTime_Stats)
('EntraAuditLogs Stats duration:        {0} h {1} min {2} sec' -f $Time_Stats.Hours, $Time_Stats.Minutes, $Time_Stats.Seconds) >> "$OUTPUT_FOLDER\Stats.txt"

}

#endregion Stats

Get-Stats

#############################################################################################################################################################################################
#############################################################################################################################################################################################

Function Get-IPLocation {

$StartTime_IPLocation = (Get-Date)

# Count IP addresses
Write-Output "[Info]  Data Enrichment w/ IPinfo.io ..."
New-Item "$OUTPUT_FOLDER\IpAddress" -ItemType Directory -Force | Out-Null

if (!(Test-Path "$OUTPUT_FOLDER\EntraAuditLogs\CSV\Untouched.csv"))
{
    Write-Host "[Error] 'Untouched.csv' NOT found." -ForegroundColor Red
    Write-Host ""
    Stop-Transcript
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

$Data = Import-Csv -Path "$OUTPUT_FOLDER\EntraAuditLogs\CSV\Untouched.csv" -Delimiter "," | Where-Object {$_.IPAddress -ne '' } | Select-Object -ExpandProperty IPAddress

$Unique = $Data | Sort-Object -Unique
$Unique | Out-File "$OUTPUT_FOLDER\IPAddress\IP-All.txt"

$Count = ($Unique | Measure-Object).Count
$Total = ($Data | Measure-Object).Count
Write-Output "[Info]  $Count IP addresses found ($Total)"

# IPv4
# https://ipinfo.io/bogon
$IPv4 = "(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
$Private = "^(192\.168|10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.)"
$Special = "^(0\.0\.0\.0|127\.0\.0\.1|169\.254\.|224\.0\.0)"
Get-Content "$OUTPUT_FOLDER\IPAddress\IP-All.txt" | Select-String -Pattern $IPv4 -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique -Property { [System.Version]$_ } | Out-File "$OUTPUT_FOLDER\IPAddress\IPv4-All.txt"
Get-Content "$OUTPUT_FOLDER\IPAddress\IP-All.txt" | Select-String -Pattern $IPv4 -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique -Property { [System.Version]$_ } | Where-Object {$_ -notmatch $Private} | Where-Object {$_ -notmatch $Special} | Out-File "$OUTPUT_FOLDER\IPAddress\IPv4.txt"

# Count
$Total = (Get-Content "$OUTPUT_FOLDER\IPAddress\IPv4-All.txt" | Measure-Object).Count # Public (Unique) + Private (Unique) --> Note: Extracts IPv4 addresses of IPv4-compatible IPv6 addresses.
$Public = (Get-Content "$OUTPUT_FOLDER\IPAddress\IPv4.txt" | Measure-Object).Count # Public (Unique)
$UniquePublic = '{0:N0}' -f $Public
Write-Output "[Info]  $UniquePublic Public IPv4 addresses found ($Total)"

# IPv6
# https://ipinfo.io/bogon
$IPv6 = ":(?::[a-f\d]{1,4}){0,5}(?:(?::[a-f\d]{1,4}){1,2}|:(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})))|[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}|:)|(?::(?:[a-f\d]{1,4})?|(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))))|:(?:(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|[a-f\d]{1,4}(?::[a-f\d]{1,4})?|))|(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|:[a-f\d]{1,4}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){0,2})|:))|(?:(?::[a-f\d]{1,4}){0,2}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:))|(?:(?::[a-f\d]{1,4}){0,3}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:))|(?:(?::[a-f\d]{1,4}){0,4}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:))"
$Bogon = "^(::1|::ffff:|100::|2001:10::|2001:db8::|fc00::|fe80::|fec0::|ff00::)"
Get-Content "$OUTPUT_FOLDER\IPAddress\IP-All.txt" | Select-String -Pattern $IPv6 -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique | Out-File "$OUTPUT_FOLDER\IPAddress\IPv6-All.txt"
Get-Content "$OUTPUT_FOLDER\IPAddress\IP-All.txt" | Select-String -Pattern $IPv6 -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique | Where-Object {$_ -notmatch $Bogon} | Out-File "$OUTPUT_FOLDER\IPAddress\IPv6.txt"

# Count
$Total = (Get-Content "$OUTPUT_FOLDER\IPAddress\IPv6-All.txt" | Measure-Object).Count # including Bogus IPv6 addresses (e.g. IPv4-compatible IPv6 addresses)
$Public = (Get-Content "$OUTPUT_FOLDER\IPAddress\IPv6.txt" | Measure-Object).Count
Write-Output "[Info]  $Public Public IPv6 addresses found ($Total)"

# IP.txt
Write-Output "IPAddress" | Out-File "$OUTPUT_FOLDER\IPAddress\IP.txt" # Header

# IPv4.txt
if (Test-Path "$OUTPUT_FOLDER\IPAddress\IPv4.txt")
{
    if ((Get-Item "$OUTPUT_FOLDER\IPAddress\IPv4.txt").Length -gt 0kb)
    {
        Get-Content -Path "$OUTPUT_FOLDER\IPAddress\IPv4.txt" | Out-File "$OUTPUT_FOLDER\IPAddress\IP.txt" -Append
    }
}

# IPv6.txt
if (Test-Path "$OUTPUT_FOLDER\IPAddress\IPv6.txt")
{
    if ((Get-Item "$OUTPUT_FOLDER\IPAddress\IPv6.txt").Length -gt 0kb)
    {
        Get-Content -Path "$OUTPUT_FOLDER\IPAddress\IPv6.txt" | Out-File "$OUTPUT_FOLDER\IPAddress\IP.txt" -Append
    }
}

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
    if (Test-Path "$OUTPUT_FOLDER\IPAddress\IP.txt")
    {
        if ((Get-Item "$OUTPUT_FOLDER\IPAddress\IP.txt").Length -gt 0kb)
        {
            # Internet Connectivity Check (Vista+)
            $NetworkListManager = [Activator]::CreateInstance([Type]::GetTypeFromCLSID([Guid]'{DCB00C01-570F-4A9B-8D69-199FDBA5723B}')).IsConnectedToInternet

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
                    New-Item "$OUTPUT_FOLDER\IPAddress\IPinfo" -ItemType Directory -Force | Out-Null
                    Get-Content "$OUTPUT_FOLDER\IPAddress\IP.txt" | & $IPinfo map | Out-File "$OUTPUT_FOLDER\IPAddress\IPinfo\Map.txt"

                    # Access Token
                    # https://ipinfo.io/signup?ref=cli
                    if (!("$Token" -eq "access_token"))
                    {
                        # Summarize IPs
                        # https://ipinfo.io/summarize-ips

                        # TXT --> Top Privacy Services
                        Get-Content "$OUTPUT_FOLDER\IPAddress\IP.txt" | & $IPinfo summarize --token "$Token" | Out-File "$OUTPUT_FOLDER\IPAddress\IPinfo\Summary.txt"

                        # CSV
                        Get-Content "$OUTPUT_FOLDER\IPAddress\IP.txt" | & $IPinfo --csv --token "$Token" | Out-File "$OUTPUT_FOLDER\IPAddress\IPinfo\IPinfo.csv"

                        # Custom CSV (Free)
                        if ($PrivacyDetection -eq "False")
                        {
                            if (Test-Path "$OUTPUT_FOLDER\IPAddress\IPinfo\IPinfo.csv")
                            {
                                if([int](& $xsv count "$OUTPUT_FOLDER\IPAddress\IPinfo\IPinfo.csv") -gt 0)
                                {
                                    $IPinfoRecords = Import-Csv "$OUTPUT_FOLDER\IPAddress\IPinfo\IPinfo.csv" -Delimiter "," -Encoding UTF8

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

                                    $Results | Sort-Object {$_.ip -as [Version]} | Export-Csv -Path "$OUTPUT_FOLDER\IPAddress\IPinfo\IPinfo-Custom.csv" -NoTypeInformation -Encoding UTF8
                                }
                            }

                            # Custom XLSX (Free)
                            if (Test-Path "$OUTPUT_FOLDER\IPAddress\IPinfo\IPinfo-Custom.csv")
                            {
                                if([int](& $xsv count "$OUTPUT_FOLDER\IPAddress\IPinfo\IPinfo-Custom.csv") -gt 0)
                                {
                                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\IPAddress\IPinfo\IPinfo-Custom.csv" -Delimiter "," | Sort-Object {$_.ip -as [Version]}
                                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\IPAddress\IPinfo\IPinfo-Custom.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -IncludePivotTable -PivotTableName "PivotTable" -PivotRows "Country Name" -PivotData @{"IP"="Count"} -WorkSheetname "IPinfo (Free)" -CellStyleSB {
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
                            if (Test-Path "$OUTPUT_FOLDER\IPAddress\IPinfo\IPinfo.csv")
                            {
                                if([int](& $xsv count "$OUTPUT_FOLDER\IPAddress\IPinfo\IPinfo.csv") -gt 0)
                                {
                                    $IPinfoRecords = Import-Csv "$OUTPUT_FOLDER\IPAddress\IPinfo\IPinfo.csv" -Delimiter "," -Encoding UTF8
                                
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

                                    $Results | Sort-Object {$_.ip-as [Version]} | Export-Csv -Path "$OUTPUT_FOLDER\IPAddress\IPinfo\IPinfo-Custom.csv" -NoTypeInformation -Encoding UTF8
                                }
                            }

                            # Custom XLSX (Privacy Detection)
                            if (Test-Path "$OUTPUT_FOLDER\IPAddress\IPinfo\IPinfo-Custom.csv")
                            {
                                if([int](& $xsv count "$OUTPUT_FOLDER\IPAddress\IPinfo\IPinfo-Custom.csv") -gt 0)
                                {
                                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\IPAddress\IPinfo\IPinfo-Custom.csv" -Delimiter "," | Sort-Object {$_.ip -as [Version]}
                                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\IPAddress\IPinfo\IPinfo-Custom.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -IncludePivotTable -PivotTableName "PivotTable" -PivotRows "Country Name" -PivotData @{"IP"="Count"} -WorkSheetname "IPinfo (Standard)" -CellStyleSB {
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
                        if (Test-Path "$OUTPUT_FOLDER\IPAddress\IPinfo\IPinfo-Custom.csv")
                        {
                            if([int](& $xsv count "$OUTPUT_FOLDER\IPAddress\IPinfo\IPinfo-Custom.csv") -gt 0)
                            {
                                # Free
                                if ($PrivacyDetection -eq "False")
                                {
                                    Import-Csv -Path "$OUTPUT_FOLDER\IPAddress\IPinfo\IPinfo-Custom.csv" -Delimiter "," -Encoding UTF8 | ForEach-Object { $IPinfo_HashTable[$_.IP] = $_.City,$_.Region,$_.Country,$_."Country Name",$_.Location,$_.ASN,$_.OrgName,$_."Postal Code",$_.Timezone }
                                }

                                # Privacy Detection
                                if ($PrivacyDetection -eq "True")
                                {
                                    Import-Csv -Path "$OUTPUT_FOLDER\IPAddress\IPinfo\IPinfo-Custom.csv" -Delimiter "," -Encoding UTF8 | ForEach-Object { $IPinfo_HashTable[$_.IP] = $_.City,$_.Region,$_.Country,$_."Country Name",$_.Location,$_.ASN,$_.OrgName,$_."Postal Code",$_.Timezone,$_.VPN,$_.Proxy,$_.Tor,$_.Relay,$_.Hosting,$_.Service }
                                }

                                # Count Ingested Properties
                                $Count = $IPinfo_HashTable.Count
                                Write-Output "[Info]  Initializing 'IPinfo-Custom.csv' Lookup Table ($Count) ..."
                            }
                        }

                        # Initializing Blacklists
                        $Count = $ApplicationBlacklist_HashTable.Count
                        Write-Output "[Info]  Initializing 'Application-Blacklist.csv' Lookup Table ($Count) ..."

                        $Count = $AsnBlacklist_HashTable.Count
                        Write-Output "[Info]  Initializing 'ASN-Blacklist.csv' Lookup Table ($Count) ..."

                        $Count = $CountryBlacklist_HashTable.Count
                        Write-Output "[Info]  Initializing 'Country-Blacklist.csv' Lookup Table ($Count) ..."

                        # Entra Audit Logs

                        # IPinfo Subscription: Free
                        if ($PrivacyDetection -eq "False")
                        {
                            if (Test-Path "$OUTPUT_FOLDER\EntraAuditLogs\CSV\Untouched.csv")
                            {
                                if([int](& $xsv count "$OUTPUT_FOLDER\EntraAuditLogs\CSV\Untouched.csv") -gt 0)
                                {
                                    $Records = Import-Csv -Path "$OUTPUT_FOLDER\EntraAuditLogs\CSV\Untouched.csv" -Delimiter "," -Encoding UTF8

                                    # CSV
                                    $Results = [Collections.Generic.List[PSObject]]::new()
                                    ForEach($Record in $Records)
                                    {
                                        # IPAddress
                                        $IP = $Record.IPAddress

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
                                            "ActivityDateTime"                 = $Record.activityDateTime # Date and time the activity was performed in UTC.
                                            "InitiatedBy (UPN)"                = $Record."InitiatedBy (UPN)"
                                            "TargetResources (UPN)"            = $Record."TargetResources (UPN)"
                                            "UserId"                           = $Record.UserId
                                            "AppDisplayName"                   = $Record.AppDisplayName
                                            "AppId"                            = $Record.AppId # Empty
                                            "ServicePrincipalId"               = $record.ServicePrincipalId
                                            "Service"                          = $Record.loggedByService # Service that initiated the activity.
                                            "Category"                         = $Record.category
                                            "Activity"                         = $Record.activityDisplayName # Activity name or the operation name.
                                            "OperationType"                    = $Record.operationType # Type of the operation. Possible values are Add Update Delete and Other.
                                            "Status"                           = $Record.result # Result of the activity. Possible values are: success, failure, timeout, and unknownFutureValue.
                                            "StatusReason"                     = $Record.resultReason # Describes cause of failure or timeout results.
                                            "IPAddress"                        = $IP
                                            "City"                             = $City
                                            "Region"                           = $Region
                                            "Country"                          = $Country
                                            "Country Name"                     = $CountryName
                                            "ASN"                              = $ASN
                                            "OrgName"                          = $OrgName
                                            "Timezone"                         = $Timezone
                                            "UserPrincipalName"                = $Record.UserPrincipalName
                                            "ServicePrincipalName"             = $Record.ServicePrincipalName
                                            "Target1DisplayName"               = $Record.Target1DisplayName
                                            "Target1GroupType"                 = $Record.Target1GroupType
                                            "Target1Id"                        = $Record.Target1Id
                                            "Target1Type"                      = $Record.Target1Type
                                            "Target1ModifiedProperty1Name"     = $Record.Target1ModifiedProperty1Name
                                            "Target1ModifiedProperty1OldValue" = $Record.Target1ModifiedProperty1OldValue
                                            "Target1ModifiedProperty1NewValue" = $Record.Target1ModifiedProperty1NewValue
                                            "Target1ModifiedProperty2Name"     = $Record.Target1ModifiedProperty2Name
                                            "Target1ModifiedProperty2OldValue" = $Record.Target1ModifiedProperty2OldValue
                                            "Target1ModifiedProperty2NewValue" = $Record.Target1ModifiedProperty2NewValue
                                            "Target1ModifiedProperty3Name"     = $Record.Target1ModifiedProperty3Name
                                            "Target1ModifiedProperty3OldValue" = $Record.Target1ModifiedProperty3OldValue
                                            "Target1ModifiedProperty3NewValue" = $Record.Target1ModifiedProperty3NewValue
                                            "Target1ModifiedProperty4Name"     = $Record.Target1ModifiedProperty4Name
                                            "Target1ModifiedProperty4OldValue" = $Record.Target1ModifiedProperty4OldValue
                                            "Target1ModifiedProperty4NewValue" = $Record.Target1ModifiedProperty4NewValue
                                            "Target1ModifiedProperty5Name"     = $Record.Target1ModifiedProperty5Name
                                            "Target1ModifiedProperty5OldValue" = $Record.Target1ModifiedProperty5OldValue
                                            "Target1ModifiedProperty5NewValue" = $Record.Target1ModifiedProperty5NewValue
                                            "Target1UserPrincipalName"         = $Record.Target1UserPrincipalName
                                            "Target2DisplayName"               = $Record.Target2DisplayName
                                            "Target2GroupType"                 = $Record.Target2GroupType
                                            "Target2Id"                        = $Record.Target2Id
                                            "Target2Type"                      = $Record.Target2Type
                                            "Target2UserPrincipalName"         = $Record.Target2UserPrincipalName
                                            "Target3DisplayName"               = $Record.Target3DisplayName
                                            "Target3GroupType"                 = $Record.Target3GroupType
                                            "Target3Id"                        = $Record.Target3Id
                                            "Target3Type"                      = $Record.Target3Type
                                            "Target3UserPrincipalName"         = $Record.Target3UserPrincipalName
                                            "GroupType"                        = $Record.GroupType
                                            "UserType"                         = $Record.UserType
                                            "UserAgent"                        = $Record.UserAgent
                                            "DeviceId"                         = $Record.DeviceId
                                            "DeviceOSType"                     = $Record.DeviceOSType
                                            "DeviceTrustType"                  = $Record.DeviceTrustType
                                            "CorrelationId"                    = $Record.CorrelationId
                                            "Id"                               = $Record.Id
                                        }

                                        $Results.Add($Line)
                                    }

                                    $Results | Export-Csv -Path "$OUTPUT_FOLDER\EntraAuditLogs\CSV\Hunt.csv" -NoTypeInformation -Encoding UTF8
                                }
                            }

                            # XLSX
                            if (Test-Path "$OUTPUT_FOLDER\EntraAuditLogs\CSV\Hunt.csv")
                            {
                                if([int](& $xsv count "$OUTPUT_FOLDER\EntraAuditLogs\CSV\Hunt.csv") -gt 0)
                                {
                                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\EntraAuditLogs\CSV\Hunt.csv" -Delimiter "," | Sort-Object { $_.ActivityDateTime -as [datetime] } -Descending
                                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\EntraAuditLogs\XLSX\Hunt.xlsx" -NoHyperLinkConversion * -NoNumberConversion * -FreezePane 2,4 -BoldTopRow -AutoSize -AutoFilter -IncludePivotTable -PivotTableName "PivotTable" -WorkSheetname "EntraAuditLogs" -CellStyleSB {
                                    param($WorkSheet)
                                    # BackgroundColor and FontColor for specific cells of TopRow
                                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                    Set-Format -Address $WorkSheet.Cells["A1:BI1"] -BackgroundColor $BackgroundColor -FontColor White
                                    # HorizontalAlignment "Center" of columns A-L and N-BI
                                    $WorkSheet.Cells["A:L"].Style.HorizontalAlignment="Center"
                                    $WorkSheet.Cells["N:BI"].Style.HorizontalAlignment="Center"
                                    # ConditionalFormatting - Activity
                                    $Cells = "J:J"
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Add application",$J1)))' -BackgroundColor Red # Application Creation (Privilege Escalation)
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Add delegated permission grant",$J1)))' -BackgroundColor Red # OAuth Application Permission Grant
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Add eligible member to role in PIM completed (permanent)",$J1)))' -BackgroundColor Red # AZT401 - Privileged Identity Management Role (Privilege Escalation)
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Add eligible member to role in PIM requested (permanent)",$J1)))' -BackgroundColor Red # AZT401 - Privileged Identity Management Role (Privilege Escalation)
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Add member to role completed (PIM activation)",$J1)))' -BackgroundColor Red # AZT401 - Privileged Identity Management Role (Privilege Escalation)
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Add member to role requested (PIM activation)",$J1)))' -BackgroundColor Red # AZT401 - Privileged Identity Management Role (Privilege Escalation)
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Change user password",$J1)))' -BackgroundColor Yellow # A user changes their password. Self-service password reset has to be enabled (for all or selected users) in your organization to allow users to reset their password.
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Consent to application",$J1)))' -BackgroundColor Red # OAuth Application Permission Grant
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Disable account",$J1)))' -BackgroundColor Yellow # Disable a user in Microsoft Entra ID
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Reset user password",$J1)))' -BackgroundColor Red # Administrator resets the password for a user. ATO?
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Set domain authentication",$J1)))' -BackgroundColor Red # Modification of Trusted Domain
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Set federation settings on domain",$J1)))' -BackgroundColor Red # Modification of Trusted Domain
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Update application",$J1)))' -BackgroundColor Red # Modifying Permissions / Adding Permissions (Privilege Escalation)
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Update application - Certificates and secrets management",$J1)))' -BackgroundColor Red # A user added a secret or certificate to an Entra ID Application (Privilege Escalation)
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Update StsRefreshTokenValidFrom Timestamp",$J1)))' -BackgroundColor Yellow # A Refresh Token becomes valid. Entra ID will force users to perform re-authentication whenever this attribute is updated (e.g. after Session Revoke).  
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("User registered all required security info",$J1)))' -BackgroundColor Red # MFA registered
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("User registered security info",$J1)))' -BackgroundColor Red # MFA registered
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("User reported unusual sign-in event as not legitimate",$J1)))' -BackgroundColor Red # ATO
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("User started security info registration",$J1)))' -BackgroundColor Red # MFA registered
                                    # ConditionalFormatting - StatusReason
                                    $Cells = "M:M"
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Access denied. Insufficient privileges to proceed.",$M1)))' -BackgroundColor Red # Denied Access Request
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("User failed to register Authenticator App with Code",$M1)))' -BackgroundColor Red # Persistence Attempt
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("User registered all required security info.",$M1)))' -BackgroundColor Red # Persistence
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("User registered Authenticator App with Code",$M1)))' -BackgroundColor Red # Persistence
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("User registered Authenticator App with Notification",$M1)))' -BackgroundColor Red # Persistence
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("User registered Authenticator App with Notification and Code",$M1)))' -BackgroundColor Red # Persistence
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("User started the registration for Authenticator App with Code",$M1)))' -BackgroundColor Red # Persistence
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("User started the registration for Authenticator App with Notification and Code",$M1)))' -BackgroundColor Red # Persistence
                                    # ConditionalFormatting - UserAgent
                                    $Cells = "BC:BC"
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("AzurePowershell/",$BC1)))' -BackgroundColor $Orange # User-Agent associated with scripting/generic HTTP client
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("PostmanRuntime/",$BC1)))' -BackgroundColor Red # User-Agent associated with scripting/generic HTTP client
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("PowerShell/5.1",$BC1)))' -BackgroundColor $Orange # User-Agent associated with scripting/generic HTTP client
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("PowerShell/7",$BC1)))' -BackgroundColor $Orange # User-Agent associated with scripting/generic HTTP client
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("python-requests",$BC1)))' -BackgroundColor Red # User-Agent associated with scripting/generic HTTP client
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("python/",$BC1)))' -BackgroundColor Red # User-Agent associated with scripting/generic HTTP client
                                    
                                    # Iterating over the Application-Blacklist HashTable - Target1ModifiedProperty3NewValue
                                    foreach ($AppId in $ApplicationBlacklist_HashTable.Keys) 
                                    {
                                        $Severity = $ApplicationBlacklist_HashTable["$AppId"][1]
                                        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$AJ1)))' -f $AppId
                                        Add-ConditionalFormatting -Address $WorkSheet.Cells["AJ:AJ"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
                                    }

                                    # Iterating over the ASN-Blacklist HashTable
                                    foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
                                    {
                                        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$S1)))' -f $ASN
                                        Add-ConditionalFormatting -Address $WorkSheet.Cells["S:S"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
                                    }

                                    # Iterating over the Country-Blacklist HashTable
                                    foreach ($Country in $CountryBlacklist_HashTable.Keys) 
                                    {
                                        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$R1)))' -f $Country
                                        Add-ConditionalFormatting -Address $WorkSheet.Cells["R:R"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
                                    }

                                    }
                                }
                            } 
                        }

                        # IPinfo Subscription Plan w/ Privacy Detection
                        if ($PrivacyDetection -eq "True")
                        {
                            if (Test-Path "$OUTPUT_FOLDER\EntraAuditLogs\CSV\Untouched.csv")
                            {
                                if([int](& $xsv count "$OUTPUT_FOLDER\EntraAuditLogs\CSV\Untouched.csv") -gt 0)
                                {
                                    $Records = Import-Csv -Path "$OUTPUT_FOLDER\EntraAuditLogs\CSV\Untouched.csv" -Delimiter "," -Encoding UTF8

                                    # CSV
                                    $Results = [Collections.Generic.List[PSObject]]::new()
                                    ForEach($Record in $Records)
                                    {
                                        # IPAddress
                                        $IP = $Record.IPAddress

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
                                            "ActivityDateTime"                 = $Record.activityDateTime # Date and time the activity was performed in UTC.
                                            "InitiatedBy (UPN)"                = $Record."InitiatedBy (UPN)"
                                            "TargetResources (UPN)"            = $Record."TargetResources (UPN)"
                                            "UserId"                           = $Record.UserId
                                            "AppDisplayName"                   = $Record.AppDisplayName
                                            "AppId"                            = $Record.AppId # Empty
                                            "ServicePrincipalId"               = $record.ServicePrincipalId
                                            "Service"                          = $Record.loggedByService # Service that initiated the activity.
                                            "Category"                         = $Record.category
                                            "Activity"                         = $Record.activityDisplayName # Activity name or the operation name.
                                            "OperationType"                    = $Record.operationType # Type of the operation. Possible values are Add Update Delete and Other.
                                            "Status"                           = $Record.result # Result of the activity. Possible values are: success, failure, timeout, and unknownFutureValue.
                                            "StatusReason"                     = $Record.resultReason # Describes cause of failure or timeout results.
                                            "IPAddress"                        = $IP
                                            "City"                             = $City
                                            "Region"                           = $Region
                                            "Country"                          = $Country
                                            "Country Name"                     = $CountryName
                                            "Location"                         = $Location
                                            "ASN"                              = $ASN
                                            "OrgName"                          = $OrgName
                                            "Postal Code"                      = $PostalCode
                                            "Timezone"                         = $Timezone
                                            "VPN"                              = $VPN
                                            "Proxy"                            = $Proxy
                                            "Tor"                              = $Tor
                                            "Relay"                            = $Relay
                                            "Hosting"                          = $Hosting
                                            "Privacy Service"                  = $Service
                                            "UserPrincipalName"                = $Record.UserPrincipalName
                                            "ServicePrincipalName"             = $Record.ServicePrincipalName
                                            "Target1DisplayName"               = $Record.Target1DisplayName
                                            "Target1GroupType"                 = $Record.Target1GroupType
                                            "Target1Id"                        = $Record.Target1Id
                                            "Target1Type"                      = $Record.Target1Type
                                            "Target1ModifiedProperty1Name"     = $Record.Target1ModifiedProperty1Name
                                            "Target1ModifiedProperty1OldValue" = $Record.Target1ModifiedProperty1OldValue
                                            "Target1ModifiedProperty1NewValue" = $Record.Target1ModifiedProperty1NewValue
                                            "Target1ModifiedProperty2Name"     = $Record.Target1ModifiedProperty2Name
                                            "Target1ModifiedProperty2OldValue" = $Record.Target1ModifiedProperty2OldValue
                                            "Target1ModifiedProperty2NewValue" = $Record.Target1ModifiedProperty2NewValue
                                            "Target1ModifiedProperty3Name"     = $Record.Target1ModifiedProperty3Name
                                            "Target1ModifiedProperty3OldValue" = $Record.Target1ModifiedProperty3OldValue
                                            "Target1ModifiedProperty3NewValue" = $Record.Target1ModifiedProperty3NewValue
                                            "Target1ModifiedProperty4Name"     = $Record.Target1ModifiedProperty4Name
                                            "Target1ModifiedProperty4OldValue" = $Record.Target1ModifiedProperty4OldValue
                                            "Target1ModifiedProperty4NewValue" = $Record.Target1ModifiedProperty4NewValue
                                            "Target1ModifiedProperty5Name"     = $Record.Target1ModifiedProperty5Name
                                            "Target1ModifiedProperty5OldValue" = $Record.Target1ModifiedProperty5OldValue
                                            "Target1ModifiedProperty5NewValue" = $Record.Target1ModifiedProperty5NewValue
                                            "Target1UserPrincipalName"         = $Record.Target1UserPrincipalName
                                            "Target2DisplayName"               = $Record.Target2DisplayName
                                            "Target2GroupType"                 = $Record.Target2GroupType
                                            "Target2Id"                        = $Record.Target2Id
                                            "Target2Type"                      = $Record.Target2Type
                                            "Target2UserPrincipalName"         = $Record.Target2UserPrincipalName
                                            "Target3DisplayName"               = $Record.Target3DisplayName
                                            "Target3GroupType"                 = $Record.Target3GroupType
                                            "Target3Id"                        = $Record.Target3Id
                                            "Target3Type"                      = $Record.Target3Type
                                            "Target3UserPrincipalName"         = $Record.Target3UserPrincipalName
                                            "GroupType"                        = $Record.GroupType
                                            "UserType"                         = $Record.UserType
                                            "UserAgent"                        = $Record.UserAgent
                                            "DeviceId"                         = $Record.DeviceId
                                            "DeviceOSType"                     = $Record.DeviceOSType
                                            "DeviceTrustType"                  = $Record.DeviceTrustType
                                            "CorrelationId"                    = $Record.CorrelationId
                                            "Id"                               = $Record.Id
                                        }

                                        $Results.Add($Line)
                                    }

                                    $Results | Export-Csv -Path "$OUTPUT_FOLDER\EntraAuditLogs\CSV\Hunt.csv" -NoTypeInformation -Encoding UTF8
                                }
                            }

                            # XLSX
                            if (Test-Path "$OUTPUT_FOLDER\EntraAuditLogs\CSV\Hunt.csv")
                            {
                                if([int](& $xsv count "$OUTPUT_FOLDER\EntraAuditLogs\CSV\Hunt.csv") -gt 0)
                                {
                                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\EntraAuditLogs\CSV\Hunt.csv" -Delimiter "," | Sort-Object { $_.ActivityDateTime -as [datetime] } -Descending
                                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\EntraAuditLogs\XLSX\Hunt.xlsx" -NoHyperLinkConversion * -NoNumberConversion * -FreezePane 2,4 -BoldTopRow -AutoSize -AutoFilter -IncludePivotTable -PivotTableName "PivotTable" -WorkSheetname "EntraAuditLogs" -CellStyleSB {
                                    param($WorkSheet)
                                    # BackgroundColor and FontColor for specific cells of TopRow
                                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                    Set-Format -Address $WorkSheet.Cells["A1:BQ1"] -BackgroundColor $BackgroundColor -FontColor White
                                    # HorizontalAlignment "Center" of columns A-L and N-BQ
                                    $WorkSheet.Cells["A:L"].Style.HorizontalAlignment="Center"
                                    $WorkSheet.Cells["N:BQ"].Style.HorizontalAlignment="Center"
                                    # ConditionalFormatting - Activity
                                    $Cells = "J:J"
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Add application",$J1)))' -BackgroundColor Red # Application Creation (Privilege Escalation)
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Add delegated permission grant",$J1)))' -BackgroundColor Red # OAuth Application Permission Grant
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Add eligible member to role in PIM completed (permanent)",$J1)))' -BackgroundColor Red # AZT401 - Privileged Identity Management Role (Privilege Escalation)
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Add eligible member to role in PIM requested (permanent)",$J1)))' -BackgroundColor Red # AZT401 - Privileged Identity Management Role (Privilege Escalation)
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Add member to role completed (PIM activation)",$J1)))' -BackgroundColor Red # AZT401 - Privileged Identity Management Role (Privilege Escalation)
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Add member to role requested (PIM activation)",$J1)))' -BackgroundColor Red # AZT401 - Privileged Identity Management Role (Privilege Escalation)
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Change user password",$J1)))' -BackgroundColor Yellow # A user changes their password. Self-service password reset has to be enabled (for all or selected users) in your organization to allow users to reset their password.
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Consent to application",$J1)))' -BackgroundColor Red # OAuth Application Permission Grant
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Disable account",$J1)))' -BackgroundColor Yellow # Disable a user in Microsoft Entra ID
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Reset user password",$J1)))' -BackgroundColor Red # Administrator resets the password for a user. ATO?
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Set domain authentication",$J1)))' -BackgroundColor Red # Modification of Trusted Domain
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Set federation settings on domain",$J1)))' -BackgroundColor Red # Modification of Trusted Domain
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Update application",$J1)))' -BackgroundColor Red # Modifying Permissions / Adding Permissions (Privilege Escalation)
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Update application - Certificates and secrets management",$J1)))' -BackgroundColor Red # A user added a secret or certificate to an Entra ID Application (Privilege Escalation)
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Update StsRefreshTokenValidFrom Timestamp",$J1)))' -BackgroundColor Yellow # A Refresh Token becomes valid. Entra ID will force users to perform re-authentication whenever this attribute is updated (e.g. after Session Revoke).  
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("User registered all required security info",$J1)))' -BackgroundColor Red # MFA registered
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("User registered security info",$J1)))' -BackgroundColor Red # MFA registered
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("User reported unusual sign-in event as not legitimate",$J1)))' -BackgroundColor Red # ATO
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("User started security info registration",$J1)))' -BackgroundColor Red # MFA registered
                                    # ConditionalFormatting - StatusReason
                                    $Cells = "M:M"
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Access denied. Insufficient privileges to proceed.",$M1)))' -BackgroundColor Red # Denied Access Request
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("User failed to register Authenticator App with Code",$M1)))' -BackgroundColor Red # Persistence Attempt
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("User registered all required security info.",$M1)))' -BackgroundColor Red # Persistence
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("User registered Authenticator App with Code",$M1)))' -BackgroundColor Red # Persistence
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("User registered Authenticator App with Notification",$M1)))' -BackgroundColor Red # Persistence
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("User registered Authenticator App with Notification and Code",$M1)))' -BackgroundColor Red # Persistence
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("User started the registration for Authenticator App with Code",$M1)))' -BackgroundColor Red # Persistence
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("User started the registration for Authenticator App with Notification and Code",$M1)))' -BackgroundColor Red # Persistence

                                    # Iterating over the Application-Blacklist HashTable - Target1ModifiedProperty3NewValue
                                    foreach ($AppId in $ApplicationBlacklist_HashTable.Keys) 
                                    {
                                        $Severity = $ApplicationBlacklist_HashTable["$AppId"][1]
                                        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$AR1)))' -f $AppId
                                        Add-ConditionalFormatting -Address $WorkSheet.Cells["AR:AR"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
                                    }

                                    # Iterating over the ASN-Blacklist HashTable
                                    foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
                                    {
                                        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$T1)))' -f $ASN
                                        Add-ConditionalFormatting -Address $WorkSheet.Cells["T:T"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
                                    }

                                    # Iterating over the Country-Blacklist HashTable
                                    foreach ($Country in $CountryBlacklist_HashTable.Keys) 
                                    {
                                        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$R1)))' -f $Country
                                        Add-ConditionalFormatting -Address $WorkSheet.Cells["R:R"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
                                    }

                                    # Iterating over the UserAgent-Blacklist HashTable
                                    foreach ($UserAgent in $UserAgentBlacklist_HashTable.Keys) 
                                    {
                                        $Severity = $UserAgentBlacklist_HashTable["$UserAgent"][1]
                                        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$BL1)))' -f $UserAgent
                                        Add-ConditionalFormatting -Address $WorkSheet.Cells["BL:BL"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
                                    }

                                    }
                                }
                            }
                        }

                        # File Size (Hunt.xlsx)
                        if (Test-Path "$OUTPUT_FOLDER\EntraAuditLogs\XLSX\Hunt.xlsx")
                        {
                            $Size = Get-FileSize((Get-Item "$OUTPUT_FOLDER\EntraAuditLogs\XLSX\Hunt.xlsx").Length)
                            Write-Output "[Info]  File Size (Hunt.xlsx): $Size"
                        }

                        # ASN (Stats)
                        $Total = (Import-Csv -Path "$OUTPUT_FOLDER\EntraAuditLogs\CSV\Hunt.csv" -Delimiter "," | Select-Object ASN | Where-Object {$_.ASN -ne '' } | Measure-Object).Count
                        if ($Total -ge "1")
                        {
                            $Stats = Import-Csv -Path "$OUTPUT_FOLDER\EntraAuditLogs\CSV\Hunt.csv" -Delimiter "," | Select-Object ASN,OrgName | Where-Object {$_.ASN -ne '' } | Where-Object {$null -ne ($_.PSObject.Properties | ForEach-Object {$_.Value})} | Group-Object ASN,OrgName | Select-Object @{Name='ASN'; Expression={ $_.Values[0] }},@{Name='OrgName'; Expression={ $_.Values[1] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
                            $Stats | Export-Excel -Path "$OUTPUT_FOLDER\EntraAuditLogs\Stats\ASN.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ASN" -CellStyleSB {
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

                        # IPAddress / Country Name (Stats)
                        $Total = (Import-Csv -Path "$OUTPUT_FOLDER\EntraAuditLogs\CSV\Hunt.csv" -Delimiter "," | Select-Object IPAddress | Where-Object {$_.IPAddress -ne '' } | Measure-Object).Count
                        if ($Total -ge "1")
                        {
                            $Stats = Import-Csv -Path "$OUTPUT_FOLDER\EntraAuditLogs\CSV\Hunt.csv" -Delimiter "," -Encoding UTF8 | Select-Object IPAddress,Country,"Country Name",ASN,OrgName | Where-Object {$_.IPAddress -ne '' } | Where-Object {$_."Country Name" -ne '' } | Where-Object {$null -ne ($_.PSObject.Properties | ForEach-Object {$_.Value})} | Group-Object IPAddress,Country,"Country Name",ASN,OrgName | Select-Object @{Name='IPAddress'; Expression={ $_.Values[0] }},@{Name='Country'; Expression={ $_.Values[1] }},@{Name='Country Name'; Expression={ $_.Values[2] }},@{Name='ASN'; Expression={ $_.Values[3] }},@{Name='OrgName'; Expression={ $_.Values[4] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
                            $Stats | Export-Excel -Path "$OUTPUT_FOLDER\EntraAuditLogs\Stats\IPAddress.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "IPAddress" -CellStyleSB {
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
                        $Total = (Import-Csv -Path "$OUTPUT_FOLDER\EntraAuditLogs\CSV\Hunt.csv" -Delimiter "," | Select-Object Country | Where-Object {$_.Country -ne '' } | Measure-Object).Count
                        if ($Total -ge "1")
                        {
                            $Stats = Import-Csv "$OUTPUT_FOLDER\EntraAuditLogs\CSV\Hunt.csv" -Delimiter "," | Select-Object Country,"Country Name" | Where-Object {$_.Country -ne '' } | Where-Object {$null -ne ($_.PSObject.Properties | ForEach-Object {$_.Value})} | Group-Object Country,"Country Name" | Select-Object @{Name='Country'; Expression={ $_.Values[0] }},@{Name='Country Name'; Expression={ $_.Values[1] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
                            $Stats | Export-Excel -Path "$OUTPUT_FOLDER\EntraAuditLogs\Stats\Country.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Countries" -CellStyleSB {
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

                            $Countries = (Import-Csv -Path "$OUTPUT_FOLDER\EntraAuditLogs\CSV\Hunt.csv" -Delimiter "," | Select-Object Country -Unique | Where-Object { $_.Country -ne '' } | Measure-Object).Count
                            $Cities = (Import-Csv -Path "$OUTPUT_FOLDER\EntraAuditLogs\CSV\Hunt.csv" -Delimiter "," | Select-Object City -Unique | Where-Object { $_.City -ne '' } | Measure-Object).Count
                            Write-Output "[Info]  $Countries Countries and $Cities Cities found"
                        } 

                        # OAuth Applications --> needs to be checked: AppId vs. Target1ModifiedProperty3NewValue
                        $Data = Import-Csv -Path "$OUTPUT_FOLDER\EntraAuditLogs\CSV\Hunt.csv" -Delimiter ","

                        # Iterating over the Application-Backlist HashTable
                        foreach ($AppId in $ApplicationBlacklist_HashTable.Keys) 
                        {
                            $Import = $Data | Where-Object { $_.AppId -eq "$AppId" }
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
            }
        }
    }
}

$EndTime_IPlocation = (Get-Date)
$Time_IPlocation = ($EndTime_IPlocation-$StartTime_IPlocation)
('EntraAuditLogs IPLocation duration:   {0} h {1} min {2} sec' -f $Time_IPlocation.Hours, $Time_IPlocation.Minutes, $Time_IPlocation.Seconds) >> "$OUTPUT_FOLDER\Stats.txt"

}

Get-IPLocation

#############################################################################################################################################################################################

Function Get-Analytics {

# Import Hunt Data
if (Test-Path "$OUTPUT_FOLDER\EntraAuditLogs\CSV\Hunt.csv")
{
    $Hunt = Import-Csv -Path "$OUTPUT_FOLDER\EntraAuditLogs\CSV\Hunt.csv" -Delimiter "," -Encoding UTF8
}

# Detection Rules
$Detection = (Get-Content "$SCRIPT_DIR\EntraAuditLogs-Analyzer.ps1" | Select-String -Pattern "LETHAL-" -CaseSensitive).Count -1
Write-Output "[Info]  Running Detection Ruleset ($Detection Rules) ..."

# LETHAL-001: User registered Authenticator App with Code [T1098]
# This could be an indication of an attacker adding an auth method to the user account so they can have continued access.
$Import = $Hunt | Where-Object { $_.Service -eq 'Authentication Methods' } | Where-Object { $_.Activity -eq 'User registered security info' } | Where-Object { $_.StatusReason -eq 'User registered Authenticator App with Code' }
$Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

if ($Count -ge 1)
{
    Write-Host "[Alert] Possible MFA Bypass Attack detected: User registered Authenticator App with Code [T1098] ($Count)" -ForegroundColor Red
    New-Item "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV" -ItemType Directory -Force | Out-Null
    New-Item "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\XLSX" -ItemType Directory -Force | Out-Null

    # CSV
    $Import | Export-Csv -Path "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV\User-registered-Authenticator-App-with-Code.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV\User-registered-Authenticator-App-with-Code.csv")
    {
        if([int](& $xsv count "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV\User-registered-Authenticator-App-with-Code.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV\User-registered-Authenticator-App-with-Code.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\XLSX\User-registered-Authenticator-App-with-Code.xlsx" -NoNumberConversion * -FreezePane 2,4 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Persistence" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:BI1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-L and N-BI
            $WorkSheet.Cells["A:L"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["N:BI"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting - StatusReason
            Add-ConditionalFormatting -Address $WorkSheet.Cells["H:J,M:M"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("User registered Authenticator App with Code",$M1)))' -BackgroundColor Red
            }
        }
    }
}

# LETHAL-002: User registered Authenticator App with Notification [T1098]
# This could be an indication of an attacker adding an auth method to the user account so they can have continued access.
$Import = $Hunt | Where-Object { $_.Service -eq 'Authentication Methods' } | Where-Object { $_.Activity -eq 'User registered security info' } | Where-Object { $_.StatusReason -eq 'User registered Authenticator App with Notification' }
$Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

if ($Count -ge 1)
{
    Write-Host "[Alert] Possible MFA Bypass Attack detected: User registered Authenticator App with Notification [T1098] ($Count)" -ForegroundColor Red
    New-Item "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV" -ItemType Directory -Force | Out-Null
    New-Item "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\XLSX" -ItemType Directory -Force | Out-Null

    # CSV
    $Import | Export-Csv -Path "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV\User-registered-Authenticator-App-with-Notification.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV\User-registered-Authenticator-App-with-Notification.csv")
    {
        if([int](& $xsv count "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV\User-registered-Authenticator-App-with-Notification.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV\User-registered-Authenticator-App-with-Notification.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\XLSX\User-registered-Authenticator-App-with-Notification.xlsx" -NoNumberConversion * -FreezePane 2,4 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Persistence" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:BI1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-L and N-BI
            $WorkSheet.Cells["A:L"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["N:BI"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting - StatusReason
            Add-ConditionalFormatting -Address $WorkSheet.Cells["H:J,M:M"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("User registered Authenticator App with Notification",$M1)))' -BackgroundColor Red
            }
        }
    }
}

# LETHAL-003: User registered Authenticator App with Notification and Code [T1098]
# This could be an indication of an attacker adding an auth method to the user account so they can have continued access.
$Import = $Hunt | Where-Object { $_.Service -eq 'Authentication Methods' } | Where-Object { $_.Activity -eq 'User registered security info' } | Where-Object { $_.StatusReason -eq 'User registered Authenticator App with Notification and Code' }
$Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

if ($Count -ge 1)
{
    Write-Host "[Alert] Possible MFA Bypass Attack detected: User registered Authenticator App with Notification and Code [T1098] ($Count)" -ForegroundColor Red
    New-Item "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV" -ItemType Directory -Force | Out-Null
    New-Item "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\XLSX" -ItemType Directory -Force | Out-Null

    # CSV
    $Import | Export-Csv -Path "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV\User-registered-Authenticator-App-with-Notification-and-Code.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV\User-registered-Authenticator-App-with-Notification-and-Code.csv")
    {
        if([int](& $xsv count "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV\User-registered-Authenticator-App-with-Notification-and-Code.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV\User-registered-Authenticator-App-with-Notification-and-Code.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\XLSX\User-registered-Authenticator-App-with-Notification-and-Code.xlsx" -NoNumberConversion * -FreezePane 2,4 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Persistence" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:BI1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-L and N-BI
            $WorkSheet.Cells["A:L"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["N:BI"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting - StatusReason
            Add-ConditionalFormatting -Address $WorkSheet.Cells["H:J,M:M"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("User registered Authenticator App with Notification and Code",$M1)))' -BackgroundColor Red
            }
        }
    }
}

# LETHAL-004: Phone App Details for MFA updated (Modify Authentication Process: Multi-Factor Authentication) [T1556.006]
$Import = $Hunt | Where-Object { $_.Service -eq 'Core Directory' } | Where-Object { $_.Category -eq 'UserManagement' } | Where-Object { $_.Activity -eq 'Update User' } | Where-Object { $_.Status -eq 'success' } | Where-Object { $_.Target1ModifiedProperty1Name -eq 'StrongAuthenticationPhoneAppDetail' }
$Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

if ($Count -ge 1)
{
    Write-Host "[Alert] Phone App Details for MFA updated: Update User + StrongAuthenticationPhoneAppDetail [T1556.006] ($Count)" -ForegroundColor Red
    New-Item "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV" -ItemType Directory -Force | Out-Null
    New-Item "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\XLSX" -ItemType Directory -Force | Out-Null

    # CSV
    $Import | Export-Csv -Path "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV\StrongAuthenticationPhoneAppDetail.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV\StrongAuthenticationPhoneAppDetail.csv")
    {
        if([int](& $xsv count "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV\StrongAuthenticationPhoneAppDetail.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV\StrongAuthenticationPhoneAppDetail.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\XLSX\StrongAuthenticationPhoneAppDetail.xlsx" -NoNumberConversion * -FreezePane 2,3 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Phone App Details" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:BI1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-U and X-BI
            $WorkSheet.Cells["A:U"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["X:BI"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting - ActivityDisplayName
            Add-ConditionalFormatting -Address $WorkSheet.Cells["H:J"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Update user",$J1)))' -BackgroundColor Red
            # ConditionalFormatting - Target1ModifiedProperty1Name
            Add-ConditionalFormatting -Address $WorkSheet.Cells["AB:AB"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("StrongAuthenticationPhoneAppDetail",$AB1)))' -BackgroundColor Red # IPinfo Free
            Add-ConditionalFormatting -Address $WorkSheet.Cells["AJ:AJ"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("StrongAuthenticationPhoneAppDetail",$AJ1)))' -BackgroundColor Red # IPinfo Standard
            }
        }
    }
}

# LETHAL-005: User registered Mobile Phone SMS [T1098]
# This could be an indication of an attacker adding an auth method to the user account so they can have continued access.
$Import = $Hunt | Where-Object { $_.Service -eq 'Authentication Methods' } | Where-Object { $_.Activity -eq 'User registered security info' } | Where-Object { $_.StatusReason -eq 'User registered Mobile Phone SMS' }
$Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

if ($Count -ge 1)
{
    Write-Host "[Alert] Possible MFA Bypass Attack detected: User registered Mobile Phone SMS [T1098] ($Count)" -ForegroundColor Red
    New-Item "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV" -ItemType Directory -Force | Out-Null
    New-Item "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\XLSX" -ItemType Directory -Force | Out-Null

    # CSV
    $Import | Export-Csv -Path "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV\User-registered-Mobile-Phone-SMS.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV\User-registered-Mobile-Phone-SMS.csv")
    {
        if([int](& $xsv count "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV\User-registered-Mobile-Phone-SMS.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV\User-registered-Mobile-Phone-SMS.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\XLSX\User-registered-Mobile-Phone-SMS.xlsx" -NoNumberConversion * -FreezePane 2,3 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Persistence" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:BI1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-K and N-BI
            $WorkSheet.Cells["A:K"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["N:BI"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting - StatusReason
            Add-ConditionalFormatting -Address $WorkSheet.Cells["G:I,L:L"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("User registered Mobile Phone SMS",$L1)))' -BackgroundColor Red
            }
        }
    }
}

# Sequence 1 (First-Party Application)
# Add service principal
# Add delegated permission grant   
# Consent to application

# Sequence 2 (First-Party Application)
# Add service principal
# Add delegated permission grant
# Add app role assignment grant to user
# Consent to application

# Sequence 3 (Third-Party Application)
# Add application
# Add service principal
# Add app role assignment grant to user
# Consent to application

# LETHAL-006: Add application --> Third-Party Application
$Import = $Hunt | Where-Object { $_.Service -eq 'Core Directory' } | Where-Object { $_.Category -eq 'ApplicationManagement' } | Where-Object { $_.Activity -eq 'Add application' }
$Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

if ($Count -ge 1)
{
    Write-Host "[Alert] Enterprise App Registration detected: Add application ($Count)" -ForegroundColor Red
    New-Item "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV" -ItemType Directory -Force | Out-Null
    New-Item "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\XLSX" -ItemType Directory -Force | Out-Null

    # CSV
    $Import | Export-Csv -Path "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV\Add-application.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV\Add-application.csv")
    {
        if([int](& $xsv count "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV\Add-application.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV\Add-application.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\XLSX\Add-application.xlsx" -NoNumberConversion * -FreezePane 2,3 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Add application" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:BI1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-BI
            $WorkSheet.Cells["A:BI"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting - ActivityDisplayName
            Add-ConditionalFormatting -Address $WorkSheet.Cells["H:J"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Add application",$J1)))' -BackgroundColor Red
            }
        }
    }
}

# LETHAL-007: Add service principal - Application Access Token [T1550.001]
# https://www.elastic.co/guide/en/security/current/azure-service-principal-addition.html
$Import = $Hunt | Where-Object { $_.Service -eq 'Core Directory' } | Where-Object { $_.Category -eq 'ApplicationManagement' } | Where-Object { $_.Activity -eq 'Add service principal' }
$Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

if ($Count -ge 1)
{
    Write-Host "[Alert] Service Principal Addition detected: Add service principal [T1550.001] ($Count)" -ForegroundColor Red
    New-Item "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV" -ItemType Directory -Force | Out-Null
    New-Item "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\XLSX" -ItemType Directory -Force | Out-Null

    # CSV
    $Import | Export-Csv -Path "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV\Add-service-principal.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV\Add-service-principal.csv")
    {
        if([int](& $xsv count "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV\Add-service-principal.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV\Add-service-principal.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\XLSX\Add-service-principal.xlsx" -NoNumberConversion * -FreezePane 2,3 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Add service principal" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:BI1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-Y and AA-BI
            $WorkSheet.Cells["A:Y"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["AA:BI"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting - ActivityDisplayName
            Add-ConditionalFormatting -Address $WorkSheet.Cells["H:J"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Add service principal",$J1)))' -BackgroundColor Red
            # ConditionalFormatting - Target1DisplayName
            Add-ConditionalFormatting -Address $WorkSheet.Cells["X:X"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("eM Client",$X1)))' -BackgroundColor Red

            # ConditionalFormatting - Application-Blacklist
            foreach ($AppId in $ApplicationBlacklist_HashTable.Keys) 
            {
                $Severity = $ApplicationBlacklist_HashTable["$AppId"][1]
                $ConditionValue = 'NOT(ISERROR(FIND("{0}",$AJ1)))' -f $AppId
                Add-ConditionalFormatting -Address $WorkSheet.Cells["AJ:AJ"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
            }

            }
        }
    }
}

# LETHAL-008: Add delegated permission grant - Enterprise App Abuse [T1528]
$Import = $Hunt | Where-Object { $_.Service -eq 'Core Directory' } | Where-Object { $_.Category -eq 'ApplicationManagement' } | Where-Object { $_.Activity -eq 'Add delegated permission grant' }
$Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

if ($Count -ge 1)
{
    Write-Host "[Alert] Possible Enterprise App Abuse detected: Add delegated permission grant [T1528] ($Count)" -ForegroundColor Red
    New-Item "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV" -ItemType Directory -Force | Out-Null
    New-Item "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\XLSX" -ItemType Directory -Force | Out-Null

    # CSV
    $Import | Export-Csv -Path "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV\Add-delegated-permission-grant.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV\Add-delegated-permission-grant.csv")
    {
        if([int](& $xsv count "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV\Add-delegated-permission-grant.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV\Add-delegated-permission-grant.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\XLSX\Add-delegated-permission-grant.xlsx" -NoNumberConversion * -FreezePane 2,3 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Delegated Permission Grant" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:BI1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-U and X-BI
            $WorkSheet.Cells["A:U"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["X:BI"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting - ActivityDisplayName
            Add-ConditionalFormatting -Address $WorkSheet.Cells["H:J"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Add delegated permission grant",$J1)))' -BackgroundColor Red
            }
        }
    }
}

# LETHAL-009: Add app role assignment grant to user - Enterprise App Abuse [T1528]
$Import = $Hunt | Where-Object { $_.Service -eq 'Core Directory' } | Where-Object { $_.Category -eq 'UserManagement' } | Where-Object { $_.Activity -eq 'Add app role assignment grant to user' }
$Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

if ($Count -ge 1)
{
    Write-Host "[Alert] Possible Enterprise App Abuse detected: Add app role assignment grant to user [T1528] ($Count)" -ForegroundColor Red
    New-Item "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV" -ItemType Directory -Force | Out-Null
    New-Item "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\XLSX" -ItemType Directory -Force | Out-Null

    # CSV
    $Import | Export-Csv -Path "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV\Add-app-role-assignment-grant-to-user.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV\Add-app-role-assignment-grant-to-user.csv")
    {
        if([int](& $xsv count "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV\Add-app-role-assignment-grant-to-user.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV\Add-app-role-assignment-grant-to-user.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\XLSX\Add-app-role-assignment-grant-to-user.xlsx" -NoNumberConversion * -FreezePane 2,3 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Add app role assignment grant" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:BI1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-BI
            $WorkSheet.Cells["A:BI"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting - ActivityDisplayName
            Add-ConditionalFormatting -Address $WorkSheet.Cells["H:J"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Add app role assignment grant to user",$J1)))' -BackgroundColor Red
            # ConditionalFormatting - Target1DisplayName
            Add-ConditionalFormatting -Address $WorkSheet.Cells["Q:Q"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("eM Client",$Q1)))' -BackgroundColor Red
            }
        }
    }
}

# LETHAL-010: Admin Consent to Application
$Import = $Hunt | Where-Object { $_.Service -eq 'Core Directory' } | Where-Object { $_.Category -eq 'ApplicationManagement' }  | Where-Object { $_.Activity -eq 'Consent to application' } | Where-Object { $_.Target1ModifiedProperty1Name -eq 'ConsentContext.IsAdminConsent' } | Where-Object { $_.Target1ModifiedProperty1NewValue -eq 'True' } 
$Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

if ($Count -ge 1)
{
    Write-Host "[Alert] Admin Consent to Application detected: Consent to application w/ administrative consent ($Count)" -ForegroundColor Red
    New-Item "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV" -ItemType Directory -Force | Out-Null
    New-Item "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\XLSX" -ItemType Directory -Force | Out-Null

    # CSV
    $Import | Export-Csv -Path "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV\Admin-Consent-to-application.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV\Admin-Consent-to-application.csv")
    {
        if([int](& $xsv count "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV\Admin-Consent-to-application.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV\Admin-Consent-to-application.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\XLSX\Admin-Consent-to-application.xlsx" -NoNumberConversion * -FreezePane 2,3 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Admin Consent to application" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:BI1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-AH and AJ-BI
            $WorkSheet.Cells["A:AH"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["AJ:BI"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting - ActivityDisplayName
            Add-ConditionalFormatting -Address $WorkSheet.Cells["H:J"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Consent to application",$J1)))' -BackgroundColor Red
            # ConditionalFormatting - Target1ModifiedProperty1Name + Target1ModifiedProperty1NewValue
            Add-ConditionalFormatting -Address $WorkSheet.Cells["U:U,W:W"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '=AND($U1="ConsentContext.IsAdminConsent",$W1="True")' -BackGroundColor "Red"
            }
        }
    }
}

# LETHAL-011: User Consent to Application [T1204] --> Potential Illicit Consent Grant attack via Azure registered application
# https://docs.datadoghq.com/security/default_rules/azure-ad-consent-to-application/
$Import = $Hunt | Where-Object { $_.Service -eq 'Core Directory' } | Where-Object { $_.Category -eq 'ApplicationManagement' } | Where-Object { $_.Activity -eq 'Consent to application' } | Where-Object { $_.Target1ModifiedProperty1Name -eq 'ConsentContext.IsAdminConsent' } | Where-Object { $_.Target1ModifiedProperty1NewValue -eq 'False' } 
$Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

if ($Count -ge 1)
{
    Write-Host "[Alert] User Consent to Application detected: Consent to application w/ non-administrative consent [T1204] ($Count)" -ForegroundColor Red
    New-Item "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV" -ItemType Directory -Force | Out-Null
    New-Item "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\XLSX" -ItemType Directory -Force | Out-Null

    # CSV
    $Import | Export-Csv -Path "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV\User-Consent-to-Application.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV\User-Consent-to-Application.csv")
    {
        if([int](& $xsv count "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV\User-Consent-to-Application.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV\User-Consent-to-Application.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\XLSX\User-Consent-to-Application.xlsx" -NoNumberConversion * -FreezePane 2,3 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "User Consent to Application" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:BI1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-AH and AJ-BI
            $WorkSheet.Cells["A:AH"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["AJ:BI"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting - ActivityDisplayName
            Add-ConditionalFormatting -Address $WorkSheet.Cells["H:J"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Consent to application",$J1)))' -BackgroundColor Red
            # ConditionalFormatting - Target1DisplayName
            Add-ConditionalFormatting -Address $WorkSheet.Cells["Q:Q"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("eM Client",$Q1)))' -BackgroundColor Red
            # ConditionalFormatting - Target1ModifiedProperty1Name + Target1ModifiedProperty1NewValue
            Add-ConditionalFormatting -Address $WorkSheet.Cells["U:U,W:W"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '=AND($U1="ConsentContext.IsAdminConsent",$W1="False")' -BackGroundColor "Red"
            }
        }
    }
}

# LETHAL-012: Update application – Certificates and secrets management (Enterprise Application Credential Modification)
# Note: An attacker can add a secret or certificate to an application in order to connect to Entra ID as the application and perform Graph API operations leveraging the application permissions that are assigned to it.
$Import = $Hunt | Where-Object { $_.Service -eq 'Core Directory' } | Where-Object { $_.Category -eq 'ApplicationManagement' } | Where-Object { $_.Activity -eq 'Update application – Certificates and secrets management ' }
$Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

if ($Count -ge 1)
{
    Write-Host "[Alert] New Credential is added to an Enterprise Application: Update application – Certificates and secrets management [T1550.001] ($Count)" -ForegroundColor Red
    New-Item "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV" -ItemType Directory -Force | Out-Null
    New-Item "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\XLSX" -ItemType Directory -Force | Out-Null

    # CSV
    $Import | Export-Csv -Path "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV\Update-application-Certificates-and-secrets-management.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV\Update-application-Certificates-and-secrets-management.csv")
    {
        if([int](& $xsv count "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV\Update-application-Certificates-and-secrets-management.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV\Update-application-Certificates-and-secrets-management.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\XLSX\Update-application-Certificates-and-secrets-management.xlsx" -NoNumberConversion * -FreezePane 2,3 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "App Credential Modification" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:BI1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-AH and AJ-BI
            $WorkSheet.Cells["A:AH"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["AJ:BI"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting - ActivityDisplayName
            Add-ConditionalFormatting -Address $WorkSheet.Cells["H:J"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Update application – Certificates and secrets management",$J1)))' -BackgroundColor Red
            }
        }
    }
}

# Application-Blacklist
if (Test-Path "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV\Add-service-principal.csv")
{
    if([int](& $xsv count "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV\Add-service-principal.csv") -gt 0)
    {
        $Import = Import-Csv "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV\Add-service-principal.csv" -Delimiter ","

        foreach ($AppId in $ApplicationBlacklist_HashTable.Keys)
        {
            $Data = $Import | Where-Object { $_.Target1ModifiedProperty3NewValue -eq "$AppId" }
            $Count = [string]::Format('{0:N0}',($Data | Measure-Object).Count)
            if ($Count -gt 0)
            {
                $AppDisplayName = $ApplicationBlacklist_HashTable["$AppId"][0]
                $Severity = $ApplicationBlacklist_HashTable["$AppId"][1]
                Write-Host "[Alert] Suspicious OAuth Application detected: $AppDisplayName ($Count)" -ForegroundColor $Severity
            }
        }
    }
}

# Federation and Authentication Domain Changes
# https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-monitor-federation-changes
# https://www.microsoft.com/en-us/security/blog/2024/09/26/storm-0501-ransomware-attacks-expanding-to-hybrid-cloud-environments/

# LETHAL-013: Set domain authentication - Changed the domain authentication setting for your organization (Modification of Trusted Domain)
# Note: Adversaries may add new domain trusts or modify the properties of existing domain trusts to evade defenses and/or elevate privileges.
$Import = $Hunt | Where-Object { $_.Service -eq 'Core Directory' } | Where-Object { $_.Category -eq 'DirectoryManagement' } | Where-Object { $_.Activity -eq 'Set domain authentication.' } | Where-Object { $_.Status -eq 'success' }
$Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

if ($Count -ge 1)
{
    Write-Host "[Alert] New Federated Domain added: Set domain authentication [T1484.002] ($Count)" -ForegroundColor Red
    New-Item "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV" -ItemType Directory -Force | Out-Null
    New-Item "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\XLSX" -ItemType Directory -Force | Out-Null

    # CSV
    $Import | Export-Csv -Path "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV\Set-domain-authentication.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV\Set-domain-authentication.csv")
    {
        if([int](& $xsv count "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV\Set-domain-authentication.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV\Set-domain-authentication.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\XLSX\Set-domain-authentication.xlsx" -NoNumberConversion * -FreezePane 2,3 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Set domain authentication" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:BI1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-G and I-BI
            $WorkSheet.Cells["A:G"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["I:BI"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting - ActivityDisplayName
            Add-ConditionalFormatting -Address $WorkSheet.Cells["G:I"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Set domain authentication.",$I1)))' -BackgroundColor Red
            }
        }
    }
}

# LETHAL-014: Set federation settings on domain - Changed the federation (external sharing) settings for your organization (Modification of Trusted Domain)
# Note: Adversaries may add new domain trusts or modify the properties of existing domain trusts to evade defenses and/or elevate privileges.
$Import = $Hunt | Where-Object { $_.Service -eq 'Core Directory' } | Where-Object { $_.Category -eq 'DirectoryManagement' } | Where-Object { $_.Activity -eq 'Set federation settings on domain.' } | Where-Object { $_.Status -eq 'success' }
$Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)

if ($Count -ge 1)
{
    Write-Host "[Alert] Changes to Federation Configuration detected: Set federation settings on domain [T1484.002] ($Count)" -ForegroundColor Red
    New-Item "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV" -ItemType Directory -Force | Out-Null
    New-Item "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\XLSX" -ItemType Directory -Force | Out-Null

    # CSV
    $Import | Export-Csv -Path "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV\Set-federation-settings-on-domain.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV\Set-federation-settings-on-domain.csv")
    {
        if([int](& $xsv count "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV\Set-federation-settings-on-domain.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\CSV\Set-federation-settings-on-domain.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\EntraAuditLogs\Analytics\XLSX\Set-federation-settings-on-domain.xlsx" -NoNumberConversion * -FreezePane 2,3 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Set federation settings" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:BI1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-G and I-BI
            $WorkSheet.Cells["A:G"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["I:BI"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting - ActivityDisplayName
            Add-ConditionalFormatting -Address $WorkSheet.Cells["G:I"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Set federation settings on domain.",$I1)))' -BackgroundColor Red
            }
        }
    }
}

# Microsoft Entra Connect Sync
# Microsoft Entra Connect Sync allows establishing hybrid identity scenarios by interconnecting on-premises Active Directory and Entra ID and leveraging synchronisation features in both directions. 
# As you might already know, this brings potential for abuse of the assigned permissions to the involved service accounts and permissions of this service.
$Count = ($Hunt | Where-Object { $_."InitiatedBy (UPN)" -match "^Sync_" } | Sort-Object -Unique | Measure-Object).Count
if ($Count -gt 0)
{
    Write-Output "[Info]  $Count Microsoft Entra Connect Sync account(s) found"
    $UPN = $Hunt | Where-Object { $_."InitiatedBy (UPN)" -match "^Sync_" } | Select-Object -ExpandProperty "InitiatedBy (UPN)" -Unique
    $UPN | Out-File "$OUTPUT_FOLDER\Microsoft-Entra-Connect-Sync.txt" -Encoding utf8
    (Get-Content "$OUTPUT_FOLDER\Microsoft-Entra-Connect-Sync.txt") -replace "^", "        "  | Write-Host
}
else
{
    Write-Output "[Info]  0 Microsoft Entra Connect Sync account(s) found"
}

}

Get-Analytics

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
$MessageBody = "Status: Microsoft Entra ID Audit Log Analysis completed."
$MessageTitle = "EntraAuditLogs-Analyzer.ps1 (https://lethal-forensics.com/)"
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
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUlS61hMMBSSuJ//9Rbp/AetiW
# oqWggiT/MIIFbzCCBFegAwIBAgIQSPyTtGBVlI02p8mKidaUFjANBgkqhkiG9w0B
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
# hkiG9w0BCQQxFgQUsfDGgpCbCsMG6E+BMSC4iOYOCYcwDQYJKoZIhvcNAQEBBQAE
# ggIArazh1yn7bCnW2IDfgv3mOGL/7gBjXsZumzejAXfeAow9MN8efd6KAXBZRAzi
# KwQZ28PyDKWqqcdiBd3kOBuBnrpHhsr5IhEUTR5wb9MdAygjiXinsfVPo7HyfP8x
# J112AXQmqEJhCpZLHbV33Avfd/03SUafPYkhocuinmo9KaYmL9eKQ7oeO75aXXQd
# 6Wvw9pqJwMoFzw9iHEjqJkNsBJwjxmy/jo/gXBvDmOu4ZAcJmG1Wk7FIbL/7uCpr
# rHbRDSp18+EjbYkXUp4s6c7W/rC2wvZxU34kJSw/vfKTVwiJ1JIttiKoDv3iuzFb
# Lz0O4bB6oFW37PpRf17DrwqdusxZVndoKrkcDGYxnft9OJPVbCnHGK144KV80aba
# E08WAGOIynXVt8+ZsmJCoL6DlIePUvvWcOVmvC02I8L8Gc3D8suOV6M8b0/uHjvU
# 7jjqJPGxG9efED8FFvjFNo4DVkikocIv/2FhNdJeePFs/6KGls15ju64Eh88+iZq
# zDDlHwcYsgE11lPpBCB+KGnInttwqdHJ46bjyUwpOtQp1KYZL6O91gcbZimd5CX5
# xwJ9LCNjFBVqfGAl/3aHS0v0yK+n53sVCYv9cIApJWJ2aeyS1VoGVpPQipCvWJuV
# ot9HWgkYEjE7YdfemDQeH1uB0VX/tOdBOe5/LbDcXYkKxCChggMiMIIDHgYJKoZI
# hvcNAQkGMYIDDzCCAwsCAQEwaTBVMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2Vj
# dGlnbyBMaW1pdGVkMSwwKgYDVQQDEyNTZWN0aWdvIFB1YmxpYyBUaW1lIFN0YW1w
# aW5nIENBIFIzNgIQOlJqLITOVeYdZfzMEtjpiTANBglghkgBZQMEAgIFAKB5MBgG
# CSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI1MDIyNDA2
# MDAzOVowPwYJKoZIhvcNAQkEMTIEMHFQYUt2aIHqk8nEluciKKFaCj387bUZttNi
# BIgpiMd2P5dmP7GOlP5Xoqw8zstPcTANBgkqhkiG9w0BAQEFAASCAgBOChy/TzGO
# hUROr3y45YqRALzl/UOfZ8wnpD69cSsHE2aAAHCQmnjwisxVkx2JyiMD3BjU/u1d
# JcMa2bQQSHAgICNWKNciIQxt6dUiz5SLsQnI+MN1D8n2tf351q/zleamrDCexd0j
# pJ93JTDKHQXSXSOFvFAM8aQ2s0gRwLuTqUHZLrp7i5e/sWfM7WULJrTAIUtYUPHF
# Rez1QHXuNdjmofz8REjDd5omfzfRjM5G5lM8EEA1P7Sfbt0XnOXzGqPuRWJZ1TFK
# VGAFEVj9Kg5tDLF614SWPwudosO6BhHvo6RmJm1Pgnt/rAyRr2SaYYefGFMjw/2r
# rLFI2C6hPYKTRKcsSvuBPG+wyD4emgnTVqP4i8vAcecFLnylG19QAijMj6NFulz8
# oLob+8Ii+T/TzViDknBqsO+yr1UeZn3FKt0kv76TuFmS2KmyQqBmpbwICJeFujH5
# SZJ5abjJHXqgsc4vAi/a0H0AntSQbL1v1pbopmmMPZ4poyTg4TTusr/uiZ89GlVD
# 3PyFeVyiqtJqbmoMZKyZeeflsmyBaUoXJTPL7B1JCZigRKOQlxLfkt1ujw9kd26m
# mGsbZY3zM2noJYduUhbIDtnqA40+qq1FZaAhOfok6/EtDei8KLG7d8LTJtukBcIv
# y5YSl3BgrjujjSdsylzA09pvB+ZGAY5GlQ==
# SIG # End signature block
