# OAuthPermissions-Analyzer
#
# @author:    Martin Willing
# @copyright: Copyright (c) 2024 Martin Willing. All rights reserved. Licensed under the MIT license.
# @contact:   Any feedback or suggestions are always welcome and much appreciated - mwilling@lethal-forensics.com
# @url:       https://lethal-forensics.com/
# @date:      2024-11-20
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
# xsv v0.13.0 (2018-05-12)
# https://github.com/BurntSushi/xsv
#
#
# Tested on Windows 10 Pro (x64) Version 22H2 (10.0.19045.5131) and PowerShell 5.1 (5.1.19041.5129)
# Tested on Windows 10 Pro (x64) Version 22H2 (10.0.19045.5131) and PowerShell 7.4.6
#
#
#############################################################################################################################################################################################
#############################################################################################################################################################################################

<#
.SYNOPSIS
  OAuthPermissions-Analyzer v0.3 - Automated Processing of M365 OAuth Permissions for DFIR

.DESCRIPTION
  OAuthPermissions-Analyzer.ps1 is a PowerShell script utilized to simplify the analysis of M365 OAuth Permissions extracted via "Microsoft Extractor Suite" by Invictus Incident Response.

  https://github.com/invictus-ir/Microsoft-Extractor-Suite (Microsoft-Extractor-Suite v2.1.0)

  https://microsoft-365-extractor-suite.readthedocs.io/en/latest/functionality/OAuthPermissions.html

  List delegated permissions (OAuth2PermissionGrants) and application permissions (AppRoleAssignments).

.PARAMETER OutputDir
  Specifies the output directory. Default is "$env:USERPROFILE\Desktop\OAuthPermissions-Analyzer".

  Note: The subdirectory 'OAuthPermissions-Analyzer' is automatically created.

.PARAMETER Path
  Specifies the path to the CSV-based input file (*-OAuthPermissions.csv).

.EXAMPLE
  PS> .\OAuthPermissions-Analyzer.ps1

.EXAMPLE
  PS> .\OAuthPermissions-Analyzer.ps1 -Path "$env:USERPROFILE\Desktop\*-OAuthPermissions.csv"

.EXAMPLE
  PS> .\OAuthPermissions-Analyzer.ps1 -Path "H:\Microsoft-Extractor-Suite\*-OAuthPermissions.csv" -OutputDir "H:\Microsoft-Analyzer-Suite"

.NOTES
  Author - Martin Willing

.LINK
  https://lethal-forensics.com/
#>

#############################################################################################################################################################################################
#############################################################################################################################################################################################

# Incident Response Checklist (Source: Invictus Incident Response)

# Use this checklist to remediate and recover from Azure App related incidents!

# - Identify the affected user accounts and applications: Determine which user accounts and applications were involved in the security incident.
# - Disable affected user accounts: Disable the user accounts associated with the security incident to prevent further unauthorized access.
# - Revoke application access: Revoke access to the affected applications for the disabled user accounts.
# - Review application permissions: Review the permissions granted to the affected applications and remove any unnecessary permissions.
# - Reset application credentials: Reset any credentials, such as passwords or secrets, for the affected applications.
# - Monitor for suspicious activity: Monitor the affected applications for any suspicious activity that could indicate ongoing security threats.
# - Investigate the security incident: Conduct a thorough investigation of the security incident to identify any vulnerabilities that need to be addressed to prevent similar incidents in the future.
# - Implement remediation measures: Implement remediation measures based on the findings of the investigation to address any security weaknesses and prevent future incidents.

# By following these steps, you can effectively revoke access for Azure applications after a security incident and take appropriate measures to protect your organization's data and resources.

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
$script:HighColor   = [System.Drawing.Color]::FromArgb(255,0,0) # Red
$script:MediumColor = [System.Drawing.Color]::FromArgb(255,192,0) # Orange
$script:LowColor    = [System.Drawing.Color]::FromArgb(255,255,0) # Yellow

# Output Directory
if (!($OutputDir))
{
    $script:OUTPUT_FOLDER = "$env:USERPROFILE\Desktop\OAuthPermissions-Analyzer" # Default
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
        $script:OUTPUT_FOLDER = "$OutputDir\OAuthPermissions-Analyzer" # Custom
    }
}

# Tools

# xsv
$script:xsv = "$SCRIPT_DIR\Tools\xsv\xsv.exe"

#endregion Declarations

#############################################################################################################################################################################################

#region Header

# Windows Title
$DefaultWindowsTitle = $Host.UI.RawUI.WindowTitle
$Host.UI.RawUI.WindowTitle = "OAuthPermissions-Analyzer v0.3 - Automated Processing of M365 OAuth Permissions for DFIR"

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

# Function Get-ScopeLink by Merill Fernando (@merill)
Function Get-ScopeLink($Scope) {
    if ([string]::IsNullOrEmpty($Scope)) { return $Scope }
    return "=HYPERLINK(`"https://graphpermissions.merill.net/permission/$Scope`",`"Link`")"
}

# Select Log File
if(!($Path))
{
    Function Get-LogFile($InitialDirectory)
    { 
        [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
        $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
        $OpenFileDialog.InitialDirectory = $InitialDirectory
        $OpenFileDialog.Filter = "OAuthPermissions|*-OAuthPermissions.csv|All Files (*.*)|*.*"
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
Write-Output "OAuthPermissions-Analyzer v0.3 - Automated Processing of M365 OAuth Permissions for DFIR"
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

# Create HashTable and import 'ApplicationPermission-Blacklist.csv'
$script:ApplicationPermissionBlacklist_HashTable = [ordered]@{}
if (Test-Path "$SCRIPT_DIR\Blacklists\ApplicationPermission-Blacklist.csv")
{
    if([int](& $xsv count "$SCRIPT_DIR\Blacklists\ApplicationPermission-Blacklist.csv") -gt 0)
    {
        Import-Csv "$SCRIPT_DIR\Blacklists\ApplicationPermission-Blacklist.csv" -Delimiter "," | ForEach-Object { $ApplicationPermissionBlacklist_HashTable[$_.Permission] = $_.DisplayText,$_.Severity }

        # Count Ingested Properties
        $Count = $ApplicationPermissionBlacklist_HashTable.Count
        Write-Output "[Info]  Initializing 'ApplicationPermission-Blacklist.csv' Lookup Table ($Count) ..."
    }
}

# Create HashTable and import 'DelegatedPermission-Blacklist.csv'
$script:DelegatedPermissionBlacklist_HashTable = [ordered]@{}
if (Test-Path "$SCRIPT_DIR\Blacklists\DelegatedPermission-Blacklist.csv")
{
    if([int](& $xsv count "$SCRIPT_DIR\Blacklists\DelegatedPermission-Blacklist.csv") -gt 0)
    {
        Import-Csv "$SCRIPT_DIR\Blacklists\DelegatedPermission-Blacklist.csv" -Delimiter "," | ForEach-Object { $DelegatedPermissionBlacklist_HashTable[$_.Permission] = $_.DisplayText,$_.Severity }

        # Count Ingested Properties
        $Count = $DelegatedPermissionBlacklist_HashTable.Count
        Write-Output "[Info]  Initializing 'DelegatedPermission-Blacklist.csv' Lookup Table ($Count) ..."
    }
}

#endregion Header

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Analysis

# What is OAuth?
# OAuth is open source standard that is used by web platforms to grant other platforms access to your environment. Entra ID uses OAuth to allow third party applications to integrate with your Microsoft 365 environment.

# OAuth Permissions

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

# Input Size
$InputSize = Get-FileSize((Get-Item "$LogFile").Length)
Write-Output "[Info]  Total Input Size: $InputSize"

# Count rows of CSV (w/ thousands separators)
[int]$Count = & $xsv count "$LogFile"
$Rows = '{0:N0}' -f $Count
Write-Output "[Info]  Total Lines: $Rows"

# Processing OAuth Permissions
Write-Output "[Info]  Processing M365 OAuth Permissions ..."
New-Item "$OUTPUT_FOLDER\OAuthPermissions\XLSX" -ItemType Directory -Force | Out-Null

# XLSX
if (Get-Module -ListAvailable -Name ImportExcel)
{
    if (Test-Path "$LogFile")
    {
        if([int](& $xsv count -d "," "$LogFile") -gt 0)
        {
            $IMPORT = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Select-Object PermissionType,ClientDisplayName,AppId,ClientObjectId,ResourceDisplayName,ResourceObjectId,Permission,@{Name='Description';Expression={if($_.Description){$_.Description}else{Get-ScopeLink $_.Permission}}},ConsentType,PrincipalObjectId,Homepage,PublisherName,ReplyUrls,@{Name="ExpiryTime";Expression={([DateTime]::ParseExact($_.ExpiryTime, "dd.MM.yyyy HH:mm:ss", $null).ToString("yyyy-MM-dd HH:mm:ss"))}},PrincipalDisplayName,IsEnabled,@{Name="CreationTimestamp";Expression={([DateTime]::ParseExact($_.CreationTimestamp, "dd.MM.yyyy HH:mm:ss", $null).ToString("yyyy-MM-dd HH:mm:ss"))}}
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\OAuthPermissions\XLSX\OAuthPermissions.xlsx" -NoHyperLinkConversion * -FreezePane 2,4 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "OAuthPermissions" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:Q1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-G, I-J, L and N-Q
            $WorkSheet.Cells["A:G"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["I:J"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["L:L"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["N:Q"].Style.HorizontalAlignment="Center"
            # Font Style "Underline" of column H (Link)
            Add-ConditionalFormatting -Address $WorkSheet.Cells["H:H"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Link",$H1)))' -Underline

            # Iterating over the Application-Blacklist HashTable
            foreach ($AppId in $ApplicationBlacklist_HashTable.Keys) 
            {
                $Severity = $ApplicationBlacklist_HashTable["$AppId"][1]
                $ConditionValue = 'NOT(ISERROR(FIND("{0}",$C1)))' -f $AppId
                Add-ConditionalFormatting -Address $WorkSheet.Cells["B:C"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
            }

            # Iterating over the ApplicationPermission-Blacklist HashTable
            foreach ($Permission in $ApplicationPermissionBlacklist_HashTable.Keys) 
            {
                $Severity = $ApplicationPermissionBlacklist_HashTable["$Permission"][1]
                if ($Severity -eq "High"){$BackgroundColor = $HighColor}
                if ($Severity -eq "Medium"){$BackgroundColor = $MediumColor}
                if ($Severity -eq "Low"){$BackgroundColor = $LowColor}
                $ConditionValue = '=AND($A1="Application",$G1="{0}")' -f $Permission
                Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $BackgroundColor
            }

            # Iterating over the DelegatedPermission-Blacklist HashTable
            foreach ($Permission in $DelegatedPermissionBlacklist_HashTable.Keys) 
            {
                $Severity = $DelegatedPermissionBlacklist_HashTable["$Permission"][1]
                if ($Severity -eq "High"){$BackgroundColor = $HighColor}
                if ($Severity -eq "Medium"){$BackgroundColor = $MediumColor}
                if ($Severity -eq "Low"){$BackgroundColor = $LowColor}
                $ConditionValue = '=AND($A1="Delegated",$G1="{0}")' -f $Permission
                Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $BackgroundColor
            }

            }
        }
    }
}

# OAuthApps
$ClientObjectId = (Import-Csv -Path "$LogFile" -Delimiter "," | Select-Object ClientObjectId -Unique | Measure-Object).Count
$ClientObjectIdCount = '{0:N0}' -f $ClientObjectId
$ClientDisplayName = (Import-Csv -Path "$LogFile" -Delimiter "," | Select-Object ClientDisplayName -Unique | Measure-Object).Count
$ClientDisplayNameCount = '{0:N0}' -f $ClientDisplayName
Write-Output "[Info]  $ClientObjectIdCount OAuth Applications found (ClientDisplayName: $ClientDisplayNameCount)"

# PermissionType
[int]$Delegated = (Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object { $_.PermissionType -eq "Delegated" } | Measure-Object).Count
[int]$Application = (Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Where-Object { $_.PermissionType -eq "Application" } | Measure-Object).Count
$DelegatedCount = '{0:N0}' -f $Delegated
$ApplicationCount = '{0:N0}' -f $Application
Write-Output "[Info]  $DelegatedCount Delegated Permissions and $ApplicationCount Application Permissions found"

# Application Permissions (AppRoleAssignments) vs. Delegated Permissions (OAuth2PermissionGrants)
# Microsoft 365 has two types of OAuth permissions: application permissions and delegated permissions. They often have similar or even identical names, but the difference is important because the scope of each permission type varies considerably.
# - Application permissions grant tenant-wide access to the permission requested. For example, an app that has been granted the application permissions Mail.Read and Files.Read.All can read all user mail and read all files. For obvious reasons, application permissions can only be granted by an admin.
# - Delegated Permissions grant the app access as that user within the confines of the permissions requested. For example, an app that has been granted the delegated permission Mail.Read can read the mail of the user who consented to the app.

# By default in Microsoft Entra ID, all users can register applications and manage all aspects of applications they create. Everyone also has the ability to consent to apps accessing company data on their behalf.
# https://learn.microsoft.com/en-us/azure/active-directory/roles/delegate-app-roles

# Create Application Registrations
# 1. Sign in to the Microsoft Entra admin center as a Global Administrator.
# 2. Browse to Identity > Users > User settings.
# 3. Set the Users can register applications setting to No.
# --> This will disable the default ability for users to create application registrations.

# Consent to applications
# 1. Browse to Identity > Enterprise applications > Consent and permissions.
# 2. Select the "Do not allow user consent" option.
# --> This will disable the default ability for users to consent to applications accessing company data on their behalf.

# File Size (XLSX)
if (Test-Path "$OUTPUT_FOLDER\OAuthPermissions\XLSX\OAuthPermissions.xlsx")
{
    $Size = Get-FileSize((Get-Item "$OUTPUT_FOLDER\OAuthPermissions\XLSX\OAuthPermissions.xlsx").Length)
    Write-Output "[Info]  File Size (XLSX): $Size"
}

# Application Permissions
$Import = Import-Excel -Path "$OUTPUT_FOLDER\OAuthPermissions\XLSX\OAuthPermissions.xlsx" | Where-Object { $_.PermissionType -eq "Application" } | Select-Object CreationTimestamp,PermissionType,ClientDisplayName,PublisherName,AppId,ClientObjectId,ResourceDisplayName,ResourceObjectId,Permission,Description,Homepage,ReplyUrls,IsEnabled | Sort-Object { $_.CreationTimestamp -as [datetime] } -Descending
$Import | Export-Excel -Path "$OUTPUT_FOLDER\OAuthPermissions\XLSX\ApplicationPermissions.xlsx" -NoHyperLinkConversion * -FreezePane 2,5 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Application Permissions" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:M1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns A-I and M
    $WorkSheet.Cells["A:I"].Style.HorizontalAlignment="Center"
    $WorkSheet.Cells["M:M"].Style.HorizontalAlignment="Center"

    # Iterating over the Application-Blacklist HashTable
    foreach ($AppId in $ApplicationBlacklist_HashTable.Keys) 
    {
        $Severity = $ApplicationBlacklist_HashTable["$AppId"][1]
        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$E1)))' -f $AppId
        Add-ConditionalFormatting -Address $WorkSheet.Cells["C:E"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
    }

    # Iterating over the ApplicationPermission-Blacklist HashTable
    foreach ($Permission in $ApplicationPermissionBlacklist_HashTable.Keys) 
    {
        $Severity = $ApplicationPermissionBlacklist_HashTable["$Permission"][1]
        if ($Severity -eq "High"){$BackgroundColor = $HighColor}
        if ($Severity -eq "Medium"){$BackgroundColor = $MediumColor}
        if ($Severity -eq "Low"){$BackgroundColor = $LowColor}
        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$I1)))' -f $Permission
        Add-ConditionalFormatting -Address $WorkSheet.Cells["I:I"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $BackgroundColor
    }
}

# Delegated Permissions
$Import = Import-Excel -Path "$OUTPUT_FOLDER\OAuthPermissions\XLSX\OAuthPermissions.xlsx" | Where-Object { $_.PermissionType -eq "Delegated" } | Select-Object PermissionType,PrincipalDisplayName,ClientDisplayName,PublisherName,AppId,ClientObjectId,ResourceDisplayName,ResourceObjectId,Permission,@{Name="Description";Expression={Get-ScopeLink $_.Permission}},ConsentType,ExpiryTime,PrincipalObjectId,Homepage,ReplyUrls
$Import | Export-Excel -Path "$OUTPUT_FOLDER\OAuthPermissions\XLSX\DelegatedPermissions.xlsx" -NoHyperLinkConversion * -FreezePane 2,4 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Delegated Permissions" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:O1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns A-L
    $WorkSheet.Cells["A:M"].Style.HorizontalAlignment="Center"
    # Font Style "Underline" of column J
    $LastRow = $WorkSheet.Dimension.End.Row
    $WorkSheet.Cells["J2:J$LastRow"].Style.Font.UnderLine = $true

    # Iterating over the Application-Blacklist HashTable
    foreach ($AppId in $ApplicationBlacklist_HashTable.Keys) 
    {
        $Severity = $ApplicationBlacklist_HashTable["$AppId"][1]
        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$E1)))' -f $AppId
        Add-ConditionalFormatting -Address $WorkSheet.Cells["C:E"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
    }

    # Iterating over the DelegatedPermission-Blacklist HashTable
    foreach ($Permission in $DelegatedPermissionBlacklist_HashTable.Keys) 
    {
        $Severity = $DelegatedPermissionBlacklist_HashTable["$Permission"][1]
        if ($Severity -eq "High"){$BackgroundColor = $HighColor}
        if ($Severity -eq "Medium"){$BackgroundColor = $MediumColor}
        if ($Severity -eq "Low"){$BackgroundColor = $LowColor}
        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$I1)))' -f $Permission
        Add-ConditionalFormatting -Address $WorkSheet.Cells["I:I"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $BackgroundColor
    }
}

# ConsentType
# Principal - Grant consent on behalf of a single user
# All Principals - Grant consent on behalf of your organization

#############################################################################################################################################################################################

# Stats
New-Item "$OUTPUT_FOLDER\OAuthPermissions\Stats\CSV" -ItemType Directory -Force | Out-Null
New-Item "$OUTPUT_FOLDER\OAuthPermissions\Stats\XLSX" -ItemType Directory -Force | Out-Null

# ClientDisplayName (Stats)
$Data = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8
$Applications = ($Data | Select-Object ClientDisplayName -Unique | Sort-Object ClientDisplayName).ClientDisplayName

ForEach($App in $Applications)
{
    $Count = ($Data | Where-Object {$_.ClientDisplayName -eq "$App"} | Select-Object PrincipalDisplayName -Unique | Measure-Object).Count

    New-Object -TypeName PSObject -Property @{
        "ClientDisplayName" = $App
        "Count"             = $Count
    } | Select-Object "ClientDisplayName","Count" | Export-Csv "$OUTPUT_FOLDER\OAuthPermissions\Stats\CSV\ClientDisplayName.csv" -NoTypeInformation -Encoding UTF8 -Append
}

# XLSX
if (Get-Module -ListAvailable -Name ImportExcel)
{
    if (Test-Path "$OUTPUT_FOLDER\OAuthPermissions\Stats\CSV\ClientDisplayName.csv")
    {
        if([int](& $xsv count -d "," "$OUTPUT_FOLDER\OAuthPermissions\Stats\CSV\ClientDisplayName.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\OAuthPermissions\Stats\CSV\ClientDisplayName.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\OAuthPermissions\Stats\XLSX\ClientDisplayName.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ClientDisplayName" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:B1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of column B
            $WorkSheet.Cells["B:B"].Style.HorizontalAlignment="Center"
            }
        }
    }
}

# ClientDisplayName / AppId (Stats)
$Data = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8
$Applications = ($Data | Select-Object AppId -Unique | Sort-Object AppId).AppId

ForEach($App in $Applications)
{
    $Count = ($Data | Where-Object {$_.AppId -eq "$App"} | Select-Object PrincipalDisplayName -Unique | Measure-Object).Count
    $ClientDisplayName = $Data | Where-Object {$_.AppId -eq "$App"} | Select-Object ClientDisplayName -Unique

    New-Object -TypeName PSObject -Property @{
        "ClientDisplayName" = $ClientDisplayName.ClientDisplayName
        "AppId"             = $App
        "Count"             = $Count
    } | Select-Object "ClientDisplayName","AppId","Count" | Export-Csv "$OUTPUT_FOLDER\OAuthPermissions\Stats\CSV\ClientDisplayName-AppId.csv" -NoTypeInformation -Encoding UTF8 -Append
}

# XLSX
if (Get-Module -ListAvailable -Name ImportExcel)
{
    if (Test-Path "$OUTPUT_FOLDER\OAuthPermissions\Stats\CSV\ClientDisplayName-AppId.csv")
    {
        if([int](& $xsv count -d "," "$OUTPUT_FOLDER\OAuthPermissions\Stats\CSV\ClientDisplayName-AppId.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\OAuthPermissions\Stats\CSV\ClientDisplayName-AppId.csv" -Delimiter "," | Sort-Object ClientDisplayName
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\OAuthPermissions\Stats\XLSX\ClientDisplayName-AppId.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ClientDisplayName" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of column B-C
            $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"

            # Iterating over the Application-Blacklist HashTable
            foreach ($AppId in $ApplicationBlacklist_HashTable.Keys) 
            {
                $Severity = $ApplicationBlacklist_HashTable["$AppId"][1]
                $ConditionValue = 'NOT(ISERROR(FIND("{0}",$B1)))' -f $AppId
                Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
            }

            }
        }
    }
}

# ClientObjectId (Stats)
$Data = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8
$ClientObjectIds = ($Data | Select-Object ClientObjectId -Unique | Sort-Object ClientObjectId).ClientObjectId

ForEach($Id in $ClientObjectIds)
{
    $Name = $Data | Where-Object {$_.ClientObjectId -eq "$Id"} | Select-Object -ExpandProperty ClientDisplayName -Unique
    $Count = ($Data | Where-Object {$_.ClientObjectId -eq "$Id"} | Select-Object PrincipalDisplayName -Unique | Measure-Object).Count

    New-Object -TypeName PSObject -Property ([ordered]@{
        "ClientDisplayName" = $Name
        "ClientObjectId"    = $Id
        "Users"             = $Count
    }) | Export-Csv "$OUTPUT_FOLDER\OAuthPermissions\Stats\CSV\ClientObjectId.csv" -NoTypeInformation -Encoding UTF8 -Append
}

# XLSX
if (Get-Module -ListAvailable -Name ImportExcel)
{
    if (Test-Path "$OUTPUT_FOLDER\OAuthPermissions\Stats\CSV\ClientObjectId.csv")
    {
        if([int](& $xsv count -d "," "$OUTPUT_FOLDER\OAuthPermissions\Stats\CSV\ClientObjectId.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\OAuthPermissions\Stats\CSV\ClientObjectId.csv" -Delimiter "," | Sort-Object { [int]$_.Users } -Descending
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\OAuthPermissions\Stats\XLSX\ClientObjectId.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ClientObjectId" -CellStyleSB {
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

# Permissions (Stats)
Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Select-Object PermissionType,Permission,@{Name='Description';Expression={if($_.Description){$_.Description}else{Get-ScopeLink $_.Permission}}} | Group-Object PermissionType,Permission,Description | Select-Object Count,@{Name='PermissionType'; Expression={ $_.Values[0] }},@{Name='Permission'; Expression={ $_.Values[1] }},@{Name='Description'; Expression={ $_.Values[2] }} | Sort-Object Count -Descending | Sort-Object Count -Descending | Export-Csv -Path "$OUTPUT_FOLDER\OAuthPermissions\Stats\CSV\Permissions.csv" -NoTypeInformation -Encoding UTF8

# XLSX
if (Get-Module -ListAvailable -Name ImportExcel)
{
    if (Test-Path "$OUTPUT_FOLDER\OAuthPermissions\Stats\CSV\Permissions.csv")
    {
        if([int](& $xsv count -d "," "$OUTPUT_FOLDER\OAuthPermissions\Stats\CSV\Permissions.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\OAuthPermissions\Stats\CSV\Permissions.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\OAuthPermissions\Stats\XLSX\Permissions.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Permissions" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-C
            $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
            # Font Style "Underline" of column D (Link)
            Add-ConditionalFormatting -Address $WorkSheet.Cells["D:D"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Link",$D1)))' -Underline

            # Iterating over the ApplicationPermission-Blacklist HashTable
            foreach ($Permission in $ApplicationPermissionBlacklist_HashTable.Keys) 
            {
                $Severity = $ApplicationPermissionBlacklist_HashTable["$Permission"][1]
                if ($Severity -eq "High"){$BackgroundColor = $HighColor}
                if ($Severity -eq "Medium"){$BackgroundColor = $MediumColor}
                if ($Severity -eq "Low"){$BackgroundColor = $LowColor}
                $ConditionValue = '=AND($B1="Application",$C1="{0}")' -f $Permission
                Add-ConditionalFormatting -Address $WorkSheet.Cells["C:C"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $BackgroundColor
            }

            # Iterating over the DelegatedPermission-Blacklist HashTable
            foreach ($Permission in $DelegatedPermissionBlacklist_HashTable.Keys) 
            {
                $Severity = $DelegatedPermissionBlacklist_HashTable["$Permission"][1]
                if ($Severity -eq "High"){$BackgroundColor = $HighColor}
                if ($Severity -eq "Medium"){$BackgroundColor = $MediumColor}
                if ($Severity -eq "Low"){$BackgroundColor = $LowColor}
                $ConditionValue = '=AND($B1="Delegated",$C1="{0}")' -f $Permission
                Add-ConditionalFormatting -Address $WorkSheet.Cells["C:C"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $BackgroundColor
            }

            }
        }
    }
}

# PermissionType / Permission (Stats)
$Total = (Import-Csv -Path "$LogFile" -Delimiter "," | Select-Object PermissionType | Measure-Object).Count
Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Group-Object PermissionType,Permission | Select-Object @{Name='PermissionType'; Expression={ $_.Values[0] }},@{Name='Permission'; Expression={ $_.Values[1] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending | Export-Csv -Path "$OUTPUT_FOLDER\OAuthPermissions\Stats\CSV\PermissionType-Permission.csv" -NoTypeInformation -Encoding UTF8

# XLSX
if (Get-Module -ListAvailable -Name ImportExcel)
{
    if (Test-Path "$OUTPUT_FOLDER\OAuthPermissions\Stats\CSV\PermissionType-Permission.csv")
    {
        if([int](& $xsv count -d "," "$OUTPUT_FOLDER\OAuthPermissions\Stats\CSV\PermissionType-Permission.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\OAuthPermissions\Stats\CSV\PermissionType-Permission.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\OAuthPermissions\Stats\XLSX\PermissionType-Permission.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Permissions" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-D
            $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"

            # Iterating over the ApplicationPermission-Blacklist HashTable
            foreach ($Permission in $ApplicationPermissionBlacklist_HashTable.Keys) 
            {
                $Severity = $ApplicationPermissionBlacklist_HashTable["$Permission"][1]
                if ($Severity -eq "High"){$BackgroundColor = $HighColor}
                if ($Severity -eq "Medium"){$BackgroundColor = $MediumColor}
                if ($Severity -eq "Low"){$BackgroundColor = $LowColor}
                $ConditionValue = '=AND($A1="Application",$B1="{0}")' -f $Permission
                Add-ConditionalFormatting -Address $WorkSheet.Cells["B:B"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $BackgroundColor
            }

            # Iterating over the DelegatedPermission-Blacklist HashTable
            foreach ($Permission in $DelegatedPermissionBlacklist_HashTable.Keys) 
            {
                $Severity = $DelegatedPermissionBlacklist_HashTable["$Permission"][1]
                if ($Severity -eq "High"){$BackgroundColor = $HighColor}
                if ($Severity -eq "Medium"){$BackgroundColor = $MediumColor}
                if ($Severity -eq "Low"){$BackgroundColor = $LowColor}
                $ConditionValue = '=AND($A1="Delegated",$B1="{0}")' -f $Permission
                Add-ConditionalFormatting -Address $WorkSheet.Cells["B:B"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $BackgroundColor
            }

            }
        }
    }
}

# PrincipalDisplayName (Stats)
$Data = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8
$PrincipalDisplayNames = ($Data | Select-Object PrincipalDisplayName | Where-Object {$_.PrincipalDisplayName -ne '' } | Where-Object { $null -ne ($_.PSObject.Properties | ForEach-Object {$_.Value})} | Select-Object PrincipalDisplayName -Unique | Sort-Object PrincipalDisplayName).PrincipalDisplayName

ForEach($PrincipalDisplayName in $PrincipalDisplayNames)
{
    $Permissions  = ($Data | Where-Object {$_.PrincipalDisplayName -eq "$PrincipalDisplayName"} | Select-Object Permissions | Measure-Object).Count
    $Applications = ($Data | Where-Object {$_.PrincipalDisplayName -eq "$PrincipalDisplayName"} | Select-Object AppId -Unique | Measure-Object).Count

    New-Object -TypeName PSObject -Property ([ordered]@{
        "PrincipalDisplayName" = $PrincipalDisplayName
        "Applications"         = $Applications
        "Permissions"          = $Permissions
    }) | Export-Csv "$OUTPUT_FOLDER\OAuthPermissions\Stats\CSV\PrincipalDisplayName.csv" -NoTypeInformation -Encoding UTF8 -Append
}

# XLSX
if (Get-Module -ListAvailable -Name ImportExcel)
{
    if (Test-Path "$OUTPUT_FOLDER\OAuthPermissions\Stats\CSV\PrincipalDisplayName.csv")
    {
        if([int](& $xsv count -d "," "$OUTPUT_FOLDER\OAuthPermissions\Stats\CSV\PrincipalDisplayName.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\OAuthPermissions\Stats\CSV\PrincipalDisplayName.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\OAuthPermissions\Stats\XLSX\PrincipalDisplayName.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "PrincipalDisplayName" -CellStyleSB {
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

# PublisherName (Stats)
# Note: Permissions Count
$Total = (Import-Csv -Path "$LogFile" -Delimiter "," | Select-Object PublisherName | Measure-Object).Count
$PublisherNames = (Import-Csv -Path "$LogFile" -Delimiter "," | Select-Object PublisherName | Sort-Object PublisherName -Unique | Measure-Object).Count
Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Select-Object PublisherName | Where-Object {$_.PublisherName -ne '' } | Where-Object { $null -ne ($_.PSObject.Properties | ForEach-Object {$_.Value})} | Group-Object PublisherName | Select-Object @{Name='PublisherName'; Expression={ $_.Values[0] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending | Export-Csv -Path "$OUTPUT_FOLDER\OAuthPermissions\Stats\CSV\PublisherName.csv" -NoTypeInformation -Encoding UTF8
Write-Output "[Info]  $PublisherNames Publisher Name(s) found ($Total)"

# XLSX
if (Get-Module -ListAvailable -Name ImportExcel)
{
    if (Test-Path "$OUTPUT_FOLDER\OAuthPermissions\Stats\CSV\PublisherName.csv")
    {
        if([int](& $xsv count -d "," "$OUTPUT_FOLDER\OAuthPermissions\Stats\CSV\PublisherName.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\OAuthPermissions\Stats\CSV\PublisherName.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\OAuthPermissions\Stats\XLSX\PublisherName.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "PublisherName" -CellStyleSB {
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

# PublisherName / ClientDisplayName (Stats)
$Total = (Import-Csv -Path "$LogFile" -Delimiter "," | Select-Object PublisherName | Measure-Object).Count
Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Group-Object PublisherName,ClientDisplayName | Select-Object @{Name='PublisherName'; Expression={ $_.Values[0] }},@{Name='ClientDisplayName'; Expression={ $_.Values[1] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending | Sort-Object Count -Descending | Export-Csv -Path "$OUTPUT_FOLDER\OAuthPermissions\Stats\CSV\PublisherName-ClientDisplayName.csv" -NoTypeInformation -Encoding UTF8

# XLSX
if (Get-Module -ListAvailable -Name ImportExcel)
{
    if (Test-Path "$OUTPUT_FOLDER\OAuthPermissions\Stats\CSV\PublisherName-ClientDisplayName.csv")
    {
        if([int](& $xsv count -d "," "$OUTPUT_FOLDER\OAuthPermissions\Stats\CSV\PublisherName-ClientDisplayName.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\OAuthPermissions\Stats\CSV\PublisherName-ClientDisplayName.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\OAuthPermissions\Stats\XLSX\PublisherName-ClientDisplayName.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "PublisherName" -CellStyleSB {
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

# ResourceDisplayName (Stats)
$Total = (Import-Csv -Path "$LogFile" -Delimiter "," | Select-Object ResourceDisplayName | Measure-Object).Count
Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Select-Object ResourceDisplayName | Where-Object {$_.ResourceDisplayName -ne '' } | Where-Object { $null -ne ($_.PSObject.Properties | ForEach-Object {$_.Value})} | Group-Object ResourceDisplayName | Select-Object @{Name='ResourceDisplayName'; Expression={ $_.Values[0] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending | Export-Csv -Path "$OUTPUT_FOLDER\OAuthPermissions\Stats\CSV\ResourceDisplayName.csv" -NoTypeInformation -Encoding UTF8

# XLSX
if (Get-Module -ListAvailable -Name ImportExcel)
{
    if (Test-Path "$OUTPUT_FOLDER\OAuthPermissions\Stats\CSV\ResourceDisplayName.csv")
    {
        if([int](& $xsv count -d "," "$OUTPUT_FOLDER\OAuthPermissions\Stats\CSV\ResourceDisplayName.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\OAuthPermissions\Stats\CSV\ResourceDisplayName.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\OAuthPermissions\Stats\XLSX\ResourceDisplayName.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ResourceDisplayName" -CellStyleSB {
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

#############################################################################################################################################################################################

# Risky OAuth Applications

# Application Permissions
$Data = Import-Excel -Path "$OUTPUT_FOLDER\OAuthPermissions\XLSX\ApplicationPermissions.xlsx"

foreach ($AppId in $ApplicationBlacklist_HashTable.Keys) 
{
    $Import = $Data | Where-Object { $_.AppId -eq "$AppId" }
    $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
    if ($Count -gt 0)
    {
        $AppDisplayName = $ApplicationBlacklist_HashTable["$AppId"][0]
        $Severity = $ApplicationBlacklist_HashTable["$AppId"][1]
        Write-Host "[Alert] Suspicious OAuth Application detected (Application): $AppDisplayName ($Count)" -ForegroundColor $Severity
    }
}

# Delegated Permissions
$Data = Import-Excel -Path "$OUTPUT_FOLDER\OAuthPermissions\XLSX\DelegatedPermissions.xlsx"

foreach ($AppId in $ApplicationBlacklist_HashTable.Keys) 
{
    $Import = $Data | Where-Object { $_.AppId -eq "$AppId" }
    $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
    if ($Count -gt 0)
    {
        $AppDisplayName = $ApplicationBlacklist_HashTable["$AppId"][0]
        $Severity = $ApplicationBlacklist_HashTable["$AppId"][1]
        Write-Host "[Alert] Suspicious OAuth Application detected (Delegated): $AppDisplayName ($Count)" -ForegroundColor $Severity
    }
}

}

Start-Processing

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
Start-Sleep -Milliseconds 500

# MessageBox UI
$MessageBody = "Status: OAuth Permissions Analysis completed."
$MessageTitle = "OAuthPermissions-Analyzer.ps1 (https://lethal-forensics.com/)"
$ButtonType = "OK"
$MessageIcon = "Information"
$Result = [System.Windows.Forms.MessageBox]::Show($MessageBody, $MessageTitle, $ButtonType, $MessageIcon)

if ($Result -eq "OK" ) 
{
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

#endregion Footer

#############################################################################################################################################################################################
#############################################################################################################################################################################################

# TODO

# https://github.com/randomaccess3/detections/blob/main/M365_Oauth_Apps/MaliciousOauthAppDetections.json

# https://github.com/mandiant/Mandiant-Azure-AD-Investigator 

# https://www.huntress.com/blog/legitimate-apps-as-traitorware-for-persistent-microsoft-365-compromise

# https://m365internals.com/2021/07/24/everything-about-service-principals-applications-and-api-permissions/

# Malicious Application Consent / OAuth
# Step 1 - Determine the registered applications through "App registrations" and "Enterprise applications" in Microsoft Entra ID. Write down the Application ID.
# Step 2 - Investigate the Audit logs to determine when, how and by whom the application was registered in the environment. Filter on Operation/Actvity "Add application".
#          Date (UTC) = When the application was registered
#          Display Name = How and by whom the application was registered
#          AppId = AppID of the malicious application
# Step 3 - Inspect the permissions and users of the application to determine possible impact.
#          Option 1 - Azure AD --> Enterprise Application --> App name --> Permissions
#          Note: Check both Admin & User consent to determine the API’s and users who granted permissions.
#          Option 2 - PowerShell
#          Option 3 - Automated through Get-AzureADPSPermissions script --> https://gist.github.com/psignoret/41793f8c6211d2df5051d77ca3728c09
# Step 4 - Identify the activity of the malicious application. Using the Application ID sometimes called the Client ID we can track activity belonging to an application throughout Azure (AD) and Microsoft 365.
#          Note: Check ADAuditLog and Sign-Ins
# Step 5 - Incident Response checklist
# SIG # Begin signature block
# MIIrxQYJKoZIhvcNAQcCoIIrtjCCK7ICAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUW6HMPoUb4uiQg+hY2nMdIk0Z
# JpaggiT/MIIFbzCCBFegAwIBAgIQSPyTtGBVlI02p8mKidaUFjANBgkqhkiG9w0B
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
# hkiG9w0BCQQxFgQUJGADBd4CISz8aEzxfcAFvu50b5owDQYJKoZIhvcNAQEBBQAE
# ggIAfGRdZWaK6YBW9EiJR8q+S34mBfaZnrysJN0frO71FelFQRPIWQAtTH+M71iH
# xQdVnxHD5+n80B8Jb5hv3njcQlro6S9WifwZTvM7k8GRnPpAdUbF1yc74xahoYGH
# EmXY2CYrSFdwBGw3QjteeFR/LA1n/Hd3CLsRbsaxSHcuEkt9nkQsOAKBxTLLQopF
# raEl8N8FfausmDbw+lbj1GCh3cpycype0SPpf94CMysMpjmbwM4th1wTPrX1QyQ5
# lVNODQ9aqB56+9Ev6ckNzOGpSZs3e22obYjUvSNy+NCUeUzu6KeRKqW95HkYQE+q
# mJnfrHog0bQIn6L/9xZtM5FSkCeUVNTfMfosSyebLm17L6ZAqEtpMIIRSB/K19Eg
# iv+gglYgsTHCy5+NRm8c+Lx8qRUG1nHCwkMq5W+N1F5Z72F3XVLiabiMeTYKEH2U
# 5DSgquyoMoAiJwdkeLE9oLy9TYNPYPW3Hnxy+usqOTCkEahy7w7MXbKAxdZoqzqm
# G95Dbm2Brr0iwoNdD/BEjQYi0HgF15qcBwHr7uKR5NOMPVDWxoucvG7yQOmVAP2F
# 3zCSSvzD32ZkIRojmlNgyC4wmVK/C2MKJ553hgmgkBbofrrxgPSK9+vzrYaMSKcC
# GoiFMb30lVIb1+n6fzGSlF3S0innX/Ox2S6bdpIAh8Q0HXuhggMiMIIDHgYJKoZI
# hvcNAQkGMYIDDzCCAwsCAQEwaTBVMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2Vj
# dGlnbyBMaW1pdGVkMSwwKgYDVQQDEyNTZWN0aWdvIFB1YmxpYyBUaW1lIFN0YW1w
# aW5nIENBIFIzNgIQOlJqLITOVeYdZfzMEtjpiTANBglghkgBZQMEAgIFAKB5MBgG
# CSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI0MTEyMDA1
# NDYwNFowPwYJKoZIhvcNAQkEMTIEMCFWsktcCk4xfX9J0C5zdCEir+JiGaSEmg38
# 0ZvOyiNWX4Mb+WFqXiginguZuj2+kzANBgkqhkiG9w0BAQEFAASCAgBoHfdebupX
# MyY6Zsog03iBPFxXwg1n0kzXLdXq1XfPDldl4pdAVhBD1bvMaIqDtTApiI/CMqXP
# +JwpxP50b91q9woI09Tyl07VmiseC9hFd1rclH1KzQEpaiTBSy62niuAlIQ/k270
# yvTKn/UDMpvDvQJVhYODFLOH/esMINdxl3avyLMUVXTUF3UOQR92x0rWN+iZYzk9
# HFPV5aB5UERze7uWC4ceGvYdTU/V0jyvw33I9B23U9LcxfiKTzKgjiWhtFtvTO03
# a5RVqDyn+bq4tTXJub72fn/XTubakb3wSSu0zMpM6zaUgzOArf0s8dUQeDs21JNq
# j3Zg3bA2QcyuSqAiaLQXNXnuXxO2Sarnm9iIcqDvjz8f4BX8qnrDGfQMzAa94mKR
# 9LCkwX/6zcbsRRSJebolat/zUevtn0mBSyyS1NE+2530WMVtGo73JzTA/4aXcgjP
# dzbHqK7JoabYk4x3cEQUSvrZmkDQK2Z5L/NbE9R3/NQEqM1QYNZ6JB1ne4jigGJ4
# mgg2jrz+M58FmMVm9JtCa1SFlNFRO9IxHQrpYFnJdCpUzFplz/xKWSEhS0FLpmqZ
# DaRARo8gd1lt0qBqALRXzw9PsFFJKUdrUZbAOxlkP95O5iFBMGEXU0R9WdnoHQrQ
# ho0Z70CIY4lf6HKIaWGaMMvysuyWnOt0dg==
# SIG # End signature block
