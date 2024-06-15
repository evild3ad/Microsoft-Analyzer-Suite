# OAuthPermissions-Analyzer v0.2
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
# ImportExcel v7.8.6 (2023-10-13)
# https://github.com/dfinke/ImportExcel
#
# xsv v0.13.0 (2018-05-12)
# https://github.com/BurntSushi/xsv
#
#
# Changelog:
# Version 0.1
# Release Date: 2024-04-14
# Initial Release
#
# Version 0.2
# Release Date: 2024-04-28
# Added: Application Blacklist: 9
# Added: ApplicationPermission Blacklist: 60
# Added: DelegatedPermission Blacklist: 95
# Added: Severity Scoring (Permissions) --> Low, Medium, and High
# Fixed: Other minor fixes and improvements
#
#
# Tested on Windows 10 Pro (x64) Version 22H2 (10.0.19045.4291) and PowerShell 5.1 (5.1.19041.4291)
#
#
#############################################################################################################################################################################################
#############################################################################################################################################################################################

<#
.SYNOPSIS
  OAuthPermissions-Analyzer v0.2 - Automated Processing of M365 OAuth Permissions for DFIR

.DESCRIPTION
  OAuthPermissions-Analyzer.ps1 is a PowerShell script utilized to simplify the analysis of M365 OAuth Permissions extracted via "Microsoft Extractor Suite" by Invictus Incident Response.

  https://github.com/invictus-ir/Microsoft-Extractor-Suite (Microsoft-Extractor-Suite v1.3.3)

  https://microsoft-365-extractor-suite.readthedocs.io/en/latest/functionality/OAuthPermissions.html

  List delegated permissions (OAuth2PermissionGrants) and application permissions (AppRoleAssignments).

.EXAMPLE
  PS> .\OAuthPermissions-Analyzer.ps1

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
	[string]$Path
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
$OUTPUT_FOLDER = "$env:USERPROFILE\Desktop\OAuthPermissions-Analyzer"

# Tools

# xsv
$script:xsv = "$SCRIPT_DIR\Tools\xsv\xsv.exe"

#endregion Declarations

#############################################################################################################################################################################################

#region Header

# Windows Title
$DefaultWindowsTitle = $Host.UI.RawUI.WindowTitle
$Host.UI.RawUI.WindowTitle = "OAuthPermissions-Analyzer v0.2 - Automated Processing of M365 OAuth Permissions for DFIR"

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
Write-Output "OAuthPermissions-Analyzer v0.2 - Automated Processing of M365 OAuth Permissions for DFIR"
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
    Set-Format -Address $WorkSheet.Cells["A1:N1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns A-L
    $WorkSheet.Cells["A:L"].Style.HorizontalAlignment="Center"
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
