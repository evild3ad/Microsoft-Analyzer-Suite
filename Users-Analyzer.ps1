# Users-Analyzer v0.2
#
# @author:    Martin Willing
# @copyright: Copyright (c) 2024 Martin Willing. All rights reserved.
# @contact:   Any feedback or suggestions are always welcome and much appreciated - mwilling@lethal-forensics.com
# @url:       https://lethal-forensics.com/
# @date:      2024-10-16
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
#
# Changelog:
# Version 0.1
# Release Date: 2024-06-13
# Initial Release
#
# Version 0.2
# Release Date: 2024-10-16
# Added: CmdletBinding
# Added: PowerShell 7 Support
#
# Tested on Windows 10 Pro (x64) Version 22H2 (10.0.19045.5011) and PowerShell 5.1 (5.1.19041.5007)
# Tested on Windows 10 Pro (x64) Version 22H2 (10.0.19045.5011) and PowerShell 7.4.5
#
#
#############################################################################################################################################################################################
#############################################################################################################################################################################################

<#
.SYNOPSIS
  Users-Analyzer v0.2 - Automated Processing of 'Users.csv' (Microsoft-Extractor-Suite by Invictus-IR)

.DESCRIPTION
  Users-Analyzer.ps1 is a PowerShell script utilized to simplify the analysis of the User Information extracted via "Microsoft Extractor Suite" by Invictus Incident Response.

  https://github.com/invictus-ir/Microsoft-Extractor-Suite (Microsoft-Extractor-Suite v2.1.0)

  https://microsoft-365-extractor-suite.readthedocs.io/en/latest/functionality/GetUserInfo.html#retrieve-information-for-all-users

.PARAMETER OutputDir
  Specifies the output directory. Default is "$env:USERPROFILE\Desktop\Users-Analyzer".

  Note: The subdirectory 'Users-Analyzer' is automatically created.

.PARAMETER Path
  Specifies the path to the CSV-based input file (Users.csv).

.EXAMPLE
  PS> .\Users-Analyzer.ps1

.EXAMPLE
  PS> .\Users-Analyzer.ps1 -Path "$env:USERPROFILE\Desktop\Users.csv"

.EXAMPLE
  PS> .\Users-Analyzer.ps1 -Path "H:\Microsoft-Extractor-Suite\Users.csv" -OutputDir "H:\Microsoft-Analyzer-Suite"

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

#region Declarations

# Declarations

# Output Directory
if (!($OutputDir))
{
    $script:OUTPUT_FOLDER = "$env:USERPROFILE\Desktop\Users-Analyzer" # Default
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
        $script:OUTPUT_FOLDER = "$OutputDir\Users-Analyzer" # Custom
    }
}

#endregion Declarations

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Header

# Windows Title
$DefaultWindowsTitle = $Host.UI.RawUI.WindowTitle
$Host.UI.RawUI.WindowTitle = "Users-Analyzer v0.2 - Automated Processing of 'Users.csv' (Microsoft-Extractor-Suite by Invictus-IR)"

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
        $OpenFileDialog.Filter = "Users|Users.csv|All Files (*.*)|*.*"
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
Write-Output "Users-Analyzer v0.2 - Automated Processing of 'Users.csv'"
Write-Output "(c) 2024 Martin Willing at Lethal-Forensics (https://lethal-forensics.com/)"
Write-Output ""

# Analysis date (ISO 8601)
$AnalysisDate = [datetime]::Now.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
Write-Output "Analysis date: $AnalysisDate UTC"
Write-Output ""

#endregion Header

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Analysis

# User Information
# https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.users/get-mguser?view=graph-powershell-1.0

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
$Count = 0
switch -File "$LogFile" { default { ++$Count } }
$Rows = '{0:N0}' -f $Count
Write-Output "[Info]  Total Lines: $Rows"

# Processing Users.csv
Write-Output "[Info]  Processing Users.csv ..."

# XLSX
if (Get-Module -ListAvailable -Name ImportExcel)
{
    if (Test-Path "$LogFile")
    {
        if(!([String]::IsNullOrWhiteSpace((Get-Content "$LogFile"))))
        {
            $IMPORT = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Select-Object Id,AccountEnabled,DisplayName,UserPrincipalName,Mail,@{Name="CreatedDateTime";Expression={([DateTime]::Parse($_.CreatedDateTime).ToString("yyyy-MM-dd HH:mm:ss"))}},@{Name="LastPasswordChangeDateTime";Expression={([DateTime]::Parse($_.LastPasswordChangeDateTime).ToString("yyyy-MM-dd HH:mm:ss"))}},@{Name="DeletedDateTime";Expression={([DateTime]::Parse($_.DeletedDateTime).ToString("yyyy-MM-dd HH:mm:ss"))}},JobTitle,Department,OfficeLocation,City,State,Country | Sort-Object { $_.CreatedDateTime -as [datetime] } -Descending
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Users.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "User Information" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:N1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-N
            $WorkSheet.Cells["A:N"].Style.HorizontalAlignment="Center"
            }
        }
    }
}
else
{
    Write-Host "[Error] PowerShell module 'ImportExcel' NOT found." -ForegroundColor Red
}

# File Size (XLSX)
if (Test-Path "$OUTPUT_FOLDER\Userinformation.xlsx")
{
    $Size = Get-FileSize((Get-Item "$OUTPUT_FOLDER\Userinformation.xlsx").Length)
    Write-Output "[Info]  File Size (XLSX): $Size"
}

# Count Users
$Total = (Import-Csv -Path "$LogFile" -Delimiter "," | Select-Object Id -Unique | Measure-Object).Count
$Users = '{0:N0}' -f $Total
Write-Output "[Info]  $Users User Account(s) found"

# Count enabled accounts
$Count = (Import-Csv -Path "$LogFile" -Delimiter "," | Where-Object { $_.AccountEnabled -eq "True" } | Measure-Object).Count
$AccountEnabled = '{0:N0}' -f $Count
$PercentUse = "{0:p2}" -f ($Count / $Total)
Write-Output "[Info]  $AccountEnabled out of $Users User Account(s) are enabled ($PercentUse)"

# Count disabled accounts
$Count = (Import-Csv -Path "$LogFile" -Delimiter "," | Where-Object { $_.AccountEnabled -eq "False" } | Measure-Object).Count
$AccountDisabled = '{0:N0}' -f $Count
$PercentUse = "{0:p2}" -f ($Count / $Total)
Write-Output "[Info]  $AccountDisabled out of $Users User Account(s) are disabled ($PercentUse)"

# Count users created within the last 7 days
$Date = (Get-Date).AddDays(-7)
$Count = (Import-Csv -Path "$LogFile" -Delimiter "," | Where-Object -FilterScript {[DateTime]::Parse($_.CreatedDateTime) -gt $Date} | Measure-Object).Count
$Users = '{0:N0}' -f $Count
Write-Output "[Info]  $Users users created within the last 7 days"

# Count users created within the last 30 days
$Date = (Get-Date).AddDays(-30)
$Count = (Import-Csv -Path "$LogFile" -Delimiter "," | Where-Object -FilterScript {[DateTime]::Parse($_.CreatedDateTime) -gt $Date} | Measure-Object).Count
$Users = '{0:N0}' -f $Count
Write-Output "[Info]  $Users users created within the last 30 days"

# Count users created within the last 90 days
$Date = (Get-Date).AddDays(-90)
$Count = (Import-Csv -Path "$LogFile" -Delimiter "," | Where-Object -FilterScript {[DateTime]::Parse($_.CreatedDateTime) -gt $Date} | Measure-Object).Count
$Users = '{0:N0}' -f $Count
Write-Output "[Info]  $Users users created within the last 90 days"

# Count users created within the last 6 months
$Date = (Get-Date).AddDays(-180)
$Count = (Import-Csv -Path "$LogFile" -Delimiter "," | Where-Object -FilterScript {[DateTime]::Parse($_.CreatedDateTime) -gt $Date} | Measure-Object).Count
$Users = '{0:N0}' -f $Count
Write-Output "[Info]  $Users users created within the last 6 months"

# Count users created within the last 1 year
$Date = (Get-Date).AddDays(-360)
$Count = (Import-Csv -Path "$LogFile" -Delimiter "," | Where-Object -FilterScript {[DateTime]::Parse($_.CreatedDateTime) -gt $Date} | Measure-Object).Count
$Users = '{0:N0}' -f $Count
Write-Output "[Info]  $Users users created within the last 1 year"

# Count Guest User Accounts (External Identities)
$Count = (Import-Csv "$LogFile" -Delimiter "," | Where-Object { $_.UserPrincipalName -match "#EXT#@" } | Measure-Object).Count
$Guests = '{0:N0}' -f $Count
Write-Output "[Info]  $Guests Guest User Account(s) found ($Total)"

# Microsoft Entra Connect Sync
# Microsoft Entra Connect Sync allows establishing hybrid identity scenarios by interconnecting on-premises Active Directory and Entra ID and leveraging synchronisation features in both directions. 
# As you might already know, this brings potential for abuse of the assigned permissions to the involved service accounts and permissions of this service.
$Count = (Import-Csv -Path "$LogFile" -Delimiter "," | Where-Object { $_.UserPrincipalName -match "^Sync_" } | Measure-Object).Count
if ($Count -gt 0)
{
    Write-Output "[Info]  $Count Microsoft Entra Connect Sync account(s) found"
    $UPN = Import-Csv -Path "$LogFile" -Delimiter "," | Where-Object { $_.UserPrincipalName -match "^Sync_" } | Select-Object -ExpandProperty UserPrincipalName -Unique
    $UPN | Out-File "$OUTPUT_FOLDER\Microsoft-Entra-Connect-Sync.txt" -Encoding utf8
    (Get-Content "$OUTPUT_FOLDER\Microsoft-Entra-Connect-Sync.txt") -replace "^", "        "  | Write-Host
}
else
{
    Write-Output "[Info]  0 Microsoft Entra Connect Sync account(s) found"
}

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
Start-Sleep 1

# Reset Windows Title
$Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"

#endregion Footer

#############################################################################################################################################################################################
#############################################################################################################################################################################################
