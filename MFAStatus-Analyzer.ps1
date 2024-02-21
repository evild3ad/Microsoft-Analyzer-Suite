# MFAStatus-Analyzer v0.1
#
# @author:    Martin Willing
# @copyright: Copyright (c) 2024 Martin Willing. All rights reserved.
# @contact:   Any feedback or suggestions are always welcome and much appreciated - mwilling@lethal-forensics.com
# @url:       https://lethal-forensics.com/
# @date:      2024-02-21
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
#
# Changelog:
# Version 0.1
# Release Date: 2024-02-21
# Initial Release
#
#
#############################################################################################################################################################################################
#############################################################################################################################################################################################

<#
.SYNOPSIS
  MFAStatus-Analyzer v0.1 - Automated Processing of 'MFAStatus.csv' (Microsoft-Extractor-Suite by Invictus-IR)

.DESCRIPTION
  MFAStatus-Analyzer.ps1 is a PowerShell script utilized to simplify the analysis of the MFA Status of all users extracted via "Microsoft 365 Extractor Suite" by Invictus Incident Response.

  https://github.com/invictus-ir/Microsoft-Extractor-Suite (Microsoft-365-Extractor-Suite v1.2.2)

.EXAMPLE
  PS> .\MFAStatus-Analyzer.ps1

.NOTES
  Author - Martin Willing

.LINK
  https://lethal-forensics.com/
#>

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
$OUTPUT_FOLDER = "$env:USERPROFILE\Desktop\MFAStatus-Analyzer"

#endregion Declarations

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Header

# Windows Title
$DefaultWindowsTitle = $Host.UI.RawUI.WindowTitle
$Host.UI.RawUI.WindowTitle = "MFAStatus-Analyzer v0.1 - Automated Processing of 'MFAStatus.csv' (Microsoft-Extractor-Suite by Invictus-IR)"

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
Function Get-LogFile($InitialDirectory)
{ 
    [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
    $OpenFileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $OpenFileDialog.InitialDirectory = $InitialDirectory
    $OpenFileDialog.Filter = "MFAStatus (MFAStatus.csv)|MFAStatus.csv|All Files (*.*)|*.*"
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
Write-Output "MFAStatus-Analyzer v0.1 - Automated Processing of 'MFAStatus.csv'"
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

# Processing MFAStatus.csv
Write-Output "[Info]  Processing MFAStatus.csv ..."

# XLSX
if (Get-Module -ListAvailable -Name ImportExcel)
{
    if (Test-Path "$LogFile")
    {
        if(!([String]::IsNullOrWhiteSpace((Get-Content "$LogFile"))))
        {
            $IMPORT = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\MFAStatus.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "MFA Status" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:J1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns B-J
            $WorkSheet.Cells["B:J"].Style.HorizontalAlignment="Center"
            }
        }
    }
}
else
{
    Write-Host "[Error] PowerShell module 'ImportExcel' NOT found." -ForegroundColor Red
}

# Count Users (UPN)
$Count = (Import-Csv -Path "$LogFile" -Delimiter "," | Measure-Object).Count
$Users = '{0:N0}' -f $Count
Write-Output "[Info]  $Users Users found"

# File Size (XLSX)
if (Test-Path "$OUTPUT_FOLDER\MFAStatus.xlsx")
{
    $Size = Get-FileSize((Get-Item "$OUTPUT_FOLDER\MFAStatus.xlsx").Length)
    Write-Output "[Info]  File Size (XLSX): $Size"
}

# Stats

# MFA Status - Enabled
$Enabled = (Import-Csv -Path "$LogFile" -Delimiter "," | Where-Object { $_.MFAstatus -eq "Enabled" } | Measure-Object).Count
$MFAEnabled = '{0:N0}' -f $Enabled
Write-Output "[Info]  $MFAEnabled Users have MFA enabled ($Users)"

# Email Authentication Method
# https://learn.microsoft.com/en-us/graph/api/resources/emailauthenticationmethod?view=graph-rest-1.0
$Count = (Import-Csv -Path "$LogFile" -Delimiter "," | Where-Object { $_.email -eq "True" } | Measure-Object).Count
$Email = '{0:N0}' -f $Count
Write-Output "[Info]  $Email Users registered an email address for self-service password reset (SSPR)"

# FIDO2 Authentication Method
# https://learn.microsoft.com/en-us/graph/api/resources/fido2authenticationmethod?view=graph-rest-1.0
$Count = (Import-Csv -Path "$LogFile" -Delimiter "," | Where-Object { $_.fido2 -eq "True" } | Measure-Object).Count
$FIDO2 = '{0:N0}' -f $Count
Write-Output "[Info]  $FIDO2 User(s) sign in with FIDO2 Security Keys"

# Microsoft Authenticator Authentication Method
# https://learn.microsoft.com/en-us/graph/api/resources/microsoftauthenticatorauthenticationmethod?view=graph-rest-1.0
$Count = (Import-Csv -Path "$LogFile" -Delimiter "," | Where-Object { $_.app -eq "True" } | Measure-Object).Count
$App = '{0:N0}' -f $Count
Write-Output "[Info]  $App User(s) sign in with the Microsoft Authenticator app"

# Phone Authentication Method
# https://learn.microsoft.com/en-us/graph/api/resources/phoneauthenticationmethod?view=graph-rest-1.0
$Count = (Import-Csv -Path "$LogFile" -Delimiter "," | Where-Object { $_.phone -eq "True" } | Measure-Object).Count
$Phone = '{0:N0}' -f $Count
Write-Output "[Info]  $Phone User(s) sign in with a phone call or a text message (SMS)"

# Software Oath Authentication Method (Software Token)
# https://learn.microsoft.com/en-us/graph/api/resources/softwareoathauthenticationmethod?view=graph-rest-1.0
$Count = (Import-Csv -Path "$LogFile" -Delimiter "," | Where-Object { $_.softwareoath -eq "True" } | Measure-Object).Count
$SoftwareOath = '{0:N0}' -f $Count
Write-Output "[Info]  $SoftwareOath User(s) sign in with an OATH Time-Based One Time Password (TOTP)"

# Temporary Access Pass Authentication Method (Passwordless)
# https://learn.microsoft.com/en-us/graph/api/resources/temporaryaccesspassauthenticationmethod?view=graph-rest-1.0
$Count = (Import-Csv -Path "$LogFile" -Delimiter "," | Where-Object { $_.tempaccess -eq "True" } | Measure-Object).Count
$TempAccess = '{0:N0}' -f $Count
Write-Output "[Info]  $TempAccess User(s) sign in with a Temporary Access Pass (TAP)"

# Hello For Business Authentication Method (Passwordless)
# https://learn.microsoft.com/en-us/graph/api/resources/windowshelloforbusinessauthenticationmethod?view=graph-rest-1.0
$Count = (Import-Csv -Path "$LogFile" -Delimiter "," | Where-Object { $_.hellobusiness -eq "True" } | Measure-Object).Count
$HelloBusiness = '{0:N0}' -f $Count
Write-Output "[Info]  $HelloBusiness User(s) sign in with a Windows Hello for Business Key"

# Password Authentication Method
# https://learn.microsoft.com/en-us/graph/api/resources/passwordauthenticationmethod?view=graph-rest-1.0
#$Count = (Import-Csv -Path "$LogFile" -Delimiter "," | Where-Object { $_.password -eq "True" } | Measure-Object).Count
#$Password = '{0:N0}' -f $Count
#Write-Output "[Info]  $Password User(s) sign in with a password"

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

# TODO

# - All counts need to be double-checked!!!

# Sign in with a phone call
# Sign in with a text message
# Sign in with the Microsoft Authenticator app

# Microsoft Authenticator: Push Notifications
# Microsoft Authenticator: Phone Sign-in (Passwordless)

# Certificate (Passwordless) - Certificate-based authentication
# Windows Hello (Passwordless)

# Software Token OTP (OATH)
# Hardware Token OTP (OATH)

# Voice - Voice Call Verification
# SMS
# Temporary Access Pass (TAP)

# Authentication method     Description
# Email                     Use an email address as part of the Self-Service Password Reset (SSPR) process.
# Fido2                     Use a FIDO2 Security Key to sign-in to Azure AD.
# Microsoft Authenticator   Use Microsoft Authenticator to sign-in or perform multi-factor authentication to Azure AD.
# Phone                     The user can use a phone to authenticate using SMS or voice calls (as allowed by policy).
# SoftwareOath              Use Microsoft Authenticator to sign in or perform multi-factor authentication to Azure AD.
# TemporartAccessPass       Temporary Access Pass is a time-limited passcode that serves as a strong credential and allows onboarding of passwordless credentials.
# WindowsHelloForBusiness   Windows Hello for Business is a passwordless sign-in method on Windows devices.

# OneWaySMS - Text code authentication phone
# TwoWayVoiceMobile - Call authentication phone
# TwoWayVoiceOffice - Call office phone
# PhoneAllOTP - Authenticator app or hardware token
# PhoneAppNotification - Microsoft Authenticator App

# https://activedirectorypro.com/mfa-status-powershell/
# https://www.alitajran.com/export-office-365-users-mfa-status-with-powershell/
# https://o365info.com/export-all-microsoft-365-users-mfa-status/
# https://support.microsoft.com/en-us/account-billing/set-up-an-email-address-as-your-verification-method-250b91e4-7627-4b60-b861-f2276a9c0e39
# https://support.microsoft.com/en-us/account-billing/sign-in-to-your-work-or-school-account-using-your-two-step-verification-method-c7293464-ef5e-4705-a24b-c4a3ec0d6cf9
