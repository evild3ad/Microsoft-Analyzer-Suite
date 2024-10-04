# MFA-Analyzer v0.3
#
# @author:    Martin Willing
# @copyright: Copyright (c) 2024 Martin Willing. All rights reserved.
# @contact:   Any feedback or suggestions are always welcome and much appreciated - mwilling@lethal-forensics.com
# @url:       https://lethal-forensics.com/
# @date:      2024-10-04
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
# Release Date: 2024-04-22
# Initial Release
#
# Version 0.2
# Release Date: 2024-04-29
# Added: LastUpdatedDateTime
#
# Version 0.3
# Release Date: 2024-10-04
# Added: CmdletBinding
# Added: PowerShell 7 Support
#
#
# Tested on Windows 10 Pro (x64) Version 22H2 (10.0.19045.4894) and PowerShell 5.1 (5.1.19041.4894)
# Tested on Windows 10 Pro (x64) Version 22H2 (10.0.19045.4780) and PowerShell 7.4.5
#
#
#############################################################################################################################################################################################
#############################################################################################################################################################################################

<#
.SYNOPSIS
  MFA-Analyzer v0.3 - Automated Analysis of Authentication Methods and User Registration Details for DFIR

.DESCRIPTION
  MFA-Analyzer.ps1 is a PowerShell script utilized to simplify the analysis of the MFA Status of all users extracted via "Microsoft Extractor Suite" by Invictus Incident Response.

  https://github.com/invictus-ir/Microsoft-Extractor-Suite (Microsoft-Extractor-Suite v2.1.0)

.PARAMETER OutputDir
  Specifies the output directory. Default is "$env:USERPROFILE\Desktop\MFA-Analyzer".

  Note: The subdirectory 'MFA-Analyzer' is automatically created.

.PARAMETER Path
  Specifies the path to the CSV-based input file (*-AuthenticationMethods.csv).

.EXAMPLE
  PS> .\MFA-Analyzer.ps1

.EXAMPLE
  PS> .\MFA-Analyzer.ps1 -Path "$env:USERPROFILE\Desktop\*-AuthenticationMethods.csv"

.EXAMPLE
  PS> .\MFA-Analyzer.ps1 -Path "H:\Microsoft-Extractor-Suite\*-AuthenticationMethods.csv" -OutputDir "H:\Microsoft-Analyzer-Suite"

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
    $script:OUTPUT_FOLDER = "$env:USERPROFILE\Desktop\MFA-Analyzer" # Default
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
        $script:OUTPUT_FOLDER = "$OutputDir\MFA-Analyzer" # Custom
    }
}

#endregion Declarations

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Header

# Windows Title
$DefaultWindowsTitle = $Host.UI.RawUI.WindowTitle
$Host.UI.RawUI.WindowTitle = "MFA-Analyzer v0.3 - Automated Analysis of Authentication Methods and User Registration Details for DFIR"

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
        $OpenFileDialog.Filter = "Authentication Methods (*csv)|*-AuthenticationMethods.csv|All Files (*.*)|*.*"
        $OpenFileDialog.ShowDialog()
        $OpenFileDialog.Filename
        $OpenFileDialog.ShowHelp = $true
        $OpenFileDialog.Multiselect = $false
    }

    $Result = Get-LogFile

    if($Result -eq "OK")
    {
        $script:AuthenticationMethods = $Result[1]
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
Write-Output "MFA-Analyzer v0.3 - Automated Analysis of Authentication Methods and User Registration Details for DFIR"
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
if (!(Test-Path "$AuthenticationMethods"))
{
    Write-Host "[Error] $AuthenticationMethods does not exist." -ForegroundColor Red
    Write-Host ""
    Stop-Transcript
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

# Check File Extension
$Extension = [IO.Path]::GetExtension($AuthenticationMethods)
if (!($Extension -eq ".csv" ))
{
    Write-Host "[Error] No CSV File provided." -ForegroundColor Red
    Stop-Transcript
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

# Processing Authentication Methods
Write-Output "[Info]  Processing Authentication Methods ..."
New-Item "$OUTPUT_FOLDER\CSV" -ItemType Directory -Force | Out-Null
New-Item "$OUTPUT_FOLDER\XLSX" -ItemType Directory -Force | Out-Null

# Input Size
$InputSize = Get-FileSize((Get-Item "$AuthenticationMethods").Length)
Write-Output "[Info]  Total Input Size: $InputSize"

# Count rows of CSV (w/ thousands separators)
$Count = 0
switch -File "$AuthenticationMethods" { default { ++$Count } }
$Rows = '{0:N0}' -f $Count
Write-Output "[Info]  Total Lines: $Rows"

# Authentication Methods

# CSV
if (Test-Path "$AuthenticationMethods")
{
    $Data = Import-Csv -Path "$AuthenticationMethods" -Delimiter ","

    $Results = @()
    ForEach($Record in $Data)
    {
        $Line = [PSCustomObject]@{
        "UserPrincipalName"                = $Record.user
        "MFA Status"                       = $Record.MFAstatus
        "Password"                         = $Record.password
        "Microsoft Authenticator"          = $Record.app
        "Phone"                            = $Record.phone
        "E-Mail"                           = $Record.email
        "FIDO2"                            = $Record.fido2
        "Software OATH"                    = $Record.softwareoath
        "Windows Hello for Business"       = $Record.hellobusiness
        "Temporary Access Pass"            = if([string]::IsNullOrEmpty($Record.temporaryAccessPassAuthenticationMethod)){"-"}else{$Record.temporaryAccessPassAuthenticationMethod}
        "Certificate-Based Authentication" = $Record.certificateBasedAuthConfiguration
        }

        $Results += $Line
    }

    $Results | Export-Csv -Path "$OUTPUT_FOLDER\CSV\AuthenticationMethods.csv" -NoTypeInformation
}

# XLSX
if (Get-Module -ListAvailable -Name ImportExcel)
{
    if (Test-Path "$AuthenticationMethods")
    {
        if(!([String]::IsNullOrWhiteSpace((Get-Content "$OUTPUT_FOLDER\CSV\AuthenticationMethods.csv"))))
        {
            $IMPORT = Import-Csv -Path "$OUTPUT_FOLDER\CSV\AuthenticationMethods.csv" -Delimiter "," -Encoding UTF8
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\XLSX\AuthenticationMethods.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Authentication Methods" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:K1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns B-K
            $WorkSheet.Cells["B:K"].Style.HorizontalAlignment="Center"
            }
        }
    }
}
else
{
    Write-Host "[Error] PowerShell module 'ImportExcel' NOT found." -ForegroundColor Red
}

# File Size (XLSX)
if (Test-Path "$OUTPUT_FOLDER\XLSX\AuthenticationMethods.xlsx")
{
    $Size = Get-FileSize((Get-Item "$OUTPUT_FOLDER\XLSX\AuthenticationMethods.xlsx").Length)
    Write-Output "[Info]  File Size (XLSX): $Size"
}

#############################################################################################################################################################################################

# Count Users (UPN)
$Count = (Import-Csv -Path "$AuthenticationMethods" -Delimiter "," | Measure-Object).Count
$Users = '{0:N0}' -f $Count
Write-Output "[Info]  $Users User(s) found"

# Single-Factor Authentication
$Count = (Import-Csv -Path "$AuthenticationMethods" -Delimiter "," | Where-Object { $_.MFAstatus -eq "Disabled" } | Where-Object { $_.password -eq "True" } | Measure-Object).Count
$SFA = '{0:N0}' -f $Count
Write-Output "[Info]  $SFA User(s) have Single-Factor Authentication enabled ($Users)"

# Multi-Factor Authentication
$Count = (Import-Csv -Path "$AuthenticationMethods" -Delimiter "," | Where-Object { $_.MFAstatus -eq "Enabled" } | Measure-Object).Count
$MFA = '{0:N0}' -f $Count
Write-Output "[Info]  $MFA User(s) have Multi-Factor Authentication enabled ($Users)"

# Password Authentication Method (First-Factor Authentication)
# https://learn.microsoft.com/en-us/graph/api/resources/passwordauthenticationmethod?view=graph-rest-1.0
$Count = (Import-Csv -Path "$AuthenticationMethods" -Delimiter "," | Where-Object { $_.password -eq "True" } | Measure-Object).Count
$Password = '{0:N0}' -f $Count
Write-Output "[Info]  $Password User(s) sign in with a password (First-Factor Authentication)"

# Microsoft Authenticator Authentication Method
# https://learn.microsoft.com/en-us/graph/api/resources/microsoftauthenticatorauthenticationmethod?view=graph-rest-1.0
$Count = (Import-Csv -Path "$AuthenticationMethods" -Delimiter "," | Where-Object { $_.app -eq "True" } | Measure-Object).Count
$App = '{0:N0}' -f $Count
Write-Output "[Info]  $App User(s) sign in with the Microsoft Authenticator app"

# Phone Authentication Method
# https://learn.microsoft.com/en-us/graph/api/resources/phoneauthenticationmethod?view=graph-rest-1.0
$Count = (Import-Csv -Path "$AuthenticationMethods" -Delimiter "," | Where-Object { $_.phone -eq "True" } | Measure-Object).Count
$Phone = '{0:N0}' -f $Count
Write-Output "[Info]  $Phone User(s) sign in with a phone call or a text message (SMS)"

# Email Authentication Method
# https://learn.microsoft.com/en-us/graph/api/resources/emailauthenticationmethod?view=graph-rest-1.0
$Count = (Import-Csv -Path "$AuthenticationMethods" -Delimiter "," | Where-Object { $_.email -eq "True" } | Measure-Object).Count
$Email = '{0:N0}' -f $Count
Write-Output "[Info]  $Email User(s) sign in with an Email OTP"

# FIDO2 Authentication Method
# https://learn.microsoft.com/en-us/graph/api/resources/fido2authenticationmethod?view=graph-rest-1.0
$Count = (Import-Csv -Path "$AuthenticationMethods" -Delimiter "," | Where-Object { $_.fido2 -eq "True" } | Measure-Object).Count
$FIDO2 = '{0:N0}' -f $Count
Write-Output "[Info]  $FIDO2 User(s) sign in with FIDO2 Security Keys"

# Software OATH Authentication Method (Software Token)
# https://learn.microsoft.com/en-us/graph/api/resources/softwareoathauthenticationmethod?view=graph-rest-1.0
$Count = (Import-Csv -Path "$AuthenticationMethods" -Delimiter "," | Where-Object { $_.softwareoath -eq "True" } | Measure-Object).Count
$SoftwareOath = '{0:N0}' -f $Count
Write-Output "[Info]  $SoftwareOath User(s) sign in with an OATH Time-Based One Time Password (TOTP)"

# Windows Hello For Business Authentication Method (Passwordless)
# https://learn.microsoft.com/en-us/graph/api/resources/windowshelloforbusinessauthenticationmethod?view=graph-rest-1.0
$Count = (Import-Csv -Path "$AuthenticationMethods" -Delimiter "," | Where-Object { $_.hellobusiness -eq "True" } | Measure-Object).Count
$HelloBusiness = '{0:N0}' -f $Count
Write-Output "[Info]  $HelloBusiness User(s) sign in with a Windows Hello for Business Key"

# Temporary Access Pass Authentication Method (Passwordless)
# https://learn.microsoft.com/en-us/graph/api/resources/temporaryaccesspassauthenticationmethod?view=graph-rest-1.0
$Count = (Import-Csv -Path "$AuthenticationMethods" -Delimiter "," | Where-Object { $_.tempaccess -eq "True" } | Measure-Object).Count
$TemporaryAccessPass = '{0:N0}' -f $Count
Write-Output "[Info]  $TemporaryAccessPass User(s) sign in with a Temporary Access Pass (TAP)"

# Certificate-based Authentication Method (Passwordless)
# https://learn.microsoft.com/en-us/graph/api/resources/certificateBasedAuthConfiguration?view=graph-rest-1.0
$Count = (Import-Csv -Path "$AuthenticationMethods" -Delimiter "," | Where-Object { $_.certificateBasedAuthConfiguration -eq "True" } | Measure-Object).Count
$Certificate = '{0:N0}' -f $Count
Write-Output "[Info]  $Certificate User(s) sign in with a X.509 Certificate (CBA)"

#############################################################################################################################################################################################

# Stats
New-Item "$OUTPUT_FOLDER\Stats\CSV" -ItemType Directory -Force | Out-Null
New-Item "$OUTPUT_FOLDER\Stats\XLSX" -ItemType Directory -Force | Out-Null

# MFA Status (Stats)
$Total = (Import-Csv -Path "$AuthenticationMethods" -Delimiter "," | Select-Object MFAstatus | Measure-Object).Count
Import-Csv -Path "$AuthenticationMethods" -Delimiter "," -Encoding UTF8 | Group-Object MFAstatus | Select-Object @{Name='MFA Status'; Expression={$_.Name}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending | Export-Csv -Path "$OUTPUT_FOLDER\Stats\CSV\MFA-Status.csv" -NoTypeInformation -Encoding UTF8

# XLSX
if (Test-Path "$OUTPUT_FOLDER\Stats\CSV\MFA-Status.csv")
{
    if(!([String]::IsNullOrWhiteSpace((Get-Content "$OUTPUT_FOLDER\Stats\CSV\MFA-Status.csv"))))
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\Stats\CSV\MFA-Status.csv" -Delimiter ","
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Stats\XLSX\MFA-Status.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "MFA-Status" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
        Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
        # HorizontalAlignment "Center" of columns A-C
        $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
        }
    }
}

# Authentication Method (Stats)
$Total = (Import-Csv -Path "$AuthenticationMethods" -Delimiter "," | Select-Object UserPrincipalName | Measure-Object).Count
$Password = (Import-Csv -Path "$AuthenticationMethods" -Delimiter "," | Where-Object { $_.MFAstatus -eq "Disabled" } | Where-Object { $_.password -eq "True" } | Measure-Object).Count
$AuthenticatorApp = (Import-Csv -Path "$AuthenticationMethods" -Delimiter "," | Where-Object { $_.app -eq "True" } | Measure-Object).Count
$Phone = (Import-Csv -Path "$AuthenticationMethods" -Delimiter "," | Where-Object { $_.phone -eq "True" } | Measure-Object).Count
$Email = (Import-Csv -Path "$AuthenticationMethods" -Delimiter "," | Where-Object { $_.email -eq "True" } | Measure-Object).Count
$FIDO2 = (Import-Csv -Path "$AuthenticationMethods" -Delimiter "," | Where-Object { $_.fido2 -eq "True" } | Measure-Object).Count
$SoftwareOath = (Import-Csv -Path "$AuthenticationMethods" -Delimiter "," | Where-Object { $_.softwareoath -eq "True" } | Measure-Object).Count
$HelloBusiness = (Import-Csv -Path "$AuthenticationMethods" -Delimiter "," | Where-Object { $_.hellobusiness -eq "True" } | Measure-Object).Count
$TAP = (Import-Csv -Path "$AuthenticationMethods" -Delimiter "," | Where-Object { $_.tempaccess -eq "True" } | Measure-Object).Count
$CBA = (Import-Csv -Path "$AuthenticationMethods" -Delimiter "," | Where-Object { $_.certificateBasedAuthConfiguration -eq "True" } | Measure-Object).Count

# CSV
Write-Output "AuthenticationMethod,Count" | Out-File "$OUTPUT_FOLDER\Stats\CSV\AuthenticationMethod.csv"
Write-Output "Single-Factor Authentication,$Password" | Out-File "$OUTPUT_FOLDER\Stats\CSV\AuthenticationMethod.csv" -Append # Single-Factor Authentication
Write-Output "Microsoft Authenticator,$AuthenticatorApp" | Out-File "$OUTPUT_FOLDER\Stats\CSV\AuthenticationMethod.csv" -Append
Write-Output "Phone,$Phone" | Out-File "$OUTPUT_FOLDER\Stats\CSV\AuthenticationMethod.csv" -Append
Write-Output "E-Mail,$Email" | Out-File "$OUTPUT_FOLDER\Stats\CSV\AuthenticationMethod.csv" -Append
Write-Output "FIDO2,$FIDO2" | Out-File "$OUTPUT_FOLDER\Stats\CSV\AuthenticationMethod.csv" -Append
Write-Output "SoftwareOath,$SoftwareOath" | Out-File "$OUTPUT_FOLDER\Stats\CSV\AuthenticationMethod.csv" -Append
Write-Output "Windows Hello for Business,$HelloBusiness" | Out-File "$OUTPUT_FOLDER\Stats\CSV\AuthenticationMethod.csv" -Append
Write-Output "Temporary Access Pass,$TAP" | Out-File "$OUTPUT_FOLDER\Stats\CSV\AuthenticationMethod.csv" -Append
Write-Output "Certificate-Based Authentication,$CBA" | Out-File "$OUTPUT_FOLDER\Stats\CSV\AuthenticationMethod.csv" -Append

# XLSX
if (Test-Path "$OUTPUT_FOLDER\Stats\CSV\AuthenticationMethod.csv")
{
    if(!([String]::IsNullOrWhiteSpace((Get-Content "$OUTPUT_FOLDER\Stats\CSV\AuthenticationMethod.csv"))))
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\Stats\CSV\AuthenticationMethod.csv" -Delimiter "," | Select-Object AuthenticationMethod,Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}}
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Stats\XLSX\AuthenticationMethod.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Authentication Method" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
        Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
        # HorizontalAlignment "Center" of columns B-C
        $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
        }
    }
}

#############################################################################################################################################################################################

# Processing User Registration Details
Write-Output "[Info]  Processing User Registration Details ..."

$File = Get-Item "$AuthenticationMethods"
$Prefix = $File.Name | ForEach-Object{($_ -split "-")[0]}
$FilePath = $File.Directory
$UserRegistrationDetails = "$FilePath" + "\" + "$Prefix" + "-UserRegistrationDetails.csv"

# Input-Check
if (!(Test-Path "$UserRegistrationDetails"))
{
    Write-Host "[Error] $UserRegistrationDetails does not exist." -ForegroundColor Red
    Write-Host ""
    Stop-Transcript
    $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
    Exit
}

# Input Size
$InputSize = Get-FileSize((Get-Item "$UserRegistrationDetails").Length)
Write-Output "[Info]  Total Input Size: $InputSize"

# Count rows of CSV (w/ thousands separators)
$Count = 0
switch -File "$UserRegistrationDetails" { default { ++$Count } }
$Rows = '{0:N0}' -f $Count
Write-Output "[Info]  Total Lines: $Rows"

# User Registration Details
# https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-methods-activity
# https://learn.microsoft.com/en-us/graph/api/authenticationmethodsroot-list-userregistrationdetails?view=graph-rest-1.0
# https://learn.microsoft.com/en-us/graph/api/resources/userregistrationdetails?view=graph-rest-1.0

# CSV
if (Test-Path "$UserRegistrationDetails")
{
    $Data = Import-Csv -Path "$UserRegistrationDetails" -Delimiter "," -Encoding UTF8

    # Check Timestamp Format
    $Timestamp = ($Data | Select-Object LastUpdatedDateTime -First 1).LastUpdatedDateTime

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

    $Results = @()
    ForEach($Record in $Data)
    {

        $Line = [PSCustomObject]@{
        "Id"                                            = $Record.Id # User object identifier in Microsoft Entra ID.
        "UserDisplayName"                               = $Record.UserDisplayName # User Display Name
        "UserPrincipalName"                             = $Record.UserPrincipalName # User Principal Name
        "IsAdmin"                                       = $Record.IsAdmin # Indicates whether the user has an admin role in the tenant. This value can be used to check the authentication methods that privileged accounts are registered for and capable of.
        "MFA Capable"                                   = $Record.IsMfaCapable # Indicates whether the user has registered a strong authentication method for multifactor authentication. The method must be allowed by the authentication methods policy.
        "MFA Registered"                                = $Record.IsMfaRegistered # Indicates whether the user has registered a strong authentication method for multifactor authentication. 
        "Passwordless Capable"                          = $Record.IsPasswordlessCapable # Indicates whether the user has registered a passwordless strong authentication method (including FIDO2, Windows Hello for Business, and Microsoft Authenticator (Passwordless) that is allowed by the authentication methods policy.
        "SSPR Capable"                                  = $Record.IsSsprCapable # Indicates whether the user has registered the required number of authentication methods for self-service password reset and the user is allowed to perform self-service password reset by policy.
        "SSPR Enabled"                                  = $Record.IsSsprEnabled # Indicates whether the user is allowed to perform self-service password reset by policy. The user may not necessarily have registered the required number of authentication methods for self-service password reset.
        "IsSystemPreferredAuthenticationMethodEnabled"  = $Record.IsSystemPreferredAuthenticationMethodEnabled # Indicates whether system preferred authentication method is enabled. If enabled, the system dynamically determines the most secure authentication method among the methods registered by the user.
        "MethodsRegistered"                             = ($Record | Select-Object -ExpandProperty MethodsRegistered).Replace("`r","").Replace("`n",", ").TrimEnd(", ") # Authentication methods used during registration
        "SystemPreferredAuthenticationMethods"          = $Record.SystemPreferredAuthenticationMethods # Collection of authentication methods that the system determined to be the most secure authentication methods among the registered methods for second factor authentication.
        "UserPreferredMethodForSecondaryAuthentication" = $Recrod.UserPreferredMethodForSecondaryAuthentication # The method the user selected as the default second-factor for performing multi-factor authentication.
        "UserType"                                      = $Record.UserType | ForEach-Object { $_.Replace("member","Member") } | ForEach-Object { $_.Replace("guest","Guest") } # Identifies whether the user is a member or guest in the tenant.
        "LastUpdatedDateTime"                           = ($Record | Select-Object @{Name="LastUpdatedDateTime";Expression={([DateTime]::ParseExact($_.LastUpdatedDateTime, "$TimestampFormat", [cultureinfo]::InvariantCulture).ToString("yyyy-MM-dd HH:mm:ss"))}}).LastUpdatedDateTime # The date and time (UTC) when the record was last updated.
        }

        $Results += $Line
    }

    $Results | Export-Csv -Path "$OUTPUT_FOLDER\CSV\UserRegistrationDetails.csv" -NoTypeInformation
}

# XLSX
if (Get-Module -ListAvailable -Name ImportExcel)
{
    if (Test-Path "$UserRegistrationDetails")
    {
        if(!([String]::IsNullOrWhiteSpace((Get-Content "$OUTPUT_FOLDER\CSV\UserRegistrationDetails.csv"))))
        {
            $IMPORT = Import-Csv -Path "$OUTPUT_FOLDER\CSV\UserRegistrationDetails.csv" -Delimiter "," -Encoding UTF8
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\XLSX\UserRegistrationDetails.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "User Registration Details" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:P1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns B-P
            $WorkSheet.Cells["B:P"].Style.HorizontalAlignment="Center"
            }
        }
    }
}

# File Size (XLSX)
if (Test-Path "$OUTPUT_FOLDER\XLSX\UserRegistrationDetails.xlsx")
{
    $Size = Get-FileSize((Get-Item "$OUTPUT_FOLDER\XLSX\UserRegistrationDetails.xlsx").Length)
    Write-Output "[Info]  File Size (XLSX): $Size"
}

#############################################################################################################################################################################################

# Users capable of Azure Multi-Factor Authentication
$Total = (Import-Csv -Path "$UserRegistrationDetails" -Delimiter "," | Select-Object Id | Measure-Object).Count
$Count = (Import-Csv -Path "$UserRegistrationDetails" -Delimiter "," | Where-Object { $_.IsMfaCapable -eq "True" } | Measure-Object).Count
$MFACapable = '{0:N0}' -f $Count
Write-Output "[Info]  $MFACapable Users capable of Azure Multi-Factor Authentication ($Total)"

# Users capable of Passwordless Authentication
$Total = (Import-Csv -Path "$UserRegistrationDetails" -Delimiter "," | Select-Object Id | Measure-Object).Count
$Count = (Import-Csv -Path "$UserRegistrationDetails" -Delimiter "," | Where-Object { $_.IsPasswordlessCapable -eq "True" } | Measure-Object).Count
$PasswordlessCapable = '{0:N0}' -f $Count
Write-Output "[Info]  $PasswordlessCapable Users capable of Passwordless Authentication ($Total)"

# Users capable of Self-Service Password Reset (SSPR)
$Total = (Import-Csv -Path "$UserRegistrationDetails" -Delimiter "," | Select-Object Id | Measure-Object).Count
$Count = (Import-Csv -Path "$UserRegistrationDetails" -Delimiter "," | Where-Object { $_.IsSsprCapable -eq "True" } | Measure-Object).Count
$SSPRCapable = '{0:N0}' -f $Count
Write-Output "[Info]  $SSPRCapable Users capable of Self-Service Password Reset ($Total)"

# Second-Factor Authentication Method
$Check = (Import-Csv "$UserRegistrationDetails" -Delimiter "," | Where-Object {$_.MethodsRegistered -ne '' } | Select-Object MethodsRegistered | Measure-Object).Count
if ("$Check" -eq 0)
{
    Write-Host "[Alert] 0 Users registered a Second-Factor Authentication Method ($Total)" -ForegroundColor Red
}

# MethodsRegistered (Stats)
$Check = (Import-Csv "$UserRegistrationDetails" -Delimiter "," | Where-Object {$_.MethodsRegistered -ne '' } | Select-Object MethodsRegistered | Measure-Object).Count
if ("$Check" -ge 1)
{
    $Total = ((Import-Csv "$UserRegistrationDetails" -Delimiter "," | Where-Object {$_.MethodsRegistered -ne '' } | Select-Object -ExpandProperty MethodsRegistered).Replace("`r","").Trim() | Measure-Object).Count
    (Import-Csv "$UserRegistrationDetails" -Delimiter "," | Where-Object {$_.MethodsRegistered -ne '' } | Select-Object -ExpandProperty MethodsRegistered).Replace("`r","").Trim() | Out-File "$OUTPUT_FOLDER\Stats\MethodsRegistered.txt" -Encoding UTF8
    Get-Content "$OUTPUT_FOLDER\Stats\MethodsRegistered.txt" -Encoding UTF8 | Group-Object | Select-Object @{Name='MethodsRegistered'; Expression={$_.Name}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending | Export-Csv -Path "$OUTPUT_FOLDER\Stats\CSV\MethodsRegistered.csv" -NoTypeInformation -Encoding UTF8
}

# Cleaning up
if (Test-Path "$OUTPUT_FOLDER\Stats\MethodsRegistered.txt")
{
    Remove-Item "$OUTPUT_FOLDER\Stats\MethodsRegistered.txt" -Force
}

# XLSX
if (Test-Path "$OUTPUT_FOLDER\Stats\CSV\MethodsRegistered.csv")
{
    if(!([String]::IsNullOrWhiteSpace((Get-Content "$OUTPUT_FOLDER\Stats\CSV\MethodsRegistered.csv"))))
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\Stats\CSV\MethodsRegistered.csv" -Delimiter ","
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Stats\XLSX\MethodsRegistered.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Methods Registered" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
        Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
        # HorizontalAlignment "Center" of columns B-C
        $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
        }
    }
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

# TODO

# AuthenticationMethod Function
# UserRegistrationDetails Function

# Improve "Phone Authentication Method" --> authenticationPhoneType (mobile, alternateMobile, office), smsSignInState via authenticationMethodSignInState

# https://portal.azure.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/AdminAuthMethods
# FIDO2 Security Key
# Microsoft Authenticator
# SMS
# Temporary Access Pass
# Hardware OATH tokens (Preview)
# Third-party software OATH tokens
# Voice call
# Email OTP
# Certificate based authentication

# FIDO2 Security Key = FIDO2 security keys are a phishing-resistant, standards-based passwordless authentication method available from a variety of vendors. FIDO2 keys are not usable in the Self-Service Password Reset flow.
# Microsoft Authenticator = The Microsoft Authenticator app is a flagship authentication method, usable in passwordless or simple push notification approval modes. The app is free to download and use on Android/iOS mobile devices.
# SMS = This authentication method delivers a one-time code via SMS to a user's phone, and the user then inputs that code to sign-in. SMS is usable for multi-factor authentication and Self-Service Password Reset; it can also be configured to be used as a first factor.
# Temporary Access Pass = Temporary Access Pass, or TAP, is a time-limited or limited-use passcode that can be used by users for bootstrapping new accounts, account recovery, or when other auth methods are unavailable. TAP is issuable only by administrators, and is seen by the system as strong authentication. It is not usable for Self Service Password Reset.
# Hardware OATH tokens (Preview) = Hardware OATH tokens are physical devices that use the OATH TOTP standard and a secret key to generate 6-digit codes used to authenticate. This policy control specifically manages the ability to register and use Hardware OATH tokens.
# Third-party software OATH tokens = Software OATH tokens are applications that use the OATH TOTP standard and a secret key to generate 6-digit codes used to authenticate. This policy control specifically manages the ability to register and use non-Microsoft software OATH tokens. Microsoft Authenticator can also generate software OATH codes and is managed in the Microsoft Authenticator section of this policy. Software OATH token is not usable as a first-factor authentication method.
# Voice call = This authentication method places a phone call to a user which the user must then approve using the telephone keypad. Voice call is not usable as a first-factor authentication method.
# Email OTP = Email OTP sends a code to a user's email account which is then used to authenticate. For members of a tenant, email OTP is usable only for Self-Service Password Recovery. It may also be configured to be used for sign-in by guest users.
# Certificate based authentication = Certificate-based authentication is a passwordless, phising-resistant authentication method that uses x.509 certificates and an enterprise public key infrastructure (PKI) for authentication.

# Authentication methods --> User registration details
# https://portal.azure.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/UserRegistrationDetails
# https://learn.microsoft.com/en-us/graph/api/resources/userregistrationdetails?view=graph-rest-1.0

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

# MethodsRegistered
# email
# microsoftAuthenticatorPush
# mobilePhone
# softwareOneTimePasscode
# ...

# https://activedirectorypro.com/mfa-status-powershell/
# https://www.alitajran.com/export-office-365-users-mfa-status-with-powershell/
# https://o365info.com/export-all-microsoft-365-users-mfa-status/
# https://support.microsoft.com/en-us/account-billing/set-up-an-email-address-as-your-verification-method-250b91e4-7627-4b60-b861-f2276a9c0e39
# https://support.microsoft.com/en-us/account-billing/sign-in-to-your-work-or-school-account-using-your-two-step-verification-method-c7293464-ef5e-4705-a24b-c4a3ec0d6cf9

# https://portal.azure.com/#view/Microsoft_AAD_IAM/AuthenticationMethodsMenuBlade/~/UserRegistrationDetails
# https://learn.microsoft.com/en-us/graph/api/authenticationmethodsroot-list-userregistrationdetails?view=graph-rest-1.0&tabs=powershell
# https://learn.microsoft.com/en-us/graph/api/userregistrationdetails-get?view=graph-rest-1.0&tabs=powershell
# https://learn.microsoft.com/en-us/graph/api/phoneauthenticationmethod-get?view=graph-rest-1.0&tabs=powershell
# https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.identity.signins/get-mguserauthenticationmethod?view=graph-powershell-1.0
