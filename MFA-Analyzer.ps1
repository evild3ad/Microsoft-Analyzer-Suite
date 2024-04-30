# MFA-Analyzer v0.2
#
# @author:    Martin Willing
# @copyright: Copyright (c) 2024 Martin Willing. All rights reserved.
# @contact:   Any feedback or suggestions are always welcome and much appreciated - mwilling@lethal-forensics.com
# @url:       https://lethal-forensics.com/
# @date:      2024-04-30
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
# Version 0.2
# Release Date: 2024-04-30
# Added: LastUpdatedDateTime
#
#
#############################################################################################################################################################################################
#############################################################################################################################################################################################

<#
.SYNOPSIS
  MFA-Analyzer v0.2 - Automated Analysis of Authentication Methods and User Registration Details for DFIR

.DESCRIPTION
  MFA-Analyzer.ps1 is a PowerShell script utilized to simplify the analysis of the MFA Status of all users extracted via "Microsoft Extractor Suite" by Invictus Incident Response.

  https://github.com/invictus-ir/Microsoft-Extractor-Suite (Microsoft-Extractor-Suite v1.3.4)

.EXAMPLE
  PS> .\MFA-Analyzer.ps1

.NOTES
  Author - Martin Willing

.LINK
  https://lethal-forensics.com/
#>

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Declarations

# Declarations

# Output Directory
$OUTPUT_FOLDER = "$env:USERPROFILE\Desktop\MFA-Analyzer"

#endregion Declarations

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Header

# Windows Title
$DefaultWindowsTitle = $Host.UI.RawUI.WindowTitle
$Host.UI.RawUI.WindowTitle = "MFA-Analyzer v0.2 - Automated Analysis of Authentication Methods and User Registration Details for DFIR"

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
Write-Output "MFA-Analyzer v0.2 - Automated Analysis of Authentication Methods and User Registration Details for DFIR"
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
$UserRegistrationDetails = "$FilePath" + "\" + "$Prefix" + "-MFA" + "-UserRegistrationDetails.csv"

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
    $Data = Import-Csv -Path "$UserRegistrationDetails" -Delimiter ","

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
        "AdditionalProperties"                          = $Record.AdditionalProperties # Empty
        }

        $Results += $Line
    }

    $Results | Export-Csv -Path "$OUTPUT_FOLDER\CSV\UserRegistrationDetails.csv" -NoTypeInformation
}

# lastUpdatedDateTime???

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
