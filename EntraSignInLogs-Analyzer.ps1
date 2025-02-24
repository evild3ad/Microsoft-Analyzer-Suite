# EntraSignInLogs-Analyzer
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
  EntraSignInLogs-Analyzer - Automated Processing of Microsoft Entra ID Sign-In Logs for DFIR

.DESCRIPTION
  EntraSignInLogs-Analyzer.ps1 is a PowerShell script utilized to simplify the analysis of Microsoft Entra ID Sign-In Logs extracted via "Microsoft Extractor Suite" by Invictus Incident Response.

  https://github.com/invictus-ir/Microsoft-Extractor-Suite (Microsoft-Extractor-Suite v3.0.2)

  https://microsoft-365-extractor-suite.readthedocs.io/en/latest/functionality/Azure/AzureActiveDirectorysign-inlogs.html

.PARAMETER OutputDir
  Specifies the output directory. Default is "$env:USERPROFILE\Desktop\EntraSignInLogs-Analyzer".

  Note: The subdirectory 'EntraSignInLogs-Analyzer' is automatically created.

.PARAMETER Path
  Specifies the path to the JSON-based input file (SignInLogs-interactiveUser-nonInteractiveUser-Combined.json).

.EXAMPLE
  PS> .\EntraSignInLogs-Analyzer.ps1

.EXAMPLE
  PS> .\EntraSignInLogs-Analyzer.ps1 -Path "$env:USERPROFILE\Desktop\SignInLogs-interactiveUser-nonInteractiveUser-Combined.json"

.EXAMPLE
  PS> .\EntraSignInLogs-Analyzer.ps1 -Path "H:\Microsoft-Extractor-Suite\SignInLogs-interactiveUser-nonInteractiveUser-Combined.json" -OutputDir "H:\Microsoft-Analyzer-Suite"

.NOTES
  Author - Martin Willing

.LINK
  https://lethal-forensics.com/
#>

#############################################################################################################################################################################################
#############################################################################################################################################################################################

# How long does Microsoft Entra ID store the Sign-ins data?

# Microsoft Entra ID Free      7 days
# Microsoft Entra ID P1       30 days
# Microsoft Entra ID P2       30 days

# Note: You must have a Microsoft Entra ID P1 or P2 license to download sign-in logs using the Microsoft Graph API.

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

# Output Directory
if (!($OutputDir))
{
    $script:OUTPUT_FOLDER = "$env:USERPROFILE\Desktop\EntraSignInLogs-Analyzer" # Default
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
        $script:OUTPUT_FOLDER = "$OutputDir\EntraSignInLogs-Analyzer" # Custom
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
$Host.UI.RawUI.WindowTitle = "EntraSignInLogs-Analyzer - Automated Processing of Microsoft Entra ID Sign-In Logs for DFIR"

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
        $OpenFileDialog.Filter = "Sign-In Logs|SignInLogs-interactiveUser-nonInteractiveUser-Combined.json|All Files (*.*)|*.*"
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
Write-Output "EntraSignInLogs-Analyzer - Automated Processing of Microsoft Entra ID Sign-In Logs for DFIR"
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

# Microsoft Entra ID Sign-In Logs

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

# Input Size
$InputSize = Get-FileSize((Get-Item "$LogFile").Length)
Write-Output "[Info]  Total Input Size: $InputSize"

# Count rows of JSON (w/ thousands separators)
$Count = 0
switch -File "$LogFile" { default { ++$Count } }
$Rows = '{0:N0}' -f $Count
Write-Output "[Info]  Total Lines: $Rows"

# Processing Microsoft Entra ID Sign-In Logs
Write-Output "[Info]  Processing Microsoft Entra ID Sign-In Logs ..."
New-Item "$OUTPUT_FOLDER\EntraSignInLogs\CSV" -ItemType Directory -Force | Out-Null
New-Item "$OUTPUT_FOLDER\EntraSignInLogs\XLSX" -ItemType Directory -Force | Out-Null

# Import JSON
$Data = Get-Content -Path "$LogFile" -Raw | ConvertFrom-Json | Sort-Object { $_.createdDateTime -as [datetime] } -Descending

# Time Frame
$Last  = ($Data | Sort-Object { $_.createdDateTime -as [datetime] } -Descending | Select-Object -Last 1).createdDateTime
$First = ($Data | Sort-Object { $_.createdDateTime -as [datetime] } -Descending | Select-Object -First 1).createdDateTime
$StartDate = (Get-Date $Last).ToString("yyyy-MM-dd HH:mm:ss")
$EndDate = (Get-Date $First).ToString("yyyy-MM-dd HH:mm:ss")
Write-Output "[Info]  Log data from $StartDate UTC until $EndDate UTC"

# Untouched
# https://learn.microsoft.com/en-us/powershell/module/Microsoft.Graph.Beta.Reports/Get-MgBetaAuditLogSignIn?view=graph-powershell-beta
# https://learn.microsoft.com/nb-no/graph/api/resources/signin?view=graph-rest-beta

# CSV
$Results = [Collections.Generic.List[PSObject]]::new()
ForEach($Record in $Data)
{
    $CreatedDateTime = $Record | Select-Object -ExpandProperty createdDateTime

    $Line = [PSCustomObject]@{
    "Id"                             = $Record.Id # The identifier representing the sign-in activity.
    "CreatedDateTime"                = (Get-Date $CreatedDateTime).ToString("yyyy-MM-dd HH:mm:ss")
    "UserDisplayName"                = $Record.userDisplayName # The display name of the user.
    "UserPrincipalName"              = $Record.userPrincipalName # The UPN of the user.
    "UserId"                         = $Record.userId # The identifier of the user.
    "AppDisplayName"                 = $Record.appDisplayName # The application name displayed in the Microsoft Entra admin center.
    "AppId"                          = $Record.appId # The application identifier in Microsoft Entra ID.
    "ClientAppUsed"                  = $Record.clientAppUsed # The legacy client used for sign-in activity.
    "IpAddress"                      = $Record.ipAddress # The IP address of the client from where the sign-in occurred.
    "ASN"                            = $Record.AutonomousSystemNumber # The Autonomous System Number (ASN) of the network used by the actor.
    "IPAddressFromResourceProvider"  = $Record.IPAddressFromResourceProvider # The IP address a user used to reach a resource provider, used to determine Conditional Access compliance for some policies. For example, when a user interacts with Exchange Online, the IP address that Microsoft Exchange receives from the user can be recorded here. This value is often null.
    "City"                           = $Record | Select-Object -ExpandProperty location | Select-Object -ExpandProperty city # The city from where the sign-in occurred.
    "State"                          = $Record | Select-Object -ExpandProperty location | Select-Object -ExpandProperty state # The state from where the sign-in occurred.
    "CountryOrRegion"                = $Record | Select-Object -ExpandProperty location | Select-Object -ExpandProperty countryOrRegion # The two letter country code from where the sign-in occurred.
    "Latitude"                       = $Record | Select-Object -ExpandProperty location | Select-Object -ExpandProperty geoCoordinates | Select-Object -ExpandProperty Latitude
    "Longitude"                      = $Record | Select-Object -ExpandProperty location | Select-Object -ExpandProperty geoCoordinates | Select-Object -ExpandProperty Longitude
    "AuthenticationRequirement"      = $Record.AuthenticationRequirement # This holds the highest level of authentication needed through all the sign-in steps, for sign-in to succeed.
    "SignInEventTypes"               = $Record | Select-Object -ExpandProperty SignInEventTypes # Indicates the category of sign in that the event represents.
    "AuthenticationMethodsUsed"      = $Record | Select-Object -ExpandProperty AuthenticationMethodsUsed # The authentication methods used.

    # Status - The sign-in status. Includes the error code and description of the error (for a sign-in failure).
    # https://learn.microsoft.com/nb-no/graph/api/resources/signinstatus?view=graph-rest-beta
    "ErrorCode"                      = $Record | Select-Object -ExpandProperty status | Select-Object -ExpandProperty errorCode # Provides the 5-6 digit error code that's generated during a sign-in failure.
    "FailureReason"                  = $Record | Select-Object -ExpandProperty status | Select-Object -ExpandProperty failureReason # Provides the error message or the reason for failure for the corresponding sign-in activity.
    "AdditionalDetails"              = $Record | Select-Object -ExpandProperty status | Select-Object -ExpandProperty additionalDetails # Provides additional details on the sign-in activity.

    # AuthenticationDetails - The result of the authentication attempt and more details on the authentication method.
    # https://learn.microsoft.com/nb-no/graph/api/resources/authenticationdetail?view=graph-rest-beta
    "AuthenticationMethod"           = $Record.AuthDetailsAuthenticationMethod # The type of authentication method used to perform this step of authentication.
    "AuthenticationMethodDetail"     = $Record.AuthDetailsAuthenticationMethodDetail # Details about the authentication method used to perform this authentication step.
    "AuthenticationStepDateTime"     = $Record.AuthDetailsAuthenticationStepDateTime # Represents date and time information using ISO 8601 format and is always in UTC time.
    "AuthenticationStepRequirement"  = $Record.AuthDetailsAuthenticationStepRequirement # The step of authentication that this satisfied. 
    "AuthenticationStepResultDetail" = $Record.AuthDetailsAuthenticationStepResultDetail # Details about why the step succeeded or failed. 
    "Succeeded"                      = $Record.AuthDetailsSucceeded # Indicates the status of the authentication step.

    # AuthenticationProcessingDetails - More authentication processing details, such as the agent name for PTA and PHS, or a server or farm name for federated authentication.
    "Domain Hint Present"            = ($Record | Select-Object -ExpandProperty AuthenticationProcessingDetails | Where-Object {$_.Key -eq 'Domain Hint Present'}).Value
    "Is CAE Token"                   = ($Record | Select-Object -ExpandProperty AuthenticationProcessingDetails | Where-Object {$_.Key -eq 'Is CAE Token'}).Value
    "Login Hint Present"             = ($Record | Select-Object -ExpandProperty AuthenticationProcessingDetails | Where-Object {$_.Key -eq 'Login Hint Present'}).Value
    "Oauth Scope Info"               = ($Record | Select-Object -ExpandProperty AuthenticationProcessingDetails | Where-Object {$_.Key -eq 'Oauth Scope Info'}).Value
    "Root Key Type"                  = ($Record | Select-Object -ExpandProperty AuthenticationProcessingDetails | Where-Object {$_.Key -eq 'Root Key Type'}).Value

    "ClientCredentialType"           = $Record.ClientCredentialType # Describes the credential type that a user client or service principal provided to Microsoft Entra ID to authenticate itself. You can review this property to track and eliminate less secure credential types or to watch for clients and service principals using anomalous credential types.
    "ConditionalAccessStatus"        = $Record.ConditionalAccessStatus # The status of the conditional access policy triggered.
    "CorrelationId"                  = $Record.CorrelationId # The identifier that's sent from the client when sign-in is initiated.
    "IncomingTokenType"              = $Record.IncomingTokenType # Indicates the token types that were presented to Microsoft Entra ID to authenticate the actor in the sign in. 
    "OriginalRequestId"              = $Record.OriginalRequestId # The request identifier of the first request in the authentication sequence.
    "IsInteractive"                  = $Record.IsInteractive # Indicates whether a user sign in is interactive. In interactive sign in, the user provides an authentication factor to Microsoft Entra ID. These factors include passwords, responses to MFA challenges, biometric factors, or QR codes that a user provides to Microsoft Entra ID or an associated app. In non-interactive sign in, the user doesn't provide an authentication factor. Instead, the client app uses a token or code to authenticate or access a resource on behalf of a user. Non-interactive sign ins are commonly used for a client to sign in on a user's behalf in a process transparent to the user.
    "ProcessingTimeInMilliseconds"   = $Record.ProcessingTimeInMilliseconds # The request processing time in milliseconds in AD STS.
    "ResourceDisplayName"            = $Record.ResourceDisplayName # The name of the resource that the user signed in to.
    "ResourceId"                     = $Record.ResourceId # The identifier of the resource that the user signed in to.
    "ResourceServicePrincipalId"     = $Record.ResourceServicePrincipalId # The identifier of the service principal representing the target resource in the sign-in event.
    "ResourceTenantId"               = $Record.ResourceTenantId # The tenant identifier of the resource referenced in the sign in.
    "RiskDetail"                     = $Record.RiskDetail # The reason behind a specific state of a risky user, sign-in, or a risk event.
    "RiskEventTypesV2"               = $Record | Select-Object -ExpandProperty riskEventTypes_v2 # The list of risk event types associated with the sign-in.
    "RiskLevelAggregated"            = $Record.RiskLevelAggregated # The aggregated risk level. The value hidden means the user or sign-in wasn't enabled for Microsoft Entra ID Protection.
    "RiskLevelDuringSignIn"          = $Record.RiskLevelDuringSignIn # The risk level during sign-in. The value hidden means the user or sign-in wasn't enabled for Microsoft Entra ID Protection.
    "RiskState"                      = $Record.RiskState # The risk state of a risky user, sign-in, or a risk event.
    "SignInTokenProtectionStatus"    = $Record.SignInTokenProtectionStatus # oken protection creates a cryptographically secure tie between the token and the device it is issued to. This field indicates whether the signin token was bound to the device or not.
    "TokenIssuerName"                = $Record.TokenIssuerName # The name of the identity provider.
    "TokenIssuerType"                = $Record.TokenIssuerType # The type of identity provider.
    "UniqueTokenIdentifier"          = $Record.UniqueTokenIdentifier # A unique base64 encoded request identifier used to track tokens issued by Microsoft Entra ID as they're redeemed at resource providers.
    "UserAgent"                      = $Record.UserAgent # The user agent information related to sign-in.
    "UserType"                       = $Record | Select-Object -ExpandProperty UserType | ForEach-Object { $_.Replace("member","Member") } | ForEach-Object { $_.Replace("guest","Guest") } # Identifies whether the user is a member or guest in the tenant.
    "AuthenticationProtocol"         = $Record.AuthenticationProtocol # Lists the protocol type or grant type used in the authentication.
    "OriginalTransferMethod"         = $Record.OriginalTransferMethod # Transfer method used to initiate a session throughout all subsequent request.

    # MfaDetail - This property is deprecated.
    "AuthMethod"                     = $Record | Select-Object -ExpandProperty MfaDetail | Select-Object -ExpandProperty AuthMethod
    "AuthDetail"                     = $Record | Select-Object -ExpandProperty MfaDetail | Select-Object -ExpandProperty AuthDetail

    # DeviceDetail - The device information from where the sign-in occurred. Includes information such as deviceId, OS, and browser.
    # https://learn.microsoft.com/nb-no/graph/api/resources/devicedetail?view=graph-rest-beta
    "DeviceId"                       = $Record | Select-Object -ExpandProperty DeviceDetail | Select-Object -ExpandProperty DeviceId # Refers to the UniqueID of the device used for signing-in.
    "DisplayName"                    = $Record | Select-Object -ExpandProperty DeviceDetail | Select-Object -ExpandProperty DisplayName # Refers to the name of the device used for signing-in.
    "OperatingSystem"                = $Record | Select-Object -ExpandProperty DeviceDetail | Select-Object -ExpandProperty OperatingSystem # Indicates the OS name and version used for signing-in.
    "Browser"                        = $Record | Select-Object -ExpandProperty DeviceDetail | Select-Object -ExpandProperty Browser # Indicates the browser information of the used for signing-in.
    "IsCompliant"                    = $Record | Select-Object -ExpandProperty DeviceDetail | Select-Object -ExpandProperty IsCompliant # Indicates whether the device is compliant or not.
    "IsManaged"                      = $Record | Select-Object -ExpandProperty DeviceDetail | Select-Object -ExpandProperty IsManaged # Indicates if the device is managed or not.
    "TrustType"                      = $Record | Select-Object -ExpandProperty DeviceDetail | Select-Object -ExpandProperty TrustType # Indicates information on whether the signed-in device is Workplace Joined, AzureAD Joined, Domain Joined.
    
    # NetworkLocationDetails - The network location details including the type of network used and its names.
    # https://learn.microsoft.com/nb-no/graph/api/resources/networklocationdetail?view=graph-rest-beta
    "NetworkType"                    = $Record | Select-Object -ExpandProperty NetworkLocationDetails | Select-Object -ExpandProperty NetworkType # Provides the type of network used when signing in.
    "NetworkNames"                   = $Record | Select-Object -ExpandProperty NetworkLocationDetails | Select-Object -ExpandProperty NetworkNames # Provides the name of the network used when signing in.
    }

    $Results.Add($Line)
}

$Results | Export-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Untouched.csv" -NoTypeInformation -Encoding UTF8

# XLSX
if (Test-Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Untouched.csv")
{
    if([int](& $xsv count -d "," "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Untouched.csv") -gt 0)
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Untouched.csv" -Delimiter "," -Encoding UTF8
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\XLSX\Untouched.xlsx" -NoNumberConversion * -FreezePane 2,5 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "SignInLogsGraph" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
        Set-Format -Address $WorkSheet.Cells["A1:BP1"] -BackgroundColor $BackgroundColor -FontColor White
        # HorizontalAlignment "Center" of columns A-BP
        $WorkSheet.Cells["A:BP"].Style.HorizontalAlignment="Center"
        }
    }
}

# UserId
$UserId = (Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Untouched.csv" -Delimiter "," | Select-Object UserId -Unique | Measure-Object).Count
Write-Output "[Info]  $UserId UserId(s) found"

# Member
$Member = (Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Untouched.csv" -Delimiter "," | Where-Object { $_.UserType -eq 'Member' } | Select-Object UserId -Unique  | Measure-Object).Count

# Guest
$Guest = (Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Untouched.csv" -Delimiter "," | Where-Object { $_.UserType -eq 'Guest' } | Select-Object UserId -Unique  | Measure-Object).Count
Write-Output "[Info]  $Member Member(s) and $Guest Guest(s) found"

# DeviceId
$DeviceId = (Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Untouched.csv" -Delimiter "," | Select-Object DeviceId -Unique | Measure-Object).Count
Write-Output "[Info]  $DeviceId DeviceId(s) found"

# Microsoft Entra ID P2
# https://www.microsoft.com/en-us/security/business/microsoft-entra-pricing
$RiskLevelDuringSignIn = (Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Untouched.csv" -Delimiter "," | Select-Object RiskLevelDuringSignIn -Unique).RiskLevelDuringSignIn
if (!("$RiskLevelDuringSignIn" -eq "hidden"))
{
    Write-Output "[Info]  Microsoft Entra ID P2 detected"
}

# Identity Protection
# - Risk-based Conditional Access (sign-in risk, user risk)
# - Authentication context (step-up authentication)
# - Device and application filters for Conditional Access
# - Token protection
# - Vulnerabilities and risky accounts
# - Risk event investigation

$EndTime_Processing = (Get-Date)
$Time_Processing = ($EndTime_Processing-$StartTime_Processing)
('EntraSignInLogs Processing duration:      {0} h {1} min {2} sec' -f $Time_Processing.Hours, $Time_Processing.Minutes, $Time_Processing.Seconds) >> "$OUTPUT_FOLDER\Stats.txt"

}

#############################################################################################################################################################################################
#############################################################################################################################################################################################

Function Get-IPLocation {

$StartTime_DataEnrichment = (Get-Date)

# Count IP addresses
Write-Output "[Info]  Data Enrichment w/ IPinfo ..."
New-Item "$OUTPUT_FOLDER\IpAddress" -ItemType Directory -Force | Out-Null
$Data = Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Untouched.csv" -Delimiter "," | Select-Object -ExpandProperty IpAddress

$Unique = $Data | Sort-Object -Unique
$Unique | Out-File "$OUTPUT_FOLDER\IpAddress\IP-All.txt" -Encoding UTF8

$Count = ($Unique | Measure-Object).Count
$UniqueIP = '{0:N0}' -f $Count
$Total = ($Data | Measure-Object).Count
Write-Output "[Info]  $UniqueIP IP addresses found ($Total)"

# IPv4
# https://ipinfo.io/bogon
$IPv4 = "(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
$Private = "^(192\.168|10\.|172\.1[6789]\.|172\.2[0-9]\.|172\.3[01]\.)"
$Special = "^(0\.0\.0\.0|127\.0\.0\.1|169\.254\.|224\.0\.0)"
Get-Content "$OUTPUT_FOLDER\IpAddress\IP-All.txt" | Select-String -Pattern $IPv4 -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique -Property { [System.Version]$_ } | Out-File "$OUTPUT_FOLDER\IpAddress\IPv4-All.txt" -Encoding UTF8
Get-Content "$OUTPUT_FOLDER\IpAddress\IP-All.txt" | Select-String -Pattern $IPv4 -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique -Property { [System.Version]$_ } | Where-Object {$_ -notmatch $Private} | Where-Object {$_ -notmatch $Special} | Out-File "$OUTPUT_FOLDER\IpAddress\IPv4.txt" -Encoding UTF8

# Count
$Total = (Get-Content "$OUTPUT_FOLDER\IpAddress\IPv4-All.txt" | Measure-Object).Count # Public (Unique) + Private (Unique) --> Note: Extracts IPv4 addresses of IPv4-compatible IPv6 addresses.
$Public = (Get-Content "$OUTPUT_FOLDER\IpAddress\IPv4.txt" | Measure-Object).Count # Public (Unique)
$UniquePublic = '{0:N0}' -f $Public
Write-Output "[Info]  $UniquePublic Public IPv4 addresses found ($Total)"

# IPv6
# https://ipinfo.io/bogon
$IPv6 = ":(?::[a-f\d]{1,4}){0,5}(?:(?::[a-f\d]{1,4}){1,2}|:(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})))|[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}:(?:[a-f\d]{1,4}|:)|(?::(?:[a-f\d]{1,4})?|(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))))|:(?:(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|[a-f\d]{1,4}(?::[a-f\d]{1,4})?|))|(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|:[a-f\d]{1,4}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){0,2})|:))|(?:(?::[a-f\d]{1,4}){0,2}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:))|(?:(?::[a-f\d]{1,4}){0,3}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:))|(?:(?::[a-f\d]{1,4}){0,4}(?::(?:(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})\.){3}(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))|(?::[a-f\d]{1,4}){1,2})|:))"
$Bogon = "^(::1|::ffff:|100::|2001:10::|2001:db8::|fc00::|fe80::|fec0::|ff00::)"
Get-Content "$OUTPUT_FOLDER\IpAddress\IP-All.txt" | Select-String -Pattern $IPv6 -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique | Out-File "$OUTPUT_FOLDER\IpAddress\IPv6-All.txt" -Encoding UTF8
Get-Content "$OUTPUT_FOLDER\IpAddress\IP-All.txt" | Select-String -Pattern $IPv6 -AllMatches | ForEach-Object { $_.Matches } | ForEach-Object { $_.Value } | Sort-Object -Unique | Where-Object {$_ -notmatch $Bogon} | Out-File "$OUTPUT_FOLDER\IpAddress\IPv6.txt" -Encoding UTF8

# Count
$Total = (Get-Content "$OUTPUT_FOLDER\IpAddress\IPv6-All.txt" | Measure-Object).Count # including Bogus IPv6 addresses (e.g. IPv4-compatible IPv6 addresses)
$Public = (Get-Content "$OUTPUT_FOLDER\IpAddress\IPv6.txt" | Measure-Object).Count
Write-Output "[Info]  $Public Public IPv6 addresses found ($Total)"

# IP.txt
Write-Output "IPAddress" | Out-File "$OUTPUT_FOLDER\IpAddress\IP.txt" -Encoding UTF8 # Header

# IPv4.txt
if (Test-Path "$OUTPUT_FOLDER\IpAddress\IPv4.txt")
{
    if ((Get-Item "$OUTPUT_FOLDER\IpAddress\IPv4.txt").Length -gt 0kb)
    {
        Get-Content -Path "$OUTPUT_FOLDER\IpAddress\IPv4.txt" | Out-File "$OUTPUT_FOLDER\IpAddress\IP.txt" -Encoding UTF8 -Append
    }
}

# IPv6.txt
if (Test-Path "$OUTPUT_FOLDER\IpAddress\IPv6.txt")
{
    if ((Get-Item "$OUTPUT_FOLDER\IpAddress\IPv6.txt").Length -gt 0kb)
    {
        Get-Content -Path "$OUTPUT_FOLDER\IpAddress\IPv6.txt" | Out-File "$OUTPUT_FOLDER\IpAddress\IP.txt" -Encoding UTF8 -Append
    }
}

# Check IPinfo Subscription Plan (https://ipinfo.io/pricing)
if (Test-Path "$($IPinfo)")
{
    $Quota = & $IPinfo quota
    if ($Quota -eq "err: please login first to check quota")
    {
        # IPinfo Login
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
    if (Test-Path "$OUTPUT_FOLDER\IpAddress\IP.txt")
    {
        if ((Get-Item "$OUTPUT_FOLDER\IpAddress\IP.txt").Length -gt 0kb)
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
                    New-Item "$OUTPUT_FOLDER\IpAddress\IPinfo" -ItemType Directory -Force | Out-Null
                    Get-Content "$OUTPUT_FOLDER\IpAddress\IP.txt" | & $IPinfo map | Out-File "$OUTPUT_FOLDER\IpAddress\IPinfo\Map.txt" -Encoding UTF8

                    # Access Token
                    # https://ipinfo.io/signup?ref=cli
                    if (!("$Token" -eq "access_token"))
                    {
                        # Summarize IPs
                        # https://ipinfo.io/summarize-ips

                        # TXT --> Top Privacy Services
                        Get-Content "$OUTPUT_FOLDER\IpAddress\IP.txt" | & $IPinfo summarize --token "$Token" | Out-File "$OUTPUT_FOLDER\IpAddress\IPinfo\Summary.txt" -Encoding UTF8

                        # CSV
                        Get-Content "$OUTPUT_FOLDER\IpAddress\IP.txt" | & $IPinfo --csv --token "$Token" | Out-File "$OUTPUT_FOLDER\IpAddress\IPinfo\IPinfo.csv" -Encoding UTF8

                        # Custom CSV (Free)
                        if ($PrivacyDetection -eq "False")
                        {
                            if (Test-Path "$OUTPUT_FOLDER\IpAddress\IPinfo\IPinfo.csv")
                            {
                                if([int](& $xsv count "$OUTPUT_FOLDER\IpAddress\IPinfo\IPinfo.csv") -gt 0)
                                {
                                    $IPinfoRecords = Import-Csv "$OUTPUT_FOLDER\IpAddress\IPinfo\IPinfo.csv" -Delimiter "," -Encoding UTF8

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

                                    $Results | Sort-Object {$_.IP -as [Version]} | Export-Csv -Path "$OUTPUT_FOLDER\IpAddress\IPinfo\IPinfo-Custom.csv" -NoTypeInformation -Encoding UTF8
                                }
                            }

                            # Custom XLSX (Free)
                            if (Test-Path "$OUTPUT_FOLDER\IpAddress\IPinfo\IPinfo-Custom.csv")
                            {
                                if([int](& $xsv count "$OUTPUT_FOLDER\IpAddress\IPinfo\IPinfo-Custom.csv") -gt 0)
                                {
                                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\IpAddress\IPinfo\IPinfo-Custom.csv" -Delimiter "," | Sort-Object {$_.ip -as [Version]}
                                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\IpAddress\IPinfo\IPinfo-Custom.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -IncludePivotTable -PivotTableName "PivotTable" -PivotRows "Country Name" -PivotData @{"IP"="Count"} -WorkSheetname "IPinfo (Free)" -CellStyleSB {
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
                            if (Test-Path "$OUTPUT_FOLDER\IpAddress\IPinfo\IPinfo.csv")
                            {
                                if([int](& $xsv count "$OUTPUT_FOLDER\IpAddress\IPinfo\IPinfo.csv") -gt 0)
                                {
                                    $IPinfoRecords = Import-Csv "$OUTPUT_FOLDER\IpAddress\IPinfo\IPinfo.csv" -Delimiter "," -Encoding UTF8

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

                                    $Results | Sort-Object {$_.IP -as [Version]} | Export-Csv -Path "$OUTPUT_FOLDER\IpAddress\IPinfo\IPinfo-Custom.csv" -NoTypeInformation -Encoding UTF8
                                }
                            }

                            # Custom XLSX (Privacy Detection)
                            if (Test-Path "$OUTPUT_FOLDER\IpAddress\IPinfo\IPinfo-Custom.csv")
                            {
                                if([int](& $xsv count "$OUTPUT_FOLDER\IpAddress\IPinfo\IPinfo-Custom.csv") -gt 0)
                                {
                                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\IpAddress\IPinfo\IPinfo-Custom.csv" -Delimiter "," | Sort-Object {$_.ip -as [Version]}
                                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\IpAddress\IPinfo\IPinfo-Custom.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -IncludePivotTable -PivotTableName "PivotTable" -PivotRows "Country Name" -PivotData @{"IP"="Count"} -WorkSheetname "IPinfo (Standard)" -CellStyleSB {
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
                        if (Test-Path "$OUTPUT_FOLDER\IpAddress\IPinfo\IPinfo-Custom.csv")
                        {
                            if([int](& $xsv count "$OUTPUT_FOLDER\IpAddress\IPinfo\IPinfo-Custom.csv") -gt 0)
                            {
                                # Free
                                if ($PrivacyDetection -eq "False")
                                {
                                    Import-Csv -Path "$OUTPUT_FOLDER\IpAddress\IPinfo\IPinfo-Custom.csv" -Delimiter "," -Encoding UTF8 | ForEach-Object { $IPinfo_HashTable[$_.IP] = $_.City,$_.Region,$_.Country,$_."Country Name",$_.Location,$_.ASN,$_.OrgName,$_."Postal Code",$_.Timezone }
                                }

                                # Privacy Detection
                                if ($PrivacyDetection -eq "True")
                                {
                                    Import-Csv -Path "$OUTPUT_FOLDER\IpAddress\IPinfo\IPinfo-Custom.csv" -Delimiter "," -Encoding UTF8 | ForEach-Object { $IPinfo_HashTable[$_.IP] = $_.City,$_.Region,$_.Country,$_."Country Name",$_.Location,$_.ASN,$_.OrgName,$_."Postal Code",$_.Timezone,$_.VPN,$_.Proxy,$_.Tor,$_.Relay,$_.Hosting,$_.Service }
                                }

                                # Count Ingested Properties
                                $Count = $IPinfo_HashTable.Count
                                Write-Output "[Info]  Initializing 'IPinfo-Custom.csv' Lookup Table ($Count) ..."
                            }
                        }

                        # Create HashTable and import 'Status.csv'
                        $Status_HashTable = @{}
                        if (Test-Path "$SCRIPT_DIR\Config\Status.csv")
                        {
                            if([int](& $xsv count "$SCRIPT_DIR\Config\Status.csv") -gt 0)
                            {
                                Import-Csv "$SCRIPT_DIR\Config\Status.csv" -Delimiter "," -Encoding UTF8 | ForEach-Object { $Status_HashTable[$_.ErrorCode] = $_.Status, $_.Message }
                            }
                        }
                        else
                        {
                            Write-Output "Status.csv NOT found."
                        }

                        # Hunt

                        # IPinfo Subscription: Free
                        if ($PrivacyDetection -eq "False")
                        {
                            if (Test-Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Untouched.csv")
                            {
                                if([int](& $xsv count "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Untouched.csv") -gt 0)
                                {
                                    $Records = Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Untouched.csv" -Delimiter "," -Encoding UTF8

                                    # CSV
                                    $Results = [Collections.Generic.List[PSObject]]::new()

                                    ForEach($Record in $Records)
                                    {
                                        # Status
                                        [int]$ErrorCode = $Record | Select-Object -ExpandProperty ErrorCode

                                        # Check if HashTable contains IP
                                        if($Status_HashTable.ContainsKey("$ErrorCode"))
                                        {
                                            $Status = $Status_HashTable["$ErrorCode"][0]
                                        }
                                        else
                                        {
                                            $Status = "Failure"
                                        }

                                        # Authorization Error Codes (AADSTS) aka Entra ID Sign-in Error Codes
                                        # https://learn.microsoft.com/en-us/azure/active-directory/develop/reference-error-codes
                                        # https://login.microsoftonline.com/error
                                        # https://blog.icewolf.ch/archive/2021/02/04/hunting-for-basic-authentication-in-azuread/

                                        # IpAddress
                                        $IP = $Record.IpAddress

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
                                            "Id"                           = $Record.Id
                                            "CreatedDateTime"              = $Record.CreatedDateTime
                                            "UserDisplayName"              = $Record.UserDisplayName
                                            "UserPrincipalName"            = $Record.UserPrincipalName
                                            "UserId"                       = $Record.UserId
                                            "AppId"                        = $Record.AppId
                                            "AppDisplayName"               = $Record.AppDisplayName
                                            "ClientAppUsed"                = $Record.ClientAppUsed
                                            "CorrelationId"                = $Record.CorrelationId
                                            "ConditionalAccessStatus"      = $Record.ConditionalAccessStatus
                                            "OriginalRequestId"            = $Record.OriginalRequestId
                                            "IsInteractive"                = $Record.IsInteractive
                                            "TokenIssuerName"              = $Record.TokenIssuerName
                                            "TokenIssuerType"              = $Record.TokenIssuerType
                                            "ProcessingTimeInMilliseconds" = $Record.ProcessingTimeInMilliseconds
                                            "RiskDetail"                   = $Record.RiskDetail
                                            "RiskLevelAggregated"          = $Record.RiskLevelAggregated
                                            "RiskLevelDuringSignIn"        = $Record.RiskLevelDuringSignIn
                                            "RiskState"                    = $Record.RiskState
                                            "RiskEventTypesV2"             = $Record.RiskEventTypesV2
                                            "ResourceDisplayName"          = $Record.ResourceDisplayName
                                            "ResourceId"                   = $Record.ResourceId
                                            "AuthenticationMethodsUsed"    = $Record.AuthenticationMethodsUsed
                                            "ErrorCode"                    = $Record.ErrorCode
                                            "FailureReason"                = $Record.FailureReason
                                            "AdditionalDetails"            = $Record.AdditionalDetails
                                            "Status"                       = $Status
                                            "DeviceId"                     = $Record.DeviceId
                                            "DisplayName"                  = $Record.DisplayName
                                            "OperatingSystem"              = $Record.OperatingSystem
                                            "Browser"                      = $Record.Browser
                                            "IsCompliant"                  = $Record.IsCompliant
                                            "IsManaged"                    = $Record.IsManaged
                                            "TrustType"                    = $Record.TrustType
                                            "AuthMethod"                   = $Record.AuthMethod
                                            "AuthDetail"                   = $Record.AuthDetail
                                            "AuthenticationProtocol"       = $Record.AuthenticationProtocol
                                            "IpAddress"                    = $IP
                                            "City"                         = $City
                                            "Region"                       = $Region
                                            "Country"                      = $Country
                                            "Country Name"                 = $CountryName
                                            "Location"                     = $Location
                                            "ASN"                          = $ASN
                                            "OrgName"                      = $OrgName
                                            "Postal Code"                  = $PostalCode
                                            "Timezone"                     = $Timezone
                                            "UserAgent"                    = $Record.UserAgent
                                            "UserType"                     = $Record.UserType
                                        }

                                        $Results.Add($Line)
                                    }

                                    $Results | Sort-Object {$_.IP -as [Version]} | Export-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -NoTypeInformation -Encoding UTF8
                                }
                            }

                            # XLSX
                            if (Test-Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv")
                            {
                                if([int](& $xsv count "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv") -gt 0)
                                {
                                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -Delimiter "," | Sort-Object { $_.CreatedDateTime -as [datetime] } -Descending
                                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\XLSX\Hunt.xlsx" -NoNumberConversion * -FreezePane 2,5 -BoldTopRow -AutoSize -AutoFilter -IncludePivotTable -PivotTableName "PivotTable" -WorkSheetname "Hunt" -CellStyleSB {
                                    param($WorkSheet)
                                    # BackgroundColor and FontColor for specific cells of TopRow
                                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                    Set-Format -Address $WorkSheet.Cells["A1:AW1"] -BackgroundColor $BackgroundColor -FontColor White
                                    # HorizontalAlignment "Center" of columns A-X and AA-AW
                                    $WorkSheet.Cells["A:X"].Style.HorizontalAlignment="Center"
                                    $WorkSheet.Cells["AA:AW"].Style.HorizontalAlignment="Center"
                                    # ConditionalFormatting - AppId
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["F:G"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("29d9ed98-a469-4536-ade2-f981bc1d605e",$F1)))' -BackgroundColor Red # Microsoft Authentication Broker
                                    # ConditionalFormatting - AuthenticationProtocol
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["AK:AK"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("deviceCode",$AK1)))' -BackgroundColor Red # Device Code Authentication
                                    # ConditionalFormatting - Browser
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["AE:AE"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Python Requests",$AE1)))' -BackgroundColor Red # Offensive Tool
                                    # ConditionalFormatting - ErrorCode
                                    $Cells = "X:Y"
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("50053",$X1)))' -BackgroundColor Red # Sign-in was blocked because it came from an IP address with malicious activity
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("90095",$X1)))' -BackgroundColor Red # Admin consent is required for the permissions requested by this application. An admin consent request may be sent to the admin.
                                    # ConditionalFormatting - ASN
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["AR:AR"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("13335",$AR1)))' -BackgroundColor Red # Phishing for Refresh Tokens via Cloudflare Workers (AiTM) --> AADNonInteractiveUserSignInLogs

                                    # Iterating over the Application-Blacklist HashTable
                                    foreach ($AppId in $ApplicationBlacklist_HashTable.Keys) 
                                    {
                                        $Severity = $ApplicationBlacklist_HashTable["$AppId"][1]
                                        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$F1)))' -f $AppId
                                        Add-ConditionalFormatting -Address $WorkSheet.Cells["F:G"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
                                    }

                                    # Iterating over the ASN-Blacklist HashTable
                                    foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
                                    {
                                        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$AR1)))' -f $ASN
                                        Add-ConditionalFormatting -Address $WorkSheet.Cells["AR:AS"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
                                    }

                                    # Iterating over the Country-Blacklist HashTable
                                    foreach ($Country in $CountryBlacklist_HashTable.Keys) 
                                    {
                                        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$AP1)))' -f $Country
                                        Add-ConditionalFormatting -Address $WorkSheet.Cells["AO:AP"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
                                    }

                                    # Iterating over the UserAgent-Blacklist HashTable
                                    foreach ($UserAgent in $UserAgentBlacklist_HashTable.Keys) 
                                    {
                                        $Severity = $UserAgentBlacklist_HashTable["$UserAgent"][1]
                                        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$AV1)))' -f $UserAgent
                                        Add-ConditionalFormatting -Address $WorkSheet.Cells["AV:AV"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
                                    }

                                    }
                                }
                            }
                        }

                        # IPinfo Subscription Plan w/ Privacy Detection
                        if ($PrivacyDetection -eq "True")
                        {
                            if (Test-Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Untouched.csv")
                            {
                                if([int](& $xsv count "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Untouched.csv") -gt 0)
                                {
                                    $Records = Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Untouched.csv" -Delimiter "," -Encoding UTF8

                                    # CSV
                                    $Results = [Collections.Generic.List[PSObject]]::new()

                                    ForEach($Record in $Records)
                                    {
                                        # Status
                                        [int]$ErrorCode = $Record | Select-Object -ExpandProperty ErrorCode

                                        # Check if HashTable contains IP
                                        if($Status_HashTable.ContainsKey("$ErrorCode"))
                                        {
                                            $Status = $Status_HashTable["$ErrorCode"][0]
                                        }
                                        else
                                        {
                                            $Status = "Failure"
                                        }

                                        # Authorization Error Codes (AADSTS) aka Entra ID Sign-in Error Codes
                                        # https://learn.microsoft.com/en-us/azure/active-directory/develop/reference-error-codes
                                        # https://login.microsoftonline.com/error
                                        # https://blog.icewolf.ch/archive/2021/02/04/hunting-for-basic-authentication-in-azuread/

                                        # IpAddress
                                        $IP = $Record.IpAddress

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
                                            "Id"                           = $Record.Id
                                            "CreatedDateTime"              = $Record.CreatedDateTime
                                            "UserDisplayName"              = $Record.UserDisplayName
                                            "UserPrincipalName"            = $Record.UserPrincipalName
                                            "UserId"                       = $Record.UserId
                                            "AppId"                        = $Record.AppId
                                            "AppDisplayName"               = $Record.AppDisplayName
                                            "ClientAppUsed"                = $Record.ClientAppUsed
                                            "CorrelationId"                = $Record.CorrelationId
                                            "ConditionalAccessStatus"      = $Record.ConditionalAccessStatus
                                            "OriginalRequestId"            = $Record.OriginalRequestId
                                            "IsInteractive"                = $Record.IsInteractive
                                            "TokenIssuerName"              = $Record.TokenIssuerName
                                            "TokenIssuerType"              = $Record.TokenIssuerType
                                            "ProcessingTimeInMilliseconds" = $Record.ProcessingTimeInMilliseconds
                                            "RiskDetail"                   = $Record.RiskDetail
                                            "RiskLevelAggregated"          = $Record.RiskLevelAggregated
                                            "RiskLevelDuringSignIn"        = $Record.RiskLevelDuringSignIn
                                            "RiskState"                    = $Record.RiskState
                                            "RiskEventTypesV2"             = $Record.RiskEventTypesV2
                                            "ResourceDisplayName"          = $Record.ResourceDisplayName
                                            "ResourceId"                   = $Record.ResourceId
                                            "AuthenticationMethodsUsed"    = $Record.AuthenticationMethodsUsed
                                            "ErrorCode"                    = $Record.ErrorCode
                                            "FailureReason"                = $Record.FailureReason
                                            "AdditionalDetails"            = $Record.AdditionalDetails
                                            "Status"                       = $Status
                                            "DeviceId"                     = $Record.DeviceId
                                            "DisplayName"                  = $Record.DisplayName
                                            "OperatingSystem"              = $Record.OperatingSystem
                                            "Browser"                      = $Record.Browser
                                            "IsCompliant"                  = $Record.IsCompliant
                                            "IsManaged"                    = $Record.IsManaged
                                            "TrustType"                    = $Record.TrustType
                                            "AuthMethod"                   = $Record.AuthMethod
                                            "AuthDetail"                   = $Record.AuthDetail
                                            "AuthenticationProtocol"       = $Record.AuthenticationProtocol
                                            "IpAddress"                    = $IP
                                            "City"                         = $City
                                            "Region"                       = $Region
                                            "Country"                      = $Country
                                            "Country Name"                 = $CountryName
                                            "Location"                     = $Location
                                            "ASN"                          = $ASN
                                            "OrgName"                      = $OrgName
                                            "Postal Code"                  = $PostalCode
                                            "Timezone"                     = $Timezone
                                            "VPN"                          = $VPN
                                            "Proxy"                        = $Proxy
                                            "Tor"                          = $Tor
                                            "Relay"                        = $Relay
                                            "Hosting"                      = $Hosting
                                            "Service"                      = $Service
                                            "UserAgent"                    = $Record.UserAgent
                                            "UserType"                     = $Record.UserType
                                        }

                                        $Results.Add($Line)
                                    }

                                    $Results | Sort-Object {$_.IP -as [Version]} | Export-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -NoTypeInformation -Encoding UTF8
                                }
                            }

                            # XLSX
                            if (Test-Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv")
                            {
                                if([int](& $xsv count "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv") -gt 0)
                                {
                                    $IMPORT = Import-Csv "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -Delimiter "," | Sort-Object { $_.CreatedDateTime -as [datetime] } -Descending
                                    $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\XLSX\Hunt.xlsx" -NoNumberConversion * -FreezePane 2,5 -BoldTopRow -AutoSize -AutoFilter -IncludePivotTable -PivotTableName "PivotTable" -WorkSheetname "Hunt" -CellStyleSB {
                                    param($WorkSheet)
                                    # BackgroundColor and FontColor for specific cells of TopRow
                                    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                                    Set-Format -Address $WorkSheet.Cells["A1:BC1"] -BackgroundColor $BackgroundColor -FontColor White
                                    # HorizontalAlignment "Center" of columns A-X and AA-BC
                                    $WorkSheet.Cells["A:X"].Style.HorizontalAlignment="Center"
                                    $WorkSheet.Cells["AA:BC"].Style.HorizontalAlignment="Center"
                                    # ConditionalFormatting - AppId
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["F:G"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("29d9ed98-a469-4536-ade2-f981bc1d605e",$F1)))' -BackgroundColor Red # Microsoft Authentication Broker
                                    # ConditionalFormatting - AuthenticationProtocol
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["AK:AK"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("deviceCode",$AK1)))' -BackgroundColor Red # Device Code Authentication
                                    # ConditionalFormatting - Browser
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["AE:AE"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Python Requests",$AE1)))' -BackgroundColor Red # Offensive Tool
                                    # ConditionalFormatting - ErrorCode
                                    $Cells = "X:Y"
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("50053",$X1)))' -BackgroundColor Red # Sign-in was blocked because it came from an IP address with malicious activity
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["$Cells"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("90095",$X1)))' -BackgroundColor Red # Admin consent is required for the permissions requested by this application. An admin consent request may be sent to the admin.
                                    # ConditionalFormatting - VPN
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["AV:AV"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("true",$AV1)))' -BackgroundColor Red
                                    # ConditionalFormatting - Proxy
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["AW:AW"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("true",$AW1)))' -BackgroundColor Red
                                    # ConditionalFormatting - Tor
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["AX:AX"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("true",$AX1)))' -BackgroundColor Red
                                    # ConditionalFormatting - Relay
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["AY:AY"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("true",$AY1)))' -BackgroundColor Red
                                    # ConditionalFormatting - Service
                                    $LastRow = $WorkSheet.Dimension.End.Row
                                    Add-ConditionalFormatting -Address $WorkSheet.Cells["BA2:BA$LastRow"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '=$BA2<>""' -BackgroundColor Red

                                    # Iterating over the Application-Blacklist HashTable
                                    foreach ($AppId in $ApplicationBlacklist_HashTable.Keys) 
                                    {
                                        $Severity = $ApplicationBlacklist_HashTable["$AppId"][1]
                                        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$F1)))' -f $AppId
                                        Add-ConditionalFormatting -Address $WorkSheet.Cells["F:G"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
                                    }

                                    # Iterating over the ASN-Blacklist HashTable
                                    foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
                                    {
                                        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$AR1)))' -f $ASN
                                        Add-ConditionalFormatting -Address $WorkSheet.Cells["AR:AS"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
                                    }

                                    # Iterating over the Country-Blacklist HashTable
                                    foreach ($Country in $CountryBlacklist_HashTable.Keys) 
                                    {
                                        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$AP1)))' -f $Country
                                        Add-ConditionalFormatting -Address $WorkSheet.Cells["AO:AP"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
                                    }

                                    # Iterating over the UserAgent-Blacklist HashTable
                                    foreach ($UserAgent in $UserAgentBlacklist_HashTable.Keys) 
                                    {
                                        $Severity = $UserAgentBlacklist_HashTable["$UserAgent"][1]
                                        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$BB1)))' -f $UserAgent
                                        Add-ConditionalFormatting -Address $WorkSheet.Cells["BB:BB"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
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
('EntraSignInLogs Data Enrichment duration: {0} h {1} min {2} sec' -f $Time_DataEnrichment.Hours, $Time_DataEnrichment.Minutes, $Time_DataEnrichment.Seconds) >> "$OUTPUT_FOLDER\Stats.txt"

}

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Stats

Function Get-Stats {

$StartTime_Stats = (Get-Date)

# Stats
Write-Output "[Info]  Creating Hunting Stats ..."
New-Item "$OUTPUT_FOLDER\EntraSignInLogs\Stats" -ItemType Directory -Force | Out-Null

# AppDisplayName (Stats)
$Count = (Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Untouched.csv" -Delimiter "," | Select-Object AppDisplayName -Unique | Measure-Object).Count
$AppDisplayName = '{0:N0}' -f $Count
Write-Output "[Info]  $AppDisplayName Applications found"

$Total = (Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Untouched.csv" -Delimiter "," | Select-Object AppDisplayName | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Untouched.csv" -Delimiter "," | Group-Object AppDisplayName,AppId | Select-Object @{Name='AppDisplayName'; Expression={ $_.Values[0] }},@{Name='AppId'; Expression={ $_.Values[1] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Stats\AppDisplayName.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "AppDisplayName" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns B-D
    $WorkSheet.Cells["B:D"].Style.HorizontalAlignment="Center"
        
    # Iterating over the Application-Blacklist HashTable
    foreach ($AppId in $ApplicationBlacklist_HashTable.Keys) 
    {
        $Severity = $ApplicationBlacklist_HashTable["$AppId"][1]
        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$B1)))' -f $AppId
        Add-ConditionalFormatting -Address $WorkSheet.Cells["A:D"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor $Severity
    }

    }
}

# ASN / Status (Stats)
$Total = (Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -Delimiter "," | Select-Object ASN | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = Import-Csv "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -Delimiter "," | Select-Object ASN,OrgName,Status | Where-Object {$_.ASN -ne '' } | Where-Object { $null -ne ($_.PSObject.Properties | ForEach-Object {$_.Value}) } | Group-Object ASN,OrgName,Status | Select-Object @{Name='ASN'; Expression={ $_.Values[0] }},@{Name='OrgName'; Expression={ $_.Values[1] }},@{Name='Status'; Expression={ $_.Values[2] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Stats\ASN.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ASN" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:E1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns A-E
    $WorkSheet.Cells["A:E"].Style.HorizontalAlignment="Center"

    # Iterating over the ASN-Blacklist HashTable
    foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
    {
        $ConditionValue = 'NOT(ISERROR(FIND("{0}",$A1)))' -f $ASN
        Add-ConditionalFormatting -Address $WorkSheet.Cells["A:E"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
    }

    }
}

# AuthenticationProtocol (Stats)
$Total = (Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Untouched.csv" -Delimiter "," | Select-Object AuthenticationProtocol | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Untouched.csv" -Delimiter "," | Group-Object AuthenticationProtocol | Select-Object @{Name='AuthenticationProtocol';Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Stats\AuthenticationProtocol.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "AuthenticationProtocol" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns B-C
    $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
    # ConditionalFormatting - AuthenticationProtocol
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("deviceCode",$A1)))' -BackgroundColor Red # Device Code Authentication
    }
}

# AuthenticationRequirement (Stats)
$Total = (Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Untouched.csv" -Delimiter "," | Select-Object AuthenticationRequirement | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Untouched.csv" -Delimiter "," | Group-Object AuthenticationRequirement | Select-Object @{Name='AuthenticationRequirement';Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Stats\AuthenticationRequirement.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "AuthenticationRequirement" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns B-C
    $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
    }
}

# AuthMethod (Stats)
$Total = (Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Untouched.csv" -Delimiter "," | Select-Object AuthMethod | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Untouched.csv" -Delimiter "," | Group-Object AuthMethod | Select-Object @{Name='AuthMethod';Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Stats\AuthMethod.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "AuthMethod" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns B-C
    $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
    }
}

# Browser (Stats)
$Total = (Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Untouched.csv" -Delimiter "," | Select-Object Browser | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Untouched.csv" -Delimiter "," | Group-Object Browser | Select-Object @{Name='Browser';Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Stats\Browser.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Browser" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns B-C
    $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
    # ConditionalFormatting - Browser
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Python Requests",$A1)))' -BackgroundColor Red
    }
}

# ClientAppUsed (Stats)
$Total = (Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Untouched.csv" -Delimiter "," | Select-Object ClientAppUsed | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Untouched.csv" -Delimiter "," | Group-Object ClientAppUsed | Select-Object @{Name='ClientAppUsed';Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Stats\ClientAppUsed.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ClientAppUsed" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns B-C
    $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
    # ConditionalFormatting - Modern Authentication Clients
    $Green = [System.Drawing.Color]::FromArgb(0,176,80)
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Browser",$A1)))' -BackgroundColor $Green
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Mobile Apps and Desktop clients",$A1)))' -BackgroundColor $Green
    # ConditionalFormatting - Legacy Authentication Clients
    # https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/block-legacy-authentication
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Authenticated SMTP",$A1)))' -BackgroundColor Red
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Other clients",$A1)))' -BackgroundColor Red
    }
}

# ClientAppUsed / Status (Stats)
$Total = (Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -Delimiter "," | Select-Object ClientAppUsed | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -Delimiter "," -Encoding UTF8 | Select-Object @{Name='ClientAppUsed'; Expression={if($_.ClientAppUsed){$_.ClientAppUsed}else{'N/A'}}},Status | Group-Object ClientAppUsed,Status | Select-Object @{Name='ClientAppUsed'; Expression={ $_.Values[0] }},@{Name='Status'; Expression={ $_.Values[1] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Stats\ClientAppUsed-Status.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ClientAppUsed" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns A-D
    $WorkSheet.Cells["A:D"].Style.HorizontalAlignment="Center"
    # ConditionalFormatting - Modern Authentication Clients
    $Green = [System.Drawing.Color]::FromArgb(0,176,80)
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:A"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Browser",$A1)))' -BackgroundColor $Green
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:A"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Mobile Apps and Desktop clients",$A1)))' -BackgroundColor $Green
    # ConditionalFormatting - Legacy Authentication Clients
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:A"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Authenticated SMTP",$A1)))' -BackgroundColor Red
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:D"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '=AND($A1="Authenticated SMTP",$B1="Failure")' -BackGroundColor "Red"
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:A"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Other clients",$A1)))' -BackgroundColor Red
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:D"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '=AND($A1="Other clients",$B1="Failure")' -BackGroundColor "Red"
    }
}

# ConditionalAccessStatus (Stats)
$Total = (Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Untouched.csv" -Delimiter "," | Select-Object ConditionalAccessStatus | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Untouched.csv" -Delimiter "," | Group-Object ConditionalAccessStatus | Select-Object @{Name='ConditionalAccessStatus'; Expression={$_.Name}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Stats\ConditionalAccessStatus.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ConditionalAccessStatus" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns A-C
    $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
    }
}

# Conditional Access Status (Investigating Sign-Ins with CA applied)
# notApplied: No policy applied to the user and application during sign-in.
# success:    One or more conditional access policies applied to the user and application (but not necessarily the other conditions) during sign-in.
# failure:    The sign-in satisfied the user and application condition of at least one Conditional Access policy and grant controls are either not satisfied or set to block access.

# Note: Conditional Access policies are enforced after first-factor authentication is completed. Conditional Access isn't intended to be an organization's first line of defense for scenarios like denial-of-service (DoS) attacks, but it can use signals from these events to determine access.

# Country / Country Name (Stats)
$Total = (Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -Delimiter "," | Select-Object Country | Measure-Object).Count
if ($Total -ge "1")
{       
    $Stats = Import-Csv "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -Delimiter "," | Select-Object Country,"Country Name" | Where-Object {$_.Country -ne '' } | Where-Object { $null -ne ($_.PSObject.Properties | ForEach-Object {$_.Value}) } | Group-Object Country,"Country Name" | Select-Object @{Name='Country'; Expression={ $_.Values[0] }},@{Name='Country Name'; Expression={ $_.Values[1] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Stats\Country.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Countries" -CellStyleSB {
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

    $Countries = (Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -Delimiter "," | Select-Object Country -Unique | Where-Object { $_.Country -ne '' } | Measure-Object).Count
    $Cities = (Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -Delimiter "," | Select-Object City -Unique | Where-Object { $_.City -ne '' } | Measure-Object).Count
    Write-Output "[Info]  $Countries Countries and $Cities Cities found"
}                  

# ErrorCode / Status (Stats)
$Total = (Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -Delimiter "," | Select-Object ErrorCode | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -Delimiter "," -Encoding UTF8| Select-Object Status,ErrorCode,FailureReason,AdditionalDetails | Group-Object Status,ErrorCode,FailureReason,AdditionalDetails | Select-Object @{Name='Status'; Expression={ $_.Values[0] }},@{Name='ErrorCode'; Expression={ $_.Values[1] }},@{Name='FailureReason'; Expression={ $_.Values[2] }},@{Name='AdditionalDetails'; Expression={ $_.Values[3] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Stats\ErrorCode.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ErrorCode" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:F1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns A-B and E-F
    $WorkSheet.Cells["A:B"].Style.HorizontalAlignment="Center"
    $WorkSheet.Cells["E:F"].Style.HorizontalAlignment="Center"
    # ConditionalFormatting - Suspicious Error Codes
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:F"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("50034",$B1)))' -BackgroundColor Red # "The user account does not exist in the tenant directory." --> involving non-existent user accounts
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:F"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("50053",$B1)))' -BackgroundColor Red # Sign-in was blocked because it came from an IP address with malicious activity or The account is locked, you've tried to sign in too many times with an incorrect user ID or password.
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:F"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("50126",$B1)))' -BackgroundColor Red # "Error validating credentials due to invalid username or password." --> Failed authentication attempts (Password Spraying Attack): Identify a traditional password spraying attack where a high number of users fail to authenticate from one single source IP in a short period of time.
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:F"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("90094",$B1)))' -BackgroundColor Red # Admin consent is required for the permissions requested by this application.
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:F"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("90095",$B1)))' -BackgroundColor Red # Admin consent is required for the permissions requested by this application. An admin consent request may be sent to the admin.
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:F"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("500121",$B1)))' -BackgroundColor Red # "Authentication failed during strong authentication request." --> MFA Fatigue aka MFA Prompt Bombing
    Add-ConditionalFormatting -Address $WorkSheet.Cells["A:F"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("530032",$B1)))' -BackgroundColor Red # User blocked due to risk on home tenant.
    }
}

# IpAddress / Country Name (Stats)
$Total = (Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -Delimiter "," | Select-Object IpAddress | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -Delimiter "," -Encoding UTF8 | Select-Object IpAddress,Country,"Country Name",ASN,OrgName | Where-Object {$_.IpAddress -ne '' } | Where-Object {$_."Country Name" -ne '' } | Where-Object { $null -ne ($_.PSObject.Properties | ForEach-Object {$_.Value}) } | Group-Object IpAddress,Country,"Country Name",ASN,OrgName | Select-Object @{Name='IpAddress'; Expression={ $_.Values[0] }},@{Name='Country'; Expression={ $_.Values[1] }},@{Name='Country Name'; Expression={ $_.Values[2] }},@{Name='ASN'; Expression={ $_.Values[3] }},@{Name='OrgName'; Expression={ $_.Values[4] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Stats\IpAddress.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "IpAddress" -CellStyleSB {
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

# NetworkNames (Stats)
$Total = (Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Untouched.csv" -Delimiter "," | Select-Object NetworkNames | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Untouched.csv" -Delimiter "," | Group-Object NetworkNames | Select-Object @{Name='NetworkNames'; Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Stats\NetworkNames.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "NetworkNames" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns B-C
    $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
    }
}

# OperatingSystem (Stats)
$Total = (Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Untouched.csv" -Delimiter "," | Select-Object OperatingSystem | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Untouched.csv" -Delimiter "," | Group-Object OperatingSystem | Select-Object @{Name='OperatingSystem';Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Stats\OperatingSystem.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "OperatingSystem" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns A-C
    $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
    }
}

# ResourceDisplayName (Stats)
$Count = (Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Untouched.csv" -Delimiter "," | Select-Object ResourceDisplayName | Sort-Object ResourceDisplayName -Unique | Measure-Object).Count
$ResourceDisplayName = '{0:N0}' -f $Count
Write-Output "[Info]  $ResourceDisplayName Resources found"

$Total = (Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Untouched.csv" -Delimiter "," | Select-Object ResourceDisplayName | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Untouched.csv" -Delimiter "," | Group-Object ResourceDisplayName | Select-Object @{Name='ResourceDisplayName';Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Stats\ResourceDisplayName.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "ResourceDisplayName" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns B-C
    $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
    }
}

# RiskDetail (Stats)
$Total = (Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Untouched.csv" -Delimiter "," | Select-Object RiskDetail | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Untouched.csv" -Delimiter "," | Group-Object RiskDetail | Select-Object @{Name='RiskDetail';Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Stats\RiskDetail.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "RiskDetail" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns B-C
    $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
    }
}

# RiskEventTypesV2 (Stats)
$Total = (Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Untouched.csv" -Delimiter "," | Select-Object RiskEventTypesV2 | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Untouched.csv" -Delimiter "," | Group-Object RiskEventTypesV2 | Select-Object @{Name='RiskEventTypesV2';Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Stats\RiskEventTypesV2.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "RiskEventTypesV2" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns B-C
    $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
    }
}

# RiskLevelDuringSignIn (Stats)
$Total = (Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Untouched.csv" -Delimiter "," | Select-Object RiskLevelDuringSignIn | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Untouched.csv" -Delimiter "," | Group-Object RiskLevelDuringSignIn | Select-Object @{Name='RiskLevelDuringSignIn';Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Stats\RiskLevelDuringSignIn.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "RiskLevelDuringSignIn" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns A-C
    $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
    }
}

# SignInEventTypes (Stats)
$Total = (Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Untouched.csv" -Delimiter "," | Select-Object SignInEventTypes | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Untouched.csv" -Delimiter "," -Encoding UTF8 | Group-Object SignInEventTypes | Select-Object @{Name='SignInEventTypes';Expression={$_.Name}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Stats\SignInEventTypes.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "SignInEventTypes" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns A-C
    $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
    }
}

# Status (Stats)
$Total = (Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -Delimiter "," | Select-Object Status | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -Delimiter "," | Group-Object Status | Select-Object @{Name='Status'; Expression={$_.Name}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Stats\Status.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Status" -CellStyleSB {
    param($WorkSheet)
    # BackgroundColor and FontColor for specific cells of TopRow
    $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
    Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
    # HorizontalAlignment "Center" of columns A-C
    $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
    }
}

# UserAgent (Stats)
$Total = (Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Untouched.csv" -Delimiter "," | Select-Object UserAgent | Measure-Object).Count
if ($Total -ge "1")
{
    $Stats = Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Untouched.csv" -Delimiter "," | Group-Object UserAgent | Select-Object @{Name='UserAgent';Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending
    $Stats | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Stats\UserAgent.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "UserAgent" -CellStyleSB {
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

# VPN Services (Stats)
if ($PrivacyDetection -eq "True")
{
    if (Test-Path "$OUTPUT_FOLDER\IpAddress\IPinfo\IPinfo-Custom.csv")
    {
        if([int](& $xsv count "$OUTPUT_FOLDER\IpAddress\IPinfo\IPinfo-Custom.csv") -gt 0)
        {
            $Import = Import-Csv "$OUTPUT_FOLDER\IpAddress\IPinfo\IPinfo-Custom.csv" -Delimiter "," | Sort-Object {$_.ip -as [Version]}
            $Count = ($Import | Where-Object {$_.VPN -eq "true"} | Measure-Object).Count

            if ($Count -ge 1)
            {
                $Total = ($Import | Measure-Object).Count
                $VPNServices = $Import | Where-Object {$_.VPN -eq "true"} | Where-Object {$_.Service -ne ""} | Group-Object Service | Select-Object @{Name='VPN Service';Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending

                Write-Host "[Alert] Suspicious VPN Services found ($Count)" -ForegroundColor Red

                foreach ($VPNService in $VPNServices) 
                {
                    $Service = $VPNService."VPN Service"
                    $Count = $VPNService.Count
                    Write-Host "[Alert] Suspicious VPN Service detected: $Service ($Count)" -ForegroundColor Red
                }

                $VPNServices | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Stats\VPN-Services.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "VPN" -CellStyleSB {
                param($WorkSheet)
                # BackgroundColor and FontColor for specific cells of TopRow
                $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
                Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
                # HorizontalAlignment "Center" of columns B-C
                $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
                # ConditionalFormatting - Service
                $LastRow = $WorkSheet.Dimension.End.Row
                Add-ConditionalFormatting -Address $WorkSheet.Cells["A2:C$LastRow"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '=$A2<>""' -BackgroundColor Red
                }
            }
        }
    }
}

$EndTime_Stats = (Get-Date)
$Time_Stats = ($EndTime_Stats-$StartTime_Stats)
('EntraSignInLogs Stats duration:           {0} h {1} min {2} sec' -f $Time_Stats.Hours, $Time_Stats.Minutes, $Time_Stats.Seconds) >> "$OUTPUT_FOLDER\Stats.txt"

}

#endregion Stats

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Analytics

Function Get-Analytics {

$StartTime_Analytics = (Get-Date)

# Brute-Force Detection
$Import = Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -Delimiter "," -Encoding UTF8 | Where-Object { $_.Status -eq 'Failure' }
$Count = ($Import | Group-Object{($_.CreatedDateTime -split "\s+")[0]} | Where-Object Count -ge 1000 | Measure-Object).Count

if ($Count -ge 1)
{
    Write-Host "[Alert] Brute-Force Attack detected: 1000+ failed Sign-In events on a single day ($Count)" -ForegroundColor Red
    New-Item "$OUTPUT_FOLDER\EntraSignInLogs\Brute-Force-Attack\CSV" -ItemType Directory -Force | Out-Null
    New-Item "$OUTPUT_FOLDER\EntraSignInLogs\Brute-Force-Attack\XLSX" -ItemType Directory -Force | Out-Null

    # CSV
    $Import | Group-Object{($_.CreatedDateTime -split "\s+")[0]} | Where-Object Count -ge 1000 | Select-Object Name,Count | Export-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\Brute-Force-Attack\CSV\Brute-Force-Attack-Overview.csv" -NoTypeInformation -Encoding UTF8
    $Import | Group-Object{($_.CreatedDateTime -split "\s+")[0]} | Where-Object Count -ge 1000 | Select-Object -Expand Group | Export-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\Brute-Force-Attack\CSV\Brute-Force-Attack.csv" -NoTypeInformation -Encoding UTF8

    # Brute-Force-Attack-Overview.xlsx
    if (Test-Path "$OUTPUT_FOLDER\EntraSignInLogs\Brute-Force-Attack\CSV\Brute-Force-Attack-Overview.csv")
    {
        if([int](& $xsv count -d "," "$OUTPUT_FOLDER\EntraSignInLogs\Brute-Force-Attack\CSV\Brute-Force-Attack-Overview.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\EntraSignInLogs\Brute-Force-Attack\CSV\Brute-Force-Attack-Overview.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Brute-Force-Attack\XLSX\Brute-Force-Attack-Overview.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Brute-Force Attack" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:B1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-B
            $WorkSheet.Cells["A:B"].Style.HorizontalAlignment="Center"
            }
        }
    }

    # Brute-Force-Attack.xlsx
    if (Test-Path "$OUTPUT_FOLDER\EntraSignInLogs\Brute-Force-Attack\CSV\Brute-Force-Attack.csv")
    {
        if([int](& $xsv count -d "," "$OUTPUT_FOLDER\EntraSignInLogs\Brute-Force-Attack\CSV\Brute-Force-Attack.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\EntraSignInLogs\Brute-Force-Attack\CSV\Brute-Force-Attack.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Brute-Force-Attack\XLSX\Brute-Force-Attack.xlsx" -NoNumberConversion * -FreezePane 2,4 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Brute-Force Attack" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:AU1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-X and AA-AU
            $WorkSheet.Cells["A:X"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["AA:AU"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting
            Add-ConditionalFormatting -Address $WorkSheet.Cells["AA:AA"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Failure",$AA1)))' -BackgroundColor Red
            Add-ConditionalFormatting -Address $WorkSheet.Cells["H:H"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Authenticated SMTP",$H1)))' -BackgroundColor Red
            }
        }
    }
}

# Basic Authentication (Legacy Authentication Client) detected: Authenticated SMTP
$Count = (Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -Delimiter "," | Where-Object { $_.ClientAppUsed -eq 'Authenticated SMTP' } | Measure-Object).Count

if ($Count -ge 1)
{
    $Failure = (Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -Delimiter "," | Where-Object { $_.ClientAppUsed -eq 'Authenticated SMTP' } | Where-Object { $_.Status -eq 'Failure' } | Measure-Object).Count
    $Success = (Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -Delimiter "," | Where-Object { $_.ClientAppUsed -eq 'Authenticated SMTP' } | Where-Object { $_.Status -eq 'Success' } | Measure-Object).Count
    $FailureCount = '{0:N0}' -f $Failure
    $SuccessCount = '{0:N0}' -f $Success
    Write-Host "[Alert] Basic Authentication (Legacy Authentication Client) detected: Authenticated SMTP ($Count)" -ForegroundColor Red
    Write-Host "[Alert] $FailureCount failed Sign-Ins via Legacy Authentication Client detected: Authenticated SMTP" -ForegroundColor Red
    Write-Host "[Alert] $SuccessCount successful Sign-Ins via Legacy Authentication Client detected: Authenticated SMTP" -ForegroundColor Red
}

# Intune Bypass / Device Compliance Bypass
$Import = Get-Content -Path "$LogFile" -Raw | ConvertFrom-Json 
$Data = $Import | Where-Object {$_.appId -eq "9ba1a5c7-f17a-4de9-a1f1-6178c8d51223"} | Where-Object {($_.status.errorCode -eq "0" -or $_.status.errorCode -eq "50199")} | Where-Object { $_.deviceDetail.IsCompliant -eq $false } | Sort-Object { $_.createdDateTime -as [datetime] } -Descending
$SignIns = $Data | Where-Object {($_.appliedConditionalAccessPolicies.enforcedGrantControls -match "RequireCompliantDevice" -and $_.appliedConditionalAccessPolicies.result -eq "failure") -or ($_.appliedConditionalAccessPolicies.enforcedGrantControls -match "Block" -and $_.appliedConditionalAccessPolicies.result -eq "notApplied")}
$Count = ($SignIns | Measure-Object).Count

if ($Count -ge 1)
{
    Write-Host "[Alert] Device Compliance Bypass detected: Microsoft Intune Company Portal ($Count)" -ForegroundColor Red
    New-Item "$OUTPUT_FOLDER\EntraSignInLogs\Alerts\IntuneBypass" -ItemType Directory -Force | Out-Null

    # JSON
    $SignIns | ConvertTo-Json -Depth 10 | Out-File "$OUTPUT_FOLDER\EntraSignInLogs\Alerts\IntuneBypass\IntuneBypass.json" -Encoding UTF8

    $Results = [Collections.Generic.List[PSObject]]::new()
    ForEach($SignIn in $SignIns)
    {
        $DeviceDetail = $SignIn | Select-Object -ExpandProperty deviceDetail
        $Status = $SignIn | Select-Object -ExpandProperty status
        $AuthenticationAppDeviceDetails = $SignIn | Select-Object -ExpandProperty authenticationAppDeviceDetails

        # IpAddress
        $IP = $SignIn.iPAddress

        # Check if HashTable contains IP
        if($IPinfo_HashTable.ContainsKey("$IP"))
        {
            $City        = $IPinfo_HashTable["$IP"][0]
            $Region      = $IPinfo_HashTable["$IP"][1]
            $Country     = $IPinfo_HashTable["$IP"][2]
            $CountryName = $IPinfo_HashTable["$IP"][3]
            $Location    = $IPinfo_HashTable["$IP"][5]
            $ASN         = $IPinfo_HashTable["$IP"][6] | ForEach-Object {$_ -replace "^AS"}
            $OrgName     = $IPinfo_HashTable["$IP"][7]
            $Timezone    = $IPinfo_HashTable["$IP"][9]
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
            $Timezone    = ""
        }

        $Line = [PSCustomObject]@{
        "Id"                               = $SignIn.id
        "CreatedDateTime"                  = (Get-Date $SignIn.createdDateTime).ToString("yyyy-MM-dd HH:mm:ss")
        "UserDisplayName"                  = $SignIn.userDisplayName
        "UserPrincipalName"                = $SignIn.userPrincipalName
        "UserId"                           = $SignIn.userId
        "AppId"                            = $SignIn.appId
        "AppDisplayName"                   = $SignIn.appDisplayName
        "ClientAppUsed"                    = $SignIn.clientAppUsed
        "CorrelationId"                    = $SignIn.correlationId
        "OriginalRequestId"                = $SignIn.originalRequestId
        "IPAddress"                        = $IP
        "City"                             = $City
        "Region"                           = $Region
        "Country"                          = $Country
        "Country Name"                     = $CountryName
        "Location"                         = $Location
        "ASN"                              = $ASN
        "OrgName"                          = $OrgName
        "Timezone"                         = $Timezone
        "UserAgent"                        = $SignIn.userAgent
        "Browser"                          = $DeviceDetail.browser
        "DeviceId"                         = $DeviceDetail.deviceId
        "DisplayName"                      = $DeviceDetail.displayName
        "ErrorCode"                        = $Status.ErrorCode
        "FailureReason"                    = $Status.FailureReason
        "AdditionalDetails"                = $Status.additionalDetails
        "SessionId"                        = $SignIn.sessionId
        "ResourceDisplayName"              = $SignIn.ResourceDisplayName
        "ResourceId"                       = $SignIn.ResourceId
        "IsCompliant"                      = $DeviceDetail.isCompliant
        "IsManaged"                        = $DeviceDetail.isManaged
        "OperatingSystem"                  = $DeviceDetail.operatingSystem
        "TrustType"                        = $DeviceDetail.trustType
        "ConditionalAccessStatus"          = $SignIn.conditionalAccessStatus | ForEach-Object { $_.Replace("success","Success") } 
        "IsInteractive"                    = $SignIn.isInteractive
        "AuthenticationProtocol"           = $SignIn.authenticationProtocol
        "AuthenticationRequirement"        = $SignIn.authenticationRequirement
        "SignInEventType"                  = $SignIn | Select-Object -ExpandProperty signInEventTypes
        "AuthenticationAppDeviceId"        = $AuthenticationAppDeviceDetails.deviceId
        "AuthenticationAppOperationSystem" = $AuthenticationAppDeviceDetails.operatingSystem
        "AuthenticationAppClientApp"       = $AuthenticationAppDeviceDetails.clientApp
        "AuthenticationAppAppVersion"      = $AuthenticationAppDeviceDetails.appVersion
        }

        $Results.Add($Line)
    }

    $Results | Export-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\Alerts\IntuneBypass\IntuneBypass.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\EntraSignInLogs\Alerts\IntuneBypass\IntuneBypass.csv")
    {
        if([int](& $xsv count "$OUTPUT_FOLDER\EntraSignInLogs\Alerts\IntuneBypass\IntuneBypass.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\EntraSignInLogs\Alerts\IntuneBypass\IntuneBypass.csv" -Delimiter "," | Sort-Object { $_.CreatedDateTime -as [datetime] } -Descending
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Alerts\IntuneBypass\IntuneBypass.xlsx" -NoNumberConversion * -FreezePane 2,5 -BoldTopRow -AutoSize -AutoFilter -IncludePivotTable -PivotTableName "PivotTable" -WorkSheetname "Intune Bypass" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:AP1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-AP
            $WorkSheet.Cells["A:AP"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting - AppId
            Add-ConditionalFormatting -Address $WorkSheet.Cells["F:G"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("9ba1a5c7-f17a-4de9-a1f1-6178c8d51223",$F1)))' -BackgroundColor Red # Microsoft Intune Company Portal
            # ConditionalFormatting - ErrorCode
            Add-ConditionalFormatting -Address $WorkSheet.Cells["X:X"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '$X1="0"' -BackgroundColor Red # Success
            Add-ConditionalFormatting -Address $WorkSheet.Cells["X:X"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '$X1="50199"' -BackgroundColor Red # Microsoft Intune Prompt: Are you trying to sign in to Microsoft Intune Company Portal?
            # ConditionalFormatting - IsCompliant
            Add-ConditionalFormatting -Address $WorkSheet.Cells["AD:AD"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '$AD1="False"' -BackgroundColor Red
            # ConditionalFormatting - ResourceId
            Add-ConditionalFormatting -Address $WorkSheet.Cells["AC:AC"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '$AC1="00000003-0000-0000-c000-000000000000"' -BackgroundColor Red # Microsoft Graph
            Add-ConditionalFormatting -Address $WorkSheet.Cells["AC:AC"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue '$AC1="00000002-0000-0000-c000-000000000000"' -BackgroundColor Red # Windows Azure Active Directory (Azure AD Graph API)
            # ConditionalFormatting - TrustType
            $LastRow = $WorkSheet.Dimension.End.Row
            Add-ConditionalFormatting -Address $WorkSheet.Cells["AG2:AG$LastRow"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("",$AG2)))' -BackgroundColor Red # Non-Joined Device / Non-Registered Device
            }
        }
    }
}

# Suspicious Error Codes

# ErrorCode: 90095 - Admin consent is required for the permissions requested by this application. An admin consent request may be sent to the admin.
$Count = (Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -Delimiter "," | Where-Object { $_.ErrorCode -eq '90095' } | Measure-Object).Count
if ($Count -ge 1)
{
    Write-Host "[Alert] Suspicious Error Code detected: 90095 - Admin consent is required for the permissions requested by an application ($Count)" -ForegroundColor Red
}

#############################################################################################################################################################################################

# Line Charts
New-Item "$OUTPUT_FOLDER\EntraSignInLogs\Stats\LineCharts" -ItemType Directory -Force | Out-Null

# Failure (Sign-Ins)
$Total = (Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -Delimiter "," | Where-Object { $_.Status -eq 'Failure' } | Select-Object IpAddress | Measure-Object).Count
$Count = (Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -Delimiter "," | Where-Object { $_.Status -eq 'Failure' } | Select-Object IpAddress -Unique | Measure-Object).Count
$UniqueFailures = '{0:N0}' -f $Count
Write-Output "IPAddress" | Out-File "$OUTPUT_FOLDER\IpAddress\Failure.txt" -Encoding UTF8 # Header
Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -Delimiter "," | Where-Object { $_.Status -eq 'Failure' } | Select-Object -ExpandProperty IpAddress -Unique | Out-File "$OUTPUT_FOLDER\IpAddress\Failure.txt" -Append
Write-Output "[Info]  $UniqueFailures failed Sign-Ins found ($Total)"

# Authentication: Failure (Line Chart) --> Failed Sign-Ins per day
$Import = Import-Csv "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -Delimiter "," | Where-Object { $_.Status -eq 'Failure' } | Group-Object{($_.CreatedDateTime -split "\s+")[0]} | Select-Object Count,@{Name='CreatedDateTime'; Expression={ $_.Values[0] }} | Sort-Object { $_.CreatedDateTime -as [datetime] }
if ($Count -gt 5)
{
    $ChartDefinition = New-ExcelChartDefinition -XRange CreatedDateTime -YRange Count -Title "Failed Sign-Ins" -ChartType Line -NoLegend -Width 1200
    $Import | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Stats\LineCharts\Failure.xlsx" -Append -WorksheetName "Line Chart" -AutoNameRange -ExcelChartDefinition $ChartDefinition
}

# Failure (Map)
if (Test-Path "$($IPinfo)")
{
    if (Test-Path "$OUTPUT_FOLDER\IpAddress\Failure.txt")
    {
        if ((Get-Item "$OUTPUT_FOLDER\IpAddress\Failure.txt").Length -gt 0kb)
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
                if (!(Test-Connection -ComputerName ipinfo.io -Count 1 -Quiet))
                {
                    Write-Host "[Error] ipinfo.io is NOT reachable. IP addresses cannot be checked via IPinfo API." -ForegroundColor Red
                }
                else
                {
                    # Map IPs
                    Get-Content "$OUTPUT_FOLDER\IpAddress\Failure.txt" | & $IPinfo map | Out-File "$OUTPUT_FOLDER\IpAddress\IPinfo\Map_Failure.txt"
                }
            }
        }
    }
}

# Success (Sign-Ins)
Write-Output "IPAddress" | Out-File "$OUTPUT_FOLDER\IpAddress\Success.txt" -Encoding UTF8 # Header
Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -Delimiter "," | Where-Object { $_.Status -eq 'Success' } | Select-Object -ExpandProperty IpAddress -Unique | Out-File "$OUTPUT_FOLDER\IpAddress\Success.txt" -Append

# Authentication: Success (Line Chart) --> Successful Sign-Ins per day
$Import = Import-Csv "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -Delimiter "," | Where-Object { $_.Status -eq 'Success' } | Group-Object{($_.CreatedDateTime -split "\s+")[0]} | Select-Object Count,@{Name='CreatedDateTime'; Expression={ $_.Values[0] }} | Sort-Object { $_.CreatedDateTime -as [datetime] }
$Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
if ($Count -gt 5)
{
    $ChartDefinition = New-ExcelChartDefinition -XRange CreatedDateTime -YRange Count -Title "Successful Sign-Ins" -ChartType Line -NoLegend -Width 1200
    $Import | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Stats\LineCharts\Success.xlsx" -Append -WorksheetName "Line Chart" -AutoNameRange -ExcelChartDefinition $ChartDefinition
}

# Success (Map)
if (Test-Path "$OUTPUT_FOLDER\IpAddress\Success.txt")
{
    if ((Get-Item "$OUTPUT_FOLDER\IpAddress\Success.txt").Length -gt 0kb)
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
            if (!(Test-Connection -ComputerName ipinfo.io -Count 1 -Quiet))
            {
                Write-Host "[Error] ipinfo.io is NOT reachable. IP addresses cannot be checked via IPinfo API." -ForegroundColor Red
            }
            else
            {
                # Map IPs
                Get-Content "$OUTPUT_FOLDER\IpAddress\Success.txt" | & $IPinfo map | Out-File "$OUTPUT_FOLDER\IpAddress\IPinfo\Map_Success.txt"
            }
        }
    }
}

# Interrupted (Sign-Ins)
Write-Output "IPAddress" | Out-File "$OUTPUT_FOLDER\IpAddress\Interrupted.txt" -Encoding UTF8 # Header
Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -Delimiter "," | Where-Object { $_.Status -eq 'Interrupted' } | Select-Object -ExpandProperty IpAddress -Unique | Out-File "$OUTPUT_FOLDER\IpAddress\Interrupted.txt" -Append

# Authentication: Interrupted (Line Chart) --> Interrupted Sign-Ins per day
$Count = (Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -Delimiter "," | Where-Object { $_.Status -eq 'Interrupted' } | Measure-Object).Count

if ($Count -ge 5)
{
    $Import = Import-Csv "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -Delimiter "," | Where-Object { $_.Status -eq 'Interrupted' } | Group-Object{($_.CreatedDateTime -split "\s+")[0]} | Select-Object Count,@{Name='CreatedDateTime'; Expression={ $_.Values[0] }} | Sort-Object { $_.CreatedDateTime -as [datetime] }
    $ChartDefinition = New-ExcelChartDefinition -XRange CreatedDateTime -YRange Count -Title "Interrupted Sign-Ins" -ChartType Line -NoLegend -Width 1200
    $Import | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Stats\LineCharts\Interrupted.xlsx" -Append -WorksheetName "Line Chart" -AutoNameRange -ExcelChartDefinition $ChartDefinition
}

#############################################################################################################################################################################################

# Conditional Access

# Conditional Access Result: Success (Line Chart)
$Count = (Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -Delimiter "," | Where-Object { $_.ConditionalAccessStatus -eq 'Success' } | Measure-Object).Count

if ($Count -ge 10)
{
    $Import = Import-Csv "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -Delimiter "," | Where-Object { $_.ConditionalAccessStatus -eq 'Success' } | Group-Object{($_.CreatedDateTime -split "\s+")[0]} | Select-Object Count,@{Name='CreatedDateTime'; Expression={ $_.Values[0] }} | Sort-Object { $_.CreatedDateTime -as [datetime] }
    $ChartDefinition = New-ExcelChartDefinition -XRange CreatedDateTime -YRange Count -Title "Conditional Access Result: Success" -ChartType Line -NoLegend -Width 1200
    $Import | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Stats\LineCharts\ConditionalAccessResult-Success.xlsx" -Append -WorksheetName "Line Chart" -AutoNameRange -ExcelChartDefinition $ChartDefinition
}

# Conditional Access Result: Failure (Line Chart)
$Count = (Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -Delimiter "," | Where-Object { $_.ConditionalAccessStatus -eq 'Failure' } | Measure-Object).Count

if ($Count -ge 10)
{
    $Import = Import-Csv "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -Delimiter "," | Where-Object { $_.ConditionalAccessStatus -eq 'Failure' } | Group-Object{($_.CreatedDateTime -split "\s+")[0]} | Select-Object Count,@{Name='CreatedDateTime'; Expression={ $_.Values[0] }} | Sort-Object { $_.CreatedDateTime -as [datetime] }
    $ChartDefinition = New-ExcelChartDefinition -XRange CreatedDateTime -YRange Count -Title "Conditional Access Result: Failure" -ChartType Line -NoLegend -Width 1200
    $Import | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Stats\LineCharts\ConditionalAccessResult-Failure.xlsx" -Append -WorksheetName "Line Chart" -AutoNameRange -ExcelChartDefinition $ChartDefinition
}

# Conditional Access Result: Not applied (Line Chart)
$Count = (Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -Delimiter "," | Where-Object { $_.ConditionalAccessStatus -eq 'notApplied' } | Measure-Object).Count

if ($Count -ge 10)
{
    $Import = Import-Csv "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -Delimiter "," | Where-Object { $_.ConditionalAccessStatus -eq 'notApplied' } | Group-Object{($_.CreatedDateTime -split "\s+")[0]} | Select-Object Count,@{Name='CreatedDateTime'; Expression={ $_.Values[0] }} | Sort-Object { $_.CreatedDateTime -as [datetime] }
    $ChartDefinition = New-ExcelChartDefinition -XRange CreatedDateTime -YRange Count -Title "Conditional Access Result: Not applied" -ChartType Line -NoLegend -Width 1200
    $Import | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\Stats\LineCharts\ConditionalAccessResult-NotApplied.xlsx" -Append -WorksheetName "Line Chart" -AutoNameRange -ExcelChartDefinition $ChartDefinition
}

# Conditional Access (NOT Blocked)
Write-Output "IPAddress" | Out-File "$OUTPUT_FOLDER\IpAddress\ConditionalAccess.txt" -Encoding UTF8 # Header
Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -Delimiter "," | Where-Object { $_.Status -eq 'Success' } | Where-Object { $_.ConditionalAccessStatus -eq "notApplied" -or $_.ConditionalAccessStatus -eq "success" } | Select-Object -ExpandProperty IpAddress -Unique | & $IPinfo grepip -o | Out-File "$OUTPUT_FOLDER\IpAddress\ConditionalAccess.txt" -Append

# Conditional Access (Map)
if (Test-Path "$OUTPUT_FOLDER\IpAddress\ConditionalAccess.txt")
{
    if ((Get-Item "$OUTPUT_FOLDER\IpAddress\ConditionalAccess.txt").Length -gt 0kb)
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
            if (!(Test-Connection -ComputerName ipinfo.io -Count 1 -Quiet))
            {
                Write-Host "[Error] ipinfo.io is NOT reachable. IP addresses cannot be checked via IPinfo API." -ForegroundColor Red
            }
            else
            {
                # Map IPs
                Get-Content "$OUTPUT_FOLDER\IpAddress\ConditionalAccess.txt" | & $IPinfo map | Out-File "$OUTPUT_FOLDER\IpAddress\IPinfo\Map_ConditionalAccess.txt"
            }
        }
    }
}

# Conditional Access Status (Investigating Sign-Ins with CA applied)
# notApplied: No policy applied to the user and application during sign-in.
# success:    One or more conditional access policies applied to the user and application (but not necessarily the other conditions) during sign-in.
# failure:    The sign-in satisfied the user and application condition of at least one Conditional Access policy and grant controls are either not satisfied or set to block access.

# Note: Conditional Access policies are enforced after first-factor authentication is completed. Conditional Access isn't intended to be an organization's first line of defense for scenarios like denial-of-service (DoS) attacks, but it can use signals from these events to determine access.

# Impact Summary
# Total: The number of users or sign-ins during the time period where at least one of the selected policies was evaluated.
# Success: The number of users or sign-ins during the time period where the combined result of the selected policies was “Success” or “Report-only: Success”.
# Failure: The number of users or sign-ins during the time period where the result of at least one of the selected policies was “Failure” or “Report-only: Failure”.
# Not applied: The number of users or sign-ins during the time period where none of the selected policies applied.

#############################################################################################################################################################################################

# Very Risky Authentication (Microsoft Entra ID Premium P2 required)
$Count = (Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -Delimiter "," | Where-Object { $_.RiskLevelDuringSignIn -eq "high" } | Where-Object { $_.RiskState -eq "atRisk" } | Where-Object {($_.RiskLevelAggregated -eq "medium" -Or $_.RiskLevelAggregated -eq "high")} | Measure-Object).Count

if ($Count -ge 1)
{
    Write-Host "[Alert] Very Risky Authentication(s) detected ($Count)" -ForegroundColor Red
}

# Adversary-in-the-Middle (AitM) Phishing / MFA Attack [T1557]
# Note: "OfficeHome" is a pretty reliable application for detecting threat actors, in particular when the DeviceId is empty. --> Check for unusual IP address (outside the country, not typical for that user, etc.)
$Import = Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -Delimiter "," | Where-Object { $_.AppDisplayName -eq "OfficeHome" } | Where-Object { $_.DeviceId -eq "" } | Where-Object {($_.ErrorCode -eq "0" -or $_.ErrorCode -eq "50074" -or $_.ErrorCode -eq "50140" -or $_.ErrorCode -eq "53000")}
$Count = ($Import | Measure-Object).Count
$Users = ($Import | Select-Object UserId -Unique | Measure-Object).Count

# ApplicationId = 4765445b-32c6-49b0-83e6-1d93765276ca
# ClientAppUsed = Browser
# IsInteractive = True

if ($Count -ge 1)
{
    Write-Host "[Alert] Potential Adversary-in-the-Middle (AitM) Phishing Attack(s) detected ($Users credentials, $Count events)" -ForegroundColor Red
    New-Item "$OUTPUT_FOLDER\EntraSignInLogs\AiTM\CSV" -ItemType Directory -Force | Out-Null
    New-Item "$OUTPUT_FOLDER\EntraSignInLogs\AiTM\XLSX" -ItemType Directory -Force | Out-Null

    # CSV
    $Import | Export-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\AiTM\CSV\AiTM.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\EntraSignInLogs\AiTM\CSV\AiTM.csv")
    {
        if([int](& $xsv count "$OUTPUT_FOLDER\EntraSignInLogs\AiTM\CSV\AiTM.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\EntraSignInLogs\AiTM\CSV\AiTM.csv" -Delimiter "," | Sort-Object { $_.CreatedDateTime -as [datetime] } -Descending
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\AiTM\XLSX\AiTM.xlsx" -NoNumberConversion * -FreezePane 2,4 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "AiTM" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:AW1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-X and AA-AW
            $WorkSheet.Cells["A:X"].Style.HorizontalAlignment="Center"
            $WorkSheet.Cells["AA:AW"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting
            Add-ConditionalFormatting -Address $WorkSheet.Cells["F:F"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("4765445b-32c6-49b0-83e6-1d93765276ca",$F1)))' -BackgroundColor Red # ApplicationId
            Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("OfficeHome",$G1)))' -BackgroundColor Red # AppDisplayName
            Add-ConditionalFormatting -Address $WorkSheet.Cells["H:H"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("Browser",$H1)))' -BackgroundColor Red # ClientAppUsed
            Add-ConditionalFormatting -Address $WorkSheet.Cells["J:J"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("notApplied",$J1)))' -BackgroundColor Red # ConditionalAccessStatus
            Add-ConditionalFormatting -Address $WorkSheet.Cells["L:L"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("True",$L1)))' -BackgroundColor Red # IsInteractive
            Add-ConditionalFormatting -Address $WorkSheet.Cells["S:S"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("atRisk",$S1)))' -BackgroundColor Red # RiskState
            Add-ConditionalFormatting -Address $WorkSheet.Cells["X:X"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("0",$X1)))' -BackgroundColor Red # ErrorCode
            Add-ConditionalFormatting -Address $WorkSheet.Cells["X:X"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("50074",$X1)))' -BackgroundColor Red # ErrorCode
            Add-ConditionalFormatting -Address $WorkSheet.Cells["X:X"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("50140",$X1)))' -BackgroundColor Red # ErrorCode
            Add-ConditionalFormatting -Address $WorkSheet.Cells["X:X"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("53000",$X1)))' -BackgroundColor Red # ErrorCode

            # Iterating over the ASN-Blacklist HashTable
            foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
            {
                $ConditionValue = 'NOT(ISERROR(FIND("{0}",$AS1)))' -f $ASN
                Add-ConditionalFormatting -Address $WorkSheet.Cells["AS:AT"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
            }

            # Iterating over the Country-Blacklist HashTable
            foreach ($Country in $CountryBlacklist_HashTable.Keys) 
            {
                $ConditionValue = 'NOT(ISERROR(FIND("{0}",$AP1)))' -f $Country
                Add-ConditionalFormatting -Address $WorkSheet.Cells["AO:AP"] -WorkSheet $WorkSheet -RuleType 'Expression' -ConditionValue $ConditionValue -BackgroundColor Red
            }

            }
        }
    }

    # Hunt

    # CSV
    $Import | Group-Object UserId,UserPrincipalName,Country,"Country Name",ASN,OrgName,Region,City | Select-Object @{Name='UserId'; Expression={ $_.Values[0] }},@{Name='UserPrincipalName'; Expression={ $_.Values[1] }},@{Name='Country'; Expression={ $_.Values[2] }},@{Name='Country Name'; Expression={ $_.Values[3] }},@{Name='ASN'; Expression={ $_.Values[4] }},@{Name='OrgName'; Expression={ $_.Values[5] }},@{Name='Region'; Expression={ $_.Values[6] }},@{Name='City'; Expression={ $_.Values[7] }},Count | Sort-Object Count -Descending | Export-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\AiTM\CSV\AiTM_Hunt.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\EntraSignInLogs\AiTM\CSV\AiTM_Hunt.csv")
    {
        if([int](& $xsv count "$OUTPUT_FOLDER\EntraSignInLogs\AiTM\CSV\AiTM_Hunt.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\EntraSignInLogs\AiTM\CSV\AiTM_Hunt.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\AiTM\XLSX\AiTM_Hunt.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "AiTM_Hunt" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:I1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-I
            $WorkSheet.Cells["A:I"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting - AuthenticationProtocol
            Add-ConditionalFormatting -Address $WorkSheet.Cells["AK:AK"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("deviceCode",$AK1)))' -BackgroundColor Red # Device Code Authentication
        

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

# Device Code Phishing --> Detect Malicious OAuth Device Code Phishing
# https://login.microsoftonline.com/common/oauth2/devicecode?api-version=1.0

# Alert #1 - Identify Device Code Usage
$Import = Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -Delimiter "," | Where-Object { $_.AuthenticationProtocol -eq "deviceCode" }

$Count = ($Import | Measure-Object).Count
$Users = ($Import | Select-Object UserId -Unique | Measure-Object).Count

if ($Count -ge 1)
{
    Write-Host "[Alert] Potential Device Code Usage detected: deviceCode ($Users credentials, $Count events)" -ForegroundColor Red
    New-Item "$OUTPUT_FOLDER\EntraSignInLogs\DeviceCode\CSV" -ItemType Directory -Force | Out-Null
    New-Item "$OUTPUT_FOLDER\EntraSignInLogs\DeviceCode\XLSX" -ItemType Directory -Force | Out-Null

    # CSV
    $Import | Export-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\DeviceCode\CSV\DeviceCode-Alert1.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\EntraSignInLogs\DeviceCode\CSV\DeviceCode-Alert1.csv")
    {
        if([int](& $xsv count "$OUTPUT_FOLDER\EntraSignInLogs\DeviceCode\CSV\DeviceCode-Alert1.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\EntraSignInLogs\DeviceCode\CSV\DeviceCode-Alert1.csv" -Delimiter "," | Sort-Object { $_.CreatedDateTime -as [datetime] } -Descending
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\DeviceCode\XLSX\DeviceCode-Alert1.xlsx" -NoNumberConversion * -FreezePane 2,5 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Alert #1" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:AY1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-AY
            $WorkSheet.Cells["A:AY"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting - AuthenticationProtocol
            Add-ConditionalFormatting -Address $WorkSheet.Cells["AL:AL"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("deviceCode",$AL1)))' -BackgroundColor Red # Device Code Authentication
            }
        }
    }
}

# Alert #2 - AppId: 29d9ed98-a469-4536-ade2-f981bc1d605e // Microsoft Authentication Broker
$Import = Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -Delimiter "," | Where-Object { $_.AppId -eq "29d9ed98-a469-4536-ade2-f981bc1d605e" }

$Count = ($Import | Measure-Object).Count
$Users = ($Import | Select-Object UserId -Unique | Measure-Object).Count

if ($Count -ge 1)
{
    Write-Host "[Alert] Potential Device Code Usage detected: Microsoft Authentication Broker ($Users credentials, $Count events)" -ForegroundColor Yellow
    New-Item "$OUTPUT_FOLDER\EntraSignInLogs\DeviceCode\CSV" -ItemType Directory -Force | Out-Null
    New-Item "$OUTPUT_FOLDER\EntraSignInLogs\DeviceCode\XLSX" -ItemType Directory -Force | Out-Null

    # CSV
    $Import | Export-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\DeviceCode\CSV\DeviceCode-Alert2.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\EntraSignInLogs\DeviceCode\CSV\DeviceCode-Alert2.csv")
    {
        if([int](& $xsv count "$OUTPUT_FOLDER\EntraSignInLogs\DeviceCode\CSV\DeviceCode-Alert2.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\EntraSignInLogs\DeviceCode\CSV\DeviceCode-Alert2.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\DeviceCode\XLSX\DeviceCode-Alert2.xlsx" -NoNumberConversion * -FreezePane 2,5 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Alert #2" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:BO1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-BO
            $WorkSheet.Cells["A:BO"].Style.HorizontalAlignment="Center"
            }
        }
    }
}

# Alert #3 - ???
$Import = Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -Delimiter "," | Where-Object { $_.AppId -eq "29d9ed98-a469-4536-ade2-f981bc1d605e" } | Where-Object { $_.AuthenticationProtocol -eq "deviceCode" }

$Count = ($Import | Measure-Object).Count
$Users = ($Import | Select-Object UserId -Unique | Measure-Object).Count

if ($Count -ge 1)
{
    Write-Host "[Alert] Potential Device Code Authentication (PRT Phishing) detected ($Users account credentials, $Count events)" -ForegroundColor Red
    New-Item "$OUTPUT_FOLDER\EntraSignInLogs\DeviceCode\CSV" -ItemType Directory -Force | Out-Null
    New-Item "$OUTPUT_FOLDER\EntraSignInLogs\DeviceCode\XLSX" -ItemType Directory -Force | Out-Null

    # CSV
    $Import | Export-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\DeviceCode\CSV\DeviceCode-Alert3.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\EntraSignInLogs\DeviceCode\CSV\DeviceCode-Alert3.csv")
    {
        if([int](& $xsv count "$OUTPUT_FOLDER\EntraSignInLogs\DeviceCode\CSV\DeviceCode-Alert3.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\EntraSignInLogs\DeviceCode\CSV\DeviceCode-Alert3.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\DeviceCode\XLSX\DeviceCode-Alert3.xlsx" -NoNumberConversion * -FreezePane 2,5 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Alert #3" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:BO1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-BO
            $WorkSheet.Cells["A:BO"].Style.HorizontalAlignment="Center"
            }
        }
    }
}

# Alert #4 - ???
$Import = Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -Delimiter "," | Where-Object { $_.AppId -eq "29d9ed98-a469-4536-ade2-f981bc1d605e" } | Where-Object { $_.AdditionalDetails -eq "MFA requirement satisfied by claim in the token" }

$Count = ($Import | Measure-Object).Count
$Users = ($Import | Select-Object UserId -Unique | Measure-Object).Count

if ($Count -ge 1)
{
    Write-Host "[Alert] Potential Device Code Usage detected: Microsoft Authentication Broker + MFA requirement satisfied by claim in the token ($Users account credentials, $Count events)" -ForegroundColor Red
    New-Item "$OUTPUT_FOLDER\EntraSignInLogs\DeviceCode\CSV" -ItemType Directory -Force | Out-Null
    New-Item "$OUTPUT_FOLDER\EntraSignInLogs\DeviceCode\XLSX" -ItemType Directory -Force | Out-Null

    # CSV
    $Import | Export-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\DeviceCode\CSV\DeviceCode-Alert4.csv" -NoTypeInformation -Encoding UTF8

    # XLSX
    if (Test-Path "$OUTPUT_FOLDER\EntraSignInLogs\DeviceCode\CSV\DeviceCode-Alert4.csv")
    {
        if([int](& $xsv count "$OUTPUT_FOLDER\EntraSignInLogs\DeviceCode\CSV\DeviceCode-Alert4.csv") -gt 0)
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\EntraSignInLogs\DeviceCode\CSV\DeviceCode-Alert4.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\EntraSignInLogs\DeviceCode\XLSX\DeviceCode-Alert4.xlsx" -NoNumberConversion * -FreezePane 2,5 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Alert #4" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:BO1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-BO
            $WorkSheet.Cells["A:BO"].Style.HorizontalAlignment="Center"
            }
        }
    }
}

# TODO
# Successful or not?

# AppId: 29d9ed98-a469-4536-ade2-f981bc1d605e
# AppDisplayName: Microsoft Authentication Broker
# ClientAppUsed: Mobile Apps and Desktop clients
# AuthenticationProtocol: deviceCode
# AdditionalDetails: MFA requirement satisfied by claim in the token
# OriginalTransferMethod: deviceCodeFlow

# Alert #1 - Identify Device Code Usage
# AuthenticationProtocol: deviceCode

# Alert #2 - AADInternals
# AppId: 29d9ed98-a469-4536-ade2-f981bc1d605e

# Alert #3 - Abuse of Device Code Authentication (PRT Phishing)
# AppId: 29d9ed98-a469-4536-ade2-f981bc1d605e // Microsoft Authentication Broker
# AuthenticationProtocol: deviceCode

# Alert #4
# AppId: 29d9ed98-a469-4536-ade2-f981bc1d605e
# AdditionalDetails: MFA requirement satisfied by claim in the token

# Phishing with device code authentication
# Device Code Flow Abuse
# xxx

# https://microsoft.com/devicelogin --> https://login.microsoftonline.com/common/oauth2/deviceauth

# PRT = Primary Refresh Token

# Detection Methodology
# ClientAppUsed: Mobile Apps and Desktop clients
# AuthenticationProtocol: deviceCode
# AuthenticationRequirement: singleFactorAuthentication or multiFactorAuthentication
# AdditionalDetails: MFA requirement satisfied by claim in the token
# OriginalTransferMethod: deviceCodeFlow
# AppId: 29d9ed98-a469-4536-ade2-f981bc1d605e // Microsoft Authentication Broker

# https://twitter.com/ITguySoCal/status/1761184877406572834
# https://dirkjanm.io/phishing-for-microsoft-entra-primary-refresh-tokens/
# https://www.invictus-ir.com/news/do-not-use-the-get-mgauditlogsignin-for-your-investigations
# https://www.inversecos.com/2022/12/how-to-detect-malicious-oauth-device.html
# https://github.com/pushsecurity/saas-attacks/blob/main/techniques/device_code_phishing/examples/microsoft.md
# https://aadinternals.com/post/phishing/
# https://cloudbrothers.info/en/protect-users-device-code-flow-abuse/

# Detect MFASweep usage (Default Scan) --> xxx
# https://github.com/dafthack/MFASweep
# https://zolder.io/detecting-mfasweep-using-azure-sentinel/
# https://www.blackhillsinfosec.com/exploiting-mfa-inconsistencies-on-microsoft-services/
# https://www.splunk.com/en_us/blog/security/hunting-m365-invaders-blue-team-s-guide-to-initial-access-vectors.html
#
# This rule will trigger once MFASweep is used against an existing M365 account
# Tactics: InitialAccess
# TA0001
#
# AppId
# 1b730954-1685-4b74-9bfd-dac224a7b894 // Azure Active Directory PowerShell
# 1950a258-227b-4e31-a9cf-717495945fc2 // Microsoft Azure PowerShell
# 00000002-0000-0ff1-ce00-000000000000 // Office 365 Exchange Online
#
# ClientAppUsed
# Browser
# Exchange ActiveSync
# Mobile Apps and Desktop clients
# Exchange Web Services
#
# ResultType 0 means a successful login, while 50126 is a failed login attempt

# Device Registration Attack
# AppDisplayName: Microsoft Device Registration Client
# ResourceId: 01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9
# ResourceDisplayName: Device Registration Service

#############################################################################################################################################################################################

# Blacklisting

# Applications

# Create HashTable and import 'Application-Blacklist.csv'
$ApplicationBlacklist_HashTable = [ordered]@{}
if (Test-Path "$SCRIPT_DIR\Blacklists\Application-Blacklist.csv")
{
    if([int](& $xsv count "$SCRIPT_DIR\Blacklists\Application-Blacklist.csv") -gt 0)
    {
        Import-Csv "$SCRIPT_DIR\Blacklists\Application-Blacklist.csv" -Delimiter "," | ForEach-Object { $ApplicationBlacklist_HashTable[$_.AppId] = $_.AppDisplayName,$_.Severity }

        # Count Ingested Properties
        $Count = $ApplicationBlacklist_HashTable.Count
        Write-Output "[Info]  Initializing 'Application-Blacklist.csv' Lookup Table ($Count) ..."

        $Data = Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -Delimiter ","

        # Iterating over the HashTable
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

# ASN

# Create HashTable and import 'ASN-Blacklist.csv'
$AsnBlacklist_HashTable = [ordered]@{}
if (Test-Path "$SCRIPT_DIR\Blacklists\ASN-Blacklist.csv")
{
    if([int](& $xsv count "$SCRIPT_DIR\Blacklists\ASN-Blacklist.csv") -gt 0)
    {
        Import-Csv "$SCRIPT_DIR\Blacklists\ASN-Blacklist.csv" -Delimiter "," | ForEach-Object { $AsnBlacklist_HashTable[$_.ASN] = $_.OrgName,$_.Info }

        # Count Ingested Properties
        $Count = $AsnBlacklist_HashTable.Count
        Write-Output "[Info]  Initializing 'ASN-Blacklist.csv' Lookup Table ($Count) ..."

        $Data = Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -Delimiter ","

        # Iterating over the HashTable
        foreach ($ASN in $AsnBlacklist_HashTable.Keys) 
        {
            $Import = $Data | Where-Object { $_.ASN -eq "$ASN" }
            $Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
            if ($Count -gt 0)
            {
                $OrgName = $AsnBlacklist_HashTable["$ASN"][0]
                Write-Host "[Alert] Suspicious ASN detected: AS$ASN - $OrgName ($Count)" -ForegroundColor Red
            }
        }
    }
}

# Country

# Create HashTable and import 'Country-Blacklist.csv'
$CountryBlacklist_HashTable = [ordered]@{}
if (Test-Path "$SCRIPT_DIR\Blacklists\Country-Blacklist.csv")
{
    if([int](& $xsv count "$SCRIPT_DIR\Blacklists\Country-Blacklist.csv") -gt 0)
    {
        Import-Csv "$SCRIPT_DIR\Blacklists\Country-Blacklist.csv" -Delimiter "," | ForEach-Object { $CountryBlacklist_HashTable[$_."Country Name"] = $_.Country }

        # Count Ingested Properties
        $Count = $CountryBlacklist_HashTable.Count
        Write-Output "[Info]  Initializing 'Country-Blacklist.csv' Lookup Table ($Count) ..."

        $Data = Import-Csv -Path "$OUTPUT_FOLDER\EntraSignInLogs\CSV\Hunt.csv" -Delimiter ","

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

$EndTime_Analytics = (Get-Date)
$Time_Analytics = ($EndTime_Analytics-$StartTime_Analytics)
('EntraSignInLogs Analytics duration:       {0} h {1} min {2} sec' -f $Time_Analytics.Hours, $Time_Analytics.Minutes, $Time_Analytics.Seconds) >> "$OUTPUT_FOLDER\Stats.txt"

}

#endregion Analytics

#############################################################################################################################################################################################
#############################################################################################################################################################################################

# Main
Start-Processing
Get-IPLocation
Get-Stats
Get-Analytics

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
$MessageBody = "Status: Sign-In Logs Analysis completed."
$MessageTitle = "EntraSignInLogs-Analyzer.ps1 (https://lethal-forensics.com/)"
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
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQU9FzcTw6HuRskndwuhdN0xVHW
# fXOggiT/MIIFbzCCBFegAwIBAgIQSPyTtGBVlI02p8mKidaUFjANBgkqhkiG9w0B
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
# hkiG9w0BCQQxFgQUyGlmrihcO/NVRGfu4mjKv2XVZY4wDQYJKoZIhvcNAQEBBQAE
# ggIAbmVgvkxW/FGZQZWWCIEUJA4WglagdkJgU5Yux/9Umgzn7e/wEv6GklHcAi6/
# tqChydkfCOWD0PbbYSzKqeaIjNELJlCyS7cR3EQVqrhc22sbq6atxnUG1eSkZXHr
# Y1Qa6MtlSpTMWlNVHQsjB25RfBuPfHmNz6GpoueVv1Mw2MpiKu6Q3lBaYuZSg3Eu
# aA8dUC+fJBjs8tF0mqWxHZ9TfCXY3gEoC4as2eVmHah4p0MmfAB1bUeuOFy2tTwi
# ubIF1UORRfH6h0ozbuJdfJHtTzLX8A8/P9lEtxVqTNLsycV/vkYsw5rDWDDTSypK
# pPqztgm7fet9TrSHYtpdEs22fxm/4Q6d+gRaQoySfW3eXFsQLTwe4dUVbUyMCHZB
# KX0lQJfv6N9G82hYWlu9DbAGzq49buHQ/8jtJsS9jnl+4V8PeVEVeJRIaBIKe2z7
# Q35vjekBUVMqDORwPWcEACR6FuDpuIT2E0UU09K7ebhMBtWpcEnjoD7gqyM9NzRM
# 2nmfq6mqbJBGgQy6u5sa39lwY3jt71MN/S7g6mW2zQEiiml1NQE8oS5x1WaGEkDM
# mJhPNY3ZDs2hUqmCtab5mrK9RvrzGF4g/bZhl3v0wHewazkwGe+7D8KRG9QKisN/
# YRDvRcSEC2sRZhtkHEUnByqYpJc5IkRWR0TlNktww1XX1iyhggMiMIIDHgYJKoZI
# hvcNAQkGMYIDDzCCAwsCAQEwaTBVMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2Vj
# dGlnbyBMaW1pdGVkMSwwKgYDVQQDEyNTZWN0aWdvIFB1YmxpYyBUaW1lIFN0YW1w
# aW5nIENBIFIzNgIQOlJqLITOVeYdZfzMEtjpiTANBglghkgBZQMEAgIFAKB5MBgG
# CSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI1MDIyNDA2
# MDA0MlowPwYJKoZIhvcNAQkEMTIEMOgd3OngxlRjw1CnEOOURMu9FQlR/jIc9QEd
# RoUDv9ZMWEKId68BE8LXAhaHT+ug6jANBgkqhkiG9w0BAQEFAASCAgAG4N7W4VOj
# AKJ/GnGrlP8Et03QiDL4kQ2IakxxpH25FluPtgvilmrVBNH6qGU6UF6mFB0IThOR
# Kp89G0/vY90FxKc2kpTJP9TeQZRqijJB8Jux6UqPNiDiOgUaAkV1xTzK22J6up8V
# TG+LGBZGsXRwDWZBN9lsb0PCyTks7Y+lF70yLIH3X3trzo5hgoVhf1yWprwD58HP
# BeIzOgWiLVnu5KAAI+bhtVmA06EjpVw2E/GZiM5hQU1bNHg5d2CJd4uPbSCMp46w
# CBh5furSFAODSYO/zDKimwhamb+ddnLN625BijPnfV82Xt9pxxPfJqWXI02CrdNj
# xp5jSYz7zf4/Lh1HzzKNrNLg7bXt3UK02caNVf97OzyLxPhBCoGXb1BIjtRdU5wh
# s3quIszTjaVQucUphr7FEhRMY9uuW928g81NRPh6sTzvuFWs5iB+AJu/NtHsuZEm
# 445s/uTJlfQUm2fVE/+tHgpmJgo+/uwsCjUEi/JU/bbzB4OajceD63uYW6xKIuF5
# ggti9Rl0tkK+cq/0LW0GaAtxybVDz3Gtt3OeQGBot84d5JtBGyNHjUq60tvfKZOQ
# eRY83Jpi3YrTh1KVVM6W/0MWjTuXSHG0dhS/br0Yce/x4FHArHts4DBIkxrUw94M
# j+Pmtu98OlMc7Rn+5YFcTcdIUmtRPnONQQ==
# SIG # End signature block
