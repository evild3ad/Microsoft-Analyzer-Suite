# RiskyDetections-Analyzer
#
# @author:    Martin Willing
# @copyright: Copyright (c) 2024 Martin Willing. All rights reserved. Licensed under the MIT license.
# @contact:   Any feedback or suggestions are always welcome and much appreciated - mwilling@lethal-forensics.com
# @url:       https://lethal-forensics.com/
# @date:      2024-11-21
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
#
# Tested on Windows 10 Pro (x64) Version 22H2 (10.0.19045.5131) and PowerShell 5.1 (5.1.19041.5129)
# Tested on Windows 10 Pro (x64) Version 22H2 (10.0.19045.5131) and PowerShell 7.4.6
#
#
#############################################################################################################################################################################################
#############################################################################################################################################################################################

<#
.SYNOPSIS
  RiskyDetections-Analyzer - Automated Processing of 'RiskyDetections.csv' (Microsoft-Extractor-Suite by Invictus-IR)

.DESCRIPTION
  RiskyDetections-Analyzer.ps1 is a PowerShell script utilized to simplify the analysis of the Risk Detections from the Entra ID Identity Protection extracted via "Microsoft-Extractor-Suite" by Invictus Incident Response.

  https://github.com/invictus-ir/Microsoft-Extractor-Suite (Microsoft-Extractor-Suite v2.1.1)

  https://microsoft-365-extractor-suite.readthedocs.io/en/latest/functionality/GetUserInfo.html#retrieves-the-risky-detections

.PARAMETER OutputDir
  Specifies the output directory. Default is "$env:USERPROFILE\Desktop\RiskyDetections-Analyzer".

  Note: The subdirectory 'RiskyDetections-Analyzer' is automatically created.

.PARAMETER Path
  Specifies the path to the CSV-based input file (*-RiskyDetections.csv).

.EXAMPLE
  PS> .\RiskyDetections-Analyzer.ps1

.EXAMPLE
  PS> .\RiskyDetections-Analyzer.ps1 -Path "$env:USERPROFILE\Desktop\*-RiskyDetections.csv"

.EXAMPLE
  PS> .\RiskyDetections-Analyzer.ps1 -Path "H:\Microsoft-Extractor-Suite\*-RiskyDetections.csv" -OutputDir "H:\Microsoft-Analyzer-Suite"

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
    $script:OUTPUT_FOLDER = "$env:USERPROFILE\Desktop\RiskyDetections-Analyzer" # Default
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
        $script:OUTPUT_FOLDER = "$OutputDir\RiskyDetections-Analyzer" # Custom
    }
}

#endregion Declarations

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Header

# Windows Title
$DefaultWindowsTitle = $Host.UI.RawUI.WindowTitle
$Host.UI.RawUI.WindowTitle = "RiskyDetections-Analyzer - Automated Processing of 'RiskyDetections.csv' (Microsoft-Extractor-Suite by Invictus-IR)"

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
        $OpenFileDialog.Filter = "Risky Detections|*-RiskyDetections.csv|All Files (*.*)|*.*"
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
Write-Output "RiskyDetections-Analyzer - Automated Processing of 'RiskyDetections.csv'"
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

# Risky Detections include any identified suspicious actions related to user accounts in the directory.
# https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks

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

# Processing RiskyDetections.csv
Write-Output "[Info]  Processing RiskyDetections.csv ..."
New-Item "$OUTPUT_FOLDER\CSV" -ItemType Directory -Force | Out-Null
New-Item "$OUTPUT_FOLDER\XLSX" -ItemType Directory -Force | Out-Null

# Check Timestamp Format
$Timestamp = (Import-Csv -Path "$LogFile" -Delimiter "," | Select-Object ActivityDateTime -First 1).ActivityDateTime

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
$StartDate = (Import-Csv -Path "$LogFile" -Delimiter "," | Select-Object @{Name="ActivityDateTime";Expression={([DateTime]::ParseExact($_.ActivityDateTime, "$TimestampFormat", [cultureinfo]::InvariantCulture).ToString("yyyy-MM-dd HH:mm:ss"))}} | Sort-Object { $_.ActivityDateTime -as [datetime] } -Descending | Select-Object -Last 1).ActivityDateTime
$EndDate = (Import-Csv -Path "$LogFile" -Delimiter "," | Select-Object @{Name="ActivityDateTime";Expression={([DateTime]::ParseExact($_.ActivityDateTime, "$TimestampFormat", [cultureinfo]::InvariantCulture).ToString("yyyy-MM-dd HH:mm:ss"))}} | Sort-Object { $_.ActivityDateTime -as [datetime] } -Descending | Select-Object -First 1).ActivityDateTime
Write-Output "[Info]  Log data from $StartDate UTC until $EndDate UTC"

# CSV
# https://learn.microsoft.com/en-us/graph/api/resources/riskdetection?view=graph-rest-1.0
# https://github.com/microsoftgraph/microsoft-graph-docs-contrib/blob/main/api-reference/v1.0/resources/riskdetection.md
# https://learn.microsoft.com/en-us/powershell/module/Microsoft.Graph.Beta.Identity.SignIns/Get-MgBetaRiskDetection?view=graph-powershell-beta
$Data = Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Sort-Object { $_.ActivityDateTime -as [DateTime] } -Descending

$Results = @()
ForEach($Record in $Data)
{
    $AdditionalInfo = $Record.AdditionalInfo | ConvertFrom-Json

    $Line = [PSCustomObject]@{
    "Activity"                    = $Record.Activity # Indicates the activity type the detected risk is linked to.
    "ActivityDateTime"            = ($Record | Select-Object @{Name="ActivityDateTime";Expression={([DateTime]::ParseExact($_.ActivityDateTime, "$TimestampFormat", [cultureinfo]::InvariantCulture).ToString("yyyy-MM-dd HH:mm:ss"))}}).ActivityDateTime # Date and time that the risky activity occurred (UTC). 
    "DetectedDateTime"            = ($Record | Select-Object @{Name="DetectedDateTime";Expression={([DateTime]::ParseExact($_.DetectedDateTime, "$TimestampFormat", [cultureinfo]::InvariantCulture).ToString("yyyy-MM-dd HH:mm:ss"))}}).DetectedDateTime # Date and time that the risk was detected.
    "LastUpdatedDateTime"         = ($Record | Select-Object @{Name="LastUpdatedDateTime";Expression={([DateTime]::ParseExact($_.LastUpdatedDateTime, "$TimestampFormat", [cultureinfo]::InvariantCulture).ToString("yyyy-MM-dd HH:mm:ss"))}}).LastUpdatedDateTime # Date and time that the risk detection was last updated.
    "UserPrincipalName"           = $Record.UserPrincipalName # The user principal name (UPN) of the user.
    "UserDisplayName"             = $Record.UserDisplayName # The user principal name (UPN) of the user.
    "UserId"                      = $Record.UserId # Unique ID of the user.
    "mitreTechniques"             = ($AdditionalInfo | Where-Object {$_.Key -eq "mitreTechniques"}).Value
    "RiskDetail"                  = $Record.RiskDetail # Details of the detected risk.
    "RiskEventType"               = $Record.RiskEventType # The type of risk event detected.
    "RiskLevel"                   = $Record.RiskLevel # Level of the detected risk.
    "RiskReasons"                 = ($AdditionalInfo | Where-Object {$_.Key -eq "riskReasons"}).Value -join ","
    "RiskState"                   = $Record.RiskState # The state of a detected risky user or sign-in.
    "IPAddress"                   = $Record.IPAddress # Provides the IP address of the client from where the risk occurred.
    "City"                        = $Record.City # Location of the sign-in.
    "CountryOrRegion"             = $Record.CountryOrRegion # Location of the sign-in.
    "State"                       = $Record.State # Location of the sign-in.
    "DetectionTimingType"         = $Record.DetectionTimingType # Timing of the detected risk (real-time/offline).
    "Source"                      = $Record.Source # Source of the risk detection.
    "TokenIssuerType"             = $Record.TokenIssuerType # Indicates the type of token issuer for the detected sign-in risk. 
    "UserAgent"                   = ($AdditionalInfo | Where-Object {$_.Key -eq "userAgent"}).Value
    "AlertUrl"                    = ($AdditionalInfo | Where-Object {$_.Key -eq "alertUrl"}).Value # e.g. MicrosoftCloudAppSecurity
    "relatedEventTimeInUtc"       = ($AdditionalInfo | Where-Object {$_.Key -eq "relatedEventTimeInUtc"}).Value
    "relatedUserAgent"            = ($AdditionalInfo | Where-Object {$_.Key -eq "relatedUserAgent"}).Value
    "DeviceInformation"           = ($AdditionalInfo | Where-Object {$_.Key -eq "deviceInformation"}).Value
    "relatedLocation_clientIP"    = ($AdditionalInfo | Where-Object {$_.Key -eq "relatedLocation"}).Value | Select-Object -ExpandProperty clientIP
    "relatedLocation_latitude"    = ($AdditionalInfo | Where-Object {$_.Key -eq "relatedLocation"}).Value | Select-Object -ExpandProperty latitude
    "relatedLocation_longitude"   = ($AdditionalInfo | Where-Object {$_.Key -eq "relatedLocation"}).Value | Select-Object -ExpandProperty longitude
    "relatedLocation_asn"         = ($AdditionalInfo | Where-Object {$_.Key -eq "relatedLocation"}).Value | Select-Object -ExpandProperty asn
    "relatedLocation_countryCode" = ($AdditionalInfo | Where-Object {$_.Key -eq "relatedLocation"}).Value | Select-Object -ExpandProperty countryCode
    "relatedLocation_countryName" = ($AdditionalInfo | Where-Object {$_.Key -eq "relatedLocation"}).Value | Select-Object -ExpandProperty countryName
    "relatedLocation_state"       = ($AdditionalInfo | Where-Object {$_.Key -eq "relatedLocation"}).Value | Select-Object -ExpandProperty state
    "relatedLocation_city"        = ($AdditionalInfo | Where-Object {$_.Key -eq "relatedLocation"}).Value | Select-Object -ExpandProperty city
    "LastActivityTimeInUtc"       = ($AdditionalInfo | Where-Object {$_.Key -eq "lastActivityTimeInUtc"}).Value
    "MalwareName"                 = ($AdditionalInfo | Where-Object {$_.Key -eq "malwareName"}).Value
    "ClientLocation"              = ($AdditionalInfo | Where-Object {$_.Key -eq "clientLocation"}).Value
    "ClientIp"                    = ($AdditionalInfo | Where-Object {$_.Key -eq "clientIp"}).Value
    "Id"                          = $Record.Id # Unique ID of the risk event.
    "CorrelationId"               = $Record.CorrelationId # Correlation ID of the sign-in associated with the risk detection. 
    "RequestId"                   = $Record.RequestId # Request ID of the sign-in associated with the risk detection. This property is null if the risk detection is not associated with a sign-in.
    "AdditionalProperties"        = $Record.AdditionalProperties # Empty
    }

    $Results += $Line
}

$Results | Export-Csv -Path "$OUTPUT_FOLDER\CSV\RiskyDetections.csv" -NoTypeInformation -Encoding UTF8

# XLSX
if (Get-Module -ListAvailable -Name ImportExcel)
{
    if (Test-Path "$OUTPUT_FOLDER\CSV\RiskyDetections.csv")
    {
        if(!([String]::IsNullOrWhiteSpace((Get-Content "$OUTPUT_FOLDER\CSV\RiskyDetections.csv"))))
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\CSV\RiskyDetections.csv" -Delimiter "," -Encoding UTF8
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\XLSX\RiskyDetections.xlsx" -NoNumberConversion * -FreezePane 2,6 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Risky Detections" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(255,220,0)
            Set-Format -Address $WorkSheet.Cells["A1:AO1"] -BackgroundColor $BackgroundColor -FontColor Black
            # HorizontalAlignment "Center" of columns A-AO
            $WorkSheet.Cells["A:AO"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting - MITRE ATT&CK Techniques
            Add-ConditionalFormatting -Address $WorkSheet.Cells["H:H"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("T1110.001",$H1)))' -BackgroundColor Red # Brute Force: Password Guessing --> https://attack.mitre.org/techniques/T1110/001/
            Add-ConditionalFormatting -Address $WorkSheet.Cells["H:H"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("T1110.003",$H1)))' -BackgroundColor Red # Brute Force: Password Spraying --> https://attack.mitre.org/techniques/T1110/003/
            Add-ConditionalFormatting -Address $WorkSheet.Cells["H:H"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("T1114.003",$H1)))' -BackgroundColor Red # Email Collection: Email Forwarding Rule --> https://attack.mitre.org/techniques/T1114/003/
            Add-ConditionalFormatting -Address $WorkSheet.Cells["H:H"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("T1539",$H1)))' -BackgroundColor Red # Steal Web Session Cookie --> https://attack.mitre.org/techniques/T1539/
            Add-ConditionalFormatting -Address $WorkSheet.Cells["H:H"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("T1564.008",$H1)))' -BackgroundColor Red # Hide Artifacts: Email Hiding Rules --> https://attack.mitre.org/techniques/T1564/008/
            Add-ConditionalFormatting -Address $WorkSheet.Cells["H:H"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("T1589.001",$H1)))' -BackgroundColor Red # Gather Victim Identity Information: Credentials --> https://attack.mitre.org/techniques/T1589/001/
            # ConditionalFormatting - RiskEventType
            Add-ConditionalFormatting -Address $WorkSheet.Cells["J:J"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("maliciousIPAddress",$J1)))' -BackgroundColor Red
            Add-ConditionalFormatting -Address $WorkSheet.Cells["J:J"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("mcasSuspiciousInboxManipulationRules",$J1)))' -BackgroundColor Red
            Add-ConditionalFormatting -Address $WorkSheet.Cells["J:J"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("nationStateIP",$J1)))' -BackgroundColor Red
            Add-ConditionalFormatting -Address $WorkSheet.Cells["J:J"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("passwordSpray",$J1)))' -BackgroundColor Red
            # ConditionalFormatting - RiskLevel
            Add-ConditionalFormatting -Address $WorkSheet.Cells["K:K"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("high",$K1)))' -BackgroundColor Red
            $Orange = [System.Drawing.Color]::FromArgb(255,192,0)
            Add-ConditionalFormatting -Address $WorkSheet.Cells["K:K"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("medium",$K1)))' -BackgroundColor $Orange
            Add-ConditionalFormatting -Address $WorkSheet.Cells["K:K"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("low",$K1)))' -BackgroundColor Yellow
            $Green = [System.Drawing.Color]::FromArgb(0,176,80)
            Add-ConditionalFormatting -Address $WorkSheet.Cells["K:K"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("none",$K1)))' -BackgroundColor $Green
            # ConditionalFormatting - RiskState
            Add-ConditionalFormatting -Address $WorkSheet.Cells["M:M"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("atRisk",$M1)))' -BackgroundColor Red
            }
        }
    }
}
else
{
    Write-Host "[Error] PowerShell module 'ImportExcel' NOT found." -ForegroundColor Red
}

# Count Risky Detections
$Count = (Import-Csv -Path "$LogFile" -Delimiter "," | Measure-Object).Count
$RiskyDetections = '{0:N0}' -f $Count

# Count Users
$Count = (Import-Csv -Path "$LogFile" -Delimiter "," | Select-Object UserId -Unique | Measure-Object).Count
$Users = '{0:N0}' -f $Count

Write-Output "[Info]  $RiskyDetections Risky Detection(s) found ($Users Users)"

# Stats
New-Item "$OUTPUT_FOLDER\Stats\CSV" -ItemType Directory -Force | Out-Null
New-Item "$OUTPUT_FOLDER\Stats\XLSX" -ItemType Directory -Force | Out-Null

# Activity (Stats)
$Total = (Import-Csv -Path "$OUTPUT_FOLDER\CSV\RiskyDetections.csv" -Delimiter "," | Select-Object Activity | Measure-Object).Count
Import-Csv -Path "$OUTPUT_FOLDER\CSV\RiskyDetections.csv" -Delimiter "," -Encoding UTF8 | Group-Object Activity | Select-Object @{Name='Activity'; Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending | Export-Csv -Path "$OUTPUT_FOLDER\Stats\CSV\Activity.csv" -NoTypeInformation -Encoding UTF8

# XLSX
if (Test-Path "$OUTPUT_FOLDER\Stats\CSV\Activity.csv")
{
    if(!([String]::IsNullOrWhiteSpace((Get-Content "$LogFile"))))
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\Stats\CSV\Activity.csv" -Delimiter "," -Encoding UTF8
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Stats\XLSX\Activity.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Activity" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        $BackgroundColor = [System.Drawing.Color]::FromArgb(255,220,0)
        Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor Black
        # HorizontalAlignment "Center" of columns A-C
        $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
        }
    }
}

# DetectionTimingType (Stats)
$Total = (Import-Csv -Path "$OUTPUT_FOLDER\CSV\RiskyDetections.csv" -Delimiter "," | Select-Object DetectionTimingType | Measure-Object).Count
Import-Csv -Path "$OUTPUT_FOLDER\CSV\RiskyDetections.csv" -Delimiter "," -Encoding UTF8 | Group-Object DetectionTimingType | Select-Object @{Name='DetectionTimingType'; Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending | Export-Csv -Path "$OUTPUT_FOLDER\Stats\CSV\DetectionTimingType.csv" -NoTypeInformation -Encoding UTF8

# XLSX
if (Test-Path "$OUTPUT_FOLDER\Stats\CSV\DetectionTimingType.csv")
{
    if(!([String]::IsNullOrWhiteSpace((Get-Content "$LogFile"))))
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\Stats\CSV\DetectionTimingType.csv" -Delimiter "," -Encoding UTF8
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Stats\XLSX\DetectionTimingType.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "DetectionTimingType" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        $BackgroundColor = [System.Drawing.Color]::FromArgb(255,220,0)
        Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor Black
        # HorizontalAlignment "Center" of columns A-C
        $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
        }
    }
}

# MITRE ATT&CK Techniques (Stats)
# https://attack.mitre.org/matrices/enterprise/cloud/azuread/
# https://attack.mitre.org/matrices/enterprise/cloud/office365/
$Total = (Import-Csv -Path "$OUTPUT_FOLDER\CSV\RiskyDetections.csv" -Delimiter "," | Select-Object mitreTechniques | Measure-Object).Count
Import-Csv -Path "$OUTPUT_FOLDER\CSV\RiskyDetections.csv" -Delimiter "," -Encoding UTF8 | Group-Object mitreTechniques | Select-Object @{Name='mitreTechniques'; Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending | Export-Csv -Path "$OUTPUT_FOLDER\Stats\CSV\mitreTechniques.csv" -NoTypeInformation -Encoding UTF8

# XLSX
if (Test-Path "$OUTPUT_FOLDER\Stats\CSV\mitreTechniques.csv")
{
    if(!([String]::IsNullOrWhiteSpace((Get-Content "$LogFile"))))
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\Stats\CSV\mitreTechniques.csv" -Delimiter "," -Encoding UTF8
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Stats\XLSX\mitreTechniques.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "MITRE ATT&CK" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        $BackgroundColor = [System.Drawing.Color]::FromArgb(255,220,0)
        Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor Black
        # HorizontalAlignment "Center" of columns B-C
        $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
        # ConditionalFormatting
        Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("T1114.003",$A1)))' -BackgroundColor Red # Email Collection: Email Forwarding Rule --> https://attack.mitre.org/techniques/T1114/003/
        Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("T1539",$A1)))' -BackgroundColor Red # Steal Web Session Cookie --> https://attack.mitre.org/techniques/T1539/
        Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("T1564.008",$A1)))' -BackgroundColor Red # Hide Artifacts: Email Hiding Rules --> https://attack.mitre.org/techniques/T1564/008/
        Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("T1589.001",$A1)))' -BackgroundColor Red # Gather Victim Identity Information: Credentials --> https://attack.mitre.org/techniques/T1589/001/
        }
    }
}

# T1078     - Valid Accounts                                  --> https://attack.mitre.org/techniques/T1078/
# T1078.004 - Valid Accounts: Cloud Accounts                  --> https://attack.mitre.org/techniques/T1078/004/
# T1090.003 - Proxy: Multi-hop Proxy                          --> https://attack.mitre.org/techniques/T1090/003/
# T1110.001 - Brute Force: Password Guessing                  --> https://attack.mitre.org/techniques/T1110/001/
# T1110.003 - Brute Force: Password Spraying                  --> https://attack.mitre.org/techniques/T1110/003/
# T1114.003 - Email Collection: Email Forwarding Rule         --> https://attack.mitre.org/techniques/T1114/003/
# T1539     - Steal Web Session Cookie                        --> https://attack.mitre.org/techniques/T1539/
# T1564.008 - Hide Artifacts: Email Hiding Rules              --> https://attack.mitre.org/techniques/T1564/008/
# T1589.001 - Gather Victim Identity Information: Credentials --> https://attack.mitre.org/techniques/T1589/001/

# RiskEventType (Stats)
$Total = (Import-Csv -Path "$OUTPUT_FOLDER\CSV\RiskyDetections.csv" -Delimiter "," | Select-Object RiskEventType | Measure-Object).Count
Import-Csv -Path "$OUTPUT_FOLDER\CSV\RiskyDetections.csv" -Delimiter "," -Encoding UTF8 | Group-Object RiskEventType | Select-Object @{Name='RiskEventType'; Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending | Export-Csv -Path "$OUTPUT_FOLDER\Stats\CSV\RiskEventType.csv" -NoTypeInformation -Encoding UTF8

# XLSX
if (Test-Path "$OUTPUT_FOLDER\Stats\CSV\RiskEventType.csv")
{
    if(!([String]::IsNullOrWhiteSpace((Get-Content "$LogFile"))))
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\Stats\CSV\RiskEventType.csv" -Delimiter "," -Encoding UTF8
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Stats\XLSX\RiskEventType.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "RiskEventType" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        $BackgroundColor = [System.Drawing.Color]::FromArgb(255,220,0)
        Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor Black
        # HorizontalAlignment "Center" of columns A-C
        $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
        # ConditionalFormatting
        Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("maliciousIPAddress",$A1)))' -BackgroundColor Red
        Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("mcasSuspiciousInboxManipulationRules",$A1)))' -BackgroundColor Red
        Add-ConditionalFormatting -Address $WorkSheet.Cells["A:C"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("passwordSpray",$A1)))' -BackgroundColor Red
        }
    }
}

# RiskLevel (Stats)
# Note: hidden --> Microsoft Entra ID Premium P2 required.
$Total = (Import-Csv -Path "$OUTPUT_FOLDER\CSV\RiskyDetections.csv" -Delimiter "," | Select-Object RiskLevel | Measure-Object).Count
Import-Csv -Path "$OUTPUT_FOLDER\CSV\RiskyDetections.csv" -Delimiter "," -Encoding UTF8 | Group-Object RiskLevel | Select-Object @{Name='RiskLevel'; Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending | Export-Csv -Path "$OUTPUT_FOLDER\Stats\CSV\RiskLevel.csv" -NoTypeInformation -Encoding UTF8

# XLSX
if (Test-Path "$OUTPUT_FOLDER\Stats\CSV\RiskLevel.csv")
{
    if(!([String]::IsNullOrWhiteSpace((Get-Content "$LogFile"))))
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\Stats\CSV\RiskLevel.csv" -Delimiter "," -Encoding UTF8
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Stats\XLSX\RiskLevel.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "RiskLevel" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        $BackgroundColor = [System.Drawing.Color]::FromArgb(255,220,0)
        Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor Black
        # HorizontalAlignment "Center" of columns A-C
        $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
        # ConditionalFormatting - RiskLevel
        Add-ConditionalFormatting -Address $WorkSheet.Cells["A:A"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("high",$A1)))' -BackgroundColor Red
        $Orange = [System.Drawing.Color]::FromArgb(255,192,0)
        Add-ConditionalFormatting -Address $WorkSheet.Cells["A:A"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("medium",$A1)))' -BackgroundColor $Orange
        Add-ConditionalFormatting -Address $WorkSheet.Cells["A:A"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("low",$A1)))' -BackgroundColor Yellow
        $Green = [System.Drawing.Color]::FromArgb(0,176,80)
        Add-ConditionalFormatting -Address $WorkSheet.Cells["A:A"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("none",$A1)))' -BackgroundColor $Green
        }
    }
}

# RiskDetail (Stats)
# Note: hidden --> Microsoft Entra ID Premium P2 required.
$Total = (Import-Csv -Path "$OUTPUT_FOLDER\CSV\RiskyDetections.csv" -Delimiter "," | Select-Object RiskDetail | Measure-Object).Count
Import-Csv -Path "$OUTPUT_FOLDER\CSV\RiskyDetections.csv" -Delimiter "," -Encoding UTF8 | Group-Object RiskDetail | Select-Object @{Name='RiskDetail'; Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending | Export-Csv -Path "$OUTPUT_FOLDER\Stats\CSV\RiskDetail.csv" -NoTypeInformation -Encoding UTF8

# XLSX
if (Test-Path "$OUTPUT_FOLDER\Stats\CSV\RiskDetail.csv")
{
    if(!([String]::IsNullOrWhiteSpace((Get-Content "$LogFile"))))
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\Stats\CSV\RiskDetail.csv" -Delimiter "," -Encoding UTF8
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Stats\XLSX\RiskDetail.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "RiskDetail" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        $BackgroundColor = [System.Drawing.Color]::FromArgb(255,220,0)
        Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor Black
        # HorizontalAlignment "Center" of columns A-C
        $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
        }
    }
}

# RiskReasons (Stats)
$Total = (Import-Csv -Path "$OUTPUT_FOLDER\CSV\RiskyDetections.csv" -Delimiter "," | Select-Object RiskReasons | Measure-Object).Count
Import-Csv -Path "$OUTPUT_FOLDER\CSV\RiskyDetections.csv" -Delimiter "," -Encoding UTF8 | Group-Object RiskReasons | Select-Object @{Name='RiskReasons'; Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending | Export-Csv -Path "$OUTPUT_FOLDER\Stats\CSV\RiskReasons.csv" -NoTypeInformation -Encoding UTF8

# XLSX
if (Test-Path "$OUTPUT_FOLDER\Stats\CSV\RiskReasons.csv")
{
    if(!([String]::IsNullOrWhiteSpace((Get-Content "$LogFile"))))
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\Stats\CSV\RiskReasons.csv" -Delimiter "," -Encoding UTF8
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Stats\XLSX\RiskReasons.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "RiskReasons" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        $BackgroundColor = [System.Drawing.Color]::FromArgb(255,220,0)
        Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor Black
        # HorizontalAlignment "Center" of columns B-C
        $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"

        }
    }
}

# RiskState (Stats)
$Total = (Import-Csv -Path "$OUTPUT_FOLDER\CSV\RiskyDetections.csv" -Delimiter "," | Select-Object RiskState | Measure-Object).Count
Import-Csv -Path "$OUTPUT_FOLDER\CSV\RiskyDetections.csv" -Delimiter "," -Encoding UTF8 | Group-Object RiskState | Select-Object @{Name='RiskState'; Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending | Export-Csv -Path "$OUTPUT_FOLDER\Stats\CSV\RiskState.csv" -NoTypeInformation -Encoding UTF8

# XLSX
if (Test-Path "$OUTPUT_FOLDER\Stats\CSV\RiskState.csv")
{
    if(!([String]::IsNullOrWhiteSpace((Get-Content "$LogFile"))))
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\Stats\CSV\RiskState.csv" -Delimiter "," -Encoding UTF8
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Stats\XLSX\RiskState.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "RiskState" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        $BackgroundColor = [System.Drawing.Color]::FromArgb(255,220,0)
        Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor Black
        # HorizontalAlignment "Center" of columns A-C
        $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"

        }
    }
}

# Source (Stats)
$Total = (Import-Csv -Path "$OUTPUT_FOLDER\CSV\RiskyDetections.csv" -Delimiter "," | Select-Object Source | Measure-Object).Count
Import-Csv -Path "$OUTPUT_FOLDER\CSV\RiskyDetections.csv" -Delimiter "," -Encoding UTF8 | Group-Object Source | Select-Object @{Name='Source'; Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending | Export-Csv -Path "$OUTPUT_FOLDER\Stats\CSV\Source.csv" -NoTypeInformation -Encoding UTF8

# XLSX
if (Test-Path "$OUTPUT_FOLDER\Stats\CSV\Source.csv")
{
    if(!([String]::IsNullOrWhiteSpace((Get-Content "$LogFile"))))
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\Stats\CSV\Source.csv" -Delimiter "," -Encoding UTF8
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Stats\XLSX\Source.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Source" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        $BackgroundColor = [System.Drawing.Color]::FromArgb(255,220,0)
        Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor Black
        # HorizontalAlignment "Center" of columns A-C
        $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
        }
    }
}

# UserAgent (Stats)
$Total = (Import-Csv -Path "$OUTPUT_FOLDER\CSV\RiskyDetections.csv" -Delimiter "," | Select-Object UserAgent | Measure-Object).Count
Import-Csv -Path "$OUTPUT_FOLDER\CSV\RiskyDetections.csv" -Delimiter "," -Encoding UTF8 | Group-Object UserAgent | Select-Object @{Name='UserAgent'; Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending | Export-Csv -Path "$OUTPUT_FOLDER\Stats\CSV\UserAgent.csv" -NoTypeInformation -Encoding UTF8

# XLSX
if (Test-Path "$OUTPUT_FOLDER\Stats\CSV\UserAgent.csv")
{
    if(!([String]::IsNullOrWhiteSpace((Get-Content "$LogFile"))))
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\Stats\CSV\UserAgent.csv" -Delimiter "," -Encoding UTF8
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Stats\XLSX\UserAgent.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "UserAgent" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        $BackgroundColor = [System.Drawing.Color]::FromArgb(255,220,0)
        Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor Black
        # HorizontalAlignment "Center" of columns B-C
        $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
        }
    }
}

# Line Charts
New-Item "$OUTPUT_FOLDER\Stats\XLSX\LineCharts" -ItemType Directory -Force | Out-Null

# Risk Detections (Line Chart) --> Risk Detections per day
$Import = Import-Csv "$OUTPUT_FOLDER\CSV\RiskyDetections.csv" -Delimiter "," | Group-Object{($_.ActivityDateTime -split "\s+")[0]} | Select-Object Count,@{Name='ActivityDateTime'; Expression={ $_.Values[0] }} | Sort-Object { $_.ActivityDateTime -as [datetime] }
$ChartDefinition = New-ExcelChartDefinition -XRange ActivityDateTime -YRange Count -Title "Risk Detections" -ChartType Line -NoLegend -Width 1200
$Import | Export-Excel -Path "$OUTPUT_FOLDER\Stats\XLSX\LineCharts\RiskDetections.xlsx" -Append -WorksheetName "Line Chart" -AutoNameRange -ExcelChartDefinition $ChartDefinition
 
# Risky Detections Count by User
$Total = (Import-Csv -Path "$OUTPUT_FOLDER\CSV\RiskyDetections.csv" -Delimiter "," | Select-Object UserId | Measure-Object).Count
Import-Csv "$OUTPUT_FOLDER\CSV\RiskyDetections.csv" -Delimiter "," | Group-Object UserPrincipalName,UserId | Select-Object @{Name='UserPrincipalName'; Expression={ $_.Values[0] }},@{Name='UserId'; Expression={ $_.Values[1] }},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending | Export-Csv -Path "$OUTPUT_FOLDER\Stats\CSV\UserPrincipalName.csv" -NoTypeInformation -Encoding UTF8

# XLSX
if (Test-Path "$OUTPUT_FOLDER\Stats\CSV\UserPrincipalName.csv")
{
    if(!([String]::IsNullOrWhiteSpace((Get-Content "$LogFile"))))
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\Stats\CSV\UserPrincipalName.csv" -Delimiter "," -Encoding UTF8
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Stats\XLSX\UserPrincipalName.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "UserPrincipalName" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        $BackgroundColor = [System.Drawing.Color]::FromArgb(255,220,0)
        Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor Black
        # HorizontalAlignment "Center" of columns B-D
        $WorkSheet.Cells["B:D"].Style.HorizontalAlignment="Center"
        }
    }
}

# Number of Risky Users with Risk Level "High" (Last 7 days)
$Date = (Get-Date).AddDays(-7)
$Count = (Import-Csv -Path "$OUTPUT_FOLDER\CSV\RiskyDetections.csv" -Delimiter "," | Where-Object -FilterScript {[DateTime]::Parse($_.ActivityDateTime) -gt $Date}  | Where-Object { $_.RiskLevel -eq "high" } | Measure-Object).Count
if ($Count -gt 0)
{
    $HighRiskUsers = '{0:N0}' -f $Count
    Write-Host "[Alert] Number of High Risk Users (Last 7 days): $HighRiskUsers" -ForegroundColor Red
}

# Number of Risky Users with Risk Level "High" (Last 30 days)
$Date = (Get-Date).AddDays(-30)
$Count = (Import-Csv -Path "$OUTPUT_FOLDER\CSV\RiskyDetections.csv" -Delimiter "," | Where-Object -FilterScript {[DateTime]::Parse($_.ActivityDateTime) -gt $Date}  | Where-Object { $_.RiskLevel -eq "high" } | Measure-Object).Count
if ($Count -gt 0)
{
    $HighRiskUsers = '{0:N0}' -f $Count
    Write-Host "[Alert] Number of High Risk Users (Last 30 days): $HighRiskUsers" -ForegroundColor Red
}

# Number of Risky Users with Risk Level "High" (Last 90 days)
$Date = (Get-Date).AddDays(-90)
$Count = (Import-Csv -Path "$OUTPUT_FOLDER\CSV\RiskyDetections.csv" -Delimiter "," | Where-Object -FilterScript {[DateTime]::Parse($_.ActivityDateTime) -gt $Date}  | Where-Object { $_.RiskLevel -eq "high" } | Measure-Object).Count
if ($Count -gt 0)
{
    $HighRiskUsers = '{0:N0}' -f $Count
    Write-Host "[Alert] Number of High Risk Users (Last 90 days): $HighRiskUsers" -ForegroundColor Red
}

# Number of Risky Users with Risk Level "High" (Past 6 months)
$Date = (Get-Date).AddDays(-180)
$Count = (Import-Csv -Path "$OUTPUT_FOLDER\CSV\RiskyDetections.csv" -Delimiter "," | Where-Object -FilterScript {[DateTime]::Parse($_.ActivityDateTime) -gt $Date}  | Where-Object { $_.RiskLevel -eq "high" } | Measure-Object).Count
if ($Count -gt 0)
{
    $HighRiskUsers = '{0:N0}' -f $Count
    Write-Host "[Alert] Number of High Risk Users (Past 6 months): $HighRiskUsers" -ForegroundColor Red
}

# Number of Risky Users with Risk Level "High" (Past 12 months)
$Date = (Get-Date).AddDays(-360)
$Count = (Import-Csv -Path "$OUTPUT_FOLDER\CSV\RiskyDetections.csv" -Delimiter "," | Where-Object -FilterScript {[DateTime]::Parse($_.ActivityDateTime) -gt $Date}  | Where-Object { $_.RiskLevel -eq "high" } | Measure-Object).Count

if ($Count -gt 0)
{
    $HighRiskUsers = '{0:N0}' -f $Count
    Write-Host "[Alert] Number of High Risk Users (Past 12 months): $HighRiskUsers" -ForegroundColor Red
}
else
{
    Write-Host "[Info]  Number of High Risk Users (Past 12 months): 0" -ForegroundColor Green
}

# RiskState
$Import = Import-Csv -Path "$OUTPUT_FOLDER\CSV\RiskyDetections.csv" -Delimiter "," | Where-Object { $_.RiskState -eq "atRisk" }
$Total = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
$Count = ($Import | Select-Object UserId -Unique | Measure-Object).Count
if ($Count -gt 0)
{
    Write-Host "[Alert] $Count User(s) whose Risk State is 'atRisk' detected ($Total)" -ForegroundColor Red
}

# MITRE ATT&CK Techniques

# T1110.001 - Brute Force: Password Guessing
# https://attack.mitre.org/techniques/T1110/001/
$Import = Import-Csv -Path "$OUTPUT_FOLDER\CSV\RiskyDetections.csv" -Delimiter "," | Where-Object { $_.mitreTechniques -like "*T1110.001*" }
$Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
if ($Count -gt 0)
{
    Write-Host "[Alert] MITRE ATT&CK T1110.001 - Brute Force: Password Guessing ($Count)" -ForegroundColor Red
}

# T1110.003 - Brute Force: Password Spraying
# https://attack.mitre.org/techniques/T1110/003/
$Import = Import-Csv -Path "$OUTPUT_FOLDER\CSV\RiskyDetections.csv" -Delimiter "," | Where-Object { $_.mitreTechniques -like "*T1110.003*" }
$Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
if ($Count -gt 0)
{
    Write-Host "[Alert] MITRE ATT&CK T1110.003 - Brute Force: Password Spraying ($Count)" -ForegroundColor Red
}

# T1539 - Steal Web Session Cookie (AiTM)
# https://attack.mitre.org/techniques/T1539/
$Import = Import-Csv -Path "$OUTPUT_FOLDER\CSV\RiskyDetections.csv" -Delimiter "," | Where-Object { $_.mitreTechniques -like "*T1539*" }
$Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
if ($Count -gt 0)
{
    Write-Host "[Alert] MITRE ATT&CK T1539 - Steal Web Session Cookie ($Count)" -ForegroundColor Red
}

# T1589.001 - Gather Victim Identity Information: Credentials
# https://attack.mitre.org/techniques/T1589/001/
$Import = Import-Csv -Path "$OUTPUT_FOLDER\CSV\RiskyDetections.csv" -Delimiter "," | Where-Object { $_.mitreTechniques -like "*T1589.001*" }
$Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
if ($Count -gt 0)
{
    Write-Host "[Alert] MITRE ATT&CK T1589.001 - Gather Victim Identity Information: Credentials ($Count)" -ForegroundColor Red
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
Start-Sleep 2

# Reset Windows Title
$Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"

#endregion Footer

#############################################################################################################################################################################################
#############################################################################################################################################################################################


# SIG # Begin signature block
# MIIrxQYJKoZIhvcNAQcCoIIrtjCCK7ICAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQURXrwy5t5Orxoowzr1JzXp7Qy
# pQqggiT/MIIFbzCCBFegAwIBAgIQSPyTtGBVlI02p8mKidaUFjANBgkqhkiG9w0B
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
# hkiG9w0BCQQxFgQU8Q2wpSyCtmd5NM9TEWx99koT/ecwDQYJKoZIhvcNAQEBBQAE
# ggIAHqXXLpHGcye30jUdepcvzUsmhKjKxeilsAxaLLStks3vws0hyPuCBsIJHLjz
# bsyhocsIdOv8OMpbBB8sjtvZUrhUSErCBBrtL7Cc+eebW9Jvv0FAUwfhjtbModUg
# BhMrlBSki/M/wNFMj6/jnlYNOzQK4BtlC9PaP9emHTSMxnYBRtXW67AFDtQPnEY3
# ugMpv8uqwTNLo3vsJXcMnPN6gz0A6PvH/fmdWRx61MKwUsJlSrno05MgqF0Oy8Vl
# UeBSN1qgRyNb3n0ggaQ9NsBqgN7zg3UID7uVl7Fjhv5kOVo8Gpv/iMs/X9SaCAad
# RbhlFD6l2SVXwR4V2SkA+DutmbMCy/eHbJvk/TkAIUtRA3dZu4dv2vWURHaeZpUR
# ZtkA2YMc/ldN1wa1O+vC0FiAWPLV0Y4waGKcqw6qEAktkmgwN3aN7qv0jHcXJyyo
# 3vBgXh/gFFA+FM2K4ByugXmG0wueVFGgd+UgkLaI5vkHKG8bodj2atob5Ht8kpIo
# Aq4tZe4JbKO2ZDnpitDtb+AWSO1U9VFEX0ersyKbcR1+d3rLu8B5/kWEpgsahl12
# yHKjJwJH/73pUKXAYF5O3ANTffmQcd3E50UYZQz4kJHji9SBFmhgIVvwAIjW+wyy
# OHHQOj4M/Gy0iVKcqDVm8cRUW0Ehv/sJAfrL9tvEFzhvQOWhggMiMIIDHgYJKoZI
# hvcNAQkGMYIDDzCCAwsCAQEwaTBVMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2Vj
# dGlnbyBMaW1pdGVkMSwwKgYDVQQDEyNTZWN0aWdvIFB1YmxpYyBUaW1lIFN0YW1w
# aW5nIENBIFIzNgIQOlJqLITOVeYdZfzMEtjpiTANBglghkgBZQMEAgIFAKB5MBgG
# CSqGSIb3DQEJAzELBgkqhkiG9w0BBwEwHAYJKoZIhvcNAQkFMQ8XDTI0MTEyMTA4
# MDI0M1owPwYJKoZIhvcNAQkEMTIEMOsSPy8md5rQ21F6tdUHYgozba+afJt9pxND
# +NctSgZNi/Ptg4ShSSWIEBfXORsBXTANBgkqhkiG9w0BAQEFAASCAgAVwnUylWzj
# jyESkhsRs65rfEApB04+qnyqYh1UYKx4uTPFNSEwtIKYMlOCU/eMEFNvxvXTJItk
# J+EcaCpsYS6rfQZhwiahB6ghgeTIN8QzNOLdPPXCaqZHYUy0fh6AVApH9o5FEd6a
# qVhdoBaIh6ej3D05y5RU1OVZACbAp5RcazTWTJtBwhsxMyj5EBPYOtq87WZdDFxs
# V7MIogtDJz7xymCuKT3U4YMtnznFafAuChyQyjrjSgdc+nCBfOJsHtudzup84zvE
# hzgJKBxcd0xnwHc1zAcd6HceE79n7s77kYvG5A/KdKLLO2a74QBQfjfCbsvF9y2m
# m8jBx3++tV1JZLDumPvpXHCGfZg8g6nUY/3PLW7Wi3F3Z01SmtaHJ49omSy9+iyH
# Z9Y33388iucslgOkY1G+qu8WFVxxMR4DHmH3u9deSLYJEcexwwZK+rGah8JfCv+d
# nIHU8gTlxR3mQmXBjerLXkjBdDUedtR8tHG0je9X8WII2e/pikSNrtK4desmxJMD
# Qj+jdIVrG2C4E6xZG8fV65uZqnwi+bwTQbEeJwcx4nqfn37+ro7aEPMwFXutjVg9
# WiHJeW8OSwgHaaesJIJ7utqXCaAOOSHRjXCJoCpP+FdGQ5rFxEcb3ZaCL1HstITB
# iI9hvuT1AgmQ9wTa4ZeOVgoaqD2LTn9X7g==
# SIG # End signature block
