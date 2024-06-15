# RiskyDetections-Analyzer v0.2
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
#
# Changelog:
# Version 0.1
# Release Date: 2024-02-21
# Initial Release
#
# Version 0.2
# Release Date: 2024-03-09
# Added: Support TimestampFormat (en-US)
# Fixed: Other minor fixes and improvements
#
#
#############################################################################################################################################################################################
#############################################################################################################################################################################################

<#
.SYNOPSIS
  RiskyDetections-Analyzer v0.2 - Automated Processing of 'RiskyDetections.csv' (Microsoft-Extractor-Suite by Invictus-IR)

.DESCRIPTION
  RiskyDetections-Analyzer.ps1 is a PowerShell script utilized to simplify the analysis of the Risk Detections from the Entra ID Identity Protection extracted via "Microsoft 365 Extractor Suite" by Invictus Incident Response.

  https://github.com/invictus-ir/Microsoft-Extractor-Suite

.EXAMPLE
  PS> .\RiskyDetections-Analyzer.ps1

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

# Output Directory
$OUTPUT_FOLDER = "$env:USERPROFILE\Desktop\RiskyDetections-Analyzer"

#endregion Declarations

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Header

# Windows Title
$DefaultWindowsTitle = $Host.UI.RawUI.WindowTitle
$Host.UI.RawUI.WindowTitle = "RiskyDetections-Analyzer v0.2 - Automated Processing of 'RiskyDetections.csv' (Microsoft-Extractor-Suite by Invictus-IR)"

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
        $OpenFileDialog.Filter = "Risky Detections (RiskyDetections.csv)|RiskyDetections.csv|All Files (*.*)|*.*"
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
Write-Output "RiskyDetections-Analyzer v0.1 - Automated Processing of 'RiskyDetections.csv'"
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
$Data = Import-Csv -Path "$LogFile" -Delimiter "," | Sort-Object { $_.ActivityDateTime -as [datetime] } -Descending

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

$Results | Export-Csv -Path "$OUTPUT_FOLDER\CSV\RiskyDetections.csv" -NoTypeInformation

# XLSX
if (Get-Module -ListAvailable -Name ImportExcel)
{
    if (Test-Path "$OUTPUT_FOLDER\CSV\RiskyDetections.csv")
    {
        if(!([String]::IsNullOrWhiteSpace((Get-Content "$OUTPUT_FOLDER\CSV\RiskyDetections.csv"))))
        {
            $IMPORT = Import-Csv "$OUTPUT_FOLDER\CSV\RiskyDetections.csv" -Delimiter ","
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\XLSX\RiskyDetections.xlsx" -NoNumberConversion * -FreezePane 2,6 -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Risky Detections" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:AO1"] -BackgroundColor $BackgroundColor -FontColor White
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
Write-Output "[Info]  $RiskyDetections Risky Detection(s) found"

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
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\Stats\CSV\Activity.csv" -Delimiter ","
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Stats\XLSX\Activity.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Activity" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
        Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
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
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\Stats\CSV\DetectionTimingType.csv" -Delimiter ","
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Stats\XLSX\DetectionTimingType.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "DetectionTimingType" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
        Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
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
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\Stats\CSV\mitreTechniques.csv" -Delimiter ","
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Stats\XLSX\mitreTechniques.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "MITRE ATT&CK" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
        Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
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
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\Stats\CSV\RiskEventType.csv" -Delimiter ","
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Stats\XLSX\RiskEventType.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "RiskEventType" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
        Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
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
$Total = (Import-Csv -Path "$OUTPUT_FOLDER\CSV\RiskyDetections.csv" -Delimiter "," | Select-Object RiskLevel | Measure-Object).Count
Import-Csv -Path "$OUTPUT_FOLDER\CSV\RiskyDetections.csv" -Delimiter "," -Encoding UTF8 | Group-Object RiskLevel | Select-Object @{Name='RiskLevel'; Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending | Export-Csv -Path "$OUTPUT_FOLDER\Stats\CSV\RiskLevel.csv" -NoTypeInformation -Encoding UTF8

# XLSX
if (Test-Path "$OUTPUT_FOLDER\Stats\CSV\RiskLevel.csv")
{
    if(!([String]::IsNullOrWhiteSpace((Get-Content "$LogFile"))))
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\Stats\CSV\RiskLevel.csv" -Delimiter ","
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Stats\XLSX\RiskLevel.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "RiskLevel" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
        Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
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
$Total = (Import-Csv -Path "$OUTPUT_FOLDER\CSV\RiskyDetections.csv" -Delimiter "," | Select-Object RiskDetail | Measure-Object).Count
Import-Csv -Path "$OUTPUT_FOLDER\CSV\RiskyDetections.csv" -Delimiter "," -Encoding UTF8 | Group-Object RiskDetail | Select-Object @{Name='RiskDetail'; Expression={if($_.Name){$_.Name}else{'N/A'}}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending | Export-Csv -Path "$OUTPUT_FOLDER\Stats\CSV\RiskDetail.csv" -NoTypeInformation -Encoding UTF8

# XLSX
if (Test-Path "$OUTPUT_FOLDER\Stats\CSV\RiskDetail.csv")
{
    if(!([String]::IsNullOrWhiteSpace((Get-Content "$LogFile"))))
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\Stats\CSV\RiskDetail.csv" -Delimiter ","
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Stats\XLSX\RiskDetail.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "RiskDetail" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
        Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
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
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\Stats\CSV\RiskReasons.csv" -Delimiter ","
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Stats\XLSX\RiskReasons.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "RiskReasons" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
        Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
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
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\Stats\CSV\RiskState.csv" -Delimiter ","
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Stats\XLSX\RiskState.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "RiskState" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
        Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
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
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\Stats\CSV\Source.csv" -Delimiter ","
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Stats\XLSX\Source.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Source" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
        Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
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
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\Stats\CSV\UserAgent.csv" -Delimiter ","
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Stats\XLSX\UserAgent.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "UserAgent" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
        Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
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
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\Stats\CSV\UserPrincipalName.csv" -Delimiter ","
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Stats\XLSX\UserPrincipalName.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "UserPrincipalName" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
        Set-Format -Address $WorkSheet.Cells["A1:D1"] -BackgroundColor $BackgroundColor -FontColor White
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

# Reset Windows Title
$Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"

#endregion Footer

#############################################################################################################################################################################################
#############################################################################################################################################################################################
