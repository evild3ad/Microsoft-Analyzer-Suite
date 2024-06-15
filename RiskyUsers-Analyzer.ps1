# RiskyUsers-Analyzer v0.2
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
  RiskyUsers-Analyzer v0.2 - Automated Processing of 'RiskyUsers.csv' (Microsoft-Extractor-Suite by Invictus-IR)

.DESCRIPTION
  RiskyUsers-Analyzer.ps1 is a PowerShell script utilized to simplify the analysis of the Risky Users from the Entra ID Identity Protection extracted via "Microsoft Extractor Suite" by Invictus Incident Response.

  Note: Using the riskyUsers API requires a Microsoft Entra ID P2 license.

  https://github.com/invictus-ir/Microsoft-Extractor-Suite

.EXAMPLE
  PS> .\RiskyUsers-Analyzer.ps1

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
$OUTPUT_FOLDER = "$env:USERPROFILE\Desktop\RiskyUsers-Analyzer"

#endregion Declarations

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Header

# Windows Title
$DefaultWindowsTitle = $Host.UI.RawUI.WindowTitle
$Host.UI.RawUI.WindowTitle = "RiskyUsers-Analyzer v0.2 - Automated Processing of 'RiskyUsers.csv' (Microsoft-Extractor-Suite by Invictus-IR)"

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
        $OpenFileDialog.Filter = "Risky Users (RiskyUsers.csv)|RiskyUsers.csv|All Files (*.*)|*.*"
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
Write-Output "RiskyUsers-Analyzer v0.2 - Automated Processing of 'RiskyUsers.csv'"
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

# Get-MgRiskyUser
# https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.identity.signins/get-mgriskyuser?view=graph-powershell-1.0
# https://learn.microsoft.com/en-us/graph/api/resources/riskyuser?view=graph-rest-1.0

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

# Processing RiskyUsers.csv
Write-Output "[Info]  Processing RiskyUsers.csv ..."
New-Item "$OUTPUT_FOLDER\CSV" -ItemType Directory -Force | Out-Null
New-Item "$OUTPUT_FOLDER\XLSX" -ItemType Directory -Force | Out-Null

# Check Timestamp Format
$Timestamp = (Import-Csv -Path "$LogFile" -Delimiter "," | Select-Object RiskLastUpdatedDateTime -First 1).RiskLastUpdatedDateTime

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
$StartDate = (Import-Csv -Path "$LogFile" -Delimiter "," | Select-Object @{Name="RiskLastUpdatedDateTime";Expression={([DateTime]::ParseExact($_.RiskLastUpdatedDateTime, "$TimestampFormat", [cultureinfo]::InvariantCulture).ToString("yyyy-MM-dd HH:mm:ss"))}} | Sort-Object { $_.RiskLastUpdatedDateTime -as [datetime] } -Descending | Select-Object -Last 1).RiskLastUpdatedDateTime
$EndDate = (Import-Csv -Path "$LogFile" -Delimiter "," | Select-Object @{Name="RiskLastUpdatedDateTime";Expression={([DateTime]::ParseExact($_.RiskLastUpdatedDateTime, "$TimestampFormat", [cultureinfo]::InvariantCulture).ToString("yyyy-MM-dd HH:mm:ss"))}} | Sort-Object { $_.RiskLastUpdatedDateTime -as [datetime] } -Descending | Select-Object -First 1).RiskLastUpdatedDateTime
Write-Output "[Info]  Log data from $StartDate UTC until $EndDate UTC"

# XLSX
if (Get-Module -ListAvailable -Name ImportExcel)
{
    if (Test-Path "$LogFile")
    {
        if(!([String]::IsNullOrWhiteSpace((Get-Content "$LogFile"))))
        {
            $IMPORT = Import-Csv "$LogFile" -Delimiter "," | Select-Object @{Name="RiskLastUpdatedDateTime";Expression={([DateTime]::ParseExact($_.RiskLastUpdatedDateTime, "$TimestampFormat", [cultureinfo]::InvariantCulture).ToString("yyyy-MM-dd HH:mm:ss"))}},Id,UserDisplayName,UserPrincipalName,RiskDetail,RiskLevel,RiskState,IsDeleted,IsProcessing,History | Sort-Object { $_.RiskLastUpdatedDateTime -as [datetime] } -Descending
            $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\XLSX\RiskyUsers.xlsx" -NoNumberConversion * -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "Risky Users" -CellStyleSB {
            param($WorkSheet)
            # BackgroundColor and FontColor for specific cells of TopRow
            $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
            Set-Format -Address $WorkSheet.Cells["A1:J1"] -BackgroundColor $BackgroundColor -FontColor White
            # HorizontalAlignment "Center" of columns A-J
            $WorkSheet.Cells["A:J"].Style.HorizontalAlignment="Center"
            # ConditionalFormatting - RiskLevel
            Add-ConditionalFormatting -Address $WorkSheet.Cells["F:F"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("high",$F1)))' -BackgroundColor Red
            $Orange = [System.Drawing.Color]::FromArgb(255,192,0)
            Add-ConditionalFormatting -Address $WorkSheet.Cells["F:F"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("medium",$F1)))' -BackgroundColor $Orange
            Add-ConditionalFormatting -Address $WorkSheet.Cells["F:F"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("low",$F1)))' -BackgroundColor Yellow
            $Green = [System.Drawing.Color]::FromArgb(0,176,80)
            Add-ConditionalFormatting -Address $WorkSheet.Cells["F:F"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("none",$F1)))' -BackgroundColor $Green
            # ConditionalFormatting - RiskState
            Add-ConditionalFormatting -Address $WorkSheet.Cells["G:G"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("atRisk",$G1)))' -BackgroundColor Red
            }
        }
    }
}
else
{
    Write-Host "[Error] PowerShell module 'ImportExcel' NOT found." -ForegroundColor Red
}

# Count Risky Users
$Count = (Import-Csv -Path "$LogFile" -Delimiter "," | Select-Object Id | Measure-Object).Count
$RiskyUsers = '{0:N0}' -f $Count
Write-Output "[Info]  $RiskyUsers Risky Users found"

# Number of attacks blocked by Identity Protection

# Risky Users detected within the last 7 days
$Date = (Get-Date).AddDays(-7)
$Count = (Import-Csv -Path "$LogFile" -Delimiter "," | Where-Object -FilterScript {[DateTime]::Parse($_.RiskLastUpdatedDateTime) -gt $Date} | Measure-Object).Count
$RiskyUsers = '{0:N0}' -f $Count
Write-Output "[Info]  $RiskyUsers Risky Users detected within the last 7 days"

# Risky Users detected within the last 30 days
$Date = (Get-Date).AddDays(-30)
$Count = (Import-Csv -Path "$LogFile" -Delimiter "," | Where-Object -FilterScript {[DateTime]::Parse($_.RiskLastUpdatedDateTime) -gt $Date} | Measure-Object).Count
$RiskyUsers = '{0:N0}' -f $Count
Write-Output "[Info]  $RiskyUsers Risky Users detected within the last 30 days"

# Risky Users detected within the last 90 days
$Date = (Get-Date).AddDays(-90)
$Count = (Import-Csv -Path "$LogFile" -Delimiter "," | Where-Object -FilterScript {[DateTime]::Parse($_.RiskLastUpdatedDateTime) -gt $Date} | Measure-Object).Count
$RiskyUsers = '{0:N0}' -f $Count
Write-Output "[Info]  $RiskyUsers Risky Users detected within the last 90 days"

# Risky Users detected within the last 6 months
$Date = (Get-Date).AddDays(-180)
$Count = (Import-Csv -Path "$LogFile" -Delimiter "," | Where-Object -FilterScript {[DateTime]::Parse($_.RiskLastUpdatedDateTime) -gt $Date} | Measure-Object).Count
$RiskyUsers = '{0:N0}' -f $Count
Write-Output "[Info]  $RiskyUsers Risky Users detected within the last 6 months"

# Risky Users detected within the last 12 months
$Date = (Get-Date).AddDays(-360)
$Count = (Import-Csv -Path "$LogFile" -Delimiter "," | Where-Object -FilterScript {[DateTime]::Parse($_.RiskLastUpdatedDateTime) -gt $Date} | Measure-Object).Count
$RiskyUsers = '{0:N0}' -f $Count
Write-Output "[Info]  $RiskyUsers Risky Users detected within the last 12 months"

# Stats
New-Item "$OUTPUT_FOLDER\Stats\CSV" -ItemType Directory -Force | Out-Null
New-Item "$OUTPUT_FOLDER\Stats\XLSX" -ItemType Directory -Force | Out-Null

# RiskDetail (Stats)
$Total = (Import-Csv -Path "$LogFile" -Delimiter "," | Select-Object RiskDetail | Measure-Object).Count
Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Group-Object RiskDetail | Select-Object @{Name='RiskLevel'; Expression={$_.Name}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending | Export-Csv -Path "$OUTPUT_FOLDER\Stats\CSV\RiskDetail.csv" -NoTypeInformation -Encoding UTF8

# XLSX
if (Test-Path "$OUTPUT_FOLDER\Stats\CSV\RiskDetail.csv")
{
    if(!([String]::IsNullOrWhiteSpace((Get-Content "$OUTPUT_FOLDER\Stats\CSV\RiskDetail.csv"))))
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\Stats\CSV\RiskDetail.csv" -Delimiter ","
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Stats\XLSX\RiskDetail.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "RiskDetail" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
        Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
        # HorizontalAlignment "Center" of columns B-C
        $WorkSheet.Cells["B:C"].Style.HorizontalAlignment="Center"
        }
    }
}

# RiskLevel (Stats)
$Total = (Import-Csv -Path "$LogFile" -Delimiter "," | Select-Object RiskLevel | Measure-Object).Count
Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Group-Object RiskLevel | Select-Object @{Name='RiskLevel'; Expression={$_.Name}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending | Export-Csv -Path "$OUTPUT_FOLDER\Stats\CSV\RiskLevel.csv" -NoTypeInformation -Encoding UTF8

# XLSX
if (Test-Path "$OUTPUT_FOLDER\Stats\CSV\RiskLevel.csv")
{
    if(!([String]::IsNullOrWhiteSpace((Get-Content "$OUTPUT_FOLDER\Stats\CSV\RiskLevel.csv"))))
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

# RiskLevel
# none   - No Risk
# low    - Low Risk Users
# medium - Medium Risk Users
# high   - High Risk Users
# hidden - Microsoft Entra ID P2 license required
# unknownFutureValue

# RiskState (Stats)
$Total = (Import-Csv -Path "$LogFile" -Delimiter "," | Select-Object RiskState | Measure-Object).Count
Import-Csv -Path "$LogFile" -Delimiter "," -Encoding UTF8 | Group-Object RiskState | Select-Object @{Name='RiskState'; Expression={$_.Name}},Count,@{Name='PercentUse'; Expression={"{0:p2}" -f ($_.Count / $Total)}} | Sort-Object Count -Descending | Export-Csv -Path "$OUTPUT_FOLDER\Stats\CSV\RiskState.csv" -NoTypeInformation -Encoding UTF8

# XLSX
if (Test-Path "$OUTPUT_FOLDER\Stats\CSV\RiskState.csv")
{
    if(!([String]::IsNullOrWhiteSpace((Get-Content "$OUTPUT_FOLDER\Stats\CSV\RiskState.csv"))))
    {
        $IMPORT = Import-Csv "$OUTPUT_FOLDER\Stats\CSV\RiskState.csv" -Delimiter ","
        $IMPORT | Export-Excel -Path "$OUTPUT_FOLDER\Stats\XLSX\RiskState.xlsx" -FreezeTopRow -BoldTopRow -AutoSize -AutoFilter -WorkSheetname "RiskState" -CellStyleSB {
        param($WorkSheet)
        # BackgroundColor and FontColor for specific cells of TopRow
        $BackgroundColor = [System.Drawing.Color]::FromArgb(50,60,220)
        Set-Format -Address $WorkSheet.Cells["A1:C1"] -BackgroundColor $BackgroundColor -FontColor White
        # HorizontalAlignment "Center" of columns A-C
        $WorkSheet.Cells["A:C"].Style.HorizontalAlignment="Center"
        # ConditionalFormatting - RiskState
        Add-ConditionalFormatting -Address $WorkSheet.Cells["A:A"] -WorkSheet $WorkSheet -RuleType 'Expression' 'NOT(ISERROR(FIND("atRisk",$A1)))' -BackgroundColor Red
        }
    }
}

# Line Charts
New-Item "$OUTPUT_FOLDER\Stats\XLSX\LineCharts" -ItemType Directory -Force | Out-Null

# Risky Users (Line Chart) --> Risky Users per day
$Import = Import-Csv "$LogFile" -Delimiter "," | Select-Object @{Name="RiskLastUpdatedDateTime";Expression={([DateTime]::Parse($_.RiskLastUpdatedDateTime).ToString("yyyy-MM-dd HH:mm:ss"))}}
$RiskyUsers = $Import | Group-Object{($_.RiskLastUpdatedDateTime -split "\s+")[0]} | Select-Object Count,@{Name='RiskLastUpdatedDateTime'; Expression={ $_.Values[0] }} | Sort-Object { $_.RiskLastUpdatedDateTime -as [datetime] }
$ChartDefinition = New-ExcelChartDefinition -XRange RiskLastUpdatedDateTime -YRange Count -Title "Risky Users" -ChartType Line -NoLegend -Width 1200
$RiskyUsers | Export-Excel -Path "$OUTPUT_FOLDER\Stats\XLSX\LineCharts\RiskyUsers.xlsx" -Append -WorksheetName "Line Chart" -AutoNameRange -ExcelChartDefinition $ChartDefinition

# Risky Users (Line Chart) --> Risky Users per day (Last 90 days)
$Date = (Get-Date).AddDays(-90)
$Import = Import-Csv "$LogFile" -Delimiter "," | Where-Object -FilterScript {[DateTime]::Parse($_.RiskLastUpdatedDateTime) -gt $Date} | Select-Object @{Name="RiskLastUpdatedDateTime";Expression={([DateTime]::Parse($_.RiskLastUpdatedDateTime).ToString("yyyy-MM-dd HH:mm:ss"))}}
$RiskyUsers = $Import | Group-Object{($_.RiskLastUpdatedDateTime -split "\s+")[0]} | Select-Object Count,@{Name='RiskLastUpdatedDateTime'; Expression={ $_.Values[0] }} | Sort-Object { $_.RiskLastUpdatedDateTime -as [datetime] }
$ChartDefinition = New-ExcelChartDefinition -XRange RiskLastUpdatedDateTime -YRange Count -Title "Risky Users (Last 90 days)" -ChartType Line -NoLegend -Width 1200
$RiskyUsers | Export-Excel -Path "$OUTPUT_FOLDER\Stats\XLSX\LineCharts\RiskyUsers_Last-90-days.xlsx" -Append -WorksheetName "Line Chart" -AutoNameRange -ExcelChartDefinition $ChartDefinition

# atRisk
# dismissed --> e.g. dismissed automatically
# remediated

# Number of Risky Users with Risk Level "High" (Past 12 months)
$Date = (Get-Date).AddDays(-360)
$Count = (Import-Csv -Path "$LogFile" -Delimiter "," | Where-Object -FilterScript {[DateTime]::Parse($_.RiskLastUpdatedDateTime) -gt $Date}  | Where-Object { $_.RiskLevel -eq "high" } | Measure-Object).Count

if ($Count -gt 0)
{
    $HighRiskUsers = '{0:N0}' -f $Count
    Write-Host "[Alert] Number of High Risk Users (Past 12 months): $HighRiskUsers" -ForegroundColor Red
}
else
{
    Write-Host "[Info]  Number of High Risk Users (Past 12 months): 0" -ForegroundColor Green
}

# Number of Users whose Risk State is "Remediated" or "Dismissed"
$Import = Import-Csv -Path "$LogFile" -Delimiter "," | Where-Object { $_.RiskState -eq "Remediated" -or $_.RiskState -eq "Dismissed" }
$Count = [string]::Format('{0:N0}',($Import | Measure-Object).Count)
if ($Count -gt 0)
{
    Write-Host "[Alert] Number of Users whose Risk State is 'Remediated' or 'Dismissed': $Count"
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
