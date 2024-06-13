# Microsoft-Analyzer-Suite Updater v0.2
#
# @author:    Martin Willing
# @copyright: Copyright (c) 2024 Martin Willing. All rights reserved.
# @contact:   Any feedback or suggestions are always welcome and much appreciated - mwilling@lethal-forensics.com
# @url:       https://lethal-forensics.com/
# @date:      2024-05-25
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
# Changelog:
# Version 0.1
# Release Date: 2024-03-09
# Initial Release
#
# Version 0.2
# Release Date: 2024-05-23
# Fixed: Minor fixes and improvements
#
#
#############################################################################################################################################################################################
#############################################################################################################################################################################################

<#
.SYNOPSIS
  Microsoft-Analyzer-Suite Updater v0.2 - Automated Installer/Updater for the Microsoft-Analyzer-Suite

.DESCRIPTION
  Updater.ps1 is a PowerShell script utilized to automate the installation and the update process of the "Microsoft-Extractor-Suite" by Invictus Incident Response (incl. all dependencies)
  and of all dependencies for the "Microsoft-Analyzer-Suite".

  https://github.com/invictus-ir/Microsoft-Extractor-Suite

.EXAMPLE
  PS> .\Updater.ps1

.NOTES
  Author - Martin Willing

.LINK
  https://lethal-forensics.com/
#>

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Initialisations

# Set Progress Preference to Silently Continue
$OriginalProgressPreference = $Global:ProgressPreference
$Script:ProgressPreference = 'SilentlyContinue'

#endregion Initialisations

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Declarations

# Declarations

# Script Root
if ($PSVersionTable.PSVersion.Major -gt 2)
{
    # PowerShell 3+
    $script:SCRIPT_DIR = $PSScriptRoot
    $Script:PARENT_DIR = Split-Path $SCRIPT_DIR -Parent
}

# Tools

# IPinfo CLI
$script:IPinfo = "$PARENT_DIR\Tools\IPinfo\ipinfo.exe"

# Microsoft-Extractor-Suite
$script:MicrosoftExtractorSuite = "$PARENT_DIR\Microsoft-Extractor-Suite-main\Microsoft-Extractor-Suite.psd1"

# xsv
$script:xsv = "$PARENT_DIR\Tools\xsv\xsv.exe"

#endregion Declarations

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Header

# Windows Title
$DefaultWindowsTitle = $Host.UI.RawUI.WindowTitle
$Host.UI.RawUI.WindowTitle = "Microsoft Analyzer Suite Updater v0.2 - Automated Installer/Updater for the Microsoft-Analyzer-Suite"

# Check if the PowerShell script is being run with admin rights
if (!([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
    Write-Host "[Error] This PowerShell script must be run with admin rights." -ForegroundColor Red
    Exit
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
Write-Output "Microsoft-Analyzer-Suite Updater v0.2 - Automated Installer/Updater for the Microsoft-Analyzer-Suite"
Write-Output "(c) 2024 Martin Willing at Lethal-Forensics (https://lethal-forensics.com/)"
Write-Output ""

# Update date (ISO 8601)
$script:UpdateDate = [datetime]::Now.ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss")
Write-Output "Update date: $UpdateDate UTC"
Write-Output ""

#endregion Header

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Updater

Function InternetConnectivityCheck {

    # Internet Connectivity Check (Vista+)
    $NetworkListManager = [Activator]::CreateInstance([Type]::GetTypeFromCLSID([Guid]‘{DCB00C01-570F-4A9B-8D69-199FDBA5723B}’)).IsConnectedToInternet

    # Offline
    if (!($NetworkListManager -eq "True"))
    {
        Write-Host "[Error] Your computer is NOT connected to the Internet." -ForegroundColor Red
        $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
        Exit
    }

    # Online
    if ($NetworkListManager -eq "True")
    {
        # Check if GitHub is reachable
        if (!(Test-NetConnection -ComputerName github.com -Port 443).TcpTestSucceeded)
        {
            Write-Host "[Error] github.com is NOT reachable. Please check your network connection and try again." -ForegroundColor Red
            $Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"
            Exit
        }
    }
}

#############################################################################################################################################################################################

Function Get-MicrosoftExtractorSuite {

# Microsoft-Extractor-Suite
# https://github.com/invictus-ir/Microsoft-Extractor-Suite
# https://www.powershellgallery.com/packages/Microsoft-Extractor-Suite/

# Check Current Version of Microsoft-Extractor-Suite
if (Test-Path "$($MicrosoftExtractorSuite)")
{
    $CurrentVersion = (Get-Content "$MicrosoftExtractorSuite" | Select-String -Pattern "ModuleVersion = " | ForEach-Object{($_ -split "'")[1]} | Out-String).Trim()
    Write-Output "[Info]  Current Version: Microsoft-Extractor-Suite v$CurrentVersion"
}
else
{
    Write-Output "[Info]  Microsoft-Extractor-Suite.psd1 NOT found."
    $CurrentVersion = $null
}

# Determining latest release on GitHub
$Repository = "invictus-ir/Microsoft-Extractor-Suite"
$Releases = "https://api.github.com/repos/$Repository/releases"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Response = (Invoke-WebRequest -Uri $Releases -UseBasicParsing | ConvertFrom-Json)[0]
$Tag = $Response.tag_name
$LatestVersion = $Tag.Substring(1)
$Published = $Response.published_at
$ReleaseDate = $Published.split('T')[0]
$Download = ($Response | Select-Object -ExpandProperty zipball_url | Out-String).Trim()

if ($CurrentVersion)
{
    Write-Output "[Info]  Latest Release:  Microsoft-Extractor-Suite v$LatestVersion ($ReleaseDate)"
}
else
{
    Write-Output "[Info]  Latest Release: Microsoft-Extractor-Suite v$LatestVersion ($ReleaseDate)"
}

# Check if 'Microsoft-Extractor-Suite' needs to be downloaded/updated
if ($CurrentVersion -ne $LatestVersion -Or $null -eq $CurrentVersion)
{
    Write-Output "[Info]  Dowloading Latest Release ..."
    $Zip = "Microsoft-Extractor-Suite-main.zip"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $Download -OutFile "$PARENT_DIR\$Zip"

    if (Test-Path "$PARENT_DIR\$Zip")
    {
        # Delete Directory Content and Remove Directory
        if (Test-Path "$PARENT_DIR\Microsoft-Extractor-Suite-main")
        {
            Get-ChildItem -Path "$PARENT_DIR\Microsoft-Extractor-Suite-main" -Recurse | Remove-Item -Force -Recurse
            Remove-Item "$PARENT_DIR\Microsoft-Extractor-Suite-main" -Force
        }

        # Unpacking Archive File
        Write-Output "[Info]  Extracting Files ..."
        Expand-Archive -Path "$PARENT_DIR\$Zip" -DestinationPath "$PARENT_DIR" -Force

        # Rename Unpacked Directory
        Start-Sleep 5
        $Directory = (Get-ChildItem -Path "$PARENT_DIR\invictus-ir-Microsoft-Extractor-Suite-*").FullName
        Rename-Item "$Directory" "$PARENT_DIR\Microsoft-Extractor-Suite-main" -Force

        # Remove Downloaded Archive
        Start-Sleep 5
        Remove-Item "$PARENT_DIR\$Zip" -Force
    }
}
else
{
    Write-Host "[Info]  You are running the most recent version of Microsoft-Extractor-Suite." -ForegroundColor Green
}

}

#############################################################################################################################################################################################

Function Get-ImportExcel {

# ImportExcel
# https://github.com/dfinke/ImportExcel

# Check if PowerShell module 'ImportExcel' exists
if (Get-Module -ListAvailable -Name ImportExcel) 
{
    # Check if multiple versions of PowerShell module 'ImportExcel' exist
    $Modules = (Get-Module -ListAvailable -Name ImportExcel | Measure-Object).Count

    if ($Modules -eq "1")
    {
        # Check Current Version
        $CurrentVersion = (Get-Module -ListAvailable -Name ImportExcel).Version.ToString()
        Write-Output "[Info]  Current Version: ImportExcel v$CurrentVersion"
    }
    else
    {
        Write-Host "[Info]  Multiple installed versions of PowerShell module 'ImportExcel' found. Uninstalling ..."
        Uninstall-Module -Name ImportExcel -AllVersions -ErrorAction SilentlyContinue
        $CurrentVersion = $null
    }
}
else
{
    Write-Output "[Info]  PowerShell module 'ImportExcel' NOT found."
    $CurrentVersion = $null
}

# Determining latest release on GitHub
$Repository = "dfinke/ImportExcel"
$Releases = "https://api.github.com/repos/$Repository/releases"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Response = (Invoke-WebRequest -Uri $Releases -UseBasicParsing | ConvertFrom-Json)[0]
$Tag = $Response.tag_name
$Published = $Response.published_at
$ReleaseDate = $Published.split('T')[0]
$LatestRelease = $Tag.Substring(1)

if ($CurrentVersion)
{
    Write-Output "[Info]  Latest Release:  ImportExcel $Tag ($ReleaseDate)"
}
else
{
    Write-Output "[Info]  Latest Release: ImportExcel $Tag ($ReleaseDate)"
}

# Check if ImportExcel needs to be installed
if ($null -eq $CurrentVersion)
{
    Write-Output "[Info]  Installing ImportExcel v$LatestRelease ..."
    Install-Module -Name ImportExcel -Repository PSGallery -Force
    $CurrentVersion = (Get-Module -ListAvailable -Name ImportExcel).Version.ToString()
}

# Check if ImportExcel needs to be updated
if ($CurrentVersion -lt $LatestRelease)
{
    # Update PowerShell module 'ImportExcel'
    try
    {
        Write-Output "[Info]  Updating PowerShell module 'ImportExcel' ..."
        Uninstall-Module -Name ImportExcel -AllVersions
        Install-Module -Name ImportExcel -Repository PSGallery -Force
    }
    catch
    {
        Write-Output "PowerShell module 'ImportExcel' is in use. Please close all PowerShell sessions, and run Updater.ps1 again."
    }   
}
else
{
    Write-Host "[Info]  You are running the most recent version of ImportExcel." -ForegroundColor Green
}

}

#############################################################################################################################################################################################

Function Get-IPinfo {

# IPinfo CLI
# https://github.com/ipinfo/cli

# Check Current Version of IPinfo CLI
if (Test-Path "$($IPinfo)")
{
    $CurrentVersion = & $IPinfo version
    $LastWriteTime = ((Get-Item $IPinfo).LastWriteTime).ToString("yyyy-MM-dd")
    Write-Output "[Info]  Current Version: IPinfo CLI v$CurrentVersion ($LastWriteTime)"
}
else
{
    Write-Output "[Info]  IPinfo CLI NOT found."
    $CurrentVersion = ""
}

# Determining latest release on GitHub
$Repository = "ipinfo/cli"
$Releases = "https://api.github.com/repos/$Repository/releases"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Response = (Invoke-WebRequest -Uri $Releases -UseBasicParsing | ConvertFrom-Json)

$Asset=0
while($true) {
    $Check = $Response[$Asset].assets | Select-Object @{Name="browser_download_url"; Expression={$_.browser_download_url}} | Select-String -Pattern "ipinfo-" -Quiet
    if ($Check -eq "True" )
    {
        Break
    }
    else
    {
        $Asset++
    }
}

$TagName = $Response[$Asset].tag_name
$Tag = $TagName.Split("-")[1] 
$Published = $Response[$Asset].published_at
$Download = ($Response[$Asset].assets | Select-Object -ExpandProperty browser_download_url | Select-String -Pattern "windows_amd64" | Out-String).Trim()
$ReleaseDate = $Published.split('T')[0]

if ($CurrentVersion)
{
    Write-Output "[Info]  Latest Release:  IPinfo CLI v$Tag ($ReleaseDate)"
}
else
{
    Write-Output "[Info]  Latest Release: IPinfo CLI v$Tag ($ReleaseDate)"
}

# Check if IPinfo CLI needs to be downloaded/updated
if ($CurrentVersion -ne $Tag -Or $null -eq $CurrentVersion)
{
    # Download latest release from GitHub
    Write-Output "[Info]  Dowloading Latest Release ..."
    $Zip = "IPinfo.zip"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $Download -OutFile "$PARENT_DIR\$Zip"

    if (Test-Path "$PARENT_DIR\$Zip")
    {
        # Delete Directory Content and Remove Directory
        if (Test-Path "$PARENT_DIR\Tools\IPinfo")
        {
            Get-ChildItem -Path "$PARENT_DIR\Tools\IPinfo" -Recurse | Remove-Item -Force -Recurse
            Remove-Item "$PARENT_DIR\Tools\IPinfo" -Force
        }

        # Unpacking Archive File
        Write-Output "[Info]  Extracting Files ..."
        Expand-Archive -Path "$PARENT_DIR\$Zip" -DestinationPath "$PARENT_DIR\Tools\IPinfo" -Force

        # Remove Downloaded Archive
        Start-Sleep 5
        Remove-Item "$PARENT_DIR\$Zip" -Force

        # Rename Executable
        if (Test-Path "$PARENT_DIR\Tools\IPinfo\ipinfo_*")
        {
            Get-ChildItem -Path "$PARENT_DIR\Tools\IPinfo\ipinfo_*.exe" | Rename-Item -NewName {"ipinfo.exe"}
        }
    } 
}
else
{
    Write-Host "[Info]  You are running the most recent version of IPinfo CLI." -ForegroundColor Green
}

}

#############################################################################################################################################################################################

Function Get-XSV {

# xsv
# https://github.com/BurntSushi/xsv

# Check Current Version of xsv
if (Test-Path "$($xsv)")
{
    $CurrentVersion = & $xsv --version
    $LastWriteTime = ((Get-Item $xsv).LastWriteTime).ToString("yyyy-MM-dd")
    Write-Output "[Info]  Current Version: xsv v$CurrentVersion ($LastWriteTime)"
}
else
{
    Write-Output "[Info]  xsv.exe NOT found."
    $CurrentVersion = ""
}

# Determining latest release on GitHub
$Repository = "BurntSushi/xsv"
$Releases = "https://api.github.com/repos/$Repository/releases/latest"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Response = (Invoke-WebRequest -Uri $Releases -UseBasicParsing | ConvertFrom-Json)
$Tag = $Response.tag_name
$Published = $Response.published_at
$Download = ($Response.assets | Select-Object -ExpandProperty browser_download_url | Select-String -Pattern "-x86_64-pc-windows-msvc" | Out-String).Trim()
$ReleaseDate = $Published.split('T')[0]

if ($CurrentVersion)
{
    Write-Output "[Info]  Latest Release:  xsv v$Tag ($ReleaseDate)"
}
else
{
    Write-Output "[Info]  Latest Release: xsv v$Tag ($ReleaseDate)"
}

# Check if xsv needs to be downloaded/updated
if ($CurrentVersion -ne $Tag -Or $null -eq $CurrentVersion)
{
    # Download latest release from GitHub
    Write-Output "[Info]  Dowloading Latest Release ..."
    $Zip = "xsv.zip"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $Download -OutFile "$PARENT_DIR\$Zip"

    if (Test-Path "$PARENT_DIR\$Zip")
    {
        # Delete Directory Content and Remove Directory
        if (Test-Path "$PARENT_DIR\Tools\xsv")
        {
            Get-ChildItem -Path "$PARENT_DIR\Tools\xsv" -Recurse | Remove-Item -Force -Recurse
            Remove-Item "$PARENT_DIR\Tools\xsv" -Force
        }

        # Unpacking Archive File
        Write-Output "[Info]  Extracting Files ..."
        Expand-Archive -Path "$PARENT_DIR\$Zip" -DestinationPath "$PARENT_DIR\Tools\xsv" -Force

        # Remove Downloaded Archive
        Start-Sleep 5
        Remove-Item "$PARENT_DIR\$Zip" -Force
    }
}
else
{
    Write-Host "[Info]  You are running the most recent version of xsv." -ForegroundColor Green
}

}

#############################################################################################################################################################################################

Function Get-Az {

# Azure PowerShell (Collection of PowerShell modules)
# https://www.powershellgallery.com/packages/Az/
# https://github.com/Azure/azure-powershell

# Check if Azure PowerShell modules exists
if (!(Get-Module -ListAvailable -Name Az.*))
{
    Write-Output "[Info]  PowerShell module 'Az' NOT found."
    $CurrentVersion = $null
}
else
{
    $CurrentVersion = "UNKNOWN"
}

# Determining latest version in PSGallery
$LatestVersion = (Find-Module -Name Az).Version.ToString()
Write-Output "[Info]  Latest Version: Az v$LatestVersion"

# Install/Update via PSGallery
if ($null -eq $CurrentVersion)
{
    Install-Module -Name Az -Repository PSGallery -Force
}
else
{
    Write-Output "[Info]  Current Version of Az cannot be determined. Updating the collection of 'Azure PowerShell' modules [approx. 1-3 min] ..."
    Uninstall-Module -Name Az -AllVersions
    Install-Module -Name Az -Repository PSGallery -Force
}

}

#############################################################################################################################################################################################

Function Get-AzureADPreview {

# AzureADPreview
# https://www.powershellgallery.com/packages/AzureADPreview/

# Check if PowerShell module 'AzureADPreview' exists
if (Get-Module -ListAvailable -Name AzureADPreview) 
{
    # Check Current Version
    $CurrentVersion = (Get-Module -ListAvailable -Name AzureADPreview).Version.ToString()
    Write-Output "[Info]  Current Version: AzureADPreview v$CurrentVersion"
}
else
{
    Write-Output "[Info]  PowerShell module 'AzureADPreview' NOT found."
    $CurrentVersion = $null
}

# Determining latest version in PSGallery
$LatestVersion = (Find-Module -Name AzureADPreview).Version.ToString()

if ($CurrentVersion)
{
    Write-Output "[Info]  Latest Version:  AzureADPreview v$LatestVersion"
}
else
{
    Write-Output "[Info]  Latest Version: AzureADPreview v$LatestVersion"
}

# Check if 'AzureADPreview' needs to be downloaded/updated via PowerShell Gallery
if ($CurrentVersion -ne $LatestVersion -Or $null -eq $CurrentVersion)
{
    if ($null -eq $CurrentVersion)
    {
        Write-Output "[Info]  Installing PowerShell module 'AzureADPreview' ..."
        Install-Module -Name AzureADPreview -Repository PSGallery -AllowClobber -Force
    }
    else
    {
        Write-Output "[Info]  Updating PowerShell module 'AzureADPreview' ..."
        Uninstall-Module -Name AzureADPreview -AllVersions
        Install-Module -Name AzureADPreview -Repository PSGallery -AllowClobber -Force
    }
}
else
{
    Write-Host "[Info]  You are running the most recent version of AzureADPreview." -ForegroundColor Green
}

}

#############################################################################################################################################################################################

Function Get-ExchangeOnlineManagement {

# ExchangeOnlineManagement
# https://www.powershellgallery.com/packages/ExchangeOnlineManagement/
# https://learn.microsoft.com/en-us/powershell/exchange/exchange-online-powershell-v2?view=exchange-ps#updates-for-version-300-the-exo-v3-module

# Check if PowerShell module 'ExchangeOnlineManagement' exists
if (Get-Module -ListAvailable -Name ExchangeOnlineManagement) 
{
    # Check Current Version
    $CurrentVersion = (Get-Module -ListAvailable -Name ExchangeOnlineManagement).Version.ToString()
    Write-Output "[Info]  Current Version: ExchangeOnlineManagement v$CurrentVersion"
}
else
{
    Write-Output "[Info]  PowerShell module 'ExchangeOnlineManagement' NOT found."
    $CurrentVersion = $null
}

# Determining latest version in PSGallery
$LatestVersion = (Find-Module -Name ExchangeOnlineManagement).Version.ToString()

if ($CurrentVersion)
{
    Write-Output "[Info]  Latest Version:  ExchangeOnlineManagement v$LatestVersion"
}
else
{
    Write-Output "[Info]  Latest Version: ExchangeOnlineManagement v$LatestVersion"
}

# Check if ExchangeOnlineManagement needs to be downloaded/updated via PowerShell Gallery
if ($CurrentVersion -ne $LatestVersion -Or $null -eq $CurrentVersion)
{
    if ($null -eq $CurrentVersion)
    {
        Write-Output "[Info]  Installing PowerShell module 'ExchangeOnlineManagement' ..."
        Install-Module -Name ExchangeOnlineManagement -Repository PSGallery -Force -AllowClobber
    }
    else
    {
        Write-Output "[Info]  Updating PowerShell module 'ExchangeOnlineManagement' ..."
        Uninstall-Module -Name ExchangeOnlineManagement -AllVersions
        Install-Module -Name ExchangeOnlineManagement -Repository PSGallery -Force -AllowClobber
    }
}
else
{
    Write-Host "[Info]  You are running the most recent version of ExchangeOnlineManagement." -ForegroundColor Green
}

}

#############################################################################################################################################################################################

Function Get-MicrosoftGraph {

# Microsoft.Graph
# https://github.com/microsoftgraph/msgraph-sdk-powershell

# Check if PowerShell module 'Microsoft.Graph' exists
if (Get-Module -ListAvailable -Name Microsoft.Graph) 
{
    # Check Current Version
    $CurrentVersion = (Get-Module -ListAvailable -Name Microsoft.Graph).Version.ToString()
    Write-Output "[Info]  Current Version: Microsoft.Graph v$CurrentVersion"
}
else
{
    Write-Output "[Info]  PowerShell module 'Microsoft.Graph' NOT found."
    $CurrentVersion = $null
}

# Determining latest release on GitHub
$Repository = "microsoftgraph/msgraph-sdk-powershell"
$Releases = "https://api.github.com/repos/$Repository/releases"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Response = (Invoke-WebRequest -Uri $Releases -UseBasicParsing | ConvertFrom-Json)[0]
$Tag = $Response.tag_name
$Published = $Response.published_at
$ReleaseDate = $Published.split('T')[0]

if ($CurrentVersion)
{
    Write-Output "[Info]  Latest Release:  Microsoft.Graph v$Tag ($ReleaseDate)"
}
else
{
    Write-Output "[Info]  Latest Release: Microsoft.Graph v$Tag ($ReleaseDate)"
}

# Check if Microsoft.Graph needs to be downloaded/updated via PowerShell Gallery
if ($CurrentVersion -ne $Tag -Or $null -eq $CurrentVersion)
{
    if ($null -eq $CurrentVersion)
    {
        Write-Output "[Info]  Installing PowerShell module 'Microsoft.Graph' ..."
        Install-Module -Name Microsoft.Graph -Repository PSGallery -Force
    }
    else
    {
        Write-Output "[Info]  Updating PowerShell module 'Microsoft.Graph' ..."
        Uninstall-Module -Name Microsoft.Graph -AllVersions
        Install-Module -Name Microsoft.Graph -Repository PSGallery -Force
    }
}
else
{
    Write-Host "[Info]  You are running the most recent version of Microsoft.Graph." -ForegroundColor Green
}

}

#############################################################################################################################################################################################

Function Get-MicrosoftGraphBeta {

# Microsoft.Graph.Beta
# https://github.com/microsoftgraph/msgraph-sdk-powershell
# Note: Requirement for Get-ADSignInLogs.

# Check if PowerShell module 'Microsoft.Graph.Beta' exists
if (Get-Module -ListAvailable -Name Microsoft.Graph.Beta) 
{
    # Check Current Version
    $CurrentVersion = (Get-Module -ListAvailable -Name Microsoft.Graph.Beta).Version.ToString()
    Write-Output "[Info]  Current Version: Microsoft.Graph.Beta v$CurrentVersion"
}
else
{
    Write-Output "[Info]  PowerShell module 'Microsoft.Graph.Beta' NOT found."
    $CurrentVersion = $null
}

# Determining latest release on GitHub
$Repository = "microsoftgraph/msgraph-sdk-powershell"
$Releases = "https://api.github.com/repos/$Repository/releases"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Response = (Invoke-WebRequest -Uri $Releases -UseBasicParsing | ConvertFrom-Json)[0]
$Tag = $Response.tag_name
$Published = $Response.published_at
$ReleaseDate = $Published.split('T')[0]

if ($CurrentVersion)
{
    Write-Output "[Info]  Latest Release:  Microsoft.Graph.Beta v$Tag ($ReleaseDate)"
}
else
{
    Write-Output "[Info]  Latest Release: Microsoft.Graph.Beta v$Tag ($ReleaseDate)"
}

# Check if Microsoft.Graph.Beta needs to be downloaded/updated via PowerShell Gallery
if ($CurrentVersion -ne $Tag -Or $null -eq $CurrentVersion)
{
    if ($null -eq $CurrentVersion)
    {
        Write-Output "[Info]  Installing PowerShell module 'Microsoft.Graph.Beta' ..."
        Install-Module -Name Microsoft.Graph.Beta -Repository PSGallery -Force
    }
    else
    {
        Write-Output "[Info]  Updating PowerShell module 'Microsoft.Graph.Beta' ..."
        Uninstall-Module -Name Microsoft.Graph.Beta -AllVersions
        Install-Module -Name Microsoft.Graph.Beta -Repository PSGallery -Force
    }
}
else
{
    Write-Host "[Info]  You are running the most recent version of Microsoft.Graph.Beta." -ForegroundColor Green
}

}

#############################################################################################################################################################################################

# Main
InternetConnectivityCheck
Get-MicrosoftExtractorSuite
Get-ImportExcel
Get-IPinfo
Get-XSV
Get-Az
Get-AzureADPreview
Get-ExchangeOnlineManagement
Get-MicrosoftGraph
Get-MicrosoftGraphBeta

#endregion Updater

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Footer

# Get End Time
$endTime = (Get-Date)

# Echo Time elapsed
Write-Output ""
Write-Output "FINISHED!"

$Time = ($endTime-$startTime)
$ElapsedTime = ('Overall update duration: {0} h {1} min {2} sec' -f $Time.Hours, $Time.Minutes, $Time.Seconds)
Write-Output "$ElapsedTime"

# Reset Progress Preference
$Global:ProgressPreference = $OriginalProgressPreference

# Reset Windows Title
$Host.UI.RawUI.WindowTitle = "$DefaultWindowsTitle"

#endregion Footer

#############################################################################################################################################################################################
#############################################################################################################################################################################################
