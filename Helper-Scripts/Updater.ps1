# Microsoft-Analyzer-Suite Updater v0.3
#
# @author:    Martin Willing
# @copyright: Copyright (c) 2025 Martin Willing. All rights reserved.
# @contact:   Any feedback or suggestions are always welcome and much appreciated - mwilling@lethal-forensics.com
# @url:       https://lethal-forensics.com/
# @date:      2025-01-01
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
# Version 0.3
# Release Date: 2025-01-02
# Added: Microsoft-Analyzer-Suite Updater
# Added: PowerShell 7 Support
# Fixed: Minor fixes and improvements
#
#
# Tested on Windows 10 Pro (x64) Version 22H2 (10.0.19045.5247) and PowerShell 5.1 (5.1.19041.5247)
# Tested on Windows 10 Pro (x64) Version 22H2 (10.0.19045.5247) and PowerShell 7.4.6
#
#
#############################################################################################################################################################################################
#############################################################################################################################################################################################

<#
.SYNOPSIS
  Microsoft-Analyzer-Suite Updater v0.3 - Automated Installer/Updater for the Microsoft-Analyzer-Suite

.DESCRIPTION
  Updater.ps1 is a PowerShell script utilized to automate the installation and the update process of the "Microsoft-Analyzer-Suite" (incl. all dependencies).

  https://github.com/evild3ad/Microsoft-Analyzer-Suite

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
$Global:ProgressPreference = 'SilentlyContinue'

#endregion Initialisations

#############################################################################################################################################################################################
#############################################################################################################################################################################################

#region Declarations

# Declarations

# Script Root
$script:SCRIPT_DIR = $PSScriptRoot

# Parent Directory
$Script:PARENT_DIR = Split-Path $SCRIPT_DIR -Parent

# Tools

# IPinfo CLI
$script:IPinfo = "$PARENT_DIR\Tools\IPinfo\ipinfo.exe"

# Microsoft-Analyzer-Suite
$script:MicrosoftAnalyzerSuite = "$PARENT_DIR\CHANGELOG.md"

# xsv
$script:xsv = "$PARENT_DIR\Tools\xsv\xsv.exe"

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

# PowerShell Version Check
if (!(($PSVersionTable.PSVersion.Major -eq "5") -or ($PSVersionTable.PSVersion.Major -eq "7")))
{
    Write-Host "[Error] This script requires Windows PowerShell 5.1 or PowerShell v7.x." -ForegroundColor Red
    Exit
}

# Windows Title
$DefaultWindowsTitle = $Host.UI.RawUI.WindowTitle
$Host.UI.RawUI.WindowTitle = "Microsoft Analyzer Suite Updater v0.3 - Automated Installer/Updater for the Microsoft-Analyzer-Suite"

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
Write-Output "Microsoft-Analyzer-Suite Updater v0.3 - Automated Installer/Updater for the Microsoft-Analyzer-Suite"
Write-Output "(c) 2025 Martin Willing at Lethal-Forensics (https://lethal-forensics.com/)"
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

Function Get-MicrosoftAnalyzerSuite {

# Microsoft-Analyzer-Suite (MAS)
# https://github.com/evild3ad/Microsoft-Analyzer-Suite

# Check Current Version of Microsoft-Analyzer-Suite
if (Test-Path "$($MicrosoftAnalyzerSuite)")
{
    $CurrentVersion = (Get-Content -Path "$PARENT_DIR\CHANGELOG.md" | Select-String -Pattern '(?<=\[)[^]]+(?=\])' -AllMatches).Matches.Value | Select-Object -First 1
    $Current = [System.Version]::new($CurrentVersion)
    $LastUpdate = (Get-Content -Path "$PARENT_DIR\CHANGELOG.md" | Select-String -Pattern '[0-9]{4}\-[0-9]{2}\-[0-9]{2}' -AllMatches).Matches.Value | Select-Object -First 1
    Write-Output "[Info]  Current Version: Microsoft-Analyzer-Suite v$CurrentVersion ($LastUpdate)"
}
else
{
    Write-Output "[Info]  Microsoft-Analyzer-Suite NOT found."
    $CurrentVersion = $null
}

# Determining latest release on GitHub
$Repository = "evild3ad/Microsoft-Analyzer-Suite"
$Releases = "https://api.github.com/repos/$Repository/releases"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Response = (Invoke-WebRequest -Uri $Releases -UseBasicParsing | ConvertFrom-Json)[0]
$Tag = $Response.tag_name
$LatestVersion = $Tag.Substring(1)
$Latest = [System.Version]::new($LatestVersion)
$Published = $Response.published_at

if ($Published -is [String])
{
    $ReleaseDate = $Published.split('T')[0] # Windows PowerShell
}
else
{
    $ReleaseDate = $Published.ToString("yyyy-MM-dd") # PowerShell 7
}

$Download = ($Response | Select-Object -ExpandProperty zipball_url | Out-String).Trim()

if ($CurrentVersion)
{
    Write-Output "[Info]  Latest Release:  Microsoft-Analyzer-Suite v$LatestVersion ($ReleaseDate)"
}
else
{
    Write-Output "[Info]  Latest Release: Microsoft-Analyzer-Suite v$LatestVersion ($ReleaseDate)"
}

# Check if 'Microsoft-Analyzer-Suite' needs to be downloaded/updated
if ($Current -lt $Latest -Or $null -eq $CurrentVersion)
{
    $CurrentDirectory = Get-Location
    $ParentDirectory  = Split-Path $CurrentDirectory -Parent
    $NewDirectory     = Split-Path $ParentDirectory -Parent

    Set-Location $NewDirectory

    Write-Output "[Info]  Dowloading Latest Release ..."
    $Zip = "Microsoft-Analyzer-Suite.zip"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $Download -OutFile "$NewDirectory\$Zip"

    if (Test-Path "$NewDirectory\$Zip")
    {
        # Delete Directory Content and Remove Directory
        if (Test-Path "$NewDirectory\Microsoft-Analyzer-Suite")
        {
            Get-ChildItem -Path "$NewDirectory\Microsoft-Analyzer-Suite" -Recurse | Remove-Item -Force -Recurse
            Remove-Item "$NewDirectory\Microsoft-Analyzer-Suite" -Force
        }

        # Unpacking Archive File
        Write-Output "[Info]  Extracting Files ..."
        Expand-Archive -Path "$NewDirectory\$Zip" -DestinationPath "$NewDirectory" -Force

        # Rename Unpacked Directory
        Start-Sleep 5
        $Directory = (Get-ChildItem -Path "$NewDirectory\evild3ad-Microsoft-Analyzer-Suite-*").FullName
        Rename-Item "$Directory" "$NewDirectory\Microsoft-Analyzer-Suite" -Force

        # Remove Downloaded Archive
        Start-Sleep 5
        Remove-Item "$NewDirectory\$Zip" -Force
    }

    Set-Location $CurrentDirectory
}
else
{
    Write-Host "[Info]  You are running the most recent version of Microsoft-Analyzer-Suite." -ForegroundColor Green
}

}

#############################################################################################################################################################################################

Function Get-MicrosoftExtractorSuite {

# Microsoft-Extractor-Suite (MES)
# https://github.com/invictus-ir/Microsoft-Extractor-Suite
# https://www.powershellgallery.com/packages/Microsoft-Extractor-Suite/

# PowerShell 7
if ($PSVersionTable.PSVersion.Major -eq "7")
{
    # Check if PowerShell module 'Microsoft-Extractor-Suite' exists
    if (Get-Module -ListAvailable -Name Microsoft-Extractor-Suite | Where-Object { $_.Path -notmatch "WindowsPowerShell"}) 
    {
        # Check if multiple versions of PowerShell module 'Microsoft-Extractor-Suite' exist
        $Modules = (Get-Module -ListAvailable -Name Microsoft-Extractor-Suite | Where-Object { $_.Path -notmatch "WindowsPowerShell"} | Measure-Object).Count

        if ($Modules -eq "1")
        {
            # Check Current Version
            $CurrentVersion = (Get-Module -ListAvailable -Name Microsoft-Extractor-Suite | Where-Object { $_.Path -notmatch "WindowsPowerShell"}).Version.ToString()
            $Current = [System.Version]::new($CurrentVersion)
            Write-Output "[Info]  Current Version: Microsoft-Extractor-Suite v$CurrentVersion"
        }
        else
        {
            Write-Host "[Info]  Multiple installed versions of PowerShell module 'Microsoft-Extractor-Suite' found. Uninstalling ..."
            Uninstall-Module -Name Microsoft-Extractor-Suite -AllVersions -ErrorAction SilentlyContinue
            $CurrentVersion = $null
        }
    }
    else
    {
        Write-Output "[Info]  PowerShell module 'Microsoft-Extractor-Suite' NOT found."
        $CurrentVersion = $null
    }
}

# PowerShell 5.1
if ($PSVersionTable.PSVersion.Major -eq "5")
{
    # Check if PowerShell module 'Microsoft-Extractor-Suite' exists
    if (Get-Module -ListAvailable -Name Microsoft-Extractor-Suite) 
    {
        # Check if multiple versions of PowerShell module 'Microsoft-Extractor-Suite' exist
        $Modules = (Get-Module -ListAvailable -Name Microsoft-Extractor-Suite | Measure-Object).Count

        if ($Modules -eq "1")
        {
            # Check Current Version
            $CurrentVersion = (Get-Module -ListAvailable -Name Microsoft-Extractor-Suite).Version.ToString()
            $Current = [System.Version]::new($CurrentVersion)
            Write-Output "[Info]  Current Version: Microsoft-Extractor-Suite v$CurrentVersion"
        }
        else
        {
            Write-Host "[Info]  Multiple installed versions of PowerShell module 'Microsoft-Extractor-Suite' found. Uninstalling ..."
            Uninstall-Module -Name Microsoft-Extractor-Suite -AllVersions -ErrorAction SilentlyContinue
            $CurrentVersion = $null
        }
    }
    else
    {
        Write-Output "[Info]  PowerShell module 'Microsoft-Extractor-Suite' NOT found."
        $CurrentVersion = $null
    }
}

# Determining latest version in PSGallery
$MES = Find-Module -Name Microsoft-Extractor-Suite -WarningAction SilentlyContinue
$LatestRelease = ($MES).Version.ToString()
$Latest = [System.Version]::new($LatestRelease)
$PublishedDate = ($MES | Select-Object -ExpandProperty PublishedDate).ToString("yyyy-MM-dd")

if ($CurrentVersion)
{
    Write-Output "[Info]  Latest Release:  Microsoft-Extractor-Suite v$LatestRelease ($PublishedDate)"
}
else
{
    Write-Output "[Info]  Latest Release: Microsoft-Extractor-Suite v$LatestRelease ($PublishedDate)"
}

# Check if 'Microsoft-Analyzer-Suite' needs to be downloaded/updated via PowerShell Gallery
if ($Current -lt $Latest -Or $null -eq $CurrentVersion)
{
    if ($null -eq $CurrentVersion)
    {
        Write-Output "[Info]  Installing PowerShell module 'Microsoft-Extractor-Suite' ..."
        Install-Module -Name Microsoft-Extractor-Suite -Repository PSGallery -AllowClobber -Force
    }
    else
    {
        Write-Output "[Info]  Updating PowerShell module 'Microsoft-Extractor-Suite' ..."
        Uninstall-Module -Name Microsoft-Extractor-Suite -AllVersions
        Install-Module -Name Microsoft-Extractor-Suite -Repository PSGallery -AllowClobber -Force
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
# https://www.powershellgallery.com/packages/ImportExcel

# PowerShell 7
if ($PSVersionTable.PSVersion.Major -eq "7")
{
    # Check if PowerShell module 'ImportExcel' exists
    if (Get-Module -ListAvailable -Name ImportExcel | Where-Object { $_.Path -notmatch "WindowsPowerShell"}) 
    {
        # Check if multiple versions of PowerShell module 'ImportExcel' exist
        $Modules = (Get-Module -ListAvailable -Name ImportExcel | Where-Object { $_.Path -notmatch "WindowsPowerShell"} | Measure-Object).Count

        if ($Modules -eq "1")
        {
            # Check Current Version
            $CurrentVersion = (Get-Module -ListAvailable -Name ImportExcel | Where-Object { $_.Path -notmatch "WindowsPowerShell"}).Version.ToString()
            $Current = [System.Version]::new($CurrentVersion)
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
}

# PowerShell 5.1
if ($PSVersionTable.PSVersion.Major -eq "5")
{
    # Check if PowerShell module 'ImportExcel' exists
    if (Get-Module -ListAvailable -Name ImportExcel) 
    {
        # Check if multiple versions of PowerShell module 'ImportExcel' exist
        $Modules = (Get-Module -ListAvailable -Name ImportExcel | Measure-Object).Count

        if ($Modules -eq "1")
        {
            # Check Current Version
            $CurrentVersion = (Get-Module -ListAvailable -Name ImportExcel).Version.ToString()
            $Current = [System.Version]::new($CurrentVersion)
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
}

# Determining latest version in PSGallery
$ImportExcel = Find-Module -Name ImportExcel -WarningAction SilentlyContinue
$LatestRelease = ($ImportExcel).Version.ToString()
$Latest = [System.Version]::new($LatestRelease)
$PublishedDate = ($ImportExcel | Select-Object -ExpandProperty PublishedDate).ToString("yyyy-MM-dd")

if ($CurrentVersion)
{
    Write-Output "[Info]  Latest Release:  ImportExcel v$LatestRelease ($PublishedDate)"
}
else
{
    Write-Output "[Info]  Latest Release: ImportExcel v$LatestRelease ($PublishedDate)"
}

# Check if ImportExcel needs to be installed
if ($null -eq $CurrentVersion)
{
    Write-Output "[Info]  Installing ImportExcel v$LatestRelease ..."
    Install-Module -Name ImportExcel -Repository PSGallery -Force
    $CurrentVersion = (Get-Module -ListAvailable -Name ImportExcel).Version.ToString()
}

# Check if ImportExcel needs to be updated
if ($Current -lt $Latest)
{
    # Update PowerShell module 'ImportExcel'
    try
    {
        Write-Output "[Info]  Updating PowerShell module 'ImportExcel' ..."
        Uninstall-Module -Name ImportExcel -AllVersions -Force
        Install-Module -Name ImportExcel -Repository PSGallery -Force
    }
    catch
    {
        Write-Output "PowerShell module 'ImportExcel' is in use. Please close all PowerShell sessions, and run 'Updater.ps1' again."
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
    $Current = [System.Version]::new($CurrentVersion)
    Write-Output "[Info]  Current Version: IPinfo CLI v$CurrentVersion"
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
$LatestRelease = $TagName.Split("-")[1]
$Latest = [System.Version]::new($LatestRelease)
$Published = $Response[$Asset].published_at

if ($Published -is [String])
{
    $ReleaseDate = $Published.split('T')[0] # Windows PowerShell
}
else
{
    $ReleaseDate = $Published.ToString("yyyy-MM-dd") # PowerShell 7
}

$Download = ($Response[$Asset].assets | Select-Object -ExpandProperty browser_download_url | Select-String -Pattern "windows_amd64" | Out-String).Trim()

if ($CurrentVersion)
{
    Write-Output "[Info]  Latest Release:  IPinfo CLI v$LatestRelease ($ReleaseDate)"
}
else
{
    Write-Output "[Info]  Latest Release: IPinfo CLI v$LatestRelease ($ReleaseDate)"
}

# Check if IPinfo CLI needs to be downloaded/updated
if ($Current -lt $Latest -Or $null -eq $CurrentVersion)
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
    $Current = [System.Version]::new($CurrentVersion)
    Write-Output "[Info]  Current Version: xsv v$CurrentVersion"
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
$LatestRelease = $Response.tag_name
$Latest = [System.Version]::new($LatestRelease)
$Published = $Response.published_at

if ($Published -is [String])
{
    $ReleaseDate = $Published.split('T')[0] # Windows PowerShell
}
else
{
    $ReleaseDate = $Published.ToString("yyyy-MM-dd") # PowerShell 7
}

$Download = ($Response.assets | Select-Object -ExpandProperty browser_download_url | Select-String -Pattern "-x86_64-pc-windows-msvc" | Out-String).Trim()

if ($CurrentVersion)
{
    Write-Output "[Info]  Latest Release:  xsv v$LatestRelease ($ReleaseDate)"
}
else
{
    Write-Output "[Info]  Latest Release: xsv v$LatestRelease ($ReleaseDate)"
}

# Check if xsv needs to be downloaded/updated
if ($Current -lt $Latest -Or $null -eq $CurrentVersion)
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

# PowerShell 5.1
if ($PSVersionTable.PSVersion.Major -eq "5")
{
    # Check if 'Azure PowerShell' modules exist
    if (!(Get-Module -ListAvailable -Name Az.*))
    {
        Write-Output "[Info]  Collection of 'Azure PowerShell' modules NOT found."
        $CurrentVersion = $null
    }
    else
    {
        $CurrentVersion = "UNKNOWN"
    }
}

# PowerShell 7
if ($PSVersionTable.PSVersion.Major -eq "7")
{
    # Check if 'Azure PowerShell' modules exist
    if (Get-Module -ListAvailable -Name Az.* | Where-Object { $_.Path -notmatch "WindowsPowerShell"})
    {
        # Check Current Version
        $CurrentVersion = (Get-Module -ListAvailable Az | Where-Object { $_.Path -notmatch "WindowsPowerShell"}).Version.ToString()
        $Current = [System.Version]::new($CurrentVersion)
        Write-Output "[Info]  Current Version: Azure PowerShell v$CurrentVersion"
    }
    else
    {
        Write-Output "[Info]  Collection of 'Azure PowerShell' modules NOT found."
        $CurrentVersion = $null
    }
}

# Determining latest version in PSGallery
$Az = Find-Module -Name Az -WarningAction SilentlyContinue
$LatestVersion = ($Az).Version.ToString()
$Latest = [System.Version]::new($LatestVersion)
$PublishedDate = ($Az | Select-Object -ExpandProperty PublishedDate).ToString("yyyy-MM-dd")

if ($CurrentVersion)
{
    Write-Output "[Info]  Latest Version:  Azure PowerShell v$LatestVersion ($PublishedDate)"
}
else
{
    Write-Output "[Info]  Latest Version: Azure PowerShell v$LatestVersion ($PublishedDate)"
}

# PowerShell 5.1
if ($PSVersionTable.PSVersion.Major -eq "5")
{
    # Install/Update via PSGallery
    if ($null -eq $CurrentVersion)
    {
        Write-Output "[Info]  Installing 'Azure PowerShell' modules [time-consuming task] ..."
        Install-Module -Name Az -Repository PSGallery -Force
    }
    else
    {
        Write-Output "[Info]  Current Version of 'Azure PowerShell' cannot be determined. Updating 'Azure PowerShell' modules [time-consuming task] ..."
        Uninstall-Module -Name Az -AllVersions
        Install-Module -Name Az -Repository PSGallery -Force
    }
}

# Check if 'Azure PowerShell' needs to be downloaded/updated
if ($PSVersionTable.PSVersion.Major -eq "7")
{
    if ($Current -lt $Latest -Or $null -eq $CurrentVersion)
    {
        if ($null -eq $CurrentVersion)
        {
            Write-Output "[Info]  Installing 'Azure PowerShell' modules [time-consuming task] ..."
            Install-Module -Name Az -Repository PSGallery -Force
        }
        else
        {
            Write-Output "[Info]  Updating 'Azure PowerShell' modules ..."
            Uninstall-Module -Name Az -AllVersions
            Install-Module -Name Az -Repository PSGallery -Force
        }
    }
    else
    {
        Write-Host "[Info]  You are running the most recent version of 'Azure PowerShell'." -ForegroundColor Green
    }
}

}

#############################################################################################################################################################################################

Function Get-AzureADPreview {

# AzureADPreview
# https://www.powershellgallery.com/packages/AzureADPreview/

# PowerShell 7
if ($PSVersionTable.PSVersion.Major -eq "7")
{
    # Check if PowerShell module 'AzureADPreview' exists
    if (Get-Module -ListAvailable -Name AzureADPreview | Where-Object { $_.Path -notmatch "WindowsPowerShell"}) 
    {
        # Check Current Version
        $CurrentVersion = (Get-Module -ListAvailable -Name AzureADPreview | Where-Object { $_.Path -notmatch "WindowsPowerShell"}).Version.ToString()
        $Current = [System.Version]::new($CurrentVersion)
        Write-Output "[Info]  Current Version: AzureADPreview v$CurrentVersion"
    }
    else
    {
        Write-Output "[Info]  PowerShell module 'AzureADPreview' NOT found."
        $CurrentVersion = $null
    }
}

# PowerShell 5.1
if ($PSVersionTable.PSVersion.Major -eq "5")
{
    # Check if PowerShell module 'AzureADPreview' exists
    if (Get-Module -ListAvailable -Name AzureADPreview) 
    {
        # Check Current Version
        $CurrentVersion = (Get-Module -ListAvailable -Name AzureADPreview).Version.ToString()
        $Current = [System.Version]::new($CurrentVersion)
        Write-Output "[Info]  Current Version: AzureADPreview v$CurrentVersion"
    }
    else
    {
        Write-Output "[Info]  PowerShell module 'AzureADPreview' NOT found."
        $CurrentVersion = $null
    }
}

# Determining latest version in PSGallery
$AzureADPreview = Find-Module -Name AzureADPreview -WarningAction SilentlyContinue
$LatestVersion = ($AzureADPreview).Version.ToString()
$Latest = [System.Version]::new($LatestVersion)
$PublishedDate = ($AzureADPreview | Select-Object -ExpandProperty PublishedDate).ToString("yyyy-MM-dd")

if ($CurrentVersion)
{
    Write-Output "[Info]  Latest Version:  AzureADPreview v$LatestVersion ($PublishedDate)"
}
else
{
    Write-Output "[Info]  Latest Version: AzureADPreview v$LatestVersion ($PublishedDate)"
}

# Check if 'AzureADPreview' needs to be downloaded/updated via PowerShell Gallery
if ($Current -lt $Latest -Or $null -eq $CurrentVersion)
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

# PowerShell 7
if ($PSVersionTable.PSVersion.Major -eq "7")
{
    # Check if PowerShell module 'ExchangeOnlineManagement' exists
    if (Get-Module -ListAvailable -Name ExchangeOnlineManagement | Where-Object { $_.Path -notmatch "WindowsPowerShell"}) 
    {
        # Check if multiple versions of PowerShell module 'ImportExcel' exist
        $Modules = (Get-Module -ListAvailable -Name ExchangeOnlineManagement | Where-Object { $_.Path -notmatch "WindowsPowerShell"} | Measure-Object).Count
        
        if ($Modules -eq "1")
        {
            # Check Current Version
            $CurrentVersion = (Get-Module -ListAvailable -Name ExchangeOnlineManagement | Where-Object { $_.Path -notmatch "WindowsPowerShell"}).Version.ToString()
            $Current = [System.Version]::new($CurrentVersion)
            Write-Output "[Info]  Current Version: ExchangeOnlineManagement v$CurrentVersion"
        }
        else
        {
            Write-Host "[Info]  Multiple installed versions of PowerShell module 'ExchangeOnlineManagement' found. Uninstalling ..."
            Uninstall-Module -Name ExchangeOnlineManagement -AllVersions -ErrorAction SilentlyContinue
            $CurrentVersion = $null
        }  
    }
    else
    {
        Write-Output "[Info]  PowerShell module 'ExchangeOnlineManagement' NOT found."
        $CurrentVersion = $null
    }
}

# PowerShell 5.1
if ($PSVersionTable.PSVersion.Major -eq "5")
{
    # Check if PowerShell module 'ExchangeOnlineManagement' exists
    if (Get-Module -ListAvailable -Name ExchangeOnlineManagement) 
    {
        # Check if multiple versions of PowerShell module 'ExchangeOnlineManagement' exist
        $Modules = (Get-Module -ListAvailable -Name ExchangeOnlineManagement | Measure-Object).Count

        if ($Modules -eq "1")
        {
            # Check Current Version
            $CurrentVersion = (Get-Module -ListAvailable -Name ExchangeOnlineManagement).Version.ToString()
            $Current = [System.Version]::new($CurrentVersion)
            Write-Output "[Info]  Current Version: ExchangeOnlineManagement v$CurrentVersion"
        }
        else
        {
            Write-Host "[Info]  Multiple installed versions of PowerShell module 'ExchangeOnlineManagement' found. Uninstalling ..."
            Uninstall-Module -Name ExchangeOnlineManagement -AllVersions -ErrorAction SilentlyContinue
            $CurrentVersion = $null
        }   
    }
    else
    {
        Write-Output "[Info]  PowerShell module 'ExchangeOnlineManagement' NOT found."
        $CurrentVersion = $null
    }
}

# Determining latest version in PSGallery
$ExchangeOnlineManagement = Find-Module -Name ExchangeOnlineManagement -WarningAction SilentlyContinue
$LatestVersion = ($ExchangeOnlineManagement).Version.ToString()
$Latest = [System.Version]::new($LatestVersion)
$PublishedDate = ($ExchangeOnlineManagement | Select-Object -ExpandProperty PublishedDate).ToString("yyyy-MM-dd")

if ($CurrentVersion)
{
    Write-Output "[Info]  Latest Version:  ExchangeOnlineManagement v$LatestVersion ($PublishedDate)"
}
else
{
    Write-Output "[Info]  Latest Version: ExchangeOnlineManagement v$LatestVersion ($PublishedDate)"
}

# Check if ExchangeOnlineManagement needs to be downloaded/updated via PowerShell Gallery
if ($Current -lt $Latest -Or $null -eq $CurrentVersion)
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

# PowerShell 7
if ($PSVersionTable.PSVersion.Major -eq "7")
{
    # Check if PowerShell module 'Microsoft.Graph' exists
    if (Get-Module -ListAvailable -Name Microsoft.Graph | Where-Object { $_.Path -notmatch "WindowsPowerShell"}) 
    {
        # Check Current Version
        $CurrentVersion = (Get-Module -ListAvailable -Name Microsoft.Graph | Where-Object { $_.Path -notmatch "WindowsPowerShell"}).Version.ToString()
        $Current = [System.Version]::new($CurrentVersion)
        Write-Output "[Info]  Current Version: Microsoft.Graph v$CurrentVersion"
    }
    else
    {
        Write-Output "[Info]  PowerShell module 'Microsoft.Graph' NOT found."
        $CurrentVersion = $null
    }
}

# PowerShell 5.1
if ($PSVersionTable.PSVersion.Major -eq "5")
{
    # Check if PowerShell module 'Microsoft.Graph' exists
    if (Get-Module -ListAvailable -Name Microsoft.Graph) 
    {
        # Check Current Version
        $CurrentVersion = (Get-Module -ListAvailable -Name Microsoft.Graph).Version.ToString()
        $Current = [System.Version]::new($CurrentVersion)
        Write-Output "[Info]  Current Version: Microsoft.Graph v$CurrentVersion"
    }
    else
    {
        Write-Output "[Info]  PowerShell module 'Microsoft.Graph' NOT found."
        $CurrentVersion = $null
    }
}

# Determining latest release on GitHub
$Repository = "microsoftgraph/msgraph-sdk-powershell"
$Releases = "https://api.github.com/repos/$Repository/releases"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Response = (Invoke-WebRequest -Uri $Releases -UseBasicParsing | ConvertFrom-Json)[0]
$LatestRelease = $Response.tag_name
$Latest = [System.Version]::new($LatestRelease)
$Published = $Response.published_at

if ($Published -is [String])
{
    $ReleaseDate = $Published.split('T')[0] # Windows PowerShell
}
else
{
    $ReleaseDate = $Published.ToString("yyyy-MM-dd") # PowerShell 7
}

if ($CurrentVersion)
{
    Write-Output "[Info]  Latest Release:  Microsoft.Graph v$LatestRelease ($ReleaseDate)"
}
else
{
    Write-Output "[Info]  Latest Release: Microsoft.Graph v$LatestRelease ($ReleaseDate)"
}

# Check if Microsoft.Graph needs to be downloaded/updated via PowerShell Gallery
if ($Current -lt $Latest -Or $null -eq $CurrentVersion)
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

# PowerShell 7
if ($PSVersionTable.PSVersion.Major -eq "7")
{
    # Check if PowerShell module 'Microsoft.Graph.Beta' exists
    if (Get-Module -ListAvailable -Name Microsoft.Graph.Beta | Where-Object { $_.Path -notmatch "WindowsPowerShell"}) 
    {
        # Check Current Version
        $CurrentVersion = (Get-Module -ListAvailable -Name Microsoft.Graph.Beta | Where-Object { $_.Path -notmatch "WindowsPowerShell"}).Version.ToString()
        $Current = [System.Version]::new($CurrentVersion)
        Write-Output "[Info]  Current Version: Microsoft.Graph.Beta v$CurrentVersion"
    }
    else
    {
        Write-Output "[Info]  PowerShell module 'Microsoft.Graph.Beta' NOT found."
        $CurrentVersion = $null
    }
}

# PowerShell 5.1
if ($PSVersionTable.PSVersion.Major -eq "5")
{
    # Check if PowerShell module 'Microsoft.Graph.Beta' exists
    if (Get-Module -ListAvailable -Name Microsoft.Graph.Beta) 
    {
        # Check Current Version
        $CurrentVersion = (Get-Module -ListAvailable -Name Microsoft.Graph.Beta).Version.ToString()
        $Current = [System.Version]::new($CurrentVersion)
        Write-Output "[Info]  Current Version: Microsoft.Graph.Beta v$CurrentVersion"
    }
    else
    {
        Write-Output "[Info]  PowerShell module 'Microsoft.Graph.Beta' NOT found."
        $CurrentVersion = $null
    }
}

# Determining latest release on GitHub
$Repository = "microsoftgraph/msgraph-sdk-powershell"
$Releases = "https://api.github.com/repos/$Repository/releases"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Response = (Invoke-WebRequest -Uri $Releases -UseBasicParsing | ConvertFrom-Json)[0]
$LatestRelease = $Response.tag_name
$Latest = [System.Version]::new($LatestRelease)
$Published = $Response.published_at

if ($Published -is [String])
{
    $ReleaseDate = $Published.split('T')[0] # Windows PowerShell
}
else
{
    $ReleaseDate = $Published.ToString("yyyy-MM-dd") # PowerShell 7
}

if ($CurrentVersion)
{
    Write-Output "[Info]  Latest Release:  Microsoft.Graph.Beta v$LatestRelease ($ReleaseDate)"
}
else
{
    Write-Output "[Info]  Latest Release: Microsoft.Graph.Beta v$LatestRelease ($ReleaseDate)"
}

# Check if Microsoft.Graph.Beta needs to be downloaded/updated via PowerShell Gallery
if ($Current -lt $Latest -Or $null -eq $CurrentVersion)
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
Get-MicrosoftAnalyzerSuite
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
