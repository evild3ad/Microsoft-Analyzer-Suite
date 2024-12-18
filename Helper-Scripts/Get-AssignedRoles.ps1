Function Get-AssignedRoles {

<#
.SYNOPSIS
  Get-AssignedRoles - List Microsoft Entra Role Assignments for a specific user

.DESCRIPTION
  The Get-AssignedRoles cmdlet lists the Microsoft Entra role assignments for a specific user.

  Import-Module .\Get-AssignedRoles.ps1

.PARAMETER UserId
  Specifies the UserId or User Principal Name (UPN) as primary target.

.PARAMETER FilePath (Optional)
  Specifies the path to the output file. The output is displayed in the console by default.

.EXAMPLE
  Get-AssignedRoles -UserId "<UPN>"

.EXAMPLE
  Get-AssignedRoles -UserId "<UPN>" -FilePath "$env:USERPROFILE\Desktop\AssignedRoles.txt"

.NOTES
  Author - Martin Willing

.LINK
  https://lethal-forensics.com/
#>

[CmdletBinding()]
Param(
    [string]$UserId,
    [string]$FilePath
)

# UserId
if ($UserId)
{
    if (($UserId -notmatch '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') -and ($UserId -notmatch '^([\w-\.]+)(#EXT#)?@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.)|(([\w-]+\.)+))([a-zA-Z]{2,4}|[0-9]{1,3})(\]?)$'))
    {
        Write-Host "[Error] You must provide a valid UserId or User Principal Name (UPN)." -ForegroundColor Red
        Exit
    }
}
else
{
    Write-Host "[Error] You must provide a UserId or User Principal Name (UPN)." -ForegroundColor Red
}

# File Path
if ($FilePath)
{
    if (!(Test-Path -IsValid -Path $FilePath))
    {
        Write-Host "[Error] You must provide a valid file path." -ForegroundColor Red
        Exit
    }
    else
    {
        $OutputDir = Split-Path -Path $FilePath -Parent

        if (!(Test-Path $OutputDir))
        {
            New-Item "$OutputDir" -ItemType Directory -Force | Out-Null
        }
    }
}

# Check if PowerShell module 'Microsoft.Graph' exists
if (!(Get-Module -ListAvailable -Name Microsoft.Graph))
{
    Write-Host "[Error] PowerShell module 'Microsoft.Graph' NOT found." -ForegroundColor Red
    Exit
}

# Already connected?
if (!($null -eq (Get-MgContext)))
{
    # Microsoft Graph PowerShell Module
    try {
        Write-Output "[Info]  Authentication via Microsoft Graph initiated ..."
        Connect-MgGraph -Scopes "RoleManagement.Read.Directory,User.Read.All" -NoWelcome -ErrorAction Stop

        if (!($null -eq (Get-MgContext)))
        {
            Write-Output "[Info]  Authentication complete."
        }
    }
    catch  {
        Write-Host "$_.Exception.Message" -ForegroundColor Yellow
        Write-Host "[Error] Unable to connect to Microsoft Graph! Exiting ..." -ForegroundColor Red
        Exit
    }
}

# Retrieve all activated directoryRole objects
$DirectoryRoles = Get-MgDirectoryRole -All | Select-Object -Property Id,DisplayName,Description

$AssignedRoles = @()

foreach ($Role in $DirectoryRoles) {
    $RoleId = $Role.Id
    $RoleName = $Role.DisplayName
    $RoleDescription = $Role.Description

    # Retrieve the list of principals that are assigned to the directory role
    $Principals = Get-MgDirectoryRoleMember -DirectoryRoleId $RoleId

    foreach ($Principal in $Principals) {
        # Retrieve properties and relationships of the user object
        $UserDetails = Get-MgUser -UserId $Principal.Id | Select-Object DisplayName,UserPrincipalName

        $AssignedRoles += [PSCustomObject]@{
            DisplayName       = $UserDetails.DisplayName
            UserPrincipalName = $UserDetails.UserPrincipalName
            UserId            = $Principal.Id
            RoleName          = $RoleName
            Description       = $RoleDescription
        }
    }
}

$Results = $AssignedRoles | Where-Object { $_.UserPrincipalName -eq "$UserId" }

# Results
if (!($FilePath))
{
    return $Results
}
else
{
    $Results | Out-File $FilePath -Encoding UTF8
    Write-Host "[Info]  Output written to '$FilePath'"
}

# Cleaning up
Clear-Variable -Name "FilePath"

}