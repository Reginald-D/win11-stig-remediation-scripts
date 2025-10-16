<#
.SYNOPSIS
    This PowerShell script ensures that only Administrators have the "Debug programs" user right, 
    as required by the Windows 11 DISA STIG (WN11-UR-000065).

.NOTES
    Author          : 
    LinkedIn        : 
    GitHub          : 
    Date Created    : 2025-10-16
    Last Modified   : 2025-10-16
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-UR-000065

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : Windows 11
    PowerShell Ver. : 5.1, 7.x

.USAGE
    Example:
    PS C:\> .\Remediate_DebugPrograms.ps1
#>

# Ensure script is run as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Please run this script as Administrator."
    exit
}

Write-Host "Remediating 'Debug Programs' user right..." -ForegroundColor Cyan

# Define constants
$privilege = "SeDebugPrivilege"
$allowedAccount = "*S-1-5-32-544"  # SID for Administrators group

# Import the necessary security module
try {
    secedit /export /cfg "$env:TEMP\secpol.cfg" > $null
    (Get-Content "$env:TEMP\secpol.cfg") |
        ForEach-Object {
            if ($_ -match "^$privilege") {
                "$privilege = $allowedAccount"
            } else {
                $_
            }
        } | Set-Content "$env:TEMP\secpol.cfg"

    # Apply the configuration
    secedit /configure /db "$env:TEMP\secedit.sdb" /cfg "$env:TEMP\secpol.cfg" /areas USER_RIGHTS > $null

    Write-Host "'Debug Programs' right successfully set to Administrators only." -ForegroundColor Green
}
catch {
    Write-Host "Error applying policy: $($_.Exception.Message)" -ForegroundColor Red
}
finally {
    # Cleanup
    Remove-Item "$env:TEMP\secpol.cfg","$env:TEMP\secedit.sdb" -ErrorAction SilentlyContinue
}
