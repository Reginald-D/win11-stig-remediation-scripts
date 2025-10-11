<#
.SYNOPSIS
Remediates Windows 11 DISA STIG finding for AlwaysInstallElevated (User and Computer Configuration).

.DESCRIPTION
Configures both Computer (HKLM) and User (HKCU) registry settings to disable Windows Installer
from granting elevated privileges to standard users, preventing unauthorized software installations
and privilege escalation.

STIG ID: WN11-CC-000315
Registry Paths:
HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer
HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer
Value Name: AlwaysInstallElevated
Value Type: REG_DWORD
Expected Value: 0 (Disabled)
#>

# Ensure script is run as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Please run this script as Administrator." -ForegroundColor Red
    exit
}

Write-Host "Starting remediation for AlwaysInstallElevated..." -ForegroundColor Cyan

# Define registry paths
$targets = @(
    "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer",
    "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer"
)

$valueName = "AlwaysInstallElevated"
$desiredValue = 0

foreach ($regPath in $targets) {
    if (-not (Test-Path $regPath)) {
        New-Item -Path $regPath -Force | Out-Null
        Write-Host "Created registry path: $regPath"
    }

    try {
        New-ItemProperty -Path $regPath -Name $valueName -Value $desiredValue -PropertyType DWORD -Force | Out-Null
        $currentValue = (Get-ItemProperty -Path $regPath -Name $valueName).$valueName

        if ($currentValue -eq $desiredValue) {
            Write-Host "$valueName successfully set to 0 in $regPath" -ForegroundColor Green
        } else {
            Write-Host "Failed to set $valueName in $regPath (Current value: $currentValue)" -ForegroundColor Red
        }
    } catch {
        Write-Host "Error modifying ${regPath} $_" -ForegroundColor Red
    }
}

Write-Host "Remediation complete. AlwaysInstallElevated is now disabled for both User and Computer configurations." -ForegroundColor Cyan
