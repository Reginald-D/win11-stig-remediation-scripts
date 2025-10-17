<#
.SYNOPSIS
    This PowerShell script disables Windows Game Recording and Broadcasting for Windows 11
    to comply with DISA STIG requirements.

.NOTES
    Author          : 
    LinkedIn        : 
    GitHub          : 
    Date Created    : 2025-10-16
    Last Modified   : 2025-10-16
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-CC-000252

.TESTED ON
    Date(s) Tested  : 2025-10-16
    Tested By       : 
    Systems Tested  : Windows 11 Pro / Enterprise
    PowerShell Ver. : 5.1 / 7.x

.USAGE
    Run this script as Administrator.
    Example:
        PS C:\> .\Remediate-WN11-CC-000252.ps1
#>

# Ensure script runs with administrative privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Please run this script as Administrator."
    exit
}

Write-Host "`nApplying STIG remediation for: WN11-CC-000252 (Disable Game Recording and Broadcasting)..."

# Define registry path and value
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR"
$valueName = "AllowGameDVR"
$desiredValue = 0

# Create the registry path if missing
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
    Write-Host "Created registry key: $regPath"
}

# Set the policy value
New-ItemProperty -Path $regPath -Name $valueName -Value $desiredValue -PropertyType DWORD -Force | Out-Null

# Verify configuration
$currentValue = (Get-ItemProperty -Path $regPath -Name $valueName).$valueName

if ($currentValue -eq $desiredValue) {
    Write-Host "Remediation successful. Windows Game Recording and Broadcasting is disabled."
} else {
    Write-Host "Remediation failed. Current registry value: $currentValue"
}

Write-Host "Remediation complete for STIG ID: WN11-CC-000252" -ForegroundColor Cyan
