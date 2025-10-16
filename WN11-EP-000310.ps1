<#
.SYNOPSIS
    This PowerShell script ensures Kernel DMA Protection is configured to block all external devices incompatible with DMA protection.

.NOTES
    Author          : 
    LinkedIn        : 
    GitHub          : 
    Date Created    : 2024-10-16
    Last Modified   : 2024-10-16
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-EP-000310

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : Windows 10 / Windows 11
    PowerShell Ver. : 5.1 / 7.x

.USAGE
    Example:
    PS C:\> .\Remediate_WN11-EP-000310.ps1
#>

# Ensure the script is run as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Please run this script as Administrator." -ForegroundColor Red
    exit
}

Write-Host "Applying STIG Fix: Kernel DMA Protection - Block all incompatible external devices..." -ForegroundColor Cyan

# Define registry path and values
$regPath = "HKLM:\Software\Policies\Microsoft\Windows\Kernel DMA Protection"
$valueName = "DeviceEnumerationPolicy"
$desiredValue = 0

# Create the registry path if it doesn't exist
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
    Write-Host "Created registry path: $regPath"
}

# Apply the required registry setting
New-ItemProperty -Path $regPath -Name $valueName -Value $desiredValue -PropertyType DWORD -Force | Out-Null

# Verify the configuration
$currentValue = (Get-ItemProperty -Path $regPath -Name $valueName).$valueName
if ($currentValue -eq $desiredValue) {
    Write-Host "DeviceEnumerationPolicy successfully set to 0 (Block All)." -ForegroundColor Green
} else {
    Write-Host "Failed to set DeviceEnumerationPolicy. Current value: $currentValue" -ForegroundColor Red
}

Write-Host "Remediation complete for STIG ID WN11-EP-000310." -ForegroundColor Cyan
