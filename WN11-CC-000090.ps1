<#
.SYNOPSIS
Remediates STIG ID WN11-CC-000090 - Enables "Configure registry policy processing" 
and selects "Process even if the Group Policy objects have not changed".

.DESCRIPTION
This script configures the registry to ensure Group Policy processing is forced 
on every refresh, even if no policy changes are detected. This ensures 
unauthorized changes are corrected during policy updates.

STIG ID: WN11-CC-000090
Registry Path: HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}
Value Name: NoGPOListChanges
Value Type: REG_DWORD
Expected Value: 0
#>

# Check if running as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Please run this script as Administrator." -ForegroundColor Red
    exit
}

Write-Host "Applying STIG fix for 'Configure registry policy processing'..." -ForegroundColor Cyan

# Define registry path and values
$regPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Group Policy\{35378EAC-683F-11D2-A89A-00C04FBBCFA2}"
$valueName = "NoGPOListChanges"
$desiredValue = 0

# Create registry path if missing
if (-not (Test-Path $regPath)) {
    New-Item -Path $regPath -Force | Out-Null
    Write-Host "Created registry path: $regPath"
}

# Set registry value to enforce policy processing
New-ItemProperty -Path $regPath -Name $valueName -Value $desiredValue -PropertyType DWORD -Force | Out-Null

# Verify result
$currentValue = (Get-ItemProperty -Path $regPath -Name $valueName).$valueName
if ($currentValue -eq $desiredValue) {
    Write-Host "Registry policy processing configured correctly (Process even if GPOs have not changed)." -ForegroundColor Green
} else {
    Write-Host "Failed to configure registry policy processing. Current value: $currentValue" -ForegroundColor Red
}

Write-Host "Remediation complete for STIG ID WN11-CC-000090." -ForegroundColor Cyan
