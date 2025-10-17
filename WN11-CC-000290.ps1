<#
.SYNOPSIS
  Remediates STIG ID: WN11-CC-000290 by configuring Remote Desktop Services
  with the client connection encryption level set to "High Level".

.NOTES
  STIG ID: WN11-CC-000290
  SRG: SRG-OS-000033-GPOS-00014
  Severity: Medium
  CCI: CCI-000068
  Vulnerability ID: V-253406
  Title: Remote Desktop Services must be configured with the client connection encryption set to the required level.
  Discussion: Remote connections must be encrypted to prevent interception of data or sensitive information. 
              Selecting "High Level" ensures encryption of Remote Desktop Services sessions in both directions.
  Date: 2025-10-10
  Author: No Lack LLC

.TESTED ON
  Windows 11 Pro x64 (Build 22631)

.USAGE
  Save this script as: Remediate-WN11-CC-000290.ps1
  Run PowerShell as Administrator:
    PS C:\> .\Remediate-WN11-CC-000290.ps1
#>

# ---------------------------- SCRIPT START ---------------------------- #

Write-Host "`n[INFO] Checking Remote Desktop Services encryption level policy..." -ForegroundColor Cyan

# Define the registry path and required value
$RegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
$RegName = "MinEncryptionLevel"
$RequiredValue = 3  # High Level

# Ensure the registry path exists
if (-not (Test-Path $RegPath)) {
    Write-Host "[ACTION] Registry path not found. Creating path: $RegPath" -ForegroundColor Yellow
    New-Item -Path $RegPath -Force | Out-Null
}

# Check current setting
try {
    $CurrentValue = Get-ItemProperty -Path $RegPath -Name $RegName -ErrorAction Stop | Select-Object -ExpandProperty $RegName
    Write-Host "[INFO] Current MinEncryptionLevel value: $CurrentValue" -ForegroundColor Cyan
} catch {
    Write-Host "[WARN] Registry value not found. It will be created." -ForegroundColor Yellow
    $CurrentValue = $null
}

# Compare and remediate if needed
if ($CurrentValue -ne $RequiredValue) {
    Write-Host "[ACTION] Setting MinEncryptionLevel to High (3)..." -ForegroundColor Yellow
    New-ItemProperty -Path $RegPath -Name $RegName -Value $RequiredValue -PropertyType DWord -Force | Out-Null
    Write-Host "[SUCCESS] MinEncryptionLevel successfully set to 3 (High Level)." -ForegroundColor Green
} else {
    Write-Host "[OK] MinEncryptionLevel is already set to 3 (High Level)." -ForegroundColor Green
}

# Verify configuration
$Verify = Get-ItemProperty -Path $RegPath -Name $RegName | Select-Object -ExpandProperty $RegName
if ($Verify -eq $RequiredValue) {
    Write-Host "`n[COMPLIANT] Remote Desktop Services encryption level is correctly configured." -ForegroundColor Green
} else {
    Write-Host "`n[NON-COMPLIANT] Failed to apply required encryption setting. Manual review recommended." -ForegroundColor Red
}

Write-Host "`n[COMPLETE] STIG Remediation: WN11-CC-000290" -ForegroundColor Cyan

# ---------------------------- SCRIPT END ---------------------------- #
