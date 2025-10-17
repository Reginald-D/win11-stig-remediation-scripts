<#
.SYNOPSIS
  Remediates STIG ID: WN11-AU-000010 by ensuring "Audit Credential Validation" 
  is configured to audit Success events on Windows 11 systems.

.NOTES
  STIG ID         : WN11-AU-000010
  SRG             : SRG-OS-000458-GPOS-00203
  Severity        : Medium
  CCI             : CCI-000172
  Vulnerability ID: V-253307
  Title           : The system must be configured to audit Account Logon - Credential Validation successes.
  Discussion      : Maintaining audit logs helps detect attacks, analyze compromises, 
                    and monitor system activity. This setting ensures Windows audits 
                    successful Credential Validation events.
  Date Created    : 2025-10-10
  Author          : Reginald D

.TESTED ON
  Date(s) Tested  : 2025-10-10
  Tested By       : Reginald D
  Systems Tested  : Windows 11 Pro x64 (Build 22631)
  PowerShell Ver. : 5.1+

.USAGE
  Save this script as: Remediate-WN11-AU-000010.ps1
  Run PowerShell as Administrator:
    PS C:\> .\Remediate-WN11-AU-000010.ps1
#>

Write-Host "`n[INFO] Checking audit policy for 'Credential Validation'..." -ForegroundColor Cyan

# Function to get current audit setting for a given subcategory
function Get-AuditSetting {
    param ([string]$Subcategory)
    $auditSetting = auditpol /get /subcategory:"$Subcategory" 2>$null | Select-String "$Subcategory"
    return $auditSetting
}

# Define subcategory and desired setting
$Subcategory = "Credential Validation"
$RequiredSetting = "Success"

# Retrieve current setting
$currentSetting = Get-AuditSetting -Subcategory $Subcategory

if ($null -eq $currentSetting) {
    Write-Host "[WARN] Unable to retrieve audit policy for '$Subcategory'. It will be set." -ForegroundColor Yellow
} else {
    Write-Host "[INFO] Current Setting: $currentSetting" -ForegroundColor Cyan
}

# Apply fix if Success auditing not enabled
if ($currentSetting -notmatch "Success") {
    Write-Host "[ACTION] Enabling Success auditing for '$Subcategory'..." -ForegroundColor Yellow
    auditpol /set /subcategory:"$Subcategory" /success:enable | Out-Null
    Write-Host "[SUCCESS] Audit policy for '$Subcategory' set to audit Success events." -ForegroundColor Green
} else {
    Write-Host "[OK] Audit policy for '$Subcategory' is already configured for Success." -ForegroundColor Green
}

# Verify compliance
$verifySetting = Get-AuditSetting -Subcategory $Subcategory
if ($verifySetting -match "Success") {
    Write-Host "`n[COMPLIANT] '$Subcategory' is correctly configured to audit Success events." -ForegroundColor Green
} else {
    Write-Host "`n[NON-COMPLIANT] Failed to apply the required audit policy. Manual verification recommended." -ForegroundColor Red
}

Write-Host "`n[COMPLETE] STIG Remediation: WN11-AU-000010" -ForegroundColor Cyan
