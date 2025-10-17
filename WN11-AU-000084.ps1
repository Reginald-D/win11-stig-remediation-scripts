<#
.SYNOPSIS
  Remediates STIG ID: WN11-AU-000084 by ensuring "Audit Other Object Access Events"
  is configured to audit Failure events on Windows 11 systems.

.NOTES
  STIG ID         : WN11-AU-000084
  SRG             : SRG-OS-000462-GPOS-00206
  Severity        : Medium
  CCI             : CCI-000172
  Vulnerability ID: V-253322
  Title           : Windows 11 must be configured to audit Object Access - Other Object Access Events failures.
  Discussion      : Maintaining an audit trail helps identify configuration errors, troubleshoot issues, 
                    and detect attacks. This setting ensures audit logs capture failed events related to 
                    the management of task scheduler jobs and COM+ objects.
  Date Created    : 2025-10-17
  Author          : Reginald D

.TESTED ON
  Date(s) Tested  : 2025-10-17
  Tested By       : Reginald D
  Systems Tested  : Windows 11 Pro x64 (Build 22631)
  PowerShell Ver. : 5.1+

.USAGE
  Save this script as: Remediate-WN11-AU-000084.ps1
  Run PowerShell as Administrator:
    PS C:\> .\Remediate-WN11-AU-000084.ps1
#>

Write-Host "`n[INFO] Checking audit policy for 'Other Object Access Events'..." -ForegroundColor Cyan

# Function to retrieve the current audit setting for a given subcategory
function Get-AuditSetting {
    param ([string]$Subcategory)
    $auditSetting = auditpol /get /subcategory:"$Subcategory" 2>$null | Select-String "$Subcategory"
    return $auditSetting
}

# Define subcategory and desired setting
$Subcategory = "Other Object Access Events"
$RequiredSetting = "Failure"

# Retrieve current setting
$currentSetting = Get-AuditSetting -Subcategory $Subcategory

if ($null -eq $currentSetting) {
    Write-Host "[WARN] Unable to retrieve audit policy for '$Subcategory'. It will be set." -ForegroundColor Yellow
} else {
    Write-Host "[INFO] Current Setting: $currentSetting" -ForegroundColor Cyan
}

# Apply fix if Failure auditing not enabled
if ($currentSetting -notmatch "Failure") {
    Write-Host "[ACTION] Enabling Failure auditing for '$Subcategory'..." -ForegroundColor Yellow
    auditpol /set /subcategory:"$Subcategory" /failure:enable | Out-Null
    Write-Host "[SUCCESS] Audit policy for '$Subcategory' set to audit Failure events." -ForegroundColor Green
} else {
    Write-Host "[OK] Audit policy for '$Subcategory' is already configured for Failure." -ForegroundColor Green
}

# Verify compliance
$verifySetting = Get-AuditSetting -Subcategory $Subcategory
if ($verifySetting -match "Failure") {
    Write-Host "`n[COMPLIANT] '$Subcategory' is correctly configured to audit Failure events." -ForegroundColor Green
} else {
    Write-Host "`n[NON-COMPLIANT] Failed to apply the required audit policy. Manual verification recommended." -ForegroundColor Red
}

Write-Host "`n[COMPLETE] STIG Remediation: WN11-AU-000084" -ForegroundColor Cyan
