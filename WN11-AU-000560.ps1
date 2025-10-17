<#
.SYNOPSIS
  Remediates STIG ID: WN11-AU-000560 by ensuring "Audit Other Logon/Logoff Events" 
  is configured to audit Success events on Windows 11 systems.

.NOTES
  STIG ID        : WN11-AU-000560
  SRG            : SRG-OS-000037-GPOS-00015
  Severity       : Medium
  CCI            : CCI-000130
  Vulnerability ID: V-253345
  Title          : Windows 11 must be configured to audit other Logon/Logoff Events Successes.
  Discussion     : Maintaining audit logs helps detect attacks, analyze compromises, 
                   and monitor system activity. This setting ensures Windows audits 
                   successful "Other Logon/Logoff Events".
  Date Created   : 2025-10-17
  Author         : Reginald Deroslard

.TESTED ON
  Date(s) Tested : 2025-10-17
  Tested By      : Reginald Deroslard
  Systems Tested : Windows 11 Pro x64 (Build 22631)
  PowerShell Ver.: 5.1+

.USAGE
  Save this script as: Remediate-WN11-AU-000560.ps1
  Run PowerShell as Administrator:
    PS C:\> .\Remediate-WN11-AU-000560.ps1
#>

Write-Host "`n[INFO] Checking audit policy for 'Other Logon/Logoff Events'..." -ForegroundColor Cyan

# Function to get current audit policy
function Get-AuditSetting {
    param ([string]$Subcategory)
    $auditSetting = auditpol /get /subcategory:"$Subcategory" 2>$null | Select-String "$Subcategory"
    return $auditSetting
}

# Define target policy
$Subcategory = "Other Logon/Logoff Events"
$RequiredSetting = "Success"

# Retrieve current audit policy
$currentSetting = Get-AuditSetting -Subcategory $Subcategory

if ($null -eq $currentSetting) {
    Write-Host "[WARN] Unable to retrieve audit policy for '$Subcategory'. It will be set." -ForegroundColor Yellow
} else {
    Write-Host "[INFO] Current Setting: $currentSetting" -ForegroundColor Cyan
}

# Check if Success auditing is already enabled
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

Write-Host "`n[COMPLETE] STIG Remediation: WN11-AU-000560" -ForegroundColor Cyan
