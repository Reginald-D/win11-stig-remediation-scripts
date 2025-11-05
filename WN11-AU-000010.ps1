<#
.SYNOPSIS
  Remediates STIG ID: WN11-AU-000010 by ensuring "Audit Credential Validation" 
  audits Success events on Windows systems.

.NOTES
  STIG ID         : WN11-AU-000010
  SRG             : SRG-OS-000458-GPOS-00203
  Severity        : Medium
  CCI             : CCI-000172
  Vulnerability ID: V-253307
  Title           : The system must audit Account Logon - Credential Validation successes.
  Discussion      : Ensures auditing of successful Credential Validation to detect attacks 
                    and analyze authentication activity.
  Date Created    : 2025-10-10
  Author          : Reginald D

.TESTED ON
  Windows 11 Pro x64 (Build 22631)
  PowerShell 5.1+

.USAGE
  Run as Administrator:
    PS C:\> .\WN11-AU-000010.ps1
#>

$Subcategory = "Credential Validation"
Write-Host "`n[INFO] Checking audit policy for '$Subcategory'..." -ForegroundColor Cyan
$current = (auditpol /get /subcategory:"$Subcategory" 2>$null | Select-String "$Subcategory")

if ($null -eq $current -or $current -notmatch "Success") {
    Write-Host "[ACTION] Enabling Success auditing for '$Subcategory'..." -ForegroundColor Yellow
    auditpol /set /subcategory:"$Subcategory" /success:enable | Out-Null
    Write-Host "[SUCCESS] '$Subcategory' now audits Success events." -ForegroundColor Green
} else {
    Write-Host "[OK] '$Subcategory' already audits Success events." -ForegroundColor Green
}

$verify = auditpol /get /subcategory:"$Subcategory" | Select-String "$Subcategory"
if ($verify -match "Success") {
    Write-Host "`n[COMPLIANT] '$Subcategory' correctly configured." -ForegroundColor Green
} else {
    Write-Host "`n[NON-COMPLIANT] Policy change failed. Manual check recommended." -ForegroundColor Red
}

Write-Host "`n[COMPLETE] STIG Remediation: WN11-AU-000010" -ForegroundColor Cyan
