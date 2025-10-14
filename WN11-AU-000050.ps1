<#
.SYNOPSIS
Remediates STIG ID WN11-AU-000050 (Audit Process Creation)

.DESCRIPTION
Configures the local audit policy to enable "Audit Process Creation: Success"
to meet Windows 11 DISA STIG compliance.

STIG ID: WN11-AU-000050  
SRG: SRG-OS-000064-GPOS-00033  
Severity: Medium  
CCI: CCI-000172, CCI-003938  
Vulnerability ID: V-253312

.VULNERABILITY DISCUSSION
Maintaining an audit trail of process creation events helps detect and analyze suspicious activity. 
This setting ensures successful process creation events are logged for security review.
#>

Write-Host "Checking current 'Audit Process Creation' policy..." -ForegroundColor Cyan

# Get current audit setting for Process Creation
$currentSetting = (auditpol /get /subcategory:"Process Creation" | Select-String "Success").ToString()

# Check if auditing for Success is enabled
if ($currentSetting -match "No Auditing") {
    Write-Host "Audit Process Creation is currently NOT enabled. Remediating..." -ForegroundColor Yellow
    auditpol /set /subcategory:"Process Creation" /success:enable | Out-Null
    Start-Sleep -Seconds 2
    Write-Host "'Audit Process Creation' successfully set to 'Success: Enabled'." -ForegroundColor Green
}
else {
    Write-Host "'Audit Process Creation' already enabled for Success." -ForegroundColor Green
}

# Verify the change
Write-Host "`nVerifying settings..." -ForegroundColor Cyan
auditpol /get /subcategory:"Process Creation"
Write-Host "`nSTIG WN11-AU-000050 compliance check complete." -ForegroundColor Green
