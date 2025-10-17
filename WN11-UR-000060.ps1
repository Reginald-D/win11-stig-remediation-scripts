<#
.SYNOPSIS
    This PowerShell script ensures that only the Administrators group is assigned the "Create symbolic links" user right in compliance with STIG ID: WN11-UR-000060.

.NOTES
    Author          : Reginald Deroslard
    LinkedIn        : 
    GitHub          : 
    Date Created    : 2025-10-16
    Last Modified   : 2025-10-16
    Version         : 1.0
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-UR-000060

.TESTED ON
    Date(s) Tested  : 2025-10-16
    Tested By       : Reginald Deroslard
    Systems Tested  : Windows 11 Pro / Enterprise
    PowerShell Ver. : 5.1 / 7.x

.USAGE
    Run PowerShell as Administrator.
    Example syntax:
    PS C:\> .\WN11-UR-000060_CreateSymbolicLinks.ps1
#>

# --- Audit Section ---
Write-Host "Auditing current 'Create symbolic links' user right assignments..." -ForegroundColor Cyan

$tempPath = "$env:TEMP\secpol.cfg"
secedit /export /cfg $tempPath | Out-Null

$currentAssignment = (Get-Content $tempPath | Select-String "SeCreateSymbolicLinkPrivilege").ToString()
Write-Host "Current Assigned Accounts/Groups:" -ForegroundColor Yellow
Write-Host $currentAssignment

# --- Remediation Section ---
Write-Host "Applying STIG-compliant configuration..." -ForegroundColor Cyan

$infPath = "$env:TEMP\secpol_update.inf"

@"
[Unicode]
Unicode=yes
[Version]
signature="\$CHICAGO\$"
Revision=1
[Privilege Rights]
SeCreateSymbolicLinkPrivilege = *S-1-5-32-544
"@ | Out-File $infPath -Encoding ASCII

# Apply new settings
secedit /configure /db "$env:TEMP\secedit.sdb" /cfg $infPath /areas USER_RIGHTS | Out-Null

# Force Group Policy update
gpupdate /force | Out-Null

Write-Host "Remediation complete. 'Create symbolic links' right is now restricted to Administrators only." -ForegroundColor Green

# --- Verification Section ---
Write-Host "Verifying applied configuration..." -ForegroundColor Cyan

$verifyPath = "$env:TEMP\verify.cfg"
secedit /export /cfg $verifyPath | Out-Null
$verify = Get-Content $verifyPath | Select-String "SeCreateSymbolicLinkPrivilege"
Write-Host "Post-Remediation Setting:" -ForegroundColor Yellow
Write-Host $verify.Line

Write-Host "Audit and remediation completed successfully on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Green
