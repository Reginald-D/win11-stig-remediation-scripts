<#
.SYNOPSIS
    This PowerShell script audits and remediates the "Debug Programs" (SeDebugPrivilege) user right assignment.
    Ensures only Administrators have this right, per DISA STIG ID WN11-UR-000065.

.NOTES
    Author          : 
    LinkedIn        : 
    GitHub          : 
    Date Created    : 2025-10-16
    Last Modified   : 2025-10-16
    Version         : 1.1
    CVEs            : N/A
    Plugin IDs      : N/A
    STIG-ID         : WN11-UR-000065

.TESTED ON
    Date(s) Tested  : 
    Tested By       : 
    Systems Tested  : Windows 11
    PowerShell Ver. : 5.1, 7.x

.USAGE
    Example:
    PS C:\> .\Remediate_DebugPrograms.ps1
#>

# Ensure the script is running as Administrator
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Please run this script as Administrator."
    exit
}

Write-Host "Starting audit for 'Debug Programs' (SeDebugPrivilege) user right..." -ForegroundColor Cyan

# Define constants
$privilege = "SeDebugPrivilege"
$allowedAccount = "*S-1-5-32-544"  # SID for Administrators group
$tempCfg = "$env:TEMP\secpol.cfg"
$tempDb = "$env:TEMP\secedit.sdb"

function Get-DebugPrivilegeAssignments {
    secedit /export /cfg $tempCfg | Out-Null
    $line = (Select-String -Path $tempCfg -Pattern "^$privilege").Line
    if ($line) {
        $assigned = $line -replace "$privilege\s*=\s*", "" -split ","
        $assigned = $assigned | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
        return $assigned
    } else {
        return @()
    }
}

function Audit-DebugPrivilege {
    $assigned = Get-DebugPrivilegeAssignments
    if ($assigned.Count -eq 0) {
        Write-Host "'Debug Programs' right not found in policy (potentially unconfigured)." -ForegroundColor Yellow
    } else {
        Write-Host "Current 'Debug Programs' assignments:" -ForegroundColor White
        $assigned | ForEach-Object { Write-Host " - $_" }
    }

    if (($assigned -contains $allowedAccount) -and ($assigned.Count -eq 1)) {
        Write-Host "System is compliant. Only Administrators have 'Debug Programs' rights." -ForegroundColor Green
        return $true
    } else {
        Write-Host "System is NOT compliant. Remediation required." -ForegroundColor Red
        return $false
    }
}

function Remediate-DebugPrivilege {
    Write-Host "Applying remediation for 'Debug Programs' user right..." -ForegroundColor Cyan

    try {
        secedit /export /cfg $tempCfg | Out-Null

        (Get-Content $tempCfg) |
            ForEach-Object {
                if ($_ -match "^$privilege") {
                    "$privilege = $allowedAccount"
                } else {
                    $_
                }
            } | Set-Content $tempCfg

        secedit /configure /db $tempDb /cfg $tempCfg /areas USER_RIGHTS | Out-Null

        Write-Host "'Debug Programs' right successfully restricted to Administrators only." -ForegroundColor Green
    }
    catch {
        Write-Host "Error during remediation: $($_.Exception.Message)" -ForegroundColor Red
    }
    finally {
        Remove-Item $tempCfg, $tempDb -ErrorAction SilentlyContinue
    }
}

# Run audit first
if (-not (Audit-DebugPrivilege)) {
    Remediate-DebugPrivilege
    Write-Host "Re-running audit after remediation..." -ForegroundColor Cyan
    Audit-DebugPrivilege
}

Write-Host "Audit and remediation process complete. (STIG ID: WN11-UR-000065)"
