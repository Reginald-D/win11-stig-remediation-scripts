   # Windows 11 STIG Remediation Scripts

This repository contains PowerShell scripts designed to automate the remediation of Windows 11 STIG (Security Technical Implementation Guide) findings. Each script targets a specific STIG ID and applies the required configuration settings to harden the operating system in alignment with DoD and NIST security baselines.

# Implemented STIG Remediations

| Date       | STIG ID | GitHub | Description |
|-----------|-----------------|------------|------------|
| 10/8/2025 | WN11-AU-000010 | [Link](https://github.com/Reginald-D/win11-stig-remediation-scripts/blob/main/WN11-AU-000010.ps1) | Audits Credential Validation successes to track account authentication |
| 10/6/2025 | WN11-AU-000050 | [Link](https://github.com/Reginald-D/win11-stig-remediation-scripts/blob/main/WN11-AU-000050.ps1) | Audits Logoff Events to record user sign-outs |
| 10/6/2025 | WN11-AU-000084 | [Link](https://github.com/Reginald-D/win11-stig-remediation-scripts/blob/main/WN11-AU-000084.ps1) | Audits Other Object Access Events failures to detect unauthorized access |
| 10/6/2025 | WN11-AU-000560 | [Link](https://github.com/Reginald-D/win11-stig-remediation-scripts/blob/main/WN11-AU-000560.ps1) | Audits Other Logon/Logoff Events successes to monitor login activity |
| 10/6/2025 | WN11-CC-000090 | [Link](https://github.com/Reginald-D/win11-stig-remediation-scripts/blob/main/WN11-CC-000090.ps1) | Disables Windows Connect Now to prevent unauthorized wireless setup |
| 10/6/2025 | WN11-CC-000252 | [Link](https://github.com/Reginald-D/win11-stig-remediation-scripts/blob/main/WN11-CC-000252.ps1) | Disables Game Recording and Broadcasting to avoid leaking sensitive data |
| 10/6/2025 | WN11-CC-000290 | [Link](https://github.com/Reginald-D/win11-stig-remediation-scripts/blob/main/WN11-CC-000290.ps1) | Sets RDP encryption to “High” for secure remote sessions |
| 10/6/2025 | WN11-CC-000315 | [Link](https://github.com/Reginald-D/win11-stig-remediation-scripts/blob/main/WN11-CC-000315.ps1) | Disables Error Reporting to stop diagnostic data leaks |
| 10/6/2025 | WN11-EP-000310 | [Link](https://github.com/Reginald-D/win11-stig-remediation-scripts/blob/main/WN11-EP-000310.ps1) | Enables Kernel DMA Protection to block hardware-based attacks |
| 10/7/2025 | WN11-UR-000060 | [Link](https://github.com/Reginald-D/win11-stig-remediation-scripts/blob/main/WN11-UR-000060.ps1) | Limits Create Symbolic Links rights to Administrators |
| 10/7/2025 | WN11-UR-000065 | [Link](https://github.com/Reginald-D/win11-stig-remediation-scripts/blob/main/WN11-UR-000065.ps1) | Limits Debug Programs rights to Administrators |
