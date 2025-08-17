<#
PowerShell script to secure the skaner4 project directory by removing write permissions for non-admin users.
#>
param(
    [string]$TargetPath = "$(Split-Path -Parent $MyInvocation.MyCommand.Definition)"
)

Write-Host "Securing project at: $TargetPath"

# Remove inherited permissions and grant explicit read and execute only
icacls $TargetPath /inheritance:r | Out-Null
icacls $TargetPath /grant:r "BUILTIN\Administrators:(OI)(CI)F" "BUILTIN\Users:(OI)(CI)RX" /T | Out-Null

Write-Host "Permissions updated: Administrators full control, Users read & execute only."
