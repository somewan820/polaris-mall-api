$ErrorActionPreference = 'Stop'
$devCommand = ''
$smokeCommand = ''

Write-Host "[init.ps1] pwd: $(Get-Location)"
if (-not [string]::IsNullOrWhiteSpace($devCommand)) {
  Write-Host "[init.ps1] running dev command: $devCommand"
  Invoke-Expression $devCommand
} else {
  Write-Host "[init.ps1] no dev command configured"
}

if (-not [string]::IsNullOrWhiteSpace($smokeCommand)) {
  Write-Host "[init.ps1] running smoke command: $smokeCommand"
  Invoke-Expression $smokeCommand
} else {
  Write-Host "[init.ps1] no smoke command configured"
}
