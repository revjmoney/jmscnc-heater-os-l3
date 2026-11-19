param([string]$Miner='192.168.1.50:4028',[int]$Port=8787)
$ErrorActionPreference='Stop'
$binary=Join-Path $PSScriptRoot 'build/l3lab-preview.exe'
$config=Join-Path $PSScriptRoot 'private/preview-config'
$state=Join-Path $PSScriptRoot 'private/preview-state'
Write-Host "Read-only preview: http://127.0.0.1:$Port/ (Ctrl+C stops it)"
& $binary -preview -listen "127.0.0.1:$Port" -miner $Miner -config-dir $config -state-dir $state
