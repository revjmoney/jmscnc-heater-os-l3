param([Parameter(Mandatory=$true)][string]$Base,[Parameter(Mandatory=$true)][string]$Backup)
$ErrorActionPreference='Stop'
$taskRoot=Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$goCommand=Get-Command go.exe -ErrorAction SilentlyContinue
if($goCommand){$compiler=$goCommand.Source}else{$compiler=Join-Path $taskRoot 'work/toolchains/go/bin/go.exe'}
if(!(Test-Path -LiteralPath $compiler)){throw 'Install an official Go compiler or keep the supplied workspace toolchain.'}
$env:GOCACHE=Join-Path $taskRoot 'work/go-cache'
$env:GOPATH=Join-Path $taskRoot 'work/go-path'
$env:GOTOOLCHAIN='local';$env:GOPROXY='off';$env:GOSUMDB='off';$env:GOTELEMETRY='off';$env:CGO_ENABLED='0'
Push-Location $PSScriptRoot
try {
    $env:GOOS='windows';$env:GOARCH='amd64';Remove-Item Env:GOARM -ErrorAction SilentlyContinue
    & $compiler test ./...;if($LASTEXITCODE){throw 'Go tests failed'}
    & $compiler vet ./...;if($LASTEXITCODE){throw 'Go vet failed'}
    & $compiler build -trimpath -ldflags='-s -w' -o build/l3lab-preview-build.exe .;if($LASTEXITCODE){throw 'Windows build failed'}
    $env:GOOS='linux';$env:GOARCH='arm';$env:GOARM='7'
    & $compiler build -trimpath -ldflags='-s -w' -o build/l3lab-arm .;if($LASTEXITCODE){throw 'ARM build failed'}
    python tools/build_image.py --base $Base --backup $Backup --signer build/l3lab-preview-build.exe;if($LASTEXITCODE){throw 'Image build failed'}
    python -m unittest discover -s tools -p 'test_*.py' -v;if($LASTEXITCODE){throw 'Image tests failed'}
}finally{Pop-Location}
