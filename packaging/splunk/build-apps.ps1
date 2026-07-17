$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path

Push-Location $repoRoot
try {
    & cargo run --locked -p dbx-rs-app-builder -- @args
    exit $LASTEXITCODE
}
finally {
    Pop-Location
}
