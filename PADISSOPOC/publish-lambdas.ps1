#!/usr/bin/env pwsh
# Publishes every Lambda project so `cdk deploy` has assets to package.
# Run from the repo root before `cdk synth` / `cdk deploy`.

$ErrorActionPreference = 'Stop'

$projects = @(
    'DefineAuthChallenge',
    'CreateAuthChallenge',
    'VerifyAuthChallenge',
    'PostAuthentication',
    'RequestMagicLink',
    'VerifyMagicLink'
)

foreach ($p in $projects) {
    Write-Host "Publishing $p..." -ForegroundColor Cyan
    dotnet publish "src/Lambdas/$p/$p.csproj" -c Release -r linux-x64 --self-contained false
    if ($LASTEXITCODE -ne 0) { throw "Publish failed for $p" }
}

Write-Host "`nAll Lambda projects published." -ForegroundColor Green
