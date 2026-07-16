param(
    [Parameter(Mandatory=$false)]
    [string]$GasToken,
    [Parameter(Mandatory=$false)]
    [string]$CFToken,
    [Parameter(Mandatory=$false)]
    [string]$CFAccount
)

# NovaProxy Auto-Deploy Script
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  NovaProxy - Auto Deployment Script" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Check if binary exists
$binary = ".\novaproxy.exe"
if (-not (Test-Path $binary)) {
    Write-Host "[!] Building NovaProxy..." -ForegroundColor Yellow
    $env:GOPROXY="https://goproxy.cn,https://goproxy.io,direct"
    go build -o novaproxy.exe . 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[!] Build failed!" -ForegroundColor Red
        exit 1
    }
    Write-Host "[✓] Build complete" -ForegroundColor Green
}

# Deploy
$env:NOVA_GAS_TOKEN = $GasToken
$env:NOVA_CF_TOKEN = $CFToken
$env:NOVA_CF_ACCOUNT = $CFAccount

Write-Host "[*] Running deploy..." -ForegroundColor Yellow
& .\novaproxy.exe --deploy --gas-token $GasToken 2>&1

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "[✓] Deploy complete!" -ForegroundColor Green
    
    # Save config
    $config = @{
        gas_token = $GasToken
        cf_token = $CFToken
        cf_account = $CFAccount
        deployed_at = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    }
    $config | ConvertTo-Json | Set-Content "deploy-config.json"
    Write-Host "[✓] Config saved to deploy-config.json" -ForegroundColor Green
    
    Write-Host ""
    Write-Host "Next steps:" -ForegroundColor Cyan
    Write-Host "  1. Start proxy:   .\novaproxy.exe core" -ForegroundColor White
    Write-Host "  2. Configure your browser to use proxy at 127.0.0.1:8080" -ForegroundColor White
    Write-Host "  3. Or use VPN mode: novaproxy.exe (requires admin)" -ForegroundColor White
} else {
    Write-Host "[!] Deploy failed" -ForegroundColor Red
    exit 1
}
