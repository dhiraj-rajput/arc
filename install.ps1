$ErrorActionPreference = 'Stop'

# Repository info
$repo = "dhiraj-rajput/arc"
$assetName = "arc-windows-amd64.zip"
$url = "https://github.com/$repo/releases/latest/download/$assetName"

$installDir = Join-Path $HOME "AppData\Local\arc\bin"
$zipPath = Join-Path $env:TEMP "arc.zip"

Write-Host "🌌 Installing arc on Windows..." -ForegroundColor Cyan

# Create install directory
if (-not (Test-Path $installDir)) {
    New-Item -ItemType Directory -Force -Path $installDir | Out-Null
}

Write-Host "Downloading arc from $url..." -ForegroundColor Gray
# Download
Invoke-WebRequest -Uri $url -OutFile $zipPath

Write-Host "Extracting archive..." -ForegroundColor Gray
# Extract
Expand-Archive -Path $zipPath -DestinationPath $installDir -Force
Remove-Item $zipPath -Force

# Path manipulation
$binPath = Join-Path $installDir "arc.exe"
if (-not (Test-Path $binPath)) {
    Write-Error "Error: arc.exe not found in extracted files."
    exit 1
}

# Get current User PATH
$userPath = [System.Environment]::GetEnvironmentVariable("PATH", "User")
$pathElements = $userPath -split ";"
$alreadyInPath = $false

foreach ($element in $pathElements) {
    if ($element.Trim().ToLower() -eq $installDir.ToLower()) {
        $alreadyInPath = $true
        break
    }
}

if (-not $alreadyInPath) {
    Write-Host "Adding $installDir to User PATH..." -ForegroundColor Gray
    $newUserPath = $userPath
    if (-not $newUserPath.EndsWith(";")) {
        $newUserPath += ";"
    }
    $newUserPath += $installDir
    [System.Environment]::SetEnvironmentVariable("PATH", $newUserPath, "User")
    
    # Update current session PATH so they can run it immediately
    $env:PATH += ";$installDir"
    Write-Host "✨ Added to PATH successfully!" -ForegroundColor Green
} else {
    Write-Host "Target directory is already in User PATH." -ForegroundColor Gray
}

Write-Host "✨ arc has been installed successfully to: $binPath" -ForegroundColor Green
Write-Host "🌌 Restart your terminal or shell and run 'arc --help' to get started!" -ForegroundColor Cyan
