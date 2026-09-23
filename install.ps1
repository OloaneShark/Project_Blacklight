$ErrorActionPreference = "Stop"

$Repo = "OloaneShark/Project_Blacklight"
$Api = "https://api.github.com/repos/$Repo/releases?per_page=20"
$InstallDir = if ($env:BLACKLIGHT_INSTALL_DIR) {
    $env:BLACKLIGHT_INSTALL_DIR
} else {
    Join-Path $env:LOCALAPPDATA "ProjectBlacklight\bin"
}

function Fail([string]$Message) {
    throw "Project Blacklight installer: $Message"
}

$Architecture = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString()
switch ($Architecture) {
    "X64" { $Arch = "x64" }
    "Arm64" { $Arch = "ARM64" }
    default { Fail "unsupported Windows architecture: $Architecture" }
}

$AssetName = "Project-Blacklight-Windows-$Arch.zip"

$Headers = @{
    Accept = "application/vnd.github+json"
    "X-GitHub-Api-Version" = "2022-11-28"
    "User-Agent" = "Project-Blacklight-Installer"
}

$Releases = Invoke-RestMethod -Uri $Api -Headers $Headers
$Release = $Releases | Where-Object { -not $_.draft } | Select-Object -First 1
if (-not $Release) {
    Fail "no published GitHub Release was found."
}

$Asset = $Release.assets | Where-Object { $_.name -eq $AssetName } | Select-Object -First 1
$ChecksumAsset = $Release.assets | Where-Object { $_.name -eq "SHA256SUMS" } | Select-Object -First 1

if (-not $Asset) {
    Fail "no published $AssetName standalone asset was found."
}
if (-not $ChecksumAsset) {
    Fail "release checksum file was not found."
}

$TempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("blacklight-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $TempDir | Out-Null

try {
    $Archive = Join-Path $TempDir $AssetName
    $ChecksumsPath = Join-Path $TempDir "SHA256SUMS"
    $ExtractDir = Join-Path $TempDir "extracted"

    Write-Host "Downloading $AssetName..."
    Invoke-WebRequest -Uri $Asset.browser_download_url -OutFile $Archive -Headers $Headers
    Invoke-WebRequest -Uri $ChecksumAsset.browser_download_url -OutFile $ChecksumsPath -Headers $Headers

    $ChecksumLine = Get-Content $ChecksumsPath |
        Where-Object { $_ -match ("\s+" + [regex]::Escape($AssetName) + "$") } |
        Select-Object -First 1

    if (-not $ChecksumLine) {
        Fail "checksum for $AssetName was not found."
    }

    $Expected = ($ChecksumLine -split "\s+")[0].ToLowerInvariant()
    $Actual = (Get-FileHash -Path $Archive -Algorithm SHA256).Hash.ToLowerInvariant()

    if ($Expected -ne $Actual) {
        Fail "SHA-256 verification failed."
    }

    Expand-Archive -Path $Archive -DestinationPath $ExtractDir -Force
    $Binary = Get-ChildItem -Path $ExtractDir -Filter "blacklight.exe" -Recurse |
        Select-Object -First 1

    if (-not $Binary) {
        Fail "blacklight.exe was not found in the archive."
    }

    New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
    $Destination = Join-Path $InstallDir "blacklight.exe"
    Copy-Item -Path $Binary.FullName -Destination $Destination -Force

    $UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $PathEntries = @()
    if ($UserPath) {
        $PathEntries = $UserPath -split ";"
    }

    if ($PathEntries -notcontains $InstallDir) {
        $NewUserPath = if ($UserPath) { "$UserPath;$InstallDir" } else { $InstallDir }
        [Environment]::SetEnvironmentVariable("Path", $NewUserPath, "User")
        Write-Host "Added $InstallDir to your user PATH. Open a new terminal to use it globally."
    }

    Write-Host ""
    Write-Host "Project Blacklight installed to:"
    Write-Host "  $Destination"
    & $Destination --version
}
finally {
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $TempDir
}
