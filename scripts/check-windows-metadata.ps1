param(
    [Parameter(Mandatory)]
    [string] $Path
)

$ErrorActionPreference = 'Stop'
$app = Get-Content -LiteralPath (Join-Path $PSScriptRoot '../src-tauri/tauri.conf.json') -Raw | ConvertFrom-Json
$exe = Get-Item -LiteralPath $Path
$info = $exe.VersionInfo
$expected = [ordered]@{
    ProductName      = $app.productName
    FileDescription  = $app.productName
    CompanyName      = $app.bundle.publisher
    ProductVersion   = $app.version
    FileVersion      = $app.version
    OriginalFilename = 'phi2ray.exe'
    InternalName     = 'phi2ray'
    LegalCopyright   = $app.bundle.copyright
}

foreach ($field in $expected.Keys) {
    if ($info.$field -cne $expected[$field]) {
        throw "Incorrect Windows metadata in $($exe.Name): $field should be '$($expected[$field])', got '$($info.$field)'."
    }
}
if (!$info.Comments -or !$info.Comments.Contains($app.bundle.homepage)) {
    throw "Windows metadata must include the project homepage."
}
Write-Host "Verified Windows metadata for $($exe.Name) ($($info.ProductVersion))."
