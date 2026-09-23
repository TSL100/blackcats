$ErrorActionPreference = 'Stop'
$cap = 'C:\Users\user\AppData\Local\Temp\opencode\cap'
$jar = Join-Path $cap 'fb.jar'
$base = 'https://www.tsl2.blackyou.dedyn.io'
$resolve = 'www.tsl2.blackyou.dedyn.io:443:127.0.0.1'
New-Item -ItemType Directory -Force -Path $cap | Out-Null

if (-not (Get-NetTCPConnection -LocalPort 443 -State Listen -ErrorAction SilentlyContinue)) { Write-Output 'SERVER_DOWN'; exit 1 }

Remove-Item $jar -Force -ErrorAction SilentlyContinue
# 1) landing (lure)
curl.exe -k -s -L -c $jar -b $jar -o "$cap\land.html" --resolve $resolve -w "land url=%{url_effective} code=%{http_code} size=%{size_download}`n" "$base/"
# 2) login page
curl.exe -k -s -c $jar -b $jar -o "$cap\login.html" --resolve $resolve -w "login code=%{http_code} size=%{size_download}`n" "$base/login.php"
$t = Get-Content -LiteralPath "$cap\login.html" -Raw
Write-Output '--- forms ---'
[regex]::Matches($t, '<form[^>]{0,500}') | ForEach-Object { $_.Value -replace '\s+',' ' }
Write-Output '--- unique input names ---'
[regex]::Matches($t, 'name="([^"]+)"') | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique
Write-Output '--- any absolute action to real host? ---'
[regex]::Matches($t, 'action="https?://[^"]+"') | ForEach-Object { $_.Value } | Select-Object -First 5