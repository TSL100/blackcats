# Run as Administrator (right-click -> Run with PowerShell). Re-launches itself elevated,
# normalizes hosts entries for every phishlet's per-phishlet hostname, stops stale servers,
# then starts the local evilgophish proxy so the browser on THIS PC talks to THIS PC (not the VPS).
#
# LOCAL TESTING ONLY: each phishlet is assigned its own subdomain of tsl2.blackyou.dedyn.io
# (e.g. go./ms./ms2./bk./pp.) in proxy_cfg/config.json. Every phish FQDN
# (<phish_sub>.<phishlet hostname>) is pinned to 127.0.0.1 via the hosts file.
# For a real (public) deployment the desec.io zone needs a wildcard per phishlet hostname
# (e.g. *.go.tsl2.blackyou.dedyn.io -> external IP), or clients must be pointed at the
# embedded evilginx DNS server (0.0.0.0:53) which already answers every subdomain.
$root   = 'E:\Solo Leveling\evilgophish\evilgophish'
$bin    = Join-Path $root 'evilgophish.exe'
$goph   = Join-Path $root 'gophish'
$hosts  = 'C:\Windows\System32\drivers\etc\hosts'
$cfg    = Join-Path $root 'proxy_cfg\config.json'
$base   = 'blackyou.dedyn.io'

# self-elevate
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes((Get-Content -LiteralPath $PSCommandPath -Raw)))
    Start-Process powershell -Verb RunAs -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-EncodedCommand',$enc
    exit
}

# 1) derive per-phishlet hosts: <phish_sub>.<phishlet hostname> for every configured phishlet
$phishCfg = (Get-Content -LiteralPath $cfg -Raw | ConvertFrom-Json).phishlets
$names = @()
foreach ($p in $phishCfg.PSObject.Properties) {
    $h = $p.Value.hostname
    if (-not $h) { continue }
    if ($h -notmatch [regex]::Escape($base)) { continue }
    $names += $h
    $yaml = Join-Path (Join-Path $root 'evilginx3\legacy_phishlets') ($p.Name + '.yaml')
    if (Test-Path -LiteralPath $yaml) {
        foreach ($m in [regex]::Matches((Get-Content -LiteralPath $yaml -Raw), "phish_sub:\s*'([^']*)'")) {
            $s = $m.Groups[1].Value
            if ($s -and $s -notin @('EXAMPLE','subdomainhere')) { $names += ($s + '.' + $h) }
        }
    }
}
$names = $names | Sort-Object -Unique

$cur   = @(Get-Content -LiteralPath $hosts -ErrorAction SilentlyContinue)
$pat   = '(?i)' + [regex]::Escape($base)
$keep  = @($cur | Where-Object { $_ -notmatch $pat })
if ($keep -and $keep[-1] -ne '') { $keep += '' }
$block = @("# evilgophish local phish hosts (auto-generated from proxy_cfg/config.json + legacy_phishlets phish_sub)") + ($names | ForEach-Object { "127.0.0.1`t$_" })
Set-Content -LiteralPath $hosts -Value ($keep + $block)
"hosts: normalized $($names.Count) FQDNs across $($phishCfg.PSObject.Properties | Where-Object { $_.Value.hostname } | Measure-Object | Select-Object -ExpandProperty Count) phishlets -> 127.0.0.1"

# 2) stop any stale local server
Get-Process -Name evilgophish -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

# 3) start the proxy in this console (Ctrl+C to stop)
Set-Location -LiteralPath $goph
'--- starting evilgophish with fixed templates ---'
'Serve ports: proxy 443 / admin https://127.0.0.1:3333'
'After it starts: enable the phishlet in the panel, generate the lure URL, keep the       ?rid=...  part'
& $bin serve -config 'config.json'