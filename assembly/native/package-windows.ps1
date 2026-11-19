# Package the Windows client tools that build-windows-2022.bat built.
#
#   pwsh -File assembly/native/package-windows.ps1 -BuildDir build-windows -OutDir tos-windows
#
# Run from the root of the checkout that was built, in the same
# "x64 Native Tools Command Prompt for VS 2022" environment (dumpbin comes from
# it). The script refuses to finish unless every listed file is there, the
# tools with -V report the commit of the checkout, and every shipped executable
# and DLL loads only Windows system libraries, the Microsoft C/C++ runtime or a
# DLL shipped beside it. The output directory receives the files, the smartcont
# and lib directories the Fift tools read, and BUILD-INFO with each file's
# SHA-256.
#
# validator-engine is not built on Windows (BUILD.md, Windows Build), so it is
# not shipped.

param(
  [Parameter(Mandatory = $true)][string]$BuildDir,
  [Parameter(Mandatory = $true)][string]$OutDir
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Fail([string]$Message) {
  Write-Error "package-windows: $Message" -ErrorAction Continue
  exit 1
}

if (-not (Test-Path -PathType Container 'third-party')) { Fail 'run from the repository root' }
if (-not (Test-Path -PathType Container $BuildDir)) { Fail "$BuildDir is not a build directory" }
if (Test-Path $OutDir) { Fail "$OutDir already exists" }
if (-not (Get-Command dumpbin -ErrorAction SilentlyContinue)) { Fail 'dumpbin is not on PATH; run from a VS 2022 x64 Native Tools prompt' }

$Rev = (git rev-parse HEAD).Trim()
if ($LASTEXITCODE -ne 0 -or $Rev -notmatch '^[0-9a-f]{40}$') { Fail 'cannot read the commit of the checkout' }
if (git status --porcelain --untracked-files=no) { Fail 'the checkout has local changes' }

# The shipped files and where the build puts them.
$Files = [ordered]@{
  'storage-daemon.exe'           = 'storage\storage-daemon\storage-daemon.exe'
  'storage-daemon-cli.exe'       = 'storage\storage-daemon\storage-daemon-cli.exe'
  'blockchain-explorer.exe'      = 'blockchain-explorer\blockchain-explorer.exe'
  'fift.exe'                     = 'crypto\fift.exe'
  'func.exe'                     = 'crypto\func.exe'
  'create-state.exe'             = 'crypto\create-state.exe'
  'tol.exe'                      = 'tol\tol.exe'
  'validator-engine-console.exe' = 'validator-engine-console\validator-engine-console.exe'
  'lite-client.exe'              = 'lite-client\lite-client.exe'
  'toslib-cli.exe'               = 'toslib\toslib-cli.exe'
  'toslibjson.dll'               = 'toslib\toslibjson.dll'
  'emulator.dll'                 = 'emulator\emulator.dll'
  'http-proxy.exe'               = 'http\http-proxy.exe'
  'rldp-http-proxy.exe'          = 'rldp-http-proxy\rldp-http-proxy.exe'
  'dht-server.exe'               = 'dht-server\dht-server.exe'
  'generate-random-id.exe'       = 'utils\generate-random-id.exe'
  'json2tlo.exe'                 = 'utils\json2tlo.exe'
  'proxy-liteserver.exe'         = 'utils\proxy-liteserver.exe'
  'tos-rpc.exe'                  = 'services\tos-rpc.exe'
  'tos-wallet-index.exe'         = 'services\tos-wallet-index.exe'
}
# The tools whose -V prints the commit they were built from.
$Versioned = @('lite-client.exe', 'validator-engine-console.exe', 'fift.exe', 'storage-daemon.exe', 'dht-server.exe', 'generate-random-id.exe')

foreach ($name in $Files.Keys) {
  $path = Join-Path $BuildDir $Files[$name]
  if (-not (Test-Path -PathType Leaf $path)) { Fail "$path was not built" }
}

New-Item -ItemType Directory -Path $OutDir | Out-Null
foreach ($name in $Files.Keys) {
  Copy-Item (Join-Path $BuildDir $Files[$name]) (Join-Path $OutDir $name)
}

foreach ($name in $Versioned) {
  $out = & (Join-Path $OutDir $name) -V 2>&1 | Out-String
  if ($out -notmatch "Commit: $Rev") { Fail "$name -V does not report commit $Rev" }
}

# A DLL a stock Windows does not provide would make a shipped file fail to
# start on a machine without it. The Microsoft C/C++ runtime (the Visual C++
# Redistributable) and the Windows API sets are allowed; so are the DLLs this
# package ships.
$Allowed = @(
  '^api-ms-win-.*\.dll$', '^ext-ms-win-.*\.dll$', '^ucrtbase\.dll$',
  '^vcruntime140(_1)?\.dll$', '^msvcp140(_[0-9a-z]+)?\.dll$',
  '^(kernel32|kernelbase|ntdll|user32|gdi32|advapi32|shell32|ole32|oleaut32|ws2_32|mswsock|iphlpapi|bcrypt|crypt32|secur32|ncrypt|userenv|dbghelp|psapi|shlwapi|rpcrt4|normaliz|winmm|version|powrprof|synchronization)\.dll$'
)
$Shipped = @($Files.Keys | ForEach-Object { $_.ToLowerInvariant() })
$Needed = [ordered]@{}
foreach ($name in $Files.Keys) {
  $file = Join-Path $OutDir $name
  $text = dumpbin /nologo /dependents $file | Out-String
  if ($LASTEXITCODE -ne 0) { Fail "dumpbin cannot read $name" }
  $deps = @([regex]::Matches($text, '(?im)^\s+(\S+\.dll)\s*$') | ForEach-Object { $_.Groups[1].Value.ToLowerInvariant() } | Sort-Object -Unique)
  foreach ($dep in $deps) {
    $ok = $Shipped -contains $dep
    foreach ($pattern in $Allowed) { if ($dep -match $pattern) { $ok = $true } }
    if (-not $ok) { Fail "$name loads $dep, which Windows does not provide and the package does not ship" }
  }
  $Needed[$name] = $deps -join ' '
}

Copy-Item -Recurse 'crypto\smartcont' (Join-Path $OutDir 'smartcont')
Copy-Item -Recurse 'crypto\fift\lib' (Join-Path $OutDir 'lib')

$info = New-Object System.Collections.Generic.List[string]
$info.Add("tos_revision $Rev")
$info.Add("architecture x86-64")
$info.Add("build_os $([System.Environment]::OSVersion.VersionString)")
$info.Add("compiler $((clang-cl --version | Select-Object -First 1).Trim())")
$info.Add("flags CMAKE_BUILD_TYPE=Release PORTABLE=1 CMAKE_CXX_FLAGS=/DTD_WINDOWS=1 /EHsc /bigobj")
foreach ($name in $Files.Keys) { $info.Add("needed $name $($Needed[$name])") }
foreach ($name in $Files.Keys) {
  $hash = (Get-FileHash -Algorithm SHA256 (Join-Path $OutDir $name)).Hash.ToLowerInvariant()
  $info.Add("sha256 $hash  $name")
}
Set-Content -Path (Join-Path $OutDir 'BUILD-INFO') -Value $info -Encoding ascii
Get-Content (Join-Path $OutDir 'BUILD-INFO')
