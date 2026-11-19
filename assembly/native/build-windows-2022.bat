@echo off
REM Windows x86-64: the node and its tools, built with clang-cl and lld-link from
REM Visual Studio 2022 (BUILD.md, Windows Build). Run it from the repository root
REM in an "x64 Native Tools Command Prompt for VS 2022", with ninja, NASM, Perl
REM and the Visual Studio LLVM toolset (clang-cl) on PATH. Every third-party
REM library is built from third-party\.
REM
REM   assembly\native\build-windows-2022.bat [-k]
REM
REM -k keeps going after a failed target, so one run reports every error.

setlocal
set "KEEP_GOING="
if "%~1"=="-k" set "KEEP_GOING=-k 0"

if not exist third-party (
  echo run this script from the repository root
  exit /b 1
)
for %%T in (clang-cl lld-link ninja nasm perl) do (
  where %%T >nul 2>nul
  if errorlevel 1 (
    echo %%T was not found on PATH
    exit /b 1
  )
)

if not exist build-windows mkdir build-windows
cmake -S . -B build-windows -GNinja -DCMAKE_BUILD_TYPE=Release ^
  -DCMAKE_C_COMPILER=clang-cl ^
  -DCMAKE_CXX_COMPILER=clang-cl ^
  -DCMAKE_LINKER=lld-link ^
  -DCMAKE_CXX_COMPILER_LAUNCHER= ^
  -DPORTABLE=1 ^
  -DCMAKE_CXX_FLAGS="/DTD_WINDOWS=1 /EHsc /bigobj"
if errorlevel 1 (
  echo Can't configure tos
  exit /b 1
)

ninja -C build-windows %KEEP_GOING% storage-daemon storage-daemon-cli blockchain-explorer fift func tol ^
  toslib toslibjson toslib-cli validator-engine lite-client validator-engine-console ^
  generate-random-id json2tlo dht-server http-proxy rldp-http-proxy create-state emulator ^
  proxy-liteserver tos-rpc tos-wallet-index
if errorlevel 1 (
  echo Can't compile tos
  exit /b 1
)

build-windows\validator-engine\validator-engine.exe -V
if errorlevel 1 (
  echo validator-engine.exe does not run
  exit /b 1
)
build-windows\crypto\fift.exe -V
if errorlevel 1 (
  echo fift.exe does not run
  exit /b 1
)
endlocal
