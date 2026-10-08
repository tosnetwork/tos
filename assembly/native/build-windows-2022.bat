REM execute this script inside elevated (Run as Administrator) console "x64 Native Tools Command Prompt for VS 2022"

echo off

set "SCRIPT_DIR=%~dp0"
for %%I in ("%SCRIPT_DIR%.") do set "SCRIPT_DIR=%%~fI"
set "ROOT_DIR=%SCRIPT_DIR%"
if not exist "%ROOT_DIR%\third-party" (
  for %%I in ("%SCRIPT_DIR%\..\..") do set "ROOT_DIR=%%~fI"
)

echo Using repo root: %ROOT_DIR%
cd /d "%ROOT_DIR%"

echo Installing chocolatey windows package manager...
@"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))" && SET "PATH=%PATH%;%ALLUSERSPROFILE%\chocolatey\bin"
choco -?
IF %errorlevel% NEQ 0 (
  echo Can't install chocolatey
  exit /b %errorlevel%
)

choco feature enable -n allowEmptyChecksums

echo Installing tools...
choco install -y pkgconfiglite ninja nasm
IF %errorlevel% NEQ 0 (
  echo Can't install tools
  exit /b %errorlevel%
)
SET PATH=%PATH%;C:\Program Files\NASM

REM The tree is built with clang in clang-cl mode, as upstream does; MSVC's own
REM compiler is not a supported toolchain for it.
where clang-cl
IF %errorlevel% NEQ 0 (
  echo clang-cl not found. Install the LLVM toolset for Visual Studio 2022.
  exit /b %errorlevel%
)

if not exist "third_libs" (
    mkdir "third_libs"
)
cd third_libs

set third_libs=%cd%
echo %third_libs%
set "third_party=%ROOT_DIR%\third-party"

cd ..
echo Current dir %cd%

mkdir build
cd build

REM Audit #10 (2026-04-26): CI builds always produce deployable artifacts;
REM gate against the devnet escape hatch. Mirrors build-ubuntu-shared.sh.
SET TOS_PROD_FLAG=
IF "%GITHUB_ACTIONS%"=="true" SET TOS_PROD_FLAG=-DTOS_PRODUCTION_BUILD=ON
IF "%TOS_PRODUCTION_BUILD%"=="1" SET TOS_PROD_FLAG=-DTOS_PRODUCTION_BUILD=ON
IF "%TOS_PRODUCTION_BUILD%"=="ON" SET TOS_PROD_FLAG=-DTOS_PRODUCTION_BUILD=ON

REM Windows builds the client toolchain only (see BUILD.md); the node's key and
REM configuration file handling is POSIX-only and is not built here.
cmake -GNinja  -DCMAKE_BUILD_TYPE=Release ^
-DCMAKE_C_COMPILER=clang-cl ^
-DCMAKE_CXX_COMPILER=clang-cl ^
-DCMAKE_LINKER=lld-link ^
-DTOS_CLIENT_ONLY=ON ^
-DCCACHE_FOUND= ^
-DCMAKE_CXX_COMPILER_LAUNCHER= ^
-DPORTABLE=1 ^
%TOS_PROD_FLAG% ^
-DCMAKE_CXX_FLAGS="/DTD_WINDOWS=1 /EHsc /bigobj" ..

IF %errorlevel% NEQ 0 (
  echo Can't configure TOS
  exit /b %errorlevel%
)

SET TOS_CLIENT_TARGETS=fift func tlbc tol toslib toslibjson toslib-cli lite-client emulator
IF "%1"=="-t" SET TOS_CLIENT_TARGETS=%TOS_CLIENT_TARGETS% all-tests
ninja %TOS_CLIENT_TARGETS%
IF %errorlevel% NEQ 0 (
  echo Can't compile TOS
  exit /b %errorlevel%
)

echo Strip and copy artifacts
cd ..
echo where strip
where strip
mkdir artifacts
mkdir artifacts\smartcont
mkdir artifacts\lib

for %%I in (build\crypto\fift.exe ^
  build\crypto\tlbc.exe ^
  build\crypto\func.exe ^
  build\tol\tol.exe ^
  build\toslib\toslib-cli.exe ^
  build\toslib\toslibjson.dll ^
  build\lite-client\lite-client.exe ^
  build\emulator\emulator.dll) do (
    IF NOT EXIST %%I (
      echo Missing artifact %%I
      exit /b 1
    )
    REM Stripping is best effort; a missing strip leaves the binary as built.
    strip -s %%I
    copy %%I artifacts\ || exit /b 1
)

xcopy /e /k /h /i crypto\smartcont artifacts\smartcont
xcopy /e /k /h /i crypto\fift\lib artifacts\lib
