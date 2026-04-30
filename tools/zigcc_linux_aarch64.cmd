@echo off
setlocal
set ZIGDIR=%~dp0..\build\zig-windows-x86_64-0.13.0
set ZIGEXE=%ZIGDIR%\zig.exe
set ZIG_GLOBAL_CACHE_DIR=%~dp0..\build\zig-global-cache
set ZIG_LOCAL_CACHE_DIR=%~dp0..\build\zig-local-cache-aarch64
set TMP=%~dp0..\build\tmp
set TEMP=%~dp0..\build\tmp
if not exist "%ZIGEXE%" (
  echo Missing Zig toolchain at "%ZIGEXE%".
  exit /b 1
)
if not exist "%ZIG_GLOBAL_CACHE_DIR%" mkdir "%ZIG_GLOBAL_CACHE_DIR%"
if not exist "%ZIG_LOCAL_CACHE_DIR%" mkdir "%ZIG_LOCAL_CACHE_DIR%"
if not exist "%TMP%" mkdir "%TMP%"
"%ZIGEXE%" cc -target aarch64-linux-musl -static %*
