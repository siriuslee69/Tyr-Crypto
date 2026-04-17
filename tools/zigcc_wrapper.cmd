@echo off
setlocal

set "ROOT_DIR=%~dp0.."
set "ZIG_GLOBAL_CACHE_DIR=%ROOT_DIR%\build\zig_global_cache"
set "ZIG_LOCAL_CACHE_DIR=%ROOT_DIR%\build\zig_local_cache"
set "TMP=%ROOT_DIR%\build\zig_tmp"
set "TEMP=%TMP%"

if not exist "%ZIG_GLOBAL_CACHE_DIR%" mkdir "%ZIG_GLOBAL_CACHE_DIR%"
if not exist "%ZIG_LOCAL_CACHE_DIR%" mkdir "%ZIG_LOCAL_CACHE_DIR%"
if not exist "%TMP%" mkdir "%TMP%"

if "%~1"=="--version" (
  shift
  zig cc --version %*
  exit /b %ERRORLEVEL%
)

zig cc %*
exit /b %ERRORLEVEL%
