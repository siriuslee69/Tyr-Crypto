@echo off
setlocal
set ZIGDIR=%~dp0..\build\zig-windows-x86_64-0.13.0
set ZIGEXE=%ZIGDIR%\zig.exe
if not exist "%ZIGEXE%" (
  echo Missing Zig toolchain at "%ZIGEXE%".
  exit /b 1
)
"%ZIGEXE%" cc -target aarch64-linux-android.24 %*
