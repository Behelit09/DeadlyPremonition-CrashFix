@echo off
setlocal enabledelayedexpansion

cd /d "%~dp0"

if not exist dist mkdir dist

set "CSC_EXE=%SystemRoot%\Microsoft.NET\Framework\v4.0.30319\csc.exe"
if not exist "%CSC_EXE%" (
    echo [ERROR] csc.exe not found at %CSC_EXE%
    exit /b 1
)

if not exist "tools\build_asi.exe" (
    echo [*] Compiling build helper...
    "%CSC_EXE%" /nologo /optimize /out:"tools\build_asi.exe" "tools\build_asi.cs"
    if errorlevel 1 (
        echo [ERROR] Failed to compile build helper.
        exit /b 1
    )
)

echo [*] Building CrashFix.asi...
"tools\build_asi.exe" "CrashFix\CrashFix.c" "dist\CrashFix.asi"
if errorlevel 1 (
    echo [ERROR] Failed to build CrashFix.asi
    exit /b 1
)
copy /y "CrashFix\CrashFix.ini" "dist\CrashFix.ini" >nul

echo [*] Building CrashLogger.asi...
"tools\build_asi.exe" "CrashLogger\CrashLogger.c" "dist\CrashLogger.asi"
if errorlevel 1 (
    echo [ERROR] Failed to build CrashLogger.asi
    exit /b 1
)
copy /y "CrashLogger\CrashLogger.ini" "dist\CrashLogger.ini" >nul

if exist "dist\.zig-cache" rd /s /q "dist\.zig-cache" >nul 2>nul
if exist "CrashFix\.obj" del /f /q "CrashFix\.obj" >nul 2>nul
if exist "CrashLogger\.obj" del /f /q "CrashLogger\.obj" >nul 2>nul

echo [*] Build complete. Output files placed in dist\
exit /b 0
