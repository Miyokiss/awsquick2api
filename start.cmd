@echo off
setlocal
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0start.ps1"
set "quickpool_exit=%ERRORLEVEL%"
if not "%quickpool_exit%"=="0" (
    echo.
    echo QuickPool failed to start. Read the error above.
    pause
)
exit /b %quickpool_exit%
