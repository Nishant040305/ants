@echo off
REM ANTS HTTP Packet Analyzer - Windows Launcher
echo Starting ANTS HTTP Packet Analyzer...
echo.
echo ⚠️  This requires administrator privileges for packet capture!
echo.
python ants.py %*
pause