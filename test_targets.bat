@echo off
REM Windows batch script for testing multiple targets

echo === Testing Penetration Testing Toolkit ===
echo.

echo Testing localhost...
echo 3 | pentest.exe localhost
echo.

echo Testing example.com...
echo 3 | pentest.exe example.com
echo.

echo Testing httpbin.org...
echo 3 | pentest.exe httpbin.org
echo.

echo === Testing complete ===
echo Check reports/report.json for latest results
pause
