@echo off
setlocal enabledelayedexpansion
title ThreatCheck
:start
cls
echo Welcome to ThreatCheck
echo -----------------------
echo.
echo   News shortcuts:  n        (last 24h)
echo                    n 48     (last 48 hours)
echo                    n 7d     (last 7 days)
echo                    n all    (everything)
echo.
REM Clear the variable first so previous loops don't stick
set "target_ip="
set /p target_ip="Enter IP address to check, 'n [since]' for News, or 'q' to quit: "

REM Check if input is empty
if "%target_ip%"=="" goto start

if /i "%target_ip%"=="q" exit

REM Check if input starts with 'n' (news command)
set "first_char=%target_ip:~0,1%"
if /i "!first_char!"=="n" (
    set "since_val=!target_ip:~2!"
    if "!since_val!"=="" (
        python threatcheck.py --news
    ) else (
        python threatcheck.py --news --news-since !since_val!
    )
    pause
    goto start
)

REM Default case: Check the IP
python threatcheck.py "%target_ip%"
echo.
pause
goto start