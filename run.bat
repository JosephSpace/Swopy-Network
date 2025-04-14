@echo off
title Swopy Network - JosephSpace (SW)

echo Starting Swopy Network...
echo.

:: Check if Python is installed
python --version >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo Python not found! Please install Python: https://www.python.org/downloads/
    pause
    exit /b
)

:: Install required libraries
echo Checking and installing required libraries...
pip install python-nmap scapy colorama speedtest-cli manuf psutil tabulate >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo Error occurred while installing libraries!
    pause
    exit /b
)

:: Run the Python script
echo Launching Swopy Network...
python swopy-network.py

:: Prevent terminal from closing
pause