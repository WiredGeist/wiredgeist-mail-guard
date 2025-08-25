@echo off
setlocal

:: --- Python Version Check (Now specifically for 3.10) ---
echo Checking for Python 3.10...

py -3.10 -c "import sys; sys.exit(0)" 2>nul
if %errorlevel% neq 0 (
    echo ERROR: Python 3.10 was not found by the 'py' launcher.
    echo Please install Python 3.10 and ensure it's added to your PATH.
    echo You can check by running 'py -3.10 --version' in a new command prompt.
    goto :eof
)

echo Found Python 3.10.
echo.

:: --- Virtual Environment and Installation ---
echo Creating virtual environment with Python 3.10...

:: ==========================================================
::  THIS IS THE KEY CHANGE. We are forcing the venv to use Python 3.10.
:: ==========================================================
py -3.10 -m venv venv

echo.
echo Activating virtual environment...
call venv\Scripts\activate

echo.
echo Clearing pip cache to prevent issues...
pip cache purge

echo.
echo Installing required packages from requirements.txt...
pip install -r requirements.txt

echo.
echo All dependencies installed successfully.
echo.
echo =================================
echo  Running the application (app.py)
echo =================================
echo.
python app.py

echo.
echo Application finished. Press any key to exit.
pause > nul

endlocal