@echo off
echo =================================
echo  Starting WiredGeist Mail Guard
echo =================================
echo.

echo Activating virtual environment...
call venv\Scripts\activate

echo.
echo Launching the application (app.py)...
echo.
python app.py

echo.
echo Application finished. Press any key to close this window.
pause > nul