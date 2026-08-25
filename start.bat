@echo off
echo ===================================================
echo    AGT Governance Dashboard - Windows Setup
echo ===================================================

echo.
echo Setting up Python backend...
cd backend
python -m venv .venv
call .venv\Scripts\activate.bat
pip install -q -r requirements.txt
if "%AGT_HOST%"=="" set AGT_HOST=127.0.0.1
start /B python -m uvicorn main:app --host %AGT_HOST% --port 8000 --reload
echo Backend started on http://%AGT_HOST%:8000

cd ..\frontend
echo.
echo Setting up React frontend...
call npm install
start http://localhost:3000
npm start

cd ..
