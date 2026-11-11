@echo off
setlocal enableextensions

echo ===================================================
echo    AgentGuard - Windows launcher
echo ===================================================
echo.

REM Resolve paths relative to this script.
set "ROOT=%~dp0"
set "BACKEND=%ROOT%backend"
set "FRONTEND=%ROOT%frontend"

REM Durable state so Decision traces and per-agent SLOs persist; loopback allowed
REM so the demo MCP server's tools can be imported when the scenario is seeded.
if "%AGT_STATE_DIR%"==""          set "AGT_STATE_DIR=%BACKEND%\state"
if "%AGT_HOST%"==""               set "AGT_HOST=127.0.0.1"
if "%AGT_TOOL_ALLOW_PRIVATE%"=="" set "AGT_TOOL_ALLOW_PRIVATE=1"

REM Prerequisites.
where python >nul 2>&1 || (echo ERROR: Python not found on PATH. Install Python 3.11+.& exit /b 1)
where node   >nul 2>&1 || (echo ERROR: Node.js not found on PATH. Install Node 18+.& exit /b 1)
where npm    >nul 2>&1 || (echo ERROR: npm not found on PATH.& exit /b 1)

REM ----- Backend: virtualenv + dependencies -----
echo Setting up Python backend...
cd /d "%BACKEND%"
if not exist ".venv\Scripts\python.exe" python -m venv .venv
set "VENV_PY=%BACKEND%\.venv\Scripts\python.exe"
"%VENV_PY%" -m pip install -q --upgrade pip
"%VENV_PY%" -m pip install -q -r requirements.txt || (echo ERROR: backend dependency install failed.& exit /b 1)

REM Start the API in its own window (inherits AGT_* and this cwd). --reload is a
REM dev convenience; note the audit chain lives in memory and starts empty, so
REM the seed below runs after startup to populate it.
echo Starting backend on http://%AGT_HOST%:8000  (state: %AGT_STATE_DIR%)
start "AgentGuard API" cmd /k "%VENV_PY%" -m uvicorn main:app --host %AGT_HOST% --port 8000 --reload

REM ----- Wait for the API to report healthy, then seed -----
where curl >nul 2>&1
if errorlevel 1 (
  echo curl not found; waiting 8s before seeding...
  timeout /t 8 /nobreak >nul
  goto seed
)

echo Waiting for the API to become healthy...
set /a tries=0
:waitloop
set /a tries+=1
curl -sf "http://%AGT_HOST%:8000/health" >nul 2>&1
if not errorlevel 1 goto seed
if %tries% geq 60 (
  echo WARNING: API did not report healthy after 60s; skipping demo seed.
  goto frontend
)
timeout /t 1 /nobreak >nul
goto waitloop

:seed
REM Load the demo scenario in-process via POST /demo/seed. Unlike the terminal
REM seeder, this endpoint starts the bundled demo MCP server itself and lifts
REM the loopback guard for the import, so signed MCP receipts and Decision
REM traces are produced too -- not just the governed calls. DELETE /audit first
REM gives a fresh chain. Non-fatal: the "Load demo data" button (or seed.bat)
REM can fill an empty dashboard later.
where curl >nul 2>&1
if errorlevel 1 (
  echo curl not found; skipping demo seed. Use the "Load demo data" button in the UI.
  goto frontend
)
echo Loading demo data (agents, policy, governed calls, MCP receipts, traces)...
curl -s -X DELETE "http://%AGT_HOST%:8000/audit" >nul 2>&1
curl -sf -X POST "http://%AGT_HOST%:8000/demo/seed" >nul || echo WARNING: demo seed did not complete; the dashboard will start empty.

:frontend
REM ----- Frontend: dependencies + dev server -----
echo Setting up React frontend...
cd /d "%FRONTEND%"
if not exist "node_modules" call npm install || (echo ERROR: frontend dependency install failed.& exit /b 1)
echo Starting frontend on http://localhost:3000
start "AgentGuard UI" cmd /k "set BROWSER=none && npm start"

REM Give CRA a moment to bind, then open the dashboard.
timeout /t 3 /nobreak >nul
start "" http://localhost:3000

echo.
echo ===================================================
echo   Dashboard : http://localhost:3000
echo   API       : http://localhost:8000
echo   API docs  : http://localhost:8000/docs
echo ===================================================
echo Two windows opened (AgentGuard API, AgentGuard UI).
echo Close those windows to stop the servers.

endlocal
