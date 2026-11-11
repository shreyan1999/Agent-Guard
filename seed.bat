@echo off
setlocal enableextensions

REM One-click demo re-seed. Run this any time during the demo -- e.g. after a
REM --reload restart, which clears the in-memory audit chain -- to reload the
REM agents, child policy, governed calls, MCP receipts and traces.
REM
REM It drives the in-process POST /demo/seed endpoint, which (unlike the terminal
REM seed_demo.py) starts the bundled demo MCP server itself and lifts the loopback
REM guard for the import, so the signed MCP governance receipts are produced too.
REM Nothing is fabricated: every row is a real, gated call. DELETE /audit first
REM gives a fresh chain, so the result is the same each time.

set "HOST=127.0.0.1"

where curl >nul 2>&1
if errorlevel 1 (
  echo ERROR: curl not found. Use the "Load demo data" button in the dashboard instead.
  exit /b 1
)

REM Confirm the API is up before seeding, so the failure message is truthful.
curl -sf "http://%HOST%:8000/health" >nul 2>&1
if errorlevel 1 (
  echo ERROR: API not reachable at http://%HOST%:8000 -- start it first with start.bat.
  exit /b 1
)

echo Loading demo data into http://%HOST%:8000 ...
curl -s -X DELETE "http://%HOST%:8000/audit" >nul 2>&1
curl -sf -X POST "http://%HOST%:8000/demo/seed" >nul
if errorlevel 1 (
  echo.
  echo Seed did not complete. If API auth is enabled, POST /demo/seed needs an admin token.
  exit /b 1
)

echo.
echo Demo data loaded (agents, policy, governed calls, MCP receipts, traces).
echo Refresh the dashboard at http://localhost:3000
endlocal
