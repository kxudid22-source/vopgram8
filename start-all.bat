@echo off
echo Starting Vopgram server...
start /B node server.js
timeout /t 3 /nobreak >nul
echo Starting tunnel with auto-restart...
:loop
npx localtunnel --port 3000
echo Tunnel died, restarting in 3 seconds...
timeout /t 3 /nobreak >nul
goto loop
