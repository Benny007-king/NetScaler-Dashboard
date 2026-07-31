@echo off
REM One-command upgrade for Windows (cmd or PowerShell: run  .\upgrade.bat ).
REM Re-attaches to main and fast-forwards, which also recovers a detached-HEAD
REM checkout (e.g. after "git checkout vX.Y.Z"), so the build is never mislabelled.
cd /d "%~dp0"

echo Updating source (main)...
git checkout main || goto :err
git pull --ff-only || goto :err

set /p APP_VERSION=<VERSION
echo Building netscaler-dashboard:%APP_VERSION% ...
docker compose up -d --build || goto :err

echo Now running:
docker inspect netscaler-dashboard --format "{{index .Config.Labels \"org.opencontainers.image.version\"}}"
goto :eof

:err
echo.
echo Upgrade failed - see the message above.
exit /b 1
