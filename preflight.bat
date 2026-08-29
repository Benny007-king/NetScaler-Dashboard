@echo off
REM Check everything needed to run the NetScaler Dashboard and print a download
REM link for whatever is missing. Read-only: installs nothing, changes nothing.
REM
REM   preflight.bat            check the Docker install (recommended)
REM   preflight.bat python     check running from source instead
setlocal enabledelayedexpansion
cd /d "%~dp0"

set "MODE=%~1"
if "%MODE%"=="" set "MODE=docker"
set /a MISSING=0
set /a WARN=0

set "L_DOCKER=https://www.docker.com/products/docker-desktop/  (needs WSL2: https://learn.microsoft.com/windows/wsl/install)"
set "L_COMPOSE=Ships with Docker Desktop - https://docs.docker.com/compose/install/"
set "L_GIT=https://git-scm.com/download/win"
set "L_PY=https://www.python.org/downloads/windows/  (tick \"Add python.exe to PATH\")"

echo.
echo NetScaler Dashboard - preflight check   (Windows, %MODE% install)
echo --------------------------------------------------------------------

REM ---- always needed --------------------------------------------------------
where git >nul 2>&1
if errorlevel 1 (
  call :bad "Git" "needed to clone and to run upgrade.bat" "%L_GIT%"
) else (
  for /f "delims=" %%v in ('git --version 2^>nul') do set "GITV=%%v"
  call :ok "Git" "!GITV!"
)

if /i "%MODE%"=="python" goto :python_checks

REM ---- containerised (default) ---------------------------------------------
where docker >nul 2>&1
if errorlevel 1 (
  call :bad "Docker" "runs the dashboard container" "%L_DOCKER%"
  call :bad "Docker Compose v2" "ships with Docker Desktop" "%L_COMPOSE%"
) else (
  for /f "delims=" %%v in ('docker --version 2^>nul') do set "DKV=%%v"
  call :ok "Docker" "!DKV!"
  docker info >nul 2>&1
  if errorlevel 1 (
    call :bad "Docker daemon" "installed but not running - start Docker Desktop" ""
  ) else (
    call :ok "Docker daemon" "running"
  )
  docker compose version >nul 2>&1
  if errorlevel 1 (
    call :bad "Docker Compose v2" "the 'docker compose' plugin, not docker-compose" "%L_COMPOSE%"
  ) else (
    for /f "delims=" %%v in ('docker compose version --short 2^>nul') do set "DCV=%%v"
    call :ok "Docker Compose v2" "!DCV!"
  )
)
goto :ports

REM ---- running from source --------------------------------------------------
:python_checks
set "PYOK="
where python >nul 2>&1
if not errorlevel 1 (
  python -c "import sys; sys.exit(0 if sys.version_info>=(3,9) else 1)" >nul 2>&1
  if not errorlevel 1 set "PYOK=python"
)
if not defined PYOK (
  where py >nul 2>&1
  if not errorlevel 1 (
    py -3 -c "import sys; sys.exit(0 if sys.version_info>=(3,9) else 1)" >nul 2>&1
    if not errorlevel 1 set "PYOK=py -3"
  )
)
if not defined PYOK (
  call :bad "Python 3.9+" "the app targets Python 3.9 or newer" "%L_PY%"
) else (
  for /f "delims=" %%v in ('%PYOK% --version 2^>^&1') do set "PYV=%%v"
  call :ok "Python 3.9+" "!PYV!"
  %PYOK% -m pip --version >nul 2>&1
  if errorlevel 1 (
    call :bad "pip" "needed for: pip install -r requirements.txt" "%L_PY%"
  ) else (
    call :ok "pip" "present"
  )
)

REM ---- environment (warnings only) -----------------------------------------
:ports
call :portcheck 443
call :portcheck 80

echo --------------------------------------------------------------------
if %MISSING%==0 (
  echo All required dependencies present.
  if not %WARN%==0 echo   ^(%WARN% warning^(s^) above^)
  echo.
  if /i "%MODE%"=="python" (
    echo   Next:  pip install -r requirements.txt  ^&^&  python app.py
  ) else (
    echo   Next:  docker compose up -d --build      ^(then open https://localhost/^)
  )
  echo.
  exit /b 0
)
echo %MISSING% required dependency^(ies^) missing - install the link^(s^) above, then re-run.
echo.
echo   Full guide: https://net-scaler-dashboard-web.vercel.app/docs.html#deps
echo.
exit /b 1

REM ---------------------------------------------------------------- helpers
:ok
echo   [ OK ] %~1 - %~2
exit /b 0

:bad
echo   [MISS] %~1 - %~2
if not "%~3"=="" echo          -^> %~3
set /a MISSING+=1
exit /b 0

:portcheck
netstat -ano -p tcp 2>nul | findstr /r /c:":%~1 .*LISTENING" >nul 2>&1
if errorlevel 1 (
  echo   [ OK ] Port %~1 - free
) else (
  echo   [WARN] Port %~1 - already in use, free it or change APP_PORT in .env
  set /a WARN+=1
)
exit /b 0
