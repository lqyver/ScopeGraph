@echo off
setlocal EnableExtensions
cd /d "%~dp0"

set "EDITION=community"
set "DEFAULT_COMPOSE_PROJECT=scopegraph-community"
set "DEFAULT_WEB_HOST_PORT=18080"
set "COMPOSE_PROJECT=%DEFAULT_COMPOSE_PROJECT%"
set "WEB_HOST_PORT=%DEFAULT_WEB_HOST_PORT%"
if exist ".env" (
  for /f "usebackq tokens=1,* delims==" %%A in (".env") do (
    if /i "%%A"=="SCOPEGRAPH_COMPOSE_PROJECT" set "COMPOSE_PROJECT=%%B"
    if /i "%%A"=="SCOPEGRAPH_WEB_HOST_PORT" set "WEB_HOST_PORT=%%B"
  )
)
if defined SCOPEGRAPH_COMPOSE_PROJECT set "COMPOSE_PROJECT=%SCOPEGRAPH_COMPOSE_PROJECT%"
if defined SCOPEGRAPH_WEB_HOST_PORT set "WEB_HOST_PORT=%SCOPEGRAPH_WEB_HOST_PORT%"
set "COMPOSE_PROJECT=%COMPOSE_PROJECT:"=%"
set "WEB_HOST_PORT=%WEB_HOST_PORT:"=%"

set "NO_OPEN=0"
set "BUILD_IMAGES=1"
set "CHECK_ONLY=0"
set "OFFLINE_CHECK=0"
set "APP_URL=http://127.0.0.1:%WEB_HOST_PORT%/projects"
set "HEALTH_URL=http://127.0.0.1:%WEB_HOST_PORT%/api/health"

:parse_args
if "%~1"=="" goto args_done
if /i "%~1"=="--no-open" goto arg_no_open
if /i "%~1"=="--open" goto arg_open
if /i "%~1"=="--no-build" goto arg_no_build
if /i "%~1"=="--check" goto arg_check
if /i "%~1"=="--offline-check" goto arg_offline_check
if /i "%~1"=="--help" goto usage
set "FAIL_MESSAGE=Unknown argument: %~1"
goto usage_error

:arg_no_open
set "NO_OPEN=1"
shift
goto parse_args

:arg_open
set "NO_OPEN=0"
shift
goto parse_args

:arg_no_build
set "BUILD_IMAGES=0"
shift
goto parse_args

:arg_check
set "CHECK_ONLY=1"
shift
goto parse_args

:arg_offline_check
set "CHECK_ONLY=1"
set "OFFLINE_CHECK=1"
shift
goto parse_args

:args_done

echo [ScopeGraph] Edition: %EDITION% ^| Compose project: %COMPOSE_PROJECT% ^| Web port: %WEB_HOST_PORT%
echo [ScopeGraph] Checking prerequisites...
where docker.exe >nul 2>&1
if errorlevel 1 (
  set "FAIL_MESSAGE=Docker CLI was not found. Install Docker Desktop first."
  goto fail
)

docker compose version >nul 2>&1
if errorlevel 1 (
  set "FAIL_MESSAGE=Docker Compose v2 is unavailable. Update Docker Desktop first."
  goto fail
)

echo [ScopeGraph] Validating the Compose configuration...
docker compose config --quiet >nul 2>&1
if errorlevel 1 (
  set "FAIL_MESSAGE=The Docker Compose configuration is invalid. Run docker compose config for details."
  goto fail
)

if "%OFFLINE_CHECK%"=="1" (
  echo [ScopeGraph] Offline checks passed. No Docker daemon, container, browser, or target network was contacted.
  exit /b 0
)

where curl.exe >nul 2>&1
if errorlevel 1 (
  set "FAIL_MESSAGE=curl.exe was not found, so the web health check cannot run."
  goto fail
)

for /f "delims=" %%C in ('docker context show 2^>nul') do set "DOCKER_CONTEXT=%%C"
if defined DOCKER_CONTEXT echo [ScopeGraph] Docker context: %DOCKER_CONTEXT%
echo [ScopeGraph] Checking Docker Desktop...
call :check_docker_ready >nul 2>&1
if not errorlevel 1 goto docker_ready

rem Only try Docker Desktop's Linux context after the selected context fails.
if /i "%DOCKER_CONTEXT%"=="default" (
  docker context inspect desktop-linux >nul 2>&1
  if not errorlevel 1 (
    set "DOCKER_CONTEXT=desktop-linux"
    echo [ScopeGraph] Selected context is unavailable; trying Docker Desktop context: desktop-linux
    call :check_docker_ready >nul 2>&1
    if not errorlevel 1 goto docker_ready
  )
)

if "%CHECK_ONLY%"=="1" (
  set "FAIL_MESSAGE=Docker Desktop is not reachable. --check never starts Docker; start Docker Desktop and retry."
  goto fail
)

set "DOCKER_DESKTOP=%ProgramFiles%\Docker\Docker\Docker Desktop.exe"
if not exist "%DOCKER_DESKTOP%" set "DOCKER_DESKTOP=%LocalAppData%\Docker\Docker Desktop.exe"
if not exist "%DOCKER_DESKTOP%" (
  set "FAIL_MESSAGE=Docker Desktop was not found. Install or start Docker Desktop first."
  goto fail
)

echo [ScopeGraph] Starting Docker Desktop. This can take up to two minutes...
start "" "%DOCKER_DESKTOP%"
set /a tries=0

:wait_docker
call :check_docker_ready >nul 2>&1
if not errorlevel 1 goto docker_ready
set /a tries+=1
if %tries% geq 60 goto docker_timeout
ping.exe 127.0.0.1 -n 3 >nul
goto wait_docker

:docker_timeout
set "FAIL_MESSAGE=Docker Desktop did not become ready within the configured startup timeout."
goto fail

:docker_ready
if "%CHECK_ONLY%"=="1" (
  echo [ScopeGraph] Docker, Compose, and engine checks passed. No services were started.
  exit /b 0
)

if "%BUILD_IMAGES%"=="1" (
  echo [ScopeGraph] Building changed images and starting local services...
  docker compose up -d --build
) else (
  echo [ScopeGraph] Reusing existing images without restarting healthy services...
  rem A fast launch must not interrupt a scan that is already running. Compose
  rem will still start missing or stopped services, but preserves matching ones.
  docker compose up -d --no-recreate
)
if errorlevel 1 (
  set "FAIL_MESSAGE=Services could not be started. Review the Docker message above."
  goto fail
)

echo [ScopeGraph] Waiting for the web application...
set /a tries=0

:wait_web
curl.exe --fail --silent --show-error --connect-timeout 2 --max-time 5 "%HEALTH_URL%" >nul 2>&1
if errorlevel 1 goto wait_web_retry

rem The API proxy can become healthy slightly before the Next.js page is ready.
curl.exe --fail --silent --show-error --connect-timeout 2 --max-time 5 "%APP_URL%" >nul 2>&1
if not errorlevel 1 goto web_ready

:wait_web_retry
set /a tries+=1
if %tries% geq 60 goto web_timeout
ping.exe 127.0.0.1 -n 3 >nul
goto wait_web

:web_timeout
set "FAIL_MESSAGE=Services started, but the web health check did not pass within the configured startup timeout."
goto fail

:web_ready
echo [ScopeGraph] Ready: %APP_URL%
if "%NO_OPEN%"=="1" exit /b 0
echo [ScopeGraph] Opening ScopeGraph in your default browser...
start "" "%APP_URL%" >nul 2>&1
if not errorlevel 1 goto browser_opened

rem Some Windows associations reject start with a URL. Explorer uses the shell handler.
echo [ScopeGraph] Retrying browser launch through Windows Explorer...
start "" explorer.exe "%APP_URL%" >nul 2>&1
if not errorlevel 1 goto browser_opened

echo [ScopeGraph] Browser could not be launched automatically. Open this URL manually:
echo %APP_URL%
exit /b 0

:browser_opened
echo [ScopeGraph] Browser launch requested. If no tab appears, open: %APP_URL%
exit /b 0

:fail
echo.
echo [ScopeGraph] ERROR: %FAIL_MESSAGE%
if "%CHECK_ONLY%"=="1" goto fail_without_diagnostics
echo [ScopeGraph] Current service state:
docker compose ps 2>nul
echo [ScopeGraph] Recent service logs:
docker compose logs --tail 80 2>nul
if "%NO_OPEN%"=="0" pause
exit /b 1

:fail_without_diagnostics
echo [ScopeGraph] No containers were started or inspected by this check.
exit /b 1

:check_docker_ready
powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "$p=Start-Process -FilePath 'docker.exe' -ArgumentList 'info' -WindowStyle Hidden -PassThru; if(-not $p.WaitForExit(5000)){try{$p.Kill()}catch{}; exit 124}; exit $p.ExitCode"
exit /b %errorlevel%

:usage
echo Usage: Start-ScopeGraph.cmd [--open^|--no-open] [--no-build] [--check^|--offline-check]
echo.
echo   --open      Open the ScopeGraph Web page after the Web and API checks pass. Default.
echo   --no-open   Start and verify ScopeGraph without opening a browser.
echo   --no-build  Reuse existing images and preserve healthy containers. By default changed source is rebuilt.
echo   --check     Validate Docker, Compose, and the Docker daemon without starting services.
echo   --offline-check  Validate CLI and Compose configuration only; do not contact Docker or any network.
exit /b 0

:usage_error
echo [ScopeGraph] ERROR: %FAIL_MESSAGE%
echo.
echo Usage: Start-ScopeGraph.cmd [--open^|--no-open] [--no-build] [--check^|--offline-check]
exit /b 2
