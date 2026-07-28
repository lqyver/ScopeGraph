@echo off
setlocal EnableExtensions
cd /d "%~dp0"

set "NO_OPEN=0"
set "BUILD_IMAGES=1"
set "APP_URL=http://127.0.0.1:8080/projects"
set "HEALTH_URL=http://127.0.0.1:8080/api/health"

:parse_args
if "%~1"=="" goto args_done
if /i "%~1"=="--no-open" set "NO_OPEN=1"
if /i "%~1"=="--open" set "NO_OPEN=0"
if /i "%~1"=="--no-build" set "BUILD_IMAGES=0"
if /i "%~1"=="--help" goto usage
shift
goto parse_args

:args_done

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

where curl.exe >nul 2>&1
if errorlevel 1 (
  set "FAIL_MESSAGE=curl.exe was not found, so the web health check cannot run."
  goto fail
)

echo [ScopeGraph] Checking Docker Desktop...
docker info >nul 2>&1
if not errorlevel 1 goto docker_ready

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
docker info >nul 2>&1
if not errorlevel 1 goto docker_ready
set /a tries+=1
if %tries% geq 60 goto docker_timeout
ping.exe 127.0.0.1 -n 3 >nul
goto wait_docker

:docker_timeout
set "FAIL_MESSAGE=Docker Desktop did not become ready within two minutes."
goto fail

:docker_ready
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
curl.exe -fsS "%HEALTH_URL%" >nul 2>&1
if errorlevel 1 goto wait_web_retry

rem The API proxy can become healthy slightly before the Next.js page is ready.
curl.exe -fsS "%APP_URL%" >nul 2>&1
if not errorlevel 1 goto web_ready

:wait_web_retry
set /a tries+=1
if %tries% geq 90 goto web_timeout
ping.exe 127.0.0.1 -n 3 >nul
goto wait_web

:web_timeout
set "FAIL_MESSAGE=Services started, but the web health check did not pass within two minutes."
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
echo [ScopeGraph] Current service state:
docker compose ps 2>nul
echo [ScopeGraph] Recent service logs:
docker compose logs --tail 80 2>nul
if "%NO_OPEN%"=="0" pause
exit /b 1

:usage
echo Usage: Start-ScopeGraph.cmd [--open^|--no-open] [--no-build]
echo.
echo   --open      Open the ScopeGraph Web page after the Web and API checks pass. Default.
echo   --no-open   Start and verify ScopeGraph without opening a browser.
echo   --no-build  Reuse existing images and preserve healthy containers. By default changed source is rebuilt.
exit /b 0
