@echo off
setlocal EnableExtensions
title SYSACK Agent - Instalador/Atualizador

set "SYSACK_DIR=C:\SYSACK"
set "AGENT_URL=https://sysack.vercel.app/agent-desktop.js"
set "AGENT_FILE=%SYSACK_DIR%\agent.js"
set "START_FILE=%SYSACK_DIR%\start.bat"
set "LOG_FILE=%SYSACK_DIR%\install.log"
set "TASK_NAME=SYSACK-Agent"
set "TMP_AGENT=%TEMP%\sysack-agent-download.js"

echo.
echo ============================================================
echo  SYSACK Agent - Instalador/Atualizador
echo ============================================================
echo.

net session >nul 2>&1
if errorlevel 1 (
  echo [ERRO] Execute este arquivo como Administrador.
  pause
  exit /b 1
)

if not exist "%SYSACK_DIR%" mkdir "%SYSACK_DIR%" >nul 2>&1
echo [%date% %time%] Iniciando instalacao/atualizacao >> "%LOG_FILE%"

echo [1/7] Parando tarefa anterior, se existir...
schtasks /end /tn "%TASK_NAME%" >nul 2>&1

echo [2/7] Encerrando processo antigo do agente...
for /f "skip=1 tokens=2 delims=," %%P in ('wmic process where "name='node.exe' and commandline like '%%C:\\SYSACK\\agent.js%%'" get ProcessId /format:csv 2^>nul') do (
  if not "%%P"=="" taskkill /PID %%P /F >nul 2>&1
)

echo [3/7] Verificando Node.js...
where node >nul 2>&1
if errorlevel 1 (
  echo [ERRO] Node.js nao encontrado.
  pause
  exit /b 1
)

echo [4/7] Baixando agente atualizado...
if exist "%TMP_AGENT%" del "%TMP_AGENT%" >nul 2>&1

powershell -NoProfile -ExecutionPolicy Bypass -Command "$ErrorActionPreference='Stop'; [Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12; $url='%AGENT_URL%'; $out='%TMP_AGENT%'; Invoke-WebRequest -Uri $url -OutFile $out -UseBasicParsing; if(-not (Test-Path $out)){ throw 'Arquivo nao baixado' }; $len=(Get-Item $out).Length; if($len -lt 10000){ throw ('Arquivo baixado muito pequeno: ' + $len + ' bytes') }; $txt=Get-Content $out -Raw; if(($txt -notmatch 'SYSACK') -and ($txt -notmatch 'Agent')){ throw 'Conteudo baixado nao parece ser o agente SYSACK' }; Write-Host ('Download OK: ' + $len + ' bytes')"

if errorlevel 1 (
  echo.
  echo [ERRO] Falha ao baixar agente de %AGENT_URL%
  echo Verifique se estes dois arquivos estao publicados na Vercel:
  echo   https://sysack.vercel.app/Instalar-SYSACK-Agent.bat
  echo   https://sysack.vercel.app/agent-desktop.js
  pause
  exit /b 1
)

if exist "%AGENT_FILE%" copy /Y "%AGENT_FILE%" "%SYSACK_DIR%\agent.backup.js" >nul 2>&1

echo [5/7] Instalando em %AGENT_FILE%...
copy /Y "%TMP_AGENT%" "%AGENT_FILE%" >nul
if errorlevel 1 (
  echo [ERRO] Nao foi possivel copiar o agente para %AGENT_FILE%
  pause
  exit /b 1
)

del "%TMP_AGENT%" >nul 2>&1

echo [6/7] Criando inicializador...
(
  echo @echo off
  echo cd /d "%SYSACK_DIR%"
  echo node "%AGENT_FILE%" ^>^> "%SYSACK_DIR%\agent-runtime.log" 2^>^&1
) > "%START_FILE%"

schtasks /delete /tn "%TASK_NAME%" /f >nul 2>&1

echo [7/7] Criando tarefa agendada %TASK_NAME%...
schtasks /create /tn "%TASK_NAME%" /tr "\"%START_FILE%\"" /sc onstart /ru SYSTEM /rl HIGHEST /f
if errorlevel 1 (
  echo [ERRO] Falha ao criar tarefa agendada.
  pause
  exit /b 1
)

schtasks /run /tn "%TASK_NAME%" >nul 2>&1
timeout /t 3 >nul

echo.
echo Verificando processo...
wmic process where "name='node.exe' and commandline like '%%C:\\SYSACK\\agent.js%%'" get ProcessId,CommandLine 2>nul

echo.
echo ============================================================
echo  SYSACK Agent instalado/atualizado com sucesso.
echo ============================================================
echo Arquivo em execucao: %AGENT_FILE%
echo Tarefa agendada: %TASK_NAME%
echo Logs: %LOG_FILE% e %SYSACK_DIR%\agent-runtime.log
echo ============================================================
echo.

pause
exit /b 0
