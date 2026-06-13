@echo off
setlocal EnableExtensions EnableDelayedExpansion
title Instalador SYSACK Agent

set "SYSACK_DIR=C:\SYSACK"
set "AGENT_URL=https://sysack.vercel.app/agent-desktop.js"
set "AGENT_FILE=%SYSACK_DIR%\agent.js"
set "START_FILE=%SYSACK_DIR%\start.bat"
set "LOG_FILE=%SYSACK_DIR%\install.log"
set "TASK_NAME=SYSACK-Agent"
set "TMP_AGENT=%TEMP%\sysack-agent-download.js"
set "PS_FILE=%TEMP%\sysack-download-agent.ps1"

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
  echo Instale o Node.js LTS e execute novamente.
  echo [%date% %time%] ERRO: Node.js nao encontrado >> "%LOG_FILE%"
  pause
  exit /b 1
)

echo [4/7] Baixando agente atualizado...

REM Cria um arquivo PowerShell temporario para evitar erro de aspas/caracteres no CMD
> "%PS_FILE%" echo $ErrorActionPreference = 'Stop'
>> "%PS_FILE%" echo [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
>> "%PS_FILE%" echo $url = '%AGENT_URL%'
>> "%PS_FILE%" echo $out = '%TMP_AGENT%'
>> "%PS_FILE%" echo if (Test-Path $out) { Remove-Item $out -Force }
>> "%PS_FILE%" echo Invoke-WebRequest -Uri $url -OutFile $out -UseBasicParsing
>> "%PS_FILE%" echo if (!(Test-Path $out)) { throw 'Arquivo nao baixado' }
>> "%PS_FILE%" echo $len = (Get-Item $out).Length
>> "%PS_FILE%" echo if ($len -lt 10000) { throw ('Arquivo baixado muito pequeno: ' + $len + ' bytes') }
>> "%PS_FILE%" echo $txt = Get-Content $out -Raw
>> "%PS_FILE%" echo if (($txt -notmatch 'SYSACK') -and ($txt -notmatch 'agent')) { throw 'Conteudo baixado nao parece ser o agente SYSACK' }
>> "%PS_FILE%" echo Write-Host 'Download OK:' $len 'bytes'

powershell -NoProfile -ExecutionPolicy Bypass -File "%PS_FILE%"
set "DLERR=%ERRORLEVEL%"
del "%PS_FILE%" >nul 2>&1

if not "%DLERR%"=="0" (
  echo [ERRO] Falha ao baixar agente de %AGENT_URL%
  echo Verifique se o arquivo agent-desktop.js esta publicado na Vercel.
  echo [%date% %time%] ERRO: download falhou >> "%LOG_FILE%"
  pause
  exit /b 1
)

if exist "%AGENT_FILE%" copy /Y "%AGENT_FILE%" "%SYSACK_DIR%\agent.backup.js" >nul 2>&1

echo [5/7] Instalando em %AGENT_FILE%...
copy /Y "%TMP_AGENT%" "%AGENT_FILE%" >nul
if errorlevel 1 (
  echo [ERRO] Nao foi possivel copiar o agente para %AGENT_FILE%
  echo [%date% %time%] ERRO: copy falhou >> "%LOG_FILE%"
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
sc stop SYSACKAgentDesktop >nul 2>&1
sc delete SYSACKAgentDesktop >nul 2>&1
sc stop "SYSACK Agent" >nul 2>&1
sc delete "SYSACK Agent" >nul 2>&1

echo [7/7] Criando tarefa agendada %TASK_NAME%...
schtasks /create /tn "%TASK_NAME%" /tr "\"%START_FILE%\"" /sc onstart /ru SYSTEM /rl HIGHEST /f
if errorlevel 1 (
  echo [ERRO] Falha ao criar tarefa agendada.
  echo [%date% %time%] ERRO: schtasks create falhou >> "%LOG_FILE%"
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
echo.
echo Arquivo em execucao:
echo   %AGENT_FILE%
echo.
echo Tarefa agendada:
echo   %TASK_NAME%
echo.
echo Para reiniciar manualmente:
echo   schtasks /end /tn "%TASK_NAME%"
echo   schtasks /run /tn "%TASK_NAME%"
echo.
echo Logs:
echo   %LOG_FILE%
echo   %SYSACK_DIR%\agent-runtime.log
echo.

echo [%date% %time%] Instalacao/atualizacao concluida >> "%LOG_FILE%"

pause
exit /b 0
