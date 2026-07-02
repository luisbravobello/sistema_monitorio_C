@echo off
REM ============================================================
REM  Compila el backend en Windows CON captura real via Npcap.
REM  Requisitos (una sola vez):
REM    1) Instalar Npcap (marcando "WinPcap API-compatible Mode")
REM       https://npcap.com/#download
REM    2) Descargar el Npcap SDK (npcap-sdk-x.xx.zip) desde
REM       https://npcap.com/#download y descomprimirlo en:
REM       Backend\npcap-sdk\   (debe quedar Backend\npcap-sdk\Include
REM       y Backend\npcap-sdk\Lib)
REM    3) Tener MinGW (gcc) instalado y en el PATH.
REM
REM  Uso:  build.bat
REM  Genera monitor.exe con captura real. Luego ejecutar
REM  monitor.exe COMO ADMINISTRADOR (Npcap lo requiere).
REM ============================================================

setlocal
set SDK=npcap-sdk

if not exist "%SDK%\Include\pcap.h" (
    echo [ERROR] No se encontro %SDK%\Include\pcap.h
    echo         Descarga el Npcap SDK desde https://npcap.com/#download
    echo         y descomprimelo en Backend\%SDK%\
    exit /b 1
)

REM Detecta la arquitectura REAL de tu gcc (32 vs 64 bits) para usar el
REM .lib correcto. Un gcc de 32 bits (mingw32) NO puede enlazar librerias
REM de 64 bits (Lib\x64), y viceversa: eso da errores de "undefined
REM reference" a las funciones pcap_* aunque los .lib existan.
set LIBDIR=%SDK%\Lib
for /f "delims=" %%i in ('gcc -dumpmachine') do set GCCTARGET=%%i
echo %GCCTARGET% | findstr /i "x86_64" >nul
if %errorlevel%==0 (
    if exist "%SDK%\Lib\x64\wpcap.lib" set LIBDIR=%SDK%\Lib\x64
)
echo Compilador detectado: %GCCTARGET%  -^>  usando librerias en %LIBDIR%

gcc -std=c11 -O2 -DHAVE_PCAP -Wall ^
    -Iinclude -I%SDK%\Include ^
    src\main.c src\api_server.c src\data_reader.c src\detector.c src\search.c src\sort.c src\viewmodel.c ^
    -o monitor.exe ^
    -L%LIBDIR% -lwpcap -lPacket -lws2_32

if errorlevel 1 (
    echo.
    echo [ERROR] Fallo la compilacion.
    exit /b 1
)

echo.
echo OK -^> monitor.exe generado con captura real (Npcap).
echo IMPORTANTE: corre monitor.exe como Administrador, o Npcap
echo no podra abrir los adaptadores de red.
endlocal
