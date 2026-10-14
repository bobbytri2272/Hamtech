@echo off
chcp 65001 >nul
setlocal EnableDelayedExpansion
title Build HAMTECH PC Check-in EXE

echo ==========================================
echo   BUILD HAMTECH PC CHECK-IN (FULL EMBED)
echo ==========================================
echo.

where py >nul 2>nul
if errorlevel 1 (
    echo [LOI] Chua tim thay Python. Hay cai Python 3.11 hoac 3.12 tu python.org
    echo Nho tick "Add python.exe to PATH" khi cai dat.
    pause
    exit /b 1
)

if not exist "pc_checkin.py" (
    echo [LOI] Khong tim thay pc_checkin.py.
    echo Hay de file BAT nay cung thu muc voi pc_checkin.py roi chay lai.
    pause
    exit /b 1
)

:: 1. Kiem tra Core Temp
set "CORETEMP_DIR="
if exist "tools\Core Temp\Core Temp.exe" (
    set "CORETEMP_DIR=tools\Core Temp"
) else if exist "tools\CoreTemp\CoreTemp.exe" (
    set "CORETEMP_DIR=tools\CoreTemp"
)

if "!CORETEMP_DIR!"=="" (
    echo [LOI] Khong tim thay Core Temp trong thu muc tools\Core Temp\Core Temp.exe
    echo Hay dat Core Temp vao thu muc tools\Core Temp truoc khi build.
    pause
    exit /b 1
)

:: 2. Kiem tra smartctl.exe (trong tools\ hoac thu muc con cua tools\)
set "SMARTCTL_PATH="
if exist "tools\smartctl.exe" (
    set "SMARTCTL_PATH=tools\smartctl.exe"
) else (
    for /r "tools" %%F in (smartctl.exe smartctl-nc.exe) do (
        if exist "%%F" set "SMARTCTL_PATH=%%F"
    )
)

if "!SMARTCTL_PATH!"=="" (
    echo [LOI] Khong tim thay smartctl.exe trong thu muc tools.
    echo Hay chep smartctl.exe vao thu muc tools\ truoc khi build.
    pause
    exit /b 1
)

:: 3. Kiem tra file qrious.min.js
set "QRIOUS_PATH="
if exist "tools\qrious.min.js" (
    set "QRIOUS_PATH=tools\qrious.min.js"
) else if exist "qrious.min.js" (
    set "QRIOUS_PATH=qrious.min.js"
) else (
    for /r "tools" %%F in (qrious.min.js) do (
        if exist "%%F" set "QRIOUS_PATH=%%F"
    )
)

if "!QRIOUS_PATH!"=="" (
    echo [LOI] Khong tim thay file qrious.min.js trong thu muc tools hoac cung cap.
    echo Hay chep file qrious.min.js vao thu muc tools\ truoc khi build.
    pause
    exit /b 1
)

:: 4. Kiem tra file Icon (.ico)
set "ICON_PARAM="
if exist "hamtech.ico" (
    set "ICON_PARAM=--icon=hamtech.ico"
    echo [OK] Tim thay file icon: hamtech.ico
) else if exist "icon.ico" (
    set "ICON_PARAM=--icon=icon.ico"
    echo [OK] Tim thay file icon: icon.ico
) else (
    echo [LUU Y] Khong tim thay file icon (.ico^). File EXE se dung icon mac dinh.
)

echo [OK] Da tim thay Core Temp tai: !CORETEMP_DIR!
echo [OK] Da tim thay smartctl tai:  !SMARTCTL_PATH!
echo [OK] Da tim thay qrious.min.js: !QRIOUS_PATH!
echo.

echo [1/4] Cai/nang cap PyInstaller...
py -m pip install --upgrade pyinstaller
if errorlevel 1 (
    echo [LOI] Cai PyInstaller that bai. Kiem tra Internet va Python.
    pause
    exit /b 1
)

echo.
echo [2/4] Tu dong cai dag Pillow (ho tro chuyen doi icon)...
py -m pip install --upgrade pillow
if errorlevel 1 (
    echo [LOI] Cai dat Pillow that bai.
    pause
    exit /b 1
)

echo.
echo [3/4] Dong goi thanh EXE (nhung Core Temp, smartctl, qrious va icon)...
py -m PyInstaller --noconfirm --clean --onefile --windowed --uac-admin ^
    --name "HAMTECH_PC_Checkin" ^
    --add-data "!CORETEMP_DIR!;tools\Core Temp" ^
    --add-data "!SMARTCTL_PATH!;tools" ^
    --add-data "!QRIOUS_PATH!;tools" ^
    !ICON_PARAM! ^
    "pc_checkin.py"

if errorlevel 1 (
    echo [LOI] Dong goi that bai. Xem thong bao loi o phia tren.
    pause
    exit /b 1
)

echo.
echo [4/4] Hoan tat!
echo File EXE nam tai:
echo %CD%\dist\HAMTECH_PC_Checkin.exe
pause