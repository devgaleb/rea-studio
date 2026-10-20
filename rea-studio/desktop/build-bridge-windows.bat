@echo off
setlocal
cd /d "%~dp0..\local-service"
py -3 -m pip install pyinstaller==6.13.0
py -3 -m PyInstaller --clean --noconfirm --onefile --name rea-bridge --add-data "ghidra_scripts;ghidra_scripts" --hidden-import android_analysis server.py
if errorlevel 1 exit /b 1
copy /Y dist\rea-bridge.exe rea-bridge.exe
if errorlevel 1 exit /b 1
echo Built local-service\rea-bridge.exe. Run npm run dist:win from desktop\ to build the installer.
