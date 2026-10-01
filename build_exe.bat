@echo off
cd /d %~dp0
py -m pip install --upgrade pyinstaller
pyinstaller --noconfirm --clean --onefile --windowed --name GlezRuda_Security_Engine security_engine.py
pyinstaller --noconfirm --clean --onefile --windowed --name GlezRuda_Security main.py
if not exist release mkdir release
copy /Y dist\GlezRuda_Security.exe release\GlezRuda_Security.exe >nul
copy /Y dist\GlezRuda_Security_Engine.exe release\GlezRuda_Security_Engine.exe >nul
echo.
echo V1.4 creada en: %~dp0release
echo IMPORTANTE: ambos EXE deben permanecer juntos.
pause
