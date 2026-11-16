@echo off
chcp 65001 > nul
echo ====================================================
echo Сборка SystemPurge Pro в автономный исполняемый .exe
echo ====================================================
pip install -r requirements.txt
pyinstaller --noconfirm --onefile --windowed --uac-admin --name "SystemPurgePro" main.py
echo.
echo Готово! Исполняемый файл находится в папке dist\SystemPurgePro.exe
pause
