@echo off
chcp 65001 >nul
echo =======================================================
echo NocSentinel Sanal Ortami (venv) Aktif Ediliyor...
echo =======================================================
call "%~dp0venv\Scripts\activate.bat"
cmd /k
