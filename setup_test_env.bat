@echo off
setlocal EnableDelayedExpansion
title NocSentinel - Sunucu Test Ortami Kurulumu

REM ============================================================
REM  NocSentinel - Sunucu Test Ortami Kurulumu (INTERNET GEREKLI)
REM ============================================================
REM  Bu dosya proje KOK dizininde (server\, common\, NocSentinel_Sunucu_EXE\
REM  ile ayni yerde) olmalidir. Internet varken BIR KEZ calistirin:
REM    1. Python kontrolu (yoksa winget ile Python 3.12 kurmayi dener)
REM    2. .venv olusturma (baska PC'den kopyalanmis bozuk .venv silinir)
REM    3. requirements_test.txt paketlerinin kurulumu
REM    4. Test betiginin import dogrulamasi
REM    5. Docker imajlarinin onceden indirilmesi (offline test icin)
REM ============================================================

cd /d "%~dp0"
set "ROOT=%~dp0"
set "VENV=%ROOT%.venv"
set "VPY=%VENV%\Scripts\python.exe"

:: Anaconda / Conda cakismasini onleme: Ortam degiskenlerini temizle
set "PYTHONPATH="
set "PYTHONHOME="
set "CONDA_PREFIX="
set "CONDA_DEFAULT_ENV="
set "CONDA_PYTHON_EXE="

if not exist "%ROOT%server\database.py" (
    echo [HATA] Bu dosya proje kok dizininde degil ^(server\database.py bulunamadi^).
    pause
    exit /b 1
)

echo.
echo [1/5] Python araniyor...
set "PY="
py -3 -c "import sys" >nul 2>&1
if !errorlevel! equ 0 set "PY=py -3"
if not defined PY (
    python -c "import sys" >nul 2>&1
    if !errorlevel! equ 0 set "PY=python"
)
if not defined PY (
    echo [UYARI] Python bulunamadi. winget ile Python 3.12 kurulmaya calisiliyor...
    winget install -e --id Python.Python.3.12 --scope machine --silent --accept-package-agreements --accept-source-agreements
    echo.
    echo [BILGI] Kurulum bittiyse bu pencereyi KAPATIP setup_test_env.bat'i YENIDEN calistirin.
    echo         winget yoksa python.org'dan Python 3.12 kurun ^("Add python.exe to PATH" isaretli^).
    pause
    exit /b 1
)
for /f "delims=" %%v in ('!PY! --version 2^>^&1') do echo       Bulundu: %%v  ^(!PY!^)

echo.
echo [2/5] Sanal ortam ^(.venv^) hazirlaniyor...
if exist "%VPY%" (
    "%VPY%" -c "import sys" >nul 2>&1
    if !errorlevel! neq 0 (
        echo       Mevcut .venv bu bilgisayarda calismiyor ^(baska PC'den kopyalanmis^). Siliniyor...
        rmdir /s /q "%VENV%"
    ) else (
        echo       Mevcut .venv calisiyor, yeniden kullaniliyor.
    )
)
if not exist "%VPY%" (
    !PY! -m venv "%VENV%"
    if not exist "%VPY%" (
        echo [HATA] .venv olusturulamadi.
        pause
        exit /b 1
    )
    echo       .venv olusturuldu.
)

echo.
echo [3/5] Paketler kuruluyor ^(internet gerekli^)...
"%VPY%" -m pip install --upgrade pip
"%VPY%" -m pip install -r "%ROOT%requirements_test.txt"
if !errorlevel! neq 0 (
    echo [HATA] Paket kurulumu basarisiz. Internet baglantisini kontrol edin.
    pause
    exit /b 1
)

echo.
echo [4/5] Test betigi import dogrulamasi...
"%VPY%" "%ROOT%NocSentinel_Sunucu_EXE\Tests\run_24h_matrix_test_v4.py" --help >nul 2>&1
if !errorlevel! neq 0 (
    echo [HATA] run_24h_matrix_test_v4.py acilamadi. Ayrinti:
    "%VPY%" "%ROOT%NocSentinel_Sunucu_EXE\Tests\run_24h_matrix_test_v4.py" --help
    pause
    exit /b 1
)
"%VPY%" -c "import sys; sys.path[:0]=[r'%ROOT%server', r'%ROOT%common']; from optimization import get_optimizer; [get_optimizer(n) for n in ('genetic','proportional_fair','pso')]; print('      [OK] Test betigi ve 3 algoritma yuklenebiliyor.')"

echo.
echo [5/5] Docker imajlari onceden indiriliyor ^(test sirasinda internet olmayacak^)...
where docker >nul 2>&1
if !errorlevel! neq 0 (
    echo [UYARI] docker komutu bulunamadi. Docker Desktop'i kurup acin ve su komutlari calistirin:
    echo         docker pull redis:alpine
    echo         docker pull eclipse-mosquitto:latest
) else (
    docker pull redis:alpine
    docker pull eclipse-mosquitto:latest
    if !errorlevel! neq 0 echo [UYARI] Docker imajlari indirilemedi. Docker Desktop acik mi?
)

echo.
echo ==============================================================
echo  KURULUM TAMAMLANDI. Artik internet baglantisini kesebilirsiniz.
echo  Test: NocSentinel_Sunucu_EXE\Tests\run_24h_matrix_test_v4.bat
echo ==============================================================
pause
