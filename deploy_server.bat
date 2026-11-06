@echo off
echo ===================================================
echo NocSentinel Sunucusu - Kurulum Araci (Dagitim)
echo ===================================================
echo.

:: Yonetici izinleri kontrolu
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [OK] Yonetici haklari dogrulandi.
) else (
    echo [HATA] Lutfen bu dosyaya sag tiklayip "Yonetici olarak calistir" secenegini secin!
    pause
    exit /b 1
)

:: Dosyanin calistigi dizini kontrol et ve .exe'nin bulundugu ana dizine gec
if exist "%~dp0NocSentinelServer.exe" (
    cd /d "%~dp0"
) else if exist "%~dp0..\NocSentinelServer.exe" (
    cd /d "%~dp0.."
) else (
    cd /d "%~dp0"
)

echo.
echo 1. Eski servis varsa durduruluyor...
net stop NocSentinelServer >nul 2>&1
sc delete NocSentinelServer >nul 2>&1
timeout /t 2 /nobreak >nul

echo.
echo 2. Sunucu sertifikasi guncel IP adresleriyle yeniden uretiliyor (CA korunur)...
del /f /q "%PROGRAMDATA%\NocSentinelServer\certs\server.crt" >nul 2>&1
del /f /q "%PROGRAMDATA%\NocSentinelServer\certs\server.key" >nul 2>&1
echo    ProgramData altinda Sertifikalar ve Mosquitto Ayarlari hazirlaniyor...
NocSentinelServer.exe init

echo.
echo 2b. Guvenlik duvari gelen baglanti kurallari ekleniyor (8000 API, 8883 MQTT-TLS)...
netsh advfirewall firewall delete rule name="NocSentinel API 8000" >nul 2>&1
netsh advfirewall firewall delete rule name="NocSentinel MQTT 8883" >nul 2>&1
netsh advfirewall firewall add rule name="NocSentinel API 8000" dir=in action=allow protocol=TCP localport=8000 profile=any >nul
netsh advfirewall firewall add rule name="NocSentinel MQTT 8883" dir=in action=allow protocol=TCP localport=8883 profile=any >nul

echo.
echo 3. Docker Konteynerleri (Mosquitto ^& Redis) baslatiliyor...
docker-compose up -d
docker-compose restart mosquitto

echo.
echo 4. NocSentinel Sunucu servisi sisteme kayit ediliyor...
NocSentinelServer.exe install

echo.
echo 5. Servis arka planda baslatiliyor...
NocSentinelServer.exe start

echo.
echo ===================================================
echo Kurulum/Guncelleme Basariyla Tamamlandi! 
echo Sunucu arka planda calismaya basladi.
echo ===================================================
pause
