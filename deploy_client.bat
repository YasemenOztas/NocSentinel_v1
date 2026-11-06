@echo off
echo ===================================================
echo NocSentinel Guvenlik Ajani - Kurulum Araci (Dagitim)
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

:: Dosyanin calistigi dizini kontrol et ve service_manager.exe'nin bulundugu ana dizine gec
if exist "%~dp0service_manager.exe" (
    cd /d "%~dp0"
) else if exist "%~dp0..\service_manager.exe" (
    cd /d "%~dp0.."
) else (
    cd /d "%~dp0"
)

echo.
echo 1. Eski servis varsa durduruluyor ve siliniyor (Reinstall Hazirligi)...
net stop NocSentinelClient >nul 2>&1
sc delete NocSentinelClient >nul 2>&1

:: Varsa eski oturumdan kalmis guvenlik duvari izolasyon kurallarini temizle
netsh advfirewall firewall delete rule name="NocSentinelBlockOut" >nul 2>&1
netsh advfirewall firewall delete rule name="NocSentinelBlockOutUDP" >nul 2>&1
netsh advfirewall firewall delete rule name="NocSentinelBlockIn" >nul 2>&1

timeout /t 2 /nobreak >nul

echo.
echo 2. NocSentinel servisi sisteme kayit ediliyor...
service_manager.exe install

echo.
echo 3. Servis arka planda baslatiliyor...
service_manager.exe start

echo.
echo ===================================================
echo Kurulum/Guncelleme Basariyla Tamamlandi! 
echo Ajan arka planda calismaya basladi.
echo ===================================================
pause
