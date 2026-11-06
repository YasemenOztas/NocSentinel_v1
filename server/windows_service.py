import sys
import os
import multiprocessing

import win32serviceutil
import win32service
import win32event
import servicemanager

# Yolları ayarla
server_dir = os.path.dirname(os.path.abspath(__file__))
if server_dir not in sys.path:
    sys.path.insert(0, server_dir)

import path_helper
logger = path_helper.setup_global_logging()
logger.name = "WindowsService"

import receiver_server

class NocSentinelService(win32serviceutil.ServiceFramework):
    _svc_name_ = "NocSentinelServer"
    _svc_display_name_ = "NocSentinel NOC Security Server"
    _svc_description_ = "NOC Sentinel Client Control Server - MQTT & FastAPI Backend"
    _svc_start_type_ = win32service.SERVICE_AUTO_START

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        import socket
        socket.setdefaulttimeout(60)
        self.is_running = True

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)
        sys.svc_stop_flag = True
        self.is_running = False
        logger.info("[SERVICE] Durdurma sinyali alindi (Stop pending).")

    def SvcDoRun(self):
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, '')
        )
        logger.info("[SERVICE] NocSentinelService baslatiliyor...")
        self.main()

    def main(self):
        import threading
        # receiver_server.main blocking bir dongudur. Onu main thread yerine bir alt thread'de baslatiriz.
        sys.svc_stop_flag = False
        t = threading.Thread(target=receiver_server.main, daemon=False)
        t.start()
        
        # SvcStop cagirildiginda hWaitStop eventi tetiklenecek
        win32event.WaitForSingleObject(self.hWaitStop, win32event.INFINITE)
        
        logger.info("[SERVICE] Thread'in kapanmasi bekleniyor...")
        t.join(timeout=10)
        logger.info("[SERVICE] NocSentinelService tamamen durduruldu.")

if __name__ == '__main__':
    multiprocessing.freeze_support()
    if len(sys.argv) > 1 and sys.argv[1].lower() == "init":
        print("🔐 ProgramData sertifikalari ve mosquitto.conf olusturuluyor...")
        receiver_server.check_and_generate_certificates()
        receiver_server.generate_mosquitto_conf()
        print("✅ ProgramData/NocSentinelServer ilklendirmesi tamamlandi.")
        sys.exit(0)
    
    try:
        # Eger argumansiz (hizmet yoneticisinden) cagirildiysa
        if len(sys.argv) == 1:
            servicemanager.Initialize()
            servicemanager.PrepareToHostSingle(NocSentinelService)
            servicemanager.StartServiceCtrlDispatcher()
        else:
            if 'install' in sys.argv and '--startup' not in sys.argv:
                sys.argv.insert(1, '--startup')
                sys.argv.insert(2, 'auto')
            win32serviceutil.HandleCommandLine(NocSentinelService)
    except Exception as err:
        # PyInstaller analiz sürecinde veya SCM dışı çalışmada kilitlenmeyi engelle
        pass
