import sys
import os
import site

# --- VIRTUAL ENVIRONMENT BOOTSTRAP ---
current_dir = os.path.dirname(os.path.abspath(__file__))
venv_site_packages = os.path.abspath(os.path.join(current_dir, "..", ".venv", "Lib", "site-packages"))
if os.path.exists(venv_site_packages):
    site.addsitedir(venv_site_packages)
# -------------------------------------

try:
    import win32serviceutil
    import win32service
    import win32event
    import servicemanager
    import socket
    import threading
    import time
    
    from utils.path_helper import get_base_dir
    
    # Ajan dosyalarının bulunduğu dizini yola ekle ki importlar düzgün çalışsın
    current_dir = get_base_dir()
    if current_dir not in sys.path:
        sys.path.insert(0, current_dir)
        
    # [YAMA]: win32serviceutil.HandleCommandLine sys.argv[0]'ı okurken os.chdir()
    # yüzünden dosyanın yolunu bulamıyor. Eğer paketlenmişse mutlak yolu zorlayalım.
    if getattr(sys, 'frozen', False):
        sys.argv[0] = sys.executable
        
    os.chdir(current_dir) # Servis olarak başlarken System32'de başlamaması için

    # pywin32 event log hatalarını önlemek için win32timezone gereklidir
    import win32timezone 
    import sender_agent

    class NocSentinelService(win32serviceutil.ServiceFramework):
        _svc_name_ = 'NocSentinelClient'
        _svc_display_name_ = 'Noc Sentinel Endpoint Agent'
        _svc_description_ = 'Noc Sentinel Client for security monitoring and control. Runs in background with admin privileges.'
        _svc_start_type_ = win32service.SERVICE_AUTO_START

        def __init__(self, args):
            win32serviceutil.ServiceFramework.__init__(self, args)
            self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
            self.is_running = True

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            win32event.SetEvent(self.hWaitStop)
            self.is_running = False

        def SvcDoRun(self):
            # Servisin başlatıldığını logla (Windows Event Viewer)
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, '')
            )
            self.main()

        def main(self):
            # Ajanın ana fonksiyonunu bir iş parçacığında (daemon) başlat
            # Bu sayede SvcStop olayını (hWaitStop) asenkron dinleyebiliriz.
            agent_thread = threading.Thread(target=sender_agent.main, daemon=True)
            agent_thread.start()
            
            # Stop komutu gelene kadar bekle (Windows Servis Yöneticisi durdur dediğinde uyanır)
            win32event.WaitForSingleObject(self.hWaitStop, win32event.INFINITE)
            
            # Servis durdurulduğunda MQTT bağlantısını ve süreçleri düzgünce kapatmayı dene
            try:
                if hasattr(sender_agent, 'mqtt_client') and sender_agent.mqtt_client:
                    sender_agent.mqtt_client.loop_stop()
            except Exception:
                pass
            
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STOPPED,
                (self._svc_name_, '')
            )

    if __name__ == '__main__':
        if len(sys.argv) == 1:
            # Servis Yöneticisi tarafından doğrudan çağrıldığında
            servicemanager.Initialize()
            servicemanager.PrepareToHostSingle(NocSentinelService)
            servicemanager.StartServiceCtrlDispatcher()
        else:
            # Komut satırından çağrıldığında (install, update, remove, start, vb.)
            if 'install' in sys.argv and '--startup' not in sys.argv:
                sys.argv.insert(1, '--startup')
                sys.argv.insert(2, 'auto')
            win32serviceutil.HandleCommandLine(NocSentinelService)
except Exception as top_level_e:
    import traceback
    crash_log = os.path.join(os.path.dirname(os.path.abspath(__file__)), "service_critical_crash.txt")
    with open(crash_log, "w") as f:
        f.write("Critical crash:\n" + traceback.format_exc())
    raise
