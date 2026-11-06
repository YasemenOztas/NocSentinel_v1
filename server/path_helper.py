import os
import sys
import logging

def get_base_dir():
    """
    Returns the absolute path to the directory containing the running script or EXE.
    If running from PyInstaller, it returns sys._MEIPASS (for static embedded files).
    """
    if getattr(sys, 'frozen', False):
        return sys._MEIPASS
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def get_persistent_dir(sub_dir=None):
    if os.name == 'nt':
        program_data = os.environ.get('PROGRAMDATA', 'C:\\ProgramData')
        base_persist = os.path.join(program_data, 'NocSentinelServer')
    else:
        if getattr(sys, 'frozen', False):
            base_persist = os.path.join(os.path.dirname(sys.executable), "NocSentinelData")
        else:
            base_persist = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "NocSentinelData")
    
    if sub_dir:
        target_dir = os.path.join(base_persist, sub_dir)
    else:
        target_dir = base_persist
        
    os.makedirs(target_dir, exist_ok=True)
    return target_dir

def get_log_file_path():
    """
    Returns the path to the main log file.
    """
    return os.path.join(get_persistent_dir("logs"), "server.log")

def setup_global_logging():
    """
    Configures the root logger to write to both console and the persistent log file.
    """
    log_file = get_log_file_path()
    
    # Kök logger'ı yapılandır
    root_logger = logging.getLogger()
    # Mevcut handler'ları temizle
    if root_logger.hasHandlers():
        root_logger.handlers.clear()
        
    root_logger.setLevel(logging.INFO)
    
    formatter = logging.Formatter('%(asctime)s [%(levelname)s] %(name)s: %(message)s')
    
    # File Handler
    fh = logging.FileHandler(log_file, encoding='utf-8')
    fh.setFormatter(formatter)
    root_logger.addHandler(fh)
    
    # Console Handler (opsiyonel/debug icin — sadece stdout dosyaya yonlendirilmemisse ekle)
    if sys.stdout is not None and not getattr(sys.stdout, 'name', '').endswith('server.log'):
        ch = logging.StreamHandler(sys.stdout)
        ch.setFormatter(formatter)
        root_logger.addHandler(ch)
        
    # SESSİZ ÇÖKMELERİ YAKALAMAK İÇİN STDERR YÖNLENDİRMESİ
    # PyInstaller --noconsole Windows Servisi modunda stdout ve stderr None olur.
    # Bu durumda thread'lerdeki (örn. Uvicorn) yakalanamayan hatalar görünmez.
    try:
        sys.stderr = open(log_file, "a", encoding="utf-8")
        sys.stdout = sys.stderr
    except Exception:
        pass

    return root_logger
