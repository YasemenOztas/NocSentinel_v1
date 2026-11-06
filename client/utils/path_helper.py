import os
import sys

def get_base_dir():
    """
    Returns the directory where the application is running from.
    When running as a normal Python script, it returns the directory of this file (client/).
    When running as a PyInstaller executable, it returns the directory of the .exe file.
    """
    if getattr(sys, 'frozen', False):
        # Eğer PyInstaller (veya cx_Freeze) tarafından derlenmişse
        return os.path.dirname(sys.executable)
    else:
        # Normal python betiği olarak çalışıyorsa (utils/path_helper.py'nin bir üst dizini)
        return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def get_data_dir():
    """
    Kalıcı ve güvenli verilerin (Veritabanı, Sertifikalar) saklanacağı dizini döndürür.
    Windows standartlarına uygun olarak C:\\ProgramData\\NocSentinel klasörünü kullanır.
    """
    if os.name == 'nt':
        program_data = os.environ.get('PROGRAMDATA', 'C:\\ProgramData')
        data_dir = os.path.join(program_data, 'NocSentinel')
    else:
        # Test ortamı (Linux vb.) için fallback
        data_dir = os.path.join(get_base_dir(), 'data')
        
    if not os.path.exists(data_dir):
        os.makedirs(data_dir, exist_ok=True)
        # Klasör ilk oluşturulduğunda kilit vuruluyordu ancak geliştirme ortamını kolaylaştırmak için kaldırıldı
        pass
            
    return data_dir
