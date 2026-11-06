import os
import shutil
import subprocess
import sys

def build():
    # Dosya yollarini belirle
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(current_dir)
    main_script = os.path.join(current_dir, "windows_service.py")
    icon_path = os.path.join(current_dir, "ui", "favicon.ico") # Eger yoksa onemli degil
    ui_dir = os.path.join(current_dir, "ui")
    dist_dir = os.path.join(current_dir, "dist", "NocSentinelServer")
    target_deploy_dir = os.path.join(project_root, "NocSentinel_Sunucu_EXE")

    # Anaconda / Windows Python DLL bagimliliklarini topla (OpenSSL, SQLite, Ctypes, LZMA, SSL)
    dll_search_paths = [
        os.path.join(sys.prefix, "Library", "bin"),
        os.path.join(sys.prefix, "DLLs"),
        "C:\\ProgramData\\anaconda3\\Library\\bin"
    ]
    target_dll_names = [
        "libcrypto-3-x64.dll", "libssl-3-x64.dll", "sqlite3.dll",
        "ffi.dll", "ffi-8.dll", "ffi-7.dll", "liblzma.dll", "libbz2.dll", "LIBBZ2.dll"
    ]
    found_dlls = {}
    for search_dir in dll_search_paths:
        if os.path.exists(search_dir):
            for dll_name in target_dll_names:
                if dll_name not in found_dlls:
                    dll_path = os.path.join(search_dir, dll_name)
                    if os.path.exists(dll_path):
                        found_dlls[dll_name] = dll_path

    # PyInstaller argumanlarini hazirla
    args = [
        sys.executable, "-m", "PyInstaller",
        "--name", "NocSentinelServer",
        "--onedir",           # Servis kararliligi icin onemli!
        "--noconsole",        # Arka planda sessizce calisacak
        "--clean",
        "--noconfirm",
        "--workpath=" + os.path.join(current_dir, "build"),
        "--distpath=" + os.path.join(current_dir, "dist"),
        
        # Paths (Karakter kodlamasi sorunlarina karsi guncel dizinler)
        "--paths=.",
        "--paths=..",
        "--paths=..\\common",
        
        # Data Files (Arayüz ve sertifika klasörlerini göm - relative path)
        "--add-data=ui;ui",
        "--add-data=..\\certs;certs",
        
        # Hidden Imports & Data Collections
        "--collect-all=sqlite3",
        "--hidden-import=ssl",
        "--hidden-import=_ssl",
        "--hidden-import=sqlite3",
        "--hidden-import=_sqlite3",
        "--hidden-import=sqlalchemy.dialects.sqlite",
        "--hidden-import=sqlalchemy.dialects.sqlite.pysqlite",
        "--hidden-import=sqlalchemy.dialects.postgresql",
        "--hidden-import=uvicorn",
        "--hidden-import=fastapi",
        "--hidden-import=pydantic",
        "--hidden-import=sqlalchemy",
        "--hidden-import=paho.mqtt",
        "--hidden-import=win32timezone",
        "--hidden-import=win32serviceutil",
        "--hidden-import=win32service",
        "--hidden-import=win32event",
        "--hidden-import=servicemanager",
        "--hidden-import=logging",
        "--hidden-import=path_helper",
        "--hidden-import=token_bucket",
        "--hidden-import=app_config",
        
        "windows_service.py"
    ]
    
    for dll_name, dll_path in found_dlls.items():
        args.insert(-1, f"--add-binary={dll_path};.")
        print(f"[BILGI] DLL tespit edildi ve pakete eklendi: {dll_name} -> {dll_path}")
    
    if os.path.exists(icon_path):
        args.extend(["--icon", icon_path])
        
    print("=" * 60)
    print("NocSentinel Sunucu Servisi (Windows Service) Derleniyor...")
    print("=" * 60)
    print("Calistirilan komut:")
    print(" ".join(args))
    
    try:
        subprocess.check_call(args, cwd=current_dir)
        print(f"\nDerleme basarili! Cikti: {dist_dir} klasorunde.")

        # Derlenen sunucu dosyalarini NocSentinel_Sunucu_EXE klasorune kopyala
        if os.path.exists(dist_dir):
            os.makedirs(target_deploy_dir, exist_ok=True)
            for item in os.listdir(dist_dir):
                s = os.path.join(dist_dir, item)
                d = os.path.join(target_deploy_dir, item)
                if os.path.isdir(s):
                    if os.path.exists(d):
                        shutil.rmtree(d)
                    shutil.copytree(s, d)
                else:
                    shutil.copy2(s, d)
            print(f"[KOPYALANDI] {dist_dir} -> {target_deploy_dir}")
    except subprocess.CalledProcessError as e:
        print(f"\nDerleme basarisiz oldu. Hata kodu: {e.returncode}")
        sys.exit(1)

if __name__ == "__main__":
    build()
