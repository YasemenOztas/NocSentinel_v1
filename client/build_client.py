import os
import shutil
import subprocess
import sys

def build():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(current_dir)
    spec_path = os.path.join(current_dir, "service_manager.spec")
    dist_dir = os.path.join(current_dir, "dist")
    target_deploy_dir = os.path.join(project_root, "NocSentinel_Istemci")

    args = [
        sys.executable, "-m", "PyInstaller",
        "--clean",
        "-y",
        spec_path
    ]

    print("=" * 60)
    print("NocSentinel Istemci Servisi (Client Service) Derleniyor...")
    print("=" * 60)
    print("Calistirilan komut:")
    print(" ".join(args))

    try:
        subprocess.check_call(args, cwd=current_dir)
        print(f"\nDerleme basarili! Cikti: {os.path.join(dist_dir, 'service_manager.exe')}")
        
        # Derlenen service_manager.exe'yi NocSentinel_Istemci klasorune kopyala
        built_exe = os.path.join(dist_dir, "service_manager.exe")
        target_exe = os.path.join(target_deploy_dir, "service_manager.exe")
        if os.path.exists(built_exe):
            os.makedirs(target_deploy_dir, exist_ok=True)
            shutil.copy2(built_exe, target_exe)
            print(f"[KOPYALANDI] {built_exe} -> {target_exe}")
    except subprocess.CalledProcessError as e:
        print(f"\nDerleme basarisiz oldu. Hata kodu: {e.returncode}")
        sys.exit(1)

if __name__ == "__main__":
    build()
