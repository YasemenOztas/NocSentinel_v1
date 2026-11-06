import os
import sys

dll_search_paths = [
    os.path.join(sys.prefix, "Library", "bin"),
    os.path.join(sys.prefix, "DLLs"),
    "C:\\ProgramData\\anaconda3\\Library\\bin"
]
target_dll_names = [
    "ffi.dll", "ffi-8.dll", "ffi-7.dll",
    "libcrypto-3-x64.dll", "libssl-3-x64.dll", "sqlite3.dll",
    "liblzma.dll", "libbz2.dll", "LIBBZ2.dll"
]
extra_binaries = []
for search_dir in dll_search_paths:
    if os.path.exists(search_dir):
        for dll_name in target_dll_names:
            dll_path = os.path.join(search_dir, dll_name)
            if os.path.exists(dll_path):
                extra_binaries.append((dll_path, '.'))

a = Analysis(
    ['service_manager.py'],
    pathex=['..\\common'],
    binaries=extra_binaries,
    datas=[],
    hiddenimports=['ctypes', '_ctypes', 'ssl', '_ssl', 'win32timezone', 'msgpack', 'cryptography.hazmat.primitives.ciphers.aead', 'crypto_helper', 'app_config', 'thread_supervisor', 'monitors'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='service_manager',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
