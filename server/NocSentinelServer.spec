# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_all

datas = [('ui', 'ui'), ('../certs', 'certs')]
binaries = []
hiddenimports = ['ssl', '_ssl', 'sqlite3', '_sqlite3', 'sqlalchemy.dialects.sqlite', 'sqlalchemy.dialects.sqlite.pysqlite', 'sqlalchemy.dialects.postgresql', 'uvicorn', 'fastapi', 'pydantic', 'sqlalchemy', 'paho.mqtt', 'win32timezone', 'win32serviceutil', 'win32service', 'win32event', 'servicemanager', 'logging', 'path_helper', 'token_bucket', 'app_config']
tmp_ret = collect_all('sqlite3')
datas += tmp_ret[0]; binaries += tmp_ret[1]; hiddenimports += tmp_ret[2]


a = Analysis(
    ['windows_service.py'],
    pathex=['.', '..', '../common'],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
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
    [],
    exclude_binaries=True,
    name='NocSentinelServer',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='NocSentinelServer',
)
