# PyInstaller spec for the standalone ForgeFlag CLI client.
#
# Build with:  pyinstaller forgeflag.spec
# Output:      dist/forgeflag (or forgeflag.exe on Windows)

from PyInstaller.utils.hooks import collect_submodules

hiddenimports = collect_submodules("forgeflag") + [
    "PIL._tkinter_finder",
]

a = Analysis(
    ["src/forgeflag/__main__.py"],
    pathex=["src"],
    binaries=[],
    datas=[],
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib", "numpy", "IPython", "pytest"],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    name="forgeflag",
    console=True,
    upx=False,
)
