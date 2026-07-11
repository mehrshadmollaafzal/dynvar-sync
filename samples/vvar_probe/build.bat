@echo off
setlocal

cd /d "%~dp0"

where ml64 >nul 2>&1
if errorlevel 1 (
    echo [ERROR] ml64.exe was not found.
    echo Open "x64 Native Tools Command Prompt for VS 2022" and run this script again.
    exit /b 1
)

where cl >nul 2>&1
if errorlevel 1 (
    echo [ERROR] cl.exe was not found.
    echo Open "x64 Native Tools Command Prompt for VS 2022" and run this script again.
    exit /b 1
)

if not exist "vvar_probe_x64.asm" (
    echo [ERROR] vvar_probe_x64.asm was not found.
    exit /b 1
)

if not exist "vvar_probe.c" (
    echo [ERROR] vvar_probe.c was not found.
    exit /b 1
)

if not exist "build" mkdir "build"
if errorlevel 1 (
    echo [ERROR] Could not create the build directory.
    exit /b 1
)

echo [1/2] Assembling vvar_probe_x64.asm...
ml64 /nologo /c /Zi /Fo"build\vvar_probe_x64.obj" "vvar_probe_x64.asm"
if errorlevel 1 (
    echo [ERROR] Assembly failed.
    exit /b 1
)

echo [2/2] Compiling and linking vvar_probe.exe...
cl /nologo /W4 /O2 /Zi /GS- /GL- ^
    /Fe"build\vvar_probe.exe" ^
    "vvar_probe.c" "build\vvar_probe_x64.obj" ^
    /link /DEBUG /PDB:"build\vvar_probe.pdb" /INCREMENTAL:NO /OPT:NOREF /OPT:NOICF
if errorlevel 1 (
    echo [ERROR] Build failed.
    exit /b 1
)

echo.
echo [OK] Built:
echo      build\vvar_probe.exe
echo      build\vvar_probe.pdb

endlocal
exit /b 0