@echo off
setlocal

echo ============================================================
echo   Voidwatch Agent - Build
echo ============================================================
echo.

set SRCS=src\main.c src\log.c src\json.c src\config.c src\metadata.c src\network_collector.c src\process_collector.c src\sender.c src\enroll.c
set LIBS=ws2_32.lib winhttp.lib iphlpapi.lib wintrust.lib psapi.lib advapi32.lib ole32.lib ntdll.lib
set GLIBS=-lws2_32 -lwinhttp -liphlpapi -lwintrust -lpsapi -ladvapi32 -lole32 -lntdll
set OUT=voidwatch_agent.exe

REM Try MSVC (cl.exe)
where cl >nul 2>&1
if %errorlevel%==0 goto :msvc

REM Try MinGW gcc (PATH or known install locations)
where gcc >nul 2>&1
if %errorlevel%==0 goto :mingw
if exist "C:\MinGW\mingw64\bin\gcc.exe" (
    set PATH=C:\MinGW\mingw64\bin;%PATH%
    goto :mingw
)

REM Try Clang in PATH
where clang >nul 2>&1
if %errorlevel%==0 goto :clang

REM Try Clang at known install paths
if exist "C:\LLVM\bin\clang.exe" (
    set PATH=C:\LLVM\bin;%PATH%
    goto :clang
)
if exist "C:\Program Files\LLVM\bin\clang.exe" (
    set PATH=C:\Program Files\LLVM\bin;%PATH%
    goto :clang
)

REM Try cmake as last resort
where cmake >nul 2>&1
if %errorlevel%==0 goto :cmake

echo ERROR: No C compiler found.
echo   Run:  winget install LLVM.LLVM
echo   Or install from: https://github.com/llvm/llvm-project/releases
echo   Then open a new terminal and run compile.bat again.
pause & exit /b 1

:msvc
echo Building with MSVC...
cl /O2 /W3 /D_CRT_SECURE_NO_WARNINGS /Isrc %SRCS% /Fe:%OUT% /link %LIBS%
goto :done

:mingw
echo Building with MinGW gcc...
gcc -O2 -Wall -Isrc -o %OUT% %SRCS% %GLIBS%
goto :done

:clang
echo Building with Clang...
clang -O2 -Wall -Isrc -o %OUT% %SRCS% %GLIBS%
goto :done

:cmake
echo Building with CMake...
cmake -B build -DCMAKE_BUILD_TYPE=Release
if errorlevel 1 goto :fail
cmake --build build --config Release
goto :done

:done
if exist %OUT% (
    echo.
    echo Build successful: %OUT%
) else (
    goto :fail
)
goto :end

:fail
echo.
echo Build FAILED.
pause & exit /b 1

:end
