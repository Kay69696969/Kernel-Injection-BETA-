@echo off
setlocal enabledelayedexpansion

:: =============================================
:: CONFIGURATION
:: =============================================
set "ANDROID_NDK=C:\NDK"  # Update this to your NDK path
set "NINJA_PATH=C:\Ninja" # Update this to your Ninja path
set "ANDROID_ABI=arm64-v8a"
set "ANDROID_PLATFORM=android-26"
set "BUILD_TYPE=Release"

:: =============================================
:: VALIDATION
:: =============================================
if not exist "%ANDROID_NDK%" (
    echo [ERROR] NDK missing: %ANDROID_NDK%
    echo        Install NDK or update the path in build.bat.
    pause
    exit /b 1
)

if not exist "%ANDROID_NDK%\build\cmake\android.toolchain.cmake" (
    echo [ERROR] Toolchain missing: %ANDROID_NDK%\build\cmake\android.toolchain.cmake
    echo        Your NDK installation might be corrupted.
    pause
    exit /b 1
)

set "PATH=%NINJA_PATH%;%PATH%"
where ninja >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo [ERROR] Ninja not found in: %NINJA_PATH%
    echo        Install Ninja or update NINJA_PATH in build.bat.
    pause
    exit /b 1
)

:: =============================================
:: BUILD PROCESS
:: =============================================
if exist "build" (
    echo [INFO] Removing old build directory...
    rmdir /s /q build
)
mkdir build
cd build || (
    echo [ERROR] Failed to enter build directory.
    pause
    exit /b 1
)

echo [INFO] Configuring project...
cmake -G Ninja ^
    -DCMAKE_TOOLCHAIN_FILE="%ANDROID_NDK%\build\cmake\android.toolchain.cmake" ^
    -DANDROID_ABI=%ANDROID_ABI% ^
    -DANDROID_PLATFORM=%ANDROID_PLATFORM% ^
    -DCMAKE_BUILD_TYPE=%BUILD_TYPE% ^
    -DCMAKE_MAKE_PROGRAM=ninja ^
    ..

if %ERRORLEVEL% neq 0 (
    echo [ERROR] CMake configuration failed.
    cd ..
    pause
    exit /b %ERRORLEVEL%
)

echo [INFO] Building project...
ninja

if %ERRORLEVEL% neq 0 (
    echo [ERROR] Build failed.
    cd ..
    pause
    exit /b %ERRORLEVEL%
)

cd ..
echo [SUCCESS] Build completed! Library: build\libbs_hook.so
pause