@echo off
echo Building Sentinel Firewall C backend...
gcc src\server.c -o server.exe -lws2_32 -Wall
if errorlevel 1 (
  echo.
  echo BUILD FAILED. Check that GCC MinGW is installed and added to PATH.
  pause
  exit /b 1
)
echo.
echo Build successful. Run server.exe to start the C backend.
pause
