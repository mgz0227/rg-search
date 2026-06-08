@echo off
setlocal
if "%CXX%"=="" set CXX=g++
%CXX% -std=c++20 -O3 -DNDEBUG -pthread src\rgs.cpp -lws2_32 -o rgs.exe
if errorlevel 1 exit /b 1
rgs.exe --self-test
