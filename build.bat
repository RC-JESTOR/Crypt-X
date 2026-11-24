@echo off
if not exist out mkdir out
javac -d out src\com\rcjestor\cryptx\*.java
if %ERRORLEVEL% NEQ 0 (
    echo [!] Compilation failed. Ensure JDK 17+ is installed.
    exit /b 1
)
echo [+] Build succeeded!
echo     Run: java -cp out com.rcjestor.cryptx.Main selftest
