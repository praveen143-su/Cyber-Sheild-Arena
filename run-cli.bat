@echo off
echo ==============================================================================
echo       CyberShield Arena — Launching Interactive Console Arena (CLI)
echo ==============================================================================

java -cp "out;lib/weka-stable-3.8.6.jar;lib/bounce-0.18.jar;lib/mysql-connector-j-8.3.0.jar" cybershield.Main --cli
pause
