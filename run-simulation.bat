@echo off
echo ==============================================================================
echo       CyberShield Arena — Running End-to-End Simulation & Verification
echo ==============================================================================

java -cp "out;lib/weka-stable-3.8.6.jar;lib/bounce-0.18.jar;lib/mysql-connector-j-8.3.0.jar" cybershield.Main
pause
