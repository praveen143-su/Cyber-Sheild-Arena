@echo off
echo ==============================================================================
echo       CyberShield Arena — Launching JavaFX Desktop Dashboard (Phase 8)
echo ==============================================================================

java --module-path "lib/javafx" --add-modules javafx.controls,javafx.fxml -cp "out;lib/mysql-connector-j-8.3.0.jar;lib/weka-stable-3.8.6.jar;lib/bounce-0.18.jar" cybershield.gui.ArenaApp %*
pause
