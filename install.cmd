@echo off
REM ============================================================================
REM  aiscan one-click deploy -- double-click me.
REM
REM  This file is deliberately pure ASCII: cmd.exe reads .cmd files using the
REM  local code page, so non-ASCII text here would come out garbled. All the
REM  Chinese output lives in install.ps1, which is saved as UTF-8 with BOM.
REM ============================================================================
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1" %*
