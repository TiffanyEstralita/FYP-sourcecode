@echo off
rem Double-click to run the LLM stage unattended (prompt practice round + scoring).
rem Keep the laptop plugged in. Safe to close this window: start it again to continue.
rem How many functions to score: change the number after --top below
rem (most important first; remove "--top 500" to score all ~4,350 functions).

cd /d "%~dp0"
title FYP - LLM scoring (do not close until finished)
".venv\Scripts\python.exe" run_llm_unattended.py --top 500 %*
echo.
echo Finished. Log: results\processed\llm_run.log
pause
